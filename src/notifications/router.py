"""Notification router — matches events to rules, fans out to adapters,
records every delivery, enforces a per-(channel, dedup_key) anti-storm
window.

Public API:
    await dispatch(db, event)  -> list[NotificationDelivery]

The router runs *fully inside* the calling DB transaction up to the point
of the actual adapter calls. It commits the delivery rows (with status
PENDING) before invoking adapters so concurrent callers see the dedup
window. Final status (SUCCEEDED/FAILED/SKIPPED) is written in a follow-up
update.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import decrypt
from src.models.notifications import (
    SEVERITY_ORDER,
    ChannelKind,
    DeliveryStatus,
    NotificationChannel,
    NotificationDelivery,
    NotificationRule,
)
from src.models.notification_inbox import NotificationInboxItem
from src.models.auth import User

from .adapters import (
    AdapterResult,
    ChannelContext,
    NotificationEvent,
    get_adapter,
)

_logger = logging.getLogger(__name__)


def _matches_rule(rule: NotificationRule, event: NotificationEvent) -> bool:
    if not rule.enabled:
        return False
    if rule.event_kinds and event.kind not in rule.event_kinds:
        return False
    if SEVERITY_ORDER.get(event.severity, -1) < SEVERITY_ORDER.get(
        rule.min_severity, 0
    ):
        return False
    if rule.asset_criticalities and (
        event.asset_criticality not in rule.asset_criticalities
    ):
        return False
    if rule.asset_types and (event.asset_type not in rule.asset_types):
        return False
    if rule.tags_any and not (set(rule.tags_any) & set(event.tags)):
        return False
    return True


async def _matching_rules(
    db: AsyncSession, event: NotificationEvent
) -> list[NotificationRule]:
    rows = await db.execute(
        select(NotificationRule).where(
            and_(
                NotificationRule.organization_id
                == uuid.UUID(event.organization_id),
                NotificationRule.enabled == True,  # noqa: E712
            )
        )
    )
    return [r for r in rows.scalars().all() if _matches_rule(r, event)]


async def _within_dedup_window(
    db: AsyncSession,
    channel_id: uuid.UUID,
    dedup_key: str,
    window_seconds: int,
) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    res = await db.execute(
        select(NotificationDelivery.id).where(
            and_(
                NotificationDelivery.channel_id == channel_id,
                NotificationDelivery.event_dedup_key == dedup_key,
                NotificationDelivery.delivered_at.is_not(None),
                NotificationDelivery.delivered_at > cutoff,
                NotificationDelivery.status.in_(
                    [
                        DeliveryStatus.SUCCEEDED.value,
                        DeliveryStatus.FAILED.value,
                    ]
                ),
            )
        )
    )
    return res.scalar_one_or_none() is not None


def _channel_context(ch: NotificationChannel) -> ChannelContext:
    secret = None
    if ch.secret_ciphertext:
        try:
            secret = decrypt(ch.secret_ciphertext)
        except Exception as e:  # noqa: BLE001
            _logger.error("Failed to decrypt secret for channel %s: %s", ch.id, e)
            raise
    return ChannelContext(
        id=str(ch.id),
        name=ch.name,
        kind=ch.kind,
        config=dict(ch.config or {}),
        secret=secret,
    )


# ---------------------------------------------------------------------------
# Bridge-LLM agent hooks
# ---------------------------------------------------------------------------
#
# Pre-dispatch hooks (non-fatal). Each is wrapped in a try/except so a
# Bridge outage can never block delivery. Three hooks fire inline (5s
# budget): render, runbook, severity reclassifier. Two hooks are
# enqueued (cluster, oncall_digest) and run async on the worker.

_PRE_DISPATCH_TIMEOUT_S = 5.0


async def _agent_render(
    db: AsyncSession, event: NotificationEvent, channel: NotificationChannel
) -> dict | None:
    """Inline channel-aware renderer (5s budget, falls back to default)."""
    try:
        from src.agents.governance.notifications import render_for_channel
    except Exception:  # noqa: BLE001
        return None
    try:
        payload = {
            "kind": event.kind,
            "severity": event.severity,
            "title": event.title,
            "summary": event.summary,
            "tags": list(event.tags),
            "asset_criticality": event.asset_criticality,
            "asset_type": event.asset_type,
            "extra": event.extra,
        }
        return await render_for_channel(payload, channel.kind, timeout=_PRE_DISPATCH_TIMEOUT_S)
    except Exception:  # noqa: BLE001
        _logger.exception("notification: agent_render hook failed (non-fatal)")
        return None


async def _agent_runbook(event: NotificationEvent) -> dict | None:
    try:
        from src.agents.governance.notifications import attach_runbook
    except Exception:  # noqa: BLE001
        return None
    try:
        payload = {
            "kind": event.kind,
            "severity": event.severity,
            "title": event.title,
            "summary": event.summary,
            "extra": event.extra,
        }
        return await attach_runbook(event.kind, payload, timeout=_PRE_DISPATCH_TIMEOUT_S)
    except Exception:  # noqa: BLE001
        _logger.exception("notification: agent_runbook hook failed (non-fatal)")
        return None


async def _agent_severity_check(
    event: NotificationEvent, rule: NotificationRule
) -> dict | None:
    """Severity reclassifier — only fires on critical events during a
    rule's quiet hours. Returns the verdict dict if a downgrade was
    requested, else None.
    """
    if event.severity != "critical":
        return None
    try:
        from src.agents.governance.notifications import (
            in_quiet_hours,
            reclassify_severity,
        )
    except Exception:  # noqa: BLE001
        return None
    qh = in_quiet_hours(rule)
    if qh is None:
        return None
    except_sev = str(qh.get("except_severity", "")).lower()
    if except_sev and except_sev == event.severity:
        return None
    try:
        payload = {
            "kind": event.kind,
            "severity": event.severity,
            "title": event.title,
            "summary": event.summary,
            "asset_criticality": event.asset_criticality,
            "asset_type": event.asset_type,
            "tags": list(event.tags),
            "extra": event.extra,
            "quiet_hours": qh,
        }
        verdict = await reclassify_severity(payload, timeout=_PRE_DISPATCH_TIMEOUT_S)
    except Exception:  # noqa: BLE001
        _logger.exception("notification: agent severity_reclassify failed (non-fatal)")
        return None
    if not verdict or not verdict.get("downgrade"):
        return None
    return verdict


async def _enqueue_cluster_if_needed(
    db: AsyncSession, event: NotificationEvent, delivery: NotificationDelivery
) -> None:
    """If 3+ similar deliveries (same dedup_key) fired in the last 60s,
    enqueue the clusterer. We do this fire-and-forget on the queue —
    the clusterer is summarisation, not dispatch-blocking.
    """
    if not event.dedup_key:
        return
    try:
        from src.llm.agent_queue import enqueue
    except Exception:  # noqa: BLE001
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    res = await db.execute(
        select(NotificationDelivery.id).where(
            and_(
                NotificationDelivery.organization_id == delivery.organization_id,
                NotificationDelivery.event_dedup_key == event.dedup_key,
                NotificationDelivery.created_at >= cutoff,
            )
        )
    )
    ids = [str(x) for x in res.scalars().all()]
    if len(ids) < 3:
        return
    try:
        await enqueue(
            db,
            kind="notification_cluster",
            organization_id=delivery.organization_id,
            payload={
                "delivery_ids": ids,
                "dedup_key": event.dedup_key,
            },
            dedup_key=f"cluster:{event.dedup_key}:{int(cutoff.timestamp() // 60)}",
            priority=4,
        )
    except Exception:  # noqa: BLE001
        _logger.exception("notification: cluster enqueue failed (non-fatal)")


async def _write_inbox_rows(
    db: AsyncSession,
    event: NotificationEvent,
    delivery: NotificationDelivery,
) -> int:
    """Fan an inbox row out to every admin user in the org so the
    in-app inbox surfaces the notification regardless of channel.
    """
    try:
        # If the event scopes to a single user, prefer that.
        target_user_ids: list[uuid.UUID] = []
        scoped_uid = (event.extra or {}).get("user_id")
        if scoped_uid:
            try:
                target_user_ids = [uuid.UUID(str(scoped_uid))]
            except Exception:  # noqa: BLE001
                target_user_ids = []
        if not target_user_ids:
            res = await db.execute(
                select(User.id).where(User.is_active == True)  # noqa: E712
            )
            target_user_ids = list(res.scalars().all())
        link_path = (event.extra or {}).get("link_path") or "/notifications"
        rendered = delivery.rendered_payload or {}
        for uid in target_user_ids:
            db.add(
                NotificationInboxItem(
                    organization_id=delivery.organization_id,
                    user_id=uid,
                    rule_id=delivery.rule_id,
                    delivery_id=delivery.id,
                    event_kind=event.kind,
                    severity=event.severity,
                    title=event.title[:255],
                    summary=event.summary[:4000] if event.summary else None,
                    link_path=str(link_path)[:500],
                    payload={
                        "tags": list(event.tags),
                        "extra": dict(event.extra or {}),
                        "rendered": rendered,
                    },
                )
            )
        await db.commit()
        return len(target_user_ids)
    except Exception:  # noqa: BLE001
        _logger.exception("notification: inbox write failed (non-fatal)")
        await db.rollback()
        return 0


async def dispatch(
    db: AsyncSession, event: NotificationEvent, *, dry_run: bool = False
) -> list[NotificationDelivery]:
    """Fan out an event. Always commits delivery rows; never raises."""
    rules = await _matching_rules(db, event)
    if not rules:
        return []

    # Resolve unique channel ids referenced by all matching rules.
    channel_ids: set[uuid.UUID] = set()
    for r in rules:
        channel_ids.update(r.channel_ids or [])
    if not channel_ids:
        return []

    channels = (
        await db.execute(
            select(NotificationChannel).where(
                NotificationChannel.id.in_(channel_ids)
            )
        )
    ).scalars().all()
    by_id = {c.id: c for c in channels}

    deliveries_to_run: list[
        tuple[NotificationRule, NotificationChannel, NotificationDelivery]
    ] = []
    all_created: list[NotificationDelivery] = []
    inbox_writes: list[NotificationDelivery] = []

    # Bridge-LLM pre-dispatch (runbook is event-shaped not channel-shaped,
    # so we compute it once and reuse). Render is per-channel.
    runbook = None if dry_run else await _agent_runbook(event)

    for rule in rules:
        # Severity reclassifier — only fires for critical events during
        # a rule's quiet hours. Returns None or a verdict dict.
        reclass_verdict = (
            None if dry_run else await _agent_severity_check(event, rule)
        )
        rule_demotes = bool(reclass_verdict)

        for cid in rule.channel_ids or []:
            ch = by_id.get(cid)
            if ch is None or not ch.enabled:
                continue
            skip = False
            skip_reason: str | None = None
            if event.dedup_key:
                if await _within_dedup_window(
                    db, ch.id, event.dedup_key, rule.dedup_window_seconds
                ):
                    skip = True
                    skip_reason = "dedup_window"
            if rule_demotes:
                # Demote to digest mode — write inbox row, skip channel send.
                skip = True
                skip_reason = "severity_reclassify_downgrade"

            # Channel-aware render (5s, falls back to None on failure).
            rendered: dict | None = None
            if not skip and not dry_run:
                rendered = await _agent_render(db, event, ch)
            rendered_payload: dict | None = None
            if rendered or runbook or reclass_verdict:
                rendered_payload = dict(rendered or {})
                if runbook:
                    rendered_payload["recommended_runbook"] = runbook
                if reclass_verdict:
                    rendered_payload["severity_reclassify"] = reclass_verdict
                if skip_reason:
                    rendered_payload["skip_reason"] = skip_reason

            delivery = NotificationDelivery(
                organization_id=ch.organization_id,
                rule_id=rule.id,
                channel_id=ch.id,
                event_kind=event.kind,
                event_severity=event.severity,
                event_dedup_key=event.dedup_key,
                event_payload={
                    "title": event.title,
                    "summary": event.summary,
                    "tags": list(event.tags),
                    "asset_criticality": event.asset_criticality,
                    "asset_type": event.asset_type,
                    "extra": event.extra,
                },
                rendered_payload=rendered_payload,
                status=(
                    DeliveryStatus.SKIPPED.value
                    if skip
                    else DeliveryStatus.DRY_RUN.value
                    if dry_run
                    else DeliveryStatus.PENDING.value
                ),
                attempts=0 if skip or dry_run else 1,
            )
            db.add(delivery)
            await db.flush()
            all_created.append(delivery)
            if skip and skip_reason == "severity_reclassify_downgrade":
                # Surface in-app even though we suppressed channel send.
                inbox_writes.append(delivery)
            if not skip and not dry_run:
                deliveries_to_run.append((rule, ch, delivery))

    await db.commit()

    if not deliveries_to_run:
        # Either everything was skipped or this is a dry run.
        ids = [d.id for d in all_created]
        if not ids:
            return []
        res = await db.execute(
            select(NotificationDelivery).where(
                NotificationDelivery.id.in_(ids)
            )
        )
        return list(res.scalars().all())

    async def _run(rule, ch, delivery):
        # Audit C1 — every adapter failure is now logged at WARNING with
        # channel id + kind so operators can correlate against the
        # `notification_deliveries` row. We still return an
        # `AdapterResult` (never raise) so one broken channel can't kill
        # the whole fan-out, but the failure is no longer silent.
        adapter = get_adapter(ch.kind)
        try:
            ctx = _channel_context(ch)
        except Exception as e:  # noqa: BLE001
            _logger.warning(
                "notification: secret decrypt failed for channel %s (%s): %s",
                ch.id, ch.kind, e,
            )
            return delivery, AdapterResult(
                success=False, error_message=f"secret decrypt failed: {e}"
            )
        try:
            result = await adapter.send(event, ctx)
        except Exception as e:  # noqa: BLE001
            _logger.exception(
                "notification: adapter %s raised on channel %s",
                ch.kind, ch.id,
            )
            return delivery, AdapterResult(
                success=False, error_message=f"adapter crashed: {e}"
            )
        if not result.success:
            _logger.warning(
                "notification: delivery failed channel=%s kind=%s status=%s err=%s",
                ch.id, ch.kind, result.response_status, result.error_message,
            )
        return delivery, result

    pairs = await asyncio.gather(
        *[_run(r, c, d) for r, c, d in deliveries_to_run], return_exceptions=False
    )

    now = datetime.now(timezone.utc)
    channel_by_delivery = {d.id: c for r, c, d in deliveries_to_run}
    for delivery, result in pairs:
        delivery.status = (
            DeliveryStatus.SUCCEEDED.value
            if result.success
            else DeliveryStatus.FAILED.value
        )
        delivery.response_status = result.response_status
        delivery.response_body = result.response_body
        delivery.error_message = result.error_message
        delivery.latency_ms = result.latency_ms
        delivery.delivered_at = now

        ch = channel_by_delivery[delivery.id]
        ch.last_used_at = now
        ch.last_status = delivery.status
        ch.last_error = result.error_message

    await db.commit()

    # Inbox fan-out + clusterer enqueue for every successful delivery,
    # plus the synthetic skip rows where severity reclassifier demoted
    # a critical alert into digest mode.
    succeeded = [
        d for d, r in pairs if r.success
    ]
    for d in inbox_writes:
        await _write_inbox_rows(db, event, d)
    for d in succeeded:
        await _write_inbox_rows(db, event, d)
        await _enqueue_cluster_if_needed(db, event, d)

    ids = [d.id for d in all_created]
    res = await db.execute(
        select(NotificationDelivery).where(NotificationDelivery.id.in_(ids))
    )
    return list(res.scalars().all())


__all__ = ["dispatch"]
