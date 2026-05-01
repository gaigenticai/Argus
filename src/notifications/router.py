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

    for rule in rules:
        for cid in rule.channel_ids or []:
            ch = by_id.get(cid)
            if ch is None or not ch.enabled:
                continue
            skip = False
            if event.dedup_key:
                if await _within_dedup_window(
                    db, ch.id, event.dedup_key, rule.dedup_window_seconds
                ):
                    skip = True

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

    ids = [d.id for d in all_created]
    res = await db.execute(
        select(NotificationDelivery).where(NotificationDelivery.id.in_(ids))
    )
    return list(res.scalars().all())


__all__ = ["dispatch"]
