"""Notifications agentic handlers — five Bridge-LLM agents that
upgrade the dumb-pipe notification router into an intelligent one.

Trigger surfaces
----------------

Synchronous (called inline from ``src.notifications.router.dispatch``,
5s budget, fall back to defaults on timeout):

    notification_render            channel-aware body renderer
    notification_runbook           runbook attacher (embeds into rendered_payload)
    notification_severity_reclassify  3am page-worthiness check during quiet hours

Asynchronous (enqueued via ``agent_queue``):

    notification_cluster           noise clusterer; merges N similar alerts → 1 summary
    notification_oncall_digest     08:00 user-local digest of last 8h alerts


Every prompt asks for STRICT JSON. We parse defensively — any
deviation falls back to a safe default and we log a warning.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, select

from src.llm.agent_queue import call_bridge, register_handler
from src.models.agent_task import AgentTask
from src.models.notification_inbox import NotificationInboxItem
from src.models.notifications import (
    NotificationChannel,
    NotificationDelivery,
    NotificationRule,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON-parsing utilities
# ---------------------------------------------------------------------------


_JSON_BLOCK = re.compile(r"\{[\s\S]*\}")


def _parse_json(text: str) -> dict[str, Any] | None:
    """Tolerant JSON parser — Bridge sometimes wraps output in code fences
    or chats before the JSON. We grab the first top-level ``{...}`` and try.
    """
    if not text:
        return None
    candidates = []
    stripped = text.strip()
    if stripped.startswith("```"):
        # ```json\n{...}\n```
        stripped = stripped.strip("`")
        if stripped.startswith("json"):
            stripped = stripped[4:]
    candidates.append(stripped.strip())
    m = _JSON_BLOCK.search(text)
    if m:
        candidates.append(m.group(0))
    for c in candidates:
        try:
            obj = json.loads(c)
            if isinstance(obj, dict):
                return obj
        except Exception:  # noqa: BLE001
            continue
    return None


# ---------------------------------------------------------------------------
# 1. notification_render — channel-aware content renderer
# ---------------------------------------------------------------------------


_RENDER_SYSTEM = (
    "You are a content renderer for a security operations notification "
    "platform. Your job: given a security event and a target channel "
    "kind, produce a rendering that fits that channel's UX. "
    "Slack: 3-line summary plus a header, with optional link buttons. "
    "Email: full HTML executive summary with severity color and details. "
    "SMS / Jasmin SMS: <=140 chars, plain ASCII. "
    "PagerDuty: a tight alert + recommended runbook. "
    "Teams: an Adaptive Card 1.4 JSON. "
    "ALWAYS reply with STRICT JSON of the shape: "
    '{"body_text": str, "body_html": str, "blocks": list|null, '
    '"adaptive_card": object|null}. '
    "Do not include any commentary outside the JSON."
)


def _render_user_prompt(event: dict[str, Any], channel_kind: str) -> str:
    return (
        f"Channel kind: {channel_kind}\n\n"
        f"Event:\n{json.dumps(event, indent=2, default=str)[:4000]}\n\n"
        "Render now."
    )


async def render_for_channel(
    event_payload: dict[str, Any],
    channel_kind: str,
    *,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """Synchronous-ish renderer used by the dispatch hot path.

    Returns the ``rendered_payload`` dict on success, or ``None`` on
    timeout / Bridge unreachable / parse failure.
    """
    try:
        text, _model = await asyncio.wait_for(
            call_bridge(_RENDER_SYSTEM, _render_user_prompt(event_payload, channel_kind)),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        _logger.info("notification_render: bridge timeout (>%ss) — using default render", timeout)
        return None
    except Exception as e:  # noqa: BLE001
        _logger.warning("notification_render: bridge error: %s", e)
        return None
    parsed = _parse_json(text)
    if parsed is None:
        _logger.warning("notification_render: bridge returned non-JSON; using default render")
        return None
    parsed["_renderer"] = "notification_render"
    parsed["_channel_kind"] = channel_kind
    return parsed


async def _handle_render_async(db, task: AgentTask) -> dict[str, Any]:
    """Queue handler — for cases where the render is enqueued instead of
    inlined. Persists the result onto the delivery row.
    """
    payload = task.payload or {}
    delivery_id = payload.get("delivery_id")
    channel_kind = payload.get("channel_kind", "webhook")
    event = payload.get("event") or {}
    rendered = await render_for_channel(event, channel_kind, timeout=15.0)
    if rendered is None:
        return {"rendered": False}
    if delivery_id:
        d = await db.get(NotificationDelivery, uuid.UUID(delivery_id))
        if d is not None:
            existing = dict(d.rendered_payload or {})
            existing.update(rendered)
            d.rendered_payload = existing
            await db.commit()
    return {"rendered": True, "channel_kind": channel_kind}


register_handler("notification_render", _handle_render_async)


# ---------------------------------------------------------------------------
# 2. notification_runbook — remediation runbook attacher
# ---------------------------------------------------------------------------


_RUNBOOK_SYSTEM = (
    "You are a senior SOC engineer. Generate a 3-step remediation "
    "runbook for the given security event kind. Each step has: a "
    "title, a 1-2 sentence ``what`` describing the action, and an "
    "optional ``why`` explaining the rationale. "
    "Reply with STRICT JSON of the shape: "
    '{"summary": str, "steps": [{"title": str, "what": str, "why": str|null}, ...]} '
    "with exactly 3 steps. Do not wrap in markdown."
)


async def attach_runbook(
    event_kind: str, event_payload: dict[str, Any], *, timeout: float = 5.0
) -> dict[str, Any] | None:
    user = (
        f"event_kind: {event_kind}\n"
        f"context:\n{json.dumps(event_payload, indent=2, default=str)[:2000]}\n\n"
        "Produce the 3-step runbook now."
    )
    try:
        text, _ = await asyncio.wait_for(
            call_bridge(_RUNBOOK_SYSTEM, user), timeout=timeout
        )
    except asyncio.TimeoutError:
        return None
    except Exception as e:  # noqa: BLE001
        _logger.warning("notification_runbook: bridge error: %s", e)
        return None
    parsed = _parse_json(text)
    if not parsed or "steps" not in parsed:
        return None
    return parsed


async def _handle_runbook_async(db, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    delivery_id = payload.get("delivery_id")
    runbook = await attach_runbook(
        payload.get("event_kind", "alert"),
        payload.get("event") or {},
        timeout=20.0,
    )
    if runbook is None:
        return {"attached": False}
    if delivery_id:
        d = await db.get(NotificationDelivery, uuid.UUID(delivery_id))
        if d is not None:
            existing = dict(d.rendered_payload or {})
            existing["recommended_runbook"] = runbook
            d.rendered_payload = existing
            await db.commit()
    return {"attached": True}


register_handler("notification_runbook", _handle_runbook_async)


# ---------------------------------------------------------------------------
# 3. notification_cluster — noise clusterer
# ---------------------------------------------------------------------------


_CLUSTER_SYSTEM = (
    "You are an SRE-grade alert clusterer. Given a list of similar "
    "alerts (same dedup_key) that fired in the last 60 seconds, "
    "produce a single concise cluster summary suitable for a Slack "
    "message or email. "
    "Reply with STRICT JSON: "
    '{"cluster_title": str, "cluster_summary": str, "count": int}.'
)


async def _handle_cluster(db, task: AgentTask) -> dict[str, Any]:
    """Re-run the clusterer over the ``payload.delivery_ids`` and
    persist a unified cluster_summary onto each delivery.
    """
    payload = task.payload or {}
    delivery_ids = [uuid.UUID(x) for x in (payload.get("delivery_ids") or [])]
    if not delivery_ids:
        return {"clustered": 0}
    rows = (
        await db.execute(
            select(NotificationDelivery).where(NotificationDelivery.id.in_(delivery_ids))
        )
    ).scalars().all()
    if len(rows) < 2:
        return {"clustered": 0}
    sample = [
        {
            "title": (r.event_payload or {}).get("title"),
            "severity": r.event_severity,
            "kind": r.event_kind,
            "summary": (r.event_payload or {}).get("summary"),
        }
        for r in rows[:20]
    ]
    user = json.dumps({"alerts": sample, "count": len(rows)}, default=str)
    try:
        text, _ = await asyncio.wait_for(
            call_bridge(_CLUSTER_SYSTEM, user), timeout=20.0
        )
    except Exception as e:  # noqa: BLE001
        _logger.warning("notification_cluster: bridge error: %s", e)
        return {"clustered": 0, "error": str(e)[:200]}
    parsed = _parse_json(text) or {}
    parsed.setdefault("count", len(rows))
    parsed["_dedup_key"] = payload.get("dedup_key")
    cluster_key = (payload.get("dedup_key") or "").strip() or None
    for r in rows:
        existing = dict(r.rendered_payload or {})
        existing["cluster"] = parsed
        r.rendered_payload = existing
        r.cluster_count = len(rows)
        if cluster_key:
            r.cluster_dedup_key = cluster_key
    await db.commit()
    return {"clustered": len(rows), "summary": parsed.get("cluster_summary")}


register_handler("notification_cluster", _handle_cluster)


# ---------------------------------------------------------------------------
# 4. notification_oncall_digest — wake-up digest
# ---------------------------------------------------------------------------


_DIGEST_SYSTEM = (
    "You are an on-call shift handover assistant. Summarise the last "
    "8 hours of security alerts for the on-call engineer. Identify "
    "(1) top 3 most important alerts, (2) any trend versus the prior "
    "week, (3) suggested action items. "
    "Reply with STRICT JSON: "
    '{"top_alerts": [{"title": str, "severity": str, "why": str}], '
    '"trend": str, "action_items": [str, ...]}'
)


async def _handle_oncall_digest(db, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    user_id_raw = payload.get("user_id")
    org_id_raw = payload.get("organization_id")
    if not user_id_raw or not org_id_raw:
        return {"digested": False, "error": "missing user_id or organization_id"}
    user_id = uuid.UUID(user_id_raw)
    org_id = uuid.UUID(org_id_raw)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=8)
    rows = (
        await db.execute(
            select(NotificationDelivery)
            .where(
                and_(
                    NotificationDelivery.organization_id == org_id,
                    NotificationDelivery.created_at >= cutoff,
                )
            )
            .order_by(NotificationDelivery.created_at.desc())
            .limit(200)
        )
    ).scalars().all()
    sample = [
        {
            "title": (r.event_payload or {}).get("title"),
            "severity": r.event_severity,
            "kind": r.event_kind,
            "summary": (r.event_payload or {}).get("summary"),
            "ts": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows[:60]
    ]
    user = json.dumps({"alerts_last_8h": sample, "count": len(rows)}, default=str)
    try:
        text, _ = await asyncio.wait_for(
            call_bridge(_DIGEST_SYSTEM, user), timeout=30.0
        )
    except Exception as e:  # noqa: BLE001
        _logger.warning("notification_oncall_digest: bridge error: %s", e)
        return {"digested": False, "error": str(e)[:200]}
    parsed = _parse_json(text) or {
        "top_alerts": [],
        "trend": "no data",
        "action_items": [],
    }
    title = f"On-call digest — {len(rows)} alerts in last 8h"
    summary_lines = []
    if parsed.get("trend"):
        summary_lines.append(f"Trend: {parsed['trend']}")
    for a in (parsed.get("top_alerts") or [])[:3]:
        summary_lines.append(f"- [{a.get('severity', '?')}] {a.get('title', '?')}")
    if parsed.get("action_items"):
        summary_lines.append("Action items:")
        for item in parsed["action_items"][:5]:
            summary_lines.append(f"  • {item}")
    inbox = NotificationInboxItem(
        organization_id=org_id,
        user_id=user_id,
        event_kind="oncall_digest",
        severity="info",
        title=title,
        summary="\n".join(summary_lines)[:3000],
        link_path="/notifications",
        payload={"digest": parsed, "count": len(rows)},
    )
    db.add(inbox)
    await db.commit()
    return {"digested": True, "alerts": len(rows)}


register_handler("notification_oncall_digest", _handle_oncall_digest)


# ---------------------------------------------------------------------------
# 5. notification_severity_reclassify — page-worthiness during quiet hours
# ---------------------------------------------------------------------------


_RECLASSIFY_SYSTEM = (
    "You are a noise-reduction agent for an after-hours pager. "
    "Decide whether a critical-severity alert is *actually* worth "
    "waking a human up at 3am, given the asset criticality, "
    "business hours, and any recent context provided. Be conservative: "
    "if the asset is not crown-jewel and there is no active business "
    "impact, downgrade to high (and surface in digest). "
    "Reply with STRICT JSON: "
    '{"downgrade": bool, "new_severity": str, '
    '"rationale": str}. ``new_severity`` must be one of '
    '"critical", "high", "medium", "low", "info".'
)


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


async def reclassify_severity(
    event_payload: dict[str, Any], *, timeout: float = 5.0
) -> dict[str, Any] | None:
    user = (
        f"Event:\n{json.dumps(event_payload, indent=2, default=str)[:3000]}\n\n"
        "Decide now."
    )
    try:
        text, _ = await asyncio.wait_for(
            call_bridge(_RECLASSIFY_SYSTEM, user), timeout=timeout
        )
    except asyncio.TimeoutError:
        return None
    except Exception as e:  # noqa: BLE001
        _logger.warning("notification_severity_reclassify: bridge error: %s", e)
        return None
    parsed = _parse_json(text)
    if not parsed:
        return None
    sev = str(parsed.get("new_severity", "")).lower().strip()
    if sev not in _VALID_SEVERITIES:
        return None
    parsed["new_severity"] = sev
    parsed["downgrade"] = bool(parsed.get("downgrade"))
    return parsed


async def _handle_reclassify_async(db, task: AgentTask) -> dict[str, Any]:
    """Queue handler — runs the reclassifier and writes the verdict
    onto the delivery row even though the actual demote already
    happened inline.
    """
    payload = task.payload or {}
    delivery_id = payload.get("delivery_id")
    verdict = await reclassify_severity(payload.get("event") or {}, timeout=15.0)
    if verdict is None or not delivery_id:
        return {"verdict": None}
    d = await db.get(NotificationDelivery, uuid.UUID(delivery_id))
    if d is None:
        return {"verdict": verdict}
    existing = dict(d.rendered_payload or {})
    existing["severity_reclassify"] = verdict
    d.rendered_payload = existing
    await db.commit()
    return {"verdict": verdict}


register_handler("notification_severity_reclassify", _handle_reclassify_async)


# ---------------------------------------------------------------------------
# Helpers consumed by router.py
# ---------------------------------------------------------------------------


def in_quiet_hours(rule: NotificationRule, now: datetime | None = None) -> dict | None:
    """Return the quiet-hours config dict if ``now`` lies inside the
    rule's quiet window, else None. Quiet hours are stored in
    ``description`` after the ``\\n##QH##`` marker (see API routes).
    """
    desc = rule.description or ""
    idx = desc.find("\n##QH##")
    if idx < 0:
        return None
    try:
        qh = json.loads(desc[idx + len("\n##QH##"):])
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(qh, dict):
        return None
    start = qh.get("start")  # "22:00"
    end = qh.get("end")      # "07:00"
    tz_name = qh.get("tz") or "UTC"
    if not start or not end:
        return None
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:  # noqa: BLE001
        tz = timezone.utc
    n = (now or datetime.now(timezone.utc)).astimezone(tz)
    sh, sm = (int(x) for x in start.split(":"))
    eh, em = (int(x) for x in end.split(":"))
    cur = n.hour * 60 + n.minute
    s = sh * 60 + sm
    e = eh * 60 + em
    if s == e:
        return None
    inside = (s <= cur < e) if s < e else (cur >= s or cur < e)
    return qh if inside else None


__all__ = [
    "render_for_channel",
    "attach_runbook",
    "reclassify_severity",
    "in_quiet_hours",
]
