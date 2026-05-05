"""Daily exec briefing dispatcher.

Per-org enqueue of ``leakage_exec_briefing`` agent tasks. The actual
markdown generation lives in ``src.agents.governance.leakage`` —
this module is the cron-style trigger.

For each organisation that produced at least one DlpFinding or
CardLeakageFinding in the last 24 hours, queue one briefing task with
a deterministic dedup key of ``briefing:<org_id>:<YYYY-MM-DD>``. The
queue's ``(kind, dedup_key)`` unique constraint guarantees we get
exactly one briefing per org per day no matter how often the tick
fires (the dispatcher schedules this hourly to recover from worker
restarts).

Records a single FeedHealth row per tick so the dashboard surfaces
the cron's heartbeat.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, distinct, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.llm.agent_queue import enqueue
from src.models.leakage import CardLeakageFinding, DlpFinding

logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.leakage_briefing"

_WINDOW_HOURS = 24


async def enqueue_daily_briefings(db: AsyncSession) -> None:
    """Queue one ``leakage_exec_briefing`` task per active org.

    Active = produced at least one DLP or card finding in the last
    ``_WINDOW_HOURS`` hours. dedup_key is per-day so the next tick
    becomes a no-op once today's briefing is enqueued.
    """
    started = time.monotonic()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_WINDOW_HOURS)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Distinct org IDs active in either findings table within the window.
    dlp_orgs = select(DlpFinding.organization_id).where(
        DlpFinding.detected_at >= cutoff
    ).distinct()
    card_orgs = select(CardLeakageFinding.organization_id).where(
        CardLeakageFinding.detected_at >= cutoff
    ).distinct()

    org_ids: set[uuid.UUID] = set()
    for row in (await db.execute(dlp_orgs)).scalars().all():
        if row is not None:
            org_ids.add(row)
    for row in (await db.execute(card_orgs)).scalars().all():
        if row is not None:
            org_ids.add(row)

    if not org_ids:
        await feed_health.mark_ok(
            db,
            feed_name=FEED_NAME,
            rows_ingested=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=f"window={_WINDOW_HOURS}h; no orgs with findings",
        )
        await db.commit()
        return

    enqueued = 0
    for org_id in org_ids:
        dedup = f"briefing:{org_id}:{today}"
        try:
            await enqueue(
                db,
                kind="leakage_exec_briefing",
                payload={"org_id": str(org_id), "window_hours": _WINDOW_HOURS},
                organization_id=org_id,
                dedup_key=dedup,
                priority=7,
            )
            enqueued += 1
        except Exception:  # noqa: BLE001
            logger.exception("failed to enqueue briefing for org %s", org_id)
            continue

    detail = (
        f"window={_WINDOW_HOURS}h; active_orgs={len(org_ids)}; "
        f"enqueued={enqueued}; date={today}"
    )
    await feed_health.mark_ok(
        db,
        feed_name=FEED_NAME,
        rows_ingested=enqueued,
        duration_ms=int((time.monotonic() - started) * 1000),
        detail=detail,
    )
    await db.commit()
    logger.info("leakage_briefing: %s", detail)


__all__ = ["enqueue_daily_briefings", "FEED_NAME"]
