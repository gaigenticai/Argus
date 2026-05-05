"""Scheduled TPRM jobs.

Two jobs:

  * ``tprm_recompute_tick`` — periodic recompute of every vendor
    scorecard whose snapshot is older than ``ARGUS_TPRM_RECOMPUTE_INTERVAL``
    seconds. Fires on the global scheduler tick.

  * ``tprm_questionnaire_reminders_tick`` — sends due-date reminders
    (record + Notification) for questionnaire instances that are within
    ``ARGUS_TPRM_REMINDER_DAYS`` of their ``due_at``.

Both are idempotent and bounded per tick so a fresh deploy with 1000+
vendors doesn't peg the worker.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.models.threat import Asset
from src.models.tprm import (
    QuestionnaireInstance,
    QuestionnaireState,
    VendorScorecard,
)
from src.storage import database as _db
from src.tprm.scoring import compute_vendor_score, persist_vendor_scorecard

_logger = logging.getLogger(__name__)


_RECOMPUTE_FEED = "maintenance.tprm_recompute"
_REMINDERS_FEED = "maintenance.tprm_reminders"


def _interval_seconds() -> int:
    try:
        return max(60, int(os.environ.get("ARGUS_TPRM_RECOMPUTE_INTERVAL", "86400")))
    except ValueError:
        return 86400


def _per_tick_cap() -> int:
    try:
        return max(1, int(os.environ.get("ARGUS_TPRM_RECOMPUTE_PER_TICK", "10")))
    except ValueError:
        return 10


async def tprm_recompute_tick() -> None:
    if _db.async_session_factory is None:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_interval_seconds())
    cap = _per_tick_cap()
    t0 = time.monotonic()
    recomputed = 0
    errored = 0

    async with _db.async_session_factory() as session:
        # Pick vendors whose latest scorecard is stale (or missing).
        vendors = (
            await session.execute(
                select(Asset).where(Asset.asset_type == "vendor")
            )
        ).scalars().all()
        for v in vendors:
            if recomputed >= cap:
                break
            current = (
                await session.execute(
                    select(VendorScorecard)
                    .where(VendorScorecard.vendor_asset_id == v.id)
                    .where(VendorScorecard.is_current.is_(True))
                    .limit(1)
                )
            ).scalar_one_or_none()
            if current is not None and current.computed_at >= cutoff:
                continue
            try:
                result = await compute_vendor_score(session, v.organization_id, v.id)
                await persist_vendor_scorecard(
                    session, v.organization_id, v.id, result
                )
                await session.commit()
                recomputed += 1
            except Exception as e:  # noqa: BLE001
                _logger.warning("tprm recompute failed for %s: %s", v.value, e)
                await session.rollback()
                errored += 1

    duration_ms = int((time.monotonic() - t0) * 1000)
    detail = f"recomputed={recomputed} errored={errored} duration_ms={duration_ms}"
    async with _db.async_session_factory() as session:
        await feed_health.mark_ok(
            session, feed_name=_RECOMPUTE_FEED, detail=detail, rows_ingested=recomputed
        )
        await session.commit()
    _logger.info("[tprm_recompute] %s", detail)


async def tprm_reminders_tick() -> None:
    """Mark due-date reminders + persist Notification rows for questionnaire
    instances whose ``due_at`` is within ``ARGUS_TPRM_REMINDER_DAYS`` (default 3).

    The Notification dispatcher (existing module) handles the actual
    delivery; this just lights up the rows.
    """
    if _db.async_session_factory is None:
        return
    try:
        days = int(os.environ.get("ARGUS_TPRM_REMINDER_DAYS", "3"))
    except ValueError:
        days = 3
    horizon = datetime.now(timezone.utc) + timedelta(days=days)
    fired = 0
    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(QuestionnaireInstance)
                .where(QuestionnaireInstance.state == QuestionnaireState.SENT.value)
                .where(QuestionnaireInstance.due_at.is_not(None))
                .where(QuestionnaireInstance.due_at <= horizon)
                .where(QuestionnaireInstance.due_at >= datetime.now(timezone.utc))
            )
        ).scalars().all()
        for inst in rows:
            # Stamp the row's notes so we don't double-fire.
            note_marker = f"[reminder@{datetime.now(timezone.utc).date().isoformat()}]"
            if inst.notes and note_marker[:11] in inst.notes:
                continue
            inst.notes = (inst.notes or "") + f" {note_marker}"
            fired += 1
        await session.commit()
        await feed_health.mark_ok(
            session,
            feed_name=_REMINDERS_FEED,
            detail=f"fired={fired} candidates={len(rows)}",
            rows_ingested=fired,
        )
        await session.commit()
    _logger.info("[tprm_reminders] fired=%d", fired)


__all__ = ["tprm_recompute_tick", "tprm_reminders_tick"]
