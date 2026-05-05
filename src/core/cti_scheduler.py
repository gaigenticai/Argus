"""Periodic CTI maintenance tasks.

Single async loop that fires:
  * RSS/CTI feed sync           (every 1h, only_due=true)
  * CISA KEV refresh            (every 12h)
  * MSRC + GHSA + Red Hat ingest (every 6h)
  * IOC confidence decay        (every 24h)
  * Saved-search digest deliveries (every 1h — render markdown rows
                                    for whichever frequency-windows are due)

Each tick is wrapped in try/except so one failing source never starves
the others. The loop honours an ``asyncio.Event`` for graceful shutdown.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from src.storage.database import async_session_factory

_logger = logging.getLogger(__name__)


# How often we re-evaluate which jobs are due. Each job has its own
# interval; this is just the polling cadence.
_TICK_SECONDS = 300  # 5 min


# Per-job state: when we last completed it.
_last_run: dict[str, datetime] = {}


async def _maybe_run(name: str, interval: timedelta, body) -> None:
    last = _last_run.get(name)
    now = datetime.now(timezone.utc)
    if last is not None and (now - last) < interval:
        return
    started = datetime.now(timezone.utc)
    try:
        result = await body()
        _logger.info("[cti-sched] %s ok in %.1fs result=%s",
                     name, (datetime.now(timezone.utc) - started).total_seconds(), result)
    except Exception as e:  # noqa: BLE001
        _logger.warning("[cti-sched] %s failed: %s", name, e)
    finally:
        _last_run[name] = now


async def _job_rss_sync() -> dict:
    if async_session_factory is None:
        return {"skipped": True}
    from src.news.worker import fetch_due_feeds

    async with async_session_factory() as db:
        return await fetch_due_feeds(db, process_bodies=True, max_feeds=8)


async def _job_kev() -> dict:
    if async_session_factory is None:
        return {"skipped": True}
    from src.intel.advisory_ingest import ingest_cisa_kev

    async with async_session_factory() as db:
        return await ingest_cisa_kev(db)


async def _job_vendor_advisories() -> dict:
    if async_session_factory is None:
        return {"skipped": True}
    from src.intel.advisory_ingest import (
        ingest_ghsa,
        ingest_msrc,
        ingest_redhat,
    )

    out: dict[str, dict] = {}
    async with async_session_factory() as db:
        for name, fn, kwargs in (
            ("msrc", ingest_msrc, {"max_docs": 12}),
            ("ghsa", ingest_ghsa, {"first": 50}),
            ("redhat", ingest_redhat, {"max_docs": 100}),
        ):
            try:
                out[name] = await fn(db, **kwargs)
            except Exception as e:  # noqa: BLE001
                out[name] = {"error": str(e)[:200]}
    return out


async def _job_ioc_decay() -> dict:
    if async_session_factory is None:
        return {"skipped": True}
    import math
    from sqlalchemy import select
    from src.models.intel import IOC

    async with async_session_factory() as db:
        rows = (
            await db.execute(
                select(IOC).where(IOC.is_allowlisted.is_(False), IOC.expires_at.is_(None))
            )
        ).scalars().all()
        now = datetime.now(timezone.utc)
        decayed = sunsetted = 0
        for ioc in rows:
            if not ioc.last_seen:
                continue
            days = max(0, (now - ioc.last_seen).days)
            hl = max(1, ioc.confidence_half_life_days or 365)
            new_conf = (ioc.confidence or 0.5) * (0.5 ** (days / hl))
            if abs(new_conf - (ioc.confidence or 0)) > 0.001:
                ioc.confidence = new_conf
                decayed += 1
            if new_conf < 0.05 and days >= 2 * hl:
                ioc.expires_at = now
                sunsetted += 1
        await db.commit()
        return {"decayed": decayed, "sunsetted": sunsetted, "evaluated": len(rows)}


async def _job_digest() -> dict:
    if async_session_factory is None:
        return {"skipped": True}
    from src.intel.digest_runner import run_due_digests

    async with async_session_factory() as db:
        return await run_due_digests(db)


async def _job_actor_import() -> dict:
    """Idempotent — re-run nightly to catch new MITRE Group additions."""
    if async_session_factory is None:
        return {"skipped": True}
    from src.mitre.sync import upsert_actors_from_groups

    async with async_session_factory() as db:
        n = await upsert_actors_from_groups(db)
        return {"actors_synced": n}


_JOBS = [
    ("rss_sync", timedelta(hours=1), _job_rss_sync),
    ("vendor_advisories", timedelta(hours=6), _job_vendor_advisories),
    ("kev_refresh", timedelta(hours=12), _job_kev),
    ("ioc_decay", timedelta(hours=24), _job_ioc_decay),
    ("digest_run", timedelta(hours=1), _job_digest),
    ("actor_import", timedelta(hours=24), _job_actor_import),
]


async def run_loop(stop: asyncio.Event) -> None:
    _logger.info("[cti-sched] starting (%d jobs, tick=%ds)", len(_JOBS), _TICK_SECONDS)
    # First-tick: stagger so we don't kick all of them at once on boot.
    await asyncio.sleep(45)
    while not stop.is_set():
        for name, interval, body in _JOBS:
            if stop.is_set():
                break
            await _maybe_run(name, interval, body)
        try:
            await asyncio.wait_for(stop.wait(), timeout=_TICK_SECONDS)
        except asyncio.TimeoutError:
            pass
    _logger.info("[cti-sched] stopped")


__all__ = ["run_loop"]
