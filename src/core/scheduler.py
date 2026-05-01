"""Crawl scheduler — orchestrates periodic crawler runs.

Crawler targets are stored in the ``crawler_targets`` table. Every
tick the scheduler reloads active targets per kind and instantiates
the appropriate crawler with the populated config. The bootstrap
default of ``**{}`` (empty kwargs) is gone — a crawler is run only
when the operator has provisioned at least one target row through the
admin UI.

Each tick records a ``FeedHealth`` row keyed by the crawler name so
the dashboard can show "Tor forum crawler: ok / 47 rows / 1.4 s"
or, when no targets exist, "Tor forum crawler: unconfigured / no
targets registered".
"""

from __future__ import annotations


import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health as feed_health_helper
from src.core.tenant import SystemOrganizationMissing, get_system_org_id
from src.crawlers.tor_crawler import TorForumCrawler, TorMarketplaceCrawler
from src.crawlers.telegram_crawler import TelegramCrawler
from src.crawlers.i2p_crawler import I2PEepsiteCrawler
from src.crawlers.lokinet_crawler import LokinetCrawler
from src.crawlers.stealer_crawler import StealerLogCrawler
from src.crawlers.ransomware_crawler import RansomwareLeakCrawler
from src.crawlers.forum_crawler import ForumCrawler
from src.crawlers.matrix_crawler import MatrixCrawler
from src.ingestion.pipeline import IngestionPipeline
from src.models.admin import CrawlerKind, CrawlerTarget
from src.storage.database import async_session_factory


logger = logging.getLogger(__name__)


def _row_to_dict(row: CrawlerTarget) -> dict:
    """Translate a CrawlerTarget row into a kind-specific kwargs dict.

    Each crawler accepts a particular shape; ``identifier`` always
    becomes the primary URL/handle/room id, and ``config`` JSONB
    overlays whatever extra options the crawler exposes (selectors,
    auth tokens, mirror lists).
    """
    base = {
        "identifier": row.identifier,
        "display_name": row.display_name or row.identifier,
        **(row.config or {}),
    }
    return base


def _wrap_targets(rows: list[CrawlerTarget]) -> list[dict]:
    return [_row_to_dict(r) for r in rows if r.is_active]


async def _load_targets(
    db: AsyncSession, organization_id, kind: CrawlerKind
) -> list[CrawlerTarget]:
    return list(
        (
            await db.execute(
                select(CrawlerTarget).where(
                    CrawlerTarget.organization_id == organization_id,
                    CrawlerTarget.kind == kind.value,
                    CrawlerTarget.is_active.is_(True),
                )
            )
        ).scalars().all()
    )


# Mapping: crawler kind → (crawler class, kwarg name). The kwarg name
# is the parameter the crawler constructor expects for the list of
# target dicts. We don't pass empty lists; if there are no targets we
# record an "unconfigured" FeedHealth row and skip the run.
_CRAWLER_REGISTRY: dict[CrawlerKind, tuple[type, str, int]] = {
    CrawlerKind.TOR_FORUM: (TorForumCrawler, "forum_configs", 30),
    CrawlerKind.TOR_MARKETPLACE: (TorMarketplaceCrawler, "marketplace_configs", 30),
    CrawlerKind.TELEGRAM_CHANNEL: (TelegramCrawler, "channels", 10),
    CrawlerKind.I2P_EEPSITE: (I2PEepsiteCrawler, "eepsite_configs", 60),
    CrawlerKind.LOKINET_SITE: (LokinetCrawler, "site_configs", 60),
    CrawlerKind.STEALER_MARKETPLACE: (StealerLogCrawler, "marketplace_configs", 15),
    CrawlerKind.RANSOMWARE_LEAK_GROUP: (RansomwareLeakCrawler, "group_configs", 20),
    CrawlerKind.FORUM: (ForumCrawler, "forum_configs", 30),
    CrawlerKind.MATRIX_ROOM: (MatrixCrawler, "room_configs", 30),
}


class Scheduler:
    """Runs crawlers on schedule. One asyncio task per crawler kind.

    G9 — graceful shutdown:
        ``stop()`` flips ``_running`` to False and signals each
        per-kind task to drop out of its sleep. In-flight crawls
        complete naturally; the next iteration sees ``_running=False``
        and the task exits. ``await scheduler.start()`` returns once
        every per-kind task has cleanly exited, so a ``SIGTERM``
        handler that calls ``stop()`` and waits for ``start()`` to
        return gives a clean shutdown.

    G9 — health surface:
        Per-crawler-kind health is recorded as ``FeedHealth`` rows
        keyed ``crawler.<kind>``; the dashboard (``/admin/feed-health``)
        already renders these. ``health_snapshot()`` exposes a quick
        in-process view for ``/health/crawlers``.
    """

    def __init__(self) -> None:
        self._running = False
        self._stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._last_tick: dict[CrawlerKind, datetime] = {}

    async def start(self) -> None:
        self._running = True
        self._stop_event.clear()
        self._tasks = []
        logger.info(
            "[scheduler] Starting with %d crawler kinds", len(_CRAWLER_REGISTRY)
        )
        for kind in _CRAWLER_REGISTRY:
            task = asyncio.create_task(self._run_kind(kind), name=f"crawler-{kind.value}")
            self._tasks.append(task)
        try:
            await asyncio.gather(*self._tasks, return_exceptions=False)
        except asyncio.CancelledError:
            # SIGTERM-driven cancellation; let stop() drive the
            # graceful drain instead of raising up.
            logger.info("[scheduler] cancelled — draining tasks")
            await self._drain()
            raise

    async def stop(self, *, drain_timeout: float = 30.0) -> None:
        """Signal every per-kind task to exit on its next iteration.

        ``drain_timeout`` bounds how long we wait for in-flight
        crawls to finish; after that we cancel hard. The bounded
        wait keeps SIGTERM-to-pod-exit predictable for orchestrators
        like Kubernetes (default terminationGracePeriodSeconds=30).
        """
        if not self._running:
            return
        logger.info("[scheduler] stop requested — draining (timeout=%.0fs)", drain_timeout)
        self._running = False
        self._stop_event.set()

        if not self._tasks:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._tasks, return_exceptions=True),
                timeout=drain_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "[scheduler] drain timeout exceeded; cancelling %d task(s)",
                sum(1 for t in self._tasks if not t.done()),
            )
            await self._drain()
        self._tasks = []

    async def _drain(self) -> None:
        """Cancel any task that didn't honour the stop event."""
        for task in self._tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    def health_snapshot(self) -> dict:
        """In-process health surface for ``/health/crawlers``.

        Returns ``{"running": bool, "kinds": {<kind>: {"last_tick":
        iso, "task_alive": bool}}}``. The dashboard's main feed-health
        panel already renders the FeedHealth rows for richer detail;
        this endpoint exists so an orchestrator can liveness-probe the
        scheduler without a DB roundtrip.
        """
        return {
            "running": self._running,
            "kinds": {
                kind.value: {
                    "last_tick": (
                        self._last_tick[kind].isoformat()
                        if kind in self._last_tick else None
                    ),
                    "task_alive": any(
                        t.get_name() == f"crawler-{kind.value}" and not t.done()
                        for t in self._tasks
                    ),
                }
                for kind in _CRAWLER_REGISTRY
            },
        }

    async def _run_kind(self, kind: CrawlerKind) -> None:
        crawler_class, kwarg_name, interval_minutes = _CRAWLER_REGISTRY[kind]
        feed_name = f"crawler.{kind.value}"
        interval_seconds = interval_minutes * 60

        while self._running:
            await self._run_kind_once(kind, crawler_class, kwarg_name, feed_name)
            self._last_tick[kind] = datetime.now(timezone.utc)
            # Sleep with cancellation honored by stop_event so SIGTERM
            # doesn't have to wait the full interval before the loop
            # exits.
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=interval_seconds,
                )
                # stop_event fired during sleep → exit loop.
                return
            except asyncio.TimeoutError:
                continue

    async def _run_kind_once(
        self,
        kind: CrawlerKind,
        crawler_class: type,
        kwarg_name: str,
        feed_name: str,
    ) -> None:
        async with async_session_factory() as session:
            try:
                org_id = await get_system_org_id(session)
            except SystemOrganizationMissing:
                logger.warning(
                    "[scheduler] No system org provisioned; %s skipped", feed_name
                )
                await feed_health_helper.mark_unconfigured(
                    session,
                    feed_name=feed_name,
                    detail="System organisation not provisioned",
                )
                await session.commit()
                return

            targets = await _load_targets(session, org_id, kind)
            if not targets:
                await feed_health_helper.mark_unconfigured(
                    session,
                    feed_name=feed_name,
                    organization_id=org_id,
                    detail=(
                        f"No active CrawlerTarget rows of kind={kind.value!r}. "
                        f"Add targets via /api/v1/admin/crawler-targets."
                    ),
                )
                await session.commit()
                return

            kwargs = {kwarg_name: _wrap_targets(targets)}
            crawler = crawler_class(**kwargs)
            started = time.monotonic()
            try:
                pipeline = IngestionPipeline(session)
                rows = await pipeline.ingest_from_crawler(crawler)
            except Exception as exc:  # noqa: BLE001
                duration_ms = int((time.monotonic() - started) * 1000)
                logger.exception(
                    "[scheduler] %s crawl failed: %s", feed_name, exc
                )
                await feed_health_helper.mark_failure(
                    session,
                    feed_name=feed_name,
                    organization_id=org_id,
                    error=exc,
                    duration_ms=duration_ms,
                )
                # Bump consecutive_failures on each affected target.
                for t in targets:
                    t.consecutive_failures = (t.consecutive_failures or 0) + 1
                    t.last_run_at = datetime.now(timezone.utc)
                    t.last_run_status = "error"
                    t.last_run_summary = {"error": str(exc)[:300]}
                await session.commit()
                return

            duration_ms = int((time.monotonic() - started) * 1000)
            await feed_health_helper.mark_ok(
                session,
                feed_name=feed_name,
                organization_id=org_id,
                rows_ingested=int(rows or 0),
                duration_ms=duration_ms,
                detail=f"targets={len(targets)}",
            )
            for t in targets:
                t.consecutive_failures = 0
                t.last_run_at = datetime.now(timezone.utc)
                t.last_run_status = "ok"
                t.last_run_summary = {"rows_ingested": int(rows or 0)}
            await session.commit()
            logger.info(
                "[scheduler] %s complete — %s rows in %dms",
                feed_name, rows, duration_ms,
            )

    async def run_once(self, kind: CrawlerKind | None = None) -> None:
        """Manual single-tick trigger; used by tests and ops scripts."""
        targets = (
            list(_CRAWLER_REGISTRY.items())
            if kind is None
            else [(kind, _CRAWLER_REGISTRY[kind])]
        )
        for k, (cls, kwarg_name, _interval) in targets:
            await self._run_kind_once(k, cls, kwarg_name, f"crawler.{k.value}")


__all__ = ["Scheduler"]
