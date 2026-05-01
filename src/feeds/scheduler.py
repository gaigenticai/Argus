"""Feed scheduler — polls public threat intel feeds on configured intervals."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from src.feeds.base import BaseFeed
from src.feeds.geolocation import GeoLocator
from src.feeds.pipeline import FeedIngestionPipeline
from src.storage.database import get_session

# ---------------------------------------------------------------------------
# Feed imports — each maps to one public threat intelligence source
# ---------------------------------------------------------------------------
from src.feeds.botnet_feed import BotnetFeed
from src.feeds.honeypot_feed import HoneypotFeed
from src.feeds.ip_reputation_feed import IPReputationFeed
from src.feeds.kev_feed import KEVFeed
from src.feeds.malware_feed import MalwareFeed
from src.feeds.phishing_feed import PhishingFeed
from src.feeds.ransomware_feed import RansomwareFeed
from src.feeds.ssl_feed import SSLFeed
from src.feeds.tor_nodes_feed import TorNodesFeed
from src.feeds.greynoise_feed import GreyNoiseFeed
from src.feeds.otx_feed import OTXFeed
from src.feeds.bgp_hijack_feed import BGPHijackFeed
# P1 #1.7 — five commercial-licensable feeds
from src.feeds.certstream_feed import CertStreamFeed
from src.feeds.circl_misp_feed import CIRCLMispFeed
from src.feeds.phishtank_certpl_feed import PhishTankCertPLFeed
from src.feeds.ghsa_exploitdb_feed import GHSAExploitDBFeed
from src.feeds.abusech_tls_feed import AbuseChTLSFeed

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schedule definition
# ---------------------------------------------------------------------------


class FeedSchedule:
    """Pairs a feed class with its polling interval and optional constructor kwargs."""

    def __init__(
        self,
        feed_class: type[BaseFeed],
        interval_seconds: int,
        **kwargs,
    ):
        self.feed_class = feed_class
        self.interval = interval_seconds
        self.kwargs = kwargs
        self.last_run: datetime | None = None


# Ordered from fastest to slowest cadence.
DEFAULT_FEED_SCHEDULES: list[FeedSchedule] = [
    FeedSchedule(HoneypotFeed, interval_seconds=300),        # 5 min  — DShield infocon
    FeedSchedule(TorNodesFeed, interval_seconds=1800),       # 30 min
    FeedSchedule(BotnetFeed, interval_seconds=3600),         # 1 hour
    FeedSchedule(MalwareFeed, interval_seconds=3600),        # 1 hour
    FeedSchedule(IPReputationFeed, interval_seconds=3600),   # 1 hour
    FeedSchedule(SSLFeed, interval_seconds=3600),            # 1 hour
    FeedSchedule(PhishingFeed, interval_seconds=21600),      # 6 hours
    FeedSchedule(RansomwareFeed, interval_seconds=21600),    # 6 hours
    FeedSchedule(KEVFeed, interval_seconds=86400),           # 24 hours
    FeedSchedule(GreyNoiseFeed, interval_seconds=3600),      # 1 hour — GNQL scanner intel
    FeedSchedule(OTXFeed, interval_seconds=3600),            # 1 hour — OTX community pulses
    FeedSchedule(BGPHijackFeed, interval_seconds=3600),      # 1 hour — Cloudflare Radar BGP hijacks
    # P1 #1.7 — five commercial-licensable feeds (license verified
    # against each provider's published terms; all four below are CC0
    # / open-data / public, no operator API key required to bootstrap).
    FeedSchedule(CertStreamFeed, interval_seconds=1800),     # 30 min — crt.sh CT logs
    FeedSchedule(CIRCLMispFeed, interval_seconds=21600),     # 6 hours — CIRCL OSINT MISP
    FeedSchedule(PhishTankCertPLFeed, interval_seconds=21600),  # 6 hours
    FeedSchedule(GHSAExploitDBFeed, interval_seconds=86400),    # 24 hours
    FeedSchedule(AbuseChTLSFeed, interval_seconds=21600),    # 6 hours — SSLBL + JA3
]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class FeedScheduler:
    """Polls public threat intel feeds on their configured intervals.

    Usage::

        scheduler = FeedScheduler()
        await scheduler.start()   # blocks until stop() is called
    """

    def __init__(self, schedules: list[FeedSchedule] | None = None):
        self.schedules = schedules or DEFAULT_FEED_SCHEDULES
        self._running = False
        self._geolocator: GeoLocator | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch all feed loops concurrently.  Blocks until ``stop()``."""
        self._running = True
        self._geolocator = GeoLocator()
        logger.info(
            "[feed-scheduler] Starting with %d feeds",
            len(self.schedules),
        )
        tasks = [self._run_schedule(schedule) for schedule in self.schedules]
        try:
            await asyncio.gather(*tasks)
        finally:
            if self._geolocator:
                self._geolocator.close()

    async def stop(self) -> None:
        """Signal all feed loops to exit after their current iteration."""
        self._running = False
        logger.info("[feed-scheduler] Stop requested")

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _run_schedule(self, schedule: FeedSchedule) -> None:
        while self._running:
            await self._run_one(schedule)
            schedule.last_run = datetime.now(timezone.utc)
            if schedule.interval > 0:
                await asyncio.sleep(schedule.interval)
            else:
                # interval=0 means persistent connection (e.g. BGP WebSocket).
                # If it exits, back off 60 s before reconnecting.
                await asyncio.sleep(60)

    async def _run_one(self, schedule: FeedSchedule) -> None:
        """Execute one tick of a feed, recording a FeedHealth row.

        FeedHealth recording rules:
            * Feed sets ``last_unconfigured_reason`` (e.g. missing API
              key) → status=unconfigured, rows=0.
            * Feed raises → status=network_error (or whatever the
              subclass classified it as via ``last_failure_classification``).
            * Otherwise the count of ingested entries lands as
              status=ok, rows=N.
        """
        import time as _time

        from src.core import feed_health as _feed_health
        from src.models.admin import FeedHealthStatus

        feed = schedule.feed_class(**schedule.kwargs)
        logger.info("[feed-scheduler] Running %s", feed.name)
        t0 = _time.monotonic()
        new_count = 0
        crashed: BaseException | None = None
        try:
            async for session in get_session():
                pipeline = FeedIngestionPipeline(session, self._geolocator)
                new_count = await pipeline.ingest_from_feed(feed)
                logger.info(
                    "[feed-scheduler] %s complete — %d new entries",
                    feed.name, new_count,
                )
        except Exception as exc:  # noqa: BLE001
            crashed = exc
            logger.exception(
                "[feed-scheduler] %s failed", schedule.feed_class.__name__,
            )

        duration_ms = int((_time.monotonic() - t0) * 1000)
        async for session in get_session():
            try:
                if crashed is not None:
                    await _feed_health.mark_failure(
                        session,
                        feed_name=feed.name,
                        error=crashed,
                        duration_ms=duration_ms,
                        classify=(
                            feed.last_failure_classification
                            or FeedHealthStatus.NETWORK_ERROR.value
                        ),
                    )
                elif feed.last_unconfigured_reason:
                    await _feed_health.mark_unconfigured(
                        session,
                        feed_name=feed.name,
                        detail=feed.last_unconfigured_reason,
                    )
                elif feed.last_failure_reason:
                    await _feed_health.mark_failure(
                        session,
                        feed_name=feed.name,
                        error=feed.last_failure_reason,
                        duration_ms=duration_ms,
                        classify=(
                            feed.last_failure_classification
                            or FeedHealthStatus.NETWORK_ERROR.value
                        ),
                    )
                else:
                    await _feed_health.mark_ok(
                        session,
                        feed_name=feed.name,
                        rows_ingested=int(new_count or 0),
                        duration_ms=duration_ms,
                    )
                await session.commit()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "[feed-scheduler] could not record FeedHealth for %s",
                    feed.name,
                )

    # ------------------------------------------------------------------
    # Manual / test helpers
    # ------------------------------------------------------------------

    async def run_once(self, feed_name: str | None = None) -> None:
        """Run feeds once (useful for testing or manual triggers).

        Args:
            feed_name: If provided, only the feed whose ``name`` matches
                       will be executed.  Otherwise every scheduled feed runs.
        """
        if not self._geolocator:
            self._geolocator = GeoLocator()
        try:
            for schedule in self.schedules:
                # Instantiate just to read .name for filtering — _run_one
                # builds a fresh instance for the actual run so feed
                # state (last_unconfigured_reason, last_failure_reason)
                # is always clean per tick.
                if feed_name:
                    probe = schedule.feed_class(**schedule.kwargs)
                    if probe.name != feed_name:
                        continue
                logger.info(
                    "[feed-scheduler] Manual run: %s",
                    schedule.feed_class.__name__,
                )
                await self._run_one(schedule)
        finally:
            if self._geolocator:
                self._geolocator.close()
                self._geolocator = None
