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
            try:
                feed = schedule.feed_class(**schedule.kwargs)
                logger.info("[feed-scheduler] Running %s", feed.name)
                async for session in get_session():
                    pipeline = FeedIngestionPipeline(session, self._geolocator)
                    new_count = await pipeline.ingest_from_feed(feed)
                    logger.info(
                        "[feed-scheduler] %s complete — %d new entries",
                        feed.name,
                        new_count,
                    )
                schedule.last_run = datetime.now(timezone.utc)
            except Exception:
                logger.exception(
                    "[feed-scheduler] %s failed",
                    schedule.feed_class.__name__,
                )

            if schedule.interval > 0:
                await asyncio.sleep(schedule.interval)
            else:
                # interval=0 means persistent connection (e.g. BGP WebSocket).
                # If it exits, back off 60 s before reconnecting.
                await asyncio.sleep(60)

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
                feed = schedule.feed_class(**schedule.kwargs)
                if feed_name and feed.name != feed_name:
                    continue
                logger.info("[feed-scheduler] Manual run: %s", feed.name)
                async for session in get_session():
                    pipeline = FeedIngestionPipeline(session, self._geolocator)
                    new_count = await pipeline.ingest_from_feed(feed)
                    logger.info(
                        "[feed-scheduler] %s — %d new entries",
                        feed.name,
                        new_count,
                    )
        finally:
            if self._geolocator:
                self._geolocator.close()
                self._geolocator = None
