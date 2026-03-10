"""Crawl scheduler — orchestrates periodic crawler runs across all underground sources."""

import asyncio
import logging
from datetime import datetime, timezone

from src.crawlers.tor_crawler import TorForumCrawler, TorMarketplaceCrawler
from src.crawlers.telegram_crawler import TelegramCrawler
from src.crawlers.i2p_crawler import I2PEepsiteCrawler
from src.crawlers.lokinet_crawler import LokinetCrawler
from src.crawlers.stealer_crawler import StealerLogCrawler
from src.crawlers.ransomware_crawler import RansomwareLeakCrawler
from src.crawlers.forum_crawler import ForumCrawler
from src.crawlers.matrix_crawler import MatrixCrawler
from src.ingestion.pipeline import IngestionPipeline
from src.storage.database import get_session

logger = logging.getLogger(__name__)


class CrawlSchedule:
    """Defines when and how often a crawler should run."""

    def __init__(self, crawler_class, interval_minutes: int, **kwargs):
        self.crawler_class = crawler_class
        self.interval = interval_minutes * 60
        self.kwargs = kwargs
        self.last_run: datetime | None = None


# Default crawl schedules — underground sources only
DEFAULT_SCHEDULES = [
    # Dark web forums & marketplaces (Tor)
    CrawlSchedule(TorForumCrawler, interval_minutes=30),
    CrawlSchedule(TorMarketplaceCrawler, interval_minutes=30),

    # Telegram threat channels — fast-moving, check frequently
    CrawlSchedule(TelegramCrawler, interval_minutes=10),

    # I2P eepsites — slow network, less frequent
    CrawlSchedule(I2PEepsiteCrawler, interval_minutes=60),

    # Lokinet — emerging, moderate frequency
    CrawlSchedule(LokinetCrawler, interval_minutes=60),

    # Stealer log markets — time-critical, check often
    CrawlSchedule(StealerLogCrawler, interval_minutes=15),

    # Ransomware leak sites — check for new victims
    CrawlSchedule(RansomwareLeakCrawler, interval_minutes=20),

    # Underground forums (RU/CN/EN)
    CrawlSchedule(ForumCrawler, interval_minutes=30),

    # Matrix rooms — moderate frequency
    CrawlSchedule(MatrixCrawler, interval_minutes=30),
]


class Scheduler:
    """Runs crawlers on schedule and feeds results through the pipeline."""

    def __init__(self, schedules: list[CrawlSchedule] | None = None):
        self.schedules = schedules or DEFAULT_SCHEDULES
        self._running = False

    async def start(self):
        """Start the scheduler loop."""
        self._running = True
        logger.info(f"[scheduler] Starting with {len(self.schedules)} crawlers")

        tasks = [self._run_schedule(schedule) for schedule in self.schedules]
        await asyncio.gather(*tasks)

    async def stop(self):
        self._running = False

    async def _run_schedule(self, schedule: CrawlSchedule):
        """Run a single crawler on its schedule."""
        while self._running:
            try:
                crawler = schedule.crawler_class(**schedule.kwargs)
                logger.info(f"[scheduler] Running {crawler.name}")

                async for session in get_session():
                    pipeline = IngestionPipeline(session)
                    alert_count = await pipeline.ingest_from_crawler(crawler)
                    logger.info(
                        f"[scheduler] {crawler.name} complete — {alert_count} new alerts"
                    )

                schedule.last_run = datetime.now(timezone.utc)

            except Exception as e:
                logger.error(f"[scheduler] {schedule.crawler_class.__name__} failed: {e}")

            await asyncio.sleep(schedule.interval)

    async def run_once(self, crawler_name: str | None = None):
        """Run crawlers once (for testing / manual trigger)."""
        for schedule in self.schedules:
            crawler = schedule.crawler_class(**schedule.kwargs)
            if crawler_name and crawler.name != crawler_name:
                continue

            logger.info(f"[scheduler] Manual run: {crawler.name}")
            async for session in get_session():
                pipeline = IngestionPipeline(session)
                alert_count = await pipeline.ingest_from_crawler(crawler)
                logger.info(f"[scheduler] {crawler.name} — {alert_count} new alerts")
