"""Crawl scheduler — orchestrates periodic crawler runs."""

import asyncio
import logging
from datetime import datetime, timezone

from src.crawlers.cve_crawler import CVECrawler
from src.crawlers.github_crawler import GitHubCrawler
from src.crawlers.paste_crawler import PasteCrawler
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


# Default crawl schedules
DEFAULT_SCHEDULES = [
    CrawlSchedule(CVECrawler, interval_minutes=30),
    CrawlSchedule(PasteCrawler, interval_minutes=15),
    CrawlSchedule(GitHubCrawler, interval_minutes=60),
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
