"""Base crawler — all crawlers inherit from this."""

import asyncio
import hashlib
import logging
import random
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import AsyncIterator

import aiohttp
from aiohttp_socks import ProxyConnector

from src.config.settings import settings
from src.models.threat import SourceType

logger = logging.getLogger(__name__)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


class CrawlResult:
    """Single piece of collected intelligence."""

    def __init__(
        self,
        source_type: SourceType,
        source_url: str | None,
        source_name: str,
        title: str | None,
        content: str,
        author: str | None = None,
        published_at: datetime | None = None,
        raw_data: dict | None = None,
    ):
        self.source_type = source_type
        self.source_url = source_url
        self.source_name = source_name
        self.title = title
        self.content = content
        self.author = author
        self.published_at = published_at
        self.raw_data = raw_data
        self.collected_at = datetime.now(timezone.utc)

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()


class BaseCrawler(ABC):
    """Abstract base for all Argus crawlers."""

    name: str = "base"
    source_type: SourceType = SourceType.SURFACE_WEB

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None
        self._semaphore = asyncio.Semaphore(settings.crawler.max_concurrent)

    async def _get_session(self, use_tor: bool = False) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = None
            if use_tor:
                connector = ProxyConnector.from_url(settings.tor.socks_proxy)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=settings.crawler.timeout),
                headers={"User-Agent": self._random_ua()},
            )
        return self._session

    def _random_ua(self) -> str:
        if settings.crawler.user_agent_rotate:
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]

    async def _delay(self):
        delay = random.uniform(
            settings.crawler.request_delay_min,
            settings.crawler.request_delay_max,
        )
        await asyncio.sleep(delay)

    async def _fetch(self, url: str, use_tor: bool = False) -> str | None:
        async with self._semaphore:
            for attempt in range(settings.crawler.max_retries):
                try:
                    session = await self._get_session(use_tor=use_tor)
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.text()
                        logger.warning(
                            f"[{self.name}] {url} returned {resp.status} (attempt {attempt + 1})"
                        )
                except Exception as e:
                    logger.error(f"[{self.name}] Error fetching {url}: {e} (attempt {attempt + 1})")

                if attempt < settings.crawler.max_retries - 1:
                    await self._delay()

            return None

    @abstractmethod
    async def crawl(self) -> AsyncIterator[CrawlResult]:
        """Yield CrawlResults from this source."""
        ...

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
