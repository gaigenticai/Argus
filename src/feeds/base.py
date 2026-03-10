"""Base feed — all public threat intelligence feeds inherit from this."""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator

import aiohttp

from src.core.activity import ActivityType, emit as activity_emit

logger = logging.getLogger(__name__)


@dataclass
class FeedEntry:
    """Single parsed entry from a public threat intelligence feed."""
    feed_name: str
    layer: str          # "ransomware", "botnet_c2", "phishing", etc.
    entry_type: str     # "ip", "domain", "url", "hash", "victim", "cve"
    value: str
    label: str | None = None
    description: str | None = None
    severity: str = "medium"
    confidence: float = 0.7
    ip_for_geo: str | None = None  # IP to geolocate (may differ from value)
    country_code: str | None = None  # Pre-filled if feed provides country
    latitude: float | None = None    # Pre-filled if feed provides coords
    longitude: float | None = None
    feed_metadata: dict | None = None
    first_seen: datetime | None = None
    expires_hours: int = 168  # Default 7 days


class BaseFeed(ABC):
    """Abstract base for all public threat intelligence feeds.

    Unlike BaseCrawler (which scrapes HTML via Tor with stealth), feeds poll
    public structured APIs/downloads over clearnet with standard HTTP.
    """

    name: str = "base_feed"
    layer: str = "unknown"
    default_interval_seconds: int = 3600

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers={
                    "User-Agent": "Argus Threat Intelligence Platform (https://github.com/argus-ti)",
                    "Accept": "application/json, text/plain, */*",
                },
            )
        return self._session

    async def _fetch_text(self, url: str) -> str | None:
        """GET a URL, return text body or None on failure."""
        try:
            session = await self._get_session()
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.text()
                logger.warning("[%s] %s returned %d", self.name, url, resp.status)
                return None
        except Exception as e:
            logger.error("[%s] Error fetching %s: %s", self.name, url, e)
            return None

    async def _fetch_json(
        self,
        url: str,
        method: str = "GET",
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict | list | None:
        """Fetch a URL and parse JSON response."""
        try:
            session = await self._get_session()
            kwargs: dict = {}
            if headers:
                kwargs["headers"] = headers
            if params:
                kwargs["params"] = params
            if method == "POST":
                if json_body is not None:
                    kwargs["json"] = json_body
                async with session.post(url, **kwargs) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning("[%s] %s returned %d", self.name, url, resp.status)
                    return None
            else:
                async with session.get(url, **kwargs) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning("[%s] %s returned %d", self.name, url, resp.status)
                    return None
        except Exception as e:
            logger.error("[%s] Error fetching %s: %s", self.name, url, e)
            return None

    async def _fetch_csv_lines(self, url: str, skip_comments: bool = True) -> list[str]:
        """Fetch a URL and return non-empty lines (optionally skipping # comments)."""
        text = await self._fetch_text(url)
        if text is None:
            return []
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if skip_comments and line.startswith("#"):
                continue
            lines.append(line)
        return lines

    @abstractmethod
    async def poll(self) -> AsyncIterator[FeedEntry]:
        """Yield FeedEntry objects from this feed source."""
        ...

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
