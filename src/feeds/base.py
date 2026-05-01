"""Base feed — all public threat intelligence feeds inherit from this."""

from __future__ import annotations


import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator

import aiohttp

from src.core.activity import ActivityType, emit as activity_emit
from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

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

    Health surfacing
    ----------------
    A feed that returns zero entries can be in one of three real
    states: configured + nothing new, missing credentials, or
    upstream broken. Subclasses set ``self.last_unconfigured_reason``
    to a non-empty string when ``poll`` aborts due to missing
    credentials; the worker reads that flag after iteration ends and
    persists a ``FeedHealth`` row with status=unconfigured. When
    ``last_failure_reason`` is set instead, status is recorded as
    ``network_error`` (or whatever string the subclass classified it
    as). Callers who don't set either flag get the default OK record.
    """

    name: str = "base_feed"
    layer: str = "unknown"
    default_interval_seconds: int = 3600

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None
        # Surfaced to the worker after ``poll`` completes; consumed by
        # the FeedHealth recorder. Resetting them here means each
        # invocation of poll starts with a clean slate.
        self.last_unconfigured_reason: str | None = None
        self.last_failure_reason: str | None = None
        self.last_failure_classification: str | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            from src.core.opsec import randomize_headers

            headers = randomize_headers()
            headers["Accept"] = "application/json, text/plain, */*"
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers=headers,
            )
        return self._session

    async def _fetch_text(self, url: str) -> str | None:
        """GET a URL, return text body or None on failure.

        Failures are surfaced via ``self.last_failure_reason`` /
        ``last_failure_classification`` so the scheduler's FeedHealth
        recorder distinguishes "feed ran clean and saw nothing" from
        "upstream broken / rate-limited".
        """
        from src.models.admin import FeedHealthStatus

        breaker = get_breaker(f"feed:{self.name}")
        try:
            async with breaker:
                session = await self._get_session()
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    logger.warning("[%s] %s returned %d", self.name, url, resp.status)
                    self.last_failure_reason = f"{url}: HTTP {resp.status}"
                    if resp.status == 429:
                        self.last_failure_classification = FeedHealthStatus.RATE_LIMITED.value
                    elif resp.status in (401, 403):
                        self.last_failure_classification = FeedHealthStatus.AUTH_ERROR.value
                        # 4xx auth failures are configuration errors,
                        # not upstream outages. Don't trip the breaker.
                        return None
                    else:
                        self.last_failure_classification = FeedHealthStatus.NETWORK_ERROR.value
                    raise aiohttp.ClientResponseError(
                        request_info=resp.request_info,
                        history=resp.history,
                        status=resp.status,
                        message=f"HTTP {resp.status}",
                    )
        except CircuitBreakerOpenError as e:
            self.last_failure_reason = f"{url}: {e}"
            self.last_failure_classification = FeedHealthStatus.NETWORK_ERROR.value
            return None
        except Exception as e:
            logger.error("[%s] Error fetching %s: %s", self.name, url, e)
            self.last_failure_reason = f"{url}: {type(e).__name__}: {e}"
            if not self.last_failure_classification:
                self.last_failure_classification = FeedHealthStatus.NETWORK_ERROR.value
            return None

    async def _fetch_json(
        self,
        url: str,
        method: str = "GET",
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict | list | None:
        """Fetch a URL and parse JSON response.

        Failures are surfaced via ``self.last_failure_reason`` /
        ``last_failure_classification`` so the scheduler's FeedHealth
        recorder distinguishes "feed ran clean and saw nothing" from
        "upstream broken / rate-limited".
        """
        from src.models.admin import FeedHealthStatus

        def _classify(status: int) -> str:
            if status == 429:
                return FeedHealthStatus.RATE_LIMITED.value
            if status in (401, 403):
                return FeedHealthStatus.AUTH_ERROR.value
            return FeedHealthStatus.NETWORK_ERROR.value

        breaker = get_breaker(f"feed:{self.name}")
        try:
            async with breaker:
                session = await self._get_session()
                kwargs: dict = {}
                if headers:
                    kwargs["headers"] = headers
                if params:
                    kwargs["params"] = params
                if method == "POST":
                    if json_body is not None:
                        kwargs["json"] = json_body
                    ctx = session.post(url, **kwargs)
                else:
                    ctx = session.get(url, **kwargs)
                async with ctx as resp:
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning("[%s] %s returned %d", self.name, url, resp.status)
                    self.last_failure_reason = f"{url}: HTTP {resp.status}"
                    self.last_failure_classification = _classify(resp.status)
                    # Auth misconfig is the operator's bug — don't
                    # cool off the upstream for it.
                    if resp.status in (401, 403):
                        return None
                    raise aiohttp.ClientResponseError(
                        request_info=resp.request_info,
                        history=resp.history,
                        status=resp.status,
                        message=f"HTTP {resp.status}",
                    )
        except CircuitBreakerOpenError as e:
            self.last_failure_reason = f"{url}: {e}"
            self.last_failure_classification = FeedHealthStatus.NETWORK_ERROR.value
            return None
        except ValueError as e:
            # JSON decode error — distinguish from network failure.
            logger.error("[%s] Parse error for %s: %s", self.name, url, e)
            self.last_failure_reason = f"{url}: JSON decode failed: {e}"
            self.last_failure_classification = FeedHealthStatus.PARSE_ERROR.value
            return None
        except Exception as e:
            logger.error("[%s] Error fetching %s: %s", self.name, url, e)
            self.last_failure_reason = f"{url}: {type(e).__name__}: {e}"
            if not self.last_failure_classification:
                self.last_failure_classification = FeedHealthStatus.NETWORK_ERROR.value
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
