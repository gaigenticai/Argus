"""Base crawler — all crawlers inherit from this."""

from __future__ import annotations


import asyncio
import hashlib
import logging
import random
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import AsyncIterator, Sequence
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup, Tag

from src.config.settings import settings
from src.core.activity import ActivityType, emit as activity_emit
from src.core.http_circuit import CircuitBreakerOpenError, get_breaker
from src.models.threat import SourceType

logger = logging.getLogger(__name__)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_UNDERGROUND_TLDS = frozenset({".onion", ".i2p", ".loki"})
_STRUCTURE_HASH_MAX_ELEMENTS = 500


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
                # aiohttp_socks 0.11+ rejected the ``socks5h://`` scheme; the
                # canonical way to request remote DNS resolution (essential
                # for .onion addresses, since they aren't real DNS names)
                # is ``socks5://`` plus ``rdns=True``. We rewrite a legacy
                # ``socks5h://`` config to ``socks5://`` so existing .env
                # files keep working.
                from aiohttp_socks import ProxyType
                proxy_url = settings.tor.socks_proxy.replace(
                    "socks5h://", "socks5://", 1
                )
                from urllib.parse import urlparse
                parsed = urlparse(proxy_url)
                connector = ProxyConnector(
                    proxy_type=ProxyType.SOCKS5,
                    host=parsed.hostname,
                    port=parsed.port,
                    rdns=True,
                )

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

    @staticmethod
    def _is_underground_url(url: str) -> bool:
        """Return True if the URL targets an underground TLD (.onion, .i2p, .loki)."""
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            return False
        return any(hostname.endswith(tld) for tld in _UNDERGROUND_TLDS)

    async def _fetch(
        self,
        url: str,
        use_tor: bool = False,
        method: str = "GET",
    ) -> str | None:
        """Fetch a URL. Only GET is permitted for underground (.onion/.i2p/.loki) domains."""
        method = method.upper()

        # ── Read-only guardrail for underground URLs ──
        if method != "GET" and self._is_underground_url(url):
            logger.warning(
                "[%s] BLOCKED non-GET (%s) to underground URL: %s",
                self.name,
                method,
                url,
            )
            await activity_emit(
                ActivityType.SECURITY_BLOCKED,
                self.name,
                f"Blocked {method} request to underground URL",
                {"url": url, "method": method, "reason": "read_only_guardrail"},
                severity="critical",
            )
            return None

        # Adversarial audit D-16 — wrap the per-host fetch in the
        # shared circuit breaker so one failing onion doesn't keep
        # hammering its own service forever. Breaker is keyed by
        # destination host; failure across attempts opens it.
        host = (urlparse(url).hostname or "unknown")
        breaker = get_breaker(f"crawl:{host}")

        async with self._semaphore:
            await activity_emit(
                ActivityType.CRAWLER_FETCH,
                self.name,
                f"Fetching {url}",
                {"url": url, "use_tor": use_tor, "method": method},
            )
            try:
                async with breaker:
                    last_error: Exception | None = None
                    for attempt in range(settings.crawler.max_retries):
                        try:
                            session = await self._get_session(use_tor=use_tor)
                            async with session.request(method, url) as resp:
                                if resp.status == 200:
                                    return await resp.text()
                                logger.warning(
                                    f"[{self.name}] {url} returned {resp.status} (attempt {attempt + 1})"
                                )
                                last_error = RuntimeError(
                                    f"HTTP {resp.status} from {url}"
                                )
                        except Exception as e:  # noqa: BLE001
                            last_error = e
                            logger.error(
                                f"[{self.name}] Error fetching {url}: {e} (attempt {attempt + 1})"
                            )
                            await activity_emit(
                                ActivityType.CRAWLER_ERROR,
                                self.name,
                                f"Fetch error: {e}",
                                {"url": url, "attempt": attempt + 1},
                                severity="warning",
                            )

                        if attempt < settings.crawler.max_retries - 1:
                            await self._delay()

                    # Surface the last error so the breaker counts the
                    # failure; otherwise consecutive 5xx pages would not
                    # contribute to opening the circuit.
                    if last_error is not None:
                        raise last_error
                    return None
            except CircuitBreakerOpenError:
                logger.warning(
                    "[%s] circuit OPEN for %s — skipping fetch", self.name, host
                )
                return None
            except Exception:  # noqa: BLE001
                # Breaker has now recorded the failure; suppress so the
                # caller still gets None like the legacy contract.
                return None

    # ── Structure hash computation ────────────────────────────────

    @staticmethod
    def compute_structure_hash(html: str) -> str:
        """Hash the DOM tag structure (tag names + classes) ignoring text content.

        Examines up to ``_STRUCTURE_HASH_MAX_ELEMENTS`` elements and returns
        a SHA-256 hex digest representing the structural skeleton of the page.
        """
        soup = BeautifulSoup(html, "html.parser")
        parts: list[str] = []
        for idx, tag in enumerate(soup.descendants):
            if idx >= _STRUCTURE_HASH_MAX_ELEMENTS:
                break
            if not isinstance(tag, Tag):
                continue
            classes = " ".join(sorted(tag.get("class", [])))
            parts.append(f"{tag.name}:{classes}")
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    # ── Selector cascading ────────────────────────────────────────

    @staticmethod
    def _select_with_fallbacks(
        soup: BeautifulSoup,
        primary_selector: str,
        fallback_selectors: Sequence[str] | None = None,
    ) -> list:
        """Try *primary_selector* first; fall back through alternatives in order.

        Returns the result list from the first selector that matches at least
        one element, or an empty list if none match.
        """
        results = soup.select(primary_selector)
        if results:
            return results

        for selector in fallback_selectors or []:
            results = soup.select(selector)
            if results:
                logger.info(
                    "Primary selector %r missed — fell back to %r (%d hits)",
                    primary_selector,
                    selector,
                    len(results),
                )
                return results

        logger.warning(
            "All selectors exhausted (primary=%r, fallbacks=%s)",
            primary_selector,
            fallback_selectors,
        )
        return []

    # ── Mirror URL failover ───────────────────────────────────────

    async def _fetch_with_mirrors(
        self,
        primary_url: str,
        mirror_urls: Sequence[str] | None = None,
        use_tor: bool = False,
    ) -> tuple[str | None, str | None]:
        """Fetch *primary_url* first, then try each mirror in order on failure.

        Returns ``(html, url_used)`` — both ``None`` if every URL fails.
        """
        html = await self._fetch(primary_url, use_tor=use_tor)
        if html is not None:
            return html, primary_url

        for mirror in mirror_urls or []:
            logger.info(
                "[%s] Primary %s failed — trying mirror %s",
                self.name,
                primary_url,
                mirror,
            )
            html = await self._fetch(mirror, use_tor=use_tor)
            if html is not None:
                return html, mirror

        logger.error(
            "[%s] All URLs exhausted (primary + %d mirrors)",
            self.name,
            len(mirror_urls or []),
        )
        return None, None

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
