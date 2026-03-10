"""Lokinet (.loki) crawler — monitors the Oxen/Lokinet anonymity network for threat intel.

This crawler accesses .loki sites on the Lokinet network, which is built on the
Oxen blockchain and uses onion routing similar to Tor but with a different
architecture. Lokinet creates a virtual network interface on the host, so .loki
addresses resolve directly through system DNS — no proxy is needed.

IMPORTANT: This is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only) and respects site policies where available.
This tool must only be operated by authorized personnel in compliance with
applicable laws and organizational security policies.
"""

import logging
import re
import socket
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from src.config.settings import settings
from src.core.activity import ActivityType, emit as activity_emit
from src.models.threat import SourceType

from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)

# Lokinet network constants
LOKI_DOMAIN_SUFFIX = ".loki"
# Well-known Lokinet SNApp for connectivity checks (Lokinet project's own site)
LOKINET_HEALTH_CHECK_HOST = "probably.loki"
LOKINET_REQUEST_TIMEOUT = 90  # seconds — faster than I2P but still overlay network
LOKINET_CONNECT_TIMEOUT = 30  # seconds

# Regex to discover .loki links in page content
LOKI_LINK_PATTERN = re.compile(
    r"https?://([a-zA-Z0-9\-]+\.loki)(?:[/\?#]\S*)?",
    re.IGNORECASE,
)
LOKI_PUBKEY_PATTERN = re.compile(
    r"https?://([a-z0-9]{52}\.loki)(?:[/\?#]\S*)?",
    re.IGNORECASE,
)


def _check_lokinet_available() -> bool:
    """Check if the Lokinet daemon is running by attempting DNS resolution.

    When Lokinet is active, it installs a virtual network interface and DNS
    resolver that can resolve .loki addresses. If resolution fails, the
    daemon is not running or not configured correctly.
    """
    try:
        socket.getaddrinfo(LOKINET_HEALTH_CHECK_HOST, 80, socket.AF_INET)
        return True
    except socket.gaierror:
        return False


class LokinetCrawler(BaseCrawler):
    """Crawls Lokinet SNApps (Server Nameable Apps) for threat intelligence.

    Lokinet is built on the Oxen network and uses Session-based onion routing.
    Unlike Tor or I2P, Lokinet operates at the IP layer via a virtual network
    interface, so .loki addresses are resolved through the system DNS once
    the Lokinet daemon is running — no proxy configuration is needed.

    Site targets are configured per-deployment by the customer.
    """

    name = "lokinet_crawler"
    source_type = SourceType.LOKINET

    def __init__(
        self,
        site_configs: list[dict] | None = None,
        *,
        discover_new_sites: bool = True,
        skip_health_check: bool = False,
    ):
        super().__init__()
        self.site_configs = site_configs or []
        self.discover_new_sites = discover_new_sites
        self.skip_health_check = skip_health_check
        # Track .loki sites discovered during this crawl session
        self._discovered_loki_sites: set[str] = set()
        # Track already-known site hostnames
        self._known_loki_sites: set[str] = {
            urlparse(cfg.get("base_url", "")).hostname
            for cfg in self.site_configs
            if cfg.get("base_url")
        }

    # ------------------------------------------------------------------
    # Session management — Lokinet needs no proxy, just custom timeouts
    # ------------------------------------------------------------------

    async def _get_lokinet_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session for Lokinet requests.

        No proxy is needed — the Lokinet daemon handles .loki DNS resolution
        at the system level via its virtual network interface.
        """
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=LOKINET_REQUEST_TIMEOUT,
                connect=LOKINET_CONNECT_TIMEOUT,
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": self._random_ua()},
            )
        return self._session

    async def _fetch_loki(self, url: str) -> str | None:
        """Fetch a .loki URL with retry logic and Lokinet-aware error handling."""
        async with self._semaphore:
            await activity_emit(
                ActivityType.CRAWLER_FETCH,
                self.name,
                f"Fetching Lokinet SNApp: {url}",
                {"url": url},
            )

            for attempt in range(settings.crawler.max_retries):
                try:
                    session = await self._get_lokinet_session()
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.text()
                        logger.warning(
                            "[%s] %s returned %d (attempt %d)",
                            self.name, url, resp.status, attempt + 1,
                        )
                except aiohttp.ClientConnectorError as e:
                    # DNS resolution failure typically means Lokinet is down
                    # or this specific .loki address is unreachable
                    if "Name or service not known" in str(e) or "nodename nor servname" in str(e):
                        logger.error(
                            "[%s] DNS resolution failed for %s — Lokinet daemon may not be running: %s",
                            self.name, url, e,
                        )
                        await activity_emit(
                            ActivityType.CRAWLER_ERROR,
                            self.name,
                            f"Lokinet DNS resolution failed: {url}",
                            {"url": url, "error": str(e)},
                            severity="error",
                        )
                        # No point retrying if Lokinet itself is down
                        return None
                    logger.error(
                        "[%s] Connection error for %s: %s (attempt %d)",
                        self.name, url, e, attempt + 1,
                    )
                    await activity_emit(
                        ActivityType.CRAWLER_ERROR,
                        self.name,
                        f"Lokinet connection error: {e}",
                        {"url": url, "attempt": attempt + 1},
                        severity="warning",
                    )
                except Exception as e:
                    logger.error(
                        "[%s] Error fetching %s: %s (attempt %d)",
                        self.name, url, e, attempt + 1,
                    )
                    await activity_emit(
                        ActivityType.CRAWLER_ERROR,
                        self.name,
                        f"Lokinet fetch error: {e}",
                        {"url": url, "attempt": attempt + 1},
                        severity="warning",
                    )

                if attempt < settings.crawler.max_retries - 1:
                    await self._delay()

            return None

    # ------------------------------------------------------------------
    # Link discovery
    # ------------------------------------------------------------------

    def _extract_loki_links(self, html: str, base_url: str) -> set[str]:
        """Extract .loki links from HTML content for site discovery."""
        found: set[str] = set()

        # Extract from href attributes
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.hostname and parsed.hostname.endswith(LOKI_DOMAIN_SUFFIX):
                found.add(parsed.hostname)

        # Extract from raw text
        for match in LOKI_LINK_PATTERN.finditer(html):
            found.add(match.group(1).lower())
        for match in LOKI_PUBKEY_PATTERN.finditer(html):
            found.add(match.group(1).lower())

        return found

    def _record_discovered_sites(self, hostnames: set[str]) -> None:
        """Track newly discovered .loki sites and log them."""
        for hostname in hostnames:
            if hostname not in self._known_loki_sites and hostname not in self._discovered_loki_sites:
                self._discovered_loki_sites.add(hostname)
                logger.info(
                    "[%s] Discovered new Lokinet SNApp: %s",
                    self.name, hostname,
                )

    # ------------------------------------------------------------------
    # Crawl implementation
    # ------------------------------------------------------------------

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        """Crawl configured Lokinet sites and yield threat intelligence results."""
        # Verify Lokinet daemon connectivity before starting the crawl
        if not self.skip_health_check:
            lokinet_up = _check_lokinet_available()
            if not lokinet_up:
                logger.error(
                    "[%s] Lokinet daemon is not running or not resolving .loki addresses. "
                    "Ensure the lokinet service is active. Aborting crawl.",
                    self.name,
                )
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    "Lokinet daemon not available — cannot resolve .loki addresses",
                    {"health_check_host": LOKINET_HEALTH_CHECK_HOST},
                    severity="error",
                )
                return

        await activity_emit(
            ActivityType.CRAWLER_START,
            self.name,
            f"Starting Lokinet crawl ({len(self.site_configs)} configured sites)",
            {"site_count": len(self.site_configs)},
        )

        for config in self.site_configs:
            try:
                async for result in self._crawl_loki_site(config):
                    yield result
            except Exception as e:
                logger.error(
                    "[%s] Failed to crawl %s: %s",
                    self.name, config.get("name", "unknown"), e,
                )
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    f"Lokinet site crawl failed: {config.get('name', 'unknown')} — {e}",
                    {"site": config.get("name"), "error": str(e)},
                    severity="error",
                )

        if self._discovered_loki_sites:
            logger.info(
                "[%s] Session discovered %d new Lokinet SNApps: %s",
                self.name,
                len(self._discovered_loki_sites),
                ", ".join(sorted(self._discovered_loki_sites)),
            )

        await activity_emit(
            ActivityType.CRAWLER_COMPLETE,
            self.name,
            f"Lokinet crawl complete — discovered {len(self._discovered_loki_sites)} new SNApps",
            {"discovered_loki_sites": sorted(self._discovered_loki_sites)},
        )

    async def _crawl_loki_site(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Crawl a single Lokinet site based on its configuration.

        Config format:
        {
            "name": "site_name",
            "base_url": "http://xxxxx.loki",
            "index_path": "/forum/",
            "thread_selector": "a.thread-link",     # CSS selector for thread links
            "post_selector": "div.post-body",        # CSS selector for post content
            "author_selector": "span.post-author",   # CSS selector for author
            "date_selector": "span.post-date",       # CSS selector for date
            "pagination_selector": "a.next-page",    # CSS selector for next page
            "max_pages": 3,
            "max_threads": 15,
            "site_type": "forum",                    # "forum" or "marketplace"
        }
        """
        base_url = config["base_url"]
        site_type = config.get("site_type", "forum")

        logger.info("[%s] Crawling Lokinet site: %s (%s)", self.name, config["name"], base_url)

        index_url = urljoin(base_url, config.get("index_path", "/"))
        html = await self._fetch_loki(index_url)
        if not html:
            logger.warning("[%s] Could not reach Lokinet site %s", self.name, config["name"])
            return

        # Discover new .loki sites from the index page
        if self.discover_new_sites:
            discovered = self._extract_loki_links(html, base_url)
            self._record_discovered_sites(discovered)

        if site_type == "marketplace":
            async for result in self._parse_marketplace(html, config, base_url):
                yield result
        else:
            async for result in self._parse_forum(html, config, base_url):
                yield result

    async def _parse_forum(
        self, index_html: str, config: dict, base_url: str,
    ) -> AsyncIterator[CrawlResult]:
        """Parse forum-style Lokinet site pages."""
        soup = BeautifulSoup(index_html, "html.parser")

        thread_selector = config.get(
            "thread_selector", "a[href*='thread'], a[href*='topic'], a[href*='viewtopic']",
        )
        thread_links: list[tuple[str, str]] = []
        for a in soup.select(thread_selector):
            href = a.get("href", "")
            if href:
                full_url = urljoin(base_url, href)
                thread_links.append((full_url, a.get_text(strip=True)))

        logger.info(
            "[%s] Found %d threads on %s",
            self.name, len(thread_links), config["name"],
        )

        max_threads = config.get("max_threads", 15)
        for thread_url, thread_title in thread_links[:max_threads]:
            await self._delay()

            thread_html = await self._fetch_loki(thread_url)
            if not thread_html:
                continue

            # Discover .loki sites from thread pages
            if self.discover_new_sites:
                discovered = self._extract_loki_links(thread_html, base_url)
                self._record_discovered_sites(discovered)

            thread_soup = BeautifulSoup(thread_html, "html.parser")
            post_selector = config.get(
                "post_selector", "div.post, div.message-body, article, div.content",
            )
            posts = thread_soup.select(post_selector)

            for post in posts:
                content = post.get_text(strip=True)
                if not content or len(content) < 30:
                    continue

                # Try to extract author
                author = None
                author_sel = config.get("author_selector")
                if author_sel:
                    author_el = post.find_previous(author_sel) or post.select_one(author_sel)
                    if author_el:
                        author = author_el.get_text(strip=True)

                yield CrawlResult(
                    source_type=self.source_type,
                    source_url=thread_url,
                    source_name=config["name"],
                    title=thread_title,
                    content=content,
                    author=author,
                    published_at=datetime.now(timezone.utc),
                    raw_data={
                        "network": "lokinet",
                        "site": config["name"],
                        "thread_url": thread_url,
                        "thread_title": thread_title,
                    },
                )

    async def _parse_marketplace(
        self, index_html: str, config: dict, base_url: str,
    ) -> AsyncIterator[CrawlResult]:
        """Parse marketplace-style Lokinet site pages."""
        for category_path in config.get("categories", ["/"]):
            if category_path == "/":
                html = index_html
            else:
                category_url = urljoin(base_url, category_path)
                await self._delay()
                html = await self._fetch_loki(category_url)
                if not html:
                    continue

            if self.discover_new_sites:
                discovered = self._extract_loki_links(html, base_url)
                self._record_discovered_sites(discovered)

            soup = BeautifulSoup(html, "html.parser")
            listing_selector = config.get("listing_selector", "div.listing, div.product, tr.item")
            listings = soup.select(listing_selector)

            for listing in listings[:config.get("max_listings", 50)]:
                title_el = listing.select_one(config.get("title_selector", "h3, h4, .title, a"))
                desc_el = listing.select_one(config.get("desc_selector", ".description, .desc, p"))
                price_el = listing.select_one(config.get("price_selector", ".price"))
                vendor_el = listing.select_one(config.get("vendor_selector", ".vendor, .seller"))

                title = title_el.get_text(strip=True) if title_el else "Unknown Listing"
                description = desc_el.get_text(strip=True) if desc_el else ""
                price = price_el.get_text(strip=True) if price_el else "N/A"
                vendor = vendor_el.get_text(strip=True) if vendor_el else "Unknown"

                content = f"Listing: {title}\nVendor: {vendor}\nPrice: {price}\n\n{description}"

                if len(content.strip()) < 30:
                    continue

                yield CrawlResult(
                    source_type=self.source_type,
                    source_url=urljoin(base_url, category_path),
                    source_name=config["name"],
                    title=title,
                    content=content,
                    author=vendor,
                    raw_data={
                        "network": "lokinet",
                        "site": config["name"],
                        "category": category_path,
                        "price": price,
                        "vendor": vendor,
                    },
                )

            await self._delay()

    @property
    def discovered_loki_sites(self) -> frozenset[str]:
        """Return the set of .loki hostnames discovered during this session."""
        return frozenset(self._discovered_loki_sites)
