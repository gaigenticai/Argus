"""I2P eepsite crawler — monitors the Invisible Internet Project network for threat intel.

This crawler accesses .i2p eepsites through the local I2P HTTP proxy to monitor
forums, marketplaces, and discussion boards on the I2P anonymity network for
threat intelligence relevant to protected organizations.

IMPORTANT: This is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only) and respects site policies where available.
This tool must only be operated by authorized personnel in compliance with
applicable laws and organizational security policies.
"""

from __future__ import annotations


import logging
import re
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

# I2P network constants — read from settings so Docker Compose service names work.
I2P_PROXY_HOST = settings.i2p.proxy_host
I2P_PROXY_PORT = settings.i2p.proxy_port
I2P_DOMAIN_SUFFIX = ".i2p"
# I2P is significantly slower than Tor; use generous timeouts
I2P_REQUEST_TIMEOUT = 120  # seconds
I2P_CONNECT_TIMEOUT = 60  # seconds

# Regex to find .i2p links in page content
I2P_LINK_PATTERN = re.compile(
    r"https?://([a-zA-Z0-9\-]+\.i2p)(?:[/\?#]\S*)?",
    re.IGNORECASE,
)
I2P_BASE32_PATTERN = re.compile(
    r"https?://([a-z2-7]{52}\.b32\.i2p)(?:[/\?#]\S*)?",
    re.IGNORECASE,
)


class I2PEepsiteCrawler(BaseCrawler):
    """Crawls I2P eepsite forums and marketplaces for threat intelligence.

    I2P (Invisible Internet Project) is a separate anonymity network from Tor,
    using garlic routing instead of onion routing. Sites on I2P are called
    "eepsites" and use the .i2p TLD.

    Access requires a running I2P router with its HTTP proxy enabled
    (default: localhost:4444). Unlike Tor's SOCKS proxy, I2P uses a
    standard HTTP proxy.

    Eepsite targets are configured per-deployment by the customer.
    """

    name = "i2p_eepsite_crawler"
    source_type = SourceType.I2P

    def __init__(
        self,
        eepsite_configs: list[dict] | None = None,
        *,
        proxy_host: str = I2P_PROXY_HOST,
        proxy_port: int = I2P_PROXY_PORT,
        discover_new_sites: bool = True,
    ):
        super().__init__()
        self.eepsite_configs = eepsite_configs or []
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.discover_new_sites = discover_new_sites
        # Track eepsites discovered during this crawl session
        self._discovered_eepsites: set[str] = set()
        # Track already-known eepsite hostnames so we only log genuinely new ones
        self._known_eepsites: set[str] = {
            urlparse(cfg.get("base_url", "")).hostname
            for cfg in self.eepsite_configs
            if cfg.get("base_url")
        }

    @property
    def _proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"

    # ------------------------------------------------------------------
    # Session management — override base to use HTTP proxy for I2P
    # ------------------------------------------------------------------

    async def _get_i2p_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session routed through the I2P HTTP proxy."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=I2P_REQUEST_TIMEOUT,
                connect=I2P_CONNECT_TIMEOUT,
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": self._random_ua()},
            )
        return self._session

    async def _fetch_i2p(self, url: str) -> str | None:
        """Fetch a URL through the I2P HTTP proxy with retry logic.

        I2P tunnels are slower and less reliable than Tor circuits, so we use
        longer timeouts and more forgiving retry logic.
        """
        async with self._semaphore:
            await activity_emit(
                ActivityType.CRAWLER_FETCH,
                self.name,
                f"Fetching I2P eepsite: {url}",
                {"url": url, "proxy": self._proxy_url},
            )

            for attempt in range(settings.crawler.max_retries):
                try:
                    session = await self._get_i2p_session()
                    # Route the request through the I2P HTTP proxy
                    async with session.get(url, proxy=self._proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.text()
                        logger.warning(
                            "[%s] %s returned %d (attempt %d)",
                            self.name, url, resp.status, attempt + 1,
                        )
                except aiohttp.ClientProxyConnectionError as e:
                    logger.error(
                        "[%s] I2P proxy connection failed — is the I2P router running? %s (attempt %d)",
                        self.name, e, attempt + 1,
                    )
                    await activity_emit(
                        ActivityType.CRAWLER_ERROR,
                        self.name,
                        f"I2P proxy unreachable: {e}",
                        {"url": url, "attempt": attempt + 1},
                        severity="error",
                    )
                    # If the proxy itself is down, no point retrying immediately
                    return None
                except Exception as e:
                    logger.error(
                        "[%s] Error fetching %s: %s (attempt %d)",
                        self.name, url, e, attempt + 1,
                    )
                    await activity_emit(
                        ActivityType.CRAWLER_ERROR,
                        self.name,
                        f"I2P fetch error: {e}",
                        {"url": url, "attempt": attempt + 1},
                        severity="warning",
                    )

                if attempt < settings.crawler.max_retries - 1:
                    # Use longer delays for I2P — tunnels need time to rebuild
                    await self._delay()
                    await self._delay()  # double delay for I2P

            return None

    # ------------------------------------------------------------------
    # Link discovery
    # ------------------------------------------------------------------

    def _extract_i2p_links(self, html: str, base_url: str) -> set[str]:
        """Extract .i2p links from HTML content for eepsite discovery."""
        found: set[str] = set()

        # Extract from href attributes
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.hostname and parsed.hostname.endswith(I2P_DOMAIN_SUFFIX):
                found.add(parsed.hostname)

        # Extract from raw text (catches links in post bodies, etc.)
        for match in I2P_LINK_PATTERN.finditer(html):
            found.add(match.group(1).lower())
        for match in I2P_BASE32_PATTERN.finditer(html):
            found.add(match.group(1).lower())

        return found

    def _record_discovered_eepsites(self, hostnames: set[str]) -> None:
        """Track newly discovered eepsites and log them."""
        for hostname in hostnames:
            if hostname not in self._known_eepsites and hostname not in self._discovered_eepsites:
                self._discovered_eepsites.add(hostname)
                logger.info(
                    "[%s] Discovered new I2P eepsite: %s",
                    self.name, hostname,
                )

    # ------------------------------------------------------------------
    # Crawl implementation
    # ------------------------------------------------------------------

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        """Crawl configured I2P eepsites and yield threat intelligence results."""
        await activity_emit(
            ActivityType.CRAWLER_START,
            self.name,
            f"Starting I2P eepsite crawl ({len(self.eepsite_configs)} configured sites)",
            {"site_count": len(self.eepsite_configs)},
        )

        for config in self.eepsite_configs:
            try:
                async for result in self._crawl_eepsite(config):
                    yield result
            except Exception as e:
                logger.error(
                    "[%s] Failed to crawl %s: %s",
                    self.name, config.get("name", "unknown"), e,
                )
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    f"Eepsite crawl failed: {config.get('name', 'unknown')} — {e}",
                    {"site": config.get("name"), "error": str(e)},
                    severity="error",
                )

        if self._discovered_eepsites:
            logger.info(
                "[%s] Session discovered %d new I2P eepsites: %s",
                self.name,
                len(self._discovered_eepsites),
                ", ".join(sorted(self._discovered_eepsites)),
            )

        await activity_emit(
            ActivityType.CRAWLER_COMPLETE,
            self.name,
            f"I2P crawl complete — discovered {len(self._discovered_eepsites)} new eepsites",
            {"discovered_eepsites": sorted(self._discovered_eepsites)},
        )

    async def _crawl_eepsite(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Crawl a single I2P eepsite based on its configuration.

        Config format:
        {
            "name": "eepsite_name",
            "base_url": "http://xxxxx.i2p",
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

        logger.info("[%s] Crawling I2P eepsite: %s (%s)", self.name, config["name"], base_url)

        index_url = urljoin(base_url, config.get("index_path", "/"))
        html = await self._fetch_i2p(index_url)
        if not html:
            logger.warning("[%s] Could not reach eepsite %s", self.name, config["name"])
            return

        # Discover new eepsites from the index page
        if self.discover_new_sites:
            discovered = self._extract_i2p_links(html, base_url)
            self._record_discovered_eepsites(discovered)

        if site_type == "marketplace":
            async for result in self._parse_marketplace(html, config, base_url):
                yield result
        else:
            async for result in self._parse_forum(html, config, base_url):
                yield result

    async def _parse_forum(
        self, index_html: str, config: dict, base_url: str,
    ) -> AsyncIterator[CrawlResult]:
        """Parse forum-style eepsite pages."""
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

            thread_html = await self._fetch_i2p(thread_url)
            if not thread_html:
                continue

            # Discover eepsites from thread pages too
            if self.discover_new_sites:
                discovered = self._extract_i2p_links(thread_html, base_url)
                self._record_discovered_eepsites(discovered)

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
                        "network": "i2p",
                        "eepsite": config["name"],
                        "thread_url": thread_url,
                        "thread_title": thread_title,
                    },
                )

    async def _parse_marketplace(
        self, index_html: str, config: dict, base_url: str,
    ) -> AsyncIterator[CrawlResult]:
        """Parse marketplace-style eepsite pages."""
        for category_path in config.get("categories", ["/"]):
            if category_path == "/":
                html = index_html
            else:
                category_url = urljoin(base_url, category_path)
                await self._delay()
                html = await self._fetch_i2p(category_url)
                if not html:
                    continue

            if self.discover_new_sites:
                discovered = self._extract_i2p_links(html, base_url)
                self._record_discovered_eepsites(discovered)

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
                        "network": "i2p",
                        "eepsite": config["name"],
                        "category": category_path,
                        "price": price,
                        "vendor": vendor,
                    },
                )

            await self._delay()

    @property
    def discovered_eepsites(self) -> set[str]:
        """Return the set of eepsite hostnames discovered during this session."""
        return frozenset(self._discovered_eepsites)
