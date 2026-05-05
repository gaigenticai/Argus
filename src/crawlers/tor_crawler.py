"""Tor hidden service crawler — the core dark web monitoring engine.

This crawler accesses .onion sites through the Tor SOCKS proxy to monitor
dark web forums, marketplaces, and discussion boards for threat intelligence.

IMPORTANT: This is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only) and respects robots.txt where available.
"""

from __future__ import annotations


import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from src.models.threat import SourceType
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


class TorForumCrawler(BaseCrawler):
    """Crawls Tor hidden service forums for threat intelligence.

    Forum targets are configured per-deployment by the customer.
    This crawler handles generic forum structures (phpBB, XenForo,
    custom forum software commonly found on .onion sites).
    """

    name = "tor_forum"
    source_type = SourceType.TOR_FORUM

    def __init__(self, forum_configs: list[dict] | None = None):
        super().__init__()
        self.forum_configs = forum_configs or []

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        for config in self.forum_configs:
            try:
                async for result in self._crawl_forum(config):
                    yield result
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl {config.get('name', 'unknown')}: {e}")

    async def _crawl_forum(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Crawl a single forum based on its configuration.

        Config format:
        {
            "name": "forum_name",
            "base_url": "http://xxxxx.onion",
            "index_path": "/forum/",
            "thread_selector": "a.thread-link",     # CSS selector for thread links
            "post_selector": "div.post-body",        # CSS selector for post content
            "author_selector": "span.post-author",   # CSS selector for author
            "date_selector": "span.post-date",       # CSS selector for date
            "pagination_selector": "a.next-page",    # CSS selector for next page
            "max_pages": 5,
        }
        """
        base_url = config["base_url"]
        index_url = urljoin(base_url, config.get("index_path", "/"))

        html = await self._fetch(index_url, use_tor=True)
        if not html:
            logger.warning(f"[{self.name}] Could not reach {config['name']}")
            return

        soup = BeautifulSoup(html, "html.parser")

        # Extract thread links
        thread_selector = config.get("thread_selector", "a[href*='thread'], a[href*='topic']")
        thread_links = []
        for a in soup.select(thread_selector):
            href = a.get("href", "")
            if href:
                full_url = urljoin(base_url, href)
                thread_links.append((full_url, a.get_text(strip=True)))

        logger.info(f"[{self.name}] Found {len(thread_links)} threads on {config['name']}")

        for thread_url, thread_title in thread_links[:config.get("max_threads", 20)]:
            await self._delay()

            thread_html = await self._fetch(thread_url, use_tor=True)
            if not thread_html:
                continue

            thread_soup = BeautifulSoup(thread_html, "html.parser")

            # Extract posts
            post_selector = config.get("post_selector", "div.post, div.message-body, article")
            posts = thread_soup.select(post_selector)

            for post in posts:
                content = post.get_text(strip=True)
                if not content or len(content) < 30:
                    continue

                # Try to get author
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
                        "forum": config["name"],
                        "thread_url": thread_url,
                        "thread_title": thread_title,
                    },
                )


class TorMarketplaceCrawler(BaseCrawler):
    """Crawls Tor marketplace listings for stolen data, credentials, and exploits."""

    name = "tor_marketplace"
    source_type = SourceType.TOR_MARKETPLACE

    def __init__(self, marketplace_configs: list[dict] | None = None):
        super().__init__()
        self.marketplace_configs = marketplace_configs or []

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        for config in self.marketplace_configs:
            try:
                async for result in self._crawl_marketplace(config):
                    yield result
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl {config.get('name', 'unknown')}: {e}")

    async def _crawl_marketplace(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Crawl marketplace listings.

        Config format:
        {
            "name": "marketplace_name",
            "base_url": "http://xxxxx.onion",
            "categories": ["/category/databases", "/category/exploits"],
            "listing_selector": "div.listing",
            "title_selector": "h3.listing-title",
            "desc_selector": "div.listing-description",
            "price_selector": "span.price",
            "vendor_selector": "a.vendor-name",
            "max_listings": 50,
        }
        """
        base_url = config["base_url"]

        for category_path in config.get("categories", ["/"]):
            category_url = urljoin(base_url, category_path)
            html = await self._fetch(category_url, use_tor=True)
            if not html:
                continue

            soup = BeautifulSoup(html, "html.parser")
            listing_selector = config.get("listing_selector", "div.listing, div.product")
            listings = soup.select(listing_selector)

            for listing in listings[:config.get("max_listings", 50)]:
                title_el = listing.select_one(config.get("title_selector", "h3, h4, .title"))
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
                    source_url=category_url,
                    source_name=config["name"],
                    title=title,
                    content=content,
                    author=vendor,
                    raw_data={
                        "marketplace": config["name"],
                        "category": category_path,
                        "price": price,
                        "vendor": vendor,
                    },
                )

            await self._delay()
