"""Paste site crawler — monitors paste sites for leaked data."""

import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator

from bs4 import BeautifulSoup

from src.models.threat import SourceType
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


class PasteCrawler(BaseCrawler):
    """Crawls paste sites for leaked credentials, code, and sensitive data."""

    name = "paste_crawler"
    source_type = SourceType.PASTE_SITE

    # Public paste archive APIs and sites
    SOURCES = [
        {
            "name": "rentry",
            "recent_url": "https://rentry.co/recent",
            "base_url": "https://rentry.co",
            "use_tor": False,
        },
    ]

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        for source in self.SOURCES:
            try:
                async for result in self._crawl_source(source):
                    yield result
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl {source['name']}: {e}")

    async def _crawl_source(self, source: dict) -> AsyncIterator[CrawlResult]:
        html = await self._fetch(source["recent_url"], use_tor=source.get("use_tor", False))
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")
        paste_links = self._extract_paste_links(soup, source)

        for link in paste_links:
            await self._delay()
            paste_url = f"{source['base_url']}{link}"
            paste_html = await self._fetch(paste_url, use_tor=source.get("use_tor", False))
            if not paste_html:
                continue

            paste_soup = BeautifulSoup(paste_html, "html.parser")
            content = self._extract_content(paste_soup)

            if content and len(content.strip()) > 50:
                yield CrawlResult(
                    source_type=self.source_type,
                    source_url=paste_url,
                    source_name=source["name"],
                    title=self._extract_title(paste_soup),
                    content=content,
                    author=self._extract_author(paste_soup),
                    published_at=datetime.now(timezone.utc),
                )

    def _extract_paste_links(self, soup: BeautifulSoup, source: dict) -> list[str]:
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/") and len(href) > 2 and href not in ("/recent", "/new", "/"):
                links.append(href)
        return links[:20]  # limit per crawl cycle

    def _extract_content(self, soup: BeautifulSoup) -> str | None:
        code_block = soup.find("pre") or soup.find("code")
        if code_block:
            return code_block.get_text()

        content_div = soup.find("div", class_=re.compile(r"content|paste|entry"))
        if content_div:
            return content_div.get_text()

        return None

    def _extract_title(self, soup: BeautifulSoup) -> str | None:
        title = soup.find("title")
        return title.get_text().strip() if title else None

    def _extract_author(self, soup: BeautifulSoup) -> str | None:
        return None  # most paste sites are anonymous
