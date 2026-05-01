"""Underground forum crawler — monitors Russian, Chinese, and English-language
underground forums for threat intelligence.

Covers clearnet and Tor-hosted forums running XenForo, phpBB, or custom software.
Target forums include XSS.is, Exploit.in, BreachForums successors, RAMP successors,
and Chinese dark-web forums.

IMPORTANT: This is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only) and respects robots.txt where available.
No accounts are created, no posts are made, no interactions occur.
"""

from __future__ import annotations


import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from src.models.threat import SourceType
from src.core.activity import ActivityType, emit as activity_emit

from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Preset CSS selector profiles for common forum software
# ---------------------------------------------------------------------------

SELECTOR_PROFILES: dict[str, dict[str, str]] = {
    "xenforo": {
        "thread_selector": "a[data-tp-primary], div.structItem-title a",
        "post_selector": "article.message-body .bbWrapper",
        "author_selector": "a.username, span.username",
        "date_selector": "time.u-dt",
        "pagination_selector": "a.pageNav-jump--next",
        "reputation_selector": "dl.pairs--rows dt:contains('Messages') + dd, "
                               "dl.pairs--rows dt:contains('Reaction score') + dd",
        "subforum_selector": "h3.node-title a",
        "post_count_selector": "dl.pairs--rows dt:contains('Messages') + dd",
    },
    "phpbb": {
        "thread_selector": "a.topictitle",
        "post_selector": "div.postbody div.content",
        "author_selector": "a.username, span.username",
        "date_selector": "p.author time",
        "pagination_selector": "li.next a",
        "reputation_selector": "dd.profile-posts strong",
        "subforum_selector": "a.forumtitle",
        "post_count_selector": "dd.profile-posts strong",
    },
    "custom": {
        "thread_selector": "a[href*='thread'], a[href*='topic'], a[href*='view']",
        "post_selector": "div.post, div.message-body, article, div.post_body",
        "author_selector": "a.username, span.username, span.author, a.author",
        "date_selector": "span.date, time, span.post-date",
        "pagination_selector": "a.next, a.next-page, a[rel='next']",
        "reputation_selector": "",
        "subforum_selector": "a[href*='forum'], a[href*='board']",
        "post_count_selector": "",
    },
}

# ---------------------------------------------------------------------------
# Access-broker / selling / buying intent patterns
# ---------------------------------------------------------------------------

# Multi-language patterns for detecting trade intent
_TRADE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # English
    ("selling", re.compile(
        r"\b(selling|for\s+sale|WTS|sell(?:ing)?\s+access|dump(?:s|ing)?|"
        r"fresh\s+(?:logs?|cc|cvv|rdp|ssh|vpn)|combo\s*list)\b",
        re.IGNORECASE,
    )),
    ("buying", re.compile(
        r"\b(buying|WTB|looking\s+for|need\s+access|wanted|"
        r"will\s+(?:buy|pay|purchase))\b",
        re.IGNORECASE,
    )),
    ("access_broker", re.compile(
        r"\b(initial\s+access|RDP\s+access|VPN\s+access|citrix\s+access|"
        r"corporate\s+access|network\s+access|domain\s+admin|"
        r"revenue\s*[\$\:]\s*\d|employee\s*count)\b",
        re.IGNORECASE,
    )),
    # Russian
    ("selling", re.compile(
        r"(?:\u043f\u0440\u043e\u0434\u0430[\u044e\u043c\u0436]|"  # продаю/продам/продаж
        r"\u0441\u043b\u0438\u0432|"                                 # слив
        r"\u0434\u0430\u043c\u043f)",                                # дамп
        re.IGNORECASE,
    )),
    ("buying", re.compile(
        r"(?:\u043a\u0443\u043f\u043b\u044e|"    # куплю
        r"\u0438\u0449\u0443|"                     # ищу
        r"\u043d\u0443\u0436\u043d\u043e?)",       # нужно
        re.IGNORECASE,
    )),
    # Chinese
    ("selling", re.compile(
        r"(?:\u51fa\u552e|\u6253\u5305|\u6279\u53d1|\u8d62\u5229)", re.IGNORECASE,
    )),
    ("buying", re.compile(
        r"(?:\u6c42\u8d2d|\u6536\u8d2d|\u9700\u8981)", re.IGNORECASE,
    )),
]


def _detect_trade_intent(text: str) -> list[str]:
    """Return a list of detected trade intents in the text."""
    intents: list[str] = []
    for label, pattern in _TRADE_PATTERNS:
        if pattern.search(text):
            if label not in intents:
                intents.append(label)
    return intents


class ForumCrawler(BaseCrawler):
    """Crawls underground forums (clearnet and Tor) for threat intelligence.

    Supports XenForo, phpBB, and custom forum software via preset selector
    profiles. Each forum config can override any selector individually.

    Forum config format::

        {
            "name": "xss_is",
            "base_url": "https://xss.is",
            "tor_url": "http://xssforumv3isucukbxhdhwz67hoa5e2voakcfkuieq4ch257vsburuid.onion",
            "index_path": "/",
            "language": "ru",             # ru | cn | en
            "access_type": "both",        # clearnet | tor | both
            "forum_software": "xenforo",  # xenforo | phpbb | custom
            "auth_required": false,
            "search_url": "/search/",     # optional — enables keyword search
            "max_pages": 5,
            "max_threads": 20,
            # Optional per-forum selector overrides (override preset profile):
            "thread_selector": "...",
            "post_selector": "...",
            ...
        }
    """

    name = "forum_crawler"
    source_type = SourceType.FORUM_UNDERGROUND

    def __init__(
        self,
        forum_configs: list[dict] | None = None,
        org_keywords: list[str] | None = None,
    ):
        super().__init__()
        self.forum_configs = forum_configs or []
        self.org_keywords = [kw.lower() for kw in (org_keywords or [])]

    # ------------------------------------------------------------------
    # Selector resolution
    # ------------------------------------------------------------------

    def _selectors(self, config: dict) -> dict[str, str]:
        """Merge preset profile with per-forum config overrides."""
        software = config.get("forum_software", "custom")
        profile = dict(SELECTOR_PROFILES.get(software, SELECTOR_PROFILES["custom"]))
        # Allow per-config overrides
        for key in profile:
            if key in config:
                profile[key] = config[key]
        return profile

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def _should_use_tor(self, config: dict) -> bool:
        access = config.get("access_type", "clearnet")
        return access in ("tor", "both")

    def _effective_base_url(self, config: dict) -> str:
        """Pick the best base URL depending on access type."""
        access = config.get("access_type", "clearnet")
        if access == "tor":
            return config.get("tor_url") or config["base_url"]
        # For "both", prefer clearnet for speed; tor_url is fallback
        return config["base_url"]

    # ------------------------------------------------------------------
    # Main crawl loop
    # ------------------------------------------------------------------

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        for config in self.forum_configs:
            forum_name = config.get("name", "unknown_forum")
            await activity_emit(
                ActivityType.CRAWLER_START,
                self.name,
                f"Starting crawl of {forum_name}",
                {"forum": forum_name, "language": config.get("language", "en")},
            )
            try:
                async for result in self._crawl_forum(config):
                    yield result
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl {forum_name}: {e}")
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    f"Forum crawl failed: {forum_name} — {e}",
                    {"forum": forum_name},
                    severity="error",
                )

            await activity_emit(
                ActivityType.CRAWLER_COMPLETE,
                self.name,
                f"Finished crawl of {forum_name}",
                {"forum": forum_name},
            )

    # ------------------------------------------------------------------
    # Keyword search path
    # ------------------------------------------------------------------

    async def _keyword_search(
        self, config: dict, selectors: dict[str, str],
    ) -> AsyncIterator[CrawlResult]:
        """If the forum exposes a search endpoint, query it for org keywords."""
        search_url = config.get("search_url")
        if not search_url or not self.org_keywords:
            return

        base_url = self._effective_base_url(config)
        use_tor = self._should_use_tor(config)

        for keyword in self.org_keywords:
            full_url = urljoin(base_url, search_url)
            # Most forum search endpoints accept a query parameter 'q' or 'keywords'
            search_target = f"{full_url}?q={keyword}&keywords={keyword}"

            html = await self._fetch(search_target, use_tor=use_tor)
            if not html:
                continue

            soup = BeautifulSoup(html, "html.parser")
            thread_selector = selectors["thread_selector"]

            for a in soup.select(thread_selector):
                href = a.get("href", "")
                if not href:
                    continue
                thread_url = urljoin(base_url, href)
                thread_title = a.get_text(strip=True)

                async for result in self._crawl_thread(
                    config, selectors, thread_url, thread_title,
                ):
                    yield result

                await self._delay()

    # ------------------------------------------------------------------
    # Forum index crawl
    # ------------------------------------------------------------------

    async def _crawl_forum(self, config: dict) -> AsyncIterator[CrawlResult]:
        selectors = self._selectors(config)
        base_url = self._effective_base_url(config)
        use_tor = self._should_use_tor(config)
        index_path = config.get("index_path", "/")
        max_pages = config.get("max_pages", 5)
        max_threads = config.get("max_threads", 20)

        # 1) Keyword search (if available)
        async for result in self._keyword_search(config, selectors):
            yield result

        # 2) Index crawl with pagination
        current_url: str | None = urljoin(base_url, index_path)
        pages_crawled = 0
        threads_found: list[tuple[str, str]] = []

        while current_url and pages_crawled < max_pages:
            html = await self._fetch(current_url, use_tor=use_tor)
            if not html:
                logger.warning(f"[{self.name}] Could not reach {config['name']} at {current_url}")
                break

            soup = BeautifulSoup(html, "html.parser")
            thread_selector = selectors["thread_selector"]

            for a in soup.select(thread_selector):
                href = a.get("href", "")
                if href:
                    full_url = urljoin(base_url, href)
                    threads_found.append((full_url, a.get_text(strip=True)))

            # Pagination
            pages_crawled += 1
            next_link = soup.select_one(selectors["pagination_selector"])
            if next_link and isinstance(next_link, Tag):
                next_href = next_link.get("href", "")
                current_url = urljoin(base_url, str(next_href)) if next_href else None
            else:
                current_url = None

            await self._delay()

        logger.info(
            f"[{self.name}] Found {len(threads_found)} threads on "
            f"{config['name']} across {pages_crawled} pages"
        )

        # 3) Crawl individual threads
        for thread_url, thread_title in threads_found[:max_threads]:
            async for result in self._crawl_thread(
                config, selectors, thread_url, thread_title,
            ):
                yield result
            await self._delay()

    # ------------------------------------------------------------------
    # Single thread crawl
    # ------------------------------------------------------------------

    async def _crawl_thread(
        self,
        config: dict,
        selectors: dict[str, str],
        thread_url: str,
        thread_title: str,
    ) -> AsyncIterator[CrawlResult]:
        use_tor = self._should_use_tor(config)
        language = config.get("language", "en")
        forum_name = config.get("name", "unknown_forum")

        thread_html = await self._fetch(thread_url, use_tor=use_tor)
        if not thread_html:
            return

        thread_soup = BeautifulSoup(thread_html, "html.parser")
        posts = thread_soup.select(selectors["post_selector"])

        for post in posts:
            content = post.get_text(strip=True)
            if not content or len(content) < 30:
                continue

            # --- Author extraction ---
            author = self._extract_field(post, selectors.get("author_selector", ""))

            # --- Reputation / post count ---
            reputation = self._extract_field(post, selectors.get("reputation_selector", ""))
            post_count = self._extract_field(post, selectors.get("post_count_selector", ""))

            # --- Subforum / section ---
            subforum = self._extract_field(
                thread_soup, selectors.get("subforum_selector", ""),
            )

            # --- Date ---
            published_at = self._extract_date(post, selectors.get("date_selector", ""))

            # --- Trade-intent detection ---
            trade_intents = _detect_trade_intent(content)

            # --- Keyword relevance check ---
            keyword_hits = self._match_keywords(content, thread_title)

            raw_data: dict = {
                "forum": forum_name,
                "thread_url": thread_url,
                "thread_title": thread_title,
                "language": language,
                "access_type": config.get("access_type", "clearnet"),
                "forum_software": config.get("forum_software", "custom"),
            }
            if reputation:
                raw_data["author_reputation"] = reputation
            if post_count:
                raw_data["author_post_count"] = post_count
            if subforum:
                raw_data["subforum"] = subforum
            if trade_intents:
                raw_data["trade_intents"] = trade_intents
            if keyword_hits:
                raw_data["keyword_hits"] = keyword_hits

            await activity_emit(
                ActivityType.CRAWLER_RESULT,
                self.name,
                f"Post from {author or 'unknown'} on {forum_name}",
                {"thread": thread_title, "language": language, "intents": trade_intents},
            )

            yield CrawlResult(
                source_type=self.source_type,
                source_url=thread_url,
                source_name=forum_name,
                title=thread_title,
                content=content,
                author=author,
                published_at=published_at or datetime.now(timezone.utc),
                raw_data=raw_data,
            )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_field(context: Tag | BeautifulSoup, selector: str) -> str | None:
        """Safely extract text from a CSS-selected element."""
        if not selector:
            return None
        # Selector may contain comma-separated alternatives
        el = context.select_one(selector)
        if el:
            return el.get_text(strip=True)
        # Try traversal up (for post-local elements)
        if isinstance(context, Tag):
            parent = context.find_parent()
            if parent:
                el = parent.select_one(selector)
                if el:
                    return el.get_text(strip=True)
        return None

    @staticmethod
    def _extract_date(context: Tag, selector: str) -> datetime | None:
        """Try to extract a datetime from a date element."""
        if not selector:
            return None
        el = context.select_one(selector)
        if not el:
            return None
        # Many forums use <time datetime="..."> or data-time attributes
        for attr in ("datetime", "data-time", "data-timestamp", "title"):
            raw = el.get(attr)
            if not raw:
                continue
            try:
                ts = float(str(raw))
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                pass
            try:
                return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            except (ValueError, TypeError) as exc:
                logger.debug(
                    "forum.parse: timestamp attr=%s value=%r could not be parsed: %s",
                    attr, raw, exc,
                )
        return None

    def _match_keywords(self, content: str, title: str) -> list[str]:
        """Return org keywords found in content or title."""
        if not self.org_keywords:
            return []
        combined = f"{title} {content}".lower()
        return [kw for kw in self.org_keywords if kw in combined]
