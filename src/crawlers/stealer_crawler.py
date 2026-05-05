"""Stealer log marketplace crawler — monitors info-stealer log markets for compromised credentials.

Tracks markets where stolen browser sessions, saved passwords, cookies, and
autofill data from info-stealer malware (RedLine, Raccoon, Vidar, Lumma,
StealC, RisePro, etc.) are sold.  These markets operate on both Tor (.onion)
and clearnet with rotating domains.

IMPORTANT: This crawler is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only).  It searches for an organization's own
domains/keywords so the security team can detect credential compromise and
respond before attackers weaponize stolen sessions.
"""

from __future__ import annotations


import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import urljoin, quote_plus

from bs4 import BeautifulSoup, Tag

from src.models.threat import SourceType
from src.core.activity import ActivityType, emit as activity_emit
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)

# Patterns for extracting indicators from listing text
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Known stealer families for classification
KNOWN_STEALERS = frozenset({
    "redline", "raccoon", "vidar", "lumma", "stealc", "risepro",
    "aurora", "titan", "meta", "mystic", "predator", "rhadamanthys",
    "amadey", "arkei", "mars", "erbium", "eternity", "typhon",
})


class StealerLogCrawler(BaseCrawler):
    """Crawls stealer log marketplaces for compromised credentials tied to monitored orgs.

    Operates in two modes:
      1. **Search mode** — queries marketplace search endpoints for org-specific
         keywords (domains, email patterns) to find listings that reference the
         organization's assets.
      2. **Browse mode** — fetches the most recent listings page and scans for
         org keyword matches locally.  Useful when a market has no search API.

    Marketplace targets are configured per-deployment via ``marketplace_configs``.
    """

    name = "stealer_marketplace"
    source_type = SourceType.STEALER_LOG

    def __init__(
        self,
        marketplace_configs: list[dict] | None = None,
        org_keywords: list[str] | None = None,
    ):
        """
        Args:
            marketplace_configs: List of market definitions.  Each dict:
                {
                    "name": "russian_market",
                    "base_url": "http://xxxxx.onion",
                    "search_path": "/search?q={query}",   # {query} is url-encoded
                    "browse_path": "/logs/recent",         # recent listings page
                    "listing_selector": "div.log-entry",
                    "title_selector": ".log-title",
                    "domain_selector": ".log-domain",
                    "bot_id_selector": ".bot-id",
                    "stealer_selector": ".stealer-type",
                    "credential_count_selector": ".cred-count",
                    "price_selector": ".price",
                    "country_selector": ".country",
                    "date_selector": ".log-date",
                    "detail_link_selector": "a.detail-link",
                    "pagination_selector": "a.next-page",
                    "max_pages": 3,
                    "max_listings": 100,
                    "mode": "search",  # "search" | "browse" | "both"
                }
            org_keywords: Organization-specific keywords to search for —
                domain names (e.g. ``acme.com``), email patterns
                (e.g. ``@acme.com``), internal hostnames, etc.
        """
        super().__init__()
        self.marketplace_configs = marketplace_configs or []
        self.org_keywords = [kw.lower() for kw in (org_keywords or [])]

    # ── Public entry point ──────────────────────────────────────

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        """Yield CrawlResults from configured stealer log marketplaces."""
        for config in self.marketplace_configs:
            market_name = config.get("name", "unknown_market")
            try:
                await activity_emit(
                    ActivityType.CRAWLER_START,
                    self.name,
                    f"Starting stealer log crawl: {market_name}",
                    {"market": market_name, "mode": config.get("mode", "both")},
                )

                mode = config.get("mode", "both")

                if mode in ("search", "both") and config.get("search_path"):
                    async for result in self._crawl_search_mode(config):
                        yield result

                if mode in ("browse", "both") and config.get("browse_path"):
                    async for result in self._crawl_browse_mode(config):
                        yield result

                await activity_emit(
                    ActivityType.CRAWLER_COMPLETE,
                    self.name,
                    f"Completed stealer log crawl: {market_name}",
                    {"market": market_name},
                )
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl {market_name}: {e}")
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    f"Stealer crawl failed: {market_name} — {e}",
                    {"market": market_name, "error": str(e)},
                    severity="error",
                )

    # ── Search mode ─────────────────────────────────────────────

    async def _crawl_search_mode(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Query marketplace search for each org keyword."""
        base_url = config["base_url"]
        search_path_template = config["search_path"]
        market_name = config["name"]

        for keyword in self.org_keywords:
            search_path = search_path_template.replace("{query}", quote_plus(keyword))
            search_url = urljoin(base_url, search_path)

            pages_fetched = 0
            max_pages = config.get("max_pages", 3)
            current_url: str | None = search_url

            while current_url and pages_fetched < max_pages:
                await self._delay()
                html = await self._fetch(current_url, use_tor=True)
                if not html:
                    break

                soup = BeautifulSoup(html, "html.parser")
                listings_found = 0

                async for result in self._parse_listings(soup, config, keyword):
                    listings_found += 1
                    yield result

                logger.info(
                    f"[{self.name}] Search '{keyword}' on {market_name} "
                    f"page {pages_fetched + 1}: {listings_found} listings"
                )
                pages_fetched += 1

                # Follow pagination
                current_url = self._extract_next_page(soup, config, base_url)

    # ── Browse mode ─────────────────────────────────────────────

    async def _crawl_browse_mode(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Fetch recent listings and scan for org keyword matches locally."""
        base_url = config["base_url"]
        browse_url = urljoin(base_url, config["browse_path"])
        market_name = config["name"]

        pages_fetched = 0
        max_pages = config.get("max_pages", 3)
        current_url: str | None = browse_url

        while current_url and pages_fetched < max_pages:
            await self._delay()
            html = await self._fetch(current_url, use_tor=True)
            if not html:
                break

            soup = BeautifulSoup(html, "html.parser")
            listings_found = 0

            async for result in self._parse_listings(soup, config, keyword=None):
                listings_found += 1
                yield result

            logger.info(
                f"[{self.name}] Browse {market_name} "
                f"page {pages_fetched + 1}: {listings_found} listings"
            )
            pages_fetched += 1
            current_url = self._extract_next_page(soup, config, base_url)

    # ── Listing parser ──────────────────────────────────────────

    async def _parse_listings(
        self,
        soup: BeautifulSoup,
        config: dict,
        keyword: str | None,
    ) -> AsyncIterator[CrawlResult]:
        """Extract structured data from listing elements on a page.

        When ``keyword`` is ``None`` (browse mode), every listing is checked
        against all ``self.org_keywords``.  When ``keyword`` is set (search
        mode), the marketplace already filtered results — but we still
        double-check relevance for precision.
        """
        listing_selector = config.get("listing_selector", "div.log-entry, tr.log-row")
        listings = soup.select(listing_selector)
        max_listings = config.get("max_listings", 100)

        for listing in listings[:max_listings]:
            parsed = self._extract_listing_fields(listing, config)

            # Build a combined text blob for keyword matching
            match_text = " ".join(
                str(v) for v in parsed.values() if v is not None
            ).lower()

            # Relevance check
            matched_keywords = self._match_keywords(match_text)
            if not matched_keywords:
                # In search mode the market already filtered, but if our
                # keywords don't appear in the listing text, skip it — reduces
                # false positives.
                continue

            # Extract IOC-grade indicators
            indicators = self._extract_indicators(match_text)

            # Detect stealer family
            stealer_type = parsed.get("stealer_type") or self._detect_stealer(match_text)

            # Freshness tracking — try to parse listing date
            published_at = self._parse_listing_date(parsed.get("date_text"))

            title = parsed.get("title") or parsed.get("victim_domain") or "Stealer log listing"
            content_parts = [
                f"Market: {config['name']}",
                f"Victim domain: {parsed.get('victim_domain', 'N/A')}",
                f"Stealer: {stealer_type or 'unknown'}",
                f"Credentials: {parsed.get('credential_count', 'N/A')}",
                f"Bot ID: {parsed.get('bot_id', 'N/A')}",
                f"Country: {parsed.get('country', 'N/A')}",
                f"Price: {parsed.get('price', 'N/A')}",
                f"Date: {parsed.get('date_text', 'N/A')}",
                f"Matched keywords: {', '.join(matched_keywords)}",
            ]
            content = "\n".join(content_parts)

            # Optionally fetch detail page for richer data
            detail_url = self._extract_detail_link(listing, config)
            detail_content: str | None = None
            if detail_url:
                await self._delay()
                detail_html = await self._fetch(
                    urljoin(config["base_url"], detail_url), use_tor=True,
                )
                if detail_html:
                    detail_soup = BeautifulSoup(detail_html, "html.parser")
                    detail_content = detail_soup.get_text(separator="\n", strip=True)[:2000]
                    # Re-extract indicators from detail page
                    detail_indicators = self._extract_indicators(detail_content.lower())
                    indicators = self._merge_indicators(indicators, detail_indicators)

            await activity_emit(
                ActivityType.CRAWLER_RESULT,
                self.name,
                f"Stealer log hit: {parsed.get('victim_domain', 'unknown')} on {config['name']}",
                {
                    "market": config["name"],
                    "victim_domain": parsed.get("victim_domain"),
                    "stealer": stealer_type,
                    "matched_keywords": matched_keywords,
                },
            )

            yield CrawlResult(
                source_type=self.source_type,
                source_url=urljoin(config["base_url"], detail_url) if detail_url else config["base_url"],
                source_name=config["name"],
                title=title,
                content=content,
                author=None,
                published_at=published_at,
                raw_data={
                    "market": config["name"],
                    "victim_domain": parsed.get("victim_domain"),
                    "credential_count": parsed.get("credential_count"),
                    "bot_id": parsed.get("bot_id"),
                    "stealer_type": stealer_type,
                    "price": parsed.get("price"),
                    "country": parsed.get("country"),
                    "matched_keywords": matched_keywords,
                    "indicators": indicators,
                    "detail_snippet": detail_content[:500] if detail_content else None,
                },
            )

    # ── Field extraction helpers ────────────────────────────────

    def _extract_listing_fields(self, listing: Tag, config: dict) -> dict:
        """Pull structured fields from a single listing element using config selectors."""

        def _text(selector_key: str, default_selector: str) -> str | None:
            sel = config.get(selector_key, default_selector)
            el = listing.select_one(sel)
            return el.get_text(strip=True) if el else None

        return {
            "title": _text("title_selector", ".log-title, .title"),
            "victim_domain": _text("domain_selector", ".log-domain, .domain"),
            "bot_id": _text("bot_id_selector", ".bot-id, .botid"),
            "stealer_type": _text("stealer_selector", ".stealer-type, .stealer"),
            "credential_count": _text("credential_count_selector", ".cred-count, .passwords"),
            "price": _text("price_selector", ".price"),
            "country": _text("country_selector", ".country, .geo"),
            "date_text": _text("date_selector", ".log-date, .date, time"),
        }

    def _extract_detail_link(self, listing: Tag, config: dict) -> str | None:
        """Get href from a detail-link element inside the listing."""
        sel = config.get("detail_link_selector", "a.detail-link, a.view")
        el = listing.select_one(sel)
        if el:
            return el.get("href")
        return None

    def _extract_next_page(
        self, soup: BeautifulSoup, config: dict, base_url: str,
    ) -> str | None:
        """Return the absolute URL for the next page, or None."""
        sel = config.get("pagination_selector", "a.next-page, a.next, a[rel='next']")
        el = soup.select_one(sel)
        if el:
            href = el.get("href")
            if href:
                return urljoin(base_url, href)
        return None

    # ── Keyword matching ────────────────────────────────────────

    def _match_keywords(self, text: str) -> list[str]:
        """Return list of org keywords found in *text*."""
        return [kw for kw in self.org_keywords if kw in text]

    # ── Indicator extraction ────────────────────────────────────

    def _extract_indicators(self, text: str) -> dict[str, list[str]]:
        """Pull emails, domains, and IPs from raw text."""
        return {
            "emails": list(set(_EMAIL_RE.findall(text))),
            "domains": list(set(_DOMAIN_RE.findall(text))),
            "ips": list(set(_IP_RE.findall(text))),
        }

    @staticmethod
    def _merge_indicators(a: dict[str, list[str]], b: dict[str, list[str]]) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for key in set(list(a.keys()) + list(b.keys())):
            merged[key] = list(set(a.get(key, []) + b.get(key, [])))
        return merged

    # ── Stealer detection ───────────────────────────────────────

    @staticmethod
    def _detect_stealer(text: str) -> str | None:
        """Try to identify the stealer family from listing text."""
        for stealer in KNOWN_STEALERS:
            if stealer in text:
                return stealer
        return None

    # ── Date parsing ────────────────────────────────────────────

    @staticmethod
    def _parse_listing_date(date_text: str | None) -> datetime | None:
        """Best-effort parse of marketplace date strings.

        Stealer markets use many formats — ISO, relative ("2h ago"), timestamps.
        We try common patterns and fall back to None.
        """
        if not date_text:
            return None

        date_text = date_text.strip()

        # Relative time patterns (e.g. "2h ago", "30m ago", "1d ago")
        relative_match = re.match(r"(\d+)\s*([mhdMHD])\w*\s*ago", date_text)
        if relative_match:
            amount = int(relative_match.group(1))
            unit = relative_match.group(2).lower()
            from datetime import timedelta

            delta_map = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}
            delta = delta_map.get(unit)
            if delta:
                return datetime.now(timezone.utc) - delta

        # Common absolute formats
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%d.%m.%Y %H:%M",
            "%d.%m.%Y",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y",
            "%b %d, %Y",
        ):
            try:
                return datetime.strptime(date_text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None
