"""Ransomware leak site crawler — monitors gang blogs for victim postings and data dumps.

Every major ransomware group maintains one or more Tor leak sites where they
name-and-shame victims and publish stolen data: LockBit, BlackCat/ALPHV, Cl0p,
Play, Akira, Black Basta, Medusa, Royal, RansomHub, BianLian, etc.  These
.onion addresses change frequently after law-enforcement takedowns and group
rebrands.

IMPORTANT: This crawler is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only).  It checks whether monitored organizations
appear on leak sites so the security team can respond to active incidents.  No
data is downloaded — only listing metadata is collected.
"""

import hashlib
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from src.models.threat import SourceType
from src.core.activity import ActivityType, emit as activity_emit
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)

# Countdown / timer patterns commonly seen on leak sites
_COUNTDOWN_RE = re.compile(
    r"(?:(\d+)\s*d(?:ays?)?)?\s*(?:(\d+)\s*h(?:ours?)?)?\s*(?:(\d+)\s*m(?:in(?:utes?)?)?)?",
    re.IGNORECASE,
)
_SIZE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(GB|TB|MB|KB)", re.IGNORECASE)


class RansomwareLeakCrawler(BaseCrawler):
    """Crawls ransomware group leak sites for victim listings.

    For each configured ransomware group the crawler:
      1. Tries multiple mirror URLs (failover) until one responds.
      2. Parses the victim listing page to extract company names,
         descriptions, deadlines/timers, and data sizes.
      3. Matches victims against monitored organization names and keywords.
      4. Tracks new vs. previously-seen victims via content hashing.
      5. Optionally discovers links to *other* ransomware group sites
         (discovery mode).

    Group targets are configured per-deployment via ``group_configs``.
    """

    name = "ransomware_leak_crawler"
    source_type = SourceType.RANSOMWARE_LEAK

    def __init__(
        self,
        group_configs: list[dict] | None = None,
        org_keywords: list[str] | None = None,
        seen_hashes: set[str] | None = None,
        discovery_mode: bool = False,
    ):
        """
        Args:
            group_configs: List of ransomware group site definitions.  Each dict:
                {
                    "group_name": "lockbit",
                    "onion_urls": [
                        "http://lockbitxxxxx.onion",
                        "http://lockbit2xxxx.onion",
                    ],
                    "index_path": "/",
                    "victim_selector": "div.post-block, div.victim-card",
                    "name_selector": ".post-title, .victim-name",
                    "description_selector": ".post-body, .victim-desc",
                    "deadline_selector": ".timer, .countdown, .deadline",
                    "size_selector": ".data-size, .size",
                    "date_selector": ".post-date, .date",
                    "industry_selector": ".industry, .sector",
                    "detail_link_selector": "a.read-more, a.detail",
                    "pagination_selector": "a.next, a[rel='next']",
                    "max_pages": 3,
                }
            org_keywords: Organization names / keywords to match against victim
                listings.  Case-insensitive matching.
            seen_hashes: Set of previously seen content hashes — used to detect
                new victims vs. already-known ones.
            discovery_mode: When ``True``, the crawler also scans page content
                for .onion links that may point to other ransomware group sites.
        """
        super().__init__()
        self.group_configs = group_configs or []
        self.org_keywords = [kw.lower() for kw in (org_keywords or [])]
        self.seen_hashes: set[str] = seen_hashes if seen_hashes is not None else set()
        self.discovery_mode = discovery_mode
        self._discovered_onions: set[str] = set()

    # ── Public entry point ──────────────────────────────────────

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        """Yield CrawlResults from configured ransomware leak sites."""
        for config in self.group_configs:
            group_name = config.get("group_name", "unknown_group")
            try:
                await activity_emit(
                    ActivityType.CRAWLER_START,
                    self.name,
                    f"Starting ransomware leak crawl: {group_name}",
                    {"group": group_name, "mirrors": len(config.get("onion_urls", []))},
                )

                async for result in self._crawl_group(config):
                    yield result

                await activity_emit(
                    ActivityType.CRAWLER_COMPLETE,
                    self.name,
                    f"Completed ransomware leak crawl: {group_name}",
                    {"group": group_name},
                )
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl {group_name}: {e}")
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    f"Ransomware crawl failed: {group_name} — {e}",
                    {"group": group_name, "error": str(e)},
                    severity="error",
                )

        # If discovery mode found new .onion links, yield a summary result
        if self.discovery_mode and self._discovered_onions:
            yield CrawlResult(
                source_type=self.source_type,
                source_url=None,
                source_name="ransomware_discovery",
                title="Discovered potential ransomware group .onion links",
                content="\n".join(sorted(self._discovered_onions)),
                raw_data={
                    "discovered_onions": sorted(self._discovered_onions),
                    "count": len(self._discovered_onions),
                },
            )

    # ── Per-group crawl with mirror failover ────────────────────

    async def _crawl_group(self, config: dict) -> AsyncIterator[CrawlResult]:
        """Try each mirror URL until one responds, then crawl victim listings."""
        group_name = config["group_name"]
        onion_urls = config.get("onion_urls", [])
        index_path = config.get("index_path", "/")

        reachable_base: str | None = None

        for mirror in onion_urls:
            index_url = urljoin(mirror, index_path)
            html = await self._fetch(index_url, use_tor=True)
            if html:
                reachable_base = mirror
                logger.info(f"[{self.name}] {group_name}: mirror reachable — {mirror}")
                break
            else:
                logger.warning(f"[{self.name}] {group_name}: mirror unreachable — {mirror}")
                await self._delay()

        if not reachable_base or not html:
            logger.error(f"[{self.name}] {group_name}: all {len(onion_urls)} mirrors unreachable")
            await activity_emit(
                ActivityType.CRAWLER_ERROR,
                self.name,
                f"All mirrors down for {group_name}",
                {"group": group_name, "mirrors_tried": len(onion_urls)},
                severity="warning",
            )
            return

        # Parse first page (already fetched)
        pages_parsed = 0
        max_pages = config.get("max_pages", 3)
        current_url: str | None = urljoin(reachable_base, index_path)

        while html and pages_parsed < max_pages:
            soup = BeautifulSoup(html, "html.parser")

            async for result in self._parse_victim_page(soup, config, reachable_base):
                yield result

            # Discovery mode — scan for .onion links
            if self.discovery_mode:
                self._scan_for_onion_links(soup, reachable_base)

            pages_parsed += 1

            # Pagination
            next_url = self._extract_next_page(soup, config, reachable_base)
            if next_url and pages_parsed < max_pages:
                await self._delay()
                html = await self._fetch(next_url, use_tor=True)
                current_url = next_url
            else:
                break

    # ── Victim page parser ──────────────────────────────────────

    async def _parse_victim_page(
        self,
        soup: BeautifulSoup,
        config: dict,
        base_url: str,
    ) -> AsyncIterator[CrawlResult]:
        """Extract victim entries from a leak site listing page."""
        group_name = config["group_name"]
        victim_selector = config.get("victim_selector", "div.post-block, div.victim-card, article")
        victims = soup.select(victim_selector)

        logger.info(f"[{self.name}] {group_name}: found {len(victims)} victim entries on page")

        for victim_el in victims:
            parsed = self._extract_victim_fields(victim_el, config)
            victim_name = parsed.get("name") or "Unknown victim"
            description = parsed.get("description") or ""

            # Content hash for dedup
            hash_input = f"{group_name}:{victim_name}:{description[:200]}"
            content_hash = hashlib.sha256(hash_input.encode()).hexdigest()
            is_new = content_hash not in self.seen_hashes
            self.seen_hashes.add(content_hash)

            # Check org keyword match
            match_text = f"{victim_name} {description}".lower()
            matched_keywords = [kw for kw in self.org_keywords if kw in match_text]

            # Parse deadline / countdown
            deadline_info = self._parse_deadline(parsed.get("deadline_text"))

            # Parse data size
            data_size = self._parse_data_size(parsed.get("size_text"))

            # Parse date
            published_at = self._parse_date(parsed.get("date_text"))

            # Build content summary
            content_parts = [
                f"Ransomware group: {group_name}",
                f"Victim: {victim_name}",
                f"Description: {description[:500]}" if description else None,
                f"Industry: {parsed.get('industry')}" if parsed.get("industry") else None,
                f"Data size: {data_size}" if data_size else None,
                f"Deadline: {deadline_info}" if deadline_info else None,
                f"Date posted: {parsed.get('date_text')}" if parsed.get("date_text") else None,
                f"New listing: {'YES' if is_new else 'no'}",
                f"Org match: {', '.join(matched_keywords)}" if matched_keywords else None,
            ]
            content = "\n".join(p for p in content_parts if p is not None)

            # Detail link for richer data
            detail_url = self._extract_detail_link(victim_el, config)
            detail_content: str | None = None
            if detail_url:
                full_detail_url = urljoin(base_url, detail_url)
                await self._delay()
                detail_html = await self._fetch(full_detail_url, use_tor=True)
                if detail_html:
                    detail_soup = BeautifulSoup(detail_html, "html.parser")
                    detail_content = detail_soup.get_text(separator="\n", strip=True)[:3000]

                    # Re-check keyword match against detail page
                    if not matched_keywords:
                        detail_lower = detail_content.lower()
                        matched_keywords = [kw for kw in self.org_keywords if kw in detail_lower]

                    # Check for countdown timer on detail page
                    if not deadline_info:
                        deadline_el = detail_soup.select_one(
                            config.get("deadline_selector", ".timer, .countdown, .deadline")
                        )
                        if deadline_el:
                            deadline_info = self._parse_deadline(deadline_el.get_text(strip=True))

            severity = "info"
            if matched_keywords:
                severity = "critical"
            elif is_new:
                severity = "warning"

            await activity_emit(
                ActivityType.CRAWLER_RESULT,
                self.name,
                f"Ransomware victim: {victim_name} ({group_name})"
                + (f" — ORG MATCH: {matched_keywords}" if matched_keywords else ""),
                {
                    "group": group_name,
                    "victim": victim_name,
                    "is_new": is_new,
                    "org_match": matched_keywords,
                    "has_deadline": deadline_info is not None,
                },
                severity=severity,
            )

            yield CrawlResult(
                source_type=self.source_type,
                source_url=urljoin(base_url, detail_url) if detail_url else base_url,
                source_name=f"ransomware:{group_name}",
                title=f"[{group_name.upper()}] {victim_name}",
                content=content,
                author=group_name,
                published_at=published_at,
                raw_data={
                    "group_name": group_name,
                    "victim_name": victim_name,
                    "description": description[:1000] if description else None,
                    "industry": parsed.get("industry"),
                    "data_size": data_size,
                    "deadline": deadline_info,
                    "is_new_victim": is_new,
                    "content_hash": content_hash,
                    "matched_keywords": matched_keywords,
                    "detail_snippet": detail_content[:500] if detail_content else None,
                },
            )

    # ── Field extraction helpers ────────────────────────────────

    def _extract_victim_fields(self, el: Tag, config: dict) -> dict:
        """Pull structured fields from a single victim listing element."""

        def _text(selector_key: str, default_selector: str) -> str | None:
            sel = config.get(selector_key, default_selector)
            found = el.select_one(sel)
            return found.get_text(strip=True) if found else None

        return {
            "name": _text("name_selector", ".post-title, .victim-name, h2, h3"),
            "description": _text("description_selector", ".post-body, .victim-desc, p"),
            "deadline_text": _text("deadline_selector", ".timer, .countdown, .deadline"),
            "size_text": _text("size_selector", ".data-size, .size"),
            "date_text": _text("date_selector", ".post-date, .date, time"),
            "industry": _text("industry_selector", ".industry, .sector"),
        }

    def _extract_detail_link(self, el: Tag, config: dict) -> str | None:
        sel = config.get("detail_link_selector", "a.read-more, a.detail, a[href]")
        found = el.select_one(sel)
        if found:
            return found.get("href")
        return None

    def _extract_next_page(
        self, soup: BeautifulSoup, config: dict, base_url: str,
    ) -> str | None:
        sel = config.get("pagination_selector", "a.next, a[rel='next']")
        el = soup.select_one(sel)
        if el:
            href = el.get("href")
            if href:
                return urljoin(base_url, href)
        return None

    # ── Deadline / countdown parser ─────────────────────────────

    @staticmethod
    def _parse_deadline(text: str | None) -> str | None:
        """Parse countdown text into a human-readable deadline string.

        Ransomware groups commonly show a countdown timer (e.g. "2d 14h 30m")
        indicating when stolen data will be published if the ransom is not paid.
        """
        if not text:
            return None

        text = text.strip()

        # Try to interpret as a relative countdown
        match = _COUNTDOWN_RE.search(text)
        if match and any(match.groups()):
            days = int(match.group(1) or 0)
            hours = int(match.group(2) or 0)
            minutes = int(match.group(3) or 0)
            if days or hours or minutes:
                deadline_dt = datetime.now(timezone.utc) + timedelta(
                    days=days, hours=hours, minutes=minutes,
                )
                remaining = f"{days}d {hours}h {minutes}m"
                return f"{remaining} remaining (approx. {deadline_dt.strftime('%Y-%m-%d %H:%M UTC')})"

        # If the text looks like a date, return as-is
        if any(c.isdigit() for c in text):
            return text

        return None

    # ── Data size parser ────────────────────────────────────────

    @staticmethod
    def _parse_data_size(text: str | None) -> str | None:
        """Extract data size from text like '1.5 TB leaked'."""
        if not text:
            return None
        match = _SIZE_RE.search(text)
        if match:
            return f"{match.group(1)} {match.group(2).upper()}"
        return None

    # ── Date parser ─────────────────────────────────────────────

    @staticmethod
    def _parse_date(date_text: str | None) -> datetime | None:
        if not date_text:
            return None

        date_text = date_text.strip()

        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%d.%m.%Y %H:%M",
            "%d.%m.%Y",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y",
            "%b %d, %Y",
            "%B %d, %Y",
            "%d %b %Y",
            "%d %B %Y",
        ):
            try:
                return datetime.strptime(date_text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None

    # ── Discovery mode — scan for other .onion links ────────────

    def _scan_for_onion_links(self, soup: BeautifulSoup, current_base: str) -> None:
        """Find .onion URLs in page content that might be other ransomware group sites."""
        page_text = soup.get_text()

        # Match .onion URLs / bare hostnames
        onion_pattern = re.compile(
            r"(?:https?://)?([a-z2-7]{16,56}\.onion)(?:/\S*)?", re.IGNORECASE,
        )
        for match in onion_pattern.finditer(page_text):
            onion_host = match.group(1).lower()
            # Skip if it's a mirror of the current site
            current_host = re.search(r"([a-z2-7]{16,56}\.onion)", current_base, re.IGNORECASE)
            if current_host and onion_host == current_host.group(1).lower():
                continue
            self._discovered_onions.add(onion_host)

        # Also check <a href> links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            href_match = onion_pattern.search(href)
            if href_match:
                onion_host = href_match.group(1).lower()
                current_host = re.search(r"([a-z2-7]{16,56}\.onion)", current_base, re.IGNORECASE)
                if current_host and onion_host == current_host.group(1).lower():
                    continue
                self._discovered_onions.add(onion_host)

        if self._discovered_onions:
            logger.info(
                f"[{self.name}] Discovery: found {len(self._discovered_onions)} unique .onion addresses"
            )
