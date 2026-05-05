"""OpenPhish + PhishStats phishing URL feed."""

from __future__ import annotations


import logging
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import urlparse

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

# OpenPhish moved their canonical free feed in 2025 from
# ``openphish.com/feed.txt`` (now a 302) to a static raw file on
# GitHub. Pointing at the GitHub source directly removes the redirect
# dependency.
OPENPHISH_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)
# phishstats.info:2096 went offline in 2025. There's no drop-in free
# replacement that publishes a JSON list of high-score phishing URLs;
# OpenPhish above + URLhaus + PhishTank already cover the core
# defensive use case. Leaving this empty disables the second source
# in this feed without breaking the loop. To re-enable, point at any
# JSON endpoint with the same shape (``[{url, host, ...}]``).
PHISHSTATS_URL: str = ""


class PhishingFeed(BaseFeed):
    """Aggregates phishing URLs from OpenPhish (text list) and PhishStats (JSON API)."""

    name = "openphish"
    layer = "phishing"
    default_interval_seconds = 21600  # 6 hours

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        """Return the hostname from a URL, or None if unparseable."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            return host if host else None
        except Exception:
            return None

    @staticmethod
    def _severity_from_score(score: float | int) -> str:
        if score > 8:
            return "high"
        return "medium"

    # ------------------------------------------------------------------
    # Source: OpenPhish
    # ------------------------------------------------------------------

    async def _poll_openphish(self) -> AsyncIterator[FeedEntry]:
        """One URL per line — simple text feed."""
        text = await self._fetch_text(OPENPHISH_URL)
        if text is None:
            logger.warning("[%s] OpenPhish returned no data", self.name)
            return

        count = 0
        for raw_line in text.splitlines():
            url = raw_line.strip()
            if not url:
                continue

            domain = self._extract_domain(url)

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="url",
                value=url,
                label=domain,
                description=f"Phishing URL hosted on {domain}" if domain else "Phishing URL",
                severity="medium",
                confidence=0.7,
                ip_for_geo=None,
                country_code=None,
                latitude=None,
                longitude=None,
                feed_metadata={"source": "openphish"},
                first_seen=None,
                expires_hours=72,
            )
            count += 1

        logger.info("[%s] OpenPhish yielded %d entries", self.name, count)

    # ------------------------------------------------------------------
    # Source: PhishStats
    # ------------------------------------------------------------------

    async def _poll_phishstats(self) -> AsyncIterator[FeedEntry]:
        """JSON API returning scored phishing entries with IP / country."""
        if not PHISHSTATS_URL:
            # Source disabled (upstream went offline in 2025). Yield
            # nothing so the rest of the feed continues to work.
            return
        data = await self._fetch_json(PHISHSTATS_URL)
        if data is None:
            logger.warning("[%s] PhishStats returned no data", self.name)
            return

        if not isinstance(data, list):
            logger.warning("[%s] PhishStats response is not a list: %s", self.name, type(data))
            return

        count = 0
        for item in data:
            if not isinstance(item, dict):
                continue

            url = item.get("url")
            if not url or not isinstance(url, str):
                continue

            domain = self._extract_domain(url)
            score = item.get("score", 5)
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = 5.0

            ip_addr = item.get("ip")
            if ip_addr and not isinstance(ip_addr, str):
                ip_addr = str(ip_addr)

            country = item.get("country_code")
            if country and not isinstance(country, str):
                country = str(country)

            # Parse date if available
            first_seen: datetime | None = None
            date_str = item.get("date")
            if date_str:
                try:
                    first_seen = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            title = item.get("title")
            desc_parts = [f"Phishing URL on {domain}" if domain else "Phishing URL"]
            if title:
                desc_parts.append(f"Title: {title}")

            yield FeedEntry(
                feed_name="phishstats",
                layer=self.layer,
                entry_type="url",
                value=url,
                label=domain,
                description=" | ".join(desc_parts),
                severity=self._severity_from_score(score),
                confidence=min(score / 10.0, 1.0),
                ip_for_geo=ip_addr if ip_addr else None,
                country_code=country if country else None,
                latitude=None,
                longitude=None,
                feed_metadata={
                    "source": "phishstats",
                    "score": score,
                    "title": title,
                },
                first_seen=first_seen,
                expires_hours=72,
            )
            count += 1

        logger.info("[%s] PhishStats yielded %d entries", self.name, count)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def poll(self) -> AsyncIterator[FeedEntry]:
        """Merge OpenPhish and PhishStats into a single stream.

        Deduplication is intentionally light here — the downstream pipeline
        handles full dedup by (layer, entry_type, value).  We only log overlap.
        """
        seen_urls: set[str] = set()
        total = 0

        async for entry in self._poll_openphish():
            seen_urls.add(entry.value)
            total += 1
            yield entry

        dupes = 0
        async for entry in self._poll_phishstats():
            if entry.value in seen_urls:
                dupes += 1
                continue  # skip duplicate URL
            seen_urls.add(entry.value)
            total += 1
            yield entry

        logger.info(
            "[%s] poll complete — %d unique entries, %d cross-source duplicates skipped",
            self.name, total, dupes,
        )
