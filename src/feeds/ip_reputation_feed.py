"""IP reputation feed — aggregates malicious IP intelligence from multiple blocklists."""

import logging
from typing import AsyncIterator

from src.config.settings import settings
from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

# ── Source URLs ──────────────────────────────────────────────────────────────
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/all.txt"
FIREHOL_L1_URL = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
)

MAX_ENTRIES_PER_SOURCE = 5000


def _ipsum_severity(count: int) -> str:
    if count >= 8:
        return "critical"
    if count >= 6:
        return "high"
    if count >= 4:
        return "medium"
    return "low"


ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def _abuseipdb_severity(score: int) -> str:
    if score == 100:
        return "critical"
    if score >= 90:
        return "high"
    if score >= 75:
        return "medium"
    return "low"


class IPReputationFeed(BaseFeed):
    """Aggregated IP reputation intelligence from IPsum, Blocklist.de, FireHOL Level 1, and AbuseIPDB."""

    name = "ipsum"
    layer = "ip_reputation"
    default_interval_seconds = 3600

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        async for entry in self._poll_ipsum():
            yield entry
        async for entry in self._poll_blocklist_de():
            yield entry
        async for entry in self._poll_firehol():
            yield entry
        async for entry in self._poll_abuseipdb():
            yield entry

    # ── IPsum ────────────────────────────────────────────────────────────────

    async def _poll_ipsum(self) -> AsyncIterator[FeedEntry]:
        lines = await self._fetch_csv_lines(IPSUM_URL, skip_comments=True)
        if not lines:
            logger.warning("[%s] IPsum returned no data", self.name)
            return

        # Parse all lines into (ip, count) tuples, filtering count >= 3
        scored: list[tuple[str, int]] = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            ip = parts[0].strip()
            try:
                count = int(parts[1].strip())
            except ValueError:
                continue
            if count < 3:
                continue
            scored.append((ip, count))

        # Sort descending by count and take top N
        scored.sort(key=lambda x: x[1], reverse=True)
        scored = scored[:MAX_ENTRIES_PER_SOURCE]

        logger.info("[%s] IPsum: ingesting %d IPs (count >= 3)", self.name, len(scored))

        for ip, count in scored:
            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="ip",
                value=ip,
                label=f"Malicious IP: {ip}",
                description=f"Listed on {count} blocklist(s) (IPsum aggregation)",
                severity=_ipsum_severity(count),
                confidence=min(1.0, count / 8),
                ip_for_geo=ip,
                feed_metadata={"source": "ipsum", "score": count},
                expires_hours=168,
            )

    # ── Blocklist.de ─────────────────────────────────────────────────────────

    async def _poll_blocklist_de(self) -> AsyncIterator[FeedEntry]:
        lines = await self._fetch_csv_lines(BLOCKLIST_DE_URL, skip_comments=True)
        if not lines:
            logger.warning("[%s] Blocklist.de returned no data", self.name)
            return

        seen: set[str] = set()
        emitted = 0

        for line in lines:
            ip = line.strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)

            yield FeedEntry(
                feed_name="blocklist_de",
                layer=self.layer,
                entry_type="ip",
                value=ip,
                label=f"Malicious IP: {ip}",
                description="Attacking IP reported to blocklist.de (SSH/FTP/mail/web services)",
                severity="medium",
                confidence=0.7,
                ip_for_geo=ip,
                feed_metadata={"source": "blocklist_de"},
                expires_hours=168,
            )

            emitted += 1
            if emitted >= MAX_ENTRIES_PER_SOURCE:
                break

        logger.info("[%s] Blocklist.de: ingested %d IPs", self.name, emitted)

    # ── FireHOL Level 1 ─────────────────────────────────────────────────────

    async def _poll_firehol(self) -> AsyncIterator[FeedEntry]:
        lines = await self._fetch_csv_lines(FIREHOL_L1_URL, skip_comments=True)
        if not lines:
            logger.warning("[%s] FireHOL L1 returned no data", self.name)
            return

        seen: set[str] = set()
        emitted = 0

        for line in lines:
            ip = line.strip()
            # Skip CIDR ranges (contain /) and empty/duplicate lines
            if not ip or "/" in ip or ip in seen:
                continue
            seen.add(ip)

            yield FeedEntry(
                feed_name="firehol_l1",
                layer=self.layer,
                entry_type="ip",
                value=ip,
                label=f"Malicious IP: {ip}",
                description="FireHOL Level 1 — high-confidence malicious IP (aggregated from multiple feeds)",
                severity="high",
                confidence=0.85,
                ip_for_geo=ip,
                feed_metadata={"source": "firehol_l1"},
                expires_hours=168,
            )

            emitted += 1
            if emitted >= MAX_ENTRIES_PER_SOURCE:
                break

        logger.info("[%s] FireHOL L1: ingested %d IPs", self.name, emitted)

    # ── AbuseIPDB Blacklist ───────────────────────────────────────────────────

    async def _poll_abuseipdb(self) -> AsyncIterator[FeedEntry]:
        api_key = settings.feeds.abuseipdb_api_key
        if not api_key:
            logger.info("[%s] AbuseIPDB: no API key configured, skipping", self.name)
            return

        data = await self._fetch_json(
            ABUSEIPDB_BLACKLIST_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            params={"confidenceMinimum": "90", "limit": "10000"},
        )
        if data is None:
            logger.warning("[%s] AbuseIPDB blacklist returned no data", self.name)
            return

        if not isinstance(data, dict):
            logger.warning("[%s] AbuseIPDB unexpected response type: %s", self.name, type(data))
            return

        entries = data.get("data")
        if not isinstance(entries, list):
            logger.warning("[%s] AbuseIPDB 'data' is not a list", self.name)
            return

        emitted = 0
        for item in entries:
            if not isinstance(item, dict):
                continue

            ip = item.get("ipAddress")
            if not ip or not isinstance(ip, str):
                continue

            score = item.get("abuseConfidenceScore", 100)
            try:
                score = int(score)
            except (TypeError, ValueError):
                score = 100

            country_code = item.get("countryCode")
            last_reported = item.get("lastReportedAt")

            yield FeedEntry(
                feed_name="abuseipdb",
                layer=self.layer,
                entry_type="ip",
                value=ip,
                label=f"Abused IP: {ip}",
                description=f"AbuseIPDB confidence score {score}% — community-reported malicious IP",
                severity=_abuseipdb_severity(score),
                confidence=score / 100.0,
                ip_for_geo=ip,
                country_code=country_code if isinstance(country_code, str) else None,
                feed_metadata={
                    "source": "abuseipdb",
                    "abuse_confidence_score": score,
                    "last_reported_at": last_reported,
                },
                expires_hours=168,
            )
            emitted += 1

        logger.info("[%s] AbuseIPDB: ingested %d IPs", self.name, emitted)
