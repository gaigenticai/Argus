"""AlienVault OTX (Open Threat Exchange) feed — community threat intelligence pulses.

Pulls subscribed pulses and their indicators from OTX DirectConnect API v1.
Provides multi-layer threat data: IPs, domains, URLs, hashes, CVEs.
"""

import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.config.settings import settings
from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1"

# Map OTX indicator types to Argus entry types and layers
_INDICATOR_MAP: dict[str, dict] = {
    "IPv4": {"entry_type": "ip", "layer": "ip_reputation", "geo": True},
    "IPv6": {"entry_type": "ip", "layer": "ip_reputation", "geo": True},
    "domain": {"entry_type": "domain", "layer": "malware", "geo": False},
    "hostname": {"entry_type": "domain", "layer": "malware", "geo": False},
    "URL": {"entry_type": "url", "layer": "phishing", "geo": False},
    "FileHash-MD5": {"entry_type": "hash", "layer": "malware", "geo": False},
    "FileHash-SHA1": {"entry_type": "hash", "layer": "malware", "geo": False},
    "FileHash-SHA256": {"entry_type": "hash", "layer": "malware", "geo": False},
    "email": {"entry_type": "email", "layer": "phishing", "geo": False},
    "CVE": {"entry_type": "cve", "layer": "exploited_cve", "geo": False},
    "CIDR": {"entry_type": "cidr", "layer": "ip_reputation", "geo": False},
    "Mutex": {"entry_type": "mutex", "layer": "malware", "geo": False},
    "YARA": {"entry_type": "yara", "layer": "malware", "geo": False},
}

# OTX pulse tags → severity mapping
_HIGH_SEVERITY_TAGS = frozenset({
    "ransomware", "apt", "zero-day", "0day", "exploit", "c2", "c&c",
    "command and control", "rat", "rootkit", "backdoor", "critical",
})
_MEDIUM_SEVERITY_TAGS = frozenset({
    "malware", "phishing", "trojan", "botnet", "stealer", "infostealer",
    "spam", "scanner", "brute-force", "credential",
})


def _pulse_severity(tags: list[str], adversary: str | None) -> str:
    """Derive severity from pulse tags and adversary attribution."""
    lower_tags = {t.lower() for t in tags}
    if adversary or lower_tags & _HIGH_SEVERITY_TAGS:
        return "high"
    if lower_tags & _MEDIUM_SEVERITY_TAGS:
        return "medium"
    return "low"


def _pulse_confidence(pulse: dict) -> float:
    """Estimate confidence from pulse metadata."""
    # Factors: subscriber count, indicator count, adversary attribution, TLP
    subscribers = pulse.get("subscriber_count", 0)
    indicators_count = len(pulse.get("indicators", []))
    has_adversary = bool(pulse.get("adversary"))
    has_references = bool(pulse.get("references"))

    score = 0.5
    if subscribers > 100:
        score += 0.15
    elif subscribers > 10:
        score += 0.1
    if indicators_count > 20:
        score += 0.1
    if has_adversary:
        score += 0.1
    if has_references:
        score += 0.05
    return min(1.0, score)


class OTXFeed(BaseFeed):
    """AlienVault OTX DirectConnect — subscribed pulse indicators."""

    name = "otx_pulse"
    layer = "ip_reputation"  # Primary layer; entries route to correct layer per indicator type
    default_interval_seconds = 3600  # 1 hour

    def _headers(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": settings.feeds.otx_api_key or ""}

    async def poll(self) -> AsyncIterator[FeedEntry]:
        api_key = settings.feeds.otx_api_key
        if not api_key:
            logger.info("[%s] OTX: no API key configured, skipping", self.name)
            return

        # Fetch subscribed pulses modified in the last 24 hours
        async for entry in self._poll_subscribed_pulses():
            yield entry

        # Fetch pulses from curated collections
        async for entry in self._poll_activity_feed():
            yield entry

    async def _poll_subscribed_pulses(self) -> AsyncIterator[FeedEntry]:
        """Pull IOCs from pulses the user is subscribed to (modified recently)."""
        page = 1
        total_indicators = 0
        max_pages = 10  # Safety limit

        while page <= max_pages:
            data = await self._fetch_json(
                f"{OTX_BASE}/pulses/subscribed",
                headers=self._headers(),
                params={"modified_since": "1d", "page": str(page), "limit": "50"},
            )
            if not data or not isinstance(data, dict):
                break

            results = data.get("results", [])
            if not results:
                break

            for pulse in results:
                async for entry in self._process_pulse(pulse):
                    total_indicators += 1
                    yield entry

            # Check for next page
            next_url = data.get("next")
            if not next_url:
                break
            page += 1

        logger.info("[%s] Subscribed pulses: yielded %d indicators", self.name, total_indicators)

    async def _poll_activity_feed(self) -> AsyncIterator[FeedEntry]:
        """Pull recent activity from OTX community (top pulses)."""
        data = await self._fetch_json(
            f"{OTX_BASE}/pulses/activity",
            headers=self._headers(),
            params={"page": "1", "limit": "20"},
        )
        if not data or not isinstance(data, dict):
            return

        results = data.get("results", [])
        count = 0
        for pulse in results:
            async for entry in self._process_pulse(pulse):
                count += 1
                yield entry

        logger.info("[%s] Activity feed: yielded %d indicators", self.name, count)

    async def _process_pulse(self, pulse: dict) -> AsyncIterator[FeedEntry]:
        """Extract FeedEntry objects from a single OTX pulse."""
        if not isinstance(pulse, dict):
            return

        pulse_id = pulse.get("id", "")
        pulse_name = pulse.get("name", "Unknown Pulse")
        tags = pulse.get("tags", []) or []
        adversary = pulse.get("adversary")
        tlp = pulse.get("tlp") or "white"
        references = pulse.get("references", []) or []

        severity = _pulse_severity(tags, adversary)
        confidence = _pulse_confidence(pulse)

        # Parse pulse creation time
        created_str = pulse.get("created")
        first_seen: datetime | None = None
        if created_str:
            try:
                first_seen = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        indicators = pulse.get("indicators", [])
        if not isinstance(indicators, list):
            return

        seen_values: set[str] = set()

        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue

            ioc_type = indicator.get("type", "")
            value = indicator.get("indicator", "")
            if not value or not isinstance(value, str):
                continue

            mapping = _INDICATOR_MAP.get(ioc_type)
            if not mapping:
                continue

            # Dedup within this pulse
            dedup_key = f"{ioc_type}:{value}"
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)

            entry_type = mapping["entry_type"]
            layer = mapping["layer"]
            do_geo = mapping["geo"]

            # Indicator-level metadata
            title = indicator.get("title") or ""
            description_parts = [f"OTX Pulse: {pulse_name}"]
            if adversary:
                description_parts.append(f"Adversary: {adversary}")
            if title:
                description_parts.append(title)
            if tags:
                description_parts.append(f"Tags: {', '.join(tags[:8])}")

            yield FeedEntry(
                feed_name=self.name,
                layer=layer,
                entry_type=entry_type,
                value=value,
                label=f"{adversary or pulse_name}: {value}" if len(value) < 60 else f"{adversary or pulse_name}: {value[:50]}...",
                description=" | ".join(description_parts),
                severity=severity,
                confidence=confidence,
                ip_for_geo=value if do_geo else None,
                feed_metadata={
                    "source": "otx",
                    "pulse_id": pulse_id,
                    "pulse_name": pulse_name,
                    "adversary": adversary,
                    "tlp": tlp,
                    "tags": tags[:10],
                    "references": references[:5],
                    "ioc_type": ioc_type,
                },
                first_seen=first_seen,
                expires_hours=336,  # 14 days
            )
