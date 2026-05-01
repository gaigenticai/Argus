"""GreyNoise feed — internet-wide scanner and noise intelligence.

GreyNoise classifies IPs into:
  - NOISE: mass-scanning the internet (benign scanners, botnets, research)
  - RIOT: known-good services (CDNs, DNS, cloud providers)

This feed pulls trending malicious scanners, CVE-exploiting IPs, and
high-priority GNQL results for the threat map.
"""

from __future__ import annotations


import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.config.settings import settings
from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

GREYNOISE_BASE = "https://api.greynoise.io/v3"

# Classification → severity mapping
_CLASSIFICATION_SEVERITY: dict[str, str] = {
    "malicious": "high",
    "unknown": "medium",
    "benign": "info",
}

# Known bot categories that indicate higher severity
_HIGH_SEVERITY_TAGS = frozenset({
    "Mirai", "Hajime", "Mozi", "ZeroAccess",
    "Cobalt Strike", "Metasploit", "Brute Ratel",
    "RDP Scanner", "SSH Scanner",
})


def _tag_severity(tags: list[str], classification: str) -> str:
    """Derive severity from classification and tags."""
    if classification == "malicious":
        for tag in tags:
            if tag in _HIGH_SEVERITY_TAGS:
                return "critical"
        return "high"
    return _CLASSIFICATION_SEVERITY.get(classification, "medium")


class GreyNoiseFeed(BaseFeed):
    """GreyNoise internet scanner intelligence — malicious scanners, CVE exploitation, trending threats."""

    name = "greynoise"
    layer = "ip_reputation"
    default_interval_seconds = 3600  # 1 hour

    def _headers(self) -> dict[str, str]:
        return {
            "key": settings.feeds.greynoise_api_key or "",
            "Accept": "application/json",
        }

    async def poll(self) -> AsyncIterator[FeedEntry]:
        api_key = settings.feeds.greynoise_api_key
        if not api_key:
            self.last_unconfigured_reason = (
                "ARGUS_FEED_GREYNOISE_API_KEY is not set; GreyNoise will not "
                "run until the operator adds an API key from "
                "https://www.greynoise.io/"
            )
            logger.info("[%s] GreyNoise: %s", self.name, self.last_unconfigured_reason)
            return

        seen_ips: set[str] = set()

        # 1. Malicious internet scanners (highest priority)
        async for entry in self._poll_gnql("classification:malicious last_seen:1d", seen_ips):
            yield entry

        # 2. IPs exploiting known CVEs in the wild
        async for entry in self._poll_gnql("cve:* classification:malicious last_seen:1d", seen_ips):
            yield entry

        # 3. Botnet-associated scanners
        async for entry in self._poll_gnql(
            'tags:"Mirai" OR tags:"Hajime" OR tags:"Mozi" last_seen:1d',
            seen_ips,
        ):
            yield entry

        # 4. Targeted scanners (non-mass-scan, more suspicious)
        async for entry in self._poll_gnql(
            "spoofable:false classification:malicious last_seen:1d",
            seen_ips,
        ):
            yield entry

    async def _poll_gnql(
        self,
        query: str,
        seen_ips: set[str],
        max_results: int = 2000,
    ) -> AsyncIterator[FeedEntry]:
        """Execute a GNQL query and yield FeedEntries for matching IPs."""
        total_yielded = 0
        scroll_token: str | None = None
        fetched = 0

        while fetched < max_results:
            params: dict[str, str] = {
                "query": query,
                "size": str(min(1000, max_results - fetched)),
            }
            if scroll_token:
                params["scroll"] = scroll_token

            data = await self._fetch_json(
                f"{GREYNOISE_BASE}/noise/gnql",
                headers=self._headers(),
                params=params,
            )

            if not data or not isinstance(data, dict):
                break

            results = data.get("data", [])
            if not isinstance(results, list) or not results:
                break

            for item in results:
                if not isinstance(item, dict):
                    continue

                ip = item.get("ip")
                if not ip or not isinstance(ip, str) or ip in seen_ips:
                    continue
                seen_ips.add(ip)

                entry = self._item_to_entry(item)
                if entry:
                    total_yielded += 1
                    yield entry

            fetched += len(results)
            scroll_token = data.get("scroll")
            if not scroll_token:
                break

        logger.info(
            "[%s] GNQL query '%s': yielded %d IPs",
            self.name,
            query[:60],
            total_yielded,
        )

    def _item_to_entry(self, item: dict) -> FeedEntry | None:
        """Convert a single GreyNoise result to a FeedEntry."""
        ip = item.get("ip", "")
        classification = item.get("classification", "unknown")
        tags = item.get("tags", []) or []
        if not isinstance(tags, list):
            tags = []

        cve_list = item.get("cve", []) or []
        if not isinstance(cve_list, list):
            cve_list = []

        # Metadata from GreyNoise
        actor = item.get("actor") or ""
        asn = item.get("asn") or ""
        city = item.get("city") or ""
        country = item.get("country") or ""
        country_code = item.get("country_code") or ""
        organization = item.get("organization") or ""
        operating_system = item.get("operating_system") or ""
        bot = item.get("bot", False)
        vpn = item.get("vpn", False)
        vpn_service = item.get("vpn_service") or ""
        first_seen_str = item.get("first_seen") or ""
        last_seen_str = item.get("last_seen") or ""

        severity = _tag_severity(tags, classification)

        # Build description
        desc_parts = [f"GreyNoise: {classification} scanner"]
        if actor:
            desc_parts.append(f"Actor: {actor}")
        if tags:
            desc_parts.append(f"Tags: {', '.join(tags[:6])}")
        if cve_list:
            desc_parts.append(f"CVEs: {', '.join(cve_list[:5])}")
        if organization:
            desc_parts.append(f"Org: {organization}")
        if bot:
            desc_parts.append("Known botnet")
        if vpn:
            desc_parts.append(f"VPN: {vpn_service}" if vpn_service else "VPN detected")

        # Build label
        label_parts = []
        if actor:
            label_parts.append(actor)
        elif tags:
            label_parts.append(tags[0])
        elif classification == "malicious":
            label_parts.append("Malicious Scanner")
        else:
            label_parts.append("Internet Scanner")
        label_parts.append(ip)

        # Confidence based on classification and data richness
        confidence = 0.7
        if classification == "malicious":
            confidence = 0.85
            if tags:
                confidence = 0.9
            if cve_list:
                confidence = 0.95
        elif classification == "benign":
            confidence = 0.6

        # Parse dates
        first_seen: datetime | None = None
        if first_seen_str:
            try:
                first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc,
                )
            except (ValueError, TypeError):
                pass

        # Determine layer based on content
        layer = self.layer
        if cve_list:
            layer = "exploited_cve"
        elif bot:
            layer = "botnet_c2"

        return FeedEntry(
            feed_name=self.name,
            layer=layer,
            entry_type="ip",
            value=ip,
            label=": ".join(label_parts),
            description=" | ".join(desc_parts),
            severity=severity,
            confidence=confidence,
            ip_for_geo=ip,
            country_code=country_code if country_code else None,
            feed_metadata={
                "source": "greynoise",
                "classification": classification,
                "actor": actor,
                "tags": tags[:10],
                "cve": cve_list[:10],
                "asn": asn,
                "organization": organization,
                "os": operating_system,
                "bot": bot,
                "vpn": vpn,
                "vpn_service": vpn_service,
                "city": city,
                "country": country,
                "first_seen": first_seen_str,
                "last_seen": last_seen_str,
            },
            first_seen=first_seen,
            expires_hours=168,  # 7 days
        )
