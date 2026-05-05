"""Botnet C2 intelligence feed — aggregates Feodo Tracker and montysecurity C2-Tracker IP lists."""

from __future__ import annotations


import ipaddress
import logging
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

# montysecurity/C2-Tracker restructured in 2025 — the static
# ``data/*.txt`` lists this feed used to ingest were deleted upstream
# (the repo now ships only a ``tracker.py`` script + an OpenCTI
# connector, no public IP files). Keeping the dict empty preserves the
# loop without producing 5x 404s every tick. If the project republishes
# the lists later, repopulate this dict.
C2_TRACKER_SOURCES: dict[str, str] = {}


def _is_valid_ip(value: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class BotnetFeed(BaseFeed):
    """Aggregates multiple botnet C2 tracker sources into a unified IP indicator stream."""

    name = "feodo_tracker"
    layer = "botnet_c2"
    default_interval_seconds = 3600  # 1 hour

    FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

    async def poll(self) -> AsyncIterator[FeedEntry]:
        """Yield C2 IP entries from Feodo Tracker and montysecurity C2-Tracker."""
        seen_ips: set[str] = set()

        # ── Source 1: Feodo Tracker (abuse.ch) ──────────────────────────
        feodo_lines = await self._fetch_csv_lines(self.FEODO_URL, skip_comments=True)
        feodo_count = 0
        for line in feodo_lines:
            ip = line.strip()
            if not ip or not _is_valid_ip(ip):
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            feodo_count += 1

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="ip",
                value=ip,
                label=f"C2: {ip}",
                description=(
                    f"Feodo Tracker recommended blocklist — known botnet C2 server {ip}. "
                    "Associated with malware families such as Dridex, Emotet, TrickBot, and QakBot."
                ),
                severity="high",
                confidence=0.9,
                ip_for_geo=ip,
                feed_metadata={
                    "source": "feodo_tracker",
                    "malware_family": "feodo_blocklist",
                },
                expires_hours=168,
            )

        logger.info("[%s] Feodo Tracker yielded %d IPs", self.name, feodo_count)

        # ── Source 2: montysecurity C2-Tracker ──────────────────────────
        for framework, url in C2_TRACKER_SOURCES.items():
            lines = await self._fetch_csv_lines(url, skip_comments=True)
            framework_count = 0
            for line in lines:
                ip = line.strip()
                if not ip or not _is_valid_ip(ip):
                    continue
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                framework_count += 1

                yield FeedEntry(
                    feed_name="c2_tracker",
                    layer=self.layer,
                    entry_type="ip",
                    value=ip,
                    label=f"{framework} C2: {ip}",
                    description=(
                        f"C2-Tracker detection — IP {ip} identified as active "
                        f"{framework} command-and-control infrastructure."
                    ),
                    severity="high",
                    confidence=0.85,
                    ip_for_geo=ip,
                    feed_metadata={
                        "source": "c2_tracker",
                        "malware_family": framework,
                        "tracker_url": url,
                    },
                    expires_hours=168,
                )

            logger.info(
                "[%s] C2-Tracker %s yielded %d IPs", self.name, framework, framework_count
            )

        logger.info("[%s] Total unique C2 IPs: %d", self.name, len(seen_ips))
