"""Generic 'plain IPv4 list' feed pattern.

A surprising number of public IP-reputation feeds publish themselves
as nothing more than ``one IPv4 per line`` plain-text files. Instead
of a separate Feed class per source, this module provides a base
``PlainIpListFeed`` that subclasses point at a URL.

Subclasses set:

  * ``name``             — feed_health key + canonical IOC source label
  * ``feed_url``         — URL to fetch; one IPv4 per line, no headers
  * ``severity``         — IOC severity to attribute (default ``high``)
  * ``confidence``       — confidence score 0..1 (default 0.8)
  * ``description_tmpl`` — per-row description (formatted with ``ip``)
  * ``expires_hours``    — how long IOCs from this list stay current

Lines that aren't a parseable IPv4 are skipped silently — most "plain
IP list" feeds occasionally include an empty line or a stray comment,
and we'd rather log a count than fail the whole tick.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import AsyncIterator, ClassVar

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


class PlainIpListFeed(BaseFeed):
    """Base — see module docstring. Subclasses MUST override
    ``name``, ``feed_url``, and ``description_tmpl``."""

    feed_url: ClassVar[str] = ""
    severity: ClassVar[str] = "high"
    confidence: ClassVar[float] = 0.8
    description_tmpl: ClassVar[str] = "Listed IP per {feed_label}: {ip}"
    feed_label: ClassVar[str] = ""
    layer = "ip_reputation"
    default_interval_seconds = 3600

    async def poll(self) -> AsyncIterator[FeedEntry]:
        if not self.feed_url:
            self.last_failure_reason = (
                f"{self.name} subclass forgot to set feed_url"
            )
            return

        lines = await self._fetch_csv_lines(self.feed_url, skip_comments=False)
        if not lines:
            self.last_failure_reason = f"{self.feed_url} returned no data"
            return

        count = 0
        skipped = 0
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            ip_token = line.split()[0]
            try:
                ip_obj = ipaddress.ip_address(ip_token)
            except ValueError:
                skipped += 1
                continue
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                # Same-day IPv6 list support is a no-op until our matchers
                # learn to read IPv6 IOCs; skip rather than corrupt.
                skipped += 1
                continue

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="ip",
                value=str(ip_obj),
                label=f"{self.feed_label or self.name}: {ip_obj}",
                description=self.description_tmpl.format(
                    feed_label=self.feed_label or self.name,
                    ip=str(ip_obj),
                ),
                severity=self.severity,
                confidence=self.confidence,
                ip_for_geo=str(ip_obj),
                country_code=None,
                latitude=None,
                longitude=None,
                feed_metadata={"source": self.name},
                first_seen=None,
                expires_hours=getattr(self, "expires_hours_value", 72),
            )
            count += 1

        logger.info(
            "[%s] yielded %d IP(s); skipped %d unparseable line(s)",
            self.name, count, skipped,
        )


class BlocklistDeFeed(PlainIpListFeed):
    """blocklist.de — IPs caught attacking honeypots / SSH brute-forcers.

    Blocklist.de aggregates ~50 honeypot operators and publishes a
    consolidated list of attackers seen across the network. The
    ``all.txt`` endpoint is the union of every category. Refreshes
    near-real-time but we poll hourly.
    """

    name = "blocklist_de"
    feed_url = "https://lists.blocklist.de/lists/all.txt"
    feed_label = "blocklist.de"
    severity = "high"
    confidence = 0.85
    description_tmpl = (
        "{feed_label}: IP {ip} caught attacking honeypots in the "
        "blocklist.de network (SSH/HTTP/IMAP/etc brute-force, scanning, "
        "or similar)."
    )
    expires_hours_value = 72


class CinsScoreFeed(PlainIpListFeed):
    """CINS Army (cinsscore.com) — Sentinel IPS intel team's curated
    list of poor-reputation IPs derived from their global sensor net."""

    name = "cins_score"
    feed_url = "http://cinsscore.com/list/ci-badguys.txt"
    feed_label = "CINS Army"
    severity = "high"
    confidence = 0.8
    description_tmpl = (
        "{feed_label}: IP {ip} flagged by Sentinel IPS as poor "
        "reputation (sustained malicious behaviour observed across "
        "their global sensor network)."
    )
    expires_hours_value = 72
