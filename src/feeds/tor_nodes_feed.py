"""Tor exit node IP feed — Tor Project bulk list + dan.me.uk mirror."""

from __future__ import annotations


import logging
import re
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

TORPROJECT_BULK_URL = "https://check.torproject.org/torbulkexitlist"
DAN_ME_UK_URL = "https://www.dan.me.uk/torlist/?exit"

# Simple IPv4 validation — reject garbage lines without pulling in ipaddress
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
# IPv6 — loose check (colons present, hex chars)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def _is_valid_ip(value: str) -> bool:
    """Quick syntactic check for IPv4 or IPv6."""
    return bool(_IPV4_RE.match(value) or (_IPV6_RE.match(value) and ":" in value))


class TorNodesFeed(BaseFeed):
    """Collects known Tor exit node IPs from authoritative public lists.

    Tor exit nodes are not inherently malicious — they indicate anonymised
    traffic.  Severity is therefore ``info`` with full confidence (the lists
    are authoritative).  Downstream layers can combine this with other signals
    to escalate.
    """

    name = "tor_bulk_exit"
    layer = "tor_exit"
    default_interval_seconds = 1800  # 30 minutes

    # ------------------------------------------------------------------
    # Source fetchers
    # ------------------------------------------------------------------

    async def _fetch_torproject(self) -> set[str]:
        """Tor Project bulk exit list — one IP per line, no comments."""
        text = await self._fetch_text(TORPROJECT_BULK_URL)
        if text is None:
            logger.warning("[%s] Tor Project bulk list returned no data", self.name)
            return set()

        ips: set[str] = set()
        for line in text.splitlines():
            ip = line.strip()
            if ip and _is_valid_ip(ip):
                ips.add(ip)

        logger.info("[%s] Tor Project list: %d IPs", self.name, len(ips))
        return ips

    async def _fetch_dan_me_uk(self) -> set[str]:
        """dan.me.uk exit list — one IP per line, may have HTML preamble."""
        text = await self._fetch_text(DAN_ME_UK_URL)
        if text is None:
            logger.warning("[%s] dan.me.uk list returned no data", self.name)
            return set()

        ips: set[str] = set()
        for line in text.splitlines():
            ip = line.strip()
            # dan.me.uk occasionally serves an HTML rate-limit page
            if ip and _is_valid_ip(ip):
                ips.add(ip)

        logger.info("[%s] dan.me.uk list: %d IPs", self.name, len(ips))
        return ips

    # ------------------------------------------------------------------
    # Entry builders
    # ------------------------------------------------------------------

    @staticmethod
    def _make_entry(ip: str, source: str) -> FeedEntry:
        return FeedEntry(
            feed_name="tor_bulk_exit",
            layer="tor_exit",
            entry_type="ip",
            value=ip,
            label=f"Tor Exit: {ip}",
            description=f"Known Tor exit node (source: {source})",
            severity="info",
            confidence=1.0,
            ip_for_geo=ip,
            country_code=None,
            latitude=None,
            longitude=None,
            feed_metadata={"source": source},
            first_seen=None,
            expires_hours=48,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def poll(self) -> AsyncIterator[FeedEntry]:
        """Fetch the Tor Project bulk list, yield one entry per IP.

        ``check.torproject.org/torbulkexitlist`` is the canonical
        upstream — every other public Tor exit list (incl. dan.me.uk)
        is a mirror of it. We dropped the dan.me.uk secondary source
        in 2025 after they began rate-limiting automated callers
        (HTTP 403 with JS challenge); keeping it as a "second
        authoritative" source was always misleading anyway.
        """
        torproject_ips = await self._fetch_torproject()
        for ip in torproject_ips:
            yield self._make_entry(ip, "torproject")
        logger.info(
            "[%s] poll complete — %d unique exit nodes from torproject.org",
            self.name, len(torproject_ips),
        )
