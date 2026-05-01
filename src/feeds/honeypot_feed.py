"""Honeypot intelligence feed — polls DShield/SANS ISC API for top attacking IPs and global threat level."""

from __future__ import annotations


import ipaddress
import logging
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

INTELFEED_URL = "https://isc.sans.edu/api/intelfeed?json"
TOPIPS_URL = "https://isc.sans.edu/api/topips/records/100?json"
INFOCON_URL = "https://isc.sans.edu/api/infocon?json"


def _severity_from_count(count: int) -> str:
    """Map attack count to severity level."""
    if count > 10000:
        return "critical"
    if count > 1000:
        return "high"
    if count > 100:
        return "medium"
    return "low"


def _is_valid_ip(value: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _safe_int(value, default: int = 0) -> int:
    """Coerce a value to int, returning default on failure."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


class HoneypotFeed(BaseFeed):
    """Polls DShield/SANS Internet Storm Center for top attacking IPs and global infocon status."""

    name = "dshield"
    layer = "honeypot"
    default_interval_seconds = 300  # 5 minutes — attack data is highly ephemeral

    async def poll(self) -> AsyncIterator[FeedEntry]:
        """Yield attacker IP entries and a global infocon status entry."""
        seen_ips: set[str] = set()

        # ── Fetch infocon first (used as metadata on every entry) ───────
        infocon_status = "unknown"
        infocon_data = await self._fetch_json(INFOCON_URL)
        if isinstance(infocon_data, dict):
            infocon_status = (infocon_data.get("status") or "unknown").strip().lower()
        elif isinstance(infocon_data, list) and infocon_data:
            # Some ISC endpoints wrap response in a list
            first = infocon_data[0] if infocon_data else {}
            if isinstance(first, dict):
                infocon_status = (first.get("status") or "unknown").strip().lower()
        logger.info("[%s] DShield infocon status: %s", self.name, infocon_status)

        # Yield infocon as a special status entry for GlobalThreatStatus pipeline
        yield FeedEntry(
            feed_name=self.name,
            layer=self.layer,
            entry_type="status",
            value=infocon_status,
            label=f"DShield Infocon: {infocon_status}",
            description=(
                f"SANS Internet Storm Center global threat level is '{infocon_status}'. "
                "Levels: green (normal), yellow (notable increase), orange (significant), "
                "red (critical widespread threat)."
            ),
            severity=_infocon_to_severity(infocon_status),
            confidence=1.0,
            feed_metadata={
                "infocon": infocon_status,
                "source": "dshield_infocon",
            },
            expires_hours=1,  # Re-evaluated every poll cycle
        )

        # ── Source 1: Intel feed ────────────────────────────────────────
        intel_data = await self._fetch_json(INTELFEED_URL)
        intel_count = 0
        if isinstance(intel_data, list):
            for record in intel_data:
                if not isinstance(record, dict):
                    continue
                ip = (record.get("ipv4") or record.get("ip") or "").strip()
                if not ip or not _is_valid_ip(ip):
                    continue
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                intel_count += 1

                count = _safe_int(record.get("count") or record.get("attacks"))
                severity = _severity_from_count(count)

                yield FeedEntry(
                    feed_name=self.name,
                    layer=self.layer,
                    entry_type="ip",
                    value=ip,
                    label=f"Attacker: {ip} ({count} attacks)",
                    description=(
                        f"DShield intel feed — IP {ip} observed in {count} attack events "
                        f"across SANS honeypot sensors."
                    ),
                    severity=severity,
                    confidence=0.8,
                    ip_for_geo=ip,
                    feed_metadata={
                        "attacks": count,
                        "infocon": infocon_status,
                        "source": "dshield_intelfeed",
                        "first_seen": record.get("first_seen"),
                        "last_seen": record.get("last_seen"),
                    },
                    expires_hours=24,
                )

            logger.info("[%s] Intel feed yielded %d IPs", self.name, intel_count)
        elif intel_data is not None:
            # Might be a dict wrapping the array
            if isinstance(intel_data, dict):
                # Try common wrapper keys
                for key in ("data", "records", "results"):
                    if key in intel_data and isinstance(intel_data[key], list):
                        # Re-process — but to keep poll() as a generator, just log and move on.
                        # The topips source below will provide coverage.
                        logger.info(
                            "[%s] Intel feed returned dict with '%s' key (%d records) — "
                            "skipping nested parse, topips will cover",
                            self.name,
                            key,
                            len(intel_data[key]),
                        )
                        break
                else:
                    logger.warning(
                        "[%s] Intel feed returned unexpected dict structure", self.name
                    )

        # ── Source 2: Top 100 attacking IPs ─────────────────────────────
        topips_data = await self._fetch_json(TOPIPS_URL)
        topips_count = 0

        # Normalize response — ISC sometimes wraps in a dict
        records: list[dict] = []
        if isinstance(topips_data, list):
            records = topips_data
        elif isinstance(topips_data, dict):
            for key in ("data", "records", "results", "topips"):
                if key in topips_data and isinstance(topips_data[key], list):
                    records = topips_data[key]
                    break
            if not records:
                # The dict itself might be a single record or have numbered keys
                logger.warning(
                    "[%s] topips returned dict without recognizable list key", self.name
                )

        for record in records:
            if not isinstance(record, dict):
                continue

            ip = (
                record.get("ipv4")
                or record.get("ip")
                or record.get("source")
                or ""
            ).strip()

            if not ip or not _is_valid_ip(ip):
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            topips_count += 1

            count = _safe_int(
                record.get("count") or record.get("attacks") or record.get("reports")
            )
            severity = _severity_from_count(count)

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="ip",
                value=ip,
                label=f"Attacker: {ip} ({count} attacks)",
                description=(
                    f"DShield top attacker — IP {ip} ranked in top 100 with {count} "
                    f"attack events across global honeypot network."
                ),
                severity=severity,
                confidence=0.85,
                ip_for_geo=ip,
                feed_metadata={
                    "attacks": count,
                    "infocon": infocon_status,
                    "source": "dshield_topips",
                    "first_seen": record.get("first_seen"),
                    "last_seen": record.get("last_seen"),
                },
                expires_hours=24,
            )

        logger.info("[%s] Top IPs yielded %d new IPs", self.name, topips_count)
        logger.info(
            "[%s] Total unique attacker IPs: %d", self.name, len(seen_ips)
        )


def _infocon_to_severity(status: str) -> str:
    """Map DShield infocon level to our severity scale."""
    return {
        "green": "low",
        "yellow": "medium",
        "orange": "high",
        "red": "critical",
    }.get(status, "medium")
