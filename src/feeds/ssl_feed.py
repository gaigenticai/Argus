"""abuse.ch SSL Blacklist (SSLBL) feed — malicious SSL certificates, C2 IPs, and JA3 fingerprints."""

import csv
import io
import logging
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

# ── Source URLs ──────────────────────────────────────────────────────────────
SSLBL_CERT_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
SSLBL_IP_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
SSLBL_JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"


class SSLFeed(BaseFeed):
    """abuse.ch SSL Blacklist — malicious SSL certificates, C2 server IPs, and JA3 fingerprints."""

    name = "sslbl"
    layer = "ssl_abuse"
    default_interval_seconds = 3600

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        async for entry in self._poll_ssl_certs():
            yield entry
        async for entry in self._poll_ssl_ips():
            yield entry
        async for entry in self._poll_ja3():
            yield entry

    # ── SSL Certificate Blacklist ────────────────────────────────────────────

    async def _poll_ssl_certs(self) -> AsyncIterator[FeedEntry]:
        text = await self._fetch_text(SSLBL_CERT_URL)
        if not text:
            logger.warning("[%s] SSLBL certificate blacklist returned no data", self.name)
            return

        # Strip comment lines (start with #), then parse remaining CSV
        clean_lines = [
            line for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not clean_lines:
            return

        reader = csv.reader(io.StringIO("\n".join(clean_lines)))
        emitted = 0

        for row in reader:
            if len(row) < 3:
                continue

            listing_date, sha1, listing_reason = row[0].strip(), row[1].strip(), row[2].strip()

            # Skip the actual header row if present
            if sha1.lower() == "sha1":
                continue

            if not sha1:
                continue

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="hash",
                value=sha1,
                label=f"Malicious SSL: {sha1[:16]}...",
                description=listing_reason or "Blacklisted SSL certificate",
                severity="high",
                confidence=0.9,
                feed_metadata={"source": "sslbl_certs", "listing_date": listing_date},
                expires_hours=336,  # 14 days
            )
            emitted += 1

        logger.info("[%s] SSL certs: ingested %d entries", self.name, emitted)

    # ── SSL C2 IP Blacklist ──────────────────────────────────────────────────

    async def _poll_ssl_ips(self) -> AsyncIterator[FeedEntry]:
        text = await self._fetch_text(SSLBL_IP_URL)
        if not text:
            logger.warning("[%s] SSLBL IP blacklist returned no data", self.name)
            return

        clean_lines = [
            line for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not clean_lines:
            return

        reader = csv.reader(io.StringIO("\n".join(clean_lines)))
        seen: set[str] = set()
        emitted = 0

        for row in reader:
            if len(row) < 3:
                continue

            first_seen_str, dst_ip, dst_port = row[0].strip(), row[1].strip(), row[2].strip()

            # Skip header row
            if dst_ip.lower() == "dstip":
                continue

            if not dst_ip or dst_ip in seen:
                continue
            seen.add(dst_ip)

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="ip",
                value=dst_ip,
                label=f"SSL C2: {dst_ip}:{dst_port}",
                description=f"SSL/TLS C2 server on port {dst_port}",
                severity="high",
                confidence=0.9,
                ip_for_geo=dst_ip,
                feed_metadata={
                    "source": "sslbl_ips",
                    "port": dst_port,
                    "first_seen": first_seen_str,
                },
                expires_hours=336,
            )
            emitted += 1

        logger.info("[%s] SSL C2 IPs: ingested %d entries", self.name, emitted)

    # ── JA3 Fingerprint Blacklist ────────────────────────────────────────────

    async def _poll_ja3(self) -> AsyncIterator[FeedEntry]:
        text = await self._fetch_text(SSLBL_JA3_URL)
        if not text:
            logger.warning("[%s] SSLBL JA3 blacklist returned no data", self.name)
            return

        clean_lines = [
            line for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not clean_lines:
            return

        reader = csv.reader(io.StringIO("\n".join(clean_lines)))
        seen: set[str] = set()
        emitted = 0

        for row in reader:
            if len(row) < 3:
                continue

            first_seen_str, ja3, listing_reason = row[0].strip(), row[1].strip(), row[2].strip()

            # Skip header row
            if ja3.lower() == "ja3":
                continue

            if not ja3 or ja3 in seen:
                continue
            seen.add(ja3)

            yield FeedEntry(
                feed_name="ja3_fingerprints",
                layer=self.layer,
                entry_type="hash",
                value=ja3,
                label=f"Malicious JA3: {ja3[:16]}...",
                description=listing_reason or "Blacklisted JA3 fingerprint",
                severity="high",
                confidence=0.85,
                feed_metadata={
                    "source": "sslbl_ja3",
                    "first_seen": first_seen_str,
                },
                expires_hours=336,
            )
            emitted += 1

        logger.info("[%s] JA3 fingerprints: ingested %d entries", self.name, emitted)
