"""abuse.ch SSLBL + JA3 fingerprints feed (P1 #1.7 E).

Two abuse.ch streams that plug straight into the existing
``src/intel/tls_fingerprint`` (or compatible downstream JA3-aware
detectors) so analysts can flag a connection whose TLS handshake
matches a known malware family without inspecting payload:

  SSLBL (SSL Blacklist)
    Per-cert SHA1 fingerprints of known C2 servers, with the malware
    family that uses them. Endpoint:
    https://sslbl.abuse.ch/blacklist/sslblacklist.csv
    License: CC0 (public-domain).

  JA3 fingerprints
    Per-malware-family JA3 client hashes. Endpoint:
    https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
    License: CC0.

The CSV files use ``#`` for comments and have stable schemas; both
work without an API key.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


_SSLBL_CSV_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
_JA3_CSV_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"


def _strip_comments(text: str) -> list[str]:
    """abuse.ch CSVs ship a multi-line ``#`` header; csv.DictReader
    chokes on it. Yield only the data lines."""
    return [
        ln for ln in text.splitlines()
        if ln and not ln.startswith("#") and "," in ln
    ]


class AbuseChTLSFeed(BaseFeed):
    """abuse.ch SSL Blacklist + JA3 client fingerprints."""

    name = "abusech_tls"
    layer = "c2_infrastructure"
    default_interval_seconds = 21600  # 6 hours

    async def poll(self) -> AsyncIterator[FeedEntry]:
        async for entry in self._poll_sslbl():
            yield entry
        async for entry in self._poll_ja3():
            yield entry

    async def _poll_sslbl(self) -> AsyncIterator[FeedEntry]:
        text = await self._fetch_text(_SSLBL_CSV_URL)
        if not text:
            return
        # SSLBL columns: Listingdate,SHA1,Listingreason
        rows = _strip_comments(text)
        if not rows:
            return
        reader = csv.reader(rows)
        # Old format started with a header row; the cell value will be
        # human-readable rather than a date — skip it if so.
        records = []
        for cells in reader:
            if len(cells) < 3:
                continue
            if cells[0].strip().lower() == "listingdate":
                continue
            records.append(cells)
        logger.info("[%s] SSLBL returned %d certs", self.name, len(records))
        for cells in records:
            listing_date = cells[0].strip()
            sha1 = cells[1].strip().lower()
            reason = cells[2].strip()
            if not sha1:
                continue

            first_seen = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    first_seen = datetime.strptime(
                        listing_date, fmt
                    ).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="hash",
                value=sha1,
                label=f"SSLBL {reason}: {sha1[:12]}…",
                description=(
                    f"abuse.ch SSL Blacklist lists this SHA1 cert "
                    f"fingerprint as used by {reason!r} C2 infra."
                ),
                severity="high",
                confidence=0.95,
                feed_metadata={
                    "source": "sslbl",
                    "listing_reason": reason,
                    "listing_date": listing_date or None,
                    "fingerprint_kind": "sha1_cert",
                },
                first_seen=first_seen,
                expires_hours=8760,
            )

    async def _poll_ja3(self) -> AsyncIterator[FeedEntry]:
        text = await self._fetch_text(_JA3_CSV_URL)
        if not text:
            return
        # JA3 CSV columns: ja3_md5,Firstseen,Lastseen,Listingreason
        rows = _strip_comments(text)
        if not rows:
            return
        reader = csv.reader(rows)
        records = []
        for cells in reader:
            if len(cells) < 4:
                continue
            if cells[0].strip().lower() == "ja3_md5":
                continue
            records.append(cells)
        logger.info("[%s] JA3 returned %d fingerprints", self.name, len(records))
        for cells in records:
            ja3 = cells[0].strip().lower()
            first_seen_raw = cells[1].strip()
            last_seen_raw = cells[2].strip()
            reason = cells[3].strip()
            if not ja3:
                continue

            first_seen = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    first_seen = datetime.strptime(
                        first_seen_raw, fmt
                    ).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="ja3",
                value=ja3,
                label=f"JA3 {reason}: {ja3[:12]}…",
                description=(
                    f"abuse.ch lists JA3 fingerprint {ja3} as used by "
                    f"{reason!r} (first-seen={first_seen_raw}, "
                    f"last-seen={last_seen_raw})."
                ),
                severity="high",
                confidence=0.85,
                feed_metadata={
                    "source": "abusech_ja3",
                    "listing_reason": reason,
                    "first_seen_upstream": first_seen_raw or None,
                    "last_seen_upstream": last_seen_raw or None,
                    "fingerprint_kind": "ja3_md5",
                },
                first_seen=first_seen,
                expires_hours=8760,
            )
