"""PhishTank + CERT.PL phishing-URL feed (P1 #1.7 C).

Combines two free-for-commercial-use phishing URL streams:

  PhishTank
    Community-verified phishing URLs. Free-tier requires a registered
    application key for the JSON download — without one we fall back
    to the public ``valid`` filter at ``checkurl.phishtank.com``.
    License: requires attribution; no commercial restriction.

  CERT.PL
    Polish national CERT's malicious-URL warning list. Strong on
    Eastern-European lure variants (banking + parcel-delivery scams)
    that round out OpenPhish / OTX coverage.
    Endpoint: https://hole.cert.pl/domains/v2/domains.json
    License: open data, commercial-OK per CERT.PL Terms.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import urlparse

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


_PHISHTANK_URL_TEMPLATE = (
    "https://data.phishtank.com/data/{key}/online-valid.json"
)
_PHISHTANK_PUBLIC_URL = (
    "https://data.phishtank.com/data/online-valid.json"
)
_CERTPL_URL = "https://hole.cert.pl/domains/v2/domains.json"


class PhishTankCertPLFeed(BaseFeed):
    """Combined PhishTank + CERT.PL phishing URL stream."""

    name = "phishtank_certpl"
    layer = "phishing"
    default_interval_seconds = 21600  # 6 hours

    async def poll(self) -> AsyncIterator[FeedEntry]:
        async for entry in self._poll_phishtank():
            yield entry
        async for entry in self._poll_certpl():
            yield entry

    async def _poll_phishtank(self) -> AsyncIterator[FeedEntry]:
        api_key = (os.environ.get("ARGUS_PHISHTANK_API_KEY") or "").strip()
        # The unauthenticated ``online-valid.json`` endpoint stopped
        # accepting requests in 2024 and now returns 403 — PhishTank
        # made the public feed key-only. Without a key, skipping
        # cleanly here keeps the CERT.PL half of the combined feed
        # running and lets the operator see a clear "unconfigured"
        # signal in the Fetch Health drawer instead of "auth_error"
        # for the whole class.
        if not api_key:
            self.last_unconfigured_reason = (
                "PhishTank now requires a registered application key for "
                "unauthenticated fetches (the public online-valid.json "
                "endpoint returns 403). Get a free key at "
                "https://phishtank.org/api_register.php and set "
                "ARGUS_PHISHTANK_API_KEY. CERT.PL half of this feed will "
                "still poll without a key."
            )
            logger.info(
                "[%s] PhishTank skipped (no ARGUS_PHISHTANK_API_KEY)",
                self.name,
            )
            return
        url = _PHISHTANK_URL_TEMPLATE.format(key=api_key)
        payload = await self._fetch_json(url)
        if not isinstance(payload, list):
            return
        logger.info("[%s] PhishTank returned %d records", self.name, len(payload))
        for row in payload:
            url_val = (row.get("url") or "").strip()
            if not url_val:
                continue
            verified = (row.get("verified") or "").strip().lower() == "yes"
            verification_time = (row.get("verification_time") or "").strip()
            target = (row.get("target") or "").strip()  # e.g. "PayPal"
            phish_id = row.get("phish_id")

            first_seen = None
            if verification_time:
                try:
                    first_seen = datetime.fromisoformat(
                        verification_time.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            domain = ""
            try:
                domain = (urlparse(url_val).hostname or "").lower()
            except Exception:
                pass

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="url",
                value=url_val,
                label=f"PhishTank: {target or domain or 'phish'}",
                description=(
                    f"PhishTank reports {url_val!r} as a phishing site"
                    + (f" impersonating {target}" if target else "")
                    + (" (verified)" if verified else " (unverified)")
                    + "."
                ),
                severity="high" if verified else "medium",
                confidence=0.9 if verified else 0.6,
                feed_metadata={
                    "source": "phishtank",
                    "phish_id": phish_id,
                    "target": target or None,
                    "verified": verified,
                    "verification_time": verification_time or None,
                    "domain": domain or None,
                },
                first_seen=first_seen,
                expires_hours=336,  # 14 days
            )

    # CERT.PL's full warning list is ~130k rows — yielding every
    # one through the ingestion pipeline blows the scheduler's 600s
    # hard timeout (each yield round-trips through DB upsert, geo
    # enrichment, and feed_metadata serialisation). Cap at the
    # 5000 most-recently-inserted to stay well under budget while
    # still ingesting the meaningful tip of the list.
    _CERTPL_MAX_ROWS = 5000

    async def _poll_certpl(self) -> AsyncIterator[FeedEntry]:
        payload = await self._fetch_json(_CERTPL_URL)
        if not isinstance(payload, list):
            return
        logger.info("[%s] CERT.PL returned %d records", self.name, len(payload))
        # Sort by InsertDate DESC so we keep the freshest rows
        # when capping. CERT.PL appends to the end so reversing
        # the list approximates "most recent first" without
        # parsing every date.
        if len(payload) > self._CERTPL_MAX_ROWS:
            payload = payload[-self._CERTPL_MAX_ROWS :]
            logger.info(
                "[%s] CERT.PL capped to most-recent %d rows (timeout guard)",
                self.name, self._CERTPL_MAX_ROWS,
            )
        for row in payload:
            domain = (row.get("DomainAddress") or row.get("domain") or "").strip().lower()
            if not domain:
                continue
            inserted = (row.get("InsertDate") or row.get("insert_date") or "").strip()
            register_pos = row.get("RegisterPositionId")

            first_seen = None
            if inserted:
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S",
                ):
                    try:
                        first_seen = datetime.strptime(
                            inserted, fmt
                        ).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        continue

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="domain",
                value=domain,
                label=f"CERT.PL warning: {domain}",
                description=(
                    f"Polish national CERT lists {domain!r} as a malicious "
                    f"site (register-position #{register_pos})."
                ),
                severity="high",
                confidence=0.9,
                feed_metadata={
                    "source": "cert.pl",
                    "register_position_id": register_pos,
                    "insert_date": inserted or None,
                },
                first_seen=first_seen,
                expires_hours=720,
            )
