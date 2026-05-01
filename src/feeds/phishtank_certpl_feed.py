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
        url = (
            _PHISHTANK_URL_TEMPLATE.format(key=api_key)
            if api_key else _PHISHTANK_PUBLIC_URL
        )
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

    async def _poll_certpl(self) -> AsyncIterator[FeedEntry]:
        payload = await self._fetch_json(_CERTPL_URL)
        if not isinstance(payload, list):
            return
        logger.info("[%s] CERT.PL returned %d records", self.name, len(payload))
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
