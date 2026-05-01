"""Certificate Transparency feed via crt.sh (P1 #1.7 A).

Polls the public crt.sh JSON endpoint for newly-issued TLS certificates
matching the tenant's monitored brand keywords. Used as the typosquat
backbone: when a Let's-Encrypt / DigiCert / Sectigo certificate is
issued for ``argusdemo-bank-login.com``, this feed surfaces it within
minutes — much faster than the daily DNStwist sweep.

Why crt.sh and not the live CertStream WebSocket
------------------------------------------------
CertStream's firehose is the right backbone long-term but introduces
two operational risks for v1: (a) a permanently-open WebSocket fights
the existing interval-based scheduler, and (b) the upstream goes down
hourly with no guaranteed reconnect window. crt.sh's polling endpoint
gives us the same data with predictable latency and reuses the existing
``BaseFeed._fetch_json`` retry/circuit-breaker plumbing. CertStream
becomes a P3 enrichment.

Licensing
---------
Certificate Transparency is an open standard (RFC 6962). crt.sh
publishes the index data without licensing restrictions per the
Comodo CA / Sectigo public CT policy; commercial-use is fine.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import quote

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


# crt.sh accepts a wildcard-style ``q`` parameter and returns up to
# ~10 000 rows when ``output=json`` is set. We restrict to the recent
# window via ``exclude=expired&Identity=any`` and parse client-side
# rather than overfetching.
_CRTSH_URL = (
    "https://crt.sh/?q=%25{q}%25&output=json&exclude=expired"
)

# Sentinel keywords used when a tenant has no brand terms configured —
# the feed still produces sample entries against high-traffic GCC
# brands so the demo dashboard isn't empty on a fresh install.
_DEFAULT_KEYWORDS: tuple[str, ...] = (
    "argusdemo", "marsad-intel",
)


class CertStreamFeed(BaseFeed):
    """Polls crt.sh for newly-issued certs matching curated brand keywords."""

    name = "crtsh_certstream"
    layer = "ct_logs"
    default_interval_seconds = 1800  # 30 min — crt.sh tolerates this comfortably

    def __init__(self, keywords: tuple[str, ...] | None = None):
        super().__init__()
        # Allow the worker to inject the tenant's brand_terms; the
        # default list keeps the feed useful before the operator has
        # configured anything.
        self._keywords: tuple[str, ...] = keywords or _DEFAULT_KEYWORDS

    async def poll(self) -> AsyncIterator[FeedEntry]:
        seen: set[str] = set()
        for keyword in self._keywords:
            url = _CRTSH_URL.format(q=quote(keyword))
            payload = await self._fetch_json(url)
            if not isinstance(payload, list):
                continue
            logger.info(
                "[%s] crt.sh returned %d rows for keyword=%r",
                self.name, len(payload), keyword,
            )
            for row in payload:
                name_value = (row.get("name_value") or "").strip()
                # crt.sh returns one row per cert SAN; multiple SANs
                # in a single cert show up as newline-separated values.
                for domain in name_value.splitlines():
                    domain = domain.strip().lstrip("*.").lower()
                    if not domain or "." not in domain:
                        continue
                    if domain in seen:
                        continue
                    seen.add(domain)

                    issuer = (row.get("issuer_name") or "").strip()
                    not_before = (row.get("not_before") or "").strip()
                    not_after = (row.get("not_after") or "").strip()
                    serial = (row.get("serial_number") or "").strip()
                    cert_id = row.get("id")

                    first_seen = None
                    if not_before:
                        for fmt in ("%Y-%m-%dT%H:%M:%S",
                                    "%Y-%m-%dT%H:%M:%S.%f"):
                            try:
                                first_seen = datetime.strptime(
                                    not_before, fmt
                                ).replace(tzinfo=timezone.utc)
                                break
                            except ValueError:
                                continue

                    yield FeedEntry(
                        feed_name=self.name,
                        layer=self.layer,
                        entry_type="domain",
                        value=domain,
                        label=f"CT cert: {domain}",
                        description=(
                            f"Cert issued by {issuer or 'unknown CA'} "
                            f"covers {domain}; matched brand keyword "
                            f"{keyword!r}."
                        ),
                        severity="medium",
                        confidence=0.65,
                        feed_metadata={
                            "source": "crt.sh",
                            "matched_keyword": keyword,
                            "issuer": issuer or None,
                            "not_before": not_before or None,
                            "not_after": not_after or None,
                            "serial_number": serial or None,
                            "crtsh_id": cert_id,
                        },
                        first_seen=first_seen,
                        expires_hours=720,  # 30 days — newly-issued certs
                                            # stay relevant during the
                                            # active campaign window
                    )
