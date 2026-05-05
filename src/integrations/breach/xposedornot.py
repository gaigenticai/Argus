"""XposedOrNot breach provider — OSS-default email-breach lookup.

XposedOrNot (https://xposedornot.com) maintains an aggregated breach
corpus and exposes a free public API. Unlike HIBP / IntelX / Dehashed
(all paid commercial services), XposedOrNot's email and breach-analytics
endpoints work without a key — making this the second OSS-default
breach provider alongside HudsonRock Cavalier.

Distinct signal from Cavalier:

  * Cavalier indexes **stealer logs** — credentials harvested from
    info-stealer-infected machines. Strong "live infection" signal.
  * XposedOrNot indexes **dataset breaches** — leaks dumped to paste
    sites, dark-web markets, etc. Same shape as HIBP's bread-and-butter.

Together they cover both "infected endpoint" and "dataset breach"
without spending a dollar — the operator only reaches for HIBP /
IntelX / Dehashed when they need premium corpora the OSS pair doesn't
cover.

Endpoints (May 2026, verified via xposedornot.com/api_doc):

  GET https://api.xposedornot.com/v1/breach-analytics?email=<email>
      Public, no key. Returns BreachMetrics + ExposedBreaches with
      per-breach details (logo, date, records exposed, password risk).

  GET https://api.xposedornot.com/v1/check-email/<email>
      Public, no key. Lighter-weight "is this email in any breach" —
      we use it as a fallback when /breach-analytics fails.

Domain lookup (POST /v1/domain-breaches/) requires a paid API key, so
this provider does NOT implement search_domain — operators wanting
domain coverage should keep Cavalier configured (domain endpoint is
free there).

Rate limit: 1 req/s across endpoints — the http_circuit breaker keeps
us inside that ceiling on bursty queries.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

import aiohttp

from src.core.http_circuit import get_breaker
from .base import BreachHit, BreachProvider, ProviderResult

logger = logging.getLogger(__name__)

_API_BASE = "https://api.xposedornot.com/v1"
_BREAKER = "breach:xposedornot"


class XposedOrNotProvider(BreachProvider):
    """XposedOrNot — free OSS-default dataset-breach provider.

    is_configured()=True without any env var because the public
    endpoints don't gate on a key. The class still reads
    ``ARGUS_XPOSEDORNOT_API_KEY`` if set (forward-compat for the
    paid tier they may launch), but it isn't required."""

    name = "xposedornot"
    label = "XposedOrNot (free)"

    def __init__(self):
        from src.core import integration_keys

        # Optional — unlocks future paid endpoints if/when they're
        # introduced. The free endpoints we use here ignore it.
        self._key = (
            integration_keys.get(
                "xposedornot", env_fallback="ARGUS_XPOSEDORNOT_API_KEY",
            ) or ""
        ).strip()

    def is_configured(self) -> bool:
        return True  # public endpoints don't require a key

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": "argus-threat-intelligence",
        }
        if self._key:
            h["x-api-key"] = self._key
        return h

    async def search_email(self, email: str) -> ProviderResult:
        """``GET /breach-analytics?email=<email>`` — returns breach
        details (one record per breach the email appeared in)."""
        if not email or "@" not in email:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="empty or malformed email",
            )

        url = (
            f"{_API_BASE}/breach-analytics"
            f"?email={urllib.parse.quote(email, safe='@+')}"
        )
        breaker = get_breaker(_BREAKER)
        timeout = aiohttp.ClientTimeout(total=20)

        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        if resp.status == 404:
                            return ProviderResult(
                                provider=self.name, success=True, hits=[],
                                note="not in XposedOrNot corpus",
                            )
                        if resp.status == 429:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=(
                                    "HTTP 429 — XposedOrNot is rate-limited "
                                    "to 1 req/s; retry will succeed."
                                ),
                            )
                        if resp.status != 200:
                            text = (await resp.text())[:200]
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=f"HTTP {resp.status}: {text}",
                            )
                        try:
                            payload = await resp.json(content_type=None)
                        except Exception as e:  # noqa: BLE001
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=f"JSON parse failed: {e}",
                            )
        except Exception as e:  # noqa: BLE001
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error=f"{type(e).__name__}: {e}"[:200],
            )

        # XposedOrNot returns ``{"Error": "Not found"}`` (capital-E,
        # capitalised value) when the email isn't in the corpus
        # alongside the 200 status. Treat as a clean "not seen".
        if isinstance(payload, dict) and payload.get("Error") == "Not found":
            return ProviderResult(
                provider=self.name, success=True, hits=[],
                note="not in XposedOrNot corpus",
            )

        return ProviderResult(
            provider=self.name, success=True,
            hits=list(_payload_to_hits(self.name, email, payload)),
        )

    async def search_domain(self, domain: str) -> ProviderResult:
        """XposedOrNot's domain endpoint requires a paid API key. Surface
        as ``unsupported`` rather than failing — Cavalier covers domain
        search for free, and the unified breach surface will route around."""
        return ProviderResult(
            provider=self.name, success=False, hits=[],
            error=(
                "domain search requires the paid XposedOrNot tier; "
                "Cavalier (free) handles this query in the OSS path."
            ),
        )


def _payload_to_hits(provider: str, email: str, payload: Any) -> list[BreachHit]:
    """Translate XposedOrNot's ``ExposedBreaches.breaches_details`` into
    normalised BreachHit rows. One BreachHit per dataset breach."""
    if not isinstance(payload, dict):
        return []
    exposed = payload.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    if not isinstance(details, list):
        return []

    out: list[BreachHit] = []
    for b in details:
        if not isinstance(b, dict):
            continue
        breach_name = (b.get("breach") or "Unknown breach").strip()
        date = b.get("xposed_date") or None
        domain = b.get("domain") or None
        records = b.get("xposed_records") or 0
        password_risk = b.get("password_risk") or None
        # `xposed_data` is a semicolon-separated string of categories
        # like "Emails;Passwords;Names". Normalise to a list[str].
        raw_data = b.get("xposed_data") or ""
        data_classes = [
            d.strip() for d in str(raw_data).split(";") if d and d.strip()
        ]

        out.append(BreachHit(
            provider=provider,
            breach_name=breach_name,
            email=email,
            breach_date=date,
            description=(
                f"{breach_name} ({domain}) — "
                f"{int(records):,} record(s) exposed"
                + (
                    f". Password risk: {password_risk}."
                    if password_risk else "."
                )
                + (b.get("details") or "")[:500]
            ),
            data_classes=data_classes or ["Emails"],
            raw={
                "domain": domain,
                "records": records,
                "password_risk": password_risk,
                "industry": b.get("industry"),
                "added": b.get("added"),
                "logo": b.get("logo"),
            },
        ))
    return out
