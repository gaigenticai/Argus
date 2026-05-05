"""HudsonRock Cavalier breach provider — OSS-default for Argus.

Cavalier is HudsonRock's public stealer-log corpus. Every credential
it indexes was harvested by an information-stealer (RedLine, Vidar,
Raccoon, AZORult, Lumma, etc.) running on a real victim's machine.
That's a different signal from HIBP/IntelX (which mostly index dump
sites + dataset breaches) and arguably a sharper one for active-
compromise detection — a stealer hit means a live, infected
endpoint.

Why this is the OSS default:

  - The ``cavalier.hudsonrock.com/api/json/v2/osint-tools/*``
    endpoints are documented free-tier endpoints that return
    structured JSON. No paid plan required for the first-pass
    "is this email/domain in the corpus?" question.
  - HudsonRock actively maintains the corpus (millions of
    credentials added monthly).
  - License is operator-friendly: API ToS allows defensive
    security use without a commercial agreement for the public
    endpoints.

An optional ``ARGUS_HUDSONROCK_API_KEY`` unlocks higher rate limits
and the paid corpus endpoints. We fall back to the public endpoints
when no key is set.
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from datetime import datetime, timezone

import aiohttp

from src.core.http_circuit import get_breaker
from .base import BreachHit, BreachProvider, ProviderResult

logger = logging.getLogger(__name__)

_PUBLIC_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_BREAKER = "breach:cavalier"


class CavalierProvider(BreachProvider):
    """HudsonRock Cavalier — OSS-default stealer-log breach provider.

    Unlike the paid providers (HIBP/IntelX/Dehashed), this provider
    is_configured()=True even without an API key — the public
    endpoints are open. The API key is opt-in for higher quota."""

    name = "cavalier"
    label = "HudsonRock Cavalier (free)"

    def __init__(self):
        # Resolve API key via the integration_keys cache so operators
        # can rotate without restart. None = use public free endpoints.
        from src.core import integration_keys
        self._key = (
            integration_keys.get(
                "hudsonrock", env_fallback="ARGUS_HUDSONROCK_API_KEY",
            ) or ""
        ).strip()

    def is_configured(self) -> bool:
        # Cavalier's public free endpoints don't require a key. Always
        # configured; the ``_key`` field unlocks higher quota when set.
        return True

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": "argus-threat-intelligence",
        }
        if self._key:
            h["api-key"] = self._key
        return h

    async def search_email(self, email: str) -> ProviderResult:
        """``GET /search-by-email`` — does HudsonRock's stealer corpus
        contain credentials harvested from accounts using this email?

        Response shape (free tier):
            {
                "stealers": [
                    {
                        "stealer_family": "redline",
                        "date_compromised": "2024-08-12",
                        "computer_name": "DESKTOP-XYZ",
                        "operating_system": "Windows 10 Pro",
                        "ip": "1.2.3.4",
                        "credentials": [
                            {"url": "...", "username": "...", "type": "Saved Password"}
                        ],
                        ...
                    }
                ],
                "total_corporate_services": 0,
                "total_user_services": 5
            }
        """
        if not email or "@" not in email:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="empty or malformed email",
            )

        url = (
            f"{_PUBLIC_BASE}/search-by-email"
            f"?email={urllib.parse.quote(email, safe='@')}"
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
                                note="not in stealer-log corpus",
                            )
                        if resp.status == 401:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error="HTTP 401 — API key invalid or rate-limited; the public endpoint is rate-limited per IP",
                            )
                        if resp.status == 429:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=(
                                    "HTTP 429 — Cavalier free tier rate-limited; "
                                    "set ARGUS_HUDSONROCK_API_KEY for higher quota"
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

        return ProviderResult(
            provider=self.name, success=True,
            hits=list(_payload_to_hits(self.name, email, payload)),
        )

    async def search_domain(self, domain: str) -> ProviderResult:
        """``GET /search-by-domain`` — does the corpus contain
        stealer-derived credentials for any user @<domain>? Critical
        for proactive corporate-domain monitoring."""
        domain = (domain or "").strip().lower()
        if not domain or "." not in domain:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="empty or malformed domain",
            )

        url = (
            f"{_PUBLIC_BASE}/search-by-domain"
            f"?domain={urllib.parse.quote(domain)}"
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
                                note=f"no stealer-log victims at @{domain}",
                            )
                        if resp.status == 429:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=(
                                    "HTTP 429 — Cavalier free tier rate-limited; "
                                    "set ARGUS_HUDSONROCK_API_KEY for higher quota"
                                ),
                            )
                        if resp.status != 200:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=f"HTTP {resp.status}",
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

        # Domain search returns aggregate stats (count of compromised
        # employees + customers + URLs they were logging into), not
        # individual emails — Cavalier withholds the PII at this tier.
        # We surface the stats as a single synthetic BreachHit so the
        # /leakage view reflects "yes, there's exposure" with hard
        # numbers + the URLs that were compromised.
        if not isinstance(payload, dict):
            return ProviderResult(provider=self.name, success=True, hits=[], note="empty payload")

        employees = int(payload.get("employees") or 0)
        users = int(payload.get("users") or 0)
        third_parties = int(payload.get("third_parties") or 0)
        total = int(payload.get("total") or 0)
        data = payload.get("data") or {}
        employee_urls = (data.get("employees_urls") or [])[:10]
        client_urls = (data.get("clients_urls") or [])[:10]
        third_party_urls = (data.get("third_parties_urls") or [])[:10]

        hits: list[BreachHit] = []
        if total > 0 or employees > 0 or users > 0:
            urls_summary = []
            for u in employee_urls:
                if isinstance(u, dict) and u.get("url"):
                    urls_summary.append(f"{u.get('occurrence', 1)}x {u['url']}")
            hits.append(BreachHit(
                provider=self.name,
                breach_name=f"HudsonRock stealer-log corpus ({domain})",
                description=(
                    f"{employees} employees, {users} customers, {third_parties} "
                    f"third-parties from @{domain} found in info-stealer logs."
                    + (
                        " Top compromised URLs: " + "; ".join(urls_summary[:5])
                        if urls_summary else ""
                    )
                ),
                data_classes=["Stealer logs", "Browser-saved passwords", "VPN credentials"],
                raw={
                    "domain": domain,
                    "employees": employees,
                    "users": users,
                    "third_parties": third_parties,
                    "total_credentials": total,
                    "stealer_logs_total_in_corpus": int(payload.get("totalStealers") or 0),
                    "employee_urls": employee_urls,
                    "client_urls": client_urls,
                    "third_party_urls": third_party_urls,
                },
            ))

        return ProviderResult(
            provider=self.name, success=True, hits=hits,
            note=(
                f"{employees} employees, {users} customers, {third_parties} "
                f"third-parties compromised; {total} total credentials in corpus"
                if total > 0 else f"no stealer-log victims at @{domain}"
            ),
        )


def _payload_to_hits(provider: str, email: str, payload) -> list[BreachHit]:
    """Translate Cavalier's ``stealers`` array into normalised
    BreachHit rows. One BreachHit per stealer infection — each
    represents a single victim machine that had this email's
    credentials saved."""
    if not isinstance(payload, dict):
        return []
    out: list[BreachHit] = []
    for stealer in payload.get("stealers") or []:
        if not isinstance(stealer, dict):
            continue
        family = stealer.get("stealer_family") or stealer.get("type") or "unknown_stealer"
        date = stealer.get("date_compromised") or stealer.get("date") or None
        creds = stealer.get("credentials") or []
        n_creds = len(creds) if isinstance(creds, list) else 0
        # Surface a normalised BreachHit even when no plaintext is
        # included. The dashboard will show "victim infected by X on
        # Y, N saved-password credentials harvested" — that's the
        # actionable signal: a real machine was compromised.
        out.append(BreachHit(
            provider=provider,
            breach_name=f"HudsonRock stealer-log: {family}",
            email=email,
            breach_date=date,
            description=(
                f"Email seen in info-stealer log harvested from a victim "
                f"running {stealer.get('operating_system') or 'unknown OS'}; "
                f"{n_creds} saved-password credentials in this dump."
            ),
            data_classes=["Stealer logs", "Browser-saved passwords"],
            raw={
                "stealer_family": family,
                "computer_name": stealer.get("computer_name"),
                "operating_system": stealer.get("operating_system"),
                "antiviruses": stealer.get("antiviruses"),
                "ip": stealer.get("ip"),
                "saved_credentials": n_creds,
            },
        ))
    return out
