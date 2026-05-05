"""HIBP (Have I Been Pwned) Enterprise provider (P3 #3.9).

Two endpoints used:

  Breach lookup:  GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
                  Auth header: hibp-api-key
  Password lookup (k-anonymity):
                  GET https://api.pwnedpasswords.com/range/{first5sha1}
                  No key required; we still ship it through this wrapper
                  for uniformity.

Operator config:
  ARGUS_HIBP_API_KEY    HIBP Enterprise API key
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import BreachHit, BreachProvider, ProviderResult

logger = logging.getLogger(__name__)


_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
_PASSWORD_URL = "https://api.pwnedpasswords.com/range/{prefix}"


class HibpProvider(BreachProvider):
    name = "hibp"
    label = "Have I Been Pwned (Enterprise)"

    def __init__(self):
        # Resolve key live at construction time. Operators can rotate
        # the key from Settings → Integrations and the next provider
        # instantiation picks it up without an env-edit + restart.
        from src.core import integration_keys
        self._key = (
            integration_keys.get("hibp", env_fallback="ARGUS_HIBP_API_KEY") or ""
        ).strip()

    def is_configured(self) -> bool:
        # Re-resolve every check so a freshly-rotated key takes effect
        # mid-process. Cheap (in-memory dict lookup); no DB hit.
        if not self._key:
            from src.core import integration_keys
            self._key = (
                integration_keys.get("hibp", env_fallback="ARGUS_HIBP_API_KEY") or ""
            ).strip()
        return bool(self._key)

    async def search_email(self, email: str) -> ProviderResult:
        if not self.is_configured():
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                note="hibp not configured",
            )
        if not email:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="empty email",
            )
        # truncatedResponse=false → return full breach metadata
        url = _BREACH_URL.format(email=email) + "?truncateResponse=false"
        headers = {
            "hibp-api-key": self._key,
            "user-agent": "argus-threat-intelligence",
            "Accept": "application/json",
        }
        breaker = get_breaker("breach:hibp")
        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=headers) as resp:
                        if resp.status == 404:
                            # Not found = clean record.
                            return ProviderResult(
                                provider=self.name, success=True, hits=[],
                                note="no breach record on file",
                            )
                        if resp.status == 401:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error="HIBP 401 — check ARGUS_HIBP_API_KEY",
                            )
                        if resp.status >= 400:
                            text = await resp.text()
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        data = await resp.json()
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        hits: list[BreachHit] = []
        for b in data or []:
            if not isinstance(b, dict):
                continue
            hits.append(BreachHit(
                provider=self.name,
                breach_name=b.get("Name", "") or b.get("Title", ""),
                email=email,
                breach_date=b.get("BreachDate"),
                description=b.get("Description"),
                data_classes=list(b.get("DataClasses", []) or []),
                raw=b,
            ))
        return ProviderResult(
            provider=self.name, success=True, hits=hits,
        )

    async def search_password_hash(
        self, sha1_hash: str,
    ) -> ProviderResult:
        """k-anonymity lookup — only the first 5 chars of the SHA-1
        leave the host. Caller passes a full 40-char hex SHA-1 of the
        candidate password; HIBP returns every suffix that matches the
        prefix and we filter locally."""
        if not sha1_hash or len(sha1_hash) != 40:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="sha1_hash must be a 40-char hex string",
            )
        prefix = sha1_hash[:5].upper()
        suffix = sha1_hash[5:].upper()

        url = _PASSWORD_URL.format(prefix=prefix)
        breaker = get_breaker("breach:hibp_pwd")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url) as resp:
                        if resp.status >= 400:
                            text = await resp.text()
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        body = await resp.text()
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        # Each line: <suffix>:<count>
        for line in body.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = parts[1].strip()
                return ProviderResult(
                    provider=self.name, success=True,
                    hits=[BreachHit(
                        provider=self.name,
                        breach_name=f"HIBP password ({count} occurrences)",
                        password_hash=sha1_hash,
                        description=(
                            f"Hash appears in {count} known breaches "
                            "per HIBP's password corpus."
                        ),
                    )],
                )
        return ProviderResult(
            provider=self.name, success=True, hits=[],
            note="hash not in HIBP password corpus",
        )
