"""Dehashed.com provider (P3 #3.9).

Dehashed exposes a single search endpoint:
  GET https://api.dehashed.com/search?query=email:foo@bar.com

Auth: HTTP Basic — username + API key.

Operator config:
  ARGUS_DEHASHED_USERNAME    Dehashed account email
  ARGUS_DEHASHED_API_KEY     Dehashed API key
"""

from __future__ import annotations

import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import BreachHit, BreachProvider, ProviderResult

logger = logging.getLogger(__name__)


_API_URL = "https://api.dehashed.com/search"


class DehashedProvider(BreachProvider):
    name = "dehashed"
    label = "Dehashed"

    def __init__(self):
        self._user = (os.environ.get("ARGUS_DEHASHED_USERNAME") or "").strip()
        self._key = (os.environ.get("ARGUS_DEHASHED_API_KEY") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._user and self._key)

    async def search_email(self, email: str) -> ProviderResult:
        if not self.is_configured():
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                note="dehashed not configured",
            )
        if not email:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="empty email",
            )

        breaker = get_breaker("breach:dehashed")
        timeout = aiohttp.ClientTimeout(total=30)
        auth = aiohttp.BasicAuth(self._user, self._key)
        try:
            async with breaker:
                async with aiohttp.ClientSession(
                    timeout=timeout, auth=auth,
                ) as http:
                    async with http.get(
                        _API_URL,
                        params={"query": f"email:{email}", "size": 50},
                        headers={"Accept": "application/json"},
                    ) as resp:
                        if resp.status == 401:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error="dehashed 401 — check credentials",
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
        for entry in (data or {}).get("entries", []) or []:
            if not isinstance(entry, dict):
                continue
            hits.append(BreachHit(
                provider=self.name,
                breach_name=entry.get("database_name") or "Dehashed",
                email=entry.get("email") or email,
                username=entry.get("username") or None,
                password_hash=entry.get("hashed_password") or None,
                cleartext_password=entry.get("password") or None,
                description=entry.get("vin") or entry.get("name"),
                data_classes=list(filter(None, [
                    "email" if entry.get("email") else None,
                    "username" if entry.get("username") else None,
                    "password" if entry.get("password") else None,
                    "phone" if entry.get("phone") else None,
                    "address" if entry.get("address") else None,
                ])),
                raw=entry,
            ))
        return ProviderResult(
            provider=self.name, success=True, hits=hits,
        )
