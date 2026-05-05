"""IntelligenceX (intelx.io) provider (P3 #3.9).

IntelX exposes a dual-step search API:
  POST /intelligent/search          → returns a search id
  GET  /intelligent/search/result   → polls for results

For the dashboard pivot we use a simplified ``term`` search; bulk
result download is up to the operator's IntelX tier and uses the
``download`` endpoint separately.

Operator config:
  ARGUS_INTELX_API_KEY    paid IntelX key
  ARGUS_INTELX_BASE_URL   override (default: https://2.intelx.io)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import BreachHit, BreachProvider, ProviderResult

logger = logging.getLogger(__name__)


_DEFAULT_BASE = "https://2.intelx.io"
_RESULT_POLL_LIMIT = 5  # seconds


class IntelxProvider(BreachProvider):
    name = "intelx"
    label = "IntelligenceX"

    def __init__(self):
        from src.core import integration_keys
        self._key = (
            integration_keys.get("intelx", env_fallback="ARGUS_INTELX_API_KEY") or ""
        ).strip()
        self._base = (os.environ.get("ARGUS_INTELX_BASE_URL") or _DEFAULT_BASE) \
            .strip().rstrip("/")

    def is_configured(self) -> bool:
        return bool(self._key)

    def _headers(self) -> dict[str, str]:
        return {"x-key": self._key, "Content-Type": "application/json",
                "Accept": "application/json"}

    async def search_email(self, email: str) -> ProviderResult:
        if not self.is_configured():
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                note="intelx not configured",
            )
        if not email:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error="empty email",
            )

        breaker = get_breaker("breach:intelx")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    # 1. Submit the search
                    async with http.post(
                        f"{self._base}/intelligent/search",
                        headers=self._headers(),
                        json={
                            "term": email, "buckets": [],
                            "lookuplevel": 0, "maxresults": 50,
                            "timeout": 5, "datefrom": "", "dateto": "",
                            "sort": 4, "media": 0,
                            "terminate": [],
                        },
                    ) as resp:
                        if resp.status == 401:
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error="intelx 401 — check ARGUS_INTELX_API_KEY",
                            )
                        if resp.status >= 400:
                            text = await resp.text()
                            return ProviderResult(
                                provider=self.name, success=False, hits=[],
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        meta = await resp.json()
                    search_id = (meta or {}).get("id")
                    if not search_id:
                        return ProviderResult(
                            provider=self.name, success=False, hits=[],
                            error="intelx returned no search id",
                        )

                    # 2. Poll the result endpoint a few times.
                    items: list[dict] = []
                    for _ in range(_RESULT_POLL_LIMIT):
                        async with http.get(
                            f"{self._base}/intelligent/search/result",
                            headers=self._headers(),
                            params={"id": search_id, "limit": 50,
                                    "statistics": 1},
                        ) as r:
                            if r.status >= 400:
                                break
                            data = await r.json()
                        items.extend(data.get("records") or [])
                        if data.get("status") in (0, 1):
                            await asyncio.sleep(0.5)
                            continue
                        break
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return ProviderResult(
                provider=self.name, success=False, hits=[],
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        hits: list[BreachHit] = []
        for it in items[:50]:
            if not isinstance(it, dict):
                continue
            hits.append(BreachHit(
                provider=self.name,
                breach_name=it.get("name") or it.get("bucket") or "",
                email=email,
                breach_date=it.get("date"),
                description=it.get("description") or it.get("type"),
                data_classes=list(filter(None, [it.get("type")])),
                raw=it,
            ))
        return ProviderResult(
            provider=self.name, success=True, hits=hits,
        )
