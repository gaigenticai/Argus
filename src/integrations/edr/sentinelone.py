"""SentinelOne Singularity connector (P3 #3.2).

Endpoint: ``${S1_BASE}/web/api/v2.1``  (the per-tenant management URL)
Auth header: ``Authorization: ApiToken <token>``

IOC management: ``POST /threat-intelligence/iocs`` — create indicators.
Host action: ``POST /agents/actions/disconnect`` to disconnect from
network (S1's name for "isolate"); body is ``{filter: {ids: [...]}}``.

Operator config:
  ARGUS_S1_BASE_URL    https://your-tenant.sentinelone.net
  ARGUS_S1_API_TOKEN
  ARGUS_S1_ACCOUNT_ID  optional — pinned account for IOC scope
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import EdrConnector, EdrIoc, EdrPushResult

logger = logging.getLogger(__name__)


_S1_TYPE_MAP: dict[str, str] = {
    "ipv4":   "IPV4",
    "ipv6":   "IPV6",
    "domain": "DNS",
    "url":    "URL",
    "md5":    "MD5",
    "sha1":   "SHA1",
    "sha256": "SHA256",
}


class SentinelOneConnector(EdrConnector):
    name = "sentinelone"
    label = "SentinelOne Singularity"

    def __init__(self):
        self._base = (os.environ.get("ARGUS_S1_BASE_URL") or "") \
            .strip().rstrip("/")
        self._token = (os.environ.get("ARGUS_S1_API_TOKEN") or "").strip()
        self._account_id = (os.environ.get("ARGUS_S1_ACCOUNT_ID") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._base and self._token)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"ApiToken {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def push_iocs(self, iocs: list[EdrIoc]) -> EdrPushResult:
        if not self.is_configured():
            return EdrPushResult(edr=self.name, success=False,
                                  note="sentinelone not configured")
        if not iocs:
            return EdrPushResult(edr=self.name, success=True,
                                  pushed_count=0, note="no iocs to push")

        indicators = []
        for ioc in iocs:
            s1_type = _S1_TYPE_MAP.get(ioc.type.lower())
            if not s1_type:
                continue
            entry: dict[str, Any] = {
                "type": s1_type,
                "value": ioc.value,
                "source": "Argus",
                "description": ioc.description or "",
                "validUntil": None,
                "method": "EQUALS",
            }
            if self._account_id:
                entry["accountIds"] = [self._account_id]
            indicators.append(entry)
        if not indicators:
            return EdrPushResult(
                edr=self.name, success=False,
                note="no SentinelOne-compatible IOC types in batch",
            )

        url = f"{self._base}/web/api/v2.1/threat-intelligence/iocs"
        breaker = get_breaker("edr:sentinelone")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, headers=self._headers(),
                        data=json.dumps({"data": indicators}),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return EdrPushResult(
                                edr=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        body = json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EdrPushResult(
                edr=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        data = body.get("data") or []
        ids = [str(d.get("id")) for d in data if isinstance(d, dict)
               and d.get("id")]
        return EdrPushResult(
            edr=self.name, success=True,
            pushed_count=len(ids), remote_ids=ids,
        )

    async def isolate_host(self, *, host_id: str) -> EdrPushResult:
        if not self.is_configured():
            return EdrPushResult(edr=self.name, success=False,
                                  note="sentinelone not configured")
        url = f"{self._base}/web/api/v2.1/agents/actions/disconnect"
        breaker = get_breaker("edr:sentinelone")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, headers=self._headers(),
                        data=json.dumps({"filter": {"ids": [host_id]}}),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return EdrPushResult(
                                edr=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return EdrPushResult(
                            edr=self.name, success=True,
                            pushed_count=1, remote_ids=[host_id],
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EdrPushResult(
                edr=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

    async def health_check(self) -> EdrPushResult:
        if not self.is_configured():
            return EdrPushResult(edr=self.name, success=False,
                                  note="sentinelone not configured")
        url = f"{self._base}/web/api/v2.1/system/info"
        breaker = get_breaker("edr:sentinelone")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return EdrPushResult(
                                edr=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return EdrPushResult(
                            edr=self.name, success=True,
                            note="sentinelone /system/info reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EdrPushResult(
                edr=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
