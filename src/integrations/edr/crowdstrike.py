"""CrowdStrike Falcon connector (P3 #3.2).

Falcon's API is OAuth2-based: every call needs a bearer token from
``POST /oauth2/token`` with ``client_id`` + ``client_secret``. The
token is good for ~30 minutes; we cache it in-process and refresh
just before expiry.

IOC management: ``POST /iocs/entities/indicators/v1`` — bulk-upload
up to 200 IOCs per request.
Host action: ``POST /devices/entities/devices-actions/v2`` with
``action_name=contain`` for host isolation.

Operator config:
  ARGUS_FALCON_BASE_URL    https://api.crowdstrike.com  (or eu / gov)
  ARGUS_FALCON_CLIENT_ID
  ARGUS_FALCON_CLIENT_SECRET
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import EdrConnector, EdrIoc, EdrPushResult

logger = logging.getLogger(__name__)


_FALCON_TYPE_MAP: dict[str, str] = {
    "ipv4":   "ipv4",
    "ipv6":   "ipv6",
    "domain": "domain",
    "url":    "url",
    "md5":    "md5",
    "sha1":   "sha1",
    "sha256": "sha256",
}


class CrowdStrikeConnector(EdrConnector):
    name = "crowdstrike"
    label = "CrowdStrike Falcon"

    _TOKEN_CACHE: dict[str, tuple[str, float]] = {}

    def __init__(self):
        self._base = (os.environ.get("ARGUS_FALCON_BASE_URL") or "") \
            .strip().rstrip("/")
        self._client_id = (os.environ.get("ARGUS_FALCON_CLIENT_ID") or "").strip()
        self._client_secret = (os.environ.get("ARGUS_FALCON_CLIENT_SECRET") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._base and self._client_id and self._client_secret)

    async def _token(self) -> str | None:
        cached = self._TOKEN_CACHE.get(self._client_id)
        if cached and cached[1] > time.time() + 60:
            return cached[0]
        url = f"{self._base}/oauth2/token"
        breaker = get_breaker("edr:falcon")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(url, data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    }) as resp:
                        if resp.status >= 400:
                            return None
                        body = await resp.json()
        except (CircuitBreakerOpenError, aiohttp.ClientError):
            return None
        token = body.get("access_token")
        ttl = int(body.get("expires_in", 1800))
        if token:
            self._TOKEN_CACHE[self._client_id] = (token, time.time() + ttl)
        return token

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def push_iocs(self, iocs: list[EdrIoc]) -> EdrPushResult:
        if not self.is_configured():
            return EdrPushResult(edr=self.name, success=False,
                                  note="crowdstrike not configured")
        if not iocs:
            return EdrPushResult(edr=self.name, success=True,
                                  pushed_count=0, note="no iocs to push")

        # Filter to types Falcon accepts.
        indicators = []
        for ioc in iocs:
            falcon_type = _FALCON_TYPE_MAP.get(ioc.type.lower())
            if not falcon_type:
                continue
            indicators.append({
                "type": falcon_type,
                "value": ioc.value,
                "severity": ioc.severity.upper() if ioc.severity else "MEDIUM",
                "action": ioc.action or "detect",
                "platforms": ["windows", "mac", "linux"],
                "source": "Argus Threat Intelligence",
                "description": ioc.description or "",
                "applied_globally": True,
            })
        if not indicators:
            return EdrPushResult(
                edr=self.name, success=False,
                note="no Falcon-compatible IOC types in batch",
            )

        token = await self._token()
        if not token:
            return EdrPushResult(
                edr=self.name, success=False,
                error="failed to acquire Falcon OAuth token",
            )
        url = f"{self._base}/iocs/entities/indicators/v1"
        breaker = get_breaker("edr:falcon")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, headers=self._headers(token),
                        data=json.dumps({"indicators": indicators}),
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

        resources = body.get("resources") or []
        ids = [str(r.get("id") or r.get("value")) for r in resources
               if isinstance(r, dict)]
        return EdrPushResult(
            edr=self.name, success=True,
            pushed_count=len(ids), remote_ids=ids,
        )

    async def isolate_host(self, *, host_id: str) -> EdrPushResult:
        if not self.is_configured():
            return EdrPushResult(edr=self.name, success=False,
                                  note="crowdstrike not configured")
        token = await self._token()
        if not token:
            return EdrPushResult(
                edr=self.name, success=False,
                error="failed to acquire Falcon OAuth token",
            )
        url = (f"{self._base}/devices/entities/devices-actions/v2"
               f"?action_name=contain")
        breaker = get_breaker("edr:falcon")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, headers=self._headers(token),
                        data=json.dumps({"ids": [host_id]}),
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
                                  note="crowdstrike not configured")
        token = await self._token()
        if not token:
            return EdrPushResult(
                edr=self.name, success=False,
                error="OAuth handshake failed",
            )
        return EdrPushResult(
            edr=self.name, success=True,
            note="crowdstrike OAuth token acquired",
        )
