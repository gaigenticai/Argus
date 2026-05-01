"""Microsoft Defender for Endpoint (MDE) connector (P3 #3.2).

MDE talks Graph + the older WindowsDefenderATP API surface. Argus
uses the v1 surface — ``api.securitycenter.microsoft.com`` — which
has the cleanest IOC management:

  POST /api/indicators        upload custom IOC
  POST /api/machines/{id}/isolate    isolate a machine

Auth: AAD client-credentials → Bearer token. Same OAuth dance as
the Sentinel SIEM connector but against the WindowsDefenderATP
resource (https://api.securitycenter.microsoft.com).

Operator config:
  ARGUS_MDE_TENANT_ID
  ARGUS_MDE_CLIENT_ID
  ARGUS_MDE_CLIENT_SECRET
  ARGUS_MDE_BASE_URL    override (default api.securitycenter.microsoft.com)
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


_MDE_TYPE_MAP: dict[str, str] = {
    "ipv4":   "IpAddress",
    "ipv6":   "IpAddress",
    "domain": "DomainName",
    "url":    "Url",
    "md5":    "FileMd5",
    "sha1":   "FileSha1",
    "sha256": "FileSha256",
}

_DEFAULT_BASE = "https://api.securitycenter.microsoft.com"


class MicrosoftDefenderConnector(EdrConnector):
    name = "mde"
    label = "Microsoft Defender for Endpoint"

    _TOKEN_CACHE: dict[str, tuple[str, float]] = {}

    def __init__(self):
        self._base = (os.environ.get("ARGUS_MDE_BASE_URL") or _DEFAULT_BASE) \
            .strip().rstrip("/")
        self._tenant = (os.environ.get("ARGUS_MDE_TENANT_ID") or "").strip()
        self._client_id = (os.environ.get("ARGUS_MDE_CLIENT_ID") or "").strip()
        self._client_secret = (os.environ.get("ARGUS_MDE_CLIENT_SECRET") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._tenant and self._client_id and self._client_secret)

    async def _token(self) -> str | None:
        cached = self._TOKEN_CACHE.get(self._client_id)
        if cached and cached[1] > time.time() + 60:
            return cached[0]
        url = f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }
        breaker = get_breaker("edr:mde")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(url, data=data) as resp:
                        if resp.status >= 400:
                            return None
                        body = await resp.json()
        except (CircuitBreakerOpenError, aiohttp.ClientError):
            return None
        token = body.get("access_token")
        ttl = int(body.get("expires_in", 3600))
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
                                  note="mde not configured")
        if not iocs:
            return EdrPushResult(edr=self.name, success=True,
                                  pushed_count=0, note="no iocs to push")
        token = await self._token()
        if not token:
            return EdrPushResult(
                edr=self.name, success=False,
                error="failed to acquire MDE OAuth token",
            )

        url = f"{self._base}/api/indicators"
        breaker = get_breaker("edr:mde")
        timeout = aiohttp.ClientTimeout(total=30)
        ids: list[str] = []
        first_error: str | None = None
        for ioc in iocs:
            mde_type = _MDE_TYPE_MAP.get(ioc.type.lower())
            if mde_type is None:
                continue
            payload = {
                "indicatorValue": ioc.value,
                "indicatorType": mde_type,
                "title": "Argus IOC",
                "description": ioc.description or "Argus-supplied IOC",
                "severity": ioc.severity.capitalize() if ioc.severity else "Medium",
                "action": "Block" if ioc.action == "prevent" else "Audit",
                "rbacGroupNames": [],
                "source": "Argus",
            }
            try:
                async with breaker:
                    async with aiohttp.ClientSession(timeout=timeout) as http:
                        async with http.post(
                            url, headers=self._headers(token),
                            data=json.dumps(payload),
                        ) as resp:
                            text = await resp.text()
                            if resp.status >= 400:
                                if first_error is None:
                                    first_error = f"HTTP {resp.status}: {text[:200]}"
                                continue
                            body = json.loads(text) if text else {}
                            rid = body.get("id") or body.get("indicatorId")
                            if rid:
                                ids.append(str(rid))
            except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
                if first_error is None:
                    first_error = f"{type(exc).__name__}: {exc}"[:200]
        return EdrPushResult(
            edr=self.name, success=len(ids) > 0 or first_error is None,
            pushed_count=len(ids), remote_ids=ids, error=first_error,
        )

    async def isolate_host(self, *, host_id: str) -> EdrPushResult:
        if not self.is_configured():
            return EdrPushResult(edr=self.name, success=False,
                                  note="mde not configured")
        token = await self._token()
        if not token:
            return EdrPushResult(
                edr=self.name, success=False,
                error="failed to acquire MDE OAuth token",
            )
        url = f"{self._base}/api/machines/{host_id}/isolate"
        breaker = get_breaker("edr:mde")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, headers=self._headers(token),
                        data=json.dumps({
                            "Comment": "Isolated by Argus case copilot",
                            "IsolationType": "Full",
                        }),
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
                                  note="mde not configured")
        token = await self._token()
        if not token:
            return EdrPushResult(
                edr=self.name, success=False,
                error="OAuth handshake failed",
            )
        return EdrPushResult(
            edr=self.name, success=True,
            note="mde OAuth token acquired",
        )
