"""Microsoft Sentinel connector (P2 #2.7).

Pushes events to Sentinel via the **Logs Ingestion API** through a Data
Collection Endpoint (DCE) + Data Collection Rule (DCR) — Microsoft's
modern, AAD-authenticated path for custom log ingestion. The legacy
HTTP Data Collector API still works but is on a deprecation track;
operators on it can use the same connector — our ``ARGUS_SENTINEL_AUTH``
toggle picks between the two.

When ``ARGUS_SENTINEL_AUTH=token``:
    Direct shared-secret to a webhook URL (HTTP Data Collector style).
    Endpoint: ``ARGUS_SENTINEL_WEBHOOK_URL``
    Auth:     header ``Authorization: SharedKey ...`` derived from
              ``ARGUS_SENTINEL_SHARED_KEY``

When ``ARGUS_SENTINEL_AUTH=oauth`` (default):
    Logs Ingestion API. Operator must provision:
      - a tenant + service principal
      - a DCE
      - a DCR with custom-table mappings
    Configure:
      ARGUS_SENTINEL_DCE_URL             https://...ingest.monitor.azure.com
      ARGUS_SENTINEL_DCR_IMMUTABLE_ID    dcr-...
      ARGUS_SENTINEL_STREAM_NAME         Custom-Argus_CL  (or operator's choice)
      ARGUS_SENTINEL_TENANT_ID
      ARGUS_SENTINEL_CLIENT_ID
      ARGUS_SENTINEL_CLIENT_SECRET
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import PushResult, SiemConnector

logger = logging.getLogger(__name__)


_TOKEN_CACHE: dict[str, tuple[str, float]] = {}  # client_id → (token, expiry_ts)


class SentinelConnector(SiemConnector):
    name = "sentinel"
    label = "Microsoft Sentinel"

    def __init__(self):
        self._auth_mode = (os.environ.get("ARGUS_SENTINEL_AUTH") or "oauth") \
            .strip().lower()

        if self._auth_mode == "token":
            self._webhook_url = (os.environ.get("ARGUS_SENTINEL_WEBHOOK_URL") or "").strip()
            self._shared_key = (os.environ.get("ARGUS_SENTINEL_SHARED_KEY") or "").strip()
        else:
            self._dce_url = (os.environ.get("ARGUS_SENTINEL_DCE_URL") or "") \
                .strip().rstrip("/")
            self._dcr_id = (os.environ.get("ARGUS_SENTINEL_DCR_IMMUTABLE_ID") or "").strip()
            self._stream = (os.environ.get("ARGUS_SENTINEL_STREAM_NAME") or "").strip()
            self._tenant = (os.environ.get("ARGUS_SENTINEL_TENANT_ID") or "").strip()
            self._client_id = (os.environ.get("ARGUS_SENTINEL_CLIENT_ID") or "").strip()
            self._client_secret = (os.environ.get("ARGUS_SENTINEL_CLIENT_SECRET") or "").strip()

    def is_configured(self) -> bool:
        if self._auth_mode == "token":
            return bool(self._webhook_url and self._shared_key)
        return bool(
            self._dce_url and self._dcr_id and self._stream
            and self._tenant and self._client_id and self._client_secret
        )

    # ── OAuth token cache ────────────────────────────────────────

    async def _get_token(self) -> str | None:
        """Cached AAD client-credentials token. Tokens are good for ~1h;
        we refresh 5 min before expiry."""
        cached = _TOKEN_CACHE.get(self._client_id)
        if cached and cached[1] > time.time() + 300:
            return cached[0]
        url = f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://monitor.azure.com/.default",
        }
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.post(url, data=data) as resp:
                    if resp.status >= 400:
                        logger.warning("[sentinel] AAD token HTTP %s",
                                       resp.status)
                        return None
                    payload = await resp.json()
        except aiohttp.ClientError as exc:
            logger.warning("[sentinel] AAD token error: %s", exc)
            return None
        token = payload.get("access_token")
        expires_in = int(payload.get("expires_in", 3600))
        if token:
            _TOKEN_CACHE[self._client_id] = (token, time.time() + expires_in)
        return token

    # ── Push paths ──────────────────────────────────────────────

    async def push_events(self, events: list[dict[str, Any]]) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="sentinel not configured")
        if not events:
            return PushResult(success=True, pushed_count=0,
                              note="no events to push")
        if self._auth_mode == "token":
            return await self._push_token(events)
        return await self._push_oauth(events)

    async def _push_oauth(
        self, events: list[dict[str, Any]],
    ) -> PushResult:
        token = await self._get_token()
        if not token:
            return PushResult(
                success=False, error="failed to acquire AAD token",
            )
        url = (
            f"{self._dce_url}/dataCollectionRules/{self._dcr_id}"
            f"/streams/{self._stream}?api-version=2023-01-01"
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        breaker = get_breaker("siem:sentinel")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, headers=headers,
                        data=json.dumps(events, default=str),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        return PushResult(
                            success=True, pushed_count=len(events),
                            raw={"http_status": resp.status},
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}"[:300],
            )

    async def _push_token(
        self, events: list[dict[str, Any]],
    ) -> PushResult:
        breaker = get_breaker("siem:sentinel")
        timeout = aiohttp.ClientTimeout(total=30)
        headers = {
            "Authorization": self._shared_key,
            "Content-Type": "application/json",
        }
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        self._webhook_url, headers=headers,
                        data=json.dumps(events, default=str),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        return PushResult(
                            success=True, pushed_count=len(events),
                            raw={"http_status": resp.status},
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}"[:300],
            )

    async def health_check(self) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="sentinel not configured")
        return await self.push_events([{
            "id": "argus-health-check",
            "kind": "health_check", "source": "argus",
        }])
