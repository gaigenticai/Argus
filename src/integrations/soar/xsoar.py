"""Cortex XSOAR (Palo Alto) connector (P3 #3.7).

Pushes Argus alerts as XSOAR incidents via the public REST API.

Endpoint: ``${XSOAR_URL}/incident/create`` (auth: API key + ID)
Auth header: ``Authorization: <key>`` + ``x-xdr-auth-id: <key id>``

Operator config:
  ARGUS_XSOAR_URL          base URL (e.g. https://xsoar.example.com)
  ARGUS_XSOAR_API_KEY      API key (Settings → API keys)
  ARGUS_XSOAR_API_KEY_ID   numeric key id (shown beside the key)
  ARGUS_XSOAR_VERIFY_SSL   "false" for self-signed (default true)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import SoarConnector, SoarPushResult

logger = logging.getLogger(__name__)


_SEVERITY_TO_XSOAR: dict[str, int] = {
    # XSOAR severity scale: 0=unknown, 1=low, 2=medium, 3=high, 4=critical
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


class XsoarConnector(SoarConnector):
    name = "xsoar"
    label = "Cortex XSOAR"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_XSOAR_URL") or "") \
            .strip().rstrip("/")
        self._key = (os.environ.get("ARGUS_XSOAR_API_KEY") or "").strip()
        self._key_id = (os.environ.get("ARGUS_XSOAR_API_KEY_ID") or "").strip()
        self._verify_ssl = (os.environ.get("ARGUS_XSOAR_VERIFY_SSL") or "true") \
            .strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url and self._key and self._key_id)

    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(success=False, note="xsoar not configured")
        if not events:
            return SoarPushResult(success=True, pushed_count=0,
                                   note="no events to push")

        url = f"{self._url}/incident/create"
        headers = {
            "Authorization": self._key,
            "x-xdr-auth-id": self._key_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        breaker = get_breaker("soar:xsoar")
        timeout = aiohttp.ClientTimeout(total=30)
        remote_ids: list[str] = []
        first_error: str | None = None
        for ev in events:
            payload = {
                "name": ev.get("title") or "Argus alert",
                "type": "Argus Threat Intelligence",
                "severity": _SEVERITY_TO_XSOAR.get(
                    (ev.get("severity") or "medium").lower(), 2,
                ),
                "details": ev.get("summary") or "",
                "labels": [
                    {"type": "category", "value": ev.get("category") or ""},
                    {"type": "argus_alert_id", "value": ev.get("id") or ""},
                ],
                "rawJSON": json.dumps(ev, default=str),
            }
            try:
                async with breaker:
                    connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                    async with aiohttp.ClientSession(
                        timeout=timeout, connector=connector,
                    ) as http:
                        async with http.post(
                            url, headers=headers,
                            data=json.dumps(payload, default=str),
                        ) as resp:
                            text = await resp.text()
                            if resp.status >= 400:
                                if first_error is None:
                                    first_error = f"HTTP {resp.status}: {text[:200]}"
                                continue
                            # XSOAR returns the new incident's id field.
                            try:
                                body = json.loads(text)
                                rid = (body or {}).get("id") or ""
                                if rid:
                                    remote_ids.append(str(rid))
                            except ValueError:
                                pass
            except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
                if first_error is None:
                    first_error = f"{type(exc).__name__}: {exc}"[:200]
        return SoarPushResult(
            success=len(remote_ids) > 0 or first_error is None,
            pushed_count=len(remote_ids),
            remote_ids=remote_ids or None,
            error=first_error,
        )

    async def health_check(self) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(success=False, note="xsoar not configured")
        url = f"{self._url}/health"
        headers = {
            "Authorization": self._key,
            "x-xdr-auth-id": self._key_id,
        }
        breaker = get_breaker("soar:xsoar")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=headers) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SoarPushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SoarPushResult(
                            success=True,
                            note="xsoar /health reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SoarPushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )
