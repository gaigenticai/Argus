"""Splunk SOAR (formerly Phantom) connector (P3 #3.7).

Pushes Argus alerts as Splunk SOAR *containers* via the REST API.

Endpoint: ``${SPLUNK_SOAR_URL}/rest/container``
Auth header: ``ph-auth-token: <token>``

Operator config:
  ARGUS_SPLUNK_SOAR_URL          base URL (e.g. https://soar.example.com)
  ARGUS_SPLUNK_SOAR_TOKEN        auth token (Settings → User → ph-auth-token)
  ARGUS_SPLUNK_SOAR_LABEL        container label / queue (default: "events")
  ARGUS_SPLUNK_SOAR_VERIFY_SSL   "false" for self-signed (default true)
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


_SEVERITY_TO_SOAR: dict[str, str] = {
    "info": "low", "low": "low", "medium": "medium",
    "high": "high", "critical": "high",
}


class SplunkSoarConnector(SoarConnector):
    name = "splunk_soar"
    label = "Splunk SOAR (Phantom)"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_SPLUNK_SOAR_URL") or "") \
            .strip().rstrip("/")
        self._token = (os.environ.get("ARGUS_SPLUNK_SOAR_TOKEN") or "").strip()
        self._label = (os.environ.get("ARGUS_SPLUNK_SOAR_LABEL")
                        or "events").strip()
        self._verify_ssl = (os.environ.get("ARGUS_SPLUNK_SOAR_VERIFY_SSL") or "true") \
            .strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url and self._token)

    def _headers(self) -> dict[str, str]:
        return {
            "ph-auth-token": self._token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(success=False,
                                   note="splunk_soar not configured")
        if not events:
            return SoarPushResult(success=True, pushed_count=0,
                                   note="no events to push")

        url = f"{self._url}/rest/container"
        breaker = get_breaker("soar:splunk_soar")
        timeout = aiohttp.ClientTimeout(total=30)
        remote_ids: list[str] = []
        first_error: str | None = None
        for ev in events:
            payload = {
                "name": ev.get("title") or "Argus alert",
                "description": ev.get("summary") or "",
                "severity": _SEVERITY_TO_SOAR.get(
                    (ev.get("severity") or "medium").lower(), "medium",
                ),
                "label": self._label,
                "source_data_identifier": ev.get("id") or "",
                "data": {"argus": ev},
            }
            try:
                async with breaker:
                    connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                    async with aiohttp.ClientSession(
                        timeout=timeout, connector=connector,
                    ) as http:
                        async with http.post(
                            url, headers=self._headers(),
                            data=json.dumps(payload, default=str),
                        ) as resp:
                            text = await resp.text()
                            if resp.status >= 400:
                                if first_error is None:
                                    first_error = f"HTTP {resp.status}: {text[:200]}"
                                continue
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
            return SoarPushResult(success=False,
                                   note="splunk_soar not configured")
        url = f"{self._url}/rest/version"
        breaker = get_breaker("soar:splunk_soar")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(
                        url, headers=self._headers(),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SoarPushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SoarPushResult(
                            success=True,
                            note="splunk_soar /rest/version reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SoarPushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )
