"""Splunk HEC connector (P2 #2.7).

Splunk HTTP Event Collector — standard JSON event ingestion endpoint,
batch-friendly, available on every Splunk Enterprise / Cloud install.

Endpoint: ``${SPLUNK_HEC_URL}/services/collector/event``
Auth: ``Authorization: Splunk <token>``
Body: NDJSON of ``{"event": <obj>, "sourcetype": "argus", ...}``

Operator config:
  ARGUS_SPLUNK_HEC_URL          base URL (e.g. https://splunk.example.com:8088)
  ARGUS_SPLUNK_HEC_TOKEN        HEC token from Splunk
  ARGUS_SPLUNK_HEC_INDEX        target index (default: main)
  ARGUS_SPLUNK_HEC_VERIFY_SSL   "false" for self-signed (default true)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import PushResult, SiemConnector

logger = logging.getLogger(__name__)


class SplunkHecConnector(SiemConnector):
    name = "splunk_hec"
    label = "Splunk HTTP Event Collector"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_SPLUNK_HEC_URL") or "").strip().rstrip("/")
        self._token = (os.environ.get("ARGUS_SPLUNK_HEC_TOKEN") or "").strip()
        self._index = (os.environ.get("ARGUS_SPLUNK_HEC_INDEX") or "main").strip()
        self._verify_ssl = (os.environ.get("ARGUS_SPLUNK_HEC_VERIFY_SSL") or "true") \
            .strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url and self._token)

    async def push_events(self, events: list[dict[str, Any]]) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="splunk_hec not configured")
        if not events:
            return PushResult(success=True, pushed_count=0,
                              note="no events to push")

        # Splunk HEC NDJSON: each line is one ``{"event": ..., "sourcetype": ...}``.
        body_lines = []
        for ev in events:
            body_lines.append(json.dumps({
                "event": ev,
                "sourcetype": "argus:" + (ev.get("ioc_type") or "alert"),
                "source": "argus",
                "index": self._index,
            }, default=str))
        body = "\n".join(body_lines)

        url = f"{self._url}/services/collector/event"
        headers = {
            "Authorization": f"Splunk {self._token}",
            "Content-Type": "application/json",
        }
        breaker = get_breaker("siem:splunk_hec")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.post(
                        url, headers=headers, data=body,
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return PushResult(
                                success=False, pushed_count=0,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        return PushResult(
                            success=True, pushed_count=len(events),
                            raw={"http_status": resp.status, "body": text[:500]},
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False, pushed_count=0,
                error=f"{type(exc).__name__}: {exc}"[:300],
            )

    async def health_check(self) -> PushResult:
        """Push a single ping event and treat 2xx as healthy."""
        if not self.is_configured():
            return PushResult(success=False, note="splunk_hec not configured")
        return await self.push_events([{
            "id": "argus-health-check",
            "kind": "health_check",
            "source": "argus",
        }])
