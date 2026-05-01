"""IBM QRadar Reference Set connector (P2 #2.7).

Pushes IOC values into a QRadar reference set so QRadar's correlation
rules can match on Argus-supplied indicators. The reference set must
exist beforehand — operators can create it via the QRadar admin UI
(Reference Set Management) or the REST API; the wrapper assumes
operator-managed lifecycle.

For richer event push (alerts as full QRadar events), QRadar's "log
source" path is operator-managed too — we provide a thin POST/POST
helper but the canonical Argus → QRadar path is via reference sets.

Operator config:
  ARGUS_QRADAR_URL                    https://qradar.example.com
  ARGUS_QRADAR_TOKEN                  SEC token from Admin → Authorized Services
  ARGUS_QRADAR_REFERENCE_SET          name of the pre-created set (e.g. ArgusIOCs)
  ARGUS_QRADAR_VERIFY_SSL             "false" for self-signed
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


class QRadarConnector(SiemConnector):
    name = "qradar"
    label = "IBM QRadar"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_QRADAR_URL") or "") \
            .strip().rstrip("/")
        self._token = (os.environ.get("ARGUS_QRADAR_TOKEN") or "").strip()
        self._refset = (os.environ.get("ARGUS_QRADAR_REFERENCE_SET")
                        or "ArgusIOCs").strip()
        self._verify_ssl = (os.environ.get("ARGUS_QRADAR_VERIFY_SSL") or "true") \
            .strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url and self._token and self._refset)

    def _headers(self) -> dict[str, str]:
        return {
            "SEC": self._token,
            "Version": "16.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def push_events(self, events: list[dict[str, Any]]) -> PushResult:
        """Push IOC values from each event into the reference set.

        Alert events without an ``ioc_type``/``value`` pair are skipped
        — QRadar reference sets are designed for atomic IOC matching,
        not full event ingestion. For alert-as-event push, point the
        operator at the Splunk HEC / Sentinel / Elastic connectors.
        """
        if not self.is_configured():
            return PushResult(success=False, note="qradar not configured")

        # Reference sets accept atomic values (IPs, domains, hashes,
        # usernames). Pull a usable string out of every event.
        values: list[str] = []
        for ev in events:
            v = ev.get("value")
            if v:
                values.append(str(v))
                continue
            # Alert events: synthesise from title (operators can match
            # on titles via reference rules).
            t = ev.get("title")
            if t:
                values.append(str(t))
        if not values:
            return PushResult(success=True, pushed_count=0,
                              note="no IOC values to push")

        url = (f"{self._url}/api/reference_data/sets/bulk_load/"
               f"{self._refset}")
        breaker = get_breaker("siem:qradar")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.post(
                        url, headers=self._headers(),
                        data=json.dumps(values),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        return PushResult(
                            success=True, pushed_count=len(values),
                            raw={"http_status": resp.status, "body": text[:500]},
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}"[:300],
            )

    async def health_check(self) -> PushResult:
        """Check the reference set exists and is reachable."""
        if not self.is_configured():
            return PushResult(success=False, note="qradar not configured")
        url = f"{self._url}/api/reference_data/sets/{self._refset}"
        breaker = get_breaker("siem:qradar")
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
                        if resp.status == 404:
                            return PushResult(
                                success=False,
                                error=f"reference set {self._refset!r} not found",
                            )
                        if resp.status >= 400:
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        return PushResult(
                            success=True,
                            note=f"reference set {self._refset!r} reachable",
                            raw={"http_status": resp.status},
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}"[:300],
            )
