"""Wazuh-as-SIEM push connector.

Wazuh's indexer is OpenSearch under the hood, so the same _bulk index
contract Argus already uses for Elasticsearch / OpenSearch works
unchanged. The distinction between this connector and the existing
``elastic`` one is operator intent: customers who already run Wazuh
for endpoint telemetry get one less thing to deploy if they push
Argus events into the Wazuh indexer too — single pane of glass.

Why a separate connector instead of "just point ARGUS_ELASTIC_URL at
your Wazuh indexer": (1) Wazuh's indexer auth defaults differ
(``admin:admin`` on day-zero, then operator-set), (2) Wazuh's data
view conventions use ``argus-*`` index pattern that we pre-set so
the operator doesn't have to add a Kibana data view by hand, and
(3) Service Inventory shows Wazuh as a coherent SIEM option distinct
from "generic Elasticsearch", reducing operator confusion.

Operator config:

    ARGUS_WAZUH_INDEXER_URL          base URL (e.g. https://wazuh-indexer:9200)
    ARGUS_WAZUH_INDEXER_USERNAME     username (default 'admin')
    ARGUS_WAZUH_INDEXER_PASSWORD     password
    ARGUS_WAZUH_INDEXER_INDEX        target index (default 'argus-events')
    ARGUS_WAZUH_INDEXER_VERIFY_SSL   "false" for self-signed
"""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import PushResult, SiemConnector

logger = logging.getLogger(__name__)


class WazuhSiemConnector(SiemConnector):
    name = "wazuh_siem"
    label = "Wazuh Indexer (OSS — self-hosted)"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_WAZUH_INDEXER_URL") or "") \
            .strip().rstrip("/")
        self._username = (
            os.environ.get("ARGUS_WAZUH_INDEXER_USERNAME") or "admin"
        ).strip()
        self._password = (
            os.environ.get("ARGUS_WAZUH_INDEXER_PASSWORD") or ""
        ).strip()
        self._index = (
            os.environ.get("ARGUS_WAZUH_INDEXER_INDEX") or "argus-events"
        ).strip()
        self._verify_ssl = (
            os.environ.get("ARGUS_WAZUH_INDEXER_VERIFY_SSL") or "true"
        ).strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url and self._password)

    def _auth_headers(self) -> dict[str, str]:
        creds = base64.b64encode(
            f"{self._username}:{self._password}".encode(),
        ).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/x-ndjson",
        }

    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="wazuh_siem not configured")
        if not events:
            return PushResult(success=True, pushed_count=0, note="no events")

        # Bulk-index NDJSON: alternating action + doc lines.
        ts = datetime.now(timezone.utc).isoformat()
        lines: list[str] = []
        for ev in events:
            doc = {
                "@timestamp": ev.get("created_at") or ts,
                "argus": ev,
                "event": {
                    "kind": "alert" if "title" in ev else "indicator",
                    "module": "argus",
                    "dataset": "argus.events",
                },
            }
            lines.append(json.dumps({"index": {"_index": self._index}}))
            lines.append(json.dumps(doc))
        body = "\n".join(lines) + "\n"

        url = f"{self._url}/_bulk"
        breaker = get_breaker("siem:wazuh_siem")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.post(
                        url, headers=self._auth_headers(), data=body,
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        try:
                            payload = json.loads(text)
                        except json.JSONDecodeError:
                            payload = {}
                        if isinstance(payload, dict) and payload.get("errors"):
                            failed = [
                                item for item in (payload.get("items") or [])
                                if isinstance(item, dict)
                                and any(v.get("error") for v in item.values() if isinstance(v, dict))
                            ]
                            return PushResult(
                                success=False,
                                pushed_count=len(events) - len(failed),
                                error=f"_bulk reports {len(failed)} doc failures",
                                raw={"sample_error": failed[:1]},
                            )
                        return PushResult(
                            success=True, pushed_count=len(events),
                            note=f"indexed into {self._index}",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )

    async def health_check(self) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="wazuh_siem not configured")
        url = f"{self._url}/_cluster/health"
        breaker = get_breaker("siem:wazuh_siem")
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(
                        url,
                        headers={
                            "Authorization": self._auth_headers()["Authorization"],
                            "Accept": "application/json",
                        },
                    ) as resp:
                        if resp.status >= 400:
                            text = await resp.text()
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return PushResult(
                            success=True,
                            note="wazuh-indexer cluster reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )
