"""Elastic bulk-index connector (P2 #2.7).

Pushes events to an Elasticsearch / Elastic Cloud cluster via the
``_bulk`` API. Documents are shaped per Elastic Common Schema (ECS):

  alerts → ``{"@timestamp": …, "event": {"kind": "alert"}, …}``
  IOCs   → ``{"@timestamp": …, "threat": {"indicator": …}, …}``

Authentication:
  ARGUS_ELASTIC_URL          base URL (e.g. https://es.example.com:9200)
  ARGUS_ELASTIC_API_KEY      Elastic API key (recommended)
  ARGUS_ELASTIC_USERNAME     basic-auth username (alt to API key)
  ARGUS_ELASTIC_PASSWORD     basic-auth password
  ARGUS_ELASTIC_INDEX        target index (default: argus-events)
  ARGUS_ELASTIC_VERIFY_SSL   "false" for self-signed (default true)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import PushResult, SiemConnector

logger = logging.getLogger(__name__)


class ElasticConnector(SiemConnector):
    name = "elastic"
    label = "Elasticsearch / Elastic Cloud"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_ELASTIC_URL") or "") \
            .strip().rstrip("/")
        self._api_key = (os.environ.get("ARGUS_ELASTIC_API_KEY") or "").strip()
        self._username = (os.environ.get("ARGUS_ELASTIC_USERNAME") or "").strip()
        self._password = (os.environ.get("ARGUS_ELASTIC_PASSWORD") or "").strip()
        self._index = (os.environ.get("ARGUS_ELASTIC_INDEX") or "argus-events").strip()
        self._verify_ssl = (os.environ.get("ARGUS_ELASTIC_VERIFY_SSL") or "true") \
            .strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        if not self._url:
            return False
        return bool(self._api_key or (self._username and self._password))

    def _auth_headers(self) -> dict[str, str]:
        if self._api_key:
            return {"Authorization": f"ApiKey {self._api_key}"}
        if self._username and self._password:
            import base64
            creds = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            return {"Authorization": f"Basic {creds}"}
        return {}

    @staticmethod
    def _to_ecs(event: dict[str, Any]) -> dict[str, Any]:
        """Map an Argus event to ECS-shaped JSON."""
        kind = "alert" if "title" in event else "indicator"
        out: dict[str, Any] = {
            "@timestamp": (event.get("created_at")
                           or event.get("first_seen")
                           or datetime.now(timezone.utc).isoformat()),
            "event": {
                "kind": kind,
                "module": "argus",
                "dataset": "argus.alerts" if kind == "alert"
                            else "argus.iocs",
                "severity": event.get("severity"),
                "category": [event.get("category")] if event.get("category") else [],
            },
            "argus": event,
        }
        if kind == "indicator":
            out["threat"] = {
                "indicator": {
                    "type": event.get("ioc_type"),
                    "name": event.get("value"),
                    "confidence": event.get("confidence"),
                    "tags": event.get("tags", []),
                }
            }
        return out

    async def push_events(self, events: list[dict[str, Any]]) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="elastic not configured")
        if not events:
            return PushResult(success=True, pushed_count=0,
                              note="no events to push")

        # Bulk format: alternating action + source lines, NDJSON.
        lines: list[str] = []
        for ev in events:
            ecs = self._to_ecs(ev)
            doc_id = ev.get("id") or None
            action = {"index": {"_index": self._index}}
            if doc_id:
                action["index"]["_id"] = doc_id
            lines.append(json.dumps(action))
            lines.append(json.dumps(ecs, default=str))
        body = "\n".join(lines) + "\n"

        url = f"{self._url}/_bulk"
        headers = {
            "Content-Type": "application/x-ndjson",
            **self._auth_headers(),
        }
        breaker = get_breaker("siem:elastic")
        timeout = aiohttp.ClientTimeout(total=60)
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
                                success=False,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        # Parse the bulk response to surface per-doc errors.
                        try:
                            payload = json.loads(text)
                            errors = payload.get("errors", False)
                            if errors:
                                # Some docs failed; report partial.
                                items = payload.get("items", [])
                                ok = sum(
                                    1 for it in items
                                    if isinstance(it, dict)
                                    and not (
                                        it.get("index", {}).get("error")
                                    )
                                )
                                return PushResult(
                                    success=ok > 0,
                                    pushed_count=ok,
                                    note=f"{len(items) - ok} doc(s) had ingest errors",
                                )
                        except ValueError:
                            pass
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
            return PushResult(success=False, note="elastic not configured")
        url = f"{self._url}/_cluster/health"
        breaker = get_breaker("siem:elastic")
        timeout = aiohttp.ClientTimeout(total=15)
        headers = self._auth_headers()
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=headers) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return PushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:300]}",
                            )
                        try:
                            payload = json.loads(text)
                        except ValueError:
                            payload = {}
                        cluster_status = payload.get("status", "unknown")
                        return PushResult(
                            success=cluster_status in ("green", "yellow"),
                            note=f"cluster status={cluster_status}",
                            raw=payload,
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return PushResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}"[:300],
            )
