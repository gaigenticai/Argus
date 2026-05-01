"""Mimecast connector (P3 #3.3).

Mimecast's API requires a four-element auth header set computed
per-request:
  - x-mc-app-id        application ID (operator's app key)
  - x-mc-req-id        random per-request UUID
  - x-mc-date          RFC 1123 timestamp
  - Authorization      ``MC <access_key>:<hmac_signature>``

The HMAC signs ``date + request_id + app_id + uri`` with the
operator's secret. v1 implements:

  POST /api/ttp/url/get-logs        recent URL Protect events (fetch_threats)
  POST /api/managedsender/permit-or-block-sender   blocklist push
  POST /api/account/get-account     health check

Operator config:
  ARGUS_MIMECAST_BASE_URL    https://eu-api.mimecast.com  (or us / au …)
  ARGUS_MIMECAST_APP_ID
  ARGUS_MIMECAST_APP_KEY
  ARGUS_MIMECAST_ACCESS_KEY
  ARGUS_MIMECAST_SECRET_KEY  base64-encoded HMAC secret
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import uuid as _uuid
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import (
    EmailBlocklistItem,
    EmailGatewayConnector,
    EmailGatewayResult,
    EmailThreatEvent,
)

logger = logging.getLogger(__name__)


class MimecastConnector(EmailGatewayConnector):
    name = "mimecast"
    label = "Mimecast"

    def __init__(self):
        self._base = (os.environ.get("ARGUS_MIMECAST_BASE_URL") or "") \
            .strip().rstrip("/")
        self._app_id = (os.environ.get("ARGUS_MIMECAST_APP_ID") or "").strip()
        self._app_key = (os.environ.get("ARGUS_MIMECAST_APP_KEY") or "").strip()
        self._access = (os.environ.get("ARGUS_MIMECAST_ACCESS_KEY") or "").strip()
        self._secret = (os.environ.get("ARGUS_MIMECAST_SECRET_KEY") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._base and self._app_id and self._app_key
                    and self._access and self._secret)

    def _headers(self, uri: str) -> dict[str, str]:
        request_id = str(_uuid.uuid4())
        date = format_datetime(datetime.now(timezone.utc))
        # HMAC-SHA1 over (date + ":" + request_id + ":" + app_key + ":" + uri)
        try:
            secret_bytes = base64.b64decode(self._secret)
        except Exception:
            secret_bytes = self._secret.encode()
        message = f"{date}:{request_id}:{self._app_key}:{uri}"
        sig = hmac.new(secret_bytes, message.encode("utf-8"),
                       hashlib.sha1).digest()
        signature = base64.b64encode(sig).decode("ascii")
        return {
            "Authorization": f"MC {self._access}:{signature}",
            "x-mc-app-id": self._app_id,
            "x-mc-date": date,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _post(
        self, uri: str, body: dict[str, Any], *, timeout_seconds: int = 30,
    ) -> tuple[int, str, dict | None]:
        breaker = get_breaker("email:mimecast")
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.post(
                    f"{self._base}{uri}",
                    headers=self._headers(uri),
                    data=json.dumps(body),
                ) as resp:
                    text = await resp.text()
                    parsed: dict | None = None
                    try:
                        parsed = json.loads(text) if text else None
                    except ValueError:
                        parsed = None
                    return resp.status, text, parsed

    async def fetch_threats(
        self, *, since_iso: str | None = None,
    ) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="mimecast not configured",
            )
        uri = "/api/ttp/url/get-logs"
        body = {"data": [{
            "from": since_iso or "",
            "to": "",
            "scanResult": "malicious",
        }]}
        try:
            status, text, payload = await self._post(uri, body)
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
        if status >= 400:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"HTTP {status}: {text[:200]}",
            )

        rows = ((payload or {}).get("data") or [{}])[0].get("clickLogs") or []
        events: list[EmailThreatEvent] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            events.append(EmailThreatEvent(
                gateway=self.name,
                event_id=str(r.get("id") or ""),
                classification=("phish" if (r.get("scanResult") or "").lower()
                                 == "malicious" else "other"),
                sender=r.get("senderAddress"),
                recipient=r.get("userEmailAddress"),
                subject=r.get("subject"),
                threat_url=r.get("url"),
                occurred_at=r.get("date"),
                raw=r,
            ))
        return EmailGatewayResult(
            gateway=self.name, success=True, events=events,
        )

    async def push_blocklist(
        self, items: list[EmailBlocklistItem],
    ) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="mimecast not configured",
            )
        # Mimecast's managed-sender list takes one entry per call; we
        # batch transparently and aggregate the response.
        uri = "/api/managedsender/permit-or-block-sender"
        ids: list[str] = []
        first_error: str | None = None
        for item in items:
            if item.type not in ("sender", "domain", "url"):
                continue
            body = {"data": [{
                "sender": item.value,
                "to": "*",
                "type": "block",
                "comment": item.description or "Argus IOC",
            }]}
            try:
                status, text, payload = await self._post(uri, body)
            except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
                if first_error is None:
                    first_error = f"{type(exc).__name__}: {exc}"[:200]
                continue
            if status >= 400:
                if first_error is None:
                    first_error = f"HTTP {status}: {text[:200]}"
                continue
            data = ((payload or {}).get("data") or [])
            for d in data:
                if isinstance(d, dict) and d.get("id"):
                    ids.append(str(d["id"]))
        # Empty input or every item filtered out by type-allowlist →
        # surface as failure with a note instead of misleading success.
        if not items or (not ids and first_error is None):
            return EmailGatewayResult(
                gateway=self.name, success=False, pushed_count=0,
                note=("no Mimecast-compatible blocklist items in batch "
                      "(supported types: sender, domain, url)"),
            )
        return EmailGatewayResult(
            gateway=self.name,
            success=len(ids) > 0,
            pushed_count=len(ids),
            remote_ids=ids,
            error=first_error,
        )

    async def health_check(self) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="mimecast not configured",
            )
        try:
            status, text, _ = await self._post(
                "/api/account/get-account", {"data": []},
                timeout_seconds=15,
            )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
        if status == 401:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error="mimecast 401 — check credentials",
            )
        if status >= 400:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"HTTP {status}: {text[:200]}",
            )
        return EmailGatewayResult(
            gateway=self.name, success=True,
            note="mimecast /account/get-account reachable",
        )
