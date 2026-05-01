"""Proofpoint TAP (Targeted Attack Protection) connector (P3 #3.3).

Endpoints (Proofpoint TAP SIEM API v2):
  GET /v2/siem/all                pull recent threat events
  GET /v2/url/decode              decode a Proofpoint-rewritten URL

For URL Defense URL Protect blocklists use the Proofpoint admin
console — Proofpoint doesn't expose a programmatic blocklist write
endpoint to TAP SIEM tier. We surface ``push_blocklist`` as a
``not implemented`` stub so the API contract stays uniform.

Auth: HTTP Basic with PrincipalKey + PrincipalSecret.

Operator config:
  ARGUS_PROOFPOINT_BASE_URL    https://tap-api-v2.proofpoint.com
  ARGUS_PROOFPOINT_PRINCIPAL   PrincipalKey
  ARGUS_PROOFPOINT_SECRET      PrincipalSecret
"""

from __future__ import annotations

import json
import logging
import os
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


_DEFAULT_BASE = "https://tap-api-v2.proofpoint.com"


class ProofpointTapConnector(EmailGatewayConnector):
    name = "proofpoint"
    label = "Proofpoint TAP"
    # Proofpoint TAP is read-only — the public TAP API has no
    # programmatic blocklist write surface. push_blocklist() returns
    # a structured note so the dashboard can grey the action out.
    supports_blocklist_push = False

    def __init__(self):
        self._base = (os.environ.get("ARGUS_PROOFPOINT_BASE_URL") or _DEFAULT_BASE) \
            .strip().rstrip("/")
        self._principal = (os.environ.get("ARGUS_PROOFPOINT_PRINCIPAL") or "").strip()
        self._secret = (os.environ.get("ARGUS_PROOFPOINT_SECRET") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._principal and self._secret)

    async def fetch_threats(
        self, *, since_iso: str | None = None,
    ) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="proofpoint not configured",
            )
        url = f"{self._base}/v2/siem/all"
        params: dict[str, str] = {"format": "json"}
        if since_iso:
            params["sinceTime"] = since_iso
        else:
            params["sinceSeconds"] = "3600"
        breaker = get_breaker("email:proofpoint")
        timeout = aiohttp.ClientTimeout(total=30)
        auth = aiohttp.BasicAuth(self._principal, self._secret)
        try:
            async with breaker:
                async with aiohttp.ClientSession(
                    timeout=timeout, auth=auth,
                ) as http:
                    async with http.get(
                        url, params=params,
                        headers={"Accept": "application/json"},
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        body = json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        events: list[EmailThreatEvent] = []
        for kind, normalized in (
            ("clicksPermitted", "phish"),
            ("clicksBlocked", "phish"),
            ("messagesDelivered", "malware"),
            ("messagesBlocked", "malware"),
        ):
            for ev in body.get(kind, []) or []:
                if not isinstance(ev, dict):
                    continue
                events.append(EmailThreatEvent(
                    gateway=self.name,
                    event_id=str(ev.get("GUID") or ev.get("id") or ""),
                    classification=normalized,
                    sender=ev.get("sender"),
                    recipient=(ev.get("recipient") or [None])[0]
                        if isinstance(ev.get("recipient"), list)
                        else ev.get("recipient"),
                    subject=ev.get("subject"),
                    threat_url=ev.get("url"),
                    occurred_at=ev.get("messageTime") or ev.get("clickTime"),
                    raw=ev,
                ))
        return EmailGatewayResult(
            gateway=self.name, success=True, events=events,
        )

    async def push_blocklist(
        self, items: list[EmailBlocklistItem],
    ) -> EmailGatewayResult:
        # Proofpoint TAP SIEM tier is read-only. Document and no-op.
        return EmailGatewayResult(
            gateway=self.name, success=False,
            note=("Proofpoint TAP SIEM API is read-only; push to URL "
                  "Defense URL Protect lists from the Proofpoint admin "
                  "console."),
        )

    async def health_check(self) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="proofpoint not configured",
            )
        # ``/v2/people/vap`` is a cheap query that confirms creds work.
        url = f"{self._base}/v2/people/vap"
        breaker = get_breaker("email:proofpoint")
        timeout = aiohttp.ClientTimeout(total=15)
        auth = aiohttp.BasicAuth(self._principal, self._secret)
        try:
            async with breaker:
                async with aiohttp.ClientSession(
                    timeout=timeout, auth=auth,
                ) as http:
                    async with http.get(
                        url, params={"window": "14"},
                    ) as resp:
                        text = await resp.text()
                        if resp.status == 401:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error="proofpoint 401 — check credentials",
                            )
                        if resp.status >= 400:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return EmailGatewayResult(
                            gateway=self.name, success=True,
                            note="proofpoint /people/vap reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
