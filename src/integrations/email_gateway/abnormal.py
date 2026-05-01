"""Abnormal Security connector (P3 #3.3).

Endpoints: ``https://api.abnormalplatform.com/v1``

  GET  /threats               recent phishing threats (fetch_threats)
  POST /threats/{id}/cases    elevate a threat to a Case
  GET  /abuse_mailbox          abuse-mailbox events (operator-side
                                  reported phishing)
  GET  /detection360           detected attacks summary

Auth: ``Authorization: Bearer <token>``.

Operator config:
  ARGUS_ABNORMAL_BASE_URL    https://api.abnormalplatform.com/v1
  ARGUS_ABNORMAL_TOKEN       paid Abnormal customer token
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


_DEFAULT_BASE = "https://api.abnormalplatform.com/v1"


class AbnormalConnector(EmailGatewayConnector):
    name = "abnormal"
    label = "Abnormal Security"
    # Abnormal blocks via its detection model + admin console; there's
    # no programmatic blocklist write API. Flag the capability so the
    # dashboard can grey out the action instead of misleading the
    # analyst with a "success=False" surface.
    supports_blocklist_push = False

    def __init__(self):
        self._base = (os.environ.get("ARGUS_ABNORMAL_BASE_URL")
                       or _DEFAULT_BASE).strip().rstrip("/")
        self._token = (os.environ.get("ARGUS_ABNORMAL_TOKEN") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._token)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def fetch_threats(
        self, *, since_iso: str | None = None,
    ) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="abnormal not configured",
            )
        url = f"{self._base}/threats"
        params: dict[str, str] = {"pageSize": "50"}
        if since_iso:
            params["filter"] = f"receivedTime gte {since_iso}"
        breaker = get_breaker("email:abnormal")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(
                        url, headers=self._headers(), params=params,
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
        for t in body.get("threats", []) or []:
            if not isinstance(t, dict):
                continue
            classification = (t.get("attackType") or "phish").lower()
            if classification not in {"phish", "malware", "spam", "other"}:
                classification = "phish"
            messages = t.get("messages") or []
            first_msg = messages[0] if messages else {}
            events.append(EmailThreatEvent(
                gateway=self.name,
                event_id=str(t.get("threatId") or ""),
                classification=classification,
                sender=(first_msg.get("fromAddress") if isinstance(first_msg, dict)
                        else None),
                recipient=(first_msg.get("toAddresses", [None])[0]
                           if isinstance(first_msg, dict) else None),
                subject=(first_msg.get("subject") if isinstance(first_msg, dict)
                          else None),
                occurred_at=(first_msg.get("receivedTime")
                              if isinstance(first_msg, dict) else None),
                raw=t,
            ))
        return EmailGatewayResult(
            gateway=self.name, success=True, events=events,
        )

    async def push_blocklist(
        self, items: list[EmailBlocklistItem],
    ) -> EmailGatewayResult:
        # Abnormal's API doesn't expose a programmatic blocklist write;
        # blocking is automatic from their detection model + admin
        # console. Surface as a structured no-op so the contract stays
        # uniform across email-gateway connectors.
        return EmailGatewayResult(
            gateway=self.name, success=False,
            note=("Abnormal Security does not expose a programmatic "
                  "blocklist write API; classification is model-driven. "
                  "For operator-managed blocking, use the Abnormal "
                  "admin console."),
        )

    async def health_check(self) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="abnormal not configured",
            )
        url = f"{self._base}/detection360"
        breaker = get_breaker("email:abnormal")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(
                        url, headers=self._headers(),
                    ) as resp:
                        text = await resp.text()
                        if resp.status == 401:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error="abnormal 401 — check ARGUS_ABNORMAL_TOKEN",
                            )
                        if resp.status >= 400:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return EmailGatewayResult(
                            gateway=self.name, success=True,
                            note="abnormal /detection360 reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
