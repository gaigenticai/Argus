"""Graylog GELF push connector.

Graylog accepts events via the **GELF** (Graylog Extended Log Format)
JSON envelope, which it natively understands across HTTP, TCP, and
UDP inputs. This connector uses the HTTP input flavour because:

  * Graylog operators expose HTTP-GELF on a single port (default
    12201) regardless of cluster topology.
  * No custom protocol framing — one POST per event batch.
  * TLS termination is whatever Graylog already does.
  * Auth is optional; many operators trust the URL itself.

GELF document shape (v1.1):

    {
      "version": "1.1",
      "host":          "<hostname of sender>",
      "short_message": "<single-line summary>",
      "full_message":  "<multi-line detail (optional)>",
      "timestamp":     <unix epoch float>,
      "level":         <syslog severity 0..7>,
      "_argus_id":     "<custom field — must be _-prefixed>",
      "_argus_kind":   "alert" | "indicator",
      "_argus_*":      ...
    }

Operator config:

    ARGUS_GRAYLOG_GELF_URL       full URL incl. path (e.g.
                                 https://graylog.internal:12201/gelf)
    ARGUS_GRAYLOG_BASIC_USER     optional basic-auth username
    ARGUS_GRAYLOG_BASIC_PASSWORD optional basic-auth password
    ARGUS_GRAYLOG_VERIFY_SSL     "false" for self-signed
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import time
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import PushResult, SiemConnector

logger = logging.getLogger(__name__)


# GELF level <-> syslog severity. We only care about 4 (warning),
# 5 (notice), 6 (info), 7 (debug); Argus alert severities map onto
# syslog warning (high), error (critical), notice (medium/low).
_SEV_TO_GELF_LEVEL: dict[str, int] = {
    "critical": 2,  # critical
    "high":     3,  # error
    "medium":   4,  # warning
    "low":      5,  # notice
}


class GraylogConnector(SiemConnector):
    name = "graylog"
    label = "Graylog (GELF push)"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_GRAYLOG_GELF_URL") or "") \
            .strip()
        self._basic_user = (os.environ.get("ARGUS_GRAYLOG_BASIC_USER") or "").strip()
        self._basic_password = (
            os.environ.get("ARGUS_GRAYLOG_BASIC_PASSWORD") or ""
        ).strip()
        self._verify_ssl = (
            os.environ.get("ARGUS_GRAYLOG_VERIFY_SSL") or "true"
        ).strip().lower() not in {"false", "0", "no", "off"}
        # GELF requires a "host" field on every event; the operator
        # might want it overridden (e.g. inside containers `gethostname`
        # returns the container hash). Accept an explicit override.
        self._host = (
            os.environ.get("ARGUS_GRAYLOG_HOST_FIELD")
            or socket.gethostname()
            or "argus"
        )

    def is_configured(self) -> bool:
        return bool(self._url)

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._basic_user and self._basic_password:
            creds = base64.b64encode(
                f"{self._basic_user}:{self._basic_password}".encode(),
            ).decode()
            h["Authorization"] = f"Basic {creds}"
        return h

    def _to_gelf(self, ev: dict[str, Any]) -> dict[str, Any]:
        """Project an Argus event dict onto a GELF v1.1 document.

        Graylog requires every custom field to be ``_`` prefixed, so we
        flatten the Argus payload into ``_argus_*`` keys that the
        operator can pivot/filter on without colliding with GELF
        reserved names."""
        title = ev.get("title") or ev.get("value") or "Argus event"
        summary = ev.get("summary") or ""
        sev = (ev.get("severity") or "medium").lower()
        gelf: dict[str, Any] = {
            "version": "1.1",
            "host": self._host,
            "short_message": title[:240],
            "timestamp": time.time(),
            "level": _SEV_TO_GELF_LEVEL.get(sev, 6),
        }
        if summary:
            gelf["full_message"] = summary[:8000]
        # Project Argus fields onto _-prefixed customs.
        for k, v in ev.items():
            if v is None or k in ("title", "summary", "severity"):
                continue
            key = f"_argus_{k}".replace("-", "_")
            # Graylog's GELF schema only accepts scalars or stringified
            # values for custom fields; jsonify lists/dicts.
            if isinstance(v, (list, dict)):
                gelf[key] = json.dumps(v)[:5000]
            else:
                gelf[key] = v
        gelf.setdefault("_argus_severity", sev)
        return gelf

    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="graylog not configured")
        if not events:
            return PushResult(success=True, pushed_count=0, note="no events")

        breaker = get_breaker("siem:graylog")
        timeout = aiohttp.ClientTimeout(total=15)
        pushed = 0
        last_error: str | None = None

        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    # Graylog HTTP GELF is one event per POST. Loop —
                    # the per-event cost is small and the contract is
                    # simpler than the chunked array shape some forks
                    # accept.
                    for ev in events:
                        doc = self._to_gelf(ev)
                        try:
                            async with http.post(
                                self._url,
                                headers=self._headers(),
                                data=json.dumps(doc),
                            ) as resp:
                                if resp.status in (200, 202, 204):
                                    pushed += 1
                                else:
                                    text = await resp.text()
                                    last_error = (
                                        f"HTTP {resp.status}: {text[:160]}"
                                    )
                        except aiohttp.ClientError as exc:
                            last_error = f"{type(exc).__name__}: {exc}"[:160]
        except CircuitBreakerOpenError as exc:
            return PushResult(
                success=False, pushed_count=pushed,
                error=f"circuit open: {exc}"[:200],
            )

        if pushed == 0:
            return PushResult(
                success=False, pushed_count=0,
                error=last_error or "no events accepted",
            )
        return PushResult(
            success=True, pushed_count=pushed,
            note=(
                f"sent {pushed}/{len(events)} GELF event(s)"
                + (f"; last error: {last_error}" if last_error else "")
            ),
        )

    async def health_check(self) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note="graylog not configured")
        # Send a tiny "argus health-check" GELF doc. Graylog responds
        # 202 Accepted for valid GELF inputs even on empty datasets.
        return await self.push_events([{
            "id": "argus-health-check",
            "title": "argus health check",
            "summary": "graylog connector liveness probe",
            "severity": "low",
            "kind": "health_check",
        }])
