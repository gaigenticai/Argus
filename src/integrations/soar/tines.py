"""Tines connector (P3 #3.7).

Pushes Argus alerts to a Tines *receiver* webhook. Tines doesn't
require API auth on its public webhooks — the URL itself is the
secret — so this connector is the simplest of the three.

Operator config:
  ARGUS_TINES_WEBHOOK_URL   the receiver URL from the Tines story
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


class TinesConnector(SoarConnector):
    name = "tines"
    label = "Tines"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_TINES_WEBHOOK_URL") or "").strip()

    def is_configured(self) -> bool:
        return bool(self._url)

    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(success=False, note="tines not configured")
        if not events:
            return SoarPushResult(success=True, pushed_count=0,
                                   note="no events to push")

        breaker = get_breaker("soar:tines")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        self._url,
                        json={"source": "argus", "events": events},
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SoarPushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SoarPushResult(
                            success=True, pushed_count=len(events),
                            raw={"http_status": resp.status},
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SoarPushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )

    async def health_check(self) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(success=False, note="tines not configured")
        return await self.push_events([{"id": "argus-health-check",
                                          "kind": "health_check"}])
