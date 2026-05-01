"""MITRE Caldera REST client (P3 #3.5).

Caldera (https://github.com/mitre/caldera) drives end-to-end adversary
emulation: an "operation" runs an "adversary profile" (a tree of
abilities mapped to ATT&CK techniques) against agents on customer
endpoints. Argus invokes Caldera via its REST API so the validation
loop can chain Caldera operations with Atomic Red Team tests and
detection telemetry from EDR / SIEM.

API surface used (Caldera 5.x):
  GET  /api/v2/abilities                list abilities
  GET  /api/v2/operations               list operations
  POST /api/v2/operations               start an operation
  GET  /api/v2/operations/{id}          fetch operation status

Auth: ``KEY: <api_key>`` header (Caldera's bespoke header — not Bearer).

Operator config:
  ARGUS_CALDERA_URL       e.g. https://caldera.internal:8888
  ARGUS_CALDERA_API_KEY   value of the ``red`` user's API key
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

logger = logging.getLogger(__name__)


@dataclass
class CalderaResult:
    success: bool
    data: Any = None
    error: str | None = None
    note: str | None = None
    raw: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "note": self.note,
        }


def _base() -> str:
    return (os.environ.get("ARGUS_CALDERA_URL") or "").strip().rstrip("/")


def _key() -> str:
    return (os.environ.get("ARGUS_CALDERA_API_KEY") or "").strip()


def is_configured() -> bool:
    return bool(_base() and _key())


def _headers() -> dict[str, str]:
    return {
        "KEY": _key(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def _request(method: str, path: str, *,
                    params: dict[str, Any] | None = None,
                    body: dict[str, Any] | None = None,
                    timeout: int = 30) -> CalderaResult:
    if not is_configured():
        return CalderaResult(
            success=False,
            note=("caldera not configured — set ARGUS_CALDERA_URL and "
                  "ARGUS_CALDERA_API_KEY"),
        )
    url = f"{_base()}{path}"
    breaker = get_breaker("emulation:caldera")
    t = aiohttp.ClientTimeout(total=timeout)
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=t) as http:
                kwargs: dict[str, Any] = {"headers": _headers()}
                if params:
                    kwargs["params"] = params
                if body is not None:
                    kwargs["data"] = json.dumps(body)
                async with http.request(method, url, **kwargs) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        return CalderaResult(
                            success=False,
                            error=f"HTTP {resp.status}: {text[:200]}",
                        )
                    try:
                        parsed = json.loads(text) if text else None
                    except ValueError:
                        parsed = text
                    return CalderaResult(success=True, data=parsed, raw=parsed)
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        return CalderaResult(
            success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )


async def list_abilities(*, tactic: str | None = None) -> CalderaResult:
    """List Caldera abilities, optionally filtered by tactic.

    Each ability is mapped to one ATT&CK technique via its
    ``technique_id`` field — that's what powers coverage scoring.
    """
    params = {"tactic": tactic} if tactic else None
    return await _request("GET", "/api/v2/abilities", params=params)


async def list_operations() -> CalderaResult:
    return await _request("GET", "/api/v2/operations")


async def start_operation(
    *, adversary_id: str, group: str = "red",
    name: str | None = None, planner: str = "atomic",
    auto_close: bool = True,
) -> CalderaResult:
    """Kick off a Caldera operation against ``group`` using
    ``adversary_id``.

    The default ``planner=atomic`` means agents execute abilities
    sequentially, which is what we want for deterministic coverage
    scoring. ``auto_close`` makes the operation finish when the planner
    runs out of abilities to execute, instead of staying open forever.
    """
    body: dict[str, Any] = {
        "name": name or f"argus-{adversary_id[:8]}",
        "adversary": {"adversary_id": adversary_id},
        "group": group,
        "planner": {"id": planner},
        "auto_close": bool(auto_close),
    }
    return await _request("POST", "/api/v2/operations", body=body)


async def operation_status(operation_id: str) -> CalderaResult:
    return await _request("GET", f"/api/v2/operations/{operation_id}")


async def health_check() -> CalderaResult:
    if not is_configured():
        return CalderaResult(success=False, note="caldera not configured")
    r = await _request("GET", "/api/v2/abilities", timeout=10)
    if r.success:
        return CalderaResult(
            success=True, note="caldera /api/v2/abilities reachable",
        )
    return r
