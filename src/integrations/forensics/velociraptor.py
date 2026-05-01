"""Velociraptor remote-forensics wrapper (P3 #3.11).

Velociraptor is the open-source endpoint forensics + IR platform.
Argus drives it through its REST/GUI API to:

  - List the clients (endpoints) currently connected to the server
  - Schedule a *collection* (an artifact run) on a specific client
  - Read the resulting flow when the collection completes (deferred —
    Velociraptor's flow-result download is a separate API surface; v1
    schedules and surfaces the flow-id, the analyst pulls the result
    via the Velociraptor GUI or a follow-up API call)

The full Velociraptor gRPC surface is rich; for v1 we use only the
HTTP/REST API surface that's documented at
``https://docs.velociraptor.app/docs/server_automation/api/``.

Operator config:
  ARGUS_VELOCIRAPTOR_URL    https://velociraptor.example.com:8000
  ARGUS_VELOCIRAPTOR_TOKEN  API token (Server → API tokens)
  ARGUS_VELOCIRAPTOR_VERIFY_SSL  "false" for self-signed
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


# Allowlist of Velociraptor artifacts that ``schedule_collection`` will
# request. Defence-in-depth — Velociraptor server admins can create
# arbitrary custom artifacts (including write-side ones), so we won't
# blindly forward whatever name an Argus admin types. Operators add
# entries here when their VR deployment ships additional read-only
# collection artifacts they want to use from Argus.
_ARTIFACT_ALLOWLIST: frozenset[str] = frozenset({
    # Generic / cross-platform
    "Generic.Client.Info", "Generic.System.Pstree",
    "Generic.System.Users",
    # Windows
    "Windows.System.Pslist", "Windows.System.Pstree",
    "Windows.System.Services", "Windows.System.TaskScheduler",
    "Windows.Network.NetstatEnriched", "Windows.Network.ListeningPorts",
    "Windows.Forensics.Prefetch", "Windows.Forensics.Lnk",
    "Windows.Forensics.Timeline", "Windows.Forensics.Usn",
    "Windows.EventLogs.RDPAuth", "Windows.EventLogs.Powershell",
    "Windows.EventLogs.Sysmon", "Windows.EventLogs.Evtx",
    "Windows.Registry.NTUser", "Windows.Registry.UserAssist",
    "Windows.Sys.AllUsers", "Windows.Sys.Programs",
    "Windows.Sys.Users",
    # Linux
    "Linux.Sys.Pslist", "Linux.Network.Netstat",
    "Linux.Forensics.BashHistory", "Linux.Sys.Users",
    "Linux.System.BashHistory", "Linux.Search.FileFinder",
    "Linux.Sys.LastUserLogin",
    # macOS
    "MacOS.System.Pslist", "MacOS.Network.Netstat",
    "MacOS.Sys.Users",
})


def is_configured() -> bool:
    return bool(
        (os.environ.get("ARGUS_VELOCIRAPTOR_URL") or "").strip()
        and (os.environ.get("ARGUS_VELOCIRAPTOR_TOKEN") or "").strip()
    )


def _config() -> dict[str, Any]:
    return {
        "url": (os.environ.get("ARGUS_VELOCIRAPTOR_URL") or "")
            .strip().rstrip("/"),
        "token": (os.environ.get("ARGUS_VELOCIRAPTOR_TOKEN") or "").strip(),
        "verify_ssl": (os.environ.get("ARGUS_VELOCIRAPTOR_VERIFY_SSL")
                       or "true").strip().lower() not in {"false", "0", "no", "off"},
    }


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


@dataclass
class VelociraptorResult:
    available: bool
    success: bool
    data: Any = None
    note: str | None = None
    error: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "success": self.success,
            "data": self.data,
            "note": self.note,
            "error": self.error,
        }


# ── List clients ────────────────────────────────────────────────────


async def list_clients(*, search: str = "", limit: int = 50) -> VelociraptorResult:
    """Return the clients currently registered on the Velociraptor
    server. ``search`` filters by hostname / OS / labels using
    Velociraptor's standard query syntax (e.g. ``host:web*``)."""
    if not is_configured():
        return VelociraptorResult(
            available=False, success=False,
            note="Velociraptor not configured",
        )
    cfg = _config()
    url = f"{cfg['url']}/api/v1/SearchClients"
    body = {"query": search or "*", "limit": limit, "type": 0}
    breaker = get_breaker("forensics:velociraptor")
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with breaker:
            connector = aiohttp.TCPConnector(ssl=cfg["verify_ssl"])
            async with aiohttp.ClientSession(
                timeout=timeout, connector=connector,
            ) as http:
                async with http.post(
                    url, headers=_headers(cfg["token"]),
                    data=json.dumps(body),
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        return VelociraptorResult(
                            available=True, success=False,
                            error=f"HTTP {resp.status}: {text[:200]}",
                        )
                    try:
                        payload = json.loads(text)
                    except ValueError:
                        payload = {}
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        return VelociraptorResult(
            available=True, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    items = payload.get("items") or payload.get("clients") or []
    clients = []
    for c in items:
        if not isinstance(c, dict):
            continue
        clients.append({
            "client_id": c.get("client_id"),
            "hostname": c.get("os_info", {}).get("hostname")
                or c.get("hostname"),
            "os": c.get("os_info", {}).get("system") or c.get("os"),
            "labels": c.get("labels", []) or [],
            "last_seen_at": c.get("last_seen_at"),
        })
    return VelociraptorResult(
        available=True, success=True,
        data=clients, raw=payload,
    )


# ── Schedule collection ─────────────────────────────────────────────


async def schedule_collection(
    *,
    client_id: str,
    artifact: str,
    parameters: dict[str, str] | None = None,
) -> VelociraptorResult:
    """Schedule an artifact collection (e.g. ``Windows.System.Pslist``)
    on a specific Velociraptor client.

    Returns the new flow_id. The analyst pulls the result via the
    Velociraptor GUI or a follow-up ``GetFlowDetails`` call (not
    wrapped in v1)."""
    if not is_configured():
        return VelociraptorResult(
            available=False, success=False,
            note="Velociraptor not configured",
        )
    if not client_id or not artifact:
        return VelociraptorResult(
            available=True, success=False,
            error="client_id and artifact are required",
        )

    # Velociraptor artifact names use ``Namespace.SubNamespace.Name``.
    # Keep the request to a curated allowlist of read-only collection
    # artifacts — defence-in-depth against an admin who can create
    # write-side custom artifacts on the Velociraptor server.
    if artifact not in _ARTIFACT_ALLOWLIST:
        return VelociraptorResult(
            available=True, success=False,
            error=(
                f"artifact {artifact!r} not in Velociraptor allowlist; "
                "edit _ARTIFACT_ALLOWLIST in velociraptor.py to add it"
            ),
        )

    cfg = _config()
    url = f"{cfg['url']}/api/v1/CollectArtifact"
    body = {
        "client_id": client_id,
        "artifacts": [artifact],
        "parameters": {
            "env": [{"key": k, "value": v} for k, v in (parameters or {}).items()],
        },
    }
    breaker = get_breaker("forensics:velociraptor")
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with breaker:
            connector = aiohttp.TCPConnector(ssl=cfg["verify_ssl"])
            async with aiohttp.ClientSession(
                timeout=timeout, connector=connector,
            ) as http:
                async with http.post(
                    url, headers=_headers(cfg["token"]),
                    data=json.dumps(body),
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        return VelociraptorResult(
                            available=True, success=False,
                            error=f"HTTP {resp.status}: {text[:200]}",
                        )
                    try:
                        payload = json.loads(text)
                    except ValueError:
                        payload = {}
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        return VelociraptorResult(
            available=True, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    flow_id = (payload or {}).get("flow_id") or (payload or {}).get("FlowId")
    return VelociraptorResult(
        available=True, success=bool(flow_id),
        data={"flow_id": flow_id, "client_id": client_id, "artifact": artifact},
        raw=payload,
    )
