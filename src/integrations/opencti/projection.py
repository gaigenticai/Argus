"""OpenCTI projection + read-only graph proxy (P2 #2.1).

Argus's PostgreSQL stays system-of-record. OpenCTI is the **graph
projection** layer: every alert / IOC / actor / case Argus produces is
mirrored as STIX 2.1 objects + relationships into a co-deployed
OpenCTI instance. Analysts then drill into the rich relationship view
(observable → attributed-to → actor → uses → technique → mitigated-by
→ defense) inside OpenCTI without leaving the Argus workflow.

The legacy ``client.py`` in this package is the original GraphQL stub
left from an earlier prototype. This module is the v1 projection +
read-only-graph surface.

Operator config (env vars):
  ARGUS_OPENCTI_URL    base URL of the OpenCTI server
  ARGUS_OPENCTI_TOKEN  API token from the OpenCTI user profile

Without those set the wrappers no-op gracefully.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Config ────────────────────────────────────────────────────────


_URL_ENV = "ARGUS_OPENCTI_URL"
_TOKEN_ENV = "ARGUS_OPENCTI_TOKEN"


def is_configured() -> bool:
    return bool((os.environ.get(_URL_ENV) or "").strip()
                and (os.environ.get(_TOKEN_ENV) or "").strip())


_client: Any | None = None


def get_client() -> Any | None:
    """Return a configured ``OpenCTIApiClient`` (cached), or ``None``
    when the deployment isn't configured / pycti isn't installed."""
    global _client
    if _client is not None:
        return _client
    if not is_configured():
        return None
    try:
        from pycti import OpenCTIApiClient
    except ImportError:
        logger.warning("[opencti] pycti not installed; integration disabled")
        return None
    try:
        _client = OpenCTIApiClient(
            url=os.environ[_URL_ENV].strip(),
            token=os.environ[_TOKEN_ENV].strip(),
            log_level="warning",
        )
    except Exception as exc:  # noqa: BLE001 — handshake stays soft
        logger.warning("[opencti] client construction failed: %s", exc)
        return None
    return _client


def reset_client() -> None:
    global _client
    _client = None


# ── Result types ─────────────────────────────────────────────────


@dataclass
class ProjectionResult:
    success: bool
    stix_id: str | None
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success, "stix_id": self.stix_id,
            "note": self.note, "error": self.error,
        }


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "label": self.label,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "target": self.target,
            "relationship_type": self.relationship_type,
        }


@dataclass
class Neighbourhood:
    root: GraphNode | None
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root.to_dict() if self.root else None,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "note": self.note,
        }


# ── IOC ↔ STIX type mapping ─────────────────────────────────────


_IOC_TO_STIX_PATTERN: dict[str, str] = {
    "ipv4":     "[ipv4-addr:value = '{v}']",
    "ip":       "[ipv4-addr:value = '{v}']",
    "ipv6":     "[ipv6-addr:value = '{v}']",
    "domain":   "[domain-name:value = '{v}']",
    "url":      "[url:value = '{v}']",
    "md5":      "[file:hashes.MD5 = '{v}']",
    "sha1":     "[file:hashes.'SHA-1' = '{v}']",
    "sha256":   "[file:hashes.'SHA-256' = '{v}']",
    "email":    "[email-addr:value = '{v}']",
    "filename": "[file:name = '{v}']",
}


def _stix_pattern_for(ioc_type: str, value: str) -> str | None:
    template = _IOC_TO_STIX_PATTERN.get((ioc_type or "").lower())
    if not template:
        return None
    return template.format(v=value.replace("'", "''"))


def _main_observable_type(ioc_type: str) -> str:
    return {
        "ipv4": "IPv4-Addr", "ip": "IPv4-Addr",
        "ipv6": "IPv6-Addr",
        "domain": "Domain-Name",
        "url": "Url",
        "md5": "StixFile", "sha1": "StixFile", "sha256": "StixFile",
        "email": "Email-Addr",
        "filename": "StixFile",
    }.get((ioc_type or "").lower(), "StixFile")


# ── Projection ──────────────────────────────────────────────────


def project_ioc(
    *, ioc_type: str, value: str, confidence: int = 75,
    actor_alias: str | None = None,
) -> ProjectionResult:
    client = get_client()
    if client is None:
        return ProjectionResult(success=False, stix_id=None,
                                note="OpenCTI not configured")
    pattern = _stix_pattern_for(ioc_type, value)
    if pattern is None:
        return ProjectionResult(
            success=False, stix_id=None,
            error=f"unsupported ioc_type {ioc_type!r}",
        )
    try:
        indicator = client.indicator.create(
            pattern=pattern, pattern_type="stix",
            x_opencti_main_observable_type=_main_observable_type(ioc_type),
            confidence=confidence,
            description=f"Argus-projected IOC: {value}",
            valid_from=datetime.now(timezone.utc).isoformat(),
        )
        stix_id = (indicator or {}).get("standard_id") if isinstance(
            indicator, dict
        ) else None

        if actor_alias and stix_id:
            try:
                actor = client.threat_actor.create(name=actor_alias)
                actor_id = (actor or {}).get("standard_id") if isinstance(
                    actor, dict
                ) else None
                if actor_id:
                    client.stix_core_relationship.create(
                        fromId=stix_id, toId=actor_id,
                        relationship_type="indicates",
                    )
            except Exception as exc:  # noqa: BLE001 — best-effort
                logger.warning("[opencti] indicates-rel upsert failed: %s", exc)
        return ProjectionResult(success=True, stix_id=stix_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[opencti] indicator project failed: %s", exc)
        return ProjectionResult(
            success=False, stix_id=None,
            error=f"{type(exc).__name__}: {exc}"[:300],
        )


def project_actor(
    *, primary_alias: str, aliases: list[str] | None = None,
    description: str | None = None,
) -> ProjectionResult:
    client = get_client()
    if client is None:
        return ProjectionResult(success=False, stix_id=None,
                                note="OpenCTI not configured")
    try:
        actor = client.threat_actor.create(
            name=primary_alias,
            aliases=aliases or [],
            description=description or "",
        )
        stix_id = (actor or {}).get("standard_id") if isinstance(
            actor, dict
        ) else None
        return ProjectionResult(success=True, stix_id=stix_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[opencti] threat-actor project failed: %s", exc)
        return ProjectionResult(
            success=False, stix_id=None,
            error=f"{type(exc).__name__}: {exc}"[:300],
        )


def _confidence_from_severity(severity: str | None) -> int:
    return {"critical": 90, "high": 80, "medium": 60,
            "low": 40, "info": 20}.get((severity or "").lower(), 50)


def project_alert(
    *, alert_id: str, title: str, summary: str | None = None,
    severity: str | None = None, category: str | None = None,
) -> ProjectionResult:
    client = get_client()
    if client is None:
        return ProjectionResult(success=False, stix_id=None,
                                note="OpenCTI not configured")
    try:
        note = client.note.create(
            abstract=title,
            content=summary or title,
            confidence=_confidence_from_severity(severity),
            x_opencti_argus_alert_id=alert_id,
            x_opencti_argus_category=category,
        )
        stix_id = (note or {}).get("standard_id") if isinstance(
            note, dict
        ) else None
        return ProjectionResult(success=True, stix_id=stix_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[opencti] alert project failed: %s", exc)
        return ProjectionResult(
            success=False, stix_id=None,
            error=f"{type(exc).__name__}: {exc}"[:300],
        )


def project_case(
    *, case_id: str, title: str, summary: str | None = None,
    severity: str | None = None,
) -> ProjectionResult:
    client = get_client()
    if client is None:
        return ProjectionResult(success=False, stix_id=None,
                                note="OpenCTI not configured")
    try:
        case = client.case_incident.create(
            name=title,
            description=summary or title,
            severity=(severity or "medium").lower(),
            x_opencti_argus_case_id=case_id,
        )
        stix_id = (case or {}).get("standard_id") if isinstance(
            case, dict
        ) else None
        return ProjectionResult(success=True, stix_id=stix_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[opencti] case project failed: %s", exc)
        return ProjectionResult(
            success=False, stix_id=None,
            error=f"{type(exc).__name__}: {exc}"[:300],
        )


# ── Read-only graph proxy ───────────────────────────────────────


def fetch_neighbourhood(
    *, stix_id: str, depth: int = 1, limit: int = 50,
) -> Neighbourhood:
    client = get_client()
    if client is None:
        return Neighbourhood(
            root=None, nodes=[], edges=[],
            note="OpenCTI not configured",
        )
    try:
        relationships = client.stix_core_relationship.list(
            elementId=stix_id, first=limit,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[opencti] neighbourhood fetch failed: %s", exc)
        return Neighbourhood(
            root=None, nodes=[], edges=[],
            note=f"fetch failed: {exc}",
        )

    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def _node_from(obj: dict) -> GraphNode | None:
        if not isinstance(obj, dict):
            return None
        sid = obj.get("standard_id") or obj.get("id")
        if not sid:
            return None
        ent_type = (obj.get("entity_type") or obj.get("type")
                    or "Object").lower()
        label = (obj.get("name") or obj.get("value")
                 or obj.get("observable_value") or sid)
        return GraphNode(id=sid, type=ent_type, label=str(label))

    for rel in relationships or []:
        if not isinstance(rel, dict):
            continue
        rt = rel.get("relationship_type") or "related-to"
        n_from = _node_from(rel.get("from") or {})
        n_to = _node_from(rel.get("to") or {})
        if n_from is None or n_to is None:
            continue
        nodes.setdefault(n_from.id, n_from)
        nodes.setdefault(n_to.id, n_to)
        edges.append(GraphEdge(
            source=n_from.id, target=n_to.id, relationship_type=rt,
        ))

    root = nodes.get(stix_id)
    return Neighbourhood(
        root=root, nodes=list(nodes.values()), edges=edges,
    )
