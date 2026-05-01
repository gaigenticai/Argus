"""PyMISP integration (P2 #2.11).

Argus consumes — and (later) shares to — MISP servers via the public
``pymisp`` client. We **don't** bundle the AGPL MISP server itself;
operators run their own MISP (or use CIRCL's public instance).

Supported operations in v1:

  :func:`fetch_recent_events`        Pull events updated in the last
                                     N days, optionally filtered by tag
                                     (e.g. ``tlp:white`` or
                                     ``misp-galaxy:threat-actor="APT34"``).
  :func:`fetch_event_attributes`     Pull every attribute for one event
                                     UUID — feeds the IOC pivot pages
                                     and ``investigation_agent``.
  :func:`fetch_galaxy_clusters`      Pull a galaxy (e.g.
                                     ``mitre-attack-pattern``,
                                     ``threat-actor``).

Operator config (via env vars or settings):
  ARGUS_MISP_URL          base URL of the MISP server, e.g.
                          https://misp.example.org
  ARGUS_MISP_KEY          authkey from the MISP user profile
  ARGUS_MISP_VERIFY_SSL   "true"/"false" — defaults to true; set
                          to false only for self-signed lab MISPs

Without those env vars the wrapper returns ``None`` from
:func:`get_client` and the high-level functions return empty lists —
the dashboard renders the panel with an "MISP not configured" hint.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Config ─────────────────────────────────────────────────────────


_URL_ENV = "ARGUS_MISP_URL"
_KEY_ENV = "ARGUS_MISP_KEY"
_VERIFY_ENV = "ARGUS_MISP_VERIFY_SSL"


def is_configured() -> bool:
    return bool((os.environ.get(_URL_ENV) or "").strip()
                and (os.environ.get(_KEY_ENV) or "").strip())


def _verify_ssl() -> bool:
    return (os.environ.get(_VERIFY_ENV) or "true").strip().lower() not in {
        "false", "0", "no", "off",
    }


def get_client() -> Any | None:
    """Return a configured ``PyMISP`` client, or ``None`` if MISP is
    not set up in this deployment.

    Cached at module level so we don't pay the MISP TLS handshake on
    every call. The client is thread-safe per pymisp's docs."""
    global _client
    if _client is not None:
        return _client
    if not is_configured():
        return None
    try:
        from pymisp import PyMISP
    except ImportError:
        logger.warning("[misp] pymisp not installed; integration disabled")
        return None
    try:
        _client = PyMISP(
            url=os.environ[_URL_ENV].strip(),
            key=os.environ[_KEY_ENV].strip(),
            ssl=_verify_ssl(),
            tool="argus-threat-intelligence",
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001 — handshake errors stay soft
        logger.warning("[misp] failed to construct PyMISP client: %s", exc)
        return None
    return _client


_client: Any | None = None


def reset_client() -> None:
    """Clear the cached client. Used by tests + by the operator after
    rotating the MISP authkey via the settings page."""
    global _client
    _client = None


# ── Result types ───────────────────────────────────────────────────


@dataclass
class MispEvent:
    uuid: str
    info: str
    threat_level_id: str | None
    date: str | None
    tags: list[str]
    attribute_count: int
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid, "info": self.info,
            "threat_level_id": self.threat_level_id,
            "date": self.date, "tags": self.tags,
            "attribute_count": self.attribute_count,
        }


@dataclass
class MispAttribute:
    uuid: str
    type: str
    category: str | None
    value: str
    comment: str | None
    to_ids: bool
    tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid, "type": self.type,
            "category": self.category, "value": self.value,
            "comment": self.comment, "to_ids": self.to_ids,
            "tags": self.tags,
        }


@dataclass
class MispGalaxyCluster:
    uuid: str
    name: str
    galaxy_type: str
    description: str | None
    tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid, "name": self.name,
            "galaxy_type": self.galaxy_type,
            "description": self.description, "tags": self.tags,
        }


# ── Public API ─────────────────────────────────────────────────────


def fetch_recent_events(
    days: int = 7, *, tag: str | None = None, limit: int = 50,
) -> list[MispEvent]:
    """Return MISP events updated in the last ``days``.

    ``tag`` filters to a specific MISP tag (e.g.
    ``misp-galaxy:threat-actor="APT34"``). ``limit`` caps the returned
    events; defaults to a small number so the dashboard panel renders
    quickly even against a multi-thousand-event MISP.
    """
    client = get_client()
    if client is None:
        return []
    try:
        kwargs: dict[str, Any] = {
            "limit": limit, "page": 1, "pythonify": True,
            "metadata": True,
        }
        if tag:
            kwargs["tags"] = tag
        if days and days > 0:
            kwargs["last"] = f"{days}d"
        events = client.search(controller="events", **kwargs)
    except Exception as exc:  # noqa: BLE001 — surface upstream errors uniformly
        logger.warning("[misp] events search failed: %s", exc)
        return []

    out: list[MispEvent] = []
    for ev in events or []:
        # pymisp returns either a dict-shaped object or an MISPEvent;
        # both expose ``to_dict()``.
        d = _to_dict(ev)
        meta = d.get("Event", d) if isinstance(d, dict) else {}
        if not isinstance(meta, dict):
            continue
        tags = [t.get("name") for t in (meta.get("Tag") or [])
                if isinstance(t, dict) and t.get("name")]
        out.append(MispEvent(
            uuid=str(meta.get("uuid") or ""),
            info=str(meta.get("info") or "").strip(),
            threat_level_id=str(meta.get("threat_level_id") or "") or None,
            date=str(meta.get("date") or "") or None,
            tags=tags,
            attribute_count=int(meta.get("attribute_count") or 0),
            raw=meta,
        ))
    return out


def fetch_event_attributes(
    event_uuid: str, *, to_ids_only: bool = True,
) -> list[MispAttribute]:
    """Return every attribute (IOC) on a MISP event."""
    client = get_client()
    if client is None:
        return []
    try:
        ev = client.get_event(event_uuid, pythonify=True)
        d = _to_dict(ev)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[misp] get_event failed: %s", exc)
        return []
    meta = d.get("Event", d) if isinstance(d, dict) else {}
    if not isinstance(meta, dict):
        return []
    attrs = meta.get("Attribute") or []
    out: list[MispAttribute] = []
    for a in attrs:
        if not isinstance(a, dict):
            continue
        if to_ids_only and not a.get("to_ids"):
            continue
        tags = [t.get("name") for t in (a.get("Tag") or [])
                if isinstance(t, dict) and t.get("name")]
        out.append(MispAttribute(
            uuid=str(a.get("uuid") or ""),
            type=str(a.get("type") or ""),
            category=str(a.get("category") or "") or None,
            value=str(a.get("value") or ""),
            comment=str(a.get("comment") or "") or None,
            to_ids=bool(a.get("to_ids")),
            tags=tags,
        ))
    return out


def fetch_galaxy_clusters(
    galaxy_type: str = "threat-actor", *, limit: int = 100,
) -> list[MispGalaxyCluster]:
    """Pull MISP galaxy clusters of a given type.

    Common types: ``threat-actor`` · ``mitre-attack-pattern`` ·
    ``ransomware`` · ``country``.
    """
    client = get_client()
    if client is None:
        return []
    try:
        clusters = client.search_galaxy_clusters(
            galaxy=galaxy_type, pythonify=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[misp] galaxy_clusters failed: %s", exc)
        return []
    out: list[MispGalaxyCluster] = []
    for c in (clusters or [])[:limit]:
        d = _to_dict(c)
        meta = d.get("GalaxyCluster", d) if isinstance(d, dict) else {}
        if not isinstance(meta, dict):
            continue
        tags = []
        out.append(MispGalaxyCluster(
            uuid=str(meta.get("uuid") or ""),
            name=str(meta.get("value") or meta.get("name") or "").strip(),
            galaxy_type=galaxy_type,
            description=str(meta.get("description") or "") or None,
            tags=tags,
        ))
    return out


# ── Helpers ────────────────────────────────────────────────────────


def _to_dict(obj: Any) -> dict | None:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        try:
            return obj.to_dict()  # type: ignore[no-any-return]
        except Exception:  # noqa: BLE001
            pass
    return None
