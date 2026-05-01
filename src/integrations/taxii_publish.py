"""TAXII 2.1 publish surface (P3 #3.4).

Argus exposes its IOCs as a TAXII 2.1 Collection so customer Splunk
ES / Anomali / ThreatConnect / OpenCTI clients can subscribe to
*Argus-as-a-feed* — RF charges $150K+/yr for the equivalent
"Risk List" subscription; we ship it as a first-class endpoint.

Spec: https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

Argus is single-tenant on-prem in v1 → one Collection per install.
The wrapper is multi-tenant-ready: each Collection's id is derived
from the tenant org id, so adding a second tenant means adding a
second collection with no schema change.

What we serve:

  GET  /taxii2/                          discovery
  GET  /taxii2/api/                      API root info
  GET  /taxii2/api/collections/          collections list
  GET  /taxii2/api/collections/{id}/     collection info
  GET  /taxii2/api/collections/{id}/objects/    STIX 2.1 envelope

Each Argus IOC becomes a STIX 2.1 ``indicator`` SDO. Optional
``?added_after=<ISO>`` query keeps subscribers efficient.

Auth — analyst-gated by default; operators who want anonymous read
access can drop the ``analyst:`` dependency on the route.
"""

from __future__ import annotations

import logging
import re
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# TAXII / STIX constants
_STIX_VERSION = "2.1"
_TAXII_VERSION = "taxii-2.1"
_NAMESPACE = _uuid.UUID("12345678-aaaa-bbbb-cccc-aaaaaaaaaaaa")


def _stable_uuid(*parts: str) -> str:
    """Deterministic UUIDv5 — keeps STIX object ids stable across
    re-runs so subscribers can dedup on id alone."""
    return str(_uuid.uuid5(_NAMESPACE, "|".join(parts)))


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ── IOC → STIX 2.1 indicator pattern ─────────────────────────────────


_IOC_TO_STIX_PATTERN: dict[str, str] = {
    "ipv4":     "[ipv4-addr:value = '{v}']",
    "ipv6":     "[ipv6-addr:value = '{v}']",
    "domain":   "[domain-name:value = '{v}']",
    "url":      "[url:value = '{v}']",
    "md5":      "[file:hashes.MD5 = '{v}']",
    "sha1":     "[file:hashes.'SHA-1' = '{v}']",
    "sha256":   "[file:hashes.'SHA-256' = '{v}']",
    "email":    "[email-addr:value = '{v}']",
    "filename": "[file:name = '{v}']",
}


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    template = _IOC_TO_STIX_PATTERN.get((ioc_type or "").lower())
    if template is None:
        return None
    return template.format(v=value.replace("'", "''"))


def ioc_to_stix_indicator(ioc) -> dict[str, Any] | None:
    """Convert one Argus :class:`IOC` row into a STIX 2.1 indicator
    SDO. Returns ``None`` when ``ioc.ioc_type`` doesn't map to a STIX
    pattern slot (e.g. ``btc_address``); the caller drops it from the
    feed."""
    pattern = _stix_pattern(ioc.ioc_type, ioc.value)
    if pattern is None:
        return None
    sid = "indicator--" + _stable_uuid(
        "indicator", str(ioc.id),
    )
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": _STIX_VERSION,
        "id": sid,
        "created": _iso(ioc.first_seen) or _iso(datetime.now(timezone.utc)),
        "modified": _iso(ioc.last_seen) or _iso(datetime.now(timezone.utc)),
        "valid_from": _iso(ioc.first_seen) or _iso(datetime.now(timezone.utc)),
        "name": f"{ioc.ioc_type}: {ioc.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": _indicator_types_for(ioc),
        "confidence": int(round(float(ioc.confidence or 0.5) * 100)),
        "labels": list(ioc.tags or []),
        "x_argus_ioc_id": str(ioc.id),
        "x_argus_source": "argus",
    }
    return indicator


def _indicator_types_for(ioc) -> list[str]:
    """Map Argus IOC tags / type to the STIX 2.1
    ``indicator-type-ov`` open vocabulary."""
    tags = {t.lower() for t in (ioc.tags or [])}
    out: list[str] = []
    if "malicious" in tags or "malware" in tags:
        out.append("malicious-activity")
    if "phishing" in tags:
        out.append("anomalous-activity")
    if "c2" in tags or "command-and-control" in tags:
        out.append("attribution")
    if not out:
        out.append("anomalous-activity")
    return out


# ── Collection / envelope builders ──────────────────────────────────


def collection_id_for_org(organization_id: _uuid.UUID) -> str:
    """Stable collection id derived from the tenant org id."""
    return _stable_uuid("collection", str(organization_id))


def collection_descriptor(
    *, collection_id: str, organization_id: _uuid.UUID,
    organization_name: str,
) -> dict[str, Any]:
    return {
        "id": collection_id,
        "title": f"Argus indicators — {organization_name}",
        "description": (
            "STIX 2.1 indicators produced by the Argus Threat "
            "Intelligence Platform for this organisation."
        ),
        "can_read": True,
        "can_write": False,
        "media_types": [
            f"application/taxii+json;version={_STIX_VERSION}",
        ],
    }


def discovery_resource(*, base_url: str) -> dict[str, Any]:
    """Top-level TAXII 2.1 discovery payload (RFC §4.1)."""
    return {
        "title": "Argus Threat Intelligence — TAXII 2.1",
        "description": "Argus IOC publish endpoint.",
        "default": f"{base_url.rstrip('/')}/taxii2/api/",
        "api_roots": [f"{base_url.rstrip('/')}/taxii2/api/"],
    }


def api_root_resource() -> dict[str, Any]:
    return {
        "title": "Argus default API root",
        "description": "Argus indicator collections.",
        "versions": [_TAXII_VERSION],
        "max_content_length": 16 * 1024 * 1024,  # 16 MB envelope cap
    }


# ── Object envelope ────────────────────────────────────────────────


_DEFAULT_PAGE_LIMIT = 1000


async def fetch_indicators(
    session: AsyncSession,
    *,
    organization_id: _uuid.UUID,
    added_after: datetime | None = None,
    limit: int = _DEFAULT_PAGE_LIMIT,
) -> list[dict[str, Any]]:
    """Pull this org's IOCs (filtered by ``added_after``) and return a
    list of STIX 2.1 indicator SDOs."""
    from src.models.intel import IOC

    q = select(IOC).where(IOC.last_seen.is_not(None))
    if added_after is not None:
        q = q.where(IOC.last_seen > added_after)
    q = q.order_by(IOC.last_seen.desc()).limit(limit)
    rows = (await session.execute(q)).scalars().all()
    out: list[dict[str, Any]] = []
    for ioc in rows:
        sdo = ioc_to_stix_indicator(ioc)
        if sdo is not None:
            out.append(sdo)
    return out


def envelope(*, indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of indicator SDOs in a TAXII 2.1 Envelope."""
    return {
        "more": False,  # paging not supported in v1; TAXII clients
                         # respect this and fall back to ``added_after``
        "objects": indicators,
    }


_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
)


def parse_added_after(s: str | None) -> datetime | None:
    """Parse the ``added_after`` query parameter per TAXII 2.1 §3.4.

    Accepts RFC 3339 timestamps. Returns ``None`` for empty / invalid
    inputs so the route can decide whether to 400 or treat as
    "no filter"."""
    if not s:
        return None
    s = s.strip()
    if not _ISO_RE.match(s):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
