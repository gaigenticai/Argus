"""TAXII 2.1 publish API (P3 #3.4).

Mounted at ``/taxii2/*`` (NO ``/api/v1`` prefix — TAXII clients expect
the canonical TAXII 2.1 URL shape per RFC 8.4 / 8.5).

Subscribers (Splunk ES, Anomali, ThreatConnect, OpenCTI) point their
``Discovery URL`` at ``https://argus.example.com/taxii2/`` and use the
analyst's bearer token for authentication.

**Content-negotiation** (TAXII 2.1 §1.6.6) is enforced explicitly:

  - Server responses set ``Content-Type: application/taxii+json;
    version=2.1``. The objects endpoint additionally honours
    ``application/stix+json;version=2.1`` when the client requests it
    via the ``Accept`` header.
  - Clients sending an explicit ``Accept`` of an incompatible media
    type get **406 Not Acceptable** rather than silent JSON.
  - The objects endpoint returns ``X-TAXII-Date-Added-First`` and
    ``X-TAXII-Date-Added-Last`` headers so subscribers can paginate
    via ``?added_after`` without parsing the body.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.core.tenant import get_system_org_id
from src.integrations.taxii_publish import (
    api_root_resource,
    collection_descriptor,
    collection_id_for_org,
    discovery_resource,
    envelope,
    fetch_indicators,
    parse_added_after,
)
from src.models.threat import Organization
from src.storage.database import get_session

logger = logging.getLogger(__name__)


# TAXII routes don't sit under /api/v1 — TAXII clients expect a flat
# /taxii2/ URL prefix.
router = APIRouter(prefix="/taxii2", tags=["TAXII"])


_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
_STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


# ── Content-negotiation helpers (TAXII 2.1 §1.6.6) ──────────────────


_ACCEPT_TOKEN_RE = re.compile(r"\s*([^,;]+)(?:;[^,]*)?")


def _parse_accept(header: str | None) -> list[str]:
    """Return the lowercased media-types named in an Accept header.

    Strips parameters / weights — we only need the type token to decide
    compatibility. Empty or missing header → empty list, which the
    validators treat as "client accepts anything"."""
    if not header:
        return []
    out: list[str] = []
    for part in header.split(","):
        token = part.split(";")[0].strip().lower()
        if token:
            out.append(token)
    return out


_ACCEPTABLE_TAXII = {
    "application/taxii+json",
    "application/json",
    "*/*",
    "application/*",
}
_ACCEPTABLE_STIX = _ACCEPTABLE_TAXII | {"application/stix+json"}


def _is_taxii_acceptable(types: list[str]) -> bool:
    if not types:
        return True
    return any(t in _ACCEPTABLE_TAXII for t in types)


def _is_stix_acceptable(types: list[str]) -> bool:
    if not types:
        return True
    return any(t in _ACCEPTABLE_STIX for t in types)


def _negotiate_taxii(accept: str | None = Header(default=None)) -> None:
    if not _is_taxii_acceptable(_parse_accept(accept)):
        raise HTTPException(
            406,
            f"Not Acceptable — TAXII 2.1 endpoints serve "
            f"{_TAXII_MEDIA_TYPE!s}. Accept header was {accept!r}.",
        )


def _negotiate_objects(
    accept: str | None = Header(default=None),
) -> str:
    """Return the media-type the response body should advertise.

    Objects endpoint accepts both TAXII envelope and bare STIX bundle
    media-types (TAXII 2.1 §5.4); we still default to TAXII envelope
    because the body shape *is* an envelope."""
    types = _parse_accept(accept)
    if not _is_stix_acceptable(types):
        raise HTTPException(
            406,
            f"Not Acceptable — objects endpoint serves "
            f"{_TAXII_MEDIA_TYPE} or {_STIX_MEDIA_TYPE}. "
            f"Accept header was {accept!r}.",
        )
    if "application/stix+json" in types and (
        "application/taxii+json" not in types
    ):
        return _STIX_MEDIA_TYPE
    return _TAXII_MEDIA_TYPE


def _taxii_response(
    body: dict[str, Any], *,
    media_type: str = _TAXII_MEDIA_TYPE,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build a JSONResponse with the TAXII 2.1 Content-Type."""
    return JSONResponse(content=body, media_type=media_type,
                          headers=headers or {})


def _base_url(request: Request) -> str:
    """Reconstruct ``scheme://host[:port]`` for discovery payloads."""
    return f"{request.url.scheme}://{request.url.netloc}"


# ── Routes ─────────────────────────────────────────────────────────


@router.get("/")
async def taxii_discovery(
    request: Request,
    analyst: AnalystUser = None,  # noqa: B008
    _accept: None = Depends(_negotiate_taxii),
):
    """TAXII 2.1 discovery resource (§4.1)."""
    return _taxii_response(discovery_resource(base_url=_base_url(request)))


@router.get("/api/")
async def taxii_api_root(
    analyst: AnalystUser = None,  # noqa: B008
    _accept: None = Depends(_negotiate_taxii),
):
    """API root resource (§4.2)."""
    return _taxii_response(api_root_resource())


@router.get("/api/collections/")
async def taxii_collections_list(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
    _accept: None = Depends(_negotiate_taxii),
):
    """List collections — one per tenant org. Argus is single-tenant
    on-prem so this returns exactly one row in v1."""
    org_id = await get_system_org_id(db)
    org = await db.get(Organization, org_id)
    cid = collection_id_for_org(org_id)
    return _taxii_response({
        "collections": [
            collection_descriptor(
                collection_id=cid, organization_id=org_id,
                organization_name=org.name if org else "Argus",
            ),
        ],
    })


@router.get("/api/collections/{collection_id}/")
async def taxii_collection_info(
    collection_id: str,
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
    _accept: None = Depends(_negotiate_taxii),
):
    """Single-collection descriptor (§5.2)."""
    org_id = await get_system_org_id(db)
    expected = collection_id_for_org(org_id)
    if collection_id != expected:
        raise HTTPException(404, "collection not found")
    org = await db.get(Organization, org_id)
    return _taxii_response(collection_descriptor(
        collection_id=expected, organization_id=org_id,
        organization_name=org.name if org else "Argus",
    ))


@router.get("/api/collections/{collection_id}/objects/")
async def taxii_collection_objects(
    collection_id: str,
    analyst: AnalystUser = None,  # noqa: B008
    added_after: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
    db: AsyncSession = Depends(get_session),
    media_type: str = Depends(_negotiate_objects),
):
    """Stream the collection's STIX 2.1 indicators (§5.4).

    ``?added_after=<RFC 3339>`` lets subscribers fetch only the diff
    since their last poll. ``limit`` caps the envelope size. The
    response advertises ``X-TAXII-Date-Added-First/Last`` so clients
    can paginate without reading the body.
    """
    org_id = await get_system_org_id(db)
    expected = collection_id_for_org(org_id)
    if collection_id != expected:
        raise HTTPException(404, "collection not found")

    after = parse_added_after(added_after)
    if added_after and after is None:
        raise HTTPException(400, "invalid added_after — must be RFC 3339")

    indicators = await fetch_indicators(
        db, organization_id=org_id,
        added_after=after, limit=limit,
    )
    headers: dict[str, str] = {}
    if indicators:
        # Indicators are returned newest-first (see fetch_indicators).
        last_dt = _extract_added(indicators[0])
        first_dt = _extract_added(indicators[-1])
        if first_dt:
            headers["X-TAXII-Date-Added-First"] = first_dt
        if last_dt:
            headers["X-TAXII-Date-Added-Last"] = last_dt
    return _taxii_response(
        envelope(indicators=indicators),
        media_type=media_type,
        headers=headers,
    )


def _extract_added(indicator: dict[str, Any]) -> str | None:
    """Pull the indicator's added-to-collection timestamp.

    STIX ``modified`` is the closest analogue we have to TAXII's
    ``date_added`` — Argus stores ``last_seen`` as ``modified`` in
    ``ioc_to_stix_indicator``. Falls back to ``created`` if missing."""
    for key in ("modified", "created"):
        v = indicator.get(key)
        if isinstance(v, str) and v:
            return v
    return None
