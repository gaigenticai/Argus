"""TAXII 2.1 publish API (P3 #3.4).

Mounted at ``/taxii2/*`` (NO ``/api/v1`` prefix — TAXII clients expect
the canonical TAXII 2.1 URL shape per RFC 8.4 / 8.5).

Subscribers (Splunk ES, Anomali, ThreatConnect, OpenCTI) point their
``Discovery URL`` at ``https://argus.example.com/taxii2/`` and use the
analyst's bearer token for authentication.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
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


def _base_url(request: Request) -> str:
    """Reconstruct ``scheme://host[:port]`` for discovery payloads."""
    return f"{request.url.scheme}://{request.url.netloc}"


@router.get("/")
async def taxii_discovery(
    request: Request,
    analyst: AnalystUser = None,  # noqa: B008
):
    """TAXII 2.1 discovery resource (RFC §4.1)."""
    return discovery_resource(base_url=_base_url(request))


@router.get("/api/")
async def taxii_api_root(
    analyst: AnalystUser = None,  # noqa: B008
):
    """API root resource (RFC §4.2)."""
    return api_root_resource()


@router.get("/api/collections/")
async def taxii_collections_list(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """List collections — one per tenant org. Argus is single-tenant
    on-prem so this returns exactly one row in v1."""
    org_id = await get_system_org_id(db)
    org = await db.get(Organization, org_id)
    cid = collection_id_for_org(org_id)
    return {
        "collections": [
            collection_descriptor(
                collection_id=cid, organization_id=org_id,
                organization_name=org.name if org else "Argus",
            ),
        ],
    }


@router.get("/api/collections/{collection_id}/")
async def taxii_collection_info(
    collection_id: str,
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Single-collection descriptor (RFC §5.2)."""
    org_id = await get_system_org_id(db)
    expected = collection_id_for_org(org_id)
    if collection_id != expected:
        raise HTTPException(404, "collection not found")
    org = await db.get(Organization, org_id)
    return collection_descriptor(
        collection_id=expected, organization_id=org_id,
        organization_name=org.name if org else "Argus",
    )


@router.get("/api/collections/{collection_id}/objects/")
async def taxii_collection_objects(
    collection_id: str,
    analyst: AnalystUser = None,  # noqa: B008
    added_after: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
    db: AsyncSession = Depends(get_session),
):
    """Stream the collection's STIX 2.1 indicators (RFC §5.3).

    ``?added_after=<RFC 3339>`` lets subscribers fetch only the diff
    since their last poll. ``limit`` caps the envelope size; the
    response sets ``more=false`` because v1 doesn't paginate further
    — clients should call back with a tighter ``added_after``.
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
    return envelope(indicators=indicators)
