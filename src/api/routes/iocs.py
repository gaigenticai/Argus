"""IOC management and export endpoints."""

from __future__ import annotations


import csv
import io
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.models.intel import IOC, IOCType, ThreatActor
from src.storage.database import get_session

router = APIRouter(prefix="/iocs", tags=["Threat Intelligence"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class IOCResponse(BaseModel):
    id: uuid.UUID
    ioc_type: str
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    sighting_count: int
    tags: list[str] | None
    context: dict | None
    source_alert_id: uuid.UUID | None
    source_raw_intel_id: uuid.UUID | None
    threat_actor_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class IOCDetail(IOCResponse):
    """Extended IOC with linked actor info."""
    actor_alias: str | None = None


class IOCStats(BaseModel):
    total: int
    by_type: dict[str, int]
    top_iocs: list[dict]


class BulkSearchRequest(BaseModel):
    values: list[str]


class BulkSearchResult(BaseModel):
    value: str
    found: bool
    ioc: IOCResponse | None = None


# ---------------------------------------------------------------------------
# STIX 2.1 generation helpers
# ---------------------------------------------------------------------------

_ARGUS_IDENTITY_ID = "identity--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


def _stix_identity() -> dict:
    """Argus platform identity SDO."""
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _ARGUS_IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Argus Threat Intelligence Platform",
        "identity_class": "system",
    }


def _ioc_to_stix_indicator(ioc: IOC) -> dict:
    """Convert an IOC model to a STIX 2.1 indicator SDO."""
    pattern = _ioc_to_stix_pattern(ioc.ioc_type, ioc.value)
    indicator_id = f"indicator--{ioc.id}"

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": ioc.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": (ioc.updated_at or ioc.created_at).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": f"{ioc.ioc_type}: {ioc.value}",
        "description": f"IOC observed {ioc.sighting_count} time(s). Confidence: {ioc.confidence}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "indicator_types": [_ioc_type_to_indicator_type(ioc.ioc_type)],
        "confidence": int(ioc.confidence * 100),
        "created_by_ref": _ARGUS_IDENTITY_ID,
    }


def _ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
    """Build a valid STIX 2.1 pattern string for an IOC."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "cidr": f"[ipv4-addr:value = '{escaped}']",
        "domain": f"[domain-name:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
        "email": f"[email-addr:value = '{escaped}']",
        "md5": f"[file:hashes.MD5 = '{escaped}']",
        "sha1": f"[file:hashes.'SHA-1' = '{escaped}']",
        "sha256": f"[file:hashes.'SHA-256' = '{escaped}']",
        "btc_address": f"[artifact:payload_bin = '{escaped}']",
        "xmr_address": f"[artifact:payload_bin = '{escaped}']",
        "cve": f"[vulnerability:name = '{escaped}']",
        "ja3": f"[network-traffic:extensions.'http-request-ext'.request_header.'JA3' = '{escaped}']",
        "filename": f"[file:name = '{escaped}']",
        "registry_key": f"[windows-registry-key:key = '{escaped}']",
        "mutex": f"[mutex:name = '{escaped}']",
        "user_agent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{escaped}']",
        "asn": f"[autonomous-system:number = {value}]",
    }
    return mapping.get(ioc_type, f"[artifact:payload_bin = '{escaped}']")


def _ioc_type_to_indicator_type(ioc_type: str) -> str:
    """Map IOC type to STIX indicator_types vocabulary."""
    mapping = {
        "ipv4": "malicious-activity",
        "ipv6": "malicious-activity",
        "cidr": "malicious-activity",
        "domain": "malicious-activity",
        "url": "malicious-activity",
        "email": "malicious-activity",
        "md5": "malicious-activity",
        "sha1": "malicious-activity",
        "sha256": "malicious-activity",
        "btc_address": "malicious-activity",
        "xmr_address": "malicious-activity",
        "cve": "anomalous-activity",
        "ja3": "anomalous-activity",
        "filename": "malicious-activity",
    }
    return mapping.get(ioc_type, "unknown")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=IOCStats)
async def ioc_stats(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """IOC statistics: count by type, top IOCs by sighting count."""
    # Total
    total_q = select(func.count()).select_from(IOC)
    total = (await db.execute(total_q)).scalar() or 0

    # By type
    type_q = select(IOC.ioc_type, func.count()).group_by(IOC.ioc_type)
    type_result = await db.execute(type_q)
    by_type = {row[0]: row[1] for row in type_result}

    # Top IOCs by sighting count
    top_q = (
        select(IOC)
        .order_by(desc(IOC.sighting_count))
        .limit(20)
    )
    top_result = await db.execute(top_q)
    top_iocs = [
        {
            "id": str(ioc.id),
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "sighting_count": ioc.sighting_count,
            "confidence": ioc.confidence,
            "last_seen": ioc.last_seen.isoformat(),
        }
        for ioc in top_result.scalars().all()
    ]

    return IOCStats(total=total, by_type=by_type, top_iocs=top_iocs)


@router.get("/export/stix")
async def export_stix(
    analyst: AnalystUser,
    ioc_type: str | None = None,
    confidence_min: float | None = None,
    limit: int = Query(1000, le=10000),
    db: AsyncSession = Depends(get_session),
):
    """Export IOCs as a STIX 2.1 bundle (JSON)."""
    query = select(IOC).order_by(desc(IOC.last_seen)).limit(limit)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if confidence_min is not None:
        query = query.where(IOC.confidence >= confidence_min)

    result = await db.execute(query)
    iocs = result.scalars().all()

    objects = [_stix_identity()]
    for ioc in iocs:
        objects.append(_ioc_to_stix_indicator(ioc))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    return JSONResponse(content=bundle, media_type="application/stix+json;version=2.1")


@router.get("/export/csv")
async def export_csv(
    analyst: AnalystUser,
    ioc_type: str | None = None,
    confidence_min: float | None = None,
    limit: int = Query(5000, le=50000),
    db: AsyncSession = Depends(get_session),
):
    """Export IOCs as CSV."""
    query = select(IOC).order_by(desc(IOC.last_seen)).limit(limit)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if confidence_min is not None:
        query = query.where(IOC.confidence >= confidence_min)

    result = await db.execute(query)
    iocs = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "ioc_type", "value", "confidence", "sighting_count",
        "first_seen", "last_seen", "tags", "threat_actor_id",
    ])
    for ioc in iocs:
        writer.writerow([
            str(ioc.id),
            ioc.ioc_type,
            ioc.value,
            ioc.confidence,
            ioc.sighting_count,
            ioc.first_seen.isoformat(),
            ioc.last_seen.isoformat(),
            "|".join(ioc.tags) if ioc.tags else "",
            str(ioc.threat_actor_id) if ioc.threat_actor_id else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=iocs_export.csv"},
    )


@router.post("/search", response_model=list[BulkSearchResult])
async def bulk_search(
    body: BulkSearchRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Bulk search: accept a list of IOC values, return which ones are known."""
    if not body.values:
        return []

    results = []
    # Batch query all at once for performance
    stmt = select(IOC).where(IOC.value.in_(body.values))
    db_result = await db.execute(stmt)
    found_iocs = {ioc.value: ioc for ioc in db_result.scalars().all()}

    for val in body.values:
        ioc = found_iocs.get(val)
        results.append(BulkSearchResult(
            value=val,
            found=ioc is not None,
            ioc=IOCResponse.model_validate(ioc) if ioc else None,
        ))

    return results


@router.get("/{ioc_id}", response_model=IOCDetail)
async def get_ioc(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Get IOC detail with linked actor info."""
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")

    actor_alias = None
    if ioc.threat_actor_id:
        actor = await db.get(ThreatActor, ioc.threat_actor_id)
        if actor:
            actor_alias = actor.primary_alias

    resp = IOCDetail.model_validate(ioc)
    resp.actor_alias = actor_alias
    return resp


@router.get("/", response_model=list[IOCResponse])
async def list_iocs(
    analyst: AnalystUser,
    ioc_type: str | None = None,
    value_search: str | None = None,
    confidence_min: float | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    threat_actor_id: uuid.UUID | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List IOCs with filters."""
    query = select(IOC).order_by(desc(IOC.last_seen))

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if value_search:
        query = query.where(IOC.value.ilike(f"%{value_search}%"))
    if confidence_min is not None:
        query = query.where(IOC.confidence >= confidence_min)
    if date_from:
        query = query.where(IOC.last_seen >= date_from)
    if date_to:
        query = query.where(IOC.last_seen <= date_to)
    if threat_actor_id:
        query = query.where(IOC.threat_actor_id == threat_actor_id)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()
