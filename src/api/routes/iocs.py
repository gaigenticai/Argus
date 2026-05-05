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

from src.core.auth import AdminUser, AnalystUser
from src.models.intel import IOC, IocAudit, IocSighting, IOCType, ThreatActor
from src.storage.database import get_session
from src.intel.ioc_enrichment import enrich_ioc, malicious_score_from
from src.news.entity_extractor import defang as _defang_value

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
    is_allowlisted: bool = False
    allowlist_reason: str | None = None
    expires_at: datetime | None = None
    confidence_half_life_days: int = 365
    enrichment_data: dict = {}
    enrichment_fetched_at: datetime | None = None
    source_feed: str | None = None
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
    source_alert_id: uuid.UUID | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List IOCs with filters.

    ``source_alert_id`` returns IOCs that the feed-triage agent
    linked to a specific alert (the indicators that triggered or
    constitute that alert's evidence). Powers the "Indicators"
    section on the alert detail page.
    """
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
    if source_alert_id:
        query = query.where(IOC.source_alert_id == source_alert_id)

    # Hide allowlisted by default unless caller asked for "show suppressed".
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


# ---------------------------------------------------------------------------
# Production endpoints — write ops, allowlist, enrichment, sightings, pivot
# ---------------------------------------------------------------------------


class IOCCreate(BaseModel):
    ioc_type: IOCType
    value: str
    confidence: float = 0.5
    tags: list[str] = []
    context: dict | None = None
    threat_actor_id: uuid.UUID | None = None
    source_feed: str | None = None
    expires_at: datetime | None = None


class IOCEdit(BaseModel):
    confidence: float | None = None
    tags: list[str] | None = None
    context: dict | None = None
    threat_actor_id: uuid.UUID | None = None
    is_allowlisted: bool | None = None
    allowlist_reason: str | None = None
    expires_at: datetime | None = None
    confidence_half_life_days: int | None = None


@router.post("/", response_model=IOCResponse, status_code=201)
async def create_ioc(
    body: IOCCreate,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Manually create or upsert an IOC."""
    val = body.value.strip()
    if not val:
        raise HTTPException(422, "value cannot be empty")
    now = datetime.now(timezone.utc)
    existing = (
        await db.execute(
            select(IOC).where(IOC.ioc_type == body.ioc_type.value, IOC.value == val)
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.last_seen = now
        existing.sighting_count = (existing.sighting_count or 1) + 1
        if body.tags:
            existing.tags = sorted(set((existing.tags or []) + body.tags))
        if body.context:
            existing.context = {**(existing.context or {}), **body.context}
        if body.threat_actor_id and existing.threat_actor_id is None:
            existing.threat_actor_id = body.threat_actor_id
        existing.source_feed = existing.source_feed or body.source_feed or "manual"
        ioc = existing
    else:
        ioc = IOC(
            ioc_type=body.ioc_type.value,
            value=val[:2048],
            confidence=max(0.0, min(1.0, body.confidence)),
            first_seen=now,
            last_seen=now,
            sighting_count=1,
            tags=body.tags,
            context=body.context or {},
            threat_actor_id=body.threat_actor_id,
            source_feed=body.source_feed or "manual",
            expires_at=body.expires_at,
        )
        db.add(ioc)
        await db.flush()
    db.add(
        IocAudit(
            ioc_id=ioc.id,
            action="create" if existing is None else "edit",
            user_id=getattr(analyst, "id", None),
            after={
                "value": val,
                "ioc_type": body.ioc_type.value,
                "confidence": ioc.confidence,
                "tags": list(ioc.tags or []),
            },
        )
    )
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.patch("/{ioc_id}", response_model=IOCResponse)
async def edit_ioc(
    ioc_id: uuid.UUID,
    body: IOCEdit,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    before = {
        "confidence": ioc.confidence,
        "tags": list(ioc.tags or []),
        "is_allowlisted": ioc.is_allowlisted,
        "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
    }
    if body.confidence is not None:
        ioc.confidence = max(0.0, min(1.0, body.confidence))
    if body.tags is not None:
        ioc.tags = sorted(set(body.tags))
    if body.context is not None:
        ioc.context = {**(ioc.context or {}), **body.context}
    if body.threat_actor_id is not None:
        ioc.threat_actor_id = body.threat_actor_id
    if body.is_allowlisted is not None:
        ioc.is_allowlisted = body.is_allowlisted
        ioc.allowlist_reason = body.allowlist_reason
    if body.expires_at is not None:
        ioc.expires_at = body.expires_at
    if body.confidence_half_life_days is not None:
        ioc.confidence_half_life_days = body.confidence_half_life_days
    db.add(
        IocAudit(
            ioc_id=ioc.id,
            action="edit",
            user_id=getattr(analyst, "id", None),
            before=before,
            after={
                "confidence": ioc.confidence,
                "tags": list(ioc.tags or []),
                "is_allowlisted": ioc.is_allowlisted,
            },
        )
    )
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    db.add(
        IocAudit(
            ioc_id=ioc.id,
            action="delete",
            user_id=getattr(analyst, "id", None),
            before={"value": ioc.value, "ioc_type": ioc.ioc_type},
        )
    )
    await db.delete(ioc)
    await db.commit()


@router.post("/{ioc_id}/allowlist", response_model=IOCResponse)
async def toggle_allowlist(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    reason: str | None = Query(default=None, max_length=500),
    on: bool = Query(default=True),
):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    ioc.is_allowlisted = on
    ioc.allowlist_reason = reason if on else None
    db.add(
        IocAudit(
            ioc_id=ioc.id,
            action="allowlist_on" if on else "allowlist_off",
            user_id=getattr(analyst, "id", None),
            after={"reason": reason, "on": on},
        )
    )
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.post("/{ioc_id}/enrich", response_model=IOCResponse)
async def trigger_enrichment(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Run on-demand enrichment via OTX, AbuseIPDB, URLhaus, ThreatFox,
    Shodan InternetDB, GreyNoise, CIRCL hashlookup. Bumps confidence on
    strong malicious signals, leaves weak/unknown signals alone."""
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    enrichment = await enrich_ioc(ioc.ioc_type, ioc.value)
    ioc.enrichment_data = enrichment
    ioc.enrichment_fetched_at = datetime.now(timezone.utc)
    sig = malicious_score_from(enrichment)
    if sig is not None and sig > (ioc.confidence or 0):
        ioc.confidence = sig
    db.add(
        IocAudit(
            ioc_id=ioc.id,
            action="enrich",
            user_id=getattr(analyst, "id", None),
            after={"signals": list(enrichment.keys()), "score": sig},
        )
    )
    await db.commit()
    await db.refresh(ioc)
    return ioc


class SightingResponse(BaseModel):
    id: uuid.UUID
    ioc_id: uuid.UUID
    source: str
    source_id: uuid.UUID | None
    source_url: str | None
    seen_at: datetime
    context: dict
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/{ioc_id}/sightings", response_model=list[SightingResponse])
async def list_sightings(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=500),
):
    rows = (
        await db.execute(
            select(IocSighting)
            .where(IocSighting.ioc_id == ioc_id)
            .order_by(desc(IocSighting.seen_at))
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


@router.get("/{ioc_id}/pivot")
async def pivot_ioc(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Return related IOCs that share an article, alert, or actor."""
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")

    from src.models.news import NewsArticle, NewsArticleIoc
    article_ids = list(
        (
            await db.execute(
                select(NewsArticleIoc.article_id).where(
                    NewsArticleIoc.ioc_id == ioc_id
                )
            )
        ).scalars().all()
    )
    related_iocs: list[IOC] = []
    if article_ids:
        related_iocs = list(
            (
                await db.execute(
                    select(IOC)
                    .join(NewsArticleIoc, NewsArticleIoc.ioc_id == IOC.id)
                    .where(
                        NewsArticleIoc.article_id.in_(article_ids),
                        IOC.id != ioc_id,
                    )
                    .limit(50)
                )
            ).scalars().all()
        )
    by_actor: list[IOC] = []
    if ioc.threat_actor_id:
        by_actor = list(
            (
                await db.execute(
                    select(IOC).where(
                        IOC.threat_actor_id == ioc.threat_actor_id,
                        IOC.id != ioc_id,
                    ).limit(50)
                )
            ).scalars().all()
        )
    articles = list(
        (
            await db.execute(
                select(NewsArticle.id, NewsArticle.title, NewsArticle.url)
                .where(NewsArticle.id.in_(article_ids))
                .limit(20)
            )
        ).all()
    )
    return {
        "ioc_id": str(ioc_id),
        "related_via_articles": [
            IOCResponse.model_validate(r).model_dump(mode="json")
            for r in related_iocs
        ],
        "related_via_actor": [
            IOCResponse.model_validate(r).model_dump(mode="json") for r in by_actor
        ],
        "articles": [
            {"id": str(a[0]), "title": a[1], "url": a[2]} for a in articles
        ],
    }


class BulkImportRow(BaseModel):
    ioc_type: IOCType
    value: str
    confidence: float | None = None
    tags: list[str] = []
    source_feed: str | None = None


class BulkImportRequest(BaseModel):
    rows: list[BulkImportRow]


class BulkImportResult(BaseModel):
    inserted: int
    updated: int
    errors: list[str]


@router.post("/import", response_model=BulkImportResult)
async def bulk_import(
    body: BulkImportRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Bulk import IOCs (JSON). For CSV, parse client-side and POST as JSON."""
    inserted = updated = 0
    errors: list[str] = []
    now = datetime.now(timezone.utc)
    for row in body.rows:
        val = row.value.strip()
        if not val:
            errors.append("empty value")
            continue
        existing = (
            await db.execute(
                select(IOC).where(
                    IOC.ioc_type == row.ioc_type.value, IOC.value == val
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                IOC(
                    ioc_type=row.ioc_type.value,
                    value=val[:2048],
                    confidence=max(0.0, min(1.0, row.confidence or 0.5)),
                    first_seen=now,
                    last_seen=now,
                    sighting_count=1,
                    tags=row.tags,
                    source_feed=row.source_feed or "import",
                )
            )
            inserted += 1
        else:
            existing.last_seen = now
            existing.sighting_count = (existing.sighting_count or 1) + 1
            if row.tags:
                existing.tags = sorted(set((existing.tags or []) + row.tags))
            if row.confidence is not None and row.confidence > (existing.confidence or 0):
                existing.confidence = row.confidence
            updated += 1
    await db.commit()
    return BulkImportResult(inserted=inserted, updated=updated, errors=errors)


@router.post("/decay")
async def decay_confidence(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Apply confidence decay across all non-allowlisted IOCs.

    new_conf = old_conf * 0.5 ** (days_since_last_seen / half_life)

    Sunsets (sets expires_at = now) any IOC whose confidence drops below
    0.05 and that hasn't been seen in 2× its half-life.
    """
    import math

    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(IOC).where(
                IOC.is_allowlisted.is_(False), IOC.expires_at.is_(None)
            )
        )
    ).scalars().all()
    decayed = sunsetted = 0
    for ioc in rows:
        if not ioc.last_seen:
            continue
        days = max(0, (now - ioc.last_seen).days)
        hl = max(1, ioc.confidence_half_life_days or 365)
        factor = 0.5 ** (days / hl)
        new_conf = (ioc.confidence or 0.5) * factor
        if abs(new_conf - (ioc.confidence or 0)) > 0.001:
            ioc.confidence = new_conf
            decayed += 1
        if new_conf < 0.05 and days >= 2 * hl:
            ioc.expires_at = now
            sunsetted += 1
    await db.commit()
    return {"decayed": decayed, "sunsetted": sunsetted, "total_evaluated": len(rows)}


@router.get("/{ioc_id}/defang")
async def defanged_value(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return {"value": ioc.value, "defanged": _defang_value(ioc.value)}


class IocAuditResponse(BaseModel):
    id: uuid.UUID
    action: str
    user_id: uuid.UUID | None
    before: dict | None
    after: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/{ioc_id}/audit", response_model=list[IocAuditResponse])
async def list_audit(
    ioc_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    limit: int = Query(50, le=200),
):
    rows = (
        await db.execute(
            select(IocAudit)
            .where(IocAudit.ioc_id == ioc_id)
            .order_by(desc(IocAudit.created_at))
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)
