"""Threat actor management and timeline endpoints."""

from __future__ import annotations


import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser
from src.models.intel import ThreatActor, ActorSighting, IOC
from src.models.threat import Alert
from src.enrichment.actor_tracker import merge_actors as do_merge, calculate_risk_score
from src.storage.database import get_session

router = APIRouter(prefix="/actors", tags=["Threat Intelligence"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ActorResponse(BaseModel):
    id: uuid.UUID
    primary_alias: str
    aliases: list[str]
    description: str | None
    forums_active: list[str]
    languages: list[str]
    pgp_fingerprints: list[str]
    known_ttps: list[str]
    risk_score: float
    first_seen: datetime
    last_seen: datetime
    total_sightings: int
    profile_data: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ActorDetail(ActorResponse):
    """Extended actor profile with sightings and IOC counts."""
    recent_sightings: list[dict] = []
    ioc_count: int = 0
    linked_alert_ids: list[str] = []


class ActorUpdate(BaseModel):
    description: str | None = None
    aliases: list[str] | None = None
    known_ttps: list[str] | None = None
    languages: list[str] | None = None
    pgp_fingerprints: list[str] | None = None


class TimelineEntry(BaseModel):
    timestamp: datetime
    platform: str
    alias_used: str
    raw_intel_id: str | None
    alert_id: str | None
    context: dict | None


class ActorStats(BaseModel):
    total_actors: int
    by_platform: dict[str, int]
    avg_risk_score: float
    high_risk_count: int
    active_last_30_days: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=ActorStats)
async def actor_stats(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Aggregate statistics about tracked threat actors."""
    # Total
    total = (await db.execute(
        select(func.count()).select_from(ThreatActor)
    )).scalar() or 0

    # Average risk score
    avg_risk = (await db.execute(
        select(func.avg(ThreatActor.risk_score))
    )).scalar() or 0.0

    # High risk (>= 50)
    high_risk = (await db.execute(
        select(func.count()).select_from(ThreatActor).where(ThreatActor.risk_score >= 50.0)
    )).scalar() or 0

    # Active last 30 days
    from datetime import timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    active_30 = (await db.execute(
        select(func.count()).select_from(ThreatActor).where(ThreatActor.last_seen >= cutoff)
    )).scalar() or 0

    # By platform — unnest forums_active and count
    platform_q = select(
        func.unnest(ThreatActor.forums_active).label("platform"),
        func.count().label("cnt"),
    ).group_by("platform")
    platform_result = await db.execute(platform_q)
    by_platform = {row.platform: row.cnt for row in platform_result}

    return ActorStats(
        total_actors=total,
        by_platform=by_platform,
        avg_risk_score=round(float(avg_risk), 2),
        high_risk_count=high_risk,
        active_last_30_days=active_30,
    )


@router.get("/{actor_id}/timeline", response_model=list[TimelineEntry])
async def actor_timeline(
    actor_id: uuid.UUID,
    analyst: AnalystUser,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_session),
):
    """Chronological timeline of all sightings for an actor."""
    actor = await db.get(ThreatActor, actor_id)
    if not actor:
        raise HTTPException(404, "Threat actor not found")

    stmt = (
        select(ActorSighting)
        .where(ActorSighting.threat_actor_id == actor_id)
        .order_by(desc(ActorSighting.created_at))
        .limit(limit)
    )
    result = await db.execute(stmt)
    sightings = result.scalars().all()

    return [
        TimelineEntry(
            timestamp=s.created_at,
            platform=s.source_platform,
            alias_used=s.alias_used,
            raw_intel_id=str(s.raw_intel_id) if s.raw_intel_id else None,
            alert_id=str(s.alert_id) if s.alert_id else None,
            context=s.context,
        )
        for s in sightings
    ]


@router.post("/{actor_id}/merge/{other_id}", response_model=ActorResponse)
async def merge_actor(
    actor_id: uuid.UUID,
    other_id: uuid.UUID,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Merge two threat actors (secondary into primary)."""
    try:
        merged = await do_merge(actor_id, other_id, db)
        await db.commit()
        await db.refresh(merged)
        return merged
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/{actor_id}/navigator-layer")
async def get_actor_navigator_layer(
    actor_id: uuid.UUID,
    analyst: AnalystUser,
    matrix: str = Query(default="enterprise", pattern="^(enterprise|ics)$"),
    db: AsyncSession = Depends(get_session),
):
    """Download a MITRE ATT&CK Navigator v4.5 layer for this actor.

    Highlights every technique in the actor's ``known_ttps`` so the
    analyst can overlay it against their detection-coverage map in the
    hosted Navigator (https://mitre-attack.github.io/attack-navigator/)
    or a self-hosted instance.
    """
    from fastapi.responses import JSONResponse
    from src.intel.iran_apt_pack import build_navigator_layer

    actor = await db.get(ThreatActor, actor_id)
    if actor is None:
        raise HTTPException(404, "Threat actor not found")
    layer = build_navigator_layer(actor, matrix=matrix)
    filename = (
        f"argus-{actor.primary_alias.lower().replace(' ', '_')}-{matrix}-layer.json"
    )
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{actor_id}", response_model=ActorDetail)
async def get_actor(
    actor_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Get actor profile with sightings, IOCs, and linked alerts."""
    actor = await db.get(ThreatActor, actor_id)
    if not actor:
        raise HTTPException(404, "Threat actor not found")

    # Recent sightings (last 20)
    sighting_stmt = (
        select(ActorSighting)
        .where(ActorSighting.threat_actor_id == actor_id)
        .order_by(desc(ActorSighting.created_at))
        .limit(20)
    )
    sighting_result = await db.execute(sighting_stmt)
    sightings = [
        {
            "id": str(s.id),
            "timestamp": s.created_at.isoformat(),
            "platform": s.source_platform,
            "alias_used": s.alias_used,
            "alert_id": str(s.alert_id) if s.alert_id else None,
        }
        for s in sighting_result.scalars().all()
    ]

    # IOC count
    ioc_count = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.threat_actor_id == actor_id)
    )).scalar() or 0

    # Linked alert IDs (via sightings)
    alert_ids_stmt = (
        select(ActorSighting.alert_id)
        .where(
            ActorSighting.threat_actor_id == actor_id,
            ActorSighting.alert_id.isnot(None),
        )
        .distinct()
    )
    alert_result = await db.execute(alert_ids_stmt)
    linked_alert_ids = [str(row[0]) for row in alert_result]

    resp = ActorDetail.model_validate(actor)
    resp.recent_sightings = sightings
    resp.ioc_count = ioc_count
    resp.linked_alert_ids = linked_alert_ids
    return resp


@router.patch("/{actor_id}", response_model=ActorResponse)
async def update_actor(
    actor_id: uuid.UUID,
    body: ActorUpdate,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Update actor profile (add aliases, TTPs, description, etc.)."""
    actor = await db.get(ThreatActor, actor_id)
    if not actor:
        raise HTTPException(404, "Threat actor not found")

    if body.description is not None:
        actor.description = body.description

    if body.aliases is not None:
        existing = set(actor.aliases or [])
        existing.update(body.aliases)
        actor.aliases = sorted(existing)

    if body.known_ttps is not None:
        existing = set(actor.known_ttps or [])
        existing.update(body.known_ttps)
        actor.known_ttps = sorted(existing)

    if body.languages is not None:
        existing = set(actor.languages or [])
        existing.update(body.languages)
        actor.languages = sorted(existing)

    if body.pgp_fingerprints is not None:
        existing = set(actor.pgp_fingerprints or [])
        existing.update(body.pgp_fingerprints)
        actor.pgp_fingerprints = sorted(existing)

    # Recalculate risk score after updates
    actor.risk_score = await calculate_risk_score(actor, db)

    await db.commit()
    await db.refresh(actor)
    return actor


@router.get("/", response_model=list[ActorResponse])
async def list_actors(
    analyst: AnalystUser,
    risk_score_min: float | None = None,
    platform: str | None = None,
    language: str | None = None,
    search: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List threat actors with filters."""
    query = select(ThreatActor).order_by(desc(ThreatActor.risk_score))

    if risk_score_min is not None:
        query = query.where(ThreatActor.risk_score >= risk_score_min)
    if platform:
        query = query.where(ThreatActor.forums_active.any(platform))
    if language:
        query = query.where(ThreatActor.languages.any(language))
    if search:
        pattern = f"%{search}%"
        query = query.where(
            ThreatActor.primary_alias.ilike(pattern)
        )

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()
