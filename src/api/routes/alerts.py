"""Alert management endpoints — single-tenant.

All list/get/search/patch operations scope to the system organisation
resolved by ``src.core.tenant``. The route surface no longer accepts
``org_id`` from the client; passing one is a 400.
"""

from __future__ import annotations


import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.core.tenant import get_system_org_id
from src.models.auth import AuditAction
from src.models.threat import Alert, AlertStatus, ThreatCategory, ThreatSeverity
from src.storage.database import get_session

router = APIRouter(prefix="/alerts", tags=["Threat Intelligence"])


class AlertResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    category: str
    severity: str
    status: str
    title: str
    summary: str
    confidence: float
    agent_reasoning: str | None
    recommended_actions: list | None
    matched_entities: dict | None
    analyst_notes: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: str | None = None
    analyst_notes: str | None = None


class AlertStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_status: dict[str, int]


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    query = (
        select(Alert)
        .where(Alert.organization_id == org_id)
        .order_by(desc(Alert.created_at))
    )
    if severity:
        query = query.where(Alert.severity == severity)
    if category:
        query = query.where(Alert.category == category)
    if status:
        query = query.where(Alert.status == status)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=AlertStats)
async def alert_stats(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    base = select(Alert).where(Alert.organization_id == org_id)

    total = (await db.execute(
        select(func.count()).select_from(base.subquery())
    )).scalar() or 0

    sev_q = (
        select(Alert.severity, func.count())
        .where(Alert.organization_id == org_id)
        .group_by(Alert.severity)
    )
    by_severity = {row[0]: row[1] for row in (await db.execute(sev_q))}

    cat_q = (
        select(Alert.category, func.count())
        .where(Alert.organization_id == org_id)
        .group_by(Alert.category)
    )
    by_category = {row[0]: row[1] for row in (await db.execute(cat_q))}

    stat_q = (
        select(Alert.status, func.count())
        .where(Alert.organization_id == org_id)
        .group_by(Alert.status)
    )
    by_status = {row[0]: row[1] for row in (await db.execute(stat_q))}

    return AlertStats(
        total=total,
        by_severity=by_severity,
        by_category=by_category,
        by_status=by_status,
    )


@router.get("/search", response_model=list[AlertResponse])
async def search_alerts(
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(20, le=50),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Full-text search across alert titles and summaries, scoped to the system organisation."""
    org_id = await get_system_org_id(db)
    pattern = f"%{q}%"
    query = (
        select(Alert)
        .where(
            Alert.organization_id == org_id,
            (Alert.title.ilike(pattern)) | (Alert.summary.ilike(pattern)),
        )
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        # Don't leak existence of rows that belong to another (impossible
        # in single-tenant, but defensive against a future restore that
        # imports rows from another deployment).
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: uuid.UUID,
    body: AlertUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")

    before: dict = {}
    after: dict = {}

    if body.status:
        try:
            AlertStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"Invalid status: {body.status}")
        if alert.status != body.status:
            before["status"] = alert.status
            after["status"] = body.status
            alert.status = body.status

    if body.analyst_notes is not None and body.analyst_notes != (alert.analyst_notes or ""):
        before["analyst_notes"] = alert.analyst_notes
        after["analyst_notes"] = body.analyst_notes
        alert.analyst_notes = body.analyst_notes

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ALERT_UPDATE,
        user=analyst,
        resource_type="alert",
        resource_id=str(alert_id),
        details={"before": before, "after": after} if (before or after) else {"no_change": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(alert)
    return alert
