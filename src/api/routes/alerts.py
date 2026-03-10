"""Alert management endpoints."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.threat import Alert, AlertStatus, ThreatCategory, ThreatSeverity
from src.storage.database import get_session

router = APIRouter(prefix="/alerts", tags=["alerts"])


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


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    org_id: uuid.UUID | None = None,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    query = select(Alert).order_by(desc(Alert.created_at))

    if org_id:
        query = query.where(Alert.organization_id == org_id)
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
    org_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_session),
):
    base = select(Alert)
    if org_id:
        base = base.where(Alert.organization_id == org_id)

    # Total count
    total_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(total_q)).scalar() or 0

    # By severity
    sev_q = (
        select(Alert.severity, func.count())
        .group_by(Alert.severity)
    )
    if org_id:
        sev_q = sev_q.where(Alert.organization_id == org_id)
    sev_result = await db.execute(sev_q)
    by_severity = {row[0]: row[1] for row in sev_result}

    # By category
    cat_q = (
        select(Alert.category, func.count())
        .group_by(Alert.category)
    )
    if org_id:
        cat_q = cat_q.where(Alert.organization_id == org_id)
    cat_result = await db.execute(cat_q)
    by_category = {row[0]: row[1] for row in cat_result}

    # By status
    stat_q = (
        select(Alert.status, func.count())
        .group_by(Alert.status)
    )
    if org_id:
        stat_q = stat_q.where(Alert.organization_id == org_id)
    stat_result = await db.execute(stat_q)
    by_status = {row[0]: row[1] for row in stat_result}

    return AlertStats(
        total=total,
        by_severity=by_severity,
        by_category=by_category,
        by_status=by_status,
    )


@router.get("/search", response_model=list[AlertResponse])
async def search_alerts(
    q: str = Query("", min_length=1),
    limit: int = Query(20, le=50),
    db: AsyncSession = Depends(get_session),
):
    """Full-text search across alert titles and summaries."""
    pattern = f"%{q}%"
    query = (
        select(Alert)
        .where(
            (Alert.title.ilike(pattern)) | (Alert.summary.ilike(pattern))
        )
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
):
    alert = await db.get(Alert, alert_id)
    if not alert:
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
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    changes: dict = {}

    if body.status:
        try:
            AlertStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"Invalid status: {body.status}")
        changes["status"] = {"from": alert.status, "to": body.status}
        alert.status = body.status

    if body.analyst_notes is not None:
        changes["analyst_notes"] = "updated"
        alert.analyst_notes = body.analyst_notes

    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    await audit_log(
        db,
        AuditAction.ALERT_UPDATE,
        user=analyst,
        resource_type="alert",
        resource_id=str(alert_id),
        details=changes,
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", "unknown")[:500],
    )
    await db.commit()
    await db.refresh(alert)
    return alert
