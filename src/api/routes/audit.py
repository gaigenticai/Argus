"""Audit log viewer endpoints — admin only."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, cast, Date
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser
from src.models.auth import AuditLog
from src.storage.database import get_session

router = APIRouter(prefix="/audit", tags=["audit"])


# --- Schemas ---


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    user_id: uuid.UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    details: dict | None
    ip_address: str | None
    user_agent: str | None

    model_config = {"from_attributes": True}


class AuditListResponse(BaseModel):
    logs: list[AuditLogResponse]
    total: int


class DailyActivity(BaseModel):
    date: str
    count: int


class TopUser(BaseModel):
    user_id: str
    count: int


class AuditStatsResponse(BaseModel):
    total_events: int
    actions_per_day: list[DailyActivity]
    top_users: list[TopUser]
    actions_breakdown: dict[str, int]


# --- Endpoints ---


@router.get("/", response_model=AuditListResponse)
async def list_audit_logs(
    admin: AdminUser,
    action: str | None = None,
    user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List audit logs with filters (admin only)."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))

    if action:
        query = query.where(AuditLog.action == action)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if since:
        query = query.where(AuditLog.timestamp >= since)
    if until:
        query = query.where(AuditLog.timestamp <= until)

    # Total count for the filtered query
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return AuditListResponse(logs=logs, total=total)


@router.get("/stats", response_model=AuditStatsResponse)
async def audit_stats(
    admin: AdminUser,
    days: int = Query(30, le=365),
    db: AsyncSession = Depends(get_session),
):
    """Audit activity statistics: daily counts, top users, action breakdown (admin only)."""
    from datetime import timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    base_filter = AuditLog.timestamp >= cutoff

    # Total events in period
    total_q = select(func.count()).select_from(AuditLog).where(base_filter)
    total_events = (await db.execute(total_q)).scalar() or 0

    # Actions per day
    day_q = (
        select(
            cast(AuditLog.timestamp, Date).label("day"),
            func.count().label("cnt"),
        )
        .where(base_filter)
        .group_by("day")
        .order_by(desc("day"))
        .limit(days)
    )
    day_result = await db.execute(day_q)
    actions_per_day = [
        DailyActivity(date=str(row.day), count=row.cnt)
        for row in day_result
    ]

    # Top users by event count
    user_q = (
        select(
            AuditLog.user_id,
            func.count().label("cnt"),
        )
        .where(base_filter, AuditLog.user_id.isnot(None))
        .group_by(AuditLog.user_id)
        .order_by(desc("cnt"))
        .limit(10)
    )
    user_result = await db.execute(user_q)
    top_users = [
        TopUser(user_id=str(row.user_id), count=row.cnt)
        for row in user_result
    ]

    # Action type breakdown
    action_q = (
        select(
            AuditLog.action,
            func.count().label("cnt"),
        )
        .where(base_filter)
        .group_by(AuditLog.action)
        .order_by(desc("cnt"))
    )
    action_result = await db.execute(action_q)
    actions_breakdown = {row.action: row.cnt for row in action_result}

    return AuditStatsResponse(
        total_events=total_events,
        actions_per_day=actions_per_day,
        top_users=top_users,
        actions_breakdown=actions_breakdown,
    )
