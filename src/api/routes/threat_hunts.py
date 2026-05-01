"""Threat Hunter — API surface.

  POST /threat-hunts            → queue an ad-hoc hunt (analyst-trigger
                                  on top of the weekly schedule)
  GET  /threat-hunts            → list past hunt runs
  GET  /threat-hunts/{id}       → full detail with trace + findings
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.core.tenant import get_system_org_id
from src.models.threat_hunts import HuntStatus, ThreatHuntRun
from src.storage.database import async_session_factory, get_session


router = APIRouter(prefix="/threat-hunts", tags=["Threat Hunter"])


class HuntListItem(BaseModel):
    id: uuid.UUID
    status: str
    primary_actor_alias: str | None
    confidence: float | None
    iterations: int
    model_id: str | None
    duration_ms: int | None
    created_at: datetime
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class HuntDetail(HuntListItem):
    primary_actor_id: uuid.UUID | None
    summary: str | None
    findings: list[dict[str, Any]] | None
    trace: list[dict[str, Any]] | None
    error_message: str | None
    started_at: datetime | None


class CreateHuntResponse(BaseModel):
    id: uuid.UUID
    status: str


async def _run_in_background(run_id: uuid.UUID) -> None:
    if async_session_factory is None:
        return
    from src.agents.threat_hunter_agent import run_and_persist

    async with async_session_factory() as session:
        run = (
            await session.execute(
                select(ThreatHuntRun).where(ThreatHuntRun.id == run_id)
            )
        ).scalar_one_or_none()
        if run is None:
            return
        await run_and_persist(
            session,
            organization_id=run.organization_id,
            run_id=run_id,
        )


@router.post("", response_model=CreateHuntResponse, status_code=202)
async def create_hunt(
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CreateHuntResponse:
    """Queue an ad-hoc hunt on top of the weekly schedule.

    Idempotent over in-flight runs: if a queued/running hunt already
    exists for the org, we return that one rather than starting a
    second.
    """
    org_id = await get_system_org_id(db)
    existing = (
        await db.execute(
            select(ThreatHuntRun)
            .where(ThreatHuntRun.organization_id == org_id)
            .where(
                ThreatHuntRun.status.in_(
                    [HuntStatus.QUEUED.value, HuntStatus.RUNNING.value]
                )
            )
            .order_by(desc(ThreatHuntRun.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return CreateHuntResponse(id=existing.id, status=existing.status)

    run = ThreatHuntRun(
        organization_id=org_id,
        status=HuntStatus.QUEUED.value,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    background.add_task(_run_in_background, run.id)
    return CreateHuntResponse(id=run.id, status=run.status)


@router.get("", response_model=list[HuntListItem])
async def list_hunts(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> list[HuntListItem]:
    org_id = await get_system_org_id(db)
    stmt = (
        select(ThreatHuntRun)
        .where(ThreatHuntRun.organization_id == org_id)
        .order_by(desc(ThreatHuntRun.created_at))
        .limit(limit)
    )
    if status is not None:
        stmt = stmt.where(ThreatHuntRun.status == status)
    rows = (await db.execute(stmt)).scalars().all()
    return [HuntListItem.model_validate(r) for r in rows]


@router.get("/{run_id}", response_model=HuntDetail)
async def get_hunt(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> HuntDetail:
    org_id = await get_system_org_id(db)
    run = (
        await db.execute(
            select(ThreatHuntRun)
            .where(ThreatHuntRun.id == run_id)
            .where(ThreatHuntRun.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(404, "hunt run not found")
    return HuntDetail.model_validate(run)
