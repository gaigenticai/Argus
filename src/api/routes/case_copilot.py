"""Case Copilot — API surface.

Run-and-poll lifecycle (matches investigations / brand-actions):

  POST /cases/{case_id}/copilot           → enqueue + return id
  GET  /cases/{case_id}/copilot           → most-recent run for the case
  GET  /copilot-runs/{run_id}             → full detail with trace
  POST /copilot-runs/{run_id}/apply       → copy suggestions into the case

Idempotent enqueue: while a queued/running run exists for the case,
``POST .../copilot`` returns that run instead of creating a second.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.core.tenant import get_system_org_id
from src.models.case_copilot import CaseCopilotRun, CopilotStatus
from src.models.cases import Case
from src.storage.database import async_session_factory, get_session


router = APIRouter(tags=["Case Copilot"])


class CopilotRunListItem(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    status: str
    confidence: float | None
    iterations: int
    model_id: str | None
    duration_ms: int | None
    applied_at: datetime | None
    created_at: datetime
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class CopilotRunDetail(CopilotRunListItem):
    summary: str | None
    timeline_events: list[dict[str, Any]] | None
    suggested_mitre_ids: list[str] | None
    draft_next_steps: list[str] | None
    similar_case_ids: list[str] | None
    trace: list[dict[str, Any]] | None
    error_message: str | None
    started_at: datetime | None


class CreateCopilotResponse(BaseModel):
    id: uuid.UUID
    status: str
    case_id: uuid.UUID


class ApplyResponse(BaseModel):
    run_id: uuid.UUID
    applied_at: datetime
    already_applied: bool
    mitre_attached: int
    comment_added: bool


async def _run_in_background(run_id: uuid.UUID) -> None:
    if async_session_factory is None:
        return
    from src.agents.case_copilot_agent import run_and_persist

    async with async_session_factory() as session:
        run = (
            await session.execute(
                select(CaseCopilotRun).where(CaseCopilotRun.id == run_id)
            )
        ).scalar_one_or_none()
        if run is None:
            return
        await run_and_persist(
            session,
            case_id=run.case_id,
            organization_id=run.organization_id,
            run_id=run_id,
        )


@router.post(
    "/cases/{case_id}/copilot",
    response_model=CreateCopilotResponse,
    status_code=202,
)
async def create_copilot_run(
    case_id: uuid.UUID,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CreateCopilotResponse:
    """Queue a Case Copilot run for the given case."""
    org_id = await get_system_org_id(db)
    case = (
        await db.execute(
            select(Case)
            .where(Case.id == case_id)
            .where(Case.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if case is None:
        raise HTTPException(404, "case not found")

    existing = (
        await db.execute(
            select(CaseCopilotRun)
            .where(CaseCopilotRun.case_id == case_id)
            .where(
                CaseCopilotRun.status.in_(
                    [CopilotStatus.QUEUED.value, CopilotStatus.RUNNING.value]
                )
            )
            .order_by(desc(CaseCopilotRun.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return CreateCopilotResponse(
            id=existing.id, status=existing.status, case_id=case_id
        )

    run = CaseCopilotRun(
        organization_id=org_id,
        case_id=case_id,
        status=CopilotStatus.QUEUED.value,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    background.add_task(_run_in_background, run.id)
    return CreateCopilotResponse(
        id=run.id, status=run.status, case_id=case_id
    )


@router.get("/cases/{case_id}/copilot", response_model=CopilotRunDetail | None)
async def get_latest_copilot_run(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CopilotRunDetail | None:
    """Return the most recent copilot run for this case, or null when
    none exists. Lets the dashboard render the panel without a separate
    list call."""
    org_id = await get_system_org_id(db)
    run = (
        await db.execute(
            select(CaseCopilotRun)
            .where(CaseCopilotRun.case_id == case_id)
            .where(CaseCopilotRun.organization_id == org_id)
            .order_by(desc(CaseCopilotRun.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    if run is None:
        return None
    return CopilotRunDetail.model_validate(run)


@router.get("/copilot-runs/{run_id}", response_model=CopilotRunDetail)
async def get_copilot_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CopilotRunDetail:
    org_id = await get_system_org_id(db)
    run = (
        await db.execute(
            select(CaseCopilotRun)
            .where(CaseCopilotRun.id == run_id)
            .where(CaseCopilotRun.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(404, "copilot run not found")
    return CopilotRunDetail.model_validate(run)


@router.post("/copilot-runs/{run_id}/apply", response_model=ApplyResponse)
async def apply_copilot_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> ApplyResponse:
    """Copy the agent's suggestions into the case (MITRE attachments
    + draft next-step comment). Idempotent — already-applied runs
    return without re-attaching."""
    from src.agents.case_copilot_agent import apply_suggestions

    org_id = await get_system_org_id(db)
    run = (
        await db.execute(
            select(CaseCopilotRun)
            .where(CaseCopilotRun.id == run_id)
            .where(CaseCopilotRun.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(404, "copilot run not found")
    try:
        result = await apply_suggestions(
            db,
            run_id=run_id,
            user_id=getattr(user, "id", None) if user is not None else None,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return ApplyResponse(
        run_id=run_id,
        applied_at=datetime.fromisoformat(result["applied_at"]),
        already_applied=bool(result["already_applied"]),
        mitre_attached=int(result["mitre_attached"]),
        comment_added=bool(result["comment_added"]),
    )
