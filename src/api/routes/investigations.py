"""Investigation endpoints — kick off and inspect agentic investigations.

All routes scope to the system organisation. ``alert_id`` paths reject
alerts that don't belong to the system org.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.core.tenant import get_system_org_id
from src.models.investigations import Investigation, InvestigationStatus
from src.models.threat import Alert
from src.storage.database import async_session_factory, get_session


router = APIRouter(prefix="/investigations", tags=["Investigations"])


# ---- Schemas --------------------------------------------------------


class InvestigationListItem(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    status: str
    severity_assessment: str | None
    iterations: int
    model_id: str | None
    duration_ms: int | None
    created_at: datetime
    finished_at: datetime | None
    case_id: uuid.UUID | None = None

    model_config = {"from_attributes": True}


class InvestigationDetail(InvestigationListItem):
    final_assessment: str | None
    correlated_iocs: list[str]
    correlated_actors: list[str]
    recommended_actions: list[str]
    trace: list[dict[str, Any]] | None
    error_message: str | None
    started_at: datetime | None
    case_id: uuid.UUID | None


class CreateInvestigationResponse(BaseModel):
    id: uuid.UUID
    status: str
    alert_id: uuid.UUID


class PromoteResponse(BaseModel):
    investigation_id: uuid.UUID
    case_id: uuid.UUID
    already_promoted: bool


# ---- Background runner ---------------------------------------------


async def _run_in_background(investigation_id: uuid.UUID) -> None:
    """Drive a queued investigation to completion in its own session.

    BackgroundTasks runs after the response is sent. The DB session
    used by the request is already closed by then, so we open a fresh
    one from the global session factory.
    """
    if async_session_factory is None:
        # Worker mode — request flow already initialised the engine.
        return
    from src.agents.investigation_agent import run_and_persist

    async with async_session_factory() as session:
        # Fetch alert + org once so we can pass them through.
        inv = (
            await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
        ).scalar_one_or_none()
        if inv is None:
            return
        await run_and_persist(
            session,
            alert_id=inv.alert_id,
            organization_id=inv.organization_id,
            investigation_id=investigation_id,
        )


# ---- Routes ---------------------------------------------------------


@router.post("/{alert_id}", response_model=CreateInvestigationResponse, status_code=202)
async def create_investigation(
    alert_id: uuid.UUID,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001 — auth via Depends in the type
) -> CreateInvestigationResponse:
    """Kick off an investigation against an alert.

    Returns 202 + the investigation id immediately. The agent loop
    runs in the background; poll ``GET /investigations/{id}`` to
    follow progress.

    Idempotent for active runs: if a queued or running investigation
    already exists for this alert, return that one instead of
    starting a second.
    """
    org_id = await get_system_org_id(db)

    alert = (
        await db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(404, "alert not found")

    # Reuse an in-flight run if one exists.
    existing = (
        await db.execute(
            select(Investigation)
            .where(Investigation.alert_id == alert_id)
            .where(
                Investigation.status.in_(
                    [
                        InvestigationStatus.QUEUED.value,
                        InvestigationStatus.RUNNING.value,
                    ]
                )
            )
            .order_by(desc(Investigation.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return CreateInvestigationResponse(
            id=existing.id, status=existing.status, alert_id=alert_id
        )

    inv = Investigation(
        organization_id=org_id,
        alert_id=alert_id,
        status=InvestigationStatus.QUEUED.value,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)

    background.add_task(_run_in_background, inv.id)
    return CreateInvestigationResponse(
        id=inv.id, status=inv.status, alert_id=alert_id
    )


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001 — auth via Depends in the type
) -> InvestigationDetail:
    org_id = await get_system_org_id(db)
    inv = (
        await db.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .where(Investigation.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, "investigation not found")
    return InvestigationDetail.model_validate(inv)


@router.post("/{investigation_id}/promote", response_model=PromoteResponse)
async def promote_investigation(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> PromoteResponse:
    """Turn a completed investigation into a Case.

    Returns the case id. Idempotent — calling a second time on an
    already-promoted investigation returns the same case id with
    ``already_promoted=True``.
    """
    from src.agents.investigation_agent import PromoteError, promote_to_case

    org_id = await get_system_org_id(db)
    inv = (
        await db.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .where(Investigation.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, "investigation not found")

    already = inv.case_id is not None
    user_id = getattr(user, "id", None) if user is not None else None
    try:
        case_id = await promote_to_case(
            db, investigation_id=investigation_id, user_id=user_id
        )
    except PromoteError as exc:
        raise HTTPException(400, str(exc)) from exc
    await db.commit()
    return PromoteResponse(
        investigation_id=investigation_id,
        case_id=case_id,
        already_promoted=already,
    )


@router.get("", response_model=list[InvestigationListItem])
async def list_investigations(
    alert_id: uuid.UUID | None = Query(None),
    case_id: uuid.UUID | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001 — auth via Depends in the type
) -> list[InvestigationListItem]:
    """List investigations, scoped to the system org.

    Filters: ``alert_id`` (all runs against one alert),
    ``case_id`` (all runs that produced the same case — closes the
    loop when an analyst opens a case and wants the agent's trace),
    ``status``. Results are ordered newest-first.
    """
    org_id = await get_system_org_id(db)
    stmt = (
        select(Investigation)
        .where(Investigation.organization_id == org_id)
        .order_by(desc(Investigation.created_at))
        .limit(limit)
    )
    if alert_id is not None:
        stmt = stmt.where(Investigation.alert_id == alert_id)
    if case_id is not None:
        stmt = stmt.where(Investigation.case_id == case_id)
    if status is not None:
        stmt = stmt.where(Investigation.status == status)
    rows = (await db.execute(stmt)).scalars().all()
    return [InvestigationListItem.model_validate(r) for r in rows]
