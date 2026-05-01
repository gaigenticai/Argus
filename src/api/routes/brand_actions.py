"""Brand Defender agent — API surface.

Mirrors the investigations route shape: kick off, list, detail. The
``submit_takedown`` endpoint takes the agent's recommendation and
hands it to the existing takedown adapter for the chosen partner;
that part is a thin pass-through, the agent never auto-submits.
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
from src.models.brand import SuspectDomain
from src.models.brand_actions import BrandAction, BrandActionStatus
from src.storage.database import async_session_factory, get_session


router = APIRouter(prefix="/brand-actions", tags=["Brand Defender"])


class BrandActionListItem(BaseModel):
    id: uuid.UUID
    suspect_domain_id: uuid.UUID
    status: str
    recommendation: str | None
    confidence: float | None
    risk_signals: list[str]
    suggested_partner: str | None
    iterations: int
    model_id: str | None
    duration_ms: int | None
    created_at: datetime
    finished_at: datetime | None
    takedown_ticket_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class BrandActionDetail(BrandActionListItem):
    recommendation_reason: str | None
    trace: list[dict[str, Any]] | None
    error_message: str | None
    started_at: datetime | None


class CreateBrandActionResponse(BaseModel):
    id: uuid.UUID
    status: str
    suspect_domain_id: uuid.UUID


class SubmitTakedownPayload(BaseModel):
    """Optional override for the partner. When omitted, the agent's
    ``suggested_partner`` is used; if neither is set we fall back to
    ``manual`` so the case still produces a ticket the analyst can
    track."""

    partner: str | None = None


class SubmitTakedownResponse(BaseModel):
    action_id: uuid.UUID
    ticket_id: uuid.UUID
    partner: str
    already_submitted: bool


async def _run_in_background(action_id: uuid.UUID) -> None:
    if async_session_factory is None:
        return
    from src.agents.brand_defender_agent import run_and_persist

    async with async_session_factory() as session:
        action = (
            await session.execute(
                select(BrandAction).where(BrandAction.id == action_id)
            )
        ).scalar_one_or_none()
        if action is None:
            return
        await run_and_persist(
            session,
            suspect_domain_id=action.suspect_domain_id,
            organization_id=action.organization_id,
            action_id=action_id,
        )


@router.post(
    "/{suspect_domain_id}",
    response_model=CreateBrandActionResponse,
    status_code=202,
)
async def create_brand_action(
    suspect_domain_id: uuid.UUID,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CreateBrandActionResponse:
    """Queue a Brand Defender run for a suspect domain.

    Idempotent: returns an existing queued/running run for the same
    suspect rather than starting a duplicate.
    """
    org_id = await get_system_org_id(db)
    suspect = (
        await db.execute(
            select(SuspectDomain)
            .where(SuspectDomain.id == suspect_domain_id)
            .where(SuspectDomain.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if suspect is None:
        raise HTTPException(404, "suspect domain not found")

    existing = (
        await db.execute(
            select(BrandAction)
            .where(BrandAction.suspect_domain_id == suspect_domain_id)
            .where(
                BrandAction.status.in_(
                    [BrandActionStatus.QUEUED.value, BrandActionStatus.RUNNING.value]
                )
            )
            .order_by(desc(BrandAction.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return CreateBrandActionResponse(
            id=existing.id,
            status=existing.status,
            suspect_domain_id=suspect_domain_id,
        )

    action = BrandAction(
        organization_id=org_id,
        suspect_domain_id=suspect_domain_id,
        status=BrandActionStatus.QUEUED.value,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    background.add_task(_run_in_background, action.id)
    return CreateBrandActionResponse(
        id=action.id, status=action.status, suspect_domain_id=suspect_domain_id
    )


@router.get("/{action_id}", response_model=BrandActionDetail)
async def get_brand_action(
    action_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> BrandActionDetail:
    org_id = await get_system_org_id(db)
    action = (
        await db.execute(
            select(BrandAction)
            .where(BrandAction.id == action_id)
            .where(BrandAction.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if action is None:
        raise HTTPException(404, "brand action not found")
    return BrandActionDetail.model_validate(action)


@router.post(
    "/{action_id}/submit-takedown",
    response_model=SubmitTakedownResponse,
)
async def submit_takedown(
    action_id: uuid.UUID,
    payload: SubmitTakedownPayload,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> SubmitTakedownResponse:
    """Manually file the agent's takedown recommendation as a real
    ``TakedownTicket``. The agent does NOT auto-submit — this endpoint
    is the analyst's deliberate go-button.

    Refuses unless:
      * the action is in status ``completed``
      * the recommendation is ``takedown_now`` or ``takedown_after_review``

    Idempotent — calling a second time returns the existing ticket id.
    """
    from src.models.brand import SuspectDomain
    from src.models.brand_actions import (
        BrandActionRecommendation,
        BrandActionStatus,
    )
    from src.models.takedown import (
        TakedownPartner,
        TakedownState,
        TakedownTargetKind,
        TakedownTicket,
    )

    org_id = await get_system_org_id(db)
    action = (
        await db.execute(
            select(BrandAction)
            .where(BrandAction.id == action_id)
            .where(BrandAction.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if action is None:
        raise HTTPException(404, "brand action not found")

    if action.status != BrandActionStatus.COMPLETED.value:
        raise HTTPException(
            400,
            f"action must be completed (current={action.status})",
        )

    allowed_recs = {
        BrandActionRecommendation.TAKEDOWN_NOW.value,
        BrandActionRecommendation.TAKEDOWN_AFTER_REVIEW.value,
    }
    if action.recommendation not in allowed_recs:
        raise HTTPException(
            400,
            f"recommendation '{action.recommendation}' does not call for a takedown",
        )

    # Idempotent: existing ticket on this action → return it.
    if action.takedown_ticket_id is not None:
        existing = (
            await db.execute(
                select(TakedownTicket).where(
                    TakedownTicket.id == action.takedown_ticket_id
                )
            )
        ).scalar_one()
        return SubmitTakedownResponse(
            action_id=action_id,
            ticket_id=existing.id,
            partner=existing.partner,
            already_submitted=True,
        )

    suspect = (
        await db.execute(
            select(SuspectDomain).where(
                SuspectDomain.id == action.suspect_domain_id
            )
        )
    ).scalar_one_or_none()
    if suspect is None:
        raise HTTPException(
            400, "suspect domain no longer exists; cannot file takedown"
        )

    # Resolve partner: explicit override > agent suggestion > manual fallback.
    raw_partner = (
        payload.partner
        or action.suggested_partner
        or TakedownPartner.MANUAL.value
    ).lower()
    valid_partners = {p.value for p in TakedownPartner}
    if raw_partner not in valid_partners:
        raw_partner = TakedownPartner.MANUAL.value

    # Idempotency across paths — another flow may already have filed a
    # takedown for the same (org, target, partner) tuple (the schema's
    # ``uq_takedown_org_target_partner`` enforces this). If so, link the
    # existing ticket to the agent action instead of trying to insert a
    # duplicate that would 500 from a constraint violation.
    pre_existing = (
        await db.execute(
            select(TakedownTicket)
            .where(TakedownTicket.organization_id == org_id)
            .where(TakedownTicket.target_kind == TakedownTargetKind.SUSPECT_DOMAIN.value)
            .where(TakedownTicket.target_identifier == suspect.domain)
            .where(TakedownTicket.partner == raw_partner)
            .order_by(TakedownTicket.submitted_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if pre_existing is not None:
        action.takedown_ticket_id = pre_existing.id
        await db.commit()
        return SubmitTakedownResponse(
            action_id=action_id,
            ticket_id=pre_existing.id,
            partner=pre_existing.partner,
            already_submitted=True,
        )

    ticket = TakedownTicket(
        organization_id=org_id,
        partner=raw_partner,
        state=TakedownState.SUBMITTED.value,
        target_kind=TakedownTargetKind.SUSPECT_DOMAIN.value,
        target_identifier=suspect.domain,
        source_finding_id=suspect.id,
        submitted_by_user_id=getattr(user, "id", None) if user is not None else None,
        submitted_at=datetime.now(tz=__import__("datetime").timezone.utc),
        notes=(
            f"Filed via Brand Defender agent action {action.id}. "
            f"Confidence={action.confidence:.2f}; "
            f"signals={', '.join(action.risk_signals) or 'n/a'}."
        ),
    )
    db.add(ticket)
    await db.flush()

    action.takedown_ticket_id = ticket.id
    await db.commit()
    return SubmitTakedownResponse(
        action_id=action_id,
        ticket_id=ticket.id,
        partner=raw_partner,
        already_submitted=False,
    )


@router.get("", response_model=list[BrandActionListItem])
async def list_brand_actions(
    suspect_domain_id: uuid.UUID | None = Query(None),
    status: str | None = Query(None),
    recommendation: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> list[BrandActionListItem]:
    org_id = await get_system_org_id(db)
    stmt = (
        select(BrandAction)
        .where(BrandAction.organization_id == org_id)
        .order_by(desc(BrandAction.created_at))
        .limit(limit)
    )
    if suspect_domain_id is not None:
        stmt = stmt.where(BrandAction.suspect_domain_id == suspect_domain_id)
    if status is not None:
        stmt = stmt.where(BrandAction.status == status)
    if recommendation is not None:
        stmt = stmt.where(BrandAction.recommendation == recommendation)
    rows = (await db.execute(stmt)).scalars().all()
    return [BrandActionListItem.model_validate(r) for r in rows]
