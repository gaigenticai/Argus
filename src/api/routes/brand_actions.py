"""Brand Defender agent — API surface.

Mirrors the investigations route shape: kick off, list, detail. The
``submit_takedown`` endpoint takes the agent's recommendation and
hands it to the existing takedown adapter for the chosen partner;
that part is a thin pass-through, the agent never auto-submits.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
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
    # T56-style enrichment so the activity panel can render a useful
    # row without a second fetch per action.
    suspect_domain: str | None = None
    suspect_similarity: float | None = None
    suspect_state: str | None = None

    model_config = {"from_attributes": True}


class BrandActionDetail(BrandActionListItem):
    recommendation_reason: str | None
    trace: list[dict[str, Any]] | None
    error_message: str | None
    started_at: datetime | None
    plan: list[dict[str, Any]] | None = None
    # Token totals (T94) — surface to the FE so the cost estimator
    # can render $/run alongside duration. Null when upstream LLM
    # provider didn't surface usage on any iteration.
    input_tokens: int | None = None
    output_tokens: int | None = None


class RerunRequest(BaseModel):
    extra_context: str | None = Field(default=None, max_length=2000)


class ApprovePlanRequest(BaseModel):
    plan: list[dict[str, Any]] | None = None


class StatsResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    by_recommendation: dict[str, int]
    avg_confidence: float | None
    avg_iterations: float
    avg_duration_ms: float | None
    top_risk_signals: list[dict[str, Any]]
    defence_to_takedown_rate: float
    daily: list[dict[str, Any]]


class CompareDiff(BaseModel):
    a_id: uuid.UUID
    b_id: uuid.UUID
    same_suspect: bool
    iteration_delta: int
    duration_delta_ms: int | None
    confidence_delta: float | None
    recommendation_a: str | None
    recommendation_b: str | None
    risk_signals_added: list[str]
    risk_signals_removed: list[str]
    tools_added: list[str]
    tools_removed: list[str]


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


@router.post(
    "/{action_id}/rerun",
    response_model=CreateBrandActionResponse,
    status_code=202,
)
async def rerun_brand_action(
    action_id: uuid.UUID,
    background: BackgroundTasks,
    body: RerunRequest | None = None,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CreateBrandActionResponse:
    """Spawn a new brand-action on the same suspect (T82 pattern).

    Optional ``extra_context`` is rendered as an analyst hint in the
    new run's seed turn. Original row stays untouched.
    """
    org_id = await get_system_org_id(db)
    src = (
        await db.execute(
            select(BrandAction)
            .where(BrandAction.id == action_id)
            .where(BrandAction.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if src is None:
        raise HTTPException(404, "brand action not found")

    extra = body.extra_context.strip() if body and body.extra_context else None
    plan = [{"kind": "extra_context", "text": extra}] if extra else None

    action = BrandAction(
        organization_id=org_id,
        suspect_domain_id=src.suspect_domain_id,
        status=BrandActionStatus.QUEUED.value,
        plan=plan,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    background.add_task(_run_in_background, action.id)
    return CreateBrandActionResponse(
        id=action.id, status=action.status, suspect_domain_id=src.suspect_domain_id,
    )


@router.post(
    "/{action_id}/approve-plan",
    response_model=CreateBrandActionResponse,
)
async def approve_plan(
    action_id: uuid.UUID,
    body: ApprovePlanRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CreateBrandActionResponse:
    """Resume a plan-approval-paused brand-action."""
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
    if action.status != BrandActionStatus.AWAITING_PLAN_APPROVAL.value:
        raise HTTPException(
            409,
            f"brand action is {action.status}, not awaiting_plan_approval",
        )
    if body.plan is not None:
        action.plan = body.plan
    action.status = BrandActionStatus.RUNNING.value
    await db.commit()
    background.add_task(_run_in_background, action.id)
    return CreateBrandActionResponse(
        id=action.id, status=action.status, suspect_domain_id=action.suspect_domain_id,
    )


@router.get("/{action_id}/stream")
async def stream_brand_action(
    action_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    """Live SSE stream of agent steps for one brand-action.

    Replays persisted trace as initial burst, then streams new events.
    Closes on terminal status (completed / failed).
    """
    from src.core.brand_action_events import BrandActionEventBus, bus

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

    queue = bus.subscribe(action_id)

    async def event_stream():
        try:
            for step in (action.trace or []):
                yield BrandActionEventBus.to_sse({
                    "kind": "step",
                    "iteration": step.get("iteration"),
                    "tool": step.get("tool"),
                    "thought": step.get("thought"),
                    "args": step.get("args"),
                    "result": step.get("result"),
                    "duration_ms": step.get("duration_ms"),
                    "brand_action_id": str(action_id),
                    "replay": True,
                })
            if action.status in (
                BrandActionStatus.COMPLETED.value,
                BrandActionStatus.FAILED.value,
            ):
                yield BrandActionEventBus.to_sse({
                    "kind": "stopped",
                    "status": action.status,
                    "recommendation": action.recommendation,
                    "confidence": action.confidence,
                    "iterations": action.iterations,
                    "duration_ms": action.duration_ms,
                    "brand_action_id": str(action_id),
                    "replay": True,
                })
                return

            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield BrandActionEventBus.to_sse(ev)
                    if ev.get("kind") == "stopped":
                        break
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(action_id, queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> StatsResponse:
    """Brand-defender analytics — drives /brand/stats page.

    Defence→takedown conversion rate measures how often a completed
    action with takedown_now / takedown_after_review actually got a
    real takedown_ticket_id assigned.
    """
    org_id = await get_system_org_id(db)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = (
        select(BrandAction)
        .where(BrandAction.organization_id == org_id)
        .where(BrandAction.created_at >= cutoff)
    )
    rows: list[BrandAction] = list((await db.execute(q)).scalars().all())
    total = len(rows)

    by_status: dict[str, int] = {}
    by_rec: dict[str, int] = {}
    for r in rows:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        if r.recommendation:
            by_rec[r.recommendation] = by_rec.get(r.recommendation, 0) + 1

    confs = [r.confidence for r in rows if r.confidence is not None]
    avg_conf = sum(confs) / len(confs) if confs else None
    iters = [r.iterations for r in rows if r.iterations]
    avg_iters = sum(iters) / len(iters) if iters else 0.0
    durs = [r.duration_ms for r in rows if r.duration_ms]
    avg_dur = sum(durs) / len(durs) if durs else None

    rs_counter: dict[str, int] = {}
    for r in rows:
        for s in (r.risk_signals or []):
            rs_counter[s] = rs_counter.get(s, 0) + 1
    top_rs = sorted(
        [{"risk_signal": k, "count": v} for k, v in rs_counter.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:8]

    # Defence→takedown conversion: of completed runs with a recommendation
    # of takedown_now or takedown_after_review, how many had a ticket
    # filed against them?
    eligible = [
        r for r in rows
        if r.status == BrandActionStatus.COMPLETED.value
        and r.recommendation in ("takedown_now", "takedown_after_review")
    ]
    converted = sum(1 for r in eligible if r.takedown_ticket_id)
    conv_rate = converted / len(eligible) if eligible else 0.0

    daily_buckets: dict[str, dict[str, int]] = {}
    for r in rows:
        day = r.created_at.date().isoformat()
        b = daily_buckets.setdefault(
            day, {"total": 0, "completed": 0, "failed": 0, "takedown_now": 0}
        )
        b["total"] += 1
        if r.status == BrandActionStatus.COMPLETED.value:
            b["completed"] += 1
        elif r.status == BrandActionStatus.FAILED.value:
            b["failed"] += 1
        if r.recommendation == "takedown_now":
            b["takedown_now"] += 1
    daily = [{"date": k, **v} for k, v in sorted(daily_buckets.items())]

    return StatsResponse(
        total=total,
        by_status=by_status,
        by_recommendation=by_rec,
        avg_confidence=avg_conf,
        avg_iterations=avg_iters,
        avg_duration_ms=avg_dur,
        top_risk_signals=top_rs,
        defence_to_takedown_rate=conv_rate,
        daily=daily,
    )


@router.get("/compare", response_model=CompareDiff)
async def compare_brand_actions(
    ids: str = Query(..., description="Two action ids comma-separated"),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> CompareDiff:
    """Diff two brand-action runs against the same suspect.

    Useful when re-running after new live-probe / WHOIS evidence
    landed and the analyst wants to see what the agent learned.
    """
    parts = [p.strip() for p in ids.split(",") if p.strip()]
    if len(parts) != 2:
        raise HTTPException(422, "ids must be exactly two uuids, comma-separated")
    try:
        a_id, b_id = uuid.UUID(parts[0]), uuid.UUID(parts[1])
    except ValueError as exc:
        raise HTTPException(422, f"invalid uuid: {exc}") from exc

    org_id = await get_system_org_id(db)
    rows = list(
        (await db.execute(
            select(BrandAction)
            .where(BrandAction.id.in_([a_id, b_id]))
            .where(BrandAction.organization_id == org_id)
        )).scalars().all()
    )
    by_id = {r.id: r for r in rows}
    if a_id not in by_id or b_id not in by_id:
        raise HTTPException(404, "one or both actions not found")
    a, b = by_id[a_id], by_id[b_id]
    same_suspect = a.suspect_domain_id == b.suspect_domain_id
    if not same_suspect:
        raise HTTPException(
            422,
            "actions are on different suspects — compare requires same suspect",
        )

    def _diff(prev: list, new: list) -> tuple[list[str], list[str]]:
        ps = set(prev or [])
        ns = set(new or [])
        return sorted(ns - ps), sorted(ps - ns)

    rs_added, rs_removed = _diff(a.risk_signals, b.risk_signals)

    def _tools_used(action: BrandAction) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for s in (action.trace or []):
            t = s.get("tool")
            if isinstance(t, str) and t not in seen:
                seen.add(t)
                ordered.append(t)
        return ordered

    tools_a, tools_b = _tools_used(a), _tools_used(b)
    tools_added, tools_removed = _diff(tools_a, tools_b)

    duration_delta = None
    if a.duration_ms is not None and b.duration_ms is not None:
        duration_delta = b.duration_ms - a.duration_ms
    confidence_delta = None
    if a.confidence is not None and b.confidence is not None:
        confidence_delta = b.confidence - a.confidence

    return CompareDiff(
        a_id=a.id, b_id=b.id,
        same_suspect=same_suspect,
        iteration_delta=(b.iterations - a.iterations),
        duration_delta_ms=duration_delta,
        confidence_delta=confidence_delta,
        recommendation_a=a.recommendation,
        recommendation_b=b.recommendation,
        risk_signals_added=rs_added,
        risk_signals_removed=rs_removed,
        tools_added=tools_added,
        tools_removed=tools_removed,
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
    detail = BrandActionDetail.model_validate(action)
    suspect = await db.get(SuspectDomain, action.suspect_domain_id)
    if suspect is not None:
        detail.suspect_domain = suspect.domain
        detail.suspect_similarity = suspect.similarity
        detail.suspect_state = suspect.state
    return detail


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
    """List brand-actions with the seed suspect joined inline (T56-style)
    so the dashboard can render meaningful rows without a second fetch
    per action.
    """
    org_id = await get_system_org_id(db)
    stmt = (
        select(
            BrandAction,
            SuspectDomain.domain,
            SuspectDomain.similarity,
            SuspectDomain.state,
        )
        .join(SuspectDomain, BrandAction.suspect_domain_id == SuspectDomain.id)
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
    rows = (await db.execute(stmt)).all()
    items: list[BrandActionListItem] = []
    for action, domain, similarity, sus_state in rows:
        item = BrandActionListItem.model_validate(action)
        item.suspect_domain = domain
        item.suspect_similarity = similarity
        item.suspect_state = sus_state
        items.append(item)
    return items
