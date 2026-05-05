"""Investigation endpoints — kick off and inspect agentic investigations.

All routes scope to the system organisation. ``alert_id`` paths reject
alerts that don't belong to the system org.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.core.tenant import get_system_org_id
from src.models.investigations import (
    Investigation,
    InvestigationStatus,
    InvestigationStopReason,
)
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
    # T48 — surfaced on the list so the dashboard can colour-code
    # without a second fetch. Null for legacy rows / runs in flight.
    stop_reason: str | None = None
    final_confidence: float | None = None
    tools_used: list[str] | None = None
    # T56 — alert metadata joined inline so the list rows can show a
    # title instead of a uuid slice.
    alert_title: str | None = None
    alert_severity: str | None = None
    alert_category: str | None = None

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
    # T50 — null when the bridge doesn't expose token counts.
    input_tokens: int | None = None
    output_tokens: int | None = None
    # T57 — populated only when the run paused for plan approval.
    plan: list[dict[str, Any]] | None = None


class CreateInvestigationResponse(BaseModel):
    id: uuid.UUID
    status: str
    alert_id: uuid.UUID


class RerunRequest(BaseModel):
    """Optional analyst-supplied context the agent should consider on
    the new run. Prepended to the system prompt as a "prior analyst
    note" — the agent treats it as a hint, not a constraint."""
    extra_context: str | None = Field(default=None, max_length=2000)


class PromoteResponse(BaseModel):
    investigation_id: uuid.UUID
    case_id: uuid.UUID
    already_promoted: bool


class ApprovePlanRequest(BaseModel):
    """Resume a paused (awaiting_plan_approval) investigation.

    ``plan`` is optional: omit to approve the agent's plan as-is, or
    supply an edited plan to override. A plan is a list of tool names
    the agent should attempt in order; the agent retains discretion
    to stop early.
    """
    plan: list[dict[str, Any]] | None = None


class StopReasonCount(BaseModel):
    stop_reason: str
    count: int


class ToolCount(BaseModel):
    tool: str
    count: int


class ActorCount(BaseModel):
    actor: str
    count: int


class StatsResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    success_rate: float
    avg_iterations: float
    avg_duration_ms: float | None
    avg_final_confidence: float | None
    top_tools: list[ToolCount]
    top_actors: list[ActorCount]
    stop_reasons: list[StopReasonCount]
    daily: list[dict[str, Any]]  # [{date, total, completed, failed}]


class CompareDiff(BaseModel):
    a_id: uuid.UUID
    b_id: uuid.UUID
    same_alert: bool
    iteration_delta: int
    duration_delta_ms: int | None
    confidence_delta: float | None
    severity_a: str | None
    severity_b: str | None
    assessment_a: str | None
    assessment_b: str | None
    iocs_added: list[str]
    iocs_removed: list[str]
    actors_added: list[str]
    actors_removed: list[str]
    actions_added: list[str]
    actions_removed: list[str]
    tools_added: list[str]
    tools_removed: list[str]


# ---- Helpers --------------------------------------------------------


async def _enriched_list_item(db: AsyncSession, inv: Investigation) -> InvestigationListItem:
    """Join the seed alert and emit an enriched list item (T56).

    One alert lookup per row; for the small page sizes (≤100) the
    cost is negligible. If we ever paginate beyond that we'll switch
    to a single JOIN.
    """
    alert = await db.get(Alert, inv.alert_id)
    return InvestigationListItem(
        id=inv.id,
        alert_id=inv.alert_id,
        status=inv.status,
        severity_assessment=inv.severity_assessment,
        iterations=inv.iterations,
        model_id=inv.model_id,
        duration_ms=inv.duration_ms,
        created_at=inv.created_at,
        finished_at=inv.finished_at,
        case_id=inv.case_id,
        stop_reason=inv.stop_reason,
        final_confidence=inv.final_confidence,
        tools_used=inv.tools_used,
        alert_title=getattr(alert, "title", None),
        alert_severity=getattr(alert, "severity", None),
        alert_category=getattr(alert, "category", None),
    )


def _detail_from_row(inv: Investigation, alert: Alert | None) -> InvestigationDetail:
    return InvestigationDetail(
        id=inv.id,
        alert_id=inv.alert_id,
        status=inv.status,
        severity_assessment=inv.severity_assessment,
        iterations=inv.iterations,
        model_id=inv.model_id,
        duration_ms=inv.duration_ms,
        created_at=inv.created_at,
        finished_at=inv.finished_at,
        case_id=inv.case_id,
        stop_reason=inv.stop_reason,
        final_confidence=inv.final_confidence,
        tools_used=inv.tools_used,
        alert_title=getattr(alert, "title", None),
        alert_severity=getattr(alert, "severity", None),
        alert_category=getattr(alert, "category", None),
        final_assessment=inv.final_assessment,
        correlated_iocs=list(inv.correlated_iocs or []),
        correlated_actors=list(inv.correlated_actors or []),
        recommended_actions=list(inv.recommended_actions or []),
        trace=inv.trace,
        error_message=inv.error_message,
        started_at=inv.started_at,
        input_tokens=inv.input_tokens,
        output_tokens=inv.output_tokens,
        plan=inv.plan,
    )


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
    follow progress, or open the SSE stream at
    ``/investigations/{id}/stream`` for live trace.

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
                        InvestigationStatus.AWAITING_PLAN_APPROVAL.value,
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


@router.post(
    "/{investigation_id}/rerun",
    response_model=CreateInvestigationResponse,
    status_code=202,
)
async def rerun_investigation(
    investigation_id: uuid.UUID,
    background: BackgroundTasks,
    body: RerunRequest | None = None,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001
) -> CreateInvestigationResponse:
    """Spawn a NEW investigation on the same alert (T53).

    The original row stays untouched (audit trail intact). Optional
    ``extra_context`` is stashed on the new row's ``plan`` slot so the
    agent's first iteration sees it. Used to retry failed runs and
    to feed the agent late-arriving evidence ("you missed these IOCs").
    """
    org_id = await get_system_org_id(db)
    src = (
        await db.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .where(Investigation.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if src is None:
        raise HTTPException(404, "investigation not found")

    extra = (body.extra_context.strip() if body and body.extra_context else None)
    plan: list[dict[str, Any]] | None = None
    if extra:
        # Stash as a synthetic "plan" entry; the agent reads it as
        # extra context on the very first iteration.
        plan = [{"kind": "extra_context", "text": extra}]

    inv = Investigation(
        organization_id=org_id,
        alert_id=src.alert_id,
        status=InvestigationStatus.QUEUED.value,
        plan=plan,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    background.add_task(_run_in_background, inv.id)
    return CreateInvestigationResponse(
        id=inv.id, status=inv.status, alert_id=src.alert_id,
    )


@router.post(
    "/{investigation_id}/approve-plan",
    response_model=CreateInvestigationResponse,
)
async def approve_plan(
    investigation_id: uuid.UUID,
    body: ApprovePlanRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001
) -> CreateInvestigationResponse:
    """Resume a plan-approval-paused investigation (T57).

    The row's ``plan`` is replaced with the operator-edited plan
    (or kept as-is when the body's plan is omitted). Status flips
    back to ``running`` and the background runner picks up.
    """
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
    if inv.status != InvestigationStatus.AWAITING_PLAN_APPROVAL.value:
        raise HTTPException(
            409, f"investigation is {inv.status}, not awaiting_plan_approval"
        )
    if body.plan is not None:
        inv.plan = body.plan
    inv.status = InvestigationStatus.RUNNING.value
    await db.commit()
    background.add_task(_run_in_background, inv.id)
    return CreateInvestigationResponse(
        id=inv.id, status=inv.status, alert_id=inv.alert_id,
    )


@router.get("/{investigation_id}/stream")
async def stream_investigation(
    investigation_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001
):
    """Live SSE stream of agent steps for one investigation (T51).

    Connects to the per-investigation event bus and replays any
    already-persisted trace as the initial burst, then streams new
    events as the agent emits them. Closes when the run reaches a
    terminal status (completed / failed).
    """
    from src.core.investigation_events import InvestigationEventBus, bus

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

    queue = bus.subscribe(investigation_id)

    async def event_stream():
        # Replay persisted trace first so reconnecting clients catch up
        # without us replaying the whole loop. Each step gets the same
        # shape as live events.
        try:
            for step in (inv.trace or []):
                yield InvestigationEventBus.to_sse(
                    {
                        "kind": "step",
                        "iteration": step.get("iteration"),
                        "tool": step.get("tool"),
                        "thought": step.get("thought"),
                        "args": step.get("args"),
                        "result": step.get("result"),
                        "duration_ms": step.get("duration_ms"),
                        "investigation_id": str(investigation_id),
                        "replay": True,
                    }
                )
            # Already-terminal: emit one final ``stopped`` and close.
            if inv.status in (
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.FAILED.value,
            ):
                yield InvestigationEventBus.to_sse(
                    {
                        "kind": "stopped",
                        "status": inv.status,
                        "stop_reason": inv.stop_reason,
                        "final_confidence": inv.final_confidence,
                        "iterations": inv.iterations,
                        "duration_ms": inv.duration_ms,
                        "investigation_id": str(investigation_id),
                        "replay": True,
                    }
                )
                return

            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield InvestigationEventBus.to_sse(ev)
                    if ev.get("kind") == "stopped":
                        break
                except asyncio.TimeoutError:
                    # Heartbeat — keeps proxies (nginx / Next.js) from
                    # closing idle connections.
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(investigation_id, queue)

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
    user: AnalystUser = None,  # noqa: ARG001
) -> StatsResponse:
    """Investigation analytics — drives the /investigations/stats page.

    All metrics scoped to the system org and to the trailing N days
    (default 30). Counts include in-flight + terminal runs.
    """
    org_id = await get_system_org_id(db)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    base = (
        select(Investigation)
        .where(Investigation.organization_id == org_id)
        .where(Investigation.created_at >= cutoff)
    )
    rows: list[Investigation] = list((await db.execute(base)).scalars().all())
    total = len(rows)

    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r.status] = by_status.get(r.status, 0) + 1

    completed = by_status.get(InvestigationStatus.COMPLETED.value, 0)
    success_rate = (completed / total) if total else 0.0

    iters_with_value = [r.iterations for r in rows if r.iterations]
    avg_iters = (sum(iters_with_value) / len(iters_with_value)) if iters_with_value else 0.0

    durs = [r.duration_ms for r in rows if r.duration_ms]
    avg_dur = (sum(durs) / len(durs)) if durs else None

    confs = [r.final_confidence for r in rows if r.final_confidence is not None]
    avg_conf = (sum(confs) / len(confs)) if confs else None

    tool_counter: dict[str, int] = {}
    for r in rows:
        for t in (r.tools_used or []):
            tool_counter[t] = tool_counter.get(t, 0) + 1
    top_tools = sorted(
        ({"tool": k, "count": v} for k, v in tool_counter.items()),
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    actor_counter: dict[str, int] = {}
    for r in rows:
        for a in (r.correlated_actors or []):
            actor_counter[a] = actor_counter.get(a, 0) + 1
    top_actors = sorted(
        ({"actor": k, "count": v} for k, v in actor_counter.items()),
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    stop_counter: dict[str, int] = {}
    for r in rows:
        if r.stop_reason:
            stop_counter[r.stop_reason] = stop_counter.get(r.stop_reason, 0) + 1
    stop_dist = sorted(
        ({"stop_reason": k, "count": v} for k, v in stop_counter.items()),
        key=lambda x: x["count"],
        reverse=True,
    )

    daily_buckets: dict[str, dict[str, int]] = {}
    for r in rows:
        day = r.created_at.date().isoformat()
        b = daily_buckets.setdefault(day, {"total": 0, "completed": 0, "failed": 0})
        b["total"] += 1
        if r.status == InvestigationStatus.COMPLETED.value:
            b["completed"] += 1
        elif r.status == InvestigationStatus.FAILED.value:
            b["failed"] += 1
    daily = [
        {"date": k, **v}
        for k, v in sorted(daily_buckets.items())
    ]

    return StatsResponse(
        total=total,
        by_status=by_status,
        success_rate=success_rate,
        avg_iterations=avg_iters,
        avg_duration_ms=avg_dur,
        avg_final_confidence=avg_conf,
        top_tools=[ToolCount(**t) for t in top_tools],
        top_actors=[ActorCount(**a) for a in top_actors],
        stop_reasons=[StopReasonCount(**s) for s in stop_dist],
        daily=daily,
    )


@router.get("/compare", response_model=CompareDiff)
async def compare_investigations(
    ids: str = Query(..., description="Two investigation ids, comma-separated"),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: ARG001
) -> CompareDiff:
    """Diff two investigations, typically two runs against the same alert.

    Useful when new IOCs land between runs and the analyst wants to
    see what the agent learned. 422 if the two runs are on different
    alerts (the comparison would be apples-to-oranges).
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
            select(Investigation)
            .where(Investigation.id.in_([a_id, b_id]))
            .where(Investigation.organization_id == org_id)
        )).scalars().all()
    )
    by_id = {r.id: r for r in rows}
    if a_id not in by_id or b_id not in by_id:
        raise HTTPException(404, "one or both investigations not found")
    a, b = by_id[a_id], by_id[b_id]
    same_alert = a.alert_id == b.alert_id
    if not same_alert:
        raise HTTPException(
            422,
            "investigations are on different alerts — compare requires same alert",
        )

    def _diff(prev: list, new: list) -> tuple[list[str], list[str]]:
        ps = set(prev or [])
        ns = set(new or [])
        return sorted(ns - ps), sorted(ps - ns)

    iocs_added, iocs_removed = _diff(a.correlated_iocs, b.correlated_iocs)
    actors_added, actors_removed = _diff(a.correlated_actors, b.correlated_actors)
    actions_added, actions_removed = _diff(a.recommended_actions, b.recommended_actions)
    tools_added, tools_removed = _diff(a.tools_used or [], b.tools_used or [])

    duration_delta = None
    if a.duration_ms is not None and b.duration_ms is not None:
        duration_delta = b.duration_ms - a.duration_ms
    confidence_delta = None
    if a.final_confidence is not None and b.final_confidence is not None:
        confidence_delta = b.final_confidence - a.final_confidence

    return CompareDiff(
        a_id=a.id, b_id=b.id,
        same_alert=same_alert,
        iteration_delta=(b.iterations - a.iterations),
        duration_delta_ms=duration_delta,
        confidence_delta=confidence_delta,
        severity_a=a.severity_assessment,
        severity_b=b.severity_assessment,
        assessment_a=a.final_assessment,
        assessment_b=b.final_assessment,
        iocs_added=iocs_added, iocs_removed=iocs_removed,
        actors_added=actors_added, actors_removed=actors_removed,
        actions_added=actions_added, actions_removed=actions_removed,
        tools_added=tools_added, tools_removed=tools_removed,
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
    alert = await db.get(Alert, inv.alert_id)
    return _detail_from_row(inv, alert)


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
    rows = list((await db.execute(stmt)).scalars().all())
    items: list[InvestigationListItem] = []
    for r in rows:
        items.append(await _enriched_list_item(db, r))
    return items
