"""Playbook execution API — preview / execute / approve / step-advance / cancel / history.

Backs the AI Executive Briefing's "Open →" drawer plus the
``/playbooks/history`` and ``/playbooks/approvals`` pages.

Routes (all under the ``/exec`` prefix from
:mod:`src.api.routes.exec_briefing`'s router family — but mounted at
this module's own ``/playbooks`` sub-prefix):

    GET  /exec/playbook-catalog
    POST /exec/playbook-preview
    POST /exec/playbook-execute
    POST /exec/playbook-approve
    POST /exec/playbook-deny
    POST /exec/playbook-step-advance
    POST /exec/playbook-cancel
    GET  /exec/playbook-history
    GET  /exec/playbook-pending-approvals
    GET  /exec/playbook-execution/{execution_id}

State-machine rules live in :mod:`src.models.playbooks`. We always
``audit_log`` and never mutate state without ``commit()`` so an
operator who refreshes mid-flow always sees an authoritative status.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routes.organizations import _client_meta
from src.core.auth import AdminUser, AnalystUser, audit_log
from src.core.exec_playbooks import (
    Playbook,
    PlaybookNotFound,
    StepResult,
    applicable_catalog,
    get_playbook,
)
from src.models.auth import AuditAction, User, UserRole
from src.models.playbooks import (
    PlaybookExecution,
    PlaybookStatus,
    PlaybookTrigger,
    is_playbook_transition_allowed,
    is_terminal,
)
from src.models.threat import Organization
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/exec", tags=["External Surface"])


# ----------------------------------------------------------------------
# Pydantic request / response models
# ----------------------------------------------------------------------


class PlaybookStepDescriptor(BaseModel):
    step_id: str
    title: str
    description: str


class PlaybookDescriptor(BaseModel):
    """Catalog-level view of a Playbook — no callables exposed."""

    id: str
    title: str
    category: str
    description: str
    cta_label: str | None = None
    requires_approval: bool
    requires_input: bool
    permission: str
    input_schema: dict[str, Any] | None = None
    total_steps: int
    steps: list[PlaybookStepDescriptor]


class PlaybookCatalogResponse(BaseModel):
    items: list[PlaybookDescriptor]


class AffectedItemDTO(BaseModel):
    id: str
    label: str
    sub_label: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PreviewResponse(BaseModel):
    summary: str
    affected_items: list[AffectedItemDTO]
    warnings: list[str]
    can_execute: bool
    blocker_reason: str | None
    instructions: list[str]
    step_index: int
    step_id: str
    step_title: str
    total_steps: int


class PreviewRequest(BaseModel):
    playbook_id: str
    organization_id: uuid.UUID
    params: dict[str, Any] = Field(default_factory=dict)
    step_index: int | None = None  # default = current step on the execution
    execution_id: uuid.UUID | None = None  # tie preview to existing run for prior_results


class ExecuteRequest(BaseModel):
    playbook_id: str
    organization_id: uuid.UUID
    params: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(..., min_length=8, max_length=100)
    briefing_action_index: int | None = None
    triggered_from: PlaybookTrigger = PlaybookTrigger.MANUAL


class ApproveRequest(BaseModel):
    execution_id: uuid.UUID
    note: str | None = None


class DenyRequest(BaseModel):
    execution_id: uuid.UUID
    reason: str = Field(..., min_length=1, max_length=2000)


class StepAdvanceRequest(BaseModel):
    execution_id: uuid.UUID


class CancelRequest(BaseModel):
    execution_id: uuid.UUID
    reason: str | None = None


class StepResultDTO(BaseModel):
    step: int
    step_id: str
    ok: bool
    summary: str
    items: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    completed_at: datetime


class ExecutionResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    playbook_id: str
    status: PlaybookStatus
    params: dict[str, Any]
    current_step_index: int
    total_steps: int
    step_results: list[StepResultDTO]
    requested_by_user_id: uuid.UUID | None
    approver_user_id: uuid.UUID | None
    approval_note: str | None
    denial_reason: str | None
    error_message: str | None
    triggered_from: PlaybookTrigger
    briefing_action_index: int | None
    case_id: uuid.UUID | None = None
    copilot_run_id: uuid.UUID | None = None
    created_at: datetime
    approved_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    failed_at: datetime | None


class HistoryResponse(BaseModel):
    items: list[ExecutionResponse]
    total: int


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _descriptor(pb: Playbook) -> PlaybookDescriptor:
    return PlaybookDescriptor(
        id=pb.id,
        title=pb.title,
        category=pb.category,
        description=pb.description,
        cta_label=pb.cta_label,
        requires_approval=pb.requires_approval,
        requires_input=pb.requires_input,
        permission=pb.permission,
        input_schema=pb.input_schema,
        total_steps=pb.total_steps,
        steps=[
            PlaybookStepDescriptor(
                step_id=s.step_id, title=s.title, description=s.description,
            )
            for s in pb.steps
        ],
    )


def _to_dto(exec_: PlaybookExecution) -> ExecutionResponse:
    return ExecutionResponse(
        id=exec_.id,
        organization_id=exec_.organization_id,
        playbook_id=exec_.playbook_id,
        status=PlaybookStatus(exec_.status),
        params=exec_.params or {},
        current_step_index=exec_.current_step_index,
        total_steps=exec_.total_steps,
        step_results=[StepResultDTO(**sr) for sr in (exec_.step_results or [])],
        requested_by_user_id=exec_.requested_by_user_id,
        approver_user_id=exec_.approver_user_id,
        approval_note=exec_.approval_note,
        denial_reason=exec_.denial_reason,
        error_message=exec_.error_message,
        triggered_from=PlaybookTrigger(exec_.triggered_from),
        briefing_action_index=exec_.briefing_action_index,
        case_id=exec_.case_id,
        copilot_run_id=exec_.copilot_run_id,
        created_at=exec_.created_at,
        approved_at=exec_.approved_at,
        started_at=exec_.started_at,
        completed_at=exec_.completed_at,
        failed_at=exec_.failed_at,
    )


def _resolve_playbook_or_404(playbook_id: str) -> Playbook:
    try:
        return get_playbook(playbook_id)
    except PlaybookNotFound:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Playbook {playbook_id!r} is not in the catalog. "
            f"It may have been retired — refresh the briefing to get a "
            f"current set of recommended actions.",
        )


async def _load_org_or_404(
    db: AsyncSession, organization_id: uuid.UUID
) -> Organization:
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return org


def _check_permission(playbook: Playbook, user: User) -> None:
    if playbook.permission == "admin" and user.role != UserRole.ADMIN.value:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Playbook {playbook.id!r} requires admin role to execute.",
        )


def _prior_results(exec_: PlaybookExecution | None) -> list[StepResult]:
    if not exec_ or not exec_.step_results:
        return []
    out: list[StepResult] = []
    for sr in exec_.step_results:
        out.append(StepResult(
            ok=bool(sr.get("ok", False)),
            summary=sr.get("summary", ""),
            items=list(sr.get("items") or []),
            error=sr.get("error"),
        ))
    return out


# ----------------------------------------------------------------------
# Catalog
# ----------------------------------------------------------------------


@router.get("/playbook-catalog", response_model=PlaybookCatalogResponse)
async def playbook_catalog(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    scope: str = Query(
        "all",
        regex="^(global|investigation|all)$",
        description=(
            "global = AI briefing / manual /playbooks page; "
            "investigation = Case Copilot per-case probes; "
            "all (default) = both, merged. The ActionDrawer always "
            "calls with the default so it can resolve any execution "
            "regardless of which surface created it — without ``all`` "
            "an investigation playbook opened from the approvals "
            "queue erroneously rendered as 'no longer in the catalog'."
        ),
    ),
    db: AsyncSession = Depends(get_session),
):
    """Return the playbooks applicable to the org's current snapshot.

    Imports the snapshot builder lazily to avoid a circular import with
    ``src.api.routes.exec_briefing``.
    """
    from src.api.routes.exec_briefing import _build_snapshot

    snap = await _build_snapshot(db, organization_id)
    if scope == "all":
        items = [
            _descriptor(pb)
            for pb in (
                applicable_catalog(snap, scope="global")
                + applicable_catalog(snap, scope="investigation")
            )
        ]
    else:
        items = [
            _descriptor(pb)
            for pb in applicable_catalog(snap, scope=scope)
        ]
    return PlaybookCatalogResponse(items=items)


# ----------------------------------------------------------------------
# Preview
# ----------------------------------------------------------------------


@router.post("/playbook-preview", response_model=PreviewResponse)
async def playbook_preview(
    body: PreviewRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    pb = _resolve_playbook_or_404(body.playbook_id)
    org = await _load_org_or_404(db, body.organization_id)

    exec_: PlaybookExecution | None = None
    if body.execution_id is not None:
        exec_ = await db.get(PlaybookExecution, body.execution_id)
        if exec_ is None or exec_.organization_id != body.organization_id:
            raise HTTPException(404, "Execution not found")

    step_index = body.step_index if body.step_index is not None else (
        exec_.current_step_index if exec_ else 0
    )
    if not 0 <= step_index < pb.total_steps:
        raise HTTPException(422, f"step_index {step_index} out of range")

    step = pb.step_at(step_index)
    preview = await step.preview(
        db, org, body.params or (exec_.params if exec_ else {}), _prior_results(exec_),
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.PLAYBOOK_PREVIEW,
        user=analyst,
        resource_type="playbook",
        resource_id=pb.id,
        details={
            "step_index": step_index,
            "step_id": step.step_id,
            "execution_id": str(body.execution_id) if body.execution_id else None,
            "summary": preview.summary,
            "affected_count": len(preview.affected_items),
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()

    return PreviewResponse(
        summary=preview.summary,
        affected_items=[
            AffectedItemDTO(
                id=item.id,
                label=item.label,
                sub_label=item.sub_label,
                metadata=item.metadata,
            )
            for item in preview.affected_items
        ],
        warnings=preview.warnings,
        can_execute=preview.can_execute,
        blocker_reason=preview.blocker_reason,
        instructions=preview.instructions,
        step_index=step_index,
        step_id=step.step_id,
        step_title=step.title,
        total_steps=pb.total_steps,
    )


# ----------------------------------------------------------------------
# Execute
# ----------------------------------------------------------------------


async def _persist_step_result(
    exec_: PlaybookExecution,
    step_index: int,
    step_id: str,
    result: StepResult,
) -> None:
    entry = {
        "step": step_index,
        "step_id": step_id,
        "ok": result.ok,
        "summary": result.summary,
        "items": result.items,
        "error": result.error,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    # SQLAlchemy treats JSONB list as opaque — append+reassign so the
    # change is detected.
    exec_.step_results = [*(exec_.step_results or []), entry]


async def _run_step_and_update_status(
    db: AsyncSession,
    org: Organization,
    user: User,
    pb: Playbook,
    exec_: PlaybookExecution,
    step_index: int,
) -> StepResult:
    step = pb.step_at(step_index)
    now = datetime.now(timezone.utc)
    if exec_.started_at is None:
        exec_.started_at = now

    try:
        result = await step.execute(
            db, org, exec_.params or {}, _prior_results(exec_), user,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "playbook %s step %s execution crashed for org %s",
            pb.id, step.step_id, org.id,
        )
        result = StepResult(
            ok=False,
            summary="Step execution crashed.",
            error=f"{type(exc).__name__}: {exc}",
        )

    await _persist_step_result(exec_, step_index, step.step_id, result)

    if not result.ok:
        exec_.status = PlaybookStatus.FAILED.value
        exec_.failed_at = datetime.now(timezone.utc)
        exec_.error_message = result.error or result.summary
        return result

    is_last_step = step_index >= pb.total_steps - 1
    if is_last_step:
        exec_.status = PlaybookStatus.COMPLETED.value
        exec_.completed_at = datetime.now(timezone.utc)
    else:
        exec_.status = PlaybookStatus.STEP_COMPLETE.value

    return result


@router.post("/playbook-execute", response_model=ExecutionResponse)
async def playbook_execute(
    body: ExecuteRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    pb = _resolve_playbook_or_404(body.playbook_id)
    _check_permission(pb, analyst)
    org = await _load_org_or_404(db, body.organization_id)

    # Idempotency dedupe — same key from the same org returns the
    # existing row instead of creating a duplicate.
    existing = (
        await db.execute(
            select(PlaybookExecution).where(
                and_(
                    PlaybookExecution.organization_id == org.id,
                    PlaybookExecution.idempotency_key == body.idempotency_key,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _to_dto(existing)

    initial_status = (
        PlaybookStatus.PENDING_APPROVAL.value
        if pb.requires_approval
        else PlaybookStatus.IN_PROGRESS.value
    )

    exec_ = PlaybookExecution(
        organization_id=org.id,
        playbook_id=pb.id,
        status=initial_status,
        params=body.params or {},
        current_step_index=0,
        total_steps=pb.total_steps,
        step_results=[],
        requested_by_user_id=analyst.id,
        idempotency_key=body.idempotency_key,
        triggered_from=body.triggered_from.value,
        briefing_action_index=body.briefing_action_index,
    )
    db.add(exec_)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        # Race: another request in flight created the same idempotency
        # key between our SELECT and INSERT. Reload and return it.
        existing = (
            await db.execute(
                select(PlaybookExecution).where(
                    and_(
                        PlaybookExecution.organization_id == org.id,
                        PlaybookExecution.idempotency_key == body.idempotency_key,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return _to_dto(existing)
        raise HTTPException(409, "Conflict on idempotency_key")

    if not pb.requires_approval:
        await _run_step_and_update_status(
            db, org, analyst, pb, exec_, step_index=0,
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.PLAYBOOK_EXECUTE,
        user=analyst,
        resource_type="playbook_execution",
        resource_id=str(exec_.id),
        details={
            "playbook_id": pb.id,
            "status": exec_.status,
            "triggered_from": exec_.triggered_from,
            "briefing_action_index": exec_.briefing_action_index,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(exec_)
    return _to_dto(exec_)


# ----------------------------------------------------------------------
# Approve / Deny  (admin only)
# ----------------------------------------------------------------------


@router.post("/playbook-approve", response_model=ExecutionResponse)
async def playbook_approve(
    body: ApproveRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    exec_ = await db.get(PlaybookExecution, body.execution_id)
    if exec_ is None:
        raise HTTPException(404, "Execution not found")
    if exec_.status != PlaybookStatus.PENDING_APPROVAL.value:
        raise HTTPException(
            409,
            f"Cannot approve from status {exec_.status!r}. "
            f"Only pending_approval rows are approvable.",
        )

    pb = _resolve_playbook_or_404(exec_.playbook_id)
    org = await _load_org_or_404(db, exec_.organization_id)

    # pending_approval → approved (allowed) → in_progress (allowed) → run step 0
    if not is_playbook_transition_allowed(exec_.status, "approved"):
        raise HTTPException(409, "Illegal transition")
    exec_.status = PlaybookStatus.APPROVED.value
    exec_.approver_user_id = admin.id
    exec_.approval_note = body.note
    exec_.approved_at = datetime.now(timezone.utc)

    # Immediately advance to in_progress and run step 0.
    if not is_playbook_transition_allowed(exec_.status, "in_progress"):
        raise HTTPException(500, "Approved → in_progress transition is not allowed")
    exec_.status = PlaybookStatus.IN_PROGRESS.value
    await _run_step_and_update_status(
        db, org, admin, pb, exec_, step_index=0,
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.PLAYBOOK_APPROVE,
        user=admin,
        resource_type="playbook_execution",
        resource_id=str(exec_.id),
        details={"playbook_id": exec_.playbook_id, "note": body.note},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(exec_)
    return _to_dto(exec_)


@router.post("/playbook-deny", response_model=ExecutionResponse)
async def playbook_deny(
    body: DenyRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    exec_ = await db.get(PlaybookExecution, body.execution_id)
    if exec_ is None:
        raise HTTPException(404, "Execution not found")
    if exec_.status != PlaybookStatus.PENDING_APPROVAL.value:
        raise HTTPException(
            409,
            f"Cannot deny from status {exec_.status!r}. "
            f"Only pending_approval rows are deniable.",
        )

    if not is_playbook_transition_allowed(exec_.status, "denied"):
        raise HTTPException(500, "pending_approval → denied is not allowed")

    exec_.status = PlaybookStatus.DENIED.value
    exec_.approver_user_id = admin.id
    exec_.denial_reason = body.reason

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.PLAYBOOK_DENY,
        user=admin,
        resource_type="playbook_execution",
        resource_id=str(exec_.id),
        details={"playbook_id": exec_.playbook_id, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(exec_)
    return _to_dto(exec_)


# ----------------------------------------------------------------------
# Step advance (multi-step)
# ----------------------------------------------------------------------


@router.post("/playbook-step-advance", response_model=ExecutionResponse)
async def playbook_step_advance(
    body: StepAdvanceRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    exec_ = await db.get(PlaybookExecution, body.execution_id)
    if exec_ is None:
        raise HTTPException(404, "Execution not found")
    if exec_.status != PlaybookStatus.STEP_COMPLETE.value:
        raise HTTPException(
            409,
            f"Cannot advance from status {exec_.status!r}. "
            f"Only step_complete rows can advance.",
        )

    pb = _resolve_playbook_or_404(exec_.playbook_id)
    _check_permission(pb, analyst)
    org = await _load_org_or_404(db, exec_.organization_id)

    next_index = exec_.current_step_index + 1
    if next_index >= pb.total_steps:
        raise HTTPException(
            409, "Already on the last step — nothing to advance to.",
        )

    if not is_playbook_transition_allowed(exec_.status, "in_progress"):
        raise HTTPException(500, "step_complete → in_progress not allowed")
    exec_.status = PlaybookStatus.IN_PROGRESS.value
    exec_.current_step_index = next_index

    await _run_step_and_update_status(
        db, org, analyst, pb, exec_, step_index=next_index,
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.PLAYBOOK_STEP_ADVANCE,
        user=analyst,
        resource_type="playbook_execution",
        resource_id=str(exec_.id),
        details={
            "playbook_id": exec_.playbook_id,
            "step_index": next_index,
            "result_status": exec_.status,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(exec_)
    return _to_dto(exec_)


# ----------------------------------------------------------------------
# Cancel
# ----------------------------------------------------------------------


@router.post("/playbook-cancel", response_model=ExecutionResponse)
async def playbook_cancel(
    body: CancelRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    exec_ = await db.get(PlaybookExecution, body.execution_id)
    if exec_ is None:
        raise HTTPException(404, "Execution not found")
    if is_terminal(exec_.status):
        raise HTTPException(409, f"Already {exec_.status} — cannot cancel.")
    if not is_playbook_transition_allowed(exec_.status, "cancelled"):
        raise HTTPException(409, f"Cannot cancel from status {exec_.status!r}")

    exec_.status = PlaybookStatus.CANCELLED.value
    if body.reason:
        # Stash reason in error_message — there's no dedicated cancel-reason
        # column and we don't want to grow the schema for a v1 nicety.
        exec_.error_message = f"cancelled: {body.reason}"

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.PLAYBOOK_CANCEL,
        user=analyst,
        resource_type="playbook_execution",
        resource_id=str(exec_.id),
        details={"playbook_id": exec_.playbook_id, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(exec_)
    return _to_dto(exec_)


# ----------------------------------------------------------------------
# History + pending-approvals + drill-down
# ----------------------------------------------------------------------


@router.get("/playbook-history", response_model=HistoryResponse)
async def playbook_history(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_session),
    status_filter: PlaybookStatus | None = Query(None, alias="status"),
    playbook_id: str | None = Query(None),
    case_id: uuid.UUID | None = Query(
        None,
        description=(
            "Filter to executions queued against a specific case "
            "(Case Copilot apply_suggestions creates these). Default "
            "is no filter — every org-scoped + case-scoped run."
        ),
    ),
    copilot_run_id: uuid.UUID | None = Query(
        None,
        description="Filter to executions queued by one Copilot run.",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    base = select(PlaybookExecution).where(
        PlaybookExecution.organization_id == organization_id
    )
    if status_filter is not None:
        base = base.where(PlaybookExecution.status == status_filter.value)
    if playbook_id:
        base = base.where(PlaybookExecution.playbook_id == playbook_id)
    if case_id is not None:
        base = base.where(PlaybookExecution.case_id == case_id)
    if copilot_run_id is not None:
        base = base.where(PlaybookExecution.copilot_run_id == copilot_run_id)

    total = (
        await db.execute(
            select(func.count()).select_from(base.subquery())
        )
    ).scalar_one() or 0

    rows = (
        await db.execute(
            base.order_by(PlaybookExecution.created_at.desc())
                .limit(limit)
                .offset(offset)
        )
    ).scalars().all()
    return HistoryResponse(
        items=[_to_dto(r) for r in rows],
        total=int(total),
    )


@router.get(
    "/playbook-pending-approvals", response_model=HistoryResponse
)
async def playbook_pending_approvals(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=200),
):
    rows = (
        await db.execute(
            select(PlaybookExecution)
            .where(
                and_(
                    PlaybookExecution.organization_id == organization_id,
                    PlaybookExecution.status
                    == PlaybookStatus.PENDING_APPROVAL.value,
                )
            )
            .order_by(PlaybookExecution.created_at.asc())
            .limit(limit)
        )
    ).scalars().all()
    return HistoryResponse(
        items=[_to_dto(r) for r in rows], total=len(rows),
    )


@router.get(
    "/playbook-execution/{execution_id}", response_model=ExecutionResponse
)
async def playbook_execution_get(
    execution_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    exec_ = await db.get(PlaybookExecution, execution_id)
    if exec_ is None:
        raise HTTPException(404, "Execution not found")
    return _to_dto(exec_)
