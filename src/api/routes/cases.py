"""Case Management API.

Endpoints
---------
    POST   /cases                              create a case
    GET    /cases                              list with filters
    GET    /cases/count                        per-state / per-severity totals
    GET    /cases/{id}                         full detail (with findings, comments, transitions)
    PATCH  /cases/{id}                         update meta fields
    DELETE /cases/{id}                         hard delete (admin or owner only)
    POST   /cases/{id}/transitions             state machine transition
    POST   /cases/{id}/findings                link an alert (must belong to same org)
    DELETE /cases/{id}/findings/{alert_id}     unlink an alert
    POST   /cases/{id}/comments                add comment
    PATCH  /cases/{id}/comments/{comment_id}   edit (author only, within 15 min)
    DELETE /cases/{id}/comments/{comment_id}   soft-delete (author or admin)

State machine is enforced by ``is_transition_allowed``. Reopens are
allowed (closed → open) but require a non-empty reason.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction, UserRole
from src.models.cases import (
    ALLOWED_TRANSITIONS,
    Case,
    CaseComment,
    CaseFinding,
    CaseSeverity,
    CaseState,
    CaseStateTransition,
    is_transition_allowed,
)
from src.models.threat import Alert, Asset, Organization
from src.storage.database import get_session

router = APIRouter(prefix="/cases", tags=["Operations"])

COMMENT_EDIT_WINDOW = timedelta(minutes=15)


# --- Schemas ------------------------------------------------------------


class CaseCreate(BaseModel):
    organization_id: uuid.UUID
    title: str = Field(min_length=1, max_length=500)
    summary: str | None = None
    severity: CaseSeverity = CaseSeverity.MEDIUM
    assignee_user_id: uuid.UUID | None = None
    tags: list[str] = Field(default_factory=list)
    primary_asset_id: uuid.UUID | None = None
    sla_due_at: datetime | None = None
    initial_alert_ids: list[uuid.UUID] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    summary: str | None = None
    severity: CaseSeverity | None = None
    assignee_user_id: uuid.UUID | None = None
    tags: list[str] | None = None
    primary_asset_id: uuid.UUID | None = None
    sla_due_at: datetime | None = None


class TransitionRequest(BaseModel):
    to_state: CaseState
    reason: str | None = None


class FindingLink(BaseModel):
    alert_id: uuid.UUID
    is_primary: bool = False
    reason: str | None = None


class CommentCreate(BaseModel):
    body: str = Field(min_length=1)


class CommentUpdate(BaseModel):
    body: str = Field(min_length=1)


class FindingResponse(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    is_primary: bool
    linked_by_user_id: uuid.UUID | None
    link_reason: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CommentResponse(BaseModel):
    id: uuid.UUID
    author_user_id: uuid.UUID | None
    body: str
    edited_at: datetime | None
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TransitionResponse(BaseModel):
    id: uuid.UUID
    from_state: str | None
    to_state: str
    reason: str | None
    transitioned_by_user_id: uuid.UUID | None
    transitioned_at: datetime

    model_config = {"from_attributes": True}


class CaseResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    summary: str | None
    severity: str
    state: str
    owner_user_id: uuid.UUID | None
    assignee_user_id: uuid.UUID | None
    tags: list[str]
    sla_due_at: datetime | None
    first_response_at: datetime | None
    closed_at: datetime | None
    closed_by_user_id: uuid.UUID | None
    close_reason: str | None
    primary_asset_id: uuid.UUID | None
    extra: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CaseDetailResponse(CaseResponse):
    findings: list[FindingResponse]
    comments: list[CommentResponse]
    transitions: list[TransitionResponse]


class CaseCounts(BaseModel):
    total: int
    by_state: dict[str, int]
    by_severity: dict[str, int]
    overdue: int


# --- Helpers ------------------------------------------------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


async def _get_case_or_404(db: AsyncSession, case_id: uuid.UUID) -> Case:
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    return case


async def _ensure_alert_in_org(
    db: AsyncSession, alert_id: uuid.UUID, organization_id: uuid.UUID
) -> Alert:
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if alert.organization_id != organization_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Alert belongs to a different organization",
        )
    return alert


# --- Endpoints ----------------------------------------------------------


@router.post("", response_model=CaseResponse, status_code=201)
async def create_case(
    body: CaseCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    if body.primary_asset_id is not None:
        asset = await db.get(Asset, body.primary_asset_id)
        if not asset or asset.organization_id != body.organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "primary_asset_id refers to an asset in a different organization",
            )

    case = Case(
        organization_id=body.organization_id,
        title=body.title.strip(),
        summary=body.summary,
        severity=body.severity.value,
        state=CaseState.OPEN.value,
        owner_user_id=analyst.id,
        assignee_user_id=body.assignee_user_id,
        tags=body.tags,
        primary_asset_id=body.primary_asset_id,
        sla_due_at=body.sla_due_at,
    )
    db.add(case)
    await db.flush()

    # Initial state record
    db.add(
        CaseStateTransition(
            case_id=case.id,
            from_state=None,
            to_state=CaseState.OPEN.value,
            reason="initial creation",
            transitioned_by_user_id=analyst.id,
        )
    )

    # Link any initial alerts
    for alert_id in body.initial_alert_ids:
        alert = await _ensure_alert_in_org(db, alert_id, body.organization_id)
        db.add(
            CaseFinding(
                case_id=case.id,
                alert_id=alert.id,
                is_primary=False,
                linked_by_user_id=analyst.id,
            )
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_CREATE,
        user=analyst,
        resource_type="case",
        resource_id=str(case.id),
        details={
            "organization_id": str(body.organization_id),
            "severity": body.severity.value,
            "initial_findings": len(body.initial_alert_ids),
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(case)
    return case


@router.get("", response_model=list[CaseResponse])
async def list_cases(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: CaseState | None = None,
    severity: CaseSeverity | None = None,
    assignee_user_id: uuid.UUID | None = None,
    tag: str | None = None,
    q: str | None = None,
    overdue: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    query = select(Case).where(Case.organization_id == organization_id)
    if state is not None:
        query = query.where(Case.state == state.value)
    if severity is not None:
        query = query.where(Case.severity == severity.value)
    if assignee_user_id is not None:
        query = query.where(Case.assignee_user_id == assignee_user_id)
    if tag is not None:
        query = query.where(Case.tags.any(tag))
    if q:
        query = query.where(Case.title.ilike(f"%{q}%"))
    if overdue is True:
        query = query.where(
            and_(
                Case.sla_due_at.is_not(None),
                Case.sla_due_at < datetime.now(timezone.utc),
                Case.state != CaseState.CLOSED.value,
            )
        )

    query = query.order_by(Case.updated_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/count", response_model=CaseCounts)
async def count_cases(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    by_state = {
        row[0]: row[1]
        for row in (
            await db.execute(
                select(Case.state, func.count())
                .where(Case.organization_id == organization_id)
                .group_by(Case.state)
            )
        ).all()
    }
    by_sev = {
        row[0]: row[1]
        for row in (
            await db.execute(
                select(Case.severity, func.count())
                .where(Case.organization_id == organization_id)
                .group_by(Case.severity)
            )
        ).all()
    }
    overdue = (
        await db.execute(
            select(func.count())
            .select_from(Case)
            .where(
                and_(
                    Case.organization_id == organization_id,
                    Case.sla_due_at.is_not(None),
                    Case.sla_due_at < datetime.now(timezone.utc),
                    Case.state != CaseState.CLOSED.value,
                )
            )
        )
    ).scalar() or 0

    return CaseCounts(
        total=sum(by_state.values()),
        by_state=by_state,
        by_severity=by_sev,
        overdue=overdue,
    )


@router.get("/{case_id}", response_model=CaseDetailResponse)
async def get_case(
    case_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Case)
        .where(Case.id == case_id)
        .options(
            selectinload(Case.findings),
            selectinload(Case.comments),
            selectinload(Case.transitions),
        )
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    # Hide soft-deleted comments
    visible_comments = [c for c in case.comments if not c.is_deleted]
    return CaseDetailResponse(
        id=case.id,
        organization_id=case.organization_id,
        title=case.title,
        summary=case.summary,
        severity=case.severity,
        state=case.state,
        owner_user_id=case.owner_user_id,
        assignee_user_id=case.assignee_user_id,
        tags=case.tags,
        sla_due_at=case.sla_due_at,
        first_response_at=case.first_response_at,
        closed_at=case.closed_at,
        closed_by_user_id=case.closed_by_user_id,
        close_reason=case.close_reason,
        primary_asset_id=case.primary_asset_id,
        extra=case.extra,
        created_at=case.created_at,
        updated_at=case.updated_at,
        findings=[FindingResponse.model_validate(f) for f in case.findings],
        comments=[CommentResponse.model_validate(c) for c in visible_comments],
        transitions=[TransitionResponse.model_validate(t) for t in case.transitions],
    )


@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: uuid.UUID,
    body: CaseUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await _get_case_or_404(db, case_id)
    if case.state == CaseState.CLOSED.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Closed case is read-only. Reopen via /transitions first.",
        )

    changes: dict[str, Any] = {}
    if body.title is not None:
        case.title = body.title.strip()
        changes["title"] = case.title
    if body.summary is not None:
        case.summary = body.summary
        changes["summary"] = True
    if body.severity is not None:
        case.severity = body.severity.value
        changes["severity"] = body.severity.value
    if body.assignee_user_id is not None:
        case.assignee_user_id = body.assignee_user_id
        changes["assignee_user_id"] = str(body.assignee_user_id)
    if body.tags is not None:
        case.tags = body.tags
        changes["tags"] = body.tags
    if body.sla_due_at is not None:
        case.sla_due_at = body.sla_due_at
        changes["sla_due_at"] = body.sla_due_at.isoformat()
    if body.primary_asset_id is not None:
        asset = await db.get(Asset, body.primary_asset_id)
        if not asset or asset.organization_id != case.organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "primary_asset_id is in a different organization",
            )
        case.primary_asset_id = body.primary_asset_id
        changes["primary_asset_id"] = str(body.primary_asset_id)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_UPDATE,
        user=analyst,
        resource_type="case",
        resource_id=str(case.id),
        details={"changes": changes},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(case)
    return case


@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await _get_case_or_404(db, case_id)
    # Only owner or admin may delete
    if case.owner_user_id != analyst.id and analyst.role != UserRole.ADMIN.value:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only the case owner or an admin may delete a case",
        )
    org_id = case.organization_id
    title = case.title
    await db.delete(case)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_DELETE,
        user=analyst,
        resource_type="case",
        resource_id=str(case_id),
        details={"organization_id": str(org_id), "title": title},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.post("/{case_id}/transitions", response_model=CaseResponse)
async def transition_case(
    case_id: uuid.UUID,
    body: TransitionRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await _get_case_or_404(db, case_id)
    target = body.to_state.value
    if target == case.state:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Case is already in state {target}"
        )
    if not is_transition_allowed(case.state, target):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Transition {case.state} → {target} is not allowed",
        )
    if target == CaseState.OPEN.value and case.state == CaseState.CLOSED.value:
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Reopening a closed case requires a non-empty reason",
            )

    from_state = case.state
    case.state = target
    now = datetime.now(timezone.utc)

    # First-response timestamp
    if (
        case.first_response_at is None
        and target in {CaseState.TRIAGED.value, CaseState.IN_PROGRESS.value}
    ):
        case.first_response_at = now

    if target == CaseState.CLOSED.value:
        case.closed_at = now
        case.closed_by_user_id = analyst.id
        case.close_reason = body.reason

    # Reopen clears closed metadata
    if target == CaseState.OPEN.value and from_state == CaseState.CLOSED.value:
        case.closed_at = None
        case.closed_by_user_id = None
        case.close_reason = None

    db.add(
        CaseStateTransition(
            case_id=case.id,
            from_state=from_state,
            to_state=target,
            reason=body.reason,
            transitioned_by_user_id=analyst.id,
            transitioned_at=now,
        )
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_TRANSITION,
        user=analyst,
        resource_type="case",
        resource_id=str(case.id),
        details={"from": from_state, "to": target, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(case)
    return case


# --- Findings -----------------------------------------------------------


@router.post("/{case_id}/findings", response_model=FindingResponse, status_code=201)
async def link_finding(
    case_id: uuid.UUID,
    body: FindingLink,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await _get_case_or_404(db, case_id)
    alert = await _ensure_alert_in_org(db, body.alert_id, case.organization_id)

    finding = CaseFinding(
        case_id=case.id,
        alert_id=alert.id,
        is_primary=body.is_primary,
        linked_by_user_id=analyst.id,
        link_reason=body.reason,
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Alert is already linked to this case"
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_FINDING_LINK,
        user=analyst,
        resource_type="case_finding",
        resource_id=str(finding.id),
        details={
            "case_id": str(case.id),
            "alert_id": str(alert.id),
            "is_primary": body.is_primary,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.delete("/{case_id}/findings/{alert_id}", status_code=204)
async def unlink_finding(
    case_id: uuid.UUID,
    alert_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await _get_case_or_404(db, case_id)
    result = await db.execute(
        select(CaseFinding).where(
            and_(
                CaseFinding.case_id == case.id,
                CaseFinding.alert_id == alert_id,
            )
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding link not found")

    finding_id = finding.id
    await db.delete(finding)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_FINDING_UNLINK,
        user=analyst,
        resource_type="case_finding",
        resource_id=str(finding_id),
        details={"case_id": str(case.id), "alert_id": str(alert_id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


# --- Comments -----------------------------------------------------------


@router.post("/{case_id}/comments", response_model=CommentResponse, status_code=201)
async def add_comment(
    case_id: uuid.UUID,
    body: CommentCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await _get_case_or_404(db, case_id)
    if case.state == CaseState.CLOSED.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cannot comment on a closed case. Reopen first.",
        )

    comment = CaseComment(
        case_id=case.id,
        author_user_id=analyst.id,
        body=body.body.strip(),
    )
    db.add(comment)
    await db.flush()

    if case.first_response_at is None:
        case.first_response_at = datetime.now(timezone.utc)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_COMMENT_ADD,
        user=analyst,
        resource_type="case_comment",
        resource_id=str(comment.id),
        details={"case_id": str(case.id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(comment)
    return comment


@router.patch("/{case_id}/comments/{comment_id}", response_model=CommentResponse)
async def edit_comment(
    case_id: uuid.UUID,
    comment_id: uuid.UUID,
    body: CommentUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    comment = await db.get(CaseComment, comment_id)
    if not comment or comment.case_id != case_id or comment.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Comment not found")
    if comment.author_user_id != analyst.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only the author may edit a comment"
        )
    if datetime.now(timezone.utc) - comment.created_at > COMMENT_EDIT_WINDOW:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Edit window of {COMMENT_EDIT_WINDOW} has elapsed",
        )

    comment.body = body.body.strip()
    comment.edited_at = datetime.now(timezone.utc)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_COMMENT_EDIT,
        user=analyst,
        resource_type="case_comment",
        resource_id=str(comment.id),
        details={"case_id": str(case_id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(comment)
    return comment


@router.delete("/{case_id}/comments/{comment_id}", status_code=204)
async def delete_comment(
    case_id: uuid.UUID,
    comment_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    comment = await db.get(CaseComment, comment_id)
    if not comment or comment.case_id != case_id or comment.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Comment not found")
    if (
        comment.author_user_id != analyst.id
        and analyst.role != UserRole.ADMIN.value
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only the author or an admin may delete a comment",
        )

    comment.is_deleted = True
    comment.deleted_at = datetime.now(timezone.utc)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.CASE_COMMENT_DELETE,
        user=analyst,
        resource_type="case_comment",
        resource_id=str(comment.id),
        details={"case_id": str(case_id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None
