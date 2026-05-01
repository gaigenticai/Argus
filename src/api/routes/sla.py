"""Phase 9 — SLA + Ticketing API.

Endpoints
---------
    POST   /sla/policies                       upsert policy for severity
    GET    /sla/policies?organization_id=…     list
    DELETE /sla/policies/{id}                  delete
    POST   /sla/evaluate?organization_id=…     evaluate all open cases
    GET    /sla/breaches?organization_id=…     list breach events

    POST   /sla/tickets                        bind external ticket to case
    GET    /sla/tickets?organization_id=…      list bindings
    PATCH  /sla/tickets/{id}                   update sync metadata
    DELETE /sla/tickets/{id}                   unbind
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.cases import Case
from src.models.sla import (
    ExternalTicketBinding,
    SlaBreachEvent,
    SlaPolicy,
    SlaSeverity,
    TicketSystem,
)
from src.models.threat import Organization
from src.sla.engine import evaluate_organization
from src.storage.database import get_session

router = APIRouter(prefix="/sla", tags=["Operations"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- Policies ---------------------------------------------------------


class SlaPolicyUpsert(BaseModel):
    organization_id: uuid.UUID
    severity: SlaSeverity
    first_response_minutes: int = Field(ge=1, le=60 * 24 * 90)
    remediation_minutes: int = Field(ge=1, le=60 * 24 * 365)
    description: str | None = None


class SlaPolicyResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    severity: str
    first_response_minutes: int
    remediation_minutes: int
    description: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/policies", response_model=SlaPolicyResponse, status_code=201)
async def upsert_policy(
    body: SlaPolicyUpsert,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if body.first_response_minutes >= body.remediation_minutes:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "first_response_minutes must be < remediation_minutes",
        )
    existing = (
        await db.execute(
            select(SlaPolicy).where(
                and_(
                    SlaPolicy.organization_id == body.organization_id,
                    SlaPolicy.severity == body.severity.value,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = SlaPolicy(
            organization_id=body.organization_id,
            severity=body.severity.value,
            first_response_minutes=body.first_response_minutes,
            remediation_minutes=body.remediation_minutes,
            description=body.description,
        )
        db.add(existing)
    else:
        existing.first_response_minutes = body.first_response_minutes
        existing.remediation_minutes = body.remediation_minutes
        existing.description = body.description
    await db.flush()
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SLA_POLICY_UPSERT,
        user=analyst,
        resource_type="sla_policy",
        resource_id=str(existing.id),
        details={
            "severity": body.severity.value,
            "first_response_minutes": body.first_response_minutes,
            "remediation_minutes": body.remediation_minutes,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(existing)
    return existing


@router.get("/policies", response_model=list[SlaPolicyResponse])
async def list_policies(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (
        await db.execute(
            select(SlaPolicy)
            .where(SlaPolicy.organization_id == organization_id)
            .order_by(SlaPolicy.severity)
        )
    ).scalars().all()
    return list(rows)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    p = await db.get(SlaPolicy, policy_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    await db.delete(p)
    await db.commit()
    return None


# --- Evaluate + breaches ---------------------------------------------


class EvaluationRow(BaseModel):
    case_id: uuid.UUID
    severity: str
    first_response_breached: bool
    remediation_breached: bool
    first_response_due_at: datetime | None
    remediation_due_at: datetime | None
    new_breaches: int


class EvaluateResponse(BaseModel):
    organization_id: uuid.UUID
    cases_evaluated: int
    new_breaches: int
    rows: list[EvaluationRow]


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_org(
    organization_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    results = await evaluate_organization(db, organization_id)
    new_breaches = sum(r.new_breaches for r in results)
    if new_breaches:
        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.SLA_BREACH_RECORDED,
            user=analyst,
            resource_type="organization",
            resource_id=str(organization_id),
            details={"new_breaches": new_breaches},
            ip_address=ip,
            user_agent=ua,
        )
    await db.commit()
    return EvaluateResponse(
        organization_id=organization_id,
        cases_evaluated=len(results),
        new_breaches=new_breaches,
        rows=[
            EvaluationRow(
                case_id=r.case_id,
                severity=r.severity,
                first_response_breached=r.first_response_breached,
                remediation_breached=r.remediation_breached,
                first_response_due_at=r.first_response_due_at,
                remediation_due_at=r.remediation_due_at,
                new_breaches=r.new_breaches,
            )
            for r in results
        ],
    )


class SlaBreachResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    case_id: uuid.UUID
    kind: str
    severity: str
    threshold_minutes: int
    detected_at: datetime
    notified: bool

    model_config = {"from_attributes": True}


@router.get("/breaches", response_model=list[SlaBreachResponse])
async def list_breaches(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    case_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(SlaBreachEvent).where(
        SlaBreachEvent.organization_id == organization_id
    )
    if case_id is not None:
        q = q.where(SlaBreachEvent.case_id == case_id)
    q = q.order_by(SlaBreachEvent.detected_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


# --- Ticket bindings -------------------------------------------------


class TicketBindingCreate(BaseModel):
    organization_id: uuid.UUID
    case_id: uuid.UUID
    system: TicketSystem
    external_id: str = Field(min_length=1, max_length=255)
    external_url: str | None = None
    project_key: str | None = None
    status: str | None = None


class TicketBindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    case_id: uuid.UUID
    system: str
    external_id: str
    external_url: str | None
    project_key: str | None
    status: str | None
    last_synced_at: datetime | None
    last_sync_status: str | None
    last_sync_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TicketBindingPatch(BaseModel):
    status: str | None = None
    external_url: str | None = None
    last_sync_status: str | None = None
    last_sync_error: str | None = None
    raw: dict | None = None


@router.post("/tickets", response_model=TicketBindingResponse, status_code=201)
async def create_ticket_binding(
    body: TicketBindingCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    case = await db.get(Case, body.case_id)
    if not case or case.organization_id != body.organization_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "case_id is in a different organization",
        )
    bind = ExternalTicketBinding(
        organization_id=body.organization_id,
        case_id=case.id,
        system=body.system.value,
        external_id=body.external_id.strip(),
        external_url=body.external_url,
        project_key=body.project_key,
        status=body.status,
    )
    db.add(bind)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{body.system.value}:{body.external_id} already bound elsewhere",
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.TICKET_BINDING_CREATE,
        user=analyst,
        resource_type="external_ticket_binding",
        resource_id=str(bind.id),
        details={
            "system": body.system.value,
            "external_id": body.external_id,
            "case_id": str(case.id),
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(bind)
    return bind


@router.get("/tickets", response_model=list[TicketBindingResponse])
async def list_ticket_bindings(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    system: TicketSystem | None = None,
    case_id: uuid.UUID | None = None,
):
    q = select(ExternalTicketBinding).where(
        ExternalTicketBinding.organization_id == organization_id
    )
    if system is not None:
        q = q.where(ExternalTicketBinding.system == system.value)
    if case_id is not None:
        q = q.where(ExternalTicketBinding.case_id == case_id)
    return list(
        (await db.execute(q.order_by(ExternalTicketBinding.created_at.desc()))).scalars().all()
    )


@router.patch(
    "/tickets/{binding_id}", response_model=TicketBindingResponse
)
async def update_ticket_binding(
    binding_id: uuid.UUID,
    body: TicketBindingPatch,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    bind = await db.get(ExternalTicketBinding, binding_id)
    if not bind:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Binding not found")
    for field_name in ("status", "external_url", "last_sync_status", "last_sync_error"):
        v = getattr(body, field_name)
        if v is not None:
            setattr(bind, field_name, v)
    if body.raw is not None:
        bind.raw = body.raw
    bind.last_synced_at = datetime.now(timezone.utc)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.TICKET_BINDING_SYNC,
        user=analyst,
        resource_type="external_ticket_binding",
        resource_id=str(bind.id),
        details={"status": bind.status, "sync_status": bind.last_sync_status},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(bind)
    return bind


@router.delete("/tickets/{binding_id}", status_code=204)
async def delete_ticket_binding(
    binding_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    bind = await db.get(ExternalTicketBinding, binding_id)
    if not bind:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Binding not found")
    await db.delete(bind)
    await db.commit()
    return None
