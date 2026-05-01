"""Phase 10 — Takedown API.

Endpoints
---------
    POST  /takedown/tickets                       submit a takedown
    GET   /takedown/tickets?organization_id=…     list
    GET   /takedown/tickets/{id}                  detail
    POST  /takedown/tickets/{id}/state            state transition
    POST  /takedown/tickets/{id}/sync             pull status from partner
    GET   /takedown/partners                      list available adapters
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
from src.models.takedown import (
    TakedownPartner,
    TakedownState,
    TakedownTargetKind,
    TakedownTicket,
    is_takedown_transition_allowed,
)
from src.models.threat import Organization
from src.storage.database import get_session
from src.takedown.adapters import (
    SubmitPayload,
    get_adapter,
)

router = APIRouter(prefix="/takedown", tags=["Operations"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- Schemas ----------------------------------------------------------


class TakedownSubmit(BaseModel):
    organization_id: uuid.UUID
    partner: TakedownPartner = TakedownPartner.MANUAL
    target_kind: TakedownTargetKind
    target_identifier: str = Field(min_length=1, max_length=500)
    source_finding_id: uuid.UUID | None = None
    reason: str = Field(min_length=1)
    evidence_urls: list[str] = Field(default_factory=list)
    contact_email: str | None = None
    metadata: dict = Field(default_factory=dict)


class TakedownResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    partner: str
    state: str
    target_kind: str
    target_identifier: str
    source_finding_id: uuid.UUID | None
    partner_reference: str | None
    partner_url: str | None
    submitted_at: datetime
    acknowledged_at: datetime | None
    succeeded_at: datetime | None
    failed_at: datetime | None
    proof_evidence_sha256: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class StateChange(BaseModel):
    to_state: TakedownState
    reason: str | None = None
    proof_evidence_sha256: str | None = None


# --- Endpoints --------------------------------------------------------


@router.get("/partners")
async def list_partners(analyst: AnalystUser):
    return {"partners": [p.value for p in TakedownPartner]}


@router.post("/tickets", response_model=TakedownResponse, status_code=201)
async def submit_takedown(
    body: TakedownSubmit,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    adapter = get_adapter(body.partner.value)
    submit_result = await adapter.submit(
        SubmitPayload(
            organization_id=str(body.organization_id),
            target_kind=body.target_kind.value,
            target_identifier=body.target_identifier,
            reason=body.reason,
            evidence_urls=body.evidence_urls,
            contact_email=body.contact_email,
            metadata=body.metadata,
        )
    )

    now = datetime.now(timezone.utc)
    ticket = TakedownTicket(
        organization_id=body.organization_id,
        partner=body.partner.value,
        state=(
            TakedownState.SUBMITTED.value
            if submit_result.success
            else TakedownState.FAILED.value
        ),
        target_kind=body.target_kind.value,
        target_identifier=body.target_identifier.strip(),
        source_finding_id=body.source_finding_id,
        partner_reference=submit_result.partner_reference,
        partner_url=submit_result.partner_url,
        submitted_by_user_id=analyst.id,
        submitted_at=now,
        failed_at=now if not submit_result.success else None,
        notes=submit_result.error_message,
        raw=submit_result.raw,
    )
    db.add(ticket)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A takedown for this target+partner is already open",
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.TAKEDOWN_SUBMIT,
        user=analyst,
        resource_type="takedown_ticket",
        resource_id=str(ticket.id),
        details={
            "partner": body.partner.value,
            "target_kind": body.target_kind.value,
            "target": body.target_identifier,
            "success": submit_result.success,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(ticket)
    return ticket


@router.get("/tickets", response_model=list[TakedownResponse])
async def list_tickets(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: TakedownState | None = None,
    partner: TakedownPartner | None = None,
    target_kind: TakedownTargetKind | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(TakedownTicket).where(
        TakedownTicket.organization_id == organization_id
    )
    if state is not None:
        q = q.where(TakedownTicket.state == state.value)
    if partner is not None:
        q = q.where(TakedownTicket.partner == partner.value)
    if target_kind is not None:
        q = q.where(TakedownTicket.target_kind == target_kind.value)
    q = q.order_by(TakedownTicket.submitted_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.get("/tickets/{ticket_id}", response_model=TakedownResponse)
async def get_ticket(
    ticket_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    t = await db.get(TakedownTicket, ticket_id)
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ticket not found")
    return t


@router.post(
    "/tickets/{ticket_id}/state", response_model=TakedownResponse
)
async def change_state(
    ticket_id: uuid.UUID,
    body: StateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    t = await db.get(TakedownTicket, ticket_id)
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ticket not found")
    if body.to_state.value == t.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {t.state}")
    if not is_takedown_transition_allowed(t.state, body.to_state.value):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"transition {t.state} → {body.to_state.value} not allowed",
        )
    if body.to_state in (
        TakedownState.REJECTED,
        TakedownState.FAILED,
        TakedownState.WITHDRAWN,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required for this state",
            )
    now = datetime.now(timezone.utc)
    from_state = t.state
    t.state = body.to_state.value
    if body.to_state == TakedownState.ACKNOWLEDGED:
        t.acknowledged_at = now
    if body.to_state == TakedownState.SUCCEEDED:
        t.succeeded_at = now
        if body.proof_evidence_sha256:
            t.proof_evidence_sha256 = body.proof_evidence_sha256
    if body.to_state in (TakedownState.FAILED, TakedownState.REJECTED):
        t.failed_at = now
    if body.to_state == TakedownState.SUBMITTED:
        # Re-submitted after a previous failure / withdrawal — clear timestamps
        t.failed_at = None
        t.acknowledged_at = None
    if body.reason:
        t.notes = (t.notes or "") + (
            "\n" if t.notes else ""
        ) + f"[{from_state}→{body.to_state.value}] {body.reason}"

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.TAKEDOWN_STATE_CHANGE,
        user=analyst,
        resource_type="takedown_ticket",
        resource_id=str(t.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(t)
    return t


@router.post("/tickets/{ticket_id}/sync", response_model=TakedownResponse)
async def sync_with_partner(
    ticket_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    t = await db.get(TakedownTicket, ticket_id)
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ticket not found")
    if not t.partner_reference:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Ticket has no partner_reference yet",
        )
    adapter = get_adapter(t.partner)
    res = await adapter.fetch_status(t.partner_reference)
    if not res.success:
        t.notes = (t.notes or "") + f"\n[sync] error: {res.error_message}"
    else:
        # Map partner-state to our state heuristically
        ps = (res.partner_state or "").lower()
        mapped = None
        if ps in ("succeeded", "removed", "complete"):
            mapped = TakedownState.SUCCEEDED.value
            t.succeeded_at = datetime.now(timezone.utc)
        elif ps in ("rejected", "denied"):
            mapped = TakedownState.REJECTED.value
            t.failed_at = datetime.now(timezone.utc)
        elif ps in ("in_progress", "investigating", "pending"):
            mapped = TakedownState.IN_PROGRESS.value
        elif ps in ("acknowledged", "received"):
            mapped = TakedownState.ACKNOWLEDGED.value
            t.acknowledged_at = datetime.now(timezone.utc)
        if mapped and mapped != t.state and is_takedown_transition_allowed(t.state, mapped):
            t.state = mapped
        t.notes = (t.notes or "") + (
            "\n" if t.notes else ""
        ) + f"[sync] partner_state={res.partner_state}"

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.TAKEDOWN_STATE_CHANGE,
        user=analyst,
        resource_type="takedown_ticket",
        resource_id=str(t.id),
        details={"action": "sync", "success": res.success, "state": t.state},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(t)
    return t
