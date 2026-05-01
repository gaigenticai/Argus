"""EASM API.

Endpoints
---------
    POST /easm/scan                              enqueue a one-off discovery job
    POST /easm/worker/tick                       run worker N times (admin-only)
    GET  /easm/changes?organization_id=…         list AssetChange entries
    GET  /easm/findings?organization_id=…        list DiscoveryFinding rows (state filterable)
    POST /easm/findings/{id}/promote             promote a NEW finding into the Asset Registry
    POST /easm/findings/{id}/dismiss             dismiss a finding
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.easm.worker import tick
from src.models.asset_schemas import (
    AssetCriticality,
    AssetType,
    DiscoveryMethod,
    canonicalize_asset_value,
    validate_asset_details,
)
from src.models.auth import AuditAction
from src.models.easm import (
    AssetChange,
    ChangeKind,
    ChangeSeverity,
    DiscoveryFinding,
    FindingState,
)
from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSeverity,
    ExposureSource,
    ExposureState,
    is_state_transition_allowed,
)
from src.models.onboarding import (
    DiscoveryJob,
    DiscoveryJobKind,
    DiscoveryJobStatus,
)
from src.models.threat import Asset, Organization
from src.storage.database import get_session

router = APIRouter(prefix="/easm", tags=["External Surface"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


# --- Schemas ------------------------------------------------------------


class ScanRequest(BaseModel):
    organization_id: uuid.UUID
    kind: DiscoveryJobKind
    target: str = Field(min_length=1, max_length=500)
    asset_id: uuid.UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    job_id: uuid.UUID
    status: str
    kind: str
    target: str


class TickRequest(BaseModel):
    max_jobs: int = Field(default=10, ge=1, le=500)


class ChangeResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    discovery_job_id: uuid.UUID | None
    kind: str
    severity: str
    summary: str
    before: dict | None
    after: dict | None
    detected_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    discovery_job_id: uuid.UUID | None
    parent_asset_id: uuid.UUID | None
    asset_type: str
    value: str
    details: dict | None
    state: str
    confidence: float
    promoted_asset_id: uuid.UUID | None
    discovered_via: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PromoteRequest(BaseModel):
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: list[str] = Field(default_factory=list)
    extra_details: dict[str, Any] | None = None


# --- Endpoints ----------------------------------------------------------


@router.post("/scan", response_model=ScanResponse, status_code=201)
async def trigger_scan(
    body: ScanRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if body.asset_id is not None:
        asset = await db.get(Asset, body.asset_id)
        if not asset or asset.organization_id != body.organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "asset_id is in a different organization",
            )

    job = DiscoveryJob(
        organization_id=body.organization_id,
        asset_id=body.asset_id,
        kind=body.kind.value,
        status=DiscoveryJobStatus.QUEUED.value,
        target=body.target.strip(),
        parameters=body.parameters,
        requested_by_user_id=analyst.id,
    )
    db.add(job)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DISCOVERY_JOB_ENQUEUE,
        user=analyst,
        resource_type="discovery_job",
        resource_id=str(job.id),
        details={
            "organization_id": str(body.organization_id),
            "kind": body.kind.value,
            "target": body.target,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return ScanResponse(
        job_id=job.id, status=job.status, kind=job.kind, target=job.target
    )


@router.post("/worker/tick")
async def worker_tick(
    body: TickRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Manually run the worker loop (admin only).  Returns per-job results.

    In production, the worker runs as a long-lived process. This endpoint
    is for ops + tests.
    """
    results = await tick(db, max_jobs=body.max_jobs)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EASM_JOB_RUN,
        user=admin,
        resource_type="discovery_worker",
        resource_id="manual",
        details={"jobs_processed": len(results)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {"jobs_processed": len(results), "results": results}


@router.get("/changes", response_model=list[ChangeResponse])
async def list_changes(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    asset_id: uuid.UUID | None = None,
    kind: ChangeKind | None = None,
    severity: ChangeSeverity | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    q = select(AssetChange).where(AssetChange.organization_id == organization_id)
    if asset_id is not None:
        q = q.where(AssetChange.asset_id == asset_id)
    if kind is not None:
        q = q.where(AssetChange.kind == kind.value)
    if severity is not None:
        q = q.where(AssetChange.severity == severity.value)
    q = q.order_by(AssetChange.detected_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(q)).scalars().all())


@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: FindingState | None = None,
    asset_type: AssetType | None = None,
    parent_asset_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    q = select(DiscoveryFinding).where(
        DiscoveryFinding.organization_id == organization_id
    )
    if state is not None:
        q = q.where(DiscoveryFinding.state == state.value)
    if asset_type is not None:
        q = q.where(DiscoveryFinding.asset_type == asset_type.value)
    if parent_asset_id is not None:
        q = q.where(DiscoveryFinding.parent_asset_id == parent_asset_id)
    q = q.order_by(DiscoveryFinding.created_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(q)).scalars().all())


@router.post("/findings/{finding_id}/promote", response_model=FindingResponse)
async def promote_finding(
    finding_id: uuid.UUID,
    body: PromoteRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    finding = await db.get(DiscoveryFinding, finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if finding.state != FindingState.NEW.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Finding is already in state {finding.state}; cannot promote",
        )

    asset_type = AssetType(finding.asset_type)
    canonical_value = canonicalize_asset_value(asset_type, finding.value)
    details = {**(finding.details or {}), **(body.extra_details or {})}
    validated_details = validate_asset_details(asset_type, details)

    asset = Asset(
        organization_id=finding.organization_id,
        asset_type=asset_type.value,
        value=canonical_value,
        details=validated_details,
        criticality=body.criticality.value,
        tags=body.tags,
        owner_user_id=analyst.id,
        parent_asset_id=finding.parent_asset_id,
        discovery_method=DiscoveryMethod.EASM_DISCOVERY.value,
        discovered_at=datetime.now(timezone.utc),
    )
    db.add(asset)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An asset with that value already exists for this organization",
        )

    finding.state = FindingState.PROMOTED.value
    finding.promoted_asset_id = asset.id

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EASM_FINDING_PROMOTE,
        user=analyst,
        resource_type="discovery_finding",
        resource_id=str(finding.id),
        details={
            "asset_id": str(asset.id),
            "asset_type": asset_type.value,
            "value": canonical_value,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding


class ExposureResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    discovery_job_id: uuid.UUID | None
    severity: str
    category: str
    state: str
    source: str
    rule_id: str
    title: str
    description: str | None
    target: str
    matched_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    cvss_score: float | None
    cve_ids: list[str]
    cwe_ids: list[str]
    references: list[str]
    matcher_data: dict | None
    state_changed_by_user_id: uuid.UUID | None
    state_changed_at: datetime | None
    state_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ExposureStateChange(BaseModel):
    to_state: ExposureState
    reason: str | None = None


@router.get("/exposures", response_model=list[ExposureResponse])
async def list_exposures(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: ExposureState | None = None,
    severity: ExposureSeverity | None = None,
    category: ExposureCategory | None = None,
    source: ExposureSource | None = None,
    asset_id: uuid.UUID | None = None,
    cve: str | None = None,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    qs = select(ExposureFinding).where(
        ExposureFinding.organization_id == organization_id
    )
    if state is not None:
        qs = qs.where(ExposureFinding.state == state.value)
    if severity is not None:
        qs = qs.where(ExposureFinding.severity == severity.value)
    if category is not None:
        qs = qs.where(ExposureFinding.category == category.value)
    if source is not None:
        qs = qs.where(ExposureFinding.source == source.value)
    if asset_id is not None:
        qs = qs.where(ExposureFinding.asset_id == asset_id)
    if cve:
        qs = qs.where(ExposureFinding.cve_ids.any(cve.upper()))
    if q:
        like = f"%{q}%"
        qs = qs.where(
            (ExposureFinding.title.ilike(like))
            | (ExposureFinding.rule_id.ilike(like))
        )
    qs = qs.order_by(ExposureFinding.last_seen_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(qs)).scalars().all())


@router.get("/exposures/{exposure_id}", response_model=ExposureResponse)
async def get_exposure(
    exposure_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(ExposureFinding, exposure_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exposure not found")
    return f


@router.post("/exposures/{exposure_id}/state", response_model=ExposureResponse)
async def change_exposure_state(
    exposure_id: uuid.UUID,
    body: ExposureStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(ExposureFinding, exposure_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exposure not found")
    if body.to_state.value == f.state:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Exposure is already {f.state}"
        )
    if not is_state_transition_allowed(f.state, body.to_state.value):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Transition {f.state} → {body.to_state.value} is not allowed",
        )
    if body.to_state in (
        ExposureState.ACCEPTED_RISK,
        ExposureState.FALSE_POSITIVE,
        ExposureState.FIXED,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required to enter this state",
            )
    from_state = f.state
    f.state = body.to_state.value
    f.state_changed_at = datetime.now(timezone.utc)
    f.state_changed_by_user_id = analyst.id
    f.state_reason = body.reason

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EXPOSURE_STATE_CHANGE,
        user=analyst,
        resource_type="exposure_finding",
        resource_id=str(f.id),
        details={
            "from": from_state,
            "to": body.to_state.value,
            "reason": body.reason,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    return f


@router.post("/findings/{finding_id}/dismiss", response_model=FindingResponse)
async def dismiss_finding(
    finding_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    finding = await db.get(DiscoveryFinding, finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if finding.state != FindingState.NEW.value:
        return finding  # idempotent

    finding.state = FindingState.DISMISSED.value
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EASM_FINDING_DISMISS,
        user=analyst,
        resource_type="discovery_finding",
        resource_id=str(finding.id),
        details={"value": finding.value},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding
