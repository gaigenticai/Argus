"""Onboarding wizard API.

Resumable 5-step flow that builds an Organization plus its initial
Asset Registry in a single transaction at completion. Step layout:

    1. organization      — name, industry, primary domain, keywords
    2. infra             — domains, subdomains, IPs, IP ranges, services,
                           email_domains
    3. people_and_brand  — executives, brands, mobile apps, social handles
    4. vendors           — third parties (TPRM seed list)
    5. review            — confirms counts, optional auto-discovery, completes

Per-step PATCH calls only persist the raw payload — validation runs at
completion or when the analyst explicitly hits ``/validate``. This lets
the wizard save partial work without data loss.

The completion handler runs everything in one DB transaction:
    - upsert Organization
    - bulk-validate every asset payload through the registry validators
    - bulk-insert assets
    - optionally enqueue DiscoveryJob rows for Phase 1 EASM consumption
    - mark session COMPLETED, audit log
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.asset_schemas import (
    AssetCriticality,
    AssetType,
    DiscoveryMethod,
    canonicalize_asset_value,
    validate_asset_details,
)
from src.models.auth import AuditAction
from src.models.onboarding import (
    DiscoveryJob,
    DiscoveryJobKind,
    DiscoveryJobStatus,
    OnboardingSession,
    OnboardingState,
)
from src.models.threat import Asset, Organization
from src.storage.database import get_session

router = APIRouter(prefix="/onboarding", tags=["External Surface"])


# --- Step payload schemas ------------------------------------------------


class OrgStep(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    industry: str | None = None
    primary_domain: str | None = None
    keywords: list[str] = Field(default_factory=list)
    notes: str | None = None


class AssetEntry(BaseModel):
    """A single asset row collected by any step."""

    asset_type: AssetType
    value: str
    details: dict[str, Any] | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: list[str] = Field(default_factory=list)


class InfraStep(BaseModel):
    """Step 2 — domains, subdomains, IPs, services, email domains."""

    assets: list[AssetEntry] = Field(default_factory=list)


class PeopleAndBrandStep(BaseModel):
    """Step 3 — executives, brands, mobile apps, social handles."""

    assets: list[AssetEntry] = Field(default_factory=list)


class VendorsStep(BaseModel):
    """Step 4 — third-party vendors."""

    assets: list[AssetEntry] = Field(default_factory=list)


class ReviewStep(BaseModel):
    """Step 5 — review + auto-discovery toggle."""

    enable_auto_discovery: bool = True
    discover_kinds: list[DiscoveryJobKind] = Field(
        default_factory=lambda: [
            DiscoveryJobKind.SUBDOMAIN_ENUM,
            DiscoveryJobKind.HTTPX_PROBE,
        ]
    )


_STEP_NAMES = ("organization", "infra", "people_and_brand", "vendors", "review")
_STEP_SCHEMAS: dict[str, type[BaseModel]] = {
    "organization": OrgStep,
    "infra": InfraStep,
    "people_and_brand": PeopleAndBrandStep,
    "vendors": VendorsStep,
    "review": ReviewStep,
}
_STEP_NUMBERS = {name: i + 1 for i, name in enumerate(_STEP_NAMES)}


# --- API request/response schemas ----------------------------------------


class SessionCreate(BaseModel):
    organization_id: uuid.UUID | None = None  # resume into an existing org
    notes: str | None = None


class StepUpdate(BaseModel):
    step: Literal["organization", "infra", "people_and_brand", "vendors", "review"]
    data: dict[str, Any]
    advance: bool = True  # advance current_step pointer if this is the latest


class SessionResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    state: str
    current_step: int
    step_data: dict[str, Any]
    completed_at: datetime | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CompletionResult(BaseModel):
    organization_id: uuid.UUID
    session_id: uuid.UUID
    assets_created: int
    discovery_jobs_enqueued: int
    warnings: list[str]


class ValidationReport(BaseModel):
    step: str
    valid: bool
    errors: list[dict[str, Any]]


# --- Helpers -------------------------------------------------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


async def _get_session_or_404(
    db: AsyncSession, session_id: uuid.UUID
) -> OnboardingSession:
    sess = await db.get(OnboardingSession, session_id)
    if not sess:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onboarding session not found")
    return sess


def _validate_step(step: str, data: dict[str, Any]) -> tuple[bool, list[dict]]:
    schema = _STEP_SCHEMAS[step]
    try:
        parsed = schema.model_validate(data or {})
    except ValidationError as e:
        return False, e.errors()

    # Deep-validate asset entries for steps that contain them.
    if isinstance(parsed, (InfraStep, PeopleAndBrandStep, VendorsStep)):
        per_row_errors: list[dict] = []
        for idx, entry in enumerate(parsed.assets):
            try:
                canonicalize_asset_value(entry.asset_type, entry.value)
            except ValueError as err:
                per_row_errors.append(
                    {"loc": ["assets", idx, "value"], "msg": str(err)}
                )
                continue
            try:
                validate_asset_details(entry.asset_type, entry.details)
            except (ValidationError, ValueError) as err:
                per_row_errors.append(
                    {"loc": ["assets", idx, "details"], "msg": str(err)}
                )
        if per_row_errors:
            return False, per_row_errors
    return True, []


def _expected_kind_for_asset_type(t: AssetType) -> set[DiscoveryJobKind]:
    """Which discovery jobs apply to which asset types."""
    if t in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return {
            DiscoveryJobKind.SUBDOMAIN_ENUM,
            DiscoveryJobKind.HTTPX_PROBE,
            DiscoveryJobKind.CT_LOG_BACKFILL,
            DiscoveryJobKind.WHOIS_REFRESH,
            DiscoveryJobKind.DNS_REFRESH,
        }
    if t in (AssetType.IP_ADDRESS, AssetType.IP_RANGE):
        return {DiscoveryJobKind.PORT_SCAN, DiscoveryJobKind.HTTPX_PROBE}
    if t == AssetType.SERVICE:
        return {DiscoveryJobKind.HTTPX_PROBE}
    if t == AssetType.EMAIL_DOMAIN:
        return {DiscoveryJobKind.DNS_REFRESH}
    return set()


# --- Endpoints -----------------------------------------------------------


@router.post("/sessions", response_model=SessionResponse, status_code=201)
async def create_session(
    body: SessionCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Start a new onboarding session.

    If ``organization_id`` is supplied, the session is bound to an existing
    org (used to add more assets to a previously-onboarded tenant). Else
    the org is created at completion time.
    """
    if body.organization_id is not None:
        org = await db.get(Organization, body.organization_id)
        if not org:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "organization_id not found"
            )

    sess = OnboardingSession(
        organization_id=body.organization_id,
        started_by_user_id=analyst.id,
        state=OnboardingState.DRAFT.value,
        current_step=1,
        step_data={},
        notes=body.notes,
    )
    db.add(sess)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ONBOARDING_START,
        user=analyst,
        resource_type="onboarding_session",
        resource_id=str(sess.id),
        details={"organization_id": str(body.organization_id) if body.organization_id else None},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(sess)
    return sess


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    analyst: AnalystUser,
    state: OnboardingState | None = None,
    mine_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: AsyncSession = Depends(get_session),
):
    query = select(OnboardingSession)
    if state is not None:
        query = query.where(OnboardingSession.state == state.value)
    if mine_only:
        query = query.where(OnboardingSession.started_by_user_id == analyst.id)
    query = (
        query.order_by(OnboardingSession.updated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session_state(
    session_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return await _get_session_or_404(db, session_id)


@router.patch("/sessions/{session_id}", response_model=SessionResponse)
async def update_session(
    session_id: uuid.UUID,
    body: StepUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Persist the payload for a step. Does not validate (use /validate)."""
    sess = await _get_session_or_404(db, session_id)
    if sess.state != OnboardingState.DRAFT.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Session is {sess.state}; cannot modify",
        )

    step_data = dict(sess.step_data or {})
    step_data[body.step] = body.data
    sess.step_data = step_data

    if body.advance:
        target_step = _STEP_NUMBERS[body.step]
        if target_step + 1 > sess.current_step:
            sess.current_step = min(target_step + 1, len(_STEP_NAMES))

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ONBOARDING_UPDATE,
        user=analyst,
        resource_type="onboarding_session",
        resource_id=str(sess.id),
        details={"step": body.step, "advance": body.advance},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(sess)
    return sess


@router.post("/sessions/{session_id}/validate", response_model=list[ValidationReport])
async def validate_session(
    session_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Validate every populated step. Returns per-step report."""
    sess = await _get_session_or_404(db, session_id)
    reports: list[ValidationReport] = []
    for step in _STEP_NAMES:
        if step not in (sess.step_data or {}):
            continue
        ok, errors = _validate_step(step, sess.step_data[step])
        reports.append(ValidationReport(step=step, valid=ok, errors=errors))
    return reports


@router.post("/sessions/{session_id}/complete", response_model=CompletionResult)
async def complete_session(
    session_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Finalize the wizard: create org + assets + discovery jobs atomically."""
    sess = await _get_session_or_404(db, session_id)
    if sess.state != OnboardingState.DRAFT.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Session is already {sess.state}"
        )

    data = sess.step_data or {}

    if "organization" not in data:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Step 'organization' has not been provided",
        )

    # Validate every step before any writes.
    for step, payload in data.items():
        ok, errors = _validate_step(step, payload)
        if not ok:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                {"step": step, "errors": errors},
            )

    org_step = OrgStep.model_validate(data["organization"])
    review = ReviewStep.model_validate(data.get("review", {}))

    # Create or fetch the org
    if sess.organization_id:
        org = await db.get(Organization, sess.organization_id)
        if not org:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Bound organization disappeared")
    else:
        org = Organization(
            name=org_step.name,
            domains=[org_step.primary_domain] if org_step.primary_domain else [],
            keywords=org_step.keywords,
            industry=org_step.industry,
        )
        db.add(org)
        await db.flush()
        sess.organization_id = org.id

    # Collect every asset entry across the relevant steps
    all_entries: list[AssetEntry] = []
    if "infra" in data:
        all_entries.extend(InfraStep.model_validate(data["infra"]).assets)
    if "people_and_brand" in data:
        all_entries.extend(
            PeopleAndBrandStep.model_validate(data["people_and_brand"]).assets
        )
    if "vendors" in data:
        all_entries.extend(VendorsStep.model_validate(data["vendors"]).assets)

    # Bulk insert assets, idempotent on (org, type, value)
    now = datetime.now(timezone.utc)
    assets_created = 0
    warnings: list[str] = []
    inserted_assets_for_discovery: list[Asset] = []

    for entry in all_entries:
        canonical = canonicalize_asset_value(entry.asset_type, entry.value)
        validated_details = validate_asset_details(entry.asset_type, entry.details)

        existing = await db.execute(
            select(Asset.id).where(
                and_(
                    Asset.organization_id == org.id,
                    Asset.asset_type == entry.asset_type.value,
                    Asset.value == canonical,
                )
            )
        )
        if existing.scalar_one_or_none():
            warnings.append(
                f"Skipped duplicate {entry.asset_type.value}:{canonical}"
            )
            continue

        asset = Asset(
            organization_id=org.id,
            asset_type=entry.asset_type.value,
            value=canonical,
            details=validated_details,
            criticality=entry.criticality.value,
            tags=entry.tags,
            owner_user_id=analyst.id,
            discovery_method=DiscoveryMethod.ONBOARDING_WIZARD.value,
            discovered_at=now,
        )
        db.add(asset)
        await db.flush()
        assets_created += 1
        inserted_assets_for_discovery.append(asset)

    # Enqueue discovery jobs for relevant asset types
    discovery_jobs_enqueued = 0
    if review.enable_auto_discovery and review.discover_kinds:
        for asset in inserted_assets_for_discovery:
            applicable = _expected_kind_for_asset_type(AssetType(asset.asset_type))
            for kind in review.discover_kinds:
                if kind not in applicable:
                    continue
                job = DiscoveryJob(
                    organization_id=org.id,
                    asset_id=asset.id,
                    kind=kind.value,
                    status=DiscoveryJobStatus.QUEUED.value,
                    target=asset.value,
                    parameters={},
                    requested_by_user_id=analyst.id,
                    onboarding_session_id=sess.id,
                )
                db.add(job)
                discovery_jobs_enqueued += 1

    sess.state = OnboardingState.COMPLETED.value
    sess.completed_at = now

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ONBOARDING_COMPLETE,
        user=analyst,
        resource_type="onboarding_session",
        resource_id=str(sess.id),
        details={
            "organization_id": str(org.id),
            "assets_created": assets_created,
            "discovery_jobs_enqueued": discovery_jobs_enqueued,
        },
        ip_address=ip,
        user_agent=ua,
    )
    if discovery_jobs_enqueued:
        await audit_log(
            db,
            AuditAction.DISCOVERY_JOB_ENQUEUE,
            user=analyst,
            resource_type="organization",
            resource_id=str(org.id),
            details={"count": discovery_jobs_enqueued, "kinds": [k.value for k in review.discover_kinds]},
            ip_address=ip,
            user_agent=ua,
        )

    await db.commit()
    return CompletionResult(
        organization_id=org.id,
        session_id=sess.id,
        assets_created=assets_created,
        discovery_jobs_enqueued=discovery_jobs_enqueued,
        warnings=warnings,
    )


@router.post("/sessions/{session_id}/abandon", response_model=SessionResponse)
async def abandon_session(
    session_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    sess = await _get_session_or_404(db, session_id)
    if sess.state != OnboardingState.DRAFT.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Session is already {sess.state}"
        )
    sess.state = OnboardingState.ABANDONED.value
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ONBOARDING_ABANDON,
        user=analyst,
        resource_type="onboarding_session",
        resource_id=str(sess.id),
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(sess)
    return sess


# --- Discovery jobs (read-only here; workers come in Phase 1.1) ----------


class DiscoveryJobResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    kind: str
    status: str
    target: str
    parameters: dict
    started_at: datetime | None
    finished_at: datetime | None
    result_summary: dict | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.get("/discovery-jobs", response_model=list[DiscoveryJobResponse])
async def list_discovery_jobs(
    analyst: AnalystUser,
    organization_id: uuid.UUID | None = None,
    status_filter: Annotated[DiscoveryJobStatus | None, Query(alias="status")] = None,
    kind: DiscoveryJobKind | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    db: AsyncSession = Depends(get_session),
):
    query = select(DiscoveryJob)
    if organization_id is not None:
        query = query.where(DiscoveryJob.organization_id == organization_id)
    if status_filter is not None:
        query = query.where(DiscoveryJob.status == status_filter.value)
    if kind is not None:
        query = query.where(DiscoveryJob.kind == kind.value)
    query = query.order_by(DiscoveryJob.created_at.desc()).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/discovery-jobs/{job_id}/cancel", response_model=DiscoveryJobResponse)
async def cancel_discovery_job(
    job_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    job = await db.get(DiscoveryJob, job_id)
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discovery job not found")
    if job.status not in (
        DiscoveryJobStatus.QUEUED.value,
        DiscoveryJobStatus.RUNNING.value,
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot cancel a job in status {job.status}",
        )
    job.status = DiscoveryJobStatus.CANCELLED.value
    job.finished_at = datetime.now(timezone.utc)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DISCOVERY_JOB_CANCEL,
        user=analyst,
        resource_type="discovery_job",
        resource_id=str(job.id),
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(job)
    return job
