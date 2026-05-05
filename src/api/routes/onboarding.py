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


def _canonicalize_domain(raw: str | None) -> str | None:
    """Strip scheme/www/path/port and lowercase. Returns None if empty
    or clearly not a domain (no dot). Matches the canonicalisation used
    by ``POST /organizations/{id}/domains`` so the same string anchors
    verification end-to-end."""
    if not raw:
        return None
    cleaned = raw.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
    cleaned = cleaned.split("/", 1)[0].split(":", 1)[0]
    return cleaned if cleaned and "." in cleaned else None


async def _upsert_draft_org_for_session(
    db: AsyncSession,
    sess: OnboardingSession,
    org_payload: dict[str, Any],
    analyst: AnalystUser,
) -> Organization | None:
    """Create or update a *draft* Org bound to this wizard session.

    The org carries a domain-verification token from the moment a
    primary domain is provided so the operator can verify ownership
    *during* the wizard — verification is the identity proof, not an
    afterthought tacked onto the post-completion banner. Only the
    primary domain anchors identity; assets/keywords/etc. arrive at
    completion.

    No-op when the session is already bound to a *real* (completed)
    org, e.g. when an operator restarts the wizard against an
    existing tenant."""
    from sqlalchemy.orm.attributes import flag_modified
    from src.core.domain_verification import request_token, get_state

    domain = _canonicalize_domain(org_payload.get("primary_domain"))
    name = (org_payload.get("name") or "").strip()
    industry = (org_payload.get("industry") or "").strip() or None
    keywords_raw = org_payload.get("keywords") or []
    keywords = [k.strip() for k in keywords_raw if isinstance(k, str) and k.strip()]
    notes = (org_payload.get("notes") or "").strip() or None

    if sess.organization_id:
        org = await db.get(Organization, sess.organization_id)
        if org is None:
            # Bound org disappeared (rare — manual DB cleanup). Fall
            # through to create a fresh draft so the wizard isn't
            # wedged.
            sess.organization_id = None
        else:
            # Only mutate orgs we created as drafts for this session;
            # never silently rewrite a real org's identity.
            settings = dict(org.settings or {})
            if settings.get("draft_session_id") != str(sess.id):
                return org
            if name:
                org.name = name
            if industry is not None:
                org.industry = industry
            if keywords:
                org.keywords = keywords
            if notes is not None:
                settings["notes"] = notes
            if domain:
                existing_domains = list(org.domains or [])
                if not existing_domains or existing_domains[0] != domain:
                    # Primary changed (or not set yet). Re-mint the
                    # token only if we don't already have a live one
                    # for this exact value. Drop any other domains —
                    # a draft org should only ever carry the in-flight
                    # primary; secondary domains belong to verified
                    # orgs added later via Settings → Domains.
                    state = get_state(settings, domain)
                    if state is None or state.status not in ("pending", "verified"):
                        settings, _ = request_token(settings, domain)
                    # Strip stale verification entries for any
                    # previous primaries on this draft.
                    block = dict(settings.get("domain_verification") or {})
                    settings["domain_verification"] = {
                        k: v for k, v in block.items() if k == domain
                    }
                    org.domains = [domain]
                    flag_modified(org, "domains")
            org.settings = settings
            flag_modified(org, "settings")
            return org

    # Need at least a domain OR a name to create a draft. We prefer a
    # domain (it's identity); name alone gives us nothing to verify.
    if not domain and not name:
        return None

    base_settings: dict[str, Any] = {
        "created_via": "wizard",
        "created_by": analyst.email,
        "draft_session_id": str(sess.id),
    }
    if notes is not None:
        base_settings["notes"] = notes
    if domain:
        base_settings, _ = request_token(base_settings, domain)

    org = Organization(
        name=name or "(unnamed — verify your domain to continue)",
        domains=[domain] if domain else [],
        keywords=keywords,
        industry=industry,
        settings=base_settings,
    )
    db.add(org)
    await db.flush()
    sess.organization_id = org.id
    return org


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
                validate_asset_details(
                    entry.asset_type, entry.details, value=entry.value
                )
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

    # When step 1 ("organization") is saved, eagerly upsert a draft
    # Organization so the operator can verify the primary domain
    # *during* the wizard rather than after completion. The same draft
    # is reused on every subsequent save until completion.
    if body.step == "organization":
        await _upsert_draft_org_for_session(db, sess, body.data, analyst)

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

    # Create or fetch the org. The wizard now upserts a draft org on
    # every save of step 1, so the org typically already exists by
    # the time we get here. We re-sync the latest values either way
    # and drop the draft marker on success.
    from sqlalchemy.orm.attributes import flag_modified
    from src.core.domain_verification import request_token as _vt

    if sess.organization_id:
        org = await db.get(Organization, sess.organization_id)
        if not org:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Bound organization disappeared")
        # Sync the freshest values from the completed step 1.
        org.name = org_step.name
        if org_step.industry is not None:
            org.industry = org_step.industry
        if org_step.keywords:
            org.keywords = list(org_step.keywords)
        domain = _canonicalize_domain(org_step.primary_domain)
        settings = dict(org.settings or {})
        if domain:
            existing_domains = list(org.domains or [])
            if not existing_domains or existing_domains[0] != domain:
                settings, _ = _vt(settings, domain)
                org.domains = [domain] + [d for d in existing_domains if d != domain]
                flag_modified(org, "domains")
        # Promote out of draft.
        settings.pop("draft_session_id", None)
        org.settings = settings
        flag_modified(org, "settings")
    else:
        # No draft was ever created (e.g. step 1 was never saved with a
        # value). Same bootstrap as /quickstart so the dashboard can
        # render the verify-your-domain banner the moment the wizard
        # completes.
        base_settings: dict = {
            "created_via": "wizard",
            "created_by": analyst.email,
        }
        domain = _canonicalize_domain(org_step.primary_domain)
        if domain:
            base_settings, _ = _vt(base_settings, domain)
        org = Organization(
            name=org_step.name,
            domains=[domain] if domain else [],
            keywords=org_step.keywords,
            industry=org_step.industry,
            settings=base_settings,
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
        validated_details = validate_asset_details(
            entry.asset_type, entry.details, value=canonical
        )

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
    # If we created a draft Org for this session and it has no real
    # data on it (no assets attached), clean it up — leaving an empty
    # half-named org around just because the operator clicked Abandon
    # would clutter the org list and keep an unverifiable domain on
    # the verification gate.
    if sess.organization_id:
        draft_org = await db.get(Organization, sess.organization_id)
        if draft_org is not None:
            settings = dict(draft_org.settings or {})
            if settings.get("draft_session_id") == str(sess.id):
                asset_count = await db.scalar(
                    select(Asset.id)
                    .where(Asset.organization_id == draft_org.id)
                    .limit(1)
                )
                if not asset_count:
                    await db.delete(draft_org)
                    sess.organization_id = None
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


# ── Quickstart — first-run "see it work in 2 minutes" path ──────────
#
# Why this exists alongside the 5-step ``/onboarding/sessions`` wizard:
# the full wizard collects assets, vendors, infra, people — solid for
# a thorough rollout but heavy for a fresh login. The quickstart asks
# for the bare minimum to make the AI triage produce a *real* result
# (org name, primary domain, brand keyword) so the operator hits the
# "I see why this product exists" moment inside ~2 minutes.
#
# The full wizard is still reachable from /onboarding for deeper
# onboarding once the operator has seen the product work.


# A user-created org is one whose ``settings.created_via`` shows the
# operator deliberately chose to monitor that target — the wizard
# (``"wizard"``), the 2-minute quickstart (``"quickstart"``), or the
# load-real-target loader (``"load_real_target"``) which the operator
# runs from the CLI to pin a real customer for evaluation. The
# synthetic demo seed paths (``demo``, ``realistic``) never set this
# marker, so it remains a clean discriminator: real customer data ≠
# illustrative samples, regardless of how it got into the DB.
_USER_CREATED_MARKERS = {"quickstart", "wizard", "load_real_target"}


class QuickstartPayload(BaseModel):
    org_name: str = Field(min_length=2, max_length=255)
    primary_domain: str = Field(min_length=4, max_length=255)
    brand_keyword: str = Field(min_length=1, max_length=255)
    industry: str | None = Field(default=None, max_length=100)


class QuickstartResponse(BaseModel):
    organization_id: uuid.UUID
    asset_id: uuid.UUID
    brand_term_ids: list[uuid.UUID]


class FirstRunState(BaseModel):
    """Snapshot of where the operator is in the first-run journey.

    Drives the post-login routing decision: should the user land on
    the analytics dashboard, see a one-time demo banner, or be
    pushed through the quickstart? Distinct from the session-level
    ``OnboardingState`` enum (DRAFT/COMPLETED/ABANDONED) — that one
    tracks individual wizard sessions, this one summarises the
    operator's overall product setup state.
    """
    current_user_email: str
    is_demo_user: bool
    seed_mode: str
    user_org_count: int
    seed_org_count: int
    seed_org_names: list[str]
    has_user_created_org: bool
    has_recent_triage: bool
    has_alerts: bool
    next_action: Literal[
        "ready",          # operator has done setup; show normal dashboard
        "welcome_demo",   # demo seed; show one-time banner
        "quickstart",     # no user org yet; push to /welcome
        "trigger_triage",  # org exists but no triage run; encourage
        "review_alerts",   # triage ran, alerts produced; show them
    ]


@router.get("/state", response_model=FirstRunState)
async def get_onboarding_state(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> FirstRunState:
    """Return where the current operator is in the first-run journey.

    Called by the dashboard's auth shell on every login so it can
    route a brand-new operator to ``/welcome`` instead of dumping
    them on a sea-of-zeros analytics page.
    """
    import os
    from src.models.intel import TriageRun
    from src.models.threat import Alert

    orgs_q = await db.execute(select(Organization))
    all_orgs = list(orgs_q.scalars().all())
    user_orgs = [
        o for o in all_orgs
        if (o.settings or {}).get("created_via") in _USER_CREATED_MARKERS
    ]
    seed_orgs = [o for o in all_orgs if o not in user_orgs]

    has_recent_triage_q = await db.execute(
        select(TriageRun.id)
        .where(TriageRun.status == "completed")
        .limit(1)
    )
    has_recent_triage = has_recent_triage_q.scalar_one_or_none() is not None

    has_alerts_q = await db.execute(select(Alert.id).limit(1))
    has_alerts = has_alerts_q.scalar_one_or_none() is not None

    seed_mode = (os.environ.get("ARGUS_SEED_MODE") or "unknown").lower()
    is_demo_user = (analyst.email or "").lower() == "admin@argus.demo"

    if user_orgs:
        next_action = "review_alerts" if has_alerts else "trigger_triage"
    elif is_demo_user and seed_orgs:
        next_action = "welcome_demo"
    elif seed_orgs and seed_mode == "realistic":
        next_action = "welcome_demo"
    else:
        next_action = "quickstart"

    if next_action == "review_alerts" and has_recent_triage:
        next_action = "ready"

    return FirstRunState(
        current_user_email=analyst.email or "",
        is_demo_user=is_demo_user,
        seed_mode=seed_mode,
        user_org_count=len(user_orgs),
        seed_org_count=len(seed_orgs),
        seed_org_names=[o.name for o in seed_orgs],
        has_user_created_org=bool(user_orgs),
        has_recent_triage=has_recent_triage,
        has_alerts=has_alerts,
        next_action=next_action,
    )


@router.post("/quickstart", response_model=QuickstartResponse, status_code=201)
async def onboarding_quickstart(
    payload: QuickstartPayload,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> QuickstartResponse:
    """Create the minimum scaffold needed to make the AI triage
    produce real, org-scoped findings: an Organization, an Asset
    (the primary domain), and BrandTerm rows for the brand
    name + apex domain.

    Idempotent only at the org-name level — calling twice with the
    same ``org_name`` raises 409. The wizard handles the conflict
    by re-routing to the existing org instead of double-creating.
    """
    from src.models.brand import BrandTerm, BrandTermKind

    primary_domain = payload.primary_domain.strip().lower()
    # Strip a leading scheme/path if the operator pasted a URL — we
    # only want the apex.
    for prefix in ("https://", "http://", "www."):
        if primary_domain.startswith(prefix):
            primary_domain = primary_domain[len(prefix):]
    primary_domain = primary_domain.split("/", 1)[0].split(":", 1)[0]
    brand_keyword = payload.brand_keyword.strip()
    org_name = payload.org_name.strip()

    existing = await db.execute(
        select(Organization).where(Organization.name == org_name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"An organization named {org_name!r} already exists.",
        )

    # Auto-issue a verification challenge for the primary domain at
    # creation time so the dashboard can show TXT/HTTP instructions
    # immediately. The gate flag (ARGUS_REQUIRE_DOMAIN_VERIFICATION)
    # decides whether downstream workers respect the verified bit;
    # the operator UX is the same either way.
    from src.core.domain_verification import request_token
    from src.core.industry_defaults import default_tech_stack
    base_settings = {"created_via": "quickstart", "created_by": analyst.email}
    settings_with_token, _state = request_token(base_settings, primary_domain)

    org = Organization(
        name=org_name,
        domains=[primary_domain],
        keywords=[brand_keyword],
        industry=payload.industry,
        # Same rationale as load_real_target: seed the canonical
        # stack for the chosen industry so triage produces real
        # alerts before the operator has had a chance to refine.
        tech_stack=default_tech_stack(payload.industry),
        settings=settings_with_token,
    )
    db.add(org)
    await db.flush()

    asset = Asset(
        organization_id=org.id,
        asset_type="domain",
        value=primary_domain,
        details={"primary": True, "source": "quickstart"},
        criticality="crown_jewel",
        discovery_method="manual",
    )
    db.add(asset)

    name_term = BrandTerm(
        organization_id=org.id,
        kind=BrandTermKind.NAME.value,
        value=brand_keyword,
        keywords=[brand_keyword.lower()],
    )
    apex_term = BrandTerm(
        organization_id=org.id,
        kind=BrandTermKind.APEX_DOMAIN.value,
        value=primary_domain,
        keywords=[primary_domain],
    )
    db.add_all([name_term, apex_term])

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_CREATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(org.id),
        ip_address=ip,
        user_agent=ua,
        details={"source": "quickstart", "name": org_name, "domain": primary_domain},
    )

    await db.commit()
    await db.refresh(org)
    await db.refresh(asset)
    await db.refresh(name_term)
    await db.refresh(apex_term)
    return QuickstartResponse(
        organization_id=org.id,
        asset_id=asset.id,
        brand_term_ids=[name_term.id, apex_term.id],
    )
