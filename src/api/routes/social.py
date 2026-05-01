"""Social & Impersonation API (Phase 4).

Endpoints
---------
    POST   /social/vips                           register a VIP profile
    GET    /social/vips?organization_id=…         list
    POST   /social/vips/{id}/photos               attach a profile photo (perceptual hash stored)
    POST   /social/accounts                       register an official social account
    GET    /social/accounts?organization_id=…     list
    POST   /social/impersonations/check           score a candidate (manual + automation)
    GET    /social/impersonations?…               list findings
    POST   /social/impersonations/{id}/state      transition state
    POST   /social/mobile-apps/check              register a candidate rogue app
    GET    /social/mobile-apps?…                  list
    POST   /social/mobile-apps/{id}/state         transition
"""

from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.brand.logo_match import fingerprint as fingerprint_image
from src.config.settings import settings
from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.evidence import EvidenceBlob, EvidenceKind
from src.models.fraud import (
    FraudChannel,
    FraudFinding,
    FraudKind,
    FraudState,
)
from src.models.social import (
    ImpersonationFinding,
    ImpersonationKind,
    ImpersonationState,
    MobileAppFinding,
    MobileAppFindingState,
    MobileAppStore,
    SocialAccount,
    SocialPlatform,
    VipProfile,
)
from src.models.brand import BrandTerm
from src.models.threat import Organization
from src.social.fraud import score_text as fraud_score_text
from src.social.impersonation import score_candidate
from src.storage import evidence_store
from src.storage.database import get_session

router = APIRouter(prefix="/social", tags=["Brand Protection"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- VIPs ---------------------------------------------------------------


class VipCreate(BaseModel):
    organization_id: uuid.UUID
    full_name: str = Field(min_length=1, max_length=255)
    title: str | None = None
    aliases: list[str] = Field(default_factory=list)
    bio_keywords: list[str] = Field(default_factory=list)


class VipResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    full_name: str
    title: str | None
    aliases: list[str]
    bio_keywords: list[str]
    photo_evidence_sha256s: list[str]
    photo_phashes: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/vips", response_model=VipResponse, status_code=201)
async def register_vip(
    body: VipCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    vip = VipProfile(
        organization_id=body.organization_id,
        full_name=body.full_name.strip(),
        title=body.title,
        aliases=[a.strip() for a in body.aliases if a.strip()],
        bio_keywords=[k.strip().lower() for k in body.bio_keywords if k.strip()],
    )
    db.add(vip)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "VIP with this full_name already exists"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.VIP_PROFILE_REGISTER,
        user=analyst,
        resource_type="vip_profile",
        resource_id=str(vip.id),
        details={"full_name": vip.full_name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(vip)
    return vip


@router.get("/vips", response_model=list[VipResponse])
async def list_vips(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (
        await db.execute(
            select(VipProfile)
            .where(VipProfile.organization_id == organization_id)
            .order_by(VipProfile.created_at.desc())
        )
    ).scalars().all()
    return list(rows)


@router.post("/vips/{vip_id}/photos", response_model=VipResponse)
async def attach_photo(
    vip_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    file: Annotated[UploadFile, File()],
    db: AsyncSession = Depends(get_session),
):
    vip = await db.get(VipProfile, vip_id)
    if not vip:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VIP not found")
    blob = await file.read()
    if not blob:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "empty upload")
    try:
        fp = fingerprint_image(blob)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"could not parse image: {e}"
        )
    sha = evidence_store.sha256_of(blob)
    bucket = settings.evidence.bucket
    key = evidence_store.storage_key(str(vip.organization_id), sha)
    evidence_store.ensure_bucket(bucket)
    if not evidence_store.exists(bucket, key):
        evidence_store.put(
            bucket, key, blob, file.content_type or "image/png"
        )
    if not (
        await db.execute(
            select(EvidenceBlob).where(
                and_(
                    EvidenceBlob.organization_id == vip.organization_id,
                    EvidenceBlob.sha256 == sha,
                )
            )
        )
    ).scalar_one_or_none():
        db.add(
            EvidenceBlob(
                organization_id=vip.organization_id,
                sha256=sha,
                size_bytes=len(blob),
                content_type=file.content_type or "image/png",
                original_filename=file.filename,
                kind=EvidenceKind.EXECUTIVE_PHOTO.value,
                s3_bucket=bucket,
                s3_key=key,
                captured_at=datetime.now(timezone.utc),
                captured_by_user_id=analyst.id,
                capture_source="vip_registration",
            )
        )
    if sha not in vip.photo_evidence_sha256s:
        vip.photo_evidence_sha256s = list(vip.photo_evidence_sha256s) + [sha]
    if fp.phash_hex not in vip.photo_phashes:
        vip.photo_phashes = list(vip.photo_phashes) + [fp.phash_hex]

    await db.commit()
    await db.refresh(vip)
    return vip


# --- Social accounts ---------------------------------------------------


class SocialAccountCreate(BaseModel):
    organization_id: uuid.UUID
    vip_profile_id: uuid.UUID | None = None
    platform: SocialPlatform
    handle: str = Field(min_length=1, max_length=255)
    profile_url: str | None = None
    is_official: bool = True
    keywords: list[str] = Field(default_factory=list)


class SocialAccountResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    vip_profile_id: uuid.UUID | None
    platform: str
    handle: str
    profile_url: str | None
    is_official: bool
    keywords: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/accounts", response_model=SocialAccountResponse, status_code=201)
async def register_social_account(
    body: SocialAccountCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if body.vip_profile_id is not None:
        vip = await db.get(VipProfile, body.vip_profile_id)
        if not vip or vip.organization_id != body.organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "vip_profile_id is in a different organization",
            )
    account = SocialAccount(
        organization_id=body.organization_id,
        vip_profile_id=body.vip_profile_id,
        platform=body.platform.value,
        handle=body.handle.strip().lstrip("@"),
        profile_url=body.profile_url,
        is_official=body.is_official,
        keywords=body.keywords,
    )
    db.add(account)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Account already registered for this org"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SOCIAL_ACCOUNT_REGISTER,
        user=analyst,
        resource_type="social_account",
        resource_id=str(account.id),
        details={"platform": body.platform.value, "handle": account.handle},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(account)
    return account


@router.get("/accounts", response_model=list[SocialAccountResponse])
async def list_accounts(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    platform: SocialPlatform | None = None,
):
    q = select(SocialAccount).where(
        SocialAccount.organization_id == organization_id
    )
    if platform is not None:
        q = q.where(SocialAccount.platform == platform.value)
    return list((await db.execute(q.order_by(SocialAccount.created_at.desc()))).scalars().all())


# --- Impersonation findings -------------------------------------------


class ImpersonationCheckRequest(BaseModel):
    organization_id: uuid.UUID
    vip_profile_id: uuid.UUID
    platform: SocialPlatform
    candidate_handle: str
    candidate_display_name: str
    candidate_bio: str | None = None
    candidate_url: str | None = None
    candidate_photo_phash: str | None = None
    candidate_photo_sha256: str | None = None


class ImpersonationFindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    vip_profile_id: uuid.UUID | None
    matched_account_id: uuid.UUID | None
    kind: str
    platform: str
    candidate_handle: str
    candidate_display_name: str | None
    candidate_bio: str | None
    candidate_url: str | None
    candidate_photo_sha256: str | None
    candidate_photo_phash: str | None
    name_similarity: float
    handle_similarity: float
    bio_similarity: float
    photo_similarity: float | None
    aggregate_score: float
    signals: list[str]
    state: str
    state_reason: str | None
    state_changed_at: datetime | None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post(
    "/impersonations/check", response_model=ImpersonationFindingResponse | None
)
async def check_impersonation(
    body: ImpersonationCheckRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    vip = await db.get(VipProfile, body.vip_profile_id)
    if not vip or vip.organization_id != body.organization_id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "VIP not found in this organization"
        )

    official_accounts = (
        await db.execute(
            select(SocialAccount).where(
                and_(
                    SocialAccount.organization_id == body.organization_id,
                    SocialAccount.platform == body.platform.value,
                    SocialAccount.is_official == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    official_handles = [a.handle for a in official_accounts]

    score = score_candidate(
        candidate_handle=body.candidate_handle,
        candidate_display_name=body.candidate_display_name,
        candidate_bio=body.candidate_bio,
        candidate_photo_phash=body.candidate_photo_phash,
        vip=vip,
        official_handles=official_handles,
    )

    # If aggregate is below threshold, skip persisting (no row to return)
    if score.verdict == "ignore":
        return None

    cand_handle = body.candidate_handle.lstrip("@")
    existing = (
        await db.execute(
            select(ImpersonationFinding).where(
                and_(
                    ImpersonationFinding.organization_id == body.organization_id,
                    ImpersonationFinding.platform == body.platform.value,
                    ImpersonationFinding.candidate_handle == cand_handle,
                    ImpersonationFinding.kind == ImpersonationKind.EXECUTIVE.value,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.name_similarity = score.name_similarity
        existing.handle_similarity = score.handle_similarity
        existing.bio_similarity = score.bio_similarity
        existing.photo_similarity = score.photo_similarity
        existing.aggregate_score = score.aggregate_score
        existing.signals = score.signals
        existing.candidate_display_name = body.candidate_display_name
        existing.candidate_bio = body.candidate_bio
        existing.candidate_url = body.candidate_url
        existing.candidate_photo_phash = body.candidate_photo_phash
        existing.candidate_photo_sha256 = body.candidate_photo_sha256
        await db.commit()
        await db.refresh(existing)
        return existing

    # State auto-set: confirmed → CONFIRMED. review → OPEN.
    state = (
        ImpersonationState.CONFIRMED
        if score.verdict == "confirmed"
        else ImpersonationState.OPEN
    )
    finding = ImpersonationFinding(
        organization_id=body.organization_id,
        vip_profile_id=vip.id,
        kind=ImpersonationKind.EXECUTIVE.value,
        platform=body.platform.value,
        candidate_handle=cand_handle,
        candidate_display_name=body.candidate_display_name,
        candidate_bio=body.candidate_bio,
        candidate_url=body.candidate_url,
        candidate_photo_phash=body.candidate_photo_phash,
        candidate_photo_sha256=body.candidate_photo_sha256,
        name_similarity=score.name_similarity,
        handle_similarity=score.handle_similarity,
        bio_similarity=score.bio_similarity,
        photo_similarity=score.photo_similarity,
        aggregate_score=score.aggregate_score,
        signals=score.signals,
        state=state.value,
        detected_at=datetime.now(timezone.utc),
        raw={"rationale": score.rationale},
    )
    db.add(finding)
    await db.flush()

    # Audit D12 + D13 — confirmed impersonations are HIGH severity for
    # auto-casing; reviews are MEDIUM (no case, but a notification still
    # fires so an analyst can triage in their tool of choice).
    try:
        from src.cases.auto_link import auto_link_finding

        sev = "high" if state == ImpersonationState.CONFIRMED else "medium"
        await auto_link_finding(
            db,
            organization_id=body.organization_id,
            finding_type="impersonation",
            finding_id=finding.id,
            severity=sev,
            title=f"{body.platform.value} impersonation: {cand_handle}",
            summary=f"VIP {vip.full_name} impersonated by {cand_handle} ({score.aggregate_score:.2f})",
            event_kind="impersonation_detection",
            dedup_key=f"impersonation:{body.platform.value}:{cand_handle}",
            tags=("impersonation", body.platform.value),
        )
    except Exception:  # noqa: BLE001
        import logging as _logging
        _logging.getLogger(__name__).exception(
            "auto_link_finding failed for impersonation %s", finding.id
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.IMPERSONATION_DETECT,
        user=analyst,
        resource_type="impersonation_finding",
        resource_id=str(finding.id),
        details={
            "platform": body.platform.value,
            "handle": cand_handle,
            "score": score.aggregate_score,
            "verdict": score.verdict,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get(
    "/impersonations", response_model=list[ImpersonationFindingResponse]
)
async def list_impersonations(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: ImpersonationState | None = None,
    platform: SocialPlatform | None = None,
    min_score: Annotated[float, Query(ge=0, le=1)] = 0.0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(ImpersonationFinding).where(
        and_(
            ImpersonationFinding.organization_id == organization_id,
            ImpersonationFinding.aggregate_score >= min_score,
        )
    )
    if state is not None:
        q = q.where(ImpersonationFinding.state == state.value)
    if platform is not None:
        q = q.where(ImpersonationFinding.platform == platform.value)
    q = q.order_by(
        ImpersonationFinding.aggregate_score.desc(),
        ImpersonationFinding.detected_at.desc(),
    ).limit(limit)
    return list((await db.execute(q)).scalars().all())


class ImpersonationStateChange(BaseModel):
    to_state: ImpersonationState
    reason: str | None = None


@router.post(
    "/impersonations/{finding_id}/state",
    response_model=ImpersonationFindingResponse,
)
async def change_impersonation_state(
    finding_id: uuid.UUID,
    body: ImpersonationStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(ImpersonationFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if body.to_state.value == f.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {f.state}")
    if body.to_state in (
        ImpersonationState.TAKEDOWN_REQUESTED,
        ImpersonationState.DISMISSED,
        ImpersonationState.CLEARED,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required for this state",
            )
    from_state = f.state
    f.state = body.to_state.value
    f.state_changed_at = datetime.now(timezone.utc)
    f.state_changed_by_user_id = analyst.id
    f.state_reason = body.reason
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.IMPERSONATION_STATE_CHANGE,
        user=analyst,
        resource_type="impersonation_finding",
        resource_id=str(f.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    return f


# --- Mobile app findings ----------------------------------------------


class MobileAppCheckRequest(BaseModel):
    organization_id: uuid.UUID
    store: MobileAppStore
    app_id: str
    title: str
    publisher: str | None = None
    description: str | None = None
    url: str | None = None
    icon_sha256: str | None = None
    rating: float | None = None
    install_estimate: str | None = None
    matched_term: str
    matched_term_kind: str = "name"
    is_official_publisher: bool = False


class MobileAppFindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    store: str
    app_id: str
    title: str
    publisher: str | None
    description: str | None
    url: str | None
    icon_sha256: str | None
    rating: float | None
    install_estimate: str | None
    matched_term: str
    matched_term_kind: str
    is_official_publisher: bool
    state: str
    state_reason: str | None
    state_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post(
    "/mobile-apps/check", response_model=MobileAppFindingResponse, status_code=201
)
async def record_mobile_app(
    body: MobileAppCheckRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    finding = MobileAppFinding(
        organization_id=body.organization_id,
        store=body.store.value,
        app_id=body.app_id,
        title=body.title,
        publisher=body.publisher,
        description=body.description,
        url=body.url,
        icon_sha256=body.icon_sha256,
        rating=body.rating,
        install_estimate=body.install_estimate,
        matched_term=body.matched_term,
        matched_term_kind=body.matched_term_kind,
        is_official_publisher=body.is_official_publisher,
        state=MobileAppFindingState.OPEN.value,
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "App already recorded for this org"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.MOBILE_APP_DETECT,
        user=analyst,
        resource_type="mobile_app_finding",
        resource_id=str(finding.id),
        details={
            "store": body.store.value,
            "app_id": body.app_id,
            "title": body.title,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/mobile-apps", response_model=list[MobileAppFindingResponse])
async def list_mobile_apps(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: MobileAppFindingState | None = None,
    store: MobileAppStore | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(MobileAppFinding).where(
        MobileAppFinding.organization_id == organization_id
    )
    if state is not None:
        q = q.where(MobileAppFinding.state == state.value)
    if store is not None:
        q = q.where(MobileAppFinding.store == store.value)
    q = q.order_by(MobileAppFinding.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


class MobileAppStateChange(BaseModel):
    to_state: MobileAppFindingState
    reason: str | None = None


class FraudCheckRequest(BaseModel):
    organization_id: uuid.UUID
    channel: FraudChannel
    target_identifier: str = Field(min_length=1, max_length=500)
    text: str = Field(min_length=1)
    title: str | None = None
    min_score: float = Field(default=0.4, ge=0.0, le=1.0)


class FraudFindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    kind: str
    channel: str
    target_identifier: str
    title: str | None
    excerpt: str | None
    matched_brand_terms: list[str]
    matched_keywords: list[str]
    score: float
    rationale: str | None
    detected_at: datetime
    state: str
    state_reason: str | None
    state_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FraudStateChange(BaseModel):
    to_state: FraudState
    reason: str | None = None


@router.post(
    "/fraud/check",
    response_model=FraudFindingResponse | None,
)
async def check_fraud(
    body: FraudCheckRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Score a chunk of text against the fraud vocabulary; persist a
    FraudFinding when the score crosses ``min_score``. Returns null when
    score is below the threshold.
    """
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    terms = (
        await db.execute(
            select(BrandTerm.value).where(
                and_(
                    BrandTerm.organization_id == body.organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    score = fraud_score_text(body.text, brand_terms=terms)
    if score.score < body.min_score:
        return None

    existing = (
        await db.execute(
            select(FraudFinding).where(
                and_(
                    FraudFinding.organization_id == body.organization_id,
                    FraudFinding.channel == body.channel.value,
                    FraudFinding.target_identifier == body.target_identifier,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.score = score.score
        existing.kind = (
            FraudKind(score.kind).value
            if score.kind in [k.value for k in FraudKind]
            else FraudKind.OTHER.value
        )
        existing.matched_brand_terms = score.matched_brand_terms
        existing.matched_keywords = score.matched_keywords
        existing.rationale = score.rationale
        existing.excerpt = body.text[:2000]
        await db.commit()
        await db.refresh(existing)
        return existing

    finding = FraudFinding(
        organization_id=body.organization_id,
        kind=(
            FraudKind(score.kind).value
            if score.kind in [k.value for k in FraudKind]
            else FraudKind.OTHER.value
        ),
        channel=body.channel.value,
        target_identifier=body.target_identifier,
        title=body.title,
        excerpt=body.text[:2000],
        matched_brand_terms=score.matched_brand_terms,
        matched_keywords=score.matched_keywords,
        score=score.score,
        rationale=score.rationale,
        detected_at=datetime.now(timezone.utc),
        state=FraudState.OPEN.value,
        raw=score.extra,
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Already recorded for this target"
        )

    # Audit D12 + D13 — fraud findings escalate by score band:
    # ≥0.85 → high (auto-case + page), ≥0.6 → medium (notify-only).
    try:
        from src.cases.auto_link import auto_link_finding

        sev = "high" if score.score >= 0.85 else "medium"
        await auto_link_finding(
            db,
            organization_id=body.organization_id,
            finding_type="fraud",
            finding_id=finding.id,
            severity=sev,
            title=f"Fraud finding ({finding.kind}): {body.title or body.target_identifier}",
            summary=score.rationale or "",
            event_kind="phishing_detection",
            dedup_key=f"fraud:{body.channel.value}:{body.target_identifier}",
            tags=("fraud", finding.kind, body.channel.value),
        )
    except Exception:  # noqa: BLE001
        import logging as _logging
        _logging.getLogger(__name__).exception(
            "auto_link_finding failed for fraud %s", finding.id
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.FRAUD_FINDING_DETECT,
        user=analyst,
        resource_type="fraud_finding",
        resource_id=str(finding.id),
        details={
            "kind": finding.kind,
            "channel": finding.channel,
            "score": finding.score,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/fraud", response_model=list[FraudFindingResponse])
async def list_fraud_findings(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: FraudState | None = None,
    channel: FraudChannel | None = None,
    kind: FraudKind | None = None,
    min_score: Annotated[float, Query(ge=0, le=1)] = 0.0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(FraudFinding).where(
        and_(
            FraudFinding.organization_id == organization_id,
            FraudFinding.score >= min_score,
        )
    )
    if state is not None:
        q = q.where(FraudFinding.state == state.value)
    if channel is not None:
        q = q.where(FraudFinding.channel == channel.value)
    if kind is not None:
        q = q.where(FraudFinding.kind == kind.value)
    q = q.order_by(FraudFinding.score.desc(), FraudFinding.detected_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.post(
    "/fraud/{finding_id}/state", response_model=FraudFindingResponse
)
async def change_fraud_state(
    finding_id: uuid.UUID,
    body: FraudStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(FraudFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if body.to_state.value == f.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {f.state}")
    if body.to_state in (
        FraudState.REPORTED_TO_REGULATOR,
        FraudState.TAKEDOWN_REQUESTED,
        FraudState.DISMISSED,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required for this state",
            )
    from_state = f.state
    f.state = body.to_state.value
    f.state_changed_at = datetime.now(timezone.utc)
    f.state_changed_by_user_id = analyst.id
    f.state_reason = body.reason
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.FRAUD_FINDING_STATE_CHANGE,
        user=analyst,
        resource_type="fraud_finding",
        resource_id=str(f.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    return f


@router.post(
    "/mobile-apps/{finding_id}/state", response_model=MobileAppFindingResponse
)
async def change_mobile_app_state(
    finding_id: uuid.UUID,
    body: MobileAppStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(MobileAppFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if body.to_state.value == f.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {f.state}")
    if body.to_state in (
        MobileAppFindingState.TAKEDOWN_REQUESTED,
        MobileAppFindingState.DISMISSED,
        MobileAppFindingState.CLEARED,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required for this state",
            )
    from_state = f.state
    f.state = body.to_state.value
    f.state_changed_at = datetime.now(timezone.utc)
    f.state_changed_by_user_id = analyst.id
    f.state_reason = body.reason
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.MOBILE_APP_STATE_CHANGE,
        user=analyst,
        resource_type="mobile_app_finding",
        resource_id=str(f.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    return f
