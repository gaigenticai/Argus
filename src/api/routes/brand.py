"""Brand Protection API.

Endpoints
---------
    POST   /brand/terms                       create
    GET    /brand/terms?organization_id=…     list
    DELETE /brand/terms/{id}                  delete
    POST   /brand/scan?organization_id=…      run typosquat scan
    GET    /brand/suspects?organization_id=…  list suspect domains
    POST   /brand/suspects/{id}/state         transition state
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.brand.feed import (
    domains_from_certstream_message,
    ingest_candidates,
    parse_whoisds_blob,
)
from src.brand.logo_match import compare as compare_logos
from src.brand.logo_match import fingerprint as fingerprint_logo
from src.brand.probe import probe_suspect
from src.brand.scanner import ResolutionResult, scan_organization
from src.config.settings import settings
from src.models.evidence import EvidenceBlob, EvidenceKind
from src.models.live_probe import LiveProbe, LiveProbeVerdict
from src.models.logo import BrandLogo, LogoMatch, LogoMatchVerdict
from src.storage import evidence_store
from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.brand import (
    BrandTerm,
    BrandTermKind,
    SuspectDomain,
    SuspectDomainSource,
    SuspectDomainState,
)
from src.models.threat import Organization
from src.storage.database import get_session


router = APIRouter(prefix="/brand", tags=["Brand Protection"])


# Allow tests to inject a fake resolver via module-level swap.
_TEST_RESOLVER = None


def set_test_resolver(fn) -> None:
    """Test-only hook: replace the resolver used by /brand/scan."""
    global _TEST_RESOLVER
    _TEST_RESOLVER = fn


def reset_test_resolver() -> None:
    global _TEST_RESOLVER
    _TEST_RESOLVER = None


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- Schemas ------------------------------------------------------------


class BrandTermCreate(BaseModel):
    organization_id: uuid.UUID
    kind: BrandTermKind
    value: str = Field(min_length=1, max_length=255)
    keywords: list[str] = Field(default_factory=list)


class BrandTermResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    kind: str
    value: str
    keywords: list[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    organization_id: uuid.UUID
    terms_scanned: int
    permutations_generated: int
    candidates_resolved: int
    suspects_created: int
    suspects_seen_again: int


class SuspectDomainResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    domain: str
    matched_term_id: uuid.UUID | None
    matched_term_value: str
    similarity: float
    permutation_kind: str | None
    is_resolvable: bool | None
    a_records: list[str]
    mx_records: list[str]
    nameservers: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    state: str
    source: str
    state_reason: str | None
    state_changed_at: datetime | None

    model_config = {"from_attributes": True}


class SuspectStateChange(BaseModel):
    to_state: SuspectDomainState
    reason: str | None = None


# --- Endpoints ----------------------------------------------------------


class BrandOverviewResponse(BaseModel):
    organization_id: uuid.UUID
    terms: dict[str, int]            # by kind
    suspects_total: int
    suspects_by_state: dict[str, int]
    suspects_by_source: dict[str, int]
    suspects_top_similarity: list[dict]
    logos_count: int
    logo_matches_total: int
    logo_matches_by_verdict: dict[str, int]
    # Surfaced so the dashboard can render an explicit warning banner
    # when the customer has registered zero logos — otherwise the
    # logo-abuse engine has nothing to match against and silent zeros
    # would look like a clean signal.
    logo_corpus_health: dict[str, str]
    live_probes_total: int
    live_probes_by_verdict: dict[str, int]
    recent_phishing_probes: list[dict]
    # Audit D14 — Phase 4 rollup so the brand landing page reflects the
    # full surface, not just suspects + logos + probes.
    impersonations_total: int
    impersonations_by_state: dict[str, int]
    mobile_apps_total: int
    mobile_apps_by_state: dict[str, int]
    fraud_findings_total: int
    fraud_findings_by_state: dict[str, int]


@router.get("/overview", response_model=BrandOverviewResponse)
async def brand_overview(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Single read that aggregates the entire brand-protection surface for
    one tenant. Powers the dashboard's "/brand" landing page.
    """
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    from sqlalchemy import func

    terms_rows = (
        await db.execute(
            select(BrandTerm.kind, func.count())
            .where(BrandTerm.organization_id == organization_id)
            .group_by(BrandTerm.kind)
        )
    ).all()
    suspects_state = (
        await db.execute(
            select(SuspectDomain.state, func.count())
            .where(SuspectDomain.organization_id == organization_id)
            .group_by(SuspectDomain.state)
        )
    ).all()
    suspects_source = (
        await db.execute(
            select(SuspectDomain.source, func.count())
            .where(SuspectDomain.organization_id == organization_id)
            .group_by(SuspectDomain.source)
        )
    ).all()
    top_suspects = (
        await db.execute(
            select(SuspectDomain)
            .where(SuspectDomain.organization_id == organization_id)
            .order_by(SuspectDomain.similarity.desc())
            .limit(5)
        )
    ).scalars().all()

    logos_count = (
        await db.execute(
            select(func.count())
            .select_from(BrandLogo)
            .where(BrandLogo.organization_id == organization_id)
        )
    ).scalar() or 0
    logo_match_rows = (
        await db.execute(
            select(LogoMatch.verdict, func.count())
            .where(LogoMatch.organization_id == organization_id)
            .group_by(LogoMatch.verdict)
        )
    ).all()
    probe_rows = (
        await db.execute(
            select(LiveProbe.verdict, func.count())
            .where(LiveProbe.organization_id == organization_id)
            .group_by(LiveProbe.verdict)
        )
    ).all()
    recent_probes = (
        await db.execute(
            select(LiveProbe)
            .where(
                and_(
                    LiveProbe.organization_id == organization_id,
                    LiveProbe.verdict.in_(["phishing", "suspicious"]),
                )
            )
            .order_by(LiveProbe.fetched_at.desc())
            .limit(5)
        )
    ).scalars().all()

    # Audit D14 — Phase 4 rollup.
    from src.models.social import ImpersonationFinding, MobileAppFinding
    from src.models.fraud import FraudFinding

    imp_rows = (
        await db.execute(
            select(ImpersonationFinding.state, func.count())
            .where(ImpersonationFinding.organization_id == organization_id)
            .group_by(ImpersonationFinding.state)
        )
    ).all()
    app_rows = (
        await db.execute(
            select(MobileAppFinding.state, func.count())
            .where(MobileAppFinding.organization_id == organization_id)
            .group_by(MobileAppFinding.state)
        )
    ).all()
    fraud_rows = (
        await db.execute(
            select(FraudFinding.state, func.count())
            .where(FraudFinding.organization_id == organization_id)
            .group_by(FraudFinding.state)
        )
    ).all()

    if logos_count == 0:
        logo_corpus_health = {
            "status": "empty",
            "message": (
                "Logo abuse detection is inactive: no BrandLogo rows are "
                "registered for this organisation. Upload reference logos via "
                "POST /api/v1/brand/logos before the engine can flag rip-offs."
            ),
        }
    else:
        logo_corpus_health = {
            "status": "active",
            "message": f"{logos_count} reference logo(s) registered",
        }

    return BrandOverviewResponse(
        organization_id=organization_id,
        terms={kind: cnt for kind, cnt in terms_rows},
        suspects_total=sum(c for _, c in suspects_state),
        suspects_by_state={state: cnt for state, cnt in suspects_state},
        suspects_by_source={source: cnt for source, cnt in suspects_source},
        suspects_top_similarity=[
            {
                "id": str(s.id),
                "domain": s.domain,
                "matched_term": s.matched_term_value,
                "similarity": s.similarity,
                "state": s.state,
                "source": s.source,
            }
            for s in top_suspects
        ],
        logos_count=logos_count,
        logo_matches_total=sum(c for _, c in logo_match_rows),
        logo_matches_by_verdict={v: c for v, c in logo_match_rows},
        logo_corpus_health=logo_corpus_health,
        live_probes_total=sum(c for _, c in probe_rows),
        live_probes_by_verdict={v: c for v, c in probe_rows},
        recent_phishing_probes=[
            {
                "id": str(p.id),
                "domain": p.domain,
                "verdict": p.verdict,
                "confidence": p.confidence,
                "fetched_at": p.fetched_at.isoformat(),
            }
            for p in recent_probes
        ],
        impersonations_total=sum(c for _, c in imp_rows),
        impersonations_by_state={s: c for s, c in imp_rows},
        mobile_apps_total=sum(c for _, c in app_rows),
        mobile_apps_by_state={s: c for s, c in app_rows},
        fraud_findings_total=sum(c for _, c in fraud_rows),
        fraud_findings_by_state={s: c for s, c in fraud_rows},
    )


@router.post("/terms", response_model=BrandTermResponse, status_code=201)
async def create_term(
    body: BrandTermCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    term = BrandTerm(
        organization_id=body.organization_id,
        kind=body.kind.value,
        value=body.value.strip().lower(),
        keywords=body.keywords,
    )
    db.add(term)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Term already registered for this organization"
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.BRAND_TERM_CREATE,
        user=analyst,
        resource_type="brand_term",
        resource_id=str(term.id),
        details={"kind": body.kind.value, "value": term.value},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(term)
    return term


@router.get("/terms", response_model=list[BrandTermResponse])
async def list_terms(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    is_active: bool | None = None,
):
    q = select(BrandTerm).where(BrandTerm.organization_id == organization_id)
    if is_active is not None:
        q = q.where(BrandTerm.is_active == is_active)
    return list(
        (await db.execute(q.order_by(BrandTerm.created_at.desc()))).scalars().all()
    )


@router.delete("/terms/{term_id}", status_code=204)
async def delete_term(
    term_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    term = await db.get(BrandTerm, term_id)
    if not term:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Term not found")
    org_id = term.organization_id
    value = term.value
    await db.delete(term)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.BRAND_TERM_DELETE,
        user=analyst,
        resource_type="brand_term",
        resource_id=str(term_id),
        details={"organization_id": str(org_id), "value": value},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.post("/scan", response_model=ScanResponse)
async def run_scan(
    organization_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    only_resolvable: bool = True,
    max_permutations_per_term: Annotated[int, Query(ge=10, le=2000)] = 200,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    report = await scan_organization(
        db,
        organization_id,
        resolver=_TEST_RESOLVER,
        only_resolvable=only_resolvable,
        max_permutations_per_term=max_permutations_per_term,
    )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SUSPECT_DOMAIN_DETECT,
        user=analyst,
        resource_type="organization",
        resource_id=str(organization_id),
        details={
            "permutations": report.permutations_generated,
            "suspects_created": report.suspects_created,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return ScanResponse(
        organization_id=organization_id,
        terms_scanned=report.terms_scanned,
        permutations_generated=report.permutations_generated,
        candidates_resolved=report.candidates_resolved,
        suspects_created=report.suspects_created,
        suspects_seen_again=report.suspects_seen_again,
    )


@router.get("/suspects", response_model=list[SuspectDomainResponse])
async def list_suspects(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: SuspectDomainState | None = None,
    source: SuspectDomainSource | None = None,
    domain: str | None = None,
    min_similarity: Annotated[float, Query(ge=0, le=1)] = 0.0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(SuspectDomain).where(
        and_(
            SuspectDomain.organization_id == organization_id,
            SuspectDomain.similarity >= min_similarity,
        )
    )
    if state is not None:
        q = q.where(SuspectDomain.state == state.value)
    if source is not None:
        q = q.where(SuspectDomain.source == source.value)
    if domain:
        q = q.where(SuspectDomain.domain.ilike(f"%{domain.lower()}%"))
    q = q.order_by(
        SuspectDomain.similarity.desc(), SuspectDomain.last_seen_at.desc()
    ).limit(limit)
    return list((await db.execute(q)).scalars().all())


class FeedIngestRequest(BaseModel):
    organization_id: uuid.UUID
    domains: list[str]
    source: SuspectDomainSource = SuspectDomainSource.MANUAL
    min_similarity: float = Field(default=0.7, ge=0.0, le=1.0)


class FeedIngestResponse(BaseModel):
    candidates: int
    matches: int
    suspects_created: int
    suspects_seen_again: int
    skipped_invalid: int


@router.post("/feed/ingest", response_model=FeedIngestResponse)
async def feed_ingest(
    body: FeedIngestRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Ingest a batch of newly-registered / observed domains from any
    feed (CertStream, WhoisDS, manual). Matches each against the org's
    active brand terms; creates SuspectDomain rows for hits.
    """
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    report = await ingest_candidates(
        db,
        body.organization_id,
        body.domains,
        source=body.source,
        min_similarity=body.min_similarity,
    )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SUSPECT_DOMAIN_DETECT,
        user=analyst,
        resource_type="organization",
        resource_id=str(body.organization_id),
        details={
            "feed_source": body.source.value,
            "candidates": report.candidates,
            "matches": report.matches,
            "suspects_created": report.suspects_created,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return FeedIngestResponse(
        candidates=report.candidates,
        matches=report.matches,
        suspects_created=report.suspects_created,
        suspects_seen_again=report.suspects_seen_again,
        skipped_invalid=report.skipped_invalid,
    )


@router.post("/feed/whoisds", response_model=FeedIngestResponse)
async def feed_whoisds_upload(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID, Form()],
    file: Annotated[UploadFile, File()],
    min_similarity: Annotated[float, Query(ge=0, le=1)] = 0.7,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    blob = await file.read()
    if not blob:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "empty upload")
    try:
        domains = parse_whoisds_blob(blob)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))
    report = await ingest_candidates(
        db,
        organization_id,
        domains,
        source=SuspectDomainSource.WHOISDS,
        min_similarity=min_similarity,
    )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SUSPECT_DOMAIN_DETECT,
        user=analyst,
        resource_type="organization",
        resource_id=str(organization_id),
        details={
            "feed_source": "whoisds",
            "candidates": report.candidates,
            "matches": report.matches,
            "suspects_created": report.suspects_created,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return FeedIngestResponse(
        candidates=report.candidates,
        matches=report.matches,
        suspects_created=report.suspects_created,
        suspects_seen_again=report.suspects_seen_again,
        skipped_invalid=report.skipped_invalid,
    )


class LiveProbeResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    suspect_domain_id: uuid.UUID | None
    domain: str
    url: str | None
    fetched_at: datetime
    http_status: int | None
    final_url: str | None
    title: str | None
    html_evidence_sha256: str | None
    screenshot_evidence_sha256: str | None
    verdict: str
    classifier_name: str
    confidence: float
    signals: list[str]
    matched_brand_terms: list[str]
    rationale: str | None
    error_message: str | None
    extra: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class BrandLogoResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    label: str
    description: str | None
    width: int | None
    height: int | None
    image_evidence_sha256: str
    phash_hex: str
    dhash_hex: str
    ahash_hex: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class LogoMatchResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    brand_logo_id: uuid.UUID
    suspect_domain_id: uuid.UUID | None
    live_probe_id: uuid.UUID | None
    candidate_image_sha256: str
    phash_distance: int
    dhash_distance: int
    ahash_distance: int
    color_distance: float
    similarity: float
    verdict: str
    matched_at: datetime
    extra: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post(
    "/logos", response_model=BrandLogoResponse, status_code=201
)
async def register_logo(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID, Form()],
    label: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
    description: Annotated[str | None, Form()] = None,
    db: AsyncSession = Depends(get_session),
):
    """Register a brand logo. Image bytes go to evidence vault; perceptual
    hashes are computed and stored for cheap SQL-side lookups.
    """
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    blob = await file.read()
    if not blob:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "empty upload")
    try:
        fp = fingerprint_logo(blob)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"could not parse image: {e}"
        )

    bucket = settings.evidence.bucket
    sha = evidence_store.sha256_of(blob)
    key = evidence_store.storage_key(str(organization_id), sha)
    evidence_store.ensure_bucket(bucket)
    if not evidence_store.exists(bucket, key):
        evidence_store.put(
            bucket, key, blob, file.content_type or "image/png"
        )
    existing_blob = (
        await db.execute(
            select(EvidenceBlob).where(
                and_(
                    EvidenceBlob.organization_id == organization_id,
                    EvidenceBlob.sha256 == sha,
                )
            )
        )
    ).scalar_one_or_none()
    if existing_blob is None:
        db.add(
            EvidenceBlob(
                organization_id=organization_id,
                sha256=sha,
                size_bytes=len(blob),
                content_type=file.content_type or "image/png",
                original_filename=file.filename,
                kind=EvidenceKind.BRAND_LOGO.value,
                s3_bucket=bucket,
                s3_key=key,
                captured_at=datetime.now(__import__("datetime").timezone.utc),
                captured_by_user_id=analyst.id,
                capture_source="brand_registration",
            )
        )

    logo = BrandLogo(
        organization_id=organization_id,
        label=label.strip(),
        description=description,
        width=fp.width,
        height=fp.height,
        image_evidence_sha256=sha,
        phash_hex=fp.phash_hex,
        dhash_hex=fp.dhash_hex,
        ahash_hex=fp.ahash_hex,
        color_histogram=fp.color_histogram,
    )
    db.add(logo)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An identical logo image is already registered for this org",
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.BRAND_LOGO_REGISTER,
        user=analyst,
        resource_type="brand_logo",
        resource_id=str(logo.id),
        details={"label": logo.label, "sha256": sha},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(logo)
    return logo


@router.get("/logos", response_model=list[BrandLogoResponse])
async def list_logos(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return list(
        (
            await db.execute(
                select(BrandLogo)
                .where(BrandLogo.organization_id == organization_id)
                .order_by(BrandLogo.created_at.desc())
            )
        ).scalars().all()
    )


@router.delete("/logos/{logo_id}", status_code=204)
async def delete_logo(
    logo_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    logo = await db.get(BrandLogo, logo_id)
    if not logo:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Logo not found")
    org_id = logo.organization_id
    label = logo.label
    await db.delete(logo)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.BRAND_LOGO_DELETE,
        user=analyst,
        resource_type="brand_logo",
        resource_id=str(logo_id),
        details={"organization_id": str(org_id), "label": label},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.post(
    "/logos/match", response_model=list[LogoMatchResponse]
)
async def match_logo(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID, Form()],
    file: Annotated[UploadFile, File()],
    suspect_domain_id: Annotated[uuid.UUID | None, Form()] = None,
    live_probe_id: Annotated[uuid.UUID | None, Form()] = None,
    db: AsyncSession = Depends(get_session),
):
    """Compare an uploaded candidate image (e.g. logo cropped from a
    suspect-domain screenshot) against every registered BrandLogo for
    this org. Persists a LogoMatch row for each verdict ≠ no_match.
    """
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    blob = await file.read()
    if not blob:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "empty upload")
    try:
        cand = fingerprint_logo(blob)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"could not parse image: {e}"
        )

    cand_sha = evidence_store.sha256_of(blob)
    bucket = settings.evidence.bucket
    cand_key = evidence_store.storage_key(str(organization_id), cand_sha)
    evidence_store.ensure_bucket(bucket)
    if not evidence_store.exists(bucket, cand_key):
        evidence_store.put(
            bucket, cand_key, blob, file.content_type or "image/png"
        )

    logos = (
        await db.execute(
            select(BrandLogo).where(
                BrandLogo.organization_id == organization_id
            )
        )
    ).scalars().all()
    if not logos:
        return []

    results: list[LogoMatch] = []
    now = datetime.now(__import__("datetime").timezone.utc)
    for logo in logos:
        match = compare_logos(
            cand,
            logo.phash_hex,
            logo.dhash_hex,
            logo.ahash_hex,
            list(logo.color_histogram or []),
        )
        if match.verdict == "no_match":
            continue
        row = LogoMatch(
            organization_id=organization_id,
            brand_logo_id=logo.id,
            suspect_domain_id=suspect_domain_id,
            live_probe_id=live_probe_id,
            candidate_image_sha256=cand_sha,
            phash_distance=match.phash_distance,
            dhash_distance=match.dhash_distance,
            ahash_distance=match.ahash_distance,
            color_distance=match.color_distance,
            similarity=match.similarity,
            verdict=LogoMatchVerdict(match.verdict).value,
            matched_at=now,
            extra={"rationale": match.rationale},
        )
        db.add(row)
        results.append(row)

    if results:
        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.LOGO_MATCH_DETECTED,
            user=analyst,
            resource_type="organization",
            resource_id=str(organization_id),
            details={
                "candidate_sha256": cand_sha,
                "matches": len(results),
                "verdicts": [r.verdict for r in results],
            },
            ip_address=ip,
            user_agent=ua,
        )
    await db.commit()
    for r in results:
        await db.refresh(r)
    return results


@router.get("/logos/matches", response_model=list[LogoMatchResponse])
async def list_logo_matches(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    verdict: LogoMatchVerdict | None = None,
    brand_logo_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(LogoMatch).where(LogoMatch.organization_id == organization_id)
    if verdict is not None:
        q = q.where(LogoMatch.verdict == verdict.value)
    if brand_logo_id is not None:
        q = q.where(LogoMatch.brand_logo_id == brand_logo_id)
    q = q.order_by(LogoMatch.similarity.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.post(
    "/suspects/{suspect_id}/probe", response_model=LiveProbeResponse, status_code=201
)
async def run_live_probe(
    suspect_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Fetch the suspect domain, classify, store evidence, persist a LiveProbe."""
    suspect = await db.get(SuspectDomain, suspect_id)
    if not suspect:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Suspect not found")
    try:
        probe = await probe_suspect(
            db, suspect.organization_id, suspect.id
        )
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))

    # If verdict ≥ suspicious, auto-elevate suspect state to confirmed_phishing
    # only when verdict == phishing AND confidence >= 0.85.
    if (
        probe.verdict == LiveProbeVerdict.PHISHING.value
        and probe.confidence >= 0.85
        and suspect.state == SuspectDomainState.OPEN.value
    ):
        suspect.state = SuspectDomainState.CONFIRMED_PHISHING.value
        suspect.state_reason = (
            f"Auto-elevated by live probe (confidence {probe.confidence:.2f}, "
            f"signals: {', '.join(probe.signals[:5])})"
        )
        suspect.state_changed_at = datetime.now(__import__("datetime").timezone.utc)
        suspect.state_changed_by_user_id = analyst.id

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.LIVE_PROBE_RUN,
        user=analyst,
        resource_type="live_probe",
        resource_id=str(probe.id),
        details={
            "domain": probe.domain,
            "verdict": probe.verdict,
            "confidence": probe.confidence,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(probe)
    return probe


@router.get(
    "/suspects/{suspect_id}/probes", response_model=list[LiveProbeResponse]
)
async def list_probes(
    suspect_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    rows = (
        await db.execute(
            select(LiveProbe)
            .where(LiveProbe.suspect_domain_id == suspect_id)
            .order_by(LiveProbe.fetched_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


@router.get("/probes", response_model=list[LiveProbeResponse])
async def list_probes_for_org(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    response: Response,
    db: AsyncSession = Depends(get_session),
    verdict: str | None = Query(default=None),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Audit B1 — org-scoped live-probe listing for the dashboard's
    Brand Protection → Probes tab. Sorts newest-first; emits the
    standard ``X-Total-Count`` / ``X-Page-Limit`` / ``X-Page-Offset``
    headers via :func:`paginated_response`.
    """
    from src.core.pagination import (
        paginated_response,
        paginated_select,
        parse_paging,
    )

    await db.get(Organization, organization_id)
    base = select(LiveProbe).where(
        LiveProbe.organization_id == organization_id
    )
    if verdict:
        base = base.where(LiveProbe.verdict == verdict)
    base = base.order_by(LiveProbe.fetched_at.desc())
    paging = parse_paging(limit=limit, offset=offset)
    rows, total = await paginated_select(db, base, paging)
    return paginated_response(rows, total, paging, response)


@router.post(
    "/suspects/{suspect_id}/state",
    response_model=SuspectDomainResponse,
)
async def change_suspect_state(
    suspect_id: uuid.UUID,
    body: SuspectStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    s = await db.get(SuspectDomain, suspect_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Suspect not found")
    if body.to_state.value == s.state:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Already {s.state}"
        )
    if body.to_state in (
        SuspectDomainState.CONFIRMED_PHISHING,
        SuspectDomainState.TAKEDOWN_REQUESTED,
        SuspectDomainState.DISMISSED,
        SuspectDomainState.CLEARED,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required to enter this state",
            )

    from_state = s.state
    s.state = body.to_state.value
    s.state_changed_at = datetime.now(__import__("datetime").timezone.utc)
    s.state_changed_by_user_id = analyst.id
    s.state_reason = body.reason

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SUSPECT_DOMAIN_STATE_CHANGE,
        user=analyst,
        resource_type="suspect_domain",
        resource_id=str(s.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(s)
    return s
