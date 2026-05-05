"""Data Leakage API (Phase 5).

Endpoints
---------
    POST  /leakage/bins/import                     Bulk-import BIN registry (CSV)
    GET   /leakage/bins?organization_id=…          List BINs
    POST  /leakage/cards/scan                      Scan a chunk of text for leaked cards
    GET   /leakage/cards?organization_id=…         List card-leakage findings
    POST  /leakage/cards/{id}/state                State change

    POST  /leakage/policies                        Create DLP policy
    GET   /leakage/policies?organization_id=…      List policies
    DELETE /leakage/policies/{id}                  Delete
    POST  /leakage/policies/{id}/test              Test against arbitrary text
    POST  /leakage/dlp/scan                        Run all policies vs text
    GET   /leakage/dlp?organization_id=…           List DLP findings
    POST  /leakage/dlp/{id}/state                  State change
"""

from __future__ import annotations

import csv
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
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.leakage.cards import scan_text as scan_cards
from src.leakage.dlp import evaluate_policy, scan_text as scan_dlp
from src.models.auth import AuditAction
from src.models.leakage import (
    CardLeakageFinding,
    CardScheme,
    CardType,
    CreditCardBin,
    DlpFinding,
    DlpPolicy,
    DlpPolicyKind,
    LeakageState,
)
from src.models.threat import Organization
from src.storage.database import get_session

router = APIRouter(prefix="/leakage", tags=["Compliance & DLP"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- BINs --------------------------------------------------------------


class BinResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    bin_prefix: str
    issuer: str | None
    scheme: str
    card_type: str
    country_code: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class BinImportResult(BaseModel):
    inserted: int
    skipped_duplicates: int
    errors: list[dict]


@router.post("/bins/import", response_model=BinImportResult)
async def import_bins(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID | None, Form()] = None,
    file: Annotated[UploadFile, File()] = None,
    db: AsyncSession = Depends(get_session),
):
    """Bulk import BINs from a CSV. Required columns:
    ``bin_prefix,issuer,scheme,card_type,country_code``.
    """
    if file is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "file required")
    if organization_id is not None:
        org = await db.get(Organization, organization_id)
        if not org:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    raw = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames or "bin_prefix" not in reader.fieldnames:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "CSV must have a 'bin_prefix' column",
        )
    inserted = 0
    skipped = 0
    errors: list[dict] = []
    for idx, row in enumerate(reader):
        prefix = (row.get("bin_prefix") or "").strip()
        if not prefix.isdigit() or not (4 <= len(prefix) <= 8):
            errors.append({"index": idx, "error": "invalid bin_prefix"})
            continue
        try:
            scheme = CardScheme((row.get("scheme") or "other").strip().lower()).value
        except ValueError:
            scheme = CardScheme.OTHER.value
        try:
            card_type = CardType((row.get("card_type") or "unknown").strip().lower()).value
        except ValueError:
            card_type = CardType.UNKNOWN.value

        existing = (
            await db.execute(
                select(CreditCardBin).where(
                    and_(
                        CreditCardBin.organization_id == organization_id,
                        CreditCardBin.bin_prefix == prefix,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            skipped += 1
            continue
        db.add(
            CreditCardBin(
                organization_id=organization_id,
                bin_prefix=prefix,
                issuer=(row.get("issuer") or "").strip() or None,
                scheme=scheme,
                card_type=card_type,
                country_code=((row.get("country_code") or "").strip().upper() or None),
            )
        )
        inserted += 1
    if inserted or skipped or errors:
        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.CARD_BIN_IMPORT,
            user=analyst,
            resource_type="credit_card_bin",
            resource_id=str(organization_id) if organization_id else "global",
            details={"inserted": inserted, "skipped": skipped, "errors": len(errors)},
            ip_address=ip,
            user_agent=ua,
        )
    await db.commit()
    return BinImportResult(inserted=inserted, skipped_duplicates=skipped, errors=errors)


@router.get("/bins", response_model=list[BinResponse])
async def list_bins(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    scheme: CardScheme | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
):
    q = select(CreditCardBin)
    if organization_id is not None:
        q = q.where(
            (CreditCardBin.organization_id == organization_id)
            | (CreditCardBin.organization_id.is_(None))
        )
    if scheme is not None:
        q = q.where(CreditCardBin.scheme == scheme.value)
    q = q.order_by(CreditCardBin.bin_prefix).limit(limit)
    return list((await db.execute(q)).scalars().all())


# --- Card scan + findings ---------------------------------------------


class CardScanRequest(BaseModel):
    organization_id: uuid.UUID
    text: str
    source_url: str | None = None
    source_kind: str | None = None
    require_bin_match: bool = True


class CardScanResponse(BaseModel):
    candidates: int
    new_findings: int
    seen_again: int


class CardLeakageResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    pan_first6: str
    pan_last4: str
    pan_sha256: str
    matched_bin_id: uuid.UUID | None
    issuer: str | None
    scheme: str
    card_type: str
    source_url: str | None
    source_kind: str | None
    excerpt: str | None
    expiry: str | None
    state: str
    state_reason: str | None
    state_changed_at: datetime | None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    classification: dict | None = None
    correlated_findings: dict | None = None
    breach_correlations: dict | None = None
    takedown_draft: str | None = None

    model_config = {"from_attributes": True}


@router.post("/cards/scan", response_model=CardScanResponse)
async def cards_scan(
    body: CardScanRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    report = await scan_cards(
        db,
        body.organization_id,
        body.text,
        source_url=body.source_url,
        source_kind=body.source_kind,
        require_bin_match=body.require_bin_match,
    )
    if report.new_findings:
        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.CARD_LEAK_DETECT,
            user=analyst,
            resource_type="organization",
            resource_id=str(body.organization_id),
            details={
                "new_findings": report.new_findings,
                "candidates": report.candidates,
                "source_url": body.source_url,
            },
            ip_address=ip,
            user_agent=ua,
        )
    await db.commit()
    return CardScanResponse(
        candidates=report.candidates,
        new_findings=report.new_findings,
        seen_again=report.seen_again,
    )


@router.get("/cards", response_model=list[CardLeakageResponse])
async def list_card_findings(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: LeakageState | None = None,
    issuer: str | None = None,
    bin_prefix: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(CardLeakageFinding).where(
        CardLeakageFinding.organization_id == organization_id
    )
    if state is not None:
        q = q.where(CardLeakageFinding.state == state.value)
    if issuer:
        q = q.where(CardLeakageFinding.issuer.ilike(f"%{issuer}%"))
    if bin_prefix:
        q = q.where(CardLeakageFinding.pan_first6.like(f"{bin_prefix}%"))
    q = q.order_by(CardLeakageFinding.detected_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


class CardStateChange(BaseModel):
    to_state: LeakageState
    reason: str | None = None


@router.post(
    "/cards/{finding_id}/state", response_model=CardLeakageResponse
)
async def change_card_state(
    finding_id: uuid.UUID,
    body: CardStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(CardLeakageFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if body.to_state.value == f.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {f.state}")
    if body.to_state in (
        LeakageState.NOTIFIED,
        LeakageState.REISSUED,
        LeakageState.DISMISSED,
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
        AuditAction.CARD_LEAK_STATE_CHANGE,
        user=analyst,
        resource_type="card_leakage_finding",
        resource_id=str(f.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    return f


# --- DLP policies + findings -----------------------------------------


class DlpPolicyCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    kind: DlpPolicyKind
    pattern: str = Field(min_length=1)
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low|info)$")
    description: str | None = None
    enabled: bool = True


class DlpPolicyResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    kind: str
    pattern: str
    severity: str
    description: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DlpScanRequest(BaseModel):
    organization_id: uuid.UUID
    text: str
    source_url: str | None = None
    source_kind: str | None = None


class DlpScanResponse(BaseModel):
    policies_evaluated: int
    findings_created: int
    matches_found: int


class DlpFindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    policy_id: uuid.UUID | None
    policy_name: str
    severity: str
    source_url: str | None
    source_kind: str | None
    matched_count: int
    matched_excerpts: list[str]
    state: str
    state_reason: str | None
    state_changed_at: datetime | None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    classification: dict | None = None
    correlated_findings: dict | None = None
    breach_correlations: dict | None = None
    takedown_draft: str | None = None

    model_config = {"from_attributes": True}


class DlpPolicyTestRequest(BaseModel):
    text: str


@router.post("/policies", response_model=DlpPolicyResponse, status_code=201)
async def create_policy(
    body: DlpPolicyCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    # Validate regex compiles + reject catastrophic-backtracking shapes (Audit B8).
    if body.kind == DlpPolicyKind.REGEX:
        import re as _re

        from src.leakage.dlp import regex_pattern_is_dangerous

        try:
            _re.compile(body.pattern)
        except _re.error as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid regex: {e}"
            )
        if regex_pattern_is_dangerous(body.pattern):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "regex appears to contain a nested quantifier likely to "
                "cause catastrophic backtracking; rewrite the pattern",
            )
    policy = DlpPolicy(
        organization_id=body.organization_id,
        name=body.name.strip(),
        kind=body.kind.value,
        pattern=body.pattern,
        severity=body.severity,
        description=body.description,
        enabled=body.enabled,
    )
    db.add(policy)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Policy name already used in this org"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DLP_POLICY_CREATE,
        user=analyst,
        resource_type="dlp_policy",
        resource_id=str(policy.id),
        details={"name": policy.name, "kind": policy.kind},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/policies", response_model=list[DlpPolicyResponse])
async def list_policies(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    enabled: bool | None = None,
):
    q = select(DlpPolicy).where(DlpPolicy.organization_id == organization_id)
    if enabled is not None:
        q = q.where(DlpPolicy.enabled == enabled)
    return list((await db.execute(q.order_by(DlpPolicy.created_at.desc()))).scalars().all())


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    p = await db.get(DlpPolicy, policy_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    org_id = p.organization_id
    name = p.name
    await db.delete(p)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DLP_POLICY_DELETE,
        user=analyst,
        resource_type="dlp_policy",
        resource_id=str(policy_id),
        details={"organization_id": str(org_id), "name": name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.post("/policies/{policy_id}/test")
async def test_policy(
    policy_id: uuid.UUID,
    body: DlpPolicyTestRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    p = await db.get(DlpPolicy, policy_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    import time as _time
    _started = _time.perf_counter()
    excerpts = evaluate_policy(p, body.text)
    _duration_ms = int((_time.perf_counter() - _started) * 1000)
    return {
        "matched": len(excerpts),
        "excerpts": excerpts[:25],
        "duration_ms": _duration_ms,
    }


@router.post("/dlp/scan", response_model=DlpScanResponse)
async def dlp_scan(
    body: DlpScanRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    report = await scan_dlp(
        db,
        body.organization_id,
        body.text,
        source_url=body.source_url,
        source_kind=body.source_kind,
    )
    if report.findings_created:
        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.DLP_FINDING_DETECT,
            user=analyst,
            resource_type="organization",
            resource_id=str(body.organization_id),
            details={
                "policies_evaluated": report.policies_evaluated,
                "findings_created": report.findings_created,
                "matches_found": report.matches_found,
            },
            ip_address=ip,
            user_agent=ua,
        )
    await db.commit()
    return DlpScanResponse(
        policies_evaluated=report.policies_evaluated,
        findings_created=report.findings_created,
        matches_found=report.matches_found,
    )


@router.get("/dlp", response_model=list[DlpFindingResponse])
async def list_dlp_findings(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: LeakageState | None = None,
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(DlpFinding).where(DlpFinding.organization_id == organization_id)
    if state is not None:
        q = q.where(DlpFinding.state == state.value)
    if severity:
        q = q.where(DlpFinding.severity == severity)
    q = q.order_by(DlpFinding.detected_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


class DlpStateChange(BaseModel):
    to_state: LeakageState
    reason: str | None = None


@router.post("/dlp/{finding_id}/state", response_model=DlpFindingResponse)
async def change_dlp_state(
    finding_id: uuid.UUID,
    body: DlpStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(DlpFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if body.to_state.value == f.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {f.state}")
    if body.to_state in (
        LeakageState.NOTIFIED,
        LeakageState.REISSUED,
        LeakageState.DISMISSED,
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
        AuditAction.DLP_FINDING_STATE_CHANGE,
        user=analyst,
        resource_type="dlp_finding",
        resource_id=str(f.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    return f


# --- Agentic surfaces -------------------------------------------------
#
# Each finding row now carries Bridge-LLM-generated metadata:
#   classification         severity classifier output
#   correlated_findings    cross-org PAN/email overlap data
#   breach_correlations    HIBP per-email breach hits
#   takedown_draft         operator-triggered DMCA / abuse notice
#
# These three endpoints expose that metadata and the on-demand
# takedown drafter to the dashboard.


class TakedownDraftResponse(BaseModel):
    finding_id: uuid.UUID
    kind: str
    status: str  # "queued" | "ready"
    draft: str | None
    queued_task_id: uuid.UUID | None


async def _kick_takedown(
    db: AsyncSession,
    *,
    finding_id: uuid.UUID,
    kind: str,
    organization_id: uuid.UUID,
    existing_draft: str | None,
) -> TakedownDraftResponse:
    """Common path for both DLP and card takedown endpoints.

    Returns the existing draft if present (idempotent re-invoke), else
    enqueues a ``leakage_takedown_draft`` agent task and returns a
    ``queued`` response. The agent worker writes the draft to the row;
    the dashboard polls this endpoint until ``status == "ready"``.
    """
    if existing_draft and existing_draft.strip():
        return TakedownDraftResponse(
            finding_id=finding_id,
            kind=kind,
            status="ready",
            draft=existing_draft,
            queued_task_id=None,
        )
    from src.llm.agent_queue import enqueue as _enqueue

    task = await _enqueue(
        db,
        kind="leakage_takedown_draft",
        payload={"finding_id": str(finding_id), "kind": kind},
        organization_id=organization_id,
        # Per-finding dedup so re-clicking the button before the worker
        # finishes returns the same task instead of queuing a second.
        dedup_key=f"takedown:{kind}:{finding_id}",
        priority=4,
    )
    return TakedownDraftResponse(
        finding_id=finding_id,
        kind=kind,
        status="queued" if (task.status or "").lower() in ("queued", "running") else "ready",
        draft=None,
        queued_task_id=task.id,
    )


@router.post("/dlp/{finding_id}/draft-takedown", response_model=TakedownDraftResponse)
async def draft_takedown_dlp(
    finding_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(DlpFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return await _kick_takedown(
        db,
        finding_id=f.id,
        kind="dlp",
        organization_id=f.organization_id,
        existing_draft=f.takedown_draft,
    )


@router.post("/cards/{finding_id}/draft-takedown", response_model=TakedownDraftResponse)
async def draft_takedown_card(
    finding_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(CardLeakageFinding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return await _kick_takedown(
        db,
        finding_id=f.id,
        kind="card",
        organization_id=f.organization_id,
        existing_draft=f.takedown_draft,
    )


class AgentSummaryResponse(BaseModel):
    finding_id: uuid.UUID
    kind: str
    severity: str
    state: str
    classification: dict | None
    correlated_findings: dict | None
    breach_correlations: dict | None
    agent_summary: dict | None
    takedown_draft: str | None


@router.get("/findings/{finding_id}/agent-summary", response_model=AgentSummaryResponse)
async def finding_agent_summary(
    finding_id: uuid.UUID,
    analyst: AnalystUser,
    kind: Annotated[str | None, Query(pattern="^(dlp|card)$")] = None,
    db: AsyncSession = Depends(get_session),
):
    """Return the LLM-derived metadata for a single finding.

    ``kind`` is optional — when omitted we look up DLP first, then card.
    """
    if kind == "dlp" or kind is None:
        dlp = await db.get(DlpFinding, finding_id)
        if dlp is not None:
            return AgentSummaryResponse(
                finding_id=dlp.id,
                kind="dlp",
                severity=dlp.severity,
                state=dlp.state,
                classification=dlp.classification,
                correlated_findings=dlp.correlated_findings,
                breach_correlations=dlp.breach_correlations,
                agent_summary=dlp.agent_summary,
                takedown_draft=dlp.takedown_draft,
            )
    if kind == "card" or kind is None:
        card = await db.get(CardLeakageFinding, finding_id)
        if card is not None:
            return AgentSummaryResponse(
                finding_id=card.id,
                kind="card",
                severity=card.severity,
                state=card.state,
                classification=card.classification,
                correlated_findings=card.correlated_findings,
                breach_correlations=card.breach_correlations,
                agent_summary=card.agent_summary,
                takedown_draft=card.takedown_draft,
            )
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")


class PolicyTuneRequest(BaseModel):
    organization_id: uuid.UUID


class PolicyTuneResponse(BaseModel):
    organization_id: uuid.UUID
    queued_task_id: uuid.UUID
    status: str


@router.post("/policies/tune", response_model=PolicyTuneResponse)
async def kick_policy_tune(
    body: PolicyTuneRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Queue the regex-tuning agent for an org's policies.

    The agent runs every enabled DLP policy against the bundled benign
    corpus, computes per-policy false-positive rate, and (for any
    policy above 20% FP) asks Bridge for a tighter pattern. Results
    surface as NotificationInbox suggestions tagged
    ``leakage_policy_tune_suggestion``.
    """
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    from src.llm.agent_queue import enqueue as _enqueue

    # One outstanding tune per org per hour — re-running mid-task just
    # noises up the inbox.
    bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    task = await _enqueue(
        db,
        kind="leakage_policy_tune",
        payload={"organization_id": str(body.organization_id)},
        organization_id=body.organization_id,
        dedup_key=f"tune:{body.organization_id}:{bucket}",
        priority=8,
    )
    return PolicyTuneResponse(
        organization_id=body.organization_id,
        queued_task_id=task.id,
        status=task.status,
    )
