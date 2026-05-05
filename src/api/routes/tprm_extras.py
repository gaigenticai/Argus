"""TPRM full-audit endpoints — posture, evidence vault, contract vault,
sanctions, snapshots, percentile, executive dashboard, agents.

Mounted under the same ``/tprm`` prefix; these are additive to the
existing router so the original surface stays stable.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

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
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.tprm_brief_agent import (
    generate_brief,
    generate_playbook,
    run_quarterly_health_check,
)
from src.agents.tprm_questionnaire_autofill_agent import autofill_questionnaire
from src.agents.tprm_soc2_agent import parse_soc2_pdf
from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.threat import Asset, Organization
from src.models.tprm import (
    QuestionnaireInstance,
    VendorContract,
    VendorEvidenceFile,
    VendorPostureSignal,
    VendorScorecard,
    VendorScorecardSnapshot,
)
from src.storage.database import get_session
from src.tprm.percentile import (
    compute_category_percentile,
    compute_global_percentile,
)
from src.tprm.posture import collect_vendor_posture
from src.tprm.snapshots import detect_score_drop, list_snapshots

router = APIRouter(prefix="/tprm", tags=["TPRM"])


_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB cap on PDFs


# --- Posture --------------------------------------------------------


class CollectPostureRequest(BaseModel):
    organization_id: uuid.UUID
    vendor_asset_id: uuid.UUID
    persist: bool = True


@router.post("/posture/collect", response_model=dict)
async def collect_posture(
    body: CollectPostureRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    vendor = await db.get(Asset, body.vendor_asset_id)
    if not vendor or vendor.organization_id != body.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vendor not found")
    out = await collect_vendor_posture(
        db,
        organization_id=body.organization_id,
        vendor=vendor,
        persist=body.persist,
    )
    await db.commit()
    return out


@router.get("/posture/{vendor_asset_id}", response_model=list[dict])
async def list_posture_signals(
    vendor_asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (
        await db.execute(
            select(VendorPostureSignal).where(
                VendorPostureSignal.vendor_asset_id == vendor_asset_id
            )
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "kind": r.kind,
            "severity": r.severity,
            "score": r.score,
            "summary": r.summary,
            "evidence": r.evidence,
            "collected_at": r.collected_at.isoformat() if r.collected_at else None,
        }
        for r in rows
    ]


# --- Snapshots / trends --------------------------------------------


@router.get("/scorecards/{vendor_asset_id}/snapshots", response_model=list[dict])
async def get_snapshots(
    vendor_asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    days: Annotated[int, Query(ge=1, le=365)] = 180,
):
    vendor = await db.get(Asset, vendor_asset_id)
    if vendor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vendor not found")
    rows = await list_snapshots(
        db,
        organization_id=vendor.organization_id,
        vendor_asset_id=vendor_asset_id,
        days=days,
    )
    drop = detect_score_drop(rows) if rows else None
    return {
        "vendor_id": str(vendor_asset_id),
        "snapshots": [
            {
                "score": s.score,
                "grade": s.grade,
                "pillar_scores": s.pillar_scores,
                "snapshot_at": s.snapshot_at.isoformat(),
            }
            for s in rows
        ],
        "drop_alert": drop,
    }


# --- Percentile / peer rank ----------------------------------------


@router.get("/scorecards/{vendor_asset_id}/percentile", response_model=dict)
async def percentile_for_vendor(
    vendor_asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    vendor = await db.get(Asset, vendor_asset_id)
    if vendor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vendor not found")
    current = (
        await db.execute(
            select(VendorScorecard)
            .where(VendorScorecard.vendor_asset_id == vendor_asset_id)
            .where(VendorScorecard.is_current.is_(True))
            .limit(1)
        )
    ).scalar_one_or_none()
    if current is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No current scorecard")
    # All current scorecards in the org for percentile cohort.
    rows = (
        await db.execute(
            select(VendorScorecard, Asset.details)
            .join(Asset, Asset.id == VendorScorecard.vendor_asset_id)
            .where(VendorScorecard.organization_id == vendor.organization_id)
            .where(VendorScorecard.is_current.is_(True))
        )
    ).all()
    all_scores = [float(r[0].score) for r in rows]
    pool = [
        ((r[1] or {}).get("category") or "other", float(r[0].score)) for r in rows
    ]
    category = (vendor.details or {}).get("category") or "other"
    return {
        "vendor_id": str(vendor_asset_id),
        "score": current.score,
        "grade": current.grade,
        "global": compute_global_percentile(current.score, all_scores),
        "category": compute_category_percentile(current.score, category, pool),
    }


# --- Executive dashboard -------------------------------------------


@router.get("/exec-dashboard", response_model=dict)
async def exec_dashboard(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    rows = (
        await db.execute(
            select(VendorScorecard, Asset)
            .join(Asset, Asset.id == VendorScorecard.vendor_asset_id)
            .where(VendorScorecard.organization_id == organization_id)
            .where(VendorScorecard.is_current.is_(True))
        )
    ).all()
    cards = [r[0] for r in rows]
    assets = [r[1] for r in rows]
    if not cards:
        return {
            "organization_id": str(organization_id),
            "vendors_total": 0,
            "by_grade": {},
            "by_tier": {},
            "by_category": {},
            "avg_score": None,
            "below_threshold_count": 0,
            "top_risk": [],
            "compliant_pct": 0.0,
        }
    by_grade: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for c, a in zip(cards, assets):
        by_grade[c.grade] = by_grade.get(c.grade, 0) + 1
        details = a.details or {}
        tier = details.get("tier") or "tier_3"
        by_tier[tier] = by_tier.get(tier, 0) + 1
        cat = details.get("category") or "other"
        by_category[cat] = by_category.get(cat, 0) + 1
    avg = round(sum(c.score for c in cards) / len(cards), 2)
    sorted_cards = sorted(zip(cards, assets), key=lambda x: x[0].score)
    top_risk = [
        {
            "vendor_id": str(a.id),
            "vendor_value": a.value,
            "tier": (a.details or {}).get("tier") or "tier_3",
            "category": (a.details or {}).get("category") or "other",
            "score": c.score,
            "grade": c.grade,
            "pillar_scores": c.pillar_scores,
        }
        for c, a in sorted_cards[:10]
    ]
    threshold = 70.0
    below = sum(1 for c in cards if c.score < threshold)
    return {
        "organization_id": str(organization_id),
        "vendors_total": len(cards),
        "by_grade": by_grade,
        "by_tier": by_tier,
        "by_category": by_category,
        "avg_score": avg,
        "below_threshold_count": below,
        "top_risk": top_risk,
        "compliant_pct": round(100.0 * (len(cards) - below) / len(cards), 1),
    }


# --- Evidence vault ------------------------------------------------


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


@router.post("/evidence/upload", response_model=dict)
async def upload_evidence(
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID = Form(...),
    vendor_asset_id: uuid.UUID = Form(...),
    questionnaire_instance_id: uuid.UUID | None = Form(None),
    question_id: str | None = Form(None),
    parse_soc2: bool = Form(False),
    file: UploadFile = File(...),
):
    vendor = await db.get(Asset, vendor_asset_id)
    if not vendor or vendor.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vendor not found")
    raw = await file.read()
    if not raw:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "empty file"
        )
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large")
    sha = _sha256_bytes(raw)
    storage_key = f"tprm/evidence/{organization_id}/{vendor_asset_id}/{sha}-{file.filename}"
    # Best-effort store in MinIO; fall back to a local-only record so the
    # operator can wire storage later.
    try:
        from src.storage.evidence_store import upload as evidence_upload
        await evidence_upload(storage_key, raw, content_type=file.content_type)
    except Exception:  # noqa: BLE001
        pass

    extracted = None
    if parse_soc2 and (file.content_type or "").endswith("pdf"):
        try:
            extracted = await parse_soc2_pdf(raw)
        except Exception as e:  # noqa: BLE001
            extracted = {"error": str(e)[:300]}

    rec = VendorEvidenceFile(
        organization_id=organization_id,
        vendor_asset_id=vendor_asset_id,
        questionnaire_instance_id=questionnaire_instance_id,
        question_id=question_id,
        file_name=file.filename or "evidence.bin",
        file_size=len(raw),
        mime_type=file.content_type,
        sha256=sha,
        storage_key=storage_key,
        uploaded_by_user_id=analyst.id,
        extracted=extracted,
    )
    db.add(rec)
    await db.flush()
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "unknown")[:500]
    await audit_log(
        db,
        AuditAction.EASM_JOB_RUN,
        user=analyst,
        resource_type="vendor_evidence",
        resource_id=str(rec.id),
        details={"size": len(raw), "sha256": sha, "filename": file.filename},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {
        "id": str(rec.id),
        "sha256": sha,
        "size": len(raw),
        "extracted": extracted,
    }


@router.get("/evidence/{vendor_asset_id}", response_model=list[dict])
async def list_evidence(
    vendor_asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (
        await db.execute(
            select(VendorEvidenceFile).where(
                VendorEvidenceFile.vendor_asset_id == vendor_asset_id
            )
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "file_name": r.file_name,
            "file_size": r.file_size,
            "mime_type": r.mime_type,
            "sha256": r.sha256,
            "questionnaire_instance_id": str(r.questionnaire_instance_id)
            if r.questionnaire_instance_id
            else None,
            "question_id": r.question_id,
            "extracted": r.extracted,
            "uploaded_by_user_id": str(r.uploaded_by_user_id) if r.uploaded_by_user_id else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# --- Contract vault ------------------------------------------------


@router.post("/contracts/upload", response_model=dict)
async def upload_contract(
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID = Form(...),
    vendor_asset_id: uuid.UUID = Form(...),
    title: str = Form(...),
    contract_kind: str | None = Form(None),
    file: UploadFile = File(...),
):
    vendor = await db.get(Asset, vendor_asset_id)
    if not vendor or vendor.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vendor not found")
    raw = await file.read()
    if not raw:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "empty file"
        )
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large")
    sha = _sha256_bytes(raw)
    storage_key = f"tprm/contracts/{organization_id}/{vendor_asset_id}/{sha}-{file.filename}"
    try:
        from src.storage.evidence_store import upload as evidence_upload
        await evidence_upload(storage_key, raw, content_type=file.content_type)
    except Exception:  # noqa: BLE001
        pass

    # Extract dates + clauses heuristically from the PDF.
    extracted = await _extract_contract_clauses(raw)

    effective_date = None
    expiration_date = None
    try:
        if extracted.get("effective_date"):
            effective_date = datetime.fromisoformat(
                extracted["effective_date"]
            ).date()
    except (ValueError, TypeError):
        pass
    try:
        if extracted.get("expiration_date"):
            expiration_date = datetime.fromisoformat(
                extracted["expiration_date"]
            ).date()
    except (ValueError, TypeError):
        pass

    rec = VendorContract(
        organization_id=organization_id,
        vendor_asset_id=vendor_asset_id,
        title=title,
        contract_kind=contract_kind,
        file_name=file.filename or "contract.pdf",
        file_size=len(raw),
        sha256=sha,
        storage_key=storage_key,
        effective_date=effective_date,
        expiration_date=expiration_date,
        extracted_clauses=extracted,
        uploaded_by_user_id=analyst.id,
    )
    db.add(rec)
    await db.flush()
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "unknown")[:500]
    await audit_log(
        db,
        AuditAction.EASM_JOB_RUN,
        user=analyst,
        resource_type="vendor_contract",
        resource_id=str(rec.id),
        details={"title": title, "size": len(raw), "sha256": sha},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {
        "id": str(rec.id),
        "sha256": sha,
        "size": len(raw),
        "extracted": extracted,
    }


async def _extract_contract_clauses(pdf_bytes: bytes) -> dict[str, Any]:
    """Best-effort: pdfplumber + regex for dates / SLAs / DPA / liability cap.
    Returns a dict the FE renders as a clause table."""
    out: dict[str, Any] = {}
    try:
        import io
        import re

        import pdfplumber  # type: ignore

        text_chunks: list[str] = []
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for p in pdf.pages[:60]:
                t = p.extract_text() or ""
                if t:
                    text_chunks.append(t)
        text = "\n".join(text_chunks)
        if not text:
            return {"error": "no extractable text"}
        # Effective / expiration dates.
        eff = re.search(
            r"(?:effective\s+date|commencement\s+date)[^A-Za-z0-9]*([A-Z][a-z]+\s+\d{1,2},?\s+\d{4}|\d{4}-\d{2}-\d{2})",
            text,
            re.I,
        )
        if eff:
            try:
                from dateutil import parser as dparser  # type: ignore

                out["effective_date"] = dparser.parse(eff.group(1)).date().isoformat()
            except Exception:  # noqa: BLE001
                out["effective_date_raw"] = eff.group(1)
        exp = re.search(
            r"(?:expiration|termination|expiry)\s+date[^A-Za-z0-9]*([A-Z][a-z]+\s+\d{1,2},?\s+\d{4}|\d{4}-\d{2}-\d{2})",
            text,
            re.I,
        )
        if exp:
            try:
                from dateutil import parser as dparser  # type: ignore

                out["expiration_date"] = dparser.parse(exp.group(1)).date().isoformat()
            except Exception:  # noqa: BLE001
                out["expiration_date_raw"] = exp.group(1)
        # Liability cap.
        cap = re.search(
            r"(?:liability\s+cap|aggregate\s+liability)[^.]{0,180}",
            text,
            re.I,
        )
        if cap:
            out["liability_clause"] = cap.group(0).strip()[:300]
        # SLA mention.
        sla = re.search(r"(?:service\s+level\s+agreement|SLA)[^.]{0,200}", text, re.I)
        if sla:
            out["sla_mention"] = sla.group(0).strip()[:300]
        # DPA / GDPR.
        if re.search(r"data\s+processing\s+agreement|GDPR|CCPA", text, re.I):
            out["data_processing"] = "referenced"
        out["_text_len"] = len(text)
    except ImportError:
        out["error"] = "pdfplumber not installed"
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:200]
    return out


@router.get("/contracts/{vendor_asset_id}", response_model=list[dict])
async def list_contracts(
    vendor_asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (
        await db.execute(
            select(VendorContract).where(
                VendorContract.vendor_asset_id == vendor_asset_id
            )
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "title": r.title,
            "contract_kind": r.contract_kind,
            "file_name": r.file_name,
            "file_size": r.file_size,
            "sha256": r.sha256,
            "effective_date": r.effective_date.isoformat() if r.effective_date else None,
            "expiration_date": r.expiration_date.isoformat() if r.expiration_date else None,
            "extracted_clauses": r.extracted_clauses,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# --- Agents --------------------------------------------------------


class AutofillRequest(BaseModel):
    questionnaire_instance_id: uuid.UUID
    use_llm: bool = True


@router.post("/questionnaires/autofill", response_model=dict)
async def autofill(
    body: AutofillRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return await autofill_questionnaire(
        db,
        instance_id=body.questionnaire_instance_id,
        use_llm=body.use_llm,
    )


class BriefRequest(BaseModel):
    vendor_asset_id: uuid.UUID
    use_llm: bool = True


@router.post("/agents/brief", response_model=dict)
async def vendor_brief(
    body: BriefRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return await generate_brief(
        db,
        vendor_asset_id=body.vendor_asset_id,
        use_llm=body.use_llm,
    )


class PlaybookRequest(BaseModel):
    vendor_asset_id: uuid.UUID
    failing_pillar: str
    use_llm: bool = True


@router.post("/agents/playbook", response_model=dict)
async def vendor_playbook(
    body: PlaybookRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return await generate_playbook(
        db,
        vendor_asset_id=body.vendor_asset_id,
        failing_pillar=body.failing_pillar,
        use_llm=body.use_llm,
    )


class HealthCheckRequest(BaseModel):
    organization_id: uuid.UUID
    drop_threshold: float = 20.0


@router.post("/agents/quarterly-health-check", response_model=dict)
async def quarterly_health(
    body: HealthCheckRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return await run_quarterly_health_check(
        db,
        organization_id=body.organization_id,
        drop_threshold=body.drop_threshold,
    )


# --- Vendor self-service portal (token-gated) ----------------------
#
# A vendor receives a one-shot, signed link of the form:
#   /api/v1/tprm/portal/{instance_id}?token=<HMAC>
# and can submit answers without an Argus account.


def _portal_token(instance_id: uuid.UUID) -> str:
    import hmac
    import os

    secret = os.environ.get("ARGUS_TPRM_PORTAL_SECRET", "")
    if not secret:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "TPRM portal not configured (ARGUS_TPRM_PORTAL_SECRET unset)",
        )
    h = hmac.new(secret.encode(), str(instance_id).encode(), hashlib.sha256)
    return h.hexdigest()


@router.get("/portal/{instance_id}/token", response_model=dict)
async def get_portal_token(
    instance_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    inst = await db.get(QuestionnaireInstance, instance_id)
    if inst is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Instance not found")
    return {"instance_id": str(instance_id), "token": _portal_token(instance_id)}


@router.get("/portal/{instance_id}", response_model=dict)
async def portal_view(
    instance_id: uuid.UUID,
    token: str,
    db: AsyncSession = Depends(get_session),
):
    expected = _portal_token(instance_id)
    if token != expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid token")
    inst = await db.get(QuestionnaireInstance, instance_id)
    if inst is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Instance not found")
    return {
        "id": str(inst.id),
        "state": inst.state,
        "due_at": inst.due_at.isoformat() if inst.due_at else None,
        "questions": (inst.template_snapshot or {}).get("questions") or [],
    }


class PortalSubmitRequest(BaseModel):
    token: str
    answers: list[dict]


@router.post("/portal/{instance_id}/submit", response_model=dict)
async def portal_submit(
    instance_id: uuid.UUID,
    body: PortalSubmitRequest,
    db: AsyncSession = Depends(get_session),
):
    expected = _portal_token(instance_id)
    if body.token != expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid token")
    inst = await db.get(QuestionnaireInstance, instance_id)
    if inst is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Instance not found")
    from src.models.tprm import QuestionnaireAnswer, QuestionnaireState

    for entry in body.answers[:200]:
        qid = str(entry.get("question_id") or "")[:80]
        if not qid:
            continue
        existing = (
            await db.execute(
                select(QuestionnaireAnswer)
                .where(QuestionnaireAnswer.instance_id == instance_id)
                .where(QuestionnaireAnswer.question_id == qid)
            )
        ).scalar_one_or_none()
        ans = str(entry.get("answer_value") or "")[:5000]
        if existing is None:
            db.add(
                QuestionnaireAnswer(
                    instance_id=instance_id,
                    question_id=qid,
                    answer_value=ans,
                    notes="submitted via vendor portal",
                )
            )
        else:
            existing.answer_value = ans
            existing.notes = "submitted via vendor portal"
    inst.state = QuestionnaireState.RECEIVED.value
    inst.received_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True, "instance_id": str(instance_id), "state": inst.state}
