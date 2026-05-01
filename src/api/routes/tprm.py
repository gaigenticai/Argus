"""Phase 7 — TPRM API.

Endpoints
---------
    POST  /tprm/templates                           create a questionnaire template
    POST  /tprm/templates/seed-builtins              install SIG-Lite + CAIQ-v4 templates
    GET   /tprm/templates                           list
    GET   /tprm/templates/{id}                      detail

    POST  /tprm/questionnaires                      send a questionnaire to a vendor
    GET   /tprm/questionnaires                      list (filter by vendor / state)
    GET   /tprm/questionnaires/{id}                 detail (with answers)
    POST  /tprm/questionnaires/{id}/answers         submit a single answer (vendor)
    POST  /tprm/questionnaires/{id}/state           transition (sent→received→reviewed)

    POST  /tprm/onboarding                          begin onboarding a vendor
    GET   /tprm/onboarding?organization_id=…        list
    POST  /tprm/onboarding/{id}/transition          state machine

    POST  /tprm/scorecards/{vendor_asset_id}/recompute   compute scorecard
    GET   /tprm/scorecards/{vendor_asset_id}             current scorecard
    GET   /tprm/scorecards?organization_id=…             list (one per vendor)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.threat import Asset, Organization
from src.models.tprm import (
    AnswerKind,
    QuestionnaireAnswer,
    QuestionnaireInstance,
    QuestionnaireKind,
    QuestionnaireState,
    QuestionnaireTemplate,
    VendorOnboardingStage,
    VendorOnboardingWorkflow,
    VendorScorecard,
    is_stage_transition_allowed,
)
from src.storage.database import get_session
from src.tprm.scoring import compute_vendor_score, persist_vendor_scorecard
from src.tprm.scoring_questions import (
    BUILTIN_TEMPLATES,
    aggregate_instance_score,
    parse_question,
)


router = APIRouter(prefix="/tprm", tags=["Compliance & DLP"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- Templates ---------------------------------------------------------


class TemplateCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    kind: QuestionnaireKind = QuestionnaireKind.CUSTOM
    description: str | None = None
    questions: list[dict[str, Any]] = Field(min_length=1)
    is_active: bool = True


class TemplateResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    name: str
    kind: str
    description: str | None
    questions: list[dict]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


def _validate_questions(questions: list[dict]) -> list[dict]:
    if not questions:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "questions must not be empty",
        )
    seen_ids: set[str] = set()
    cleaned: list[dict] = []
    for q in questions:
        try:
            parsed = parse_question(q)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid question: {e}"
            )
        if not parsed.id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "every question needs a non-empty 'id'",
            )
        if parsed.id in seen_ids:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"duplicate question id: {parsed.id}",
            )
        seen_ids.add(parsed.id)
        cleaned.append(
            {
                "id": parsed.id,
                "text": parsed.text,
                "answer_kind": parsed.answer_kind.value,
                "weight": parsed.weight,
                "required": parsed.required,
            }
        )
    return cleaned


@router.post("/templates", response_model=TemplateResponse, status_code=201)
async def create_template(
    body: TemplateCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    if body.organization_id is not None:
        org = await db.get(Organization, body.organization_id)
        if not org:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "Organization not found"
            )
    cleaned = _validate_questions(body.questions)
    tpl = QuestionnaireTemplate(
        organization_id=body.organization_id,
        name=body.name.strip(),
        kind=body.kind.value,
        description=body.description,
        questions=cleaned,
        is_active=body.is_active,
    )
    db.add(tpl)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Template name already used in this scope"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.QUESTIONNAIRE_TEMPLATE_CREATE,
        user=analyst,
        resource_type="questionnaire_template",
        resource_id=str(tpl.id),
        details={"name": tpl.name, "kind": tpl.kind, "questions": len(cleaned)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(tpl)
    return tpl


@router.post("/templates/seed-builtins", response_model=list[TemplateResponse])
async def seed_builtin_templates(
    organization_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Install both SIG-Lite + CAIQ-v4 default templates for the org."""
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    out: list[QuestionnaireTemplate] = []
    for name, factory in BUILTIN_TEMPLATES.items():
        existing = (
            await db.execute(
                select(QuestionnaireTemplate).where(
                    and_(
                        QuestionnaireTemplate.organization_id == organization_id,
                        QuestionnaireTemplate.name == name,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            out.append(existing)
            continue
        questions = _validate_questions(factory())
        tpl = QuestionnaireTemplate(
            organization_id=organization_id,
            name=name,
            kind=name if name in [k.value for k in QuestionnaireKind] else QuestionnaireKind.CUSTOM.value,
            description=f"Built-in {name} template",
            questions=questions,
        )
        db.add(tpl)
        await db.flush()
        out.append(tpl)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.QUESTIONNAIRE_TEMPLATE_CREATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(organization_id),
        details={"action": "seed_builtins", "count": len(out)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return out


@router.get("/templates", response_model=list[TemplateResponse])
async def list_templates(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    is_active: bool | None = None,
):
    q = select(QuestionnaireTemplate)
    if organization_id is not None:
        q = q.where(
            (QuestionnaireTemplate.organization_id == organization_id)
            | (QuestionnaireTemplate.organization_id.is_(None))
        )
    if is_active is not None:
        q = q.where(QuestionnaireTemplate.is_active == is_active)
    return list(
        (await db.execute(q.order_by(QuestionnaireTemplate.created_at.desc()))).scalars().all()
    )


@router.get("/templates/{template_id}", response_model=TemplateResponse)
async def get_template(
    template_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    tpl = await db.get(QuestionnaireTemplate, template_id)
    if not tpl:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    return tpl


# --- Questionnaire instances ------------------------------------------


class QuestionnaireSendRequest(BaseModel):
    organization_id: uuid.UUID
    template_id: uuid.UUID
    vendor_asset_id: uuid.UUID
    due_at: datetime | None = None


class AnswerSubmit(BaseModel):
    question_id: str
    answer_value: str | None = None
    evidence_sha256: str | None = None
    notes: str | None = None
    override_score: float | None = Field(default=None, ge=0, le=100)


class QuestionnaireAnswerResponse(BaseModel):
    question_id: str
    answer_value: str | None
    evidence_sha256: str | None
    answer_score: float | None
    notes: str | None

    model_config = {"from_attributes": True}


class QuestionnaireInstanceResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    template_id: uuid.UUID
    vendor_asset_id: uuid.UUID
    state: str
    sent_at: datetime | None
    received_at: datetime | None
    due_at: datetime | None
    reviewed_at: datetime | None
    score: float | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class QuestionnaireDetailResponse(QuestionnaireInstanceResponse):
    answers: list[QuestionnaireAnswerResponse]
    template: TemplateResponse


class QuestionnaireStateChange(BaseModel):
    to_state: QuestionnaireState
    notes: str | None = None


@router.post(
    "/questionnaires", response_model=QuestionnaireInstanceResponse, status_code=201
)
async def send_questionnaire(
    body: QuestionnaireSendRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    vendor = await db.get(Asset, body.vendor_asset_id)
    if not vendor or vendor.organization_id != body.organization_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "vendor_asset_id is in a different organization",
        )
    if vendor.asset_type != "vendor":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "asset is not a vendor (asset_type must be 'vendor')",
        )
    tpl = await db.get(QuestionnaireTemplate, body.template_id)
    if not tpl or (
        tpl.organization_id is not None
        and tpl.organization_id != body.organization_id
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "template not visible to this organization",
        )
    inst = QuestionnaireInstance(
        organization_id=body.organization_id,
        template_id=tpl.id,
        vendor_asset_id=vendor.id,
        state=QuestionnaireState.SENT.value,
        sent_at=datetime.now(timezone.utc),
        due_at=body.due_at,
    )
    db.add(inst)
    await db.flush()
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.QUESTIONNAIRE_INSTANCE_CREATE,
        user=analyst,
        resource_type="questionnaire_instance",
        resource_id=str(inst.id),
        details={"vendor_asset_id": str(vendor.id), "template": tpl.name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(inst)
    return inst


@router.get(
    "/questionnaires", response_model=list[QuestionnaireInstanceResponse]
)
async def list_questionnaires(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    vendor_asset_id: uuid.UUID | None = None,
    state: QuestionnaireState | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(QuestionnaireInstance).where(
        QuestionnaireInstance.organization_id == organization_id
    )
    if vendor_asset_id is not None:
        q = q.where(QuestionnaireInstance.vendor_asset_id == vendor_asset_id)
    if state is not None:
        q = q.where(QuestionnaireInstance.state == state.value)
    q = q.order_by(QuestionnaireInstance.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.get(
    "/questionnaires/{instance_id}", response_model=QuestionnaireDetailResponse
)
async def get_questionnaire(
    instance_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    inst = await db.get(QuestionnaireInstance, instance_id)
    if not inst:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Instance not found")
    tpl = await db.get(QuestionnaireTemplate, inst.template_id)
    answers = (
        await db.execute(
            select(QuestionnaireAnswer).where(
                QuestionnaireAnswer.instance_id == inst.id
            )
        )
    ).scalars().all()
    return QuestionnaireDetailResponse(
        **{**QuestionnaireInstanceResponse.model_validate(inst).model_dump()},
        answers=[QuestionnaireAnswerResponse.model_validate(a) for a in answers],
        template=TemplateResponse.model_validate(tpl),
    )


@router.post(
    "/questionnaires/{instance_id}/answers",
    response_model=QuestionnaireAnswerResponse,
    status_code=201,
)
async def submit_answer(
    instance_id: uuid.UUID,
    body: AnswerSubmit,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    inst = await db.get(QuestionnaireInstance, instance_id)
    if not inst:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Instance not found")
    if inst.state not in (
        QuestionnaireState.SENT.value,
        QuestionnaireState.RECEIVED.value,
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Instance is {inst.state}; no further answers accepted",
        )
    tpl = await db.get(QuestionnaireTemplate, inst.template_id)
    qmap = {q["id"]: q for q in (tpl.questions or [])}
    if body.question_id not in qmap:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"unknown question_id {body.question_id!r}",
        )
    qdef = parse_question(qmap[body.question_id])
    from src.tprm.scoring_questions import score_answer
    score = score_answer(
        qdef,
        body.answer_value,
        bool(body.evidence_sha256),
        body.override_score,
    )

    existing = (
        await db.execute(
            select(QuestionnaireAnswer).where(
                and_(
                    QuestionnaireAnswer.instance_id == inst.id,
                    QuestionnaireAnswer.question_id == body.question_id,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.answer_value = body.answer_value
        existing.evidence_sha256 = body.evidence_sha256
        existing.notes = body.notes
        existing.answer_score = score
        ans = existing
    else:
        ans = QuestionnaireAnswer(
            instance_id=inst.id,
            question_id=body.question_id,
            answer_value=body.answer_value,
            evidence_sha256=body.evidence_sha256,
            notes=body.notes,
            answer_score=score,
        )
        db.add(ans)
    await db.flush()
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.QUESTIONNAIRE_ANSWER_SUBMIT,
        user=analyst,
        resource_type="questionnaire_instance",
        resource_id=str(inst.id),
        details={"question_id": body.question_id, "score": score},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(ans)
    return ans


@router.post(
    "/questionnaires/{instance_id}/state",
    response_model=QuestionnaireInstanceResponse,
)
async def transition_questionnaire(
    instance_id: uuid.UUID,
    body: QuestionnaireStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    inst = await db.get(QuestionnaireInstance, instance_id)
    if not inst:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Instance not found")
    target = body.to_state.value
    if target == inst.state:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {inst.state}")

    # Allowed transitions for instances:
    transitions = {
        "draft": {"sent", "cancelled"},
        "sent": {"received", "cancelled", "expired"},
        "received": {"reviewed", "cancelled"},
        "reviewed": set(),
        "cancelled": set(),
        "expired": {"sent"},
    }
    if target not in transitions.get(inst.state, set()):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"transition {inst.state} → {target} not allowed",
        )

    now = datetime.now(timezone.utc)
    from_state = inst.state
    inst.state = target
    if target == "received":
        inst.received_at = now
    if target == "reviewed":
        inst.reviewed_at = now
        inst.reviewed_by_user_id = analyst.id
        # Compute aggregate score from answers
        tpl = await db.get(QuestionnaireTemplate, inst.template_id)
        questions = [parse_question(q) for q in (tpl.questions or [])]
        answers = (
            await db.execute(
                select(QuestionnaireAnswer).where(
                    QuestionnaireAnswer.instance_id == inst.id
                )
            )
        ).scalars().all()
        amap = {
            a.question_id: {
                "value": a.answer_value,
                "evidence_present": bool(a.evidence_sha256),
                "override": a.answer_score
                if a.answer_score is not None
                and a.answer_value is None
                and not a.evidence_sha256
                else None,
            }
            for a in answers
        }
        # Recompute scores using the template definitions in case the
        # weights changed since the answer was submitted.
        from src.tprm.scoring_questions import score_answer

        for a in answers:
            q = next((q for q in questions if q.id == a.question_id), None)
            if q is None:
                continue
            recomputed = score_answer(
                q,
                a.answer_value,
                bool(a.evidence_sha256),
                a.answer_score
                if (
                    a.answer_value is None
                    and not a.evidence_sha256
                    and a.answer_score is not None
                )
                else None,
            )
            if recomputed is not None:
                a.answer_score = recomputed
                amap[a.question_id]["override"] = recomputed
        inst.score = aggregate_instance_score(questions, amap)
    if target == "expired":
        inst.notes = (inst.notes or "") + " [auto-expired]"
    if body.notes:
        inst.notes = (inst.notes or "") + ("\n" if inst.notes else "") + body.notes

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.QUESTIONNAIRE_INSTANCE_TRANSITION,
        user=analyst,
        resource_type="questionnaire_instance",
        resource_id=str(inst.id),
        details={"from": from_state, "to": target, "score": inst.score},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(inst)
    return inst


# --- Vendor onboarding workflow ---------------------------------------


class OnboardingCreate(BaseModel):
    organization_id: uuid.UUID
    vendor_asset_id: uuid.UUID
    notes: str | None = None


class OnboardingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    vendor_asset_id: uuid.UUID
    stage: str
    questionnaire_instance_id: uuid.UUID | None
    notes: str | None
    decided_by_user_id: uuid.UUID | None
    decision_reason: str | None
    decided_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class OnboardingTransition(BaseModel):
    to_stage: VendorOnboardingStage
    questionnaire_instance_id: uuid.UUID | None = None
    reason: str | None = None


@router.post("/onboarding", response_model=OnboardingResponse, status_code=201)
async def begin_onboarding(
    body: OnboardingCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    vendor = await db.get(Asset, body.vendor_asset_id)
    if (
        not vendor
        or vendor.organization_id != body.organization_id
        or vendor.asset_type != "vendor"
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "vendor_asset_id is invalid for this organization",
        )
    wf = VendorOnboardingWorkflow(
        organization_id=body.organization_id,
        vendor_asset_id=vendor.id,
        stage=VendorOnboardingStage.INVITED.value,
        notes=body.notes,
    )
    db.add(wf)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Vendor already in onboarding"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.VENDOR_ONBOARDING_TRANSITION,
        user=analyst,
        resource_type="vendor_onboarding_workflow",
        resource_id=str(wf.id),
        details={"action": "begin", "vendor_asset_id": str(vendor.id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(wf)
    return wf


@router.get("/onboarding", response_model=list[OnboardingResponse])
async def list_onboarding(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    stage: VendorOnboardingStage | None = None,
):
    q = select(VendorOnboardingWorkflow).where(
        VendorOnboardingWorkflow.organization_id == organization_id
    )
    if stage is not None:
        q = q.where(VendorOnboardingWorkflow.stage == stage.value)
    return list(
        (await db.execute(q.order_by(VendorOnboardingWorkflow.updated_at.desc()))).scalars().all()
    )


@router.post(
    "/onboarding/{workflow_id}/transition", response_model=OnboardingResponse
)
async def transition_onboarding(
    workflow_id: uuid.UUID,
    body: OnboardingTransition,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    wf = await db.get(VendorOnboardingWorkflow, workflow_id)
    if not wf:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workflow not found")
    if body.to_stage.value == wf.stage:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {wf.stage}")
    if not is_stage_transition_allowed(wf.stage, body.to_stage.value):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Transition {wf.stage} → {body.to_stage.value} not allowed",
        )
    if body.to_stage in (
        VendorOnboardingStage.APPROVED,
        VendorOnboardingStage.REJECTED,
        VendorOnboardingStage.ON_HOLD,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required for this stage",
            )
    if body.questionnaire_instance_id is not None:
        wf.questionnaire_instance_id = body.questionnaire_instance_id
    from_stage = wf.stage
    wf.stage = body.to_stage.value
    wf.decision_reason = body.reason
    if body.to_stage in (
        VendorOnboardingStage.APPROVED,
        VendorOnboardingStage.REJECTED,
    ):
        wf.decided_at = datetime.now(timezone.utc)
        wf.decided_by_user_id = analyst.id
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.VENDOR_ONBOARDING_TRANSITION,
        user=analyst,
        resource_type="vendor_onboarding_workflow",
        resource_id=str(wf.id),
        details={"from": from_stage, "to": body.to_stage.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(wf)
    return wf


# --- Scorecard --------------------------------------------------------


class VendorScorecardResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    vendor_asset_id: uuid.UUID
    score: float
    grade: str
    is_current: bool
    pillar_scores: dict
    summary: dict
    computed_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post(
    "/scorecards/{vendor_asset_id}/recompute",
    response_model=VendorScorecardResponse,
)
async def recompute_scorecard(
    vendor_asset_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    vendor = await db.get(Asset, vendor_asset_id)
    if not vendor or vendor.asset_type != "vendor":
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Vendor asset not found"
        )
    try:
        result = await compute_vendor_score(
            db, vendor.organization_id, vendor.id
        )
    except (LookupError, ValueError) as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))
    sc = await persist_vendor_scorecard(
        db, vendor.organization_id, vendor.id, result
    )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.VENDOR_SCORECARD_RECOMPUTE,
        user=analyst,
        resource_type="vendor_scorecard",
        resource_id=str(sc.id),
        details={"vendor_asset_id": str(vendor.id), "score": sc.score, "grade": sc.grade},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(sc)
    return sc


@router.get(
    "/scorecards/{vendor_asset_id}", response_model=VendorScorecardResponse
)
async def get_current_scorecard(
    vendor_asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    sc = (
        await db.execute(
            select(VendorScorecard).where(
                and_(
                    VendorScorecard.vendor_asset_id == vendor_asset_id,
                    VendorScorecard.is_current == True,  # noqa: E712
                )
            )
        )
    ).scalar_one_or_none()
    if not sc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No scorecard yet — call /tprm/scorecards/{vendor_asset_id}/recompute first",
        )
    return sc


@router.get("/scorecards", response_model=list[VendorScorecardResponse])
async def list_scorecards(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    grade: str | None = None,
):
    q = select(VendorScorecard).where(
        and_(
            VendorScorecard.organization_id == organization_id,
            VendorScorecard.is_current == True,  # noqa: E712
        )
    )
    if grade is not None:
        q = q.where(VendorScorecard.grade == grade)
    q = q.order_by(VendorScorecard.score.desc())
    return list((await db.execute(q)).scalars().all())
