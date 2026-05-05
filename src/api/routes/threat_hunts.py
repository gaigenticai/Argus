"""Threat Hunter — API surface.

  POST /threat-hunts            → queue an ad-hoc hunt (analyst-trigger
                                  on top of the weekly schedule)
  GET  /threat-hunts            → list past hunt runs
  GET  /threat-hunts/{id}       → full detail with trace + findings
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.core.tenant import get_system_org_id
from src.models.threat_hunts import HuntStatus, ThreatHuntRun
from src.storage.database import async_session_factory, get_session


router = APIRouter(prefix="/threat-hunts", tags=["Threat Hunter"])


class HuntListItem(BaseModel):
    id: uuid.UUID
    status: str
    primary_actor_alias: str | None
    confidence: float | None
    iterations: int
    model_id: str | None
    duration_ms: int | None
    created_at: datetime
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class HuntDetail(HuntListItem):
    primary_actor_id: uuid.UUID | None
    summary: str | None
    findings: list[dict[str, Any]] | None
    trace: list[dict[str, Any]] | None
    error_message: str | None
    started_at: datetime | None


class CreateHuntResponse(BaseModel):
    id: uuid.UUID
    status: str


async def _run_in_background(run_id: uuid.UUID) -> None:
    if async_session_factory is None:
        return
    from src.agents.threat_hunter_agent import run_and_persist

    async with async_session_factory() as session:
        run = (
            await session.execute(
                select(ThreatHuntRun).where(ThreatHuntRun.id == run_id)
            )
        ).scalar_one_or_none()
        if run is None:
            return
        await run_and_persist(
            session,
            organization_id=run.organization_id,
            run_id=run_id,
        )


@router.post("", response_model=CreateHuntResponse, status_code=202)
async def create_hunt(
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
    template_id: uuid.UUID | None = None,
) -> CreateHuntResponse:
    """Queue an ad-hoc hunt on top of the weekly schedule.

    Idempotent over in-flight runs: if a queued/running hunt already
    exists for the org, we return that one rather than starting a
    second. Pass ``template_id`` to anchor the agent on a hypothesis
    from a saved hunt template.
    """
    org_id = await get_system_org_id(db)
    existing = (
        await db.execute(
            select(ThreatHuntRun)
            .where(ThreatHuntRun.organization_id == org_id)
            .where(
                ThreatHuntRun.status.in_(
                    [HuntStatus.QUEUED.value, HuntStatus.RUNNING.value]
                )
            )
            .order_by(desc(ThreatHuntRun.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return CreateHuntResponse(id=existing.id, status=existing.status)

    run = ThreatHuntRun(
        organization_id=org_id,
        status=HuntStatus.QUEUED.value,
        template_id=template_id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    background.add_task(_run_in_background, run.id)
    return CreateHuntResponse(id=run.id, status=run.status)


@router.get("", response_model=list[HuntListItem])
async def list_hunts(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> list[HuntListItem]:
    org_id = await get_system_org_id(db)
    stmt = (
        select(ThreatHuntRun)
        .where(ThreatHuntRun.organization_id == org_id)
        .order_by(desc(ThreatHuntRun.created_at))
        .limit(limit)
    )
    if status is not None:
        stmt = stmt.where(ThreatHuntRun.status == status)
    rows = (await db.execute(stmt)).scalars().all()
    return [HuntListItem.model_validate(r) for r in rows]


@router.get("/{run_id}", response_model=HuntDetail)
async def get_hunt(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> HuntDetail:
    org_id = await get_system_org_id(db)
    run = (
        await db.execute(
            select(ThreatHuntRun)
            .where(ThreatHuntRun.id == run_id)
            .where(ThreatHuntRun.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(404, "hunt run not found")
    return HuntDetail.model_validate(run)


# --- Templates / notes / workflow / case escalation -------------------

from src.models.threat_hunts import HuntNote, HuntTemplate
from src.models.cases import Case
from src.models.sigma_rules import SigmaRule
from src.core.auth import AdminUser
from sqlalchemy import or_, func


_GLOBAL_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "T1078 — Unusual valid-account login pattern",
        "hypothesis": "An attacker is reusing valid credentials from off-hours geos to blend in with legitimate logins.",
        "description": "Look for OAuth/IdP logins outside the user's baseline geo + outside business hours. Pivot from user → IP → ASN → other auth events.",
        "mitre_technique_ids": ["T1078"],
        "data_sources": ["Authentication Logs", "User Account: User Account Authentication"],
        "tags": ["valid-accounts", "identity"],
    },
    {
        "name": "T1059.001 — PowerShell encoded command execution",
        "hypothesis": "An adversary is dropping initial-access tooling via base64-encoded powershell.exe -enc invocations.",
        "description": "Hunt process_create where image=powershell.exe and command_line contains -enc / -EncodedCommand / -ec. Decode & inspect.",
        "mitre_technique_ids": ["T1059.001"],
        "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        "tags": ["execution", "powershell"],
    },
    {
        "name": "T1490 — Inhibit System Recovery (vssadmin / wmic delete)",
        "hypothesis": "Pre-ransomware actor is disabling shadow copies before encryption.",
        "description": "Detect vssadmin delete shadows / wmic shadowcopy delete / bcdedit /set bootstatuspolicy ignoreallfailures.",
        "mitre_technique_ids": ["T1490"],
        "data_sources": ["Process: Process Creation"],
        "tags": ["impact", "ransomware"],
    },
    {
        "name": "T1566.001 — Spearphishing attachment with macro",
        "hypothesis": "Office macros are spawning child processes (powershell, mshta, cmd) — likely macro-based loader.",
        "description": "Hunt office app (winword/excel) parent → child of suspicious binaries.",
        "mitre_technique_ids": ["T1566.001", "T1204.002"],
        "data_sources": ["Process: Process Creation"],
        "tags": ["initial-access", "phishing"],
    },
    {
        "name": "T1190 — Exploit Public-Facing Application",
        "hypothesis": "An external scanner exploited a known web vuln; look for short-lived web shells in app dirs.",
        "description": "Cross-reference web-server access logs (POST to /uploads or /tmp paths) with file-create events for .php/.aspx/.jsp.",
        "mitre_technique_ids": ["T1190"],
        "data_sources": ["Network Traffic: Network Traffic Content", "File: File Creation"],
        "tags": ["initial-access", "webshell"],
    },
]


class TemplateResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    name: str
    hypothesis: str
    description: str | None
    methodology: str
    mitre_technique_ids: list[str]
    data_sources: list[str]
    tags: list[str]
    is_global: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TemplateCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    name: str
    hypothesis: str
    description: str | None = None
    methodology: str = "PEAK"
    mitre_technique_ids: list[str] = []
    data_sources: list[str] = []
    tags: list[str] = []


@router.get("/templates", response_model=list[TemplateResponse])
async def list_templates(
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
    organization_id: uuid.UUID | None = None,
):
    q = select(HuntTemplate).where(HuntTemplate.archived_at.is_(None))
    if organization_id is not None:
        q = q.where(
            or_(
                HuntTemplate.organization_id == organization_id,
                HuntTemplate.is_global.is_(True),
            )
        )
    else:
        q = q.where(HuntTemplate.is_global.is_(True))
    rows = (await db.execute(q.order_by(HuntTemplate.name))).scalars().all()
    return [TemplateResponse.model_validate(r) for r in rows]


@router.post("/templates", response_model=TemplateResponse, status_code=201)
async def create_template(
    body: TemplateCreate,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    tpl = HuntTemplate(
        organization_id=body.organization_id,
        name=body.name.strip(),
        hypothesis=body.hypothesis.strip(),
        description=body.description,
        methodology=body.methodology,
        mitre_technique_ids=sorted(set(body.mitre_technique_ids)),
        data_sources=body.data_sources,
        tags=body.tags,
        is_global=body.organization_id is None,
        created_by_user_id=getattr(user, "id", None),
    )
    db.add(tpl)
    await db.commit()
    await db.refresh(tpl)
    return TemplateResponse.model_validate(tpl)


@router.post("/templates/seed-builtins", response_model=dict)
async def seed_global_templates(
    db: AsyncSession = Depends(get_session),
    admin: AdminUser = None,  # noqa: B008
):
    inserted = updated = 0
    for spec in _GLOBAL_TEMPLATES:
        existing = (
            await db.execute(
                select(HuntTemplate).where(
                    HuntTemplate.is_global.is_(True),
                    HuntTemplate.name == spec["name"],
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                HuntTemplate(
                    organization_id=None,
                    name=spec["name"],
                    hypothesis=spec["hypothesis"],
                    description=spec["description"],
                    methodology="PEAK",
                    mitre_technique_ids=spec["mitre_technique_ids"],
                    data_sources=spec["data_sources"],
                    tags=spec["tags"],
                    is_global=True,
                )
            )
            inserted += 1
        else:
            existing.hypothesis = spec["hypothesis"]
            existing.description = spec["description"]
            existing.mitre_technique_ids = spec["mitre_technique_ids"]
            existing.data_sources = spec["data_sources"]
            existing.tags = spec["tags"]
            updated += 1
    await db.commit()
    return {"inserted": inserted, "updated": updated, "total": len(_GLOBAL_TEMPLATES)}


# --- Hunt notes (collaboration) ---------------------------------------


class HuntNoteResponse(BaseModel):
    id: uuid.UUID
    hunt_run_id: uuid.UUID
    author_user_id: uuid.UUID | None
    body: str
    created_at: datetime

    model_config = {"from_attributes": True}


class HuntNoteCreate(BaseModel):
    body: str


@router.get("/{run_id}/notes", response_model=list[HuntNoteResponse])
async def list_notes(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    rows = (
        await db.execute(
            select(HuntNote)
            .where(HuntNote.hunt_run_id == run_id)
            .order_by(HuntNote.created_at.desc())
        )
    ).scalars().all()
    return [HuntNoteResponse.model_validate(n) for n in rows]


@router.post("/{run_id}/notes", response_model=HuntNoteResponse, status_code=201)
async def add_note(
    run_id: uuid.UUID,
    body: HuntNoteCreate,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    run = await db.get(ThreatHuntRun, run_id)
    if not run:
        raise HTTPException(404, "Hunt not found")
    text = (body.body or "").strip()
    if not text:
        raise HTTPException(422, "body cannot be empty")
    note = HuntNote(
        hunt_run_id=run_id,
        author_user_id=getattr(user, "id", None),
        body=text,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return HuntNoteResponse.model_validate(note)


# --- Workflow transition + assignment + case escalation ---------------


class WorkflowTransition(BaseModel):
    next_state: str  # hypothesis | investigating | reporting | closed
    reason: str | None = None


@router.post("/{run_id}/transition", response_model=HuntDetail)
async def transition_hunt(
    run_id: uuid.UUID,
    body: WorkflowTransition,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    valid = {"hypothesis", "investigating", "reporting", "closed"}
    if body.next_state not in valid:
        raise HTTPException(422, f"next_state must be one of {sorted(valid)}")
    run = await db.get(ThreatHuntRun, run_id)
    if not run:
        raise HTTPException(404, "Hunt not found")
    log = list(run.transition_log or [])
    log.append({
        "from": run.workflow_state,
        "to": body.next_state,
        "user_id": str(getattr(user, "id", None)) if getattr(user, "id", None) else None,
        "reason": body.reason,
        "at": datetime.utcnow().isoformat(),
    })
    run.workflow_state = body.next_state
    run.transition_log = log
    await db.commit()
    await db.refresh(run)
    return HuntDetail.model_validate(run)


class AssignBody(BaseModel):
    user_id: uuid.UUID | None = None


@router.post("/{run_id}/assign", response_model=HuntDetail)
async def assign_hunt(
    run_id: uuid.UUID,
    body: AssignBody,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    run = await db.get(ThreatHuntRun, run_id)
    if not run:
        raise HTTPException(404, "Hunt not found")
    run.assigned_to_user_id = body.user_id
    await db.commit()
    await db.refresh(run)
    return HuntDetail.model_validate(run)


class EscalateRequest(BaseModel):
    finding_indices: list[int] | None = None  # which findings to attach; default all
    case_title: str | None = None


@router.post("/{run_id}/escalate", response_model=dict)
async def escalate_to_case(
    run_id: uuid.UUID,
    body: EscalateRequest,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    """Create a Case from this hunt's findings (auto-fills title + body)."""
    run = await db.get(ThreatHuntRun, run_id)
    if not run:
        raise HTTPException(404, "Hunt not found")
    findings = list(run.findings or [])
    if body.finding_indices:
        findings = [findings[i] for i in body.finding_indices if 0 <= i < len(findings)]
    if not findings:
        raise HTTPException(422, "No findings to escalate")
    title = body.case_title or (
        f"Hunt finding{'s' if len(findings) > 1 else ''} from "
        f"{run.primary_actor_alias or 'untargeted hunt'}"
    )
    body_md_lines = [f"# {title}", "", "Auto-escalated from hunt run.", ""]
    body_md_lines.append(f"**Hunt run:** `{run.id}`")
    if run.summary:
        body_md_lines.extend(["", "## Summary", run.summary])
    body_md_lines.append("")
    body_md_lines.append("## Findings")
    for i, f in enumerate(findings, 1):
        body_md_lines.append(f"### {i}. {f.get('title', '(untitled finding)')}")
        if f.get("description"):
            body_md_lines.append(f.get("description"))
        if f.get("mitre_ids"):
            body_md_lines.append(f"_MITRE_: {', '.join(f.get('mitre_ids') or [])}")
        if f.get("recommended_action"):
            body_md_lines.append(f"_Action_: {f.get('recommended_action')}")
        body_md_lines.append("")

    case = Case(
        organization_id=run.organization_id,
        title=title[:500],
        summary="\n".join(body_md_lines),
        severity="high",
        state="open",
    )
    db.add(case)
    await db.flush()
    run.case_id = case.id
    log = list(run.transition_log or [])
    log.append({
        "from": run.workflow_state,
        "to": run.workflow_state,
        "event": "escalated_to_case",
        "case_id": str(case.id),
        "user_id": str(getattr(user, "id", None)) if getattr(user, "id", None) else None,
        "at": datetime.utcnow().isoformat(),
    })
    run.transition_log = log
    await db.commit()
    return {"case_id": str(case.id), "title": title}


@router.get("/{run_id}/report")
async def hunt_report(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    """Markdown export of the hunt summary + findings + transition log."""
    run = await db.get(ThreatHuntRun, run_id)
    if not run:
        raise HTTPException(404, "Hunt not found")
    notes = (
        await db.execute(
            select(HuntNote).where(HuntNote.hunt_run_id == run_id).order_by(HuntNote.created_at)
        )
    ).scalars().all()
    lines: list[str] = [
        f"# Hunt report — {run.primary_actor_alias or '(untargeted)'}",
        "",
        f"**Status:** {run.status}  ·  **Workflow:** {run.workflow_state}",
        f"**Started:** {run.started_at}  ·  **Finished:** {run.finished_at}",
        f"**Confidence:** {run.confidence}",
        "",
    ]
    if run.summary:
        lines.extend(["## Summary", run.summary, ""])
    lines.append("## Findings")
    for i, f in enumerate(list(run.findings or []), 1):
        lines.append(f"### {i}. {f.get('title')}")
        if f.get("description"):
            lines.append(f.get("description"))
        if f.get("mitre_ids"):
            lines.append(f"_MITRE_: {', '.join(f.get('mitre_ids') or [])}")
        if f.get("recommended_action"):
            lines.append(f"_Action_: {f.get('recommended_action')}")
        lines.append("")
    if notes:
        lines.append("## Analyst notes")
        for n in notes:
            lines.append(f"- {n.created_at.isoformat()}: {n.body}")
        lines.append("")
    if run.transition_log:
        lines.append("## Transition log")
        for entry in run.transition_log:
            lines.append(f"- {entry}")
    return {"markdown": "\n".join(lines)}


# --- Sigma rules ------------------------------------------------------


class SigmaRuleResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    description: str | None
    level: str | None
    status: str | None
    author: str | None
    log_source: dict
    tags: list[str]
    technique_ids: list[str]
    references: list[str]
    source_repo: str | None
    source_path: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/sigma/ingest", response_model=dict)
async def ingest_sigma_endpoint(
    db: AsyncSession = Depends(get_session),
    admin: AdminUser = None,  # noqa: B008
):
    """Pull SigmaHQ tarball and upsert. Idempotent."""
    from src.intel.sigma_ingest import ingest_sigma_rules

    return await ingest_sigma_rules(db)


@router.post("/sigma/derive-coverage", response_model=dict)
async def derive_coverage_endpoint(
    organization_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_session),
    admin: AdminUser = None,  # noqa: B008
):
    """Auto-fill mitre_technique_coverage from sigma_rules. Re-runnable."""
    from src.intel.sigma_ingest import derive_coverage_from_sigma

    return await derive_coverage_from_sigma(db, organization_id=organization_id)


@router.get("/sigma", response_model=list[SigmaRuleResponse])
async def list_sigma_rules(
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
    technique: str | None = None,
    level: str | None = None,
    q: str | None = None,
    limit: int = 200,
):
    qry = select(SigmaRule)
    if technique:
        qry = qry.where(SigmaRule.technique_ids.any(technique.upper()))
    if level:
        qry = qry.where(SigmaRule.level == level)
    if q:
        like = f"%{q}%"
        qry = qry.where(
            or_(SigmaRule.title.ilike(like), SigmaRule.description.ilike(like))
        )
    rows = (await db.execute(qry.order_by(SigmaRule.title).limit(limit))).scalars().all()
    return [SigmaRuleResponse.model_validate(r) for r in rows]


@router.get("/sigma/stats", response_model=dict)
async def sigma_stats(
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
):
    total = (await db.execute(select(func.count()).select_from(SigmaRule))).scalar() or 0
    by_level = dict(
        (await db.execute(
            select(SigmaRule.level, func.count())
            .group_by(SigmaRule.level)
        )).all()
    )
    return {"total": total, "by_level": by_level}
