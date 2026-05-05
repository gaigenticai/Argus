"""Agent admin — posture snapshot, per-org settings, cross-agent feed.

Three concerns wired through the same router because they share the
same auth surface and are all consumed by the same Settings → Agents
dashboard tab.

Endpoints:

  GET  /agents/posture                        → master + per-feature env state
  GET  /agents/settings                       → org's row from
                                                ``organization_agent_settings``
  PATCH /agents/settings                      → flip individual toggles
  GET  /agents/activity?limit=50              → unified feed of recent runs
                                                from all four agents
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.agent_guard import posture_snapshot
from src.core.auth import AdminUser, AnalystUser
from src.core.tenant import get_system_org_id
from src.models.brand_actions import BrandAction
from src.models.case_copilot import CaseCopilotRun
from src.models.investigations import Investigation
from src.models.org_agent_settings import OrganizationAgentSettings
from src.models.threat_hunts import ThreatHuntRun
from src.storage.database import get_session


router = APIRouter(prefix="/agents", tags=["Agents"])


# ---- Schemas --------------------------------------------------------


class LLMSnapshot(BaseModel):
    provider: str
    model: str
    label: str


class PostureResponse(BaseModel):
    human_in_loop_required: bool
    features: dict[str, bool]
    env_vars: dict[str, str]
    llm: LLMSnapshot


class AgentSettingsResponse(BaseModel):
    organization_id: uuid.UUID
    investigation_enabled: bool
    brand_defender_enabled: bool
    case_copilot_enabled: bool
    threat_hunter_enabled: bool
    chain_investigation_to_hunt: bool
    auto_promote_critical: bool
    auto_takedown_high_confidence: bool
    threat_hunt_interval_seconds: int | None
    # Plan-then-act gates (T57 / T82) and Brand Defender threshold
    # (T77). Surfaced here so the dashboard can render them in
    # Settings → Agents alongside the existing kill-switches.
    investigation_plan_approval: bool = False
    brand_defence_min_similarity: float = 0.80
    brand_defence_plan_approval: bool = False

    model_config = {"from_attributes": True}


class AgentSettingsPatch(BaseModel):
    investigation_enabled: bool | None = None
    brand_defender_enabled: bool | None = None
    case_copilot_enabled: bool | None = None
    threat_hunter_enabled: bool | None = None
    chain_investigation_to_hunt: bool | None = None
    auto_promote_critical: bool | None = None
    auto_takedown_high_confidence: bool | None = None
    threat_hunt_interval_seconds: int | None = None
    investigation_plan_approval: bool | None = None
    # 0.5–0.99 — outside that range the slider is meaningless (≥1 never
    # auto-queues, <0.5 floods the dashboard with random domains).
    brand_defence_min_similarity: float | None = Field(
        default=None, ge=0.5, le=0.99,
    )
    brand_defence_plan_approval: bool | None = None


AgentKind = Literal[
    "investigation", "brand_defender", "case_copilot", "threat_hunter"
]


class AgentActivityItem(BaseModel):
    """One row from the unified feed. The discriminator is ``kind``;
    the rest of the fields are the smallest common shape across all
    four agents."""

    id: uuid.UUID
    kind: AgentKind
    status: str
    headline: str          # rendered server-side so the UI is dumb
    severity: str | None   # severity_assessment / recommendation /
                           #   primary_actor / "—" depending on agent
    confidence: float | None
    iterations: int
    model_id: str | None
    duration_ms: int | None
    created_at: datetime
    finished_at: datetime | None
    deep_link: str         # path the dashboard navigates to


# ---- Routes ---------------------------------------------------------


@router.get("/posture", response_model=PostureResponse)
async def get_posture(
    user: AnalystUser = None,  # noqa: B008
) -> PostureResponse:
    """Read the global guard state. Always synchronous — derives from
    env vars only. Useful as a banner on the agent pages."""
    snap = posture_snapshot()
    return PostureResponse(
        human_in_loop_required=bool(snap["human_in_loop_required"]),
        features={k: bool(v) for k, v in snap["features"].items()},
        env_vars={k: str(v) for k, v in snap["env_vars"].items()},
        llm=LLMSnapshot(**snap["llm"]),
    )


async def _get_or_create_settings(
    db: AsyncSession, org_id: uuid.UUID
) -> OrganizationAgentSettings:
    row = (
        await db.execute(
            select(OrganizationAgentSettings).where(
                OrganizationAgentSettings.organization_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is not None:
        return row
    row = OrganizationAgentSettings(organization_id=org_id)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/settings", response_model=AgentSettingsResponse)
async def get_settings(
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> AgentSettingsResponse:
    org_id = await get_system_org_id(db)
    row = await _get_or_create_settings(db, org_id)
    return AgentSettingsResponse.model_validate(row)


@router.patch("/settings", response_model=AgentSettingsResponse)
async def update_settings(
    payload: AgentSettingsPatch,
    db: AsyncSession = Depends(get_session),
    user: AdminUser = None,  # noqa: B008
) -> AgentSettingsResponse:
    org_id = await get_system_org_id(db)
    row = await _get_or_create_settings(db, org_id)
    diff = payload.model_dump(exclude_unset=True)
    for key, value in diff.items():
        setattr(row, key, value)
    await db.commit()
    await db.refresh(row)

    # Audit hop — flipping these toggles is a security-relevant event,
    # and bank operators want a paper trail of who turned what off.
    if diff:
        try:
            from src.core.auth import audit_log
            from src.models.auth import AuditAction

            await audit_log(
                db,
                AuditAction.SETTINGS_UPDATE,
                user=user,
                resource_type="agent_settings",
                resource_id=str(row.id),
                details={"changes": diff},
            )
            await db.commit()
        except Exception:  # noqa: BLE001
            pass
    return AgentSettingsResponse.model_validate(row)


@router.get("/activity", response_model=list[AgentActivityItem])
async def list_activity(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> list[AgentActivityItem]:
    """Unified feed of recent agentic runs. Pulls from every agent's
    table, normalises onto :class:`AgentActivityItem`, sorts by
    ``created_at`` desc, returns the top ``limit``.

    Cheap implementation — fetch ``limit`` rows from each table and
    merge in Python. Tables hold ≪ 1M rows in any plausible
    deployment so the cost is fine; switch to a UNION ALL view if
    that ever changes.
    """
    org_id = await get_system_org_id(db)

    investigations = (
        await db.execute(
            select(Investigation)
            .where(Investigation.organization_id == org_id)
            .order_by(desc(Investigation.created_at))
            .limit(limit)
        )
    ).scalars().all()
    brand_actions = (
        await db.execute(
            select(BrandAction)
            .where(BrandAction.organization_id == org_id)
            .order_by(desc(BrandAction.created_at))
            .limit(limit)
        )
    ).scalars().all()
    copilot_runs = (
        await db.execute(
            select(CaseCopilotRun)
            .where(CaseCopilotRun.organization_id == org_id)
            .order_by(desc(CaseCopilotRun.created_at))
            .limit(limit)
        )
    ).scalars().all()
    hunt_runs = (
        await db.execute(
            select(ThreatHuntRun)
            .where(ThreatHuntRun.organization_id == org_id)
            .order_by(desc(ThreatHuntRun.created_at))
            .limit(limit)
        )
    ).scalars().all()

    items: list[AgentActivityItem] = []

    for inv in investigations:
        items.append(
            AgentActivityItem(
                id=inv.id,
                kind="investigation",
                status=inv.status,
                headline=(
                    inv.final_assessment[:140]
                    if inv.final_assessment
                    else f"alert {str(inv.alert_id)[:8]}…"
                ),
                severity=inv.severity_assessment,
                confidence=None,
                iterations=inv.iterations,
                model_id=inv.model_id,
                duration_ms=inv.duration_ms,
                created_at=inv.created_at,
                finished_at=inv.finished_at,
                deep_link=f"/investigations",
            )
        )
    for act in brand_actions:
        items.append(
            AgentActivityItem(
                id=act.id,
                kind="brand_defender",
                status=act.status,
                headline=(
                    act.recommendation_reason[:140]
                    if act.recommendation_reason
                    else f"suspect {str(act.suspect_domain_id)[:8]}…"
                ),
                severity=act.recommendation,
                confidence=act.confidence,
                iterations=act.iterations,
                model_id=act.model_id,
                duration_ms=act.duration_ms,
                created_at=act.created_at,
                finished_at=act.finished_at,
                deep_link="/brand-defender",
            )
        )
    for cop in copilot_runs:
        items.append(
            AgentActivityItem(
                id=cop.id,
                kind="case_copilot",
                status=cop.status,
                headline=(
                    cop.summary[:140]
                    if cop.summary
                    else f"case {str(cop.case_id)[:8]}…"
                ),
                severity=None,
                confidence=cop.confidence,
                iterations=cop.iterations,
                model_id=cop.model_id,
                duration_ms=cop.duration_ms,
                created_at=cop.created_at,
                finished_at=cop.finished_at,
                deep_link=f"/cases/{cop.case_id}",
            )
        )
    for hunt in hunt_runs:
        items.append(
            AgentActivityItem(
                id=hunt.id,
                kind="threat_hunter",
                status=hunt.status,
                headline=(
                    hunt.summary[:140]
                    if hunt.summary
                    else f"focus actor {hunt.primary_actor_alias or 'tbd'}"
                ),
                severity=hunt.primary_actor_alias,
                confidence=hunt.confidence,
                iterations=hunt.iterations,
                model_id=hunt.model_id,
                duration_ms=hunt.duration_ms,
                created_at=hunt.created_at,
                finished_at=hunt.finished_at,
                deep_link="/threat-hunter",
            )
        )

    items.sort(key=lambda i: i.created_at, reverse=True)
    return items[:limit]
