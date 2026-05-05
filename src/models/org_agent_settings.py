"""Per-organisation agent toggles.

One row per Organization. Lets the operator turn each of the four
agents on/off, choose whether Investigation chains into a Threat
Hunter run, and (subject to the global ``ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED``
guard) opt into the bypass-the-human auto-actions.

Defaults (set on row creation): every agent on; every auto-action
off. Dashboard surfaces this as a Settings → Agents tab.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class OrganizationAgentSettings(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "organization_agent_settings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    # Per-agent enables. When false, the worker tick + auto-trigger
    # paths skip queuing new runs for this org.
    investigation_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true"
    )
    brand_defender_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true"
    )
    case_copilot_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true"
    )
    threat_hunter_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true"
    )

    # Internal routing — chain Investigation → Threat Hunter when an
    # investigation completes critical with correlated actors. Doesn't
    # mutate external state, so it sits next to the agent toggles
    # rather than the auto-action overrides.
    chain_investigation_to_hunt: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="true"
    )

    # Auto-action overrides. Even when these are true, the global
    # ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED guard takes precedence.
    auto_promote_critical: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false"
    )
    auto_takedown_high_confidence: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false"
    )

    # Plan-then-act gate. When true, every Investigation pauses after
    # iteration 1 with status=awaiting_plan_approval; the operator
    # reviews + approves the agent's proposed tool sequence before it
    # runs. Off by default — most orgs trust the agent's planning.
    investigation_plan_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false"
    )

    # ── Brand Defender ──────────────────────────────────────────────
    # Minimum suspect-domain similarity above which the ingest paths
    # auto-queue a Brand Defender run. 0.80 matches the legacy
    # ``_AUTO_DEFEND_MIN_SIMILARITY`` constant; orgs that want a
    # quieter dashboard can dial it up, those that want eager defence
    # can dial it down. Capped at 0.99 to avoid useless settings.
    brand_defence_min_similarity: Mapped[float] = mapped_column(
        Float, default=0.80, nullable=False, server_default="0.8"
    )
    # Same plan-approval gate pattern as Investigations. Off by default.
    brand_defence_plan_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false"
    )

    # Cadence for the scheduled Threat Hunter, per-org. Falls back to
    # ``ARGUS_WORKER_THREAT_HUNT_INTERVAL`` (default 7 days) when null.
    threat_hunt_interval_seconds: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        Index("ix_org_agent_settings_org", "organization_id"),
    )


__all__ = ["OrganizationAgentSettings"]
