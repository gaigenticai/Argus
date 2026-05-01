"""Threat Hunter agent runs.

Fourth agentic loop. Unlike the other three (event-triggered or
analyst-triggered), the Threat Hunter runs on a schedule. Each tick
picks an active threat-actor cluster, generates hypotheses about
where their TTPs would surface in the org's surface area, and looks.

The agent emits ``hunt_findings`` — short structured insights with
linked IOC ids, MITRE technique ids, and a recommended next-step.
Persisted as a JSONB list on the run row so the dashboard can render
them as cards without a join table.

State machine: queued → running → completed | failed.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class HuntStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatHuntRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "threat_hunt_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Optional anchor to the actor cluster the agent decided to focus
    # on. NULL when the agent decided no cluster was worth pursuing.
    primary_actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_actors.id", ondelete="SET NULL"),
    )
    primary_actor_alias: Mapped[str | None] = mapped_column(String(255))

    status: Mapped[str] = mapped_column(
        Enum(
            HuntStatus,
            name="threat_hunt_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=HuntStatus.QUEUED.value,
        nullable=False,
    )

    # Verdict
    summary: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    # findings = [{title, description, relevance, mitre_ids, ioc_ids, recommended_action}]
    findings: Mapped[list | None] = mapped_column(JSONB)

    # Provenance
    iterations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    trace: Mapped[list | None] = mapped_column(JSONB)
    model_id: Mapped[str | None] = mapped_column(String(100))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_threat_hunt_org_status", "organization_id", "status"),
        Index(
            "ix_threat_hunt_status_created",
            "status",
            "created_at",
        ),
        Index("ix_threat_hunt_actor", "primary_actor_id"),
    )


__all__ = ["ThreatHuntRun", "HuntStatus"]
