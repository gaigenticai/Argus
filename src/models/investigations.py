"""Investigation runs — persistent record of the agentic loop.

One row per execution of :class:`src.agents.investigation_agent.InvestigationAgent`.
Captures the seed alert, the verdict, every step the agent took, and
the model id that answered. Operators get an auditable trail; the
dashboard renders the trace as a collapsible per-step view.

Lifecycle::

    queued      → row created (alert just landed, worker not picked up yet)
    running     → worker started the loop
    completed   → final_assessment + severity_assessment populated
    failed      → error_message populated; trace shows what was reached
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
from sqlalchemy.dialects.postgresql import JSONB, UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class InvestigationStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Investigation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "investigations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Set when an analyst (or auto-promotion rule) promotes the
    # completed verdict into a real Case. Nullable on purpose —
    # plenty of investigations close as "informational" and never
    # need a case opened. ON DELETE SET NULL so that wiping a case
    # doesn't cascade-destroy the investigation history.
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="SET NULL"),
    )

    status: Mapped[str] = mapped_column(
        Enum(
            InvestigationStatus,
            name="investigation_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=InvestigationStatus.QUEUED.value,
        nullable=False,
    )

    # Verdict — populated only on COMPLETED.
    final_assessment: Mapped[str | None] = mapped_column(Text)
    severity_assessment: Mapped[str | None] = mapped_column(String(20))
    correlated_iocs: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    correlated_actors: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    recommended_actions: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )

    # Provenance + observability.
    iterations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    trace: Mapped[list | None] = mapped_column(JSONB)  # [{iteration, thought, tool, args, result}]
    model_id: Mapped[str | None] = mapped_column(String(100))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_investigations_alert", "alert_id"),
        Index("ix_investigations_org_status", "organization_id", "status"),
        Index("ix_investigations_status_created", "status", "created_at"),
        Index("ix_investigations_case", "case_id"),
    )


__all__ = ["Investigation", "InvestigationStatus"]
