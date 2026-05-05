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
    # Plan-then-act gate (T57): emitted after iteration 1 when the
    # org enables ``investigation_plan_approval``. The agent records
    # its proposed tool sequence into ``Investigation.plan`` and
    # blocks until POST /investigations/{id}/approve-plan resumes it.
    AWAITING_PLAN_APPROVAL = "awaiting_plan_approval"
    COMPLETED = "completed"
    FAILED = "failed"


class InvestigationStopReason(str, enum.Enum):
    """Why the agentic loop stopped. Surfaced on the dashboard so the
    analyst knows whether to trust the verdict or re-run.

    ``high_confidence`` is the desirable terminal — the agent decided
    it had enough. ``max_iterations`` means we hit the budget without
    a confident verdict (re-running rarely helps). ``no_new_evidence``
    means three iterations in a row found nothing new (reduces wasted
    LLM calls). ``llm_error`` and ``user_aborted`` are operational.
    """
    HIGH_CONFIDENCE = "high_confidence"
    MAX_ITERATIONS = "max_iterations"
    NO_NEW_EVIDENCE = "no_new_evidence"
    LLM_ERROR = "llm_error"
    USER_ABORTED = "user_aborted"


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
    trace: Mapped[list | None] = mapped_column(JSONB)  # [{iteration, thought, tool, args, result, started_at, duration_ms}]
    model_id: Mapped[str | None] = mapped_column(String(100))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Why the loop terminated — see ``InvestigationStopReason``.
    # Nullable for legacy rows; new completions always populate.
    stop_reason: Mapped[str | None] = mapped_column(
        Enum(
            InvestigationStopReason,
            name="investigation_stop_reason",
            values_callable=lambda x: [m.value for m in x],
        ),
    )
    # Agent's self-reported confidence in the final verdict (0..1).
    # Distinct from the seed alert's confidence. Used by the dashboard
    # to colour the "stopped because" line and by future auto-promotion
    # gates that require a confidence floor.
    final_confidence: Mapped[float | None] = mapped_column(Float)
    # Deduped, ordered list of tool names the agent invoked. Computed
    # at finalize time from the trace so the dashboard can render
    # "tools used" chips without re-walking the trace.
    tools_used: Mapped[list | None] = mapped_column(ARRAY(String))

    # LLM token accounting (T50). May be null when the bridge
    # provider doesn't expose per-call counts.
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)

    # Plan-then-act gate (T57). When the org has plan-approval mode on,
    # the agent stalls after iteration 1 with status=awaiting_plan_approval
    # and writes its proposed tool sequence into ``plan``. Operator
    # POSTs /approve-plan to resume.
    plan: Mapped[list | None] = mapped_column(JSONB)  # [{tool, args_preview, rationale}]

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_investigations_alert", "alert_id"),
        Index("ix_investigations_org_status", "organization_id", "status"),
        Index("ix_investigations_status_created", "status", "created_at"),
        Index("ix_investigations_case", "case_id"),
    )


__all__ = ["Investigation", "InvestigationStatus", "InvestigationStopReason"]
