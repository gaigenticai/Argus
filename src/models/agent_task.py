"""Agent task queue — async LLM jobs with retry, dedup, and observability.

A single table fronts every Bridge-LLM-driven agent in the platform
(triage classifier, takedown drafter, RCA, channel renderer, DSAR
responder, etc.). Producers enqueue rows; the worker picks them up,
calls Bridge, and writes the structured result back. The same table
powers /agent-activity for operator visibility.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class AgentTask(Base, UUIDMixin):
    """One queued LLM job. Idempotent on (kind, dedup_key)."""

    __tablename__ = "agent_tasks"

    # Discriminates the agent ("evidence_summarise", "leakage_classify",
    # "dmarc_rca", "notification_render", "retention_dsar", etc.)
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    # Optional tenant scoping; some agents (DSAR) are org-scoped, others
    # (cross-org correlation) are not.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # Idempotency key — producer-supplied. Re-enqueueing the same
    # (kind, dedup_key) returns the existing row.
    dedup_key: Mapped[str] = mapped_column(String(200), nullable=False)
    # status ∈ {queued, running, ok, error, dead}
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    # Producer-supplied input. Free-form per agent kind.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Worker-written structured output. Free-form per agent kind.
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd_estimate: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("kind", "dedup_key", name="uq_agent_tasks_kind_dedup"),
        Index("ix_agent_tasks_status_priority", "status", "priority", "created_at"),
        Index("ix_agent_tasks_kind_status", "kind", "status"),
        Index("ix_agent_tasks_org_kind", "organization_id", "kind"),
    )


__all__ = ["AgentTask"]
