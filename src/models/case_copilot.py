"""Case Copilot agent runs.

Triggered when an analyst opens a Case (or hits the "Run Copilot"
button). The agent reads the case + its linked findings, looks at
similar closed cases the org has worked before, suggests MITRE
techniques to attach, and drafts a starter timeline + next-step
playbook. Output is advisory — the analyst clicks "Apply" to copy
the suggestions into the case.

The persistence shape mirrors :class:`Investigation` and
:class:`BrandAction` so the dashboard renders all three with the same
trace UI.
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


class CopilotStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CaseCopilotRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "case_copilot_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        Enum(
            CopilotStatus,
            name="case_copilot_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=CopilotStatus.QUEUED.value,
        nullable=False,
    )

    # Verdict — three structured artefacts plus a summary blurb.
    summary: Mapped[str | None] = mapped_column(Text)
    timeline_events: Mapped[list | None] = mapped_column(JSONB)  # [{at, source, text}]
    suggested_mitre_ids: Mapped[list | None] = mapped_column(JSONB)  # ["T1190", ...]
    draft_next_steps: Mapped[list | None] = mapped_column(JSONB)  # ["Step 1...", ...]
    # Catalogued playbooks the LLM picked from the investigation
    # surface. Each entry: ``{"playbook_id": str, "params": {...},
    # "rationale": str}``. ``apply_suggestions`` turns this into one
    # ``PlaybookExecution`` per row, linked back to the case + this
    # copilot run via the new FKs on ``playbook_executions``. Older
    # runs (pre-v2) leave this NULL and apply_suggestions falls
    # through to the legacy comment-only path.
    suggested_playbooks: Mapped[list | None] = mapped_column(JSONB)
    similar_case_ids: Mapped[list | None] = mapped_column(JSONB)  # historical reference cases
    confidence: Mapped[float | None] = mapped_column(Float)

    # Operator interaction — set when the analyst clicks "Apply".
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    # Provenance
    iterations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    trace: Mapped[list | None] = mapped_column(JSONB)
    model_id: Mapped[str | None] = mapped_column(String(100))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_case_copilot_case", "case_id"),
        Index("ix_case_copilot_org_status", "organization_id", "status"),
        Index("ix_case_copilot_status_created", "status", "created_at"),
    )


__all__ = ["CaseCopilotRun", "CopilotStatus"]
