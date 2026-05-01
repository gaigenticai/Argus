"""Case Management — investigations grouping findings.

A Case is the unit of analyst work: it groups one or more Alerts (existing
threat-intel model) under a single investigation, tracks who is working
on it, the current state, SLA deadlines, comments, and a full state-
transition history.

Why a dedicated state-transition table rather than reusing AuditLog:
analysts query "show me how this case progressed" constantly; that is a
hot path which deserves its own table + indexes. AuditLog is the
generic, append-only stream for compliance — both write paths are
preserved.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


# --- Enums --------------------------------------------------------------


class CaseState(str, enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    CLOSED = "closed"


# Audit D5 — alias to the canonical Severity (see src/models/common.py).
from src.models.common import Severity as CaseSeverity  # noqa: E402


# State machine — adjacency list of allowed transitions.
# Closed cases can be reopened back to OPEN with a documented reason.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    CaseState.OPEN.value: {CaseState.TRIAGED.value, CaseState.CLOSED.value},
    CaseState.TRIAGED.value: {CaseState.IN_PROGRESS.value, CaseState.CLOSED.value},
    CaseState.IN_PROGRESS.value: {CaseState.REMEDIATED.value, CaseState.CLOSED.value},
    CaseState.REMEDIATED.value: {CaseState.VERIFIED.value, CaseState.IN_PROGRESS.value, CaseState.CLOSED.value},
    CaseState.VERIFIED.value: {CaseState.CLOSED.value, CaseState.IN_PROGRESS.value},
    CaseState.CLOSED.value: {CaseState.OPEN.value},  # reopen
}


def is_transition_allowed(from_state: str, to_state: str) -> bool:
    return to_state in ALLOWED_TRANSITIONS.get(from_state, set())


# --- Models -------------------------------------------------------------


class Case(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "cases"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)

    severity: Mapped[str] = mapped_column(
        Enum(
            CaseSeverity,
            name="case_severity",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=CaseSeverity.MEDIUM.value,
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        Enum(
            CaseState,
            name="case_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=CaseState.OPEN.value,
        nullable=False,
    )

    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)

    # SLA tracking
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_response_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    close_reason: Mapped[str | None] = mapped_column(Text)

    # Optional related asset shortcut (the primary asset). Use
    # ``case_findings`` for the full alert/finding linkage.
    primary_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )

    extra: Mapped[dict | None] = mapped_column(JSONB)

    # Audit G4 — legal hold pauses retention purging on this row.
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    findings = relationship(
        "CaseFinding",
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    comments = relationship(
        "CaseComment",
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="CaseComment.created_at",
    )
    transitions = relationship(
        "CaseStateTransition",
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="CaseStateTransition.transitioned_at",
    )

    __table_args__ = (
        Index("ix_cases_org_state", "organization_id", "state"),
        Index("ix_cases_assignee", "assignee_user_id"),
        Index("ix_cases_severity", "severity"),
        Index("ix_cases_sla_due", "sla_due_at"),
        Index("ix_cases_tags", "tags", postgresql_using="gin"),
    )


class CaseFinding(Base, UUIDMixin, TimestampMixin):
    """Many-to-many between Case and the existing Alert model.

    Stored as its own table so we keep the linkage metadata: who linked
    it, when, why, and whether it is the "primary" finding.
    """

    __tablename__ = "case_findings"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Audit D12 — `alert_id` is now optional. Polymorphic Phase 1+
    # findings (Exposure, SuspectDomain, Impersonation, Fraud,
    # CardLeakage, Dlp, LogoMatch, LiveProbe) are linked via
    # ``finding_type`` + ``finding_id`` instead of being shoehorned
    # through the Alert table.
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=True,
    )
    finding_type: Mapped[str | None] = mapped_column(String(64))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    linked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    link_reason: Mapped[str | None] = mapped_column(Text)

    case = relationship("Case", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),
        Index("ix_case_findings_alert", "alert_id"),
    )


class CaseComment(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "case_comments"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    edited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case = relationship("Case", back_populates="comments")

    __table_args__ = (Index("ix_case_comments_case", "case_id"),)


class CaseStateTransition(Base, UUIDMixin):
    """Append-only state-change log for a Case.

    Distinct from AuditLog so analysts can query a case's full state
    history with a simple WHERE case_id = X. AuditLog still records the
    same action for compliance.
    """

    __tablename__ = "case_state_transitions"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_state: Mapped[str | None] = mapped_column(String(40))
    to_state: Mapped[str] = mapped_column(String(40), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    transitioned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    transitioned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ),
        nullable=False,
    )

    case = relationship("Case", back_populates="transitions")

    __table_args__ = (Index("ix_case_transitions_case", "case_id", "transitioned_at"),)


__all__ = [
    "Case",
    "CaseFinding",
    "CaseComment",
    "CaseStateTransition",
    "CaseState",
    "CaseSeverity",
    "ALLOWED_TRANSITIONS",
    "is_transition_allowed",
]
