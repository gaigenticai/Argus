"""Phase 9 — SLA + external ticketing models.

SlaPolicy
    Per-organization rule: "for case severity X, first response within Y
    hours, remediation within Z hours."

ExternalTicketBinding
    Many-to-one binding from a Case to a Jira / ServiceNow / Linear
    ticket. We don't push to Jira directly here — adapter is pluggable
    so customers self-host.

SlaBreachEvent
    Append-only log of SLA breaches. Drives notification routing
    (Phase 0.5) and the dashboard "overdue" view.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


# Audit D5 — alias to the canonical Severity (see src/models/common.py).
from src.models.common import Severity as SlaSeverity  # noqa: E402


class TicketSystem(str, enum.Enum):
    JIRA = "jira"
    SERVICENOW = "servicenow"
    LINEAR = "linear"
    GITHUB = "github"
    CUSTOM = "custom"


class SlaBreachKind(str, enum.Enum):
    FIRST_RESPONSE = "first_response"
    REMEDIATION = "remediation"


class SlaPolicy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sla_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        Enum(
            SlaSeverity,
            name="sla_severity",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    first_response_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    remediation_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "severity", name="uq_sla_org_severity"
        ),
        CheckConstraint(
            "first_response_minutes > 0", name="ck_sla_first_response_pos"
        ),
        CheckConstraint(
            "remediation_minutes > 0", name="ck_sla_remediation_pos"
        ),
    )


class ExternalTicketBinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "external_ticket_bindings"

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
    system: Mapped[str] = mapped_column(
        Enum(
            TicketSystem,
            name="ticket_system",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    external_url: Mapped[str | None] = mapped_column(String(500))
    project_key: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str | None] = mapped_column(String(80))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[str | None] = mapped_column(String(40))
    last_sync_error: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "system", "external_id", name="uq_ticket_system_external_id"
        ),
        Index("ix_ticket_binding_case", "case_id"),
        Index("ix_ticket_binding_org_system", "organization_id", "system"),
    )


class SlaBreachEvent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sla_breach_events"

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
    kind: Mapped[str] = mapped_column(
        Enum(
            SlaBreachKind,
            name="sla_breach_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    threshold_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "case_id", "kind", name="uq_sla_breach_case_kind"
        ),
        Index("ix_sla_breach_org_detected", "organization_id", "detected_at"),
    )


__all__ = [
    "SlaSeverity",
    "TicketSystem",
    "SlaBreachKind",
    "SlaPolicy",
    "ExternalTicketBinding",
    "SlaBreachEvent",
]
