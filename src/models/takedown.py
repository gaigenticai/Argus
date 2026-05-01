"""Phase 10 — Takedown ticketing models.

TakedownTicket
    Argus-side representation of a request to remove malicious content
    from the internet. Bound to a source finding (suspect domain,
    impersonation, rogue mobile app, fraud finding) and dispatched to
    one of the configured takedown partners.

The actual partner integration (Netcraft, PhishLabs, regional vendor)
ships as a pluggable adapter — exact partner is a Krishna-deferred
decision per ``CTM360_PARITY_PLAN.md``. The default partner here is the
``manual`` adapter which simply records the ticket without sending
anywhere — so the workflow is functional even when no partner is wired.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class TakedownPartner(str, enum.Enum):
    NETCRAFT = "netcraft"
    PHISHLABS = "phishlabs"
    GROUP_IB = "group_ib"
    INTERNAL_LEGAL = "internal_legal"
    MANUAL = "manual"


class TakedownState(str, enum.Enum):
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"
    WITHDRAWN = "withdrawn"


class TakedownTargetKind(str, enum.Enum):
    SUSPECT_DOMAIN = "suspect_domain"
    IMPERSONATION = "impersonation"
    MOBILE_APP = "mobile_app"
    FRAUD = "fraud"
    OTHER = "other"


class TakedownTicket(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "takedown_tickets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    partner: Mapped[str] = mapped_column(
        Enum(
            TakedownPartner,
            name="takedown_partner",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        Enum(
            TakedownState,
            name="takedown_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=TakedownState.SUBMITTED.value,
        nullable=False,
    )
    target_kind: Mapped[str] = mapped_column(
        Enum(
            TakedownTargetKind,
            name="takedown_target_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    target_identifier: Mapped[str] = mapped_column(String(500), nullable=False)
    source_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    partner_reference: Mapped[str | None] = mapped_column(String(255))
    partner_url: Mapped[str | None] = mapped_column(String(500))
    submitted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    succeeded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    proof_evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "target_kind",
            "target_identifier",
            "partner",
            name="uq_takedown_org_target_partner",
        ),
        Index("ix_takedown_org_state", "organization_id", "state"),
        Index("ix_takedown_partner_ref", "partner", "partner_reference"),
    )


_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    # Fast partners can jump straight to succeeded — allow it.
    "submitted": {
        "acknowledged",
        "in_progress",
        "succeeded",
        "rejected",
        "withdrawn",
        "failed",
    },
    "acknowledged": {"in_progress", "succeeded", "rejected", "failed", "withdrawn"},
    "in_progress": {"succeeded", "rejected", "failed", "withdrawn"},
    "succeeded": set(),
    "rejected": {"submitted"},
    "failed": {"submitted"},
    "withdrawn": {"submitted"},
}


def is_takedown_transition_allowed(from_state: str, to_state: str) -> bool:
    return to_state in _ALLOWED_TRANSITIONS.get(from_state, set())


__all__ = [
    "TakedownPartner",
    "TakedownState",
    "TakedownTargetKind",
    "TakedownTicket",
    "is_takedown_transition_allowed",
]
