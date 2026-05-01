"""Brand Defender agent runs.

One row per execution of :class:`src.agents.brand_defender_agent.BrandDefenderAgent`.
Triggered when a new SuspectDomain lands with similarity above the
operator's threshold; the agent gathers signals (live probe, logo
similarity, WHOIS age, subsidiary allowlist) and recommends an action.

Recommendation taxonomy:
  * ``takedown_now``              — high-confidence phishing, file with partner
  * ``takedown_after_review``     — likely phishing but score isn't decisive
  * ``dismiss_subsidiary``        — matches a known subsidiary, no action
  * ``monitor``                   — low signal, leave it watched
  * ``insufficient_data``         — couldn't reach the live probe / WHOIS
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


class BrandActionStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BrandActionRecommendation(str, enum.Enum):
    TAKEDOWN_NOW = "takedown_now"
    TAKEDOWN_AFTER_REVIEW = "takedown_after_review"
    DISMISS_SUBSIDIARY = "dismiss_subsidiary"
    MONITOR = "monitor"
    INSUFFICIENT_DATA = "insufficient_data"


class BrandAction(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "brand_actions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    suspect_domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("suspect_domains.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Set by the analyst's "Submit takedown" button after reviewing the
    # recommendation; null until then. Once a takedown ticket exists,
    # the agent's recommendation is treated as historical.
    takedown_ticket_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("takedown_tickets.id", ondelete="SET NULL"),
    )

    status: Mapped[str] = mapped_column(
        Enum(
            BrandActionStatus,
            name="brand_action_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=BrandActionStatus.QUEUED.value,
        nullable=False,
    )

    # Verdict
    recommendation: Mapped[str | None] = mapped_column(
        Enum(
            BrandActionRecommendation,
            name="brand_action_recommendation",
            values_callable=lambda x: [m.value for m in x],
        )
    )
    recommendation_reason: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    risk_signals: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    suggested_partner: Mapped[str | None] = mapped_column(String(80))

    # Provenance
    iterations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    trace: Mapped[list | None] = mapped_column(JSONB)
    model_id: Mapped[str | None] = mapped_column(String(100))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_brand_actions_suspect", "suspect_domain_id"),
        Index("ix_brand_actions_org_status", "organization_id", "status"),
        Index(
            "ix_brand_actions_status_created",
            "status",
            "created_at",
        ),
    )


__all__ = [
    "BrandAction",
    "BrandActionStatus",
    "BrandActionRecommendation",
]
