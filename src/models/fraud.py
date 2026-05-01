"""Online anti-fraud findings (Phase 4.3).

A FraudFinding captures a candidate scam page / Telegram channel /
crypto-investment shill that mentions one of the org's brand terms or
executive names. We intentionally keep this distinct from
ImpersonationFinding because the operational response is different
(report to FCA / SEC / regional financial regulator vs platform takedown).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class FraudKind(str, enum.Enum):
    INVESTMENT_SCAM = "investment_scam"
    CRYPTO_GIVEAWAY = "crypto_giveaway"
    ROMANCE_SCAM = "romance_scam"
    JOB_OFFER = "job_offer"
    TECH_SUPPORT = "tech_support"
    SHILL_CHANNEL = "shill_channel"
    OTHER = "other"


class FraudChannel(str, enum.Enum):
    WEBSITE = "website"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    SOCIAL = "social"
    EMAIL = "email"
    SMS = "sms"
    OTHER = "other"


class FraudState(str, enum.Enum):
    OPEN = "open"
    REPORTED_TO_REGULATOR = "reported_to_regulator"
    TAKEDOWN_REQUESTED = "takedown_requested"
    DISMISSED = "dismissed"
    CONFIRMED = "confirmed"


class FraudFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "fraud_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(
        Enum(
            FraudKind,
            name="fraud_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    channel: Mapped[str] = mapped_column(
        Enum(
            FraudChannel,
            name="fraud_channel",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    target_identifier: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str | None] = mapped_column(String(500))
    excerpt: Mapped[str | None] = mapped_column(Text)
    matched_brand_terms: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    matched_keywords: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    state: Mapped[str] = mapped_column(
        Enum(
            FraudState,
            name="fraud_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=FraudState.OPEN.value,
        nullable=False,
    )
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "channel", "target_identifier",
            name="uq_fraud_org_channel_target",
        ),
        CheckConstraint(
            "score >= 0 AND score <= 1", name="ck_fraud_score_range"
        ),
        Index("ix_fraud_findings_org_state", "organization_id", "state"),
        Index("ix_fraud_findings_kind", "kind"),
    )


__all__ = [
    "FraudKind",
    "FraudChannel",
    "FraudState",
    "FraudFinding",
]
