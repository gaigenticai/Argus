"""Security Rating models.

Every organization has a current ``SecurityRating`` (latest computed
snapshot) and a history of past ratings. Each rating decomposes into
``RatingFactor`` rows that record exactly which signals contributed
how much, so the dashboard can answer "why is my grade B?".

Rubric versioning
-----------------
The schema and weights live in :mod:`src.ratings.engine` keyed by a
``rubric_version`` string. We never silently change weights — moving
from v1 → v2 produces a new history row and the old factors stay
auditable forever.
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
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


class RatingGrade(str, enum.Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class RatingScope(str, enum.Enum):
    ORGANIZATION = "organization"
    VENDOR = "vendor"  # Phase 7 TPRM


class SecurityRating(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "security_ratings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope: Mapped[str] = mapped_column(
        Enum(
            RatingScope,
            name="rating_scope",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=RatingScope.ORGANIZATION.value,
        nullable=False,
    )
    # Optional: when scope=vendor, the vendor asset id.
    vendor_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
    )

    rubric_version: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)  # 0..100
    grade: Mapped[str] = mapped_column(
        Enum(
            RatingGrade,
            name="rating_grade",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    is_current: Mapped[bool] = mapped_column(default=False, nullable=False)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    inputs_hash: Mapped[str | None] = mapped_column(String(64))

    factors = relationship(
        "RatingFactor",
        back_populates="rating",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="RatingFactor.factor_key",
    )

    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_rating_score_range"),
        Index("ix_rating_org_current", "organization_id", "is_current"),
        Index("ix_rating_computed_at", "computed_at"),
    )


class RatingFactor(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "rating_factors"

    rating_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_ratings.id", ondelete="CASCADE"),
        nullable=False,
    )
    factor_key: Mapped[str] = mapped_column(String(80), nullable=False)
    pillar: Mapped[str] = mapped_column(String(40), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    weight: Mapped[float] = mapped_column(Float, nullable=False)  # share of total (0..1)
    raw_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0..100
    weighted_score: Mapped[float] = mapped_column(Float, nullable=False)  # raw_score * weight
    evidence: Mapped[dict | None] = mapped_column(JSONB)

    rating = relationship("SecurityRating", back_populates="factors")

    __table_args__ = (
        UniqueConstraint(
            "rating_id", "factor_key", name="uq_rating_factor_key"
        ),
        CheckConstraint(
            "weight >= 0 AND weight <= 1", name="ck_factor_weight_range"
        ),
        CheckConstraint(
            "raw_score >= 0 AND raw_score <= 100",
            name="ck_factor_raw_score_range",
        ),
    )


__all__ = [
    "RatingGrade",
    "RatingScope",
    "SecurityRating",
    "RatingFactor",
]
