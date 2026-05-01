"""Logo abuse models (Phase 3.4).

BrandLogo
    Per-org registered logo image with multiple precomputed perceptual
    hashes (pHash, dHash, aHash, color histogram). Image bytes live in
    the Evidence Vault, hashes live here so similarity search is a
    cheap SQL query.

LogoMatch
    A live-probe screenshot that scored above the similarity threshold
    against a registered BrandLogo. Carries the per-hash distances + an
    aggregate verdict so analysts can sanity-check.
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
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class LogoMatchVerdict(str, enum.Enum):
    LIKELY_ABUSE = "likely_abuse"
    POSSIBLE_ABUSE = "possible_abuse"
    NO_MATCH = "no_match"


class BrandLogo(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "brand_logos"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image_evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Perceptual hashes — stored as hex strings for SQL-side comparison.
    phash_hex: Mapped[str] = mapped_column(String(32), nullable=False)
    dhash_hex: Mapped[str] = mapped_column(String(32), nullable=False)
    ahash_hex: Mapped[str] = mapped_column(String(32), nullable=False)
    color_histogram: Mapped[list] = mapped_column(
        ARRAY(Float), default=list, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "image_evidence_sha256", name="uq_brand_logo_org_sha"
        ),
        Index("ix_brand_logo_org_label", "organization_id", "label"),
    )


class LogoMatch(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "logo_matches"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    brand_logo_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("brand_logos.id", ondelete="CASCADE"),
        nullable=False,
    )
    suspect_domain_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("suspect_domains.id", ondelete="SET NULL"),
    )
    live_probe_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("live_probes.id", ondelete="SET NULL"),
    )
    candidate_image_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    phash_distance: Mapped[int] = mapped_column(nullable=False)
    dhash_distance: Mapped[int] = mapped_column(nullable=False)
    ahash_distance: Mapped[int] = mapped_column(nullable=False)
    color_distance: Mapped[float] = mapped_column(Float, nullable=False)
    similarity: Mapped[float] = mapped_column(Float, nullable=False)
    verdict: Mapped[str] = mapped_column(
        Enum(
            LogoMatchVerdict,
            name="logo_match_verdict",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    extra: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        CheckConstraint(
            "similarity >= 0 AND similarity <= 1",
            name="ck_logo_match_similarity_range",
        ),
        Index("ix_logo_matches_org_logo", "organization_id", "brand_logo_id"),
        Index("ix_logo_matches_suspect", "suspect_domain_id"),
        Index("ix_logo_matches_verdict", "organization_id", "verdict"),
    )


__all__ = ["BrandLogo", "LogoMatch", "LogoMatchVerdict"]
