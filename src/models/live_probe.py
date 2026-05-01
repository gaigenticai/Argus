"""Live phishing-probe storage (Phase 3.3).

A LiveProbe is a single fetch+classify of a suspect domain. We keep
every probe (not just the latest) so analysts can audit how a verdict
evolved over time when the page changes.

The actual page bytes (HTML, screenshot) live in Evidence Vault keyed
by sha256 — this row only stores the metadata + the classification
verdict.
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
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class LiveProbeVerdict(str, enum.Enum):
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNREACHABLE = "unreachable"
    PARKED = "parked"
    UNKNOWN = "unknown"


class LiveProbe(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "live_probes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    suspect_domain_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("suspect_domains.id", ondelete="CASCADE"),
        nullable=True,
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str | None] = mapped_column(String(2000))
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    http_status: Mapped[int | None] = mapped_column(Integer)
    final_url: Mapped[str | None] = mapped_column(String(2000))
    title: Mapped[str | None] = mapped_column(String(500))

    # Evidence vault SHA-256s (immutable, hash-addressed).
    html_evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    screenshot_evidence_sha256: Mapped[str | None] = mapped_column(String(64))

    verdict: Mapped[str] = mapped_column(
        Enum(
            LiveProbeVerdict,
            name="live_probe_verdict",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    classifier_name: Mapped[str] = mapped_column(String(80), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    signals: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    matched_brand_terms: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    rationale: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    extra: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_live_probe_confidence_range",
        ),
        Index("ix_live_probes_org_domain", "organization_id", "domain"),
        Index("ix_live_probes_suspect", "suspect_domain_id"),
        Index("ix_live_probes_verdict", "organization_id", "verdict"),
        Index("ix_live_probes_fetched_at", "fetched_at"),
    )


__all__ = ["LiveProbeVerdict", "LiveProbe"]
