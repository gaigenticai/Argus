"""DeepScan exposure model.

ExposureFinding
    A confirmed-or-suspected vulnerability / misconfiguration / weak
    crypto / version-disclosure observed against a customer asset by
    one of the DeepScan tools (nuclei / nmap -sV / testssl.sh).

Distinct from :class:`DiscoveryFinding` (Phase 1.1) which captures the
*existence* of an asset; this captures *exposure on a known asset*.

Lifecycle states
----------------
    open               just created
    acknowledged       analyst has seen + plans to fix
    accepted_risk      analyst has decided not to fix
    false_positive     incorrect detection
    fixed              analyst confirms remediation
    reopened           previously fixed, observed again
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


# Audit D5 — alias to the canonical Severity (see src/models/common.py).
from src.models.common import Severity as ExposureSeverity  # noqa: E402


class ExposureCategory(str, enum.Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    WEAK_CRYPTO = "weak_crypto"
    EXPOSED_SERVICE = "exposed_service"
    VERSION_DISCLOSURE = "version_disclosure"
    EXPIRED_CERT = "expired_cert"
    SELF_SIGNED_CERT = "self_signed_cert"
    DEFAULT_CREDENTIAL = "default_credential"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OTHER = "other"


class ExposureState(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    REOPENED = "reopened"


class ExposureSource(str, enum.Enum):
    NUCLEI = "nuclei"
    NMAP = "nmap"
    TESTSSL = "testssl"
    PROWLER = "prowler"
    MANUAL = "manual"
    OTHER = "other"


_TERMINAL_STATES = {"accepted_risk", "false_positive", "fixed"}


# Allowed transitions for ExposureFinding.state.
_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "open": {"acknowledged", "accepted_risk", "false_positive", "fixed"},
    "acknowledged": {"accepted_risk", "false_positive", "fixed", "open"},
    "accepted_risk": {"open", "reopened"},
    "false_positive": {"open", "reopened"},
    "fixed": {"reopened"},
    "reopened": {"acknowledged", "accepted_risk", "false_positive", "fixed"},
}


def is_state_transition_allowed(from_state: str, to_state: str) -> bool:
    return to_state in _ALLOWED_TRANSITIONS.get(from_state, set())


class ExposureFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "exposure_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="SET NULL")
    )

    severity: Mapped[str] = mapped_column(
        Enum(
            ExposureSeverity,
            name="exposure_severity",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    category: Mapped[str] = mapped_column(
        Enum(
            ExposureCategory,
            name="exposure_category",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        Enum(
            ExposureState,
            name="exposure_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=ExposureState.OPEN.value,
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        Enum(
            ExposureSource,
            name="exposure_source",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )

    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    target: Mapped[str] = mapped_column(String(500), nullable=False)
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    occurrence_count: Mapped[int] = mapped_column(default=1, nullable=False)

    cvss_score: Mapped[float | None] = mapped_column(Float)
    cve_ids: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    cwe_ids: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    references: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)

    matcher_data: Mapped[dict | None] = mapped_column(JSONB)
    raw: Mapped[dict | None] = mapped_column(JSONB)

    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_reason: Mapped[str | None] = mapped_column(Text)

    # --- EPSS / KEV enrichment (populated lazily by worker + read-time
    # backfill from CveRecord; null when no matching CVE record exists).
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- Structured remediation captured on terminal state transitions.
    # ``remediation_action`` is one of: patched | waived | mitigated | blocked |
    # false_positive — free-form remediation_notes preserves analyst commentary.
    remediation_action: Mapped[str | None] = mapped_column(String(64))
    remediation_patch_version: Mapped[str | None] = mapped_column(String(128))
    remediation_owner: Mapped[str | None] = mapped_column(String(255))
    remediation_notes: Mapped[str | None] = mapped_column(Text)

    # --- AI triage outputs.
    ai_priority: Mapped[float | None] = mapped_column(Float)
    ai_rationale: Mapped[str | None] = mapped_column(Text)
    ai_triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ai_suggest_dismiss: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    ai_dismiss_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        # Within an org, the same (rule_id, target) collapses into one row
        # whose ``occurrence_count`` and ``last_seen_at`` get bumped on
        # repeat observations.
        UniqueConstraint(
            "organization_id",
            "rule_id",
            "target",
            name="uq_exposure_org_rule_target",
        ),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_exposure_cvss_range",
        ),
        Index("ix_exposure_org_state", "organization_id", "state"),
        Index("ix_exposure_org_severity", "organization_id", "severity"),
        Index("ix_exposure_asset", "asset_id"),
        Index("ix_exposure_cve_ids", "cve_ids", postgresql_using="gin"),
        Index("ix_exposure_is_kev", "is_kev"),
        Index("ix_exposure_epss_score", "epss_score"),
        Index("ix_exposure_ai_priority", "ai_priority"),
    )


__all__ = [
    "ExposureCategory",
    "ExposureFinding",
    "ExposureSeverity",
    "ExposureSource",
    "ExposureState",
    "is_state_transition_allowed",
]
