"""Data Leakage models (Phase 5).

CreditCardBin
    BIN (Bank Identification Number) registry — first 6-8 digits of a
    PAN map to issuing bank, scheme, country, type. Lets us tell whether
    a leaked CC belongs to a customer's bank.

CardLeakageFinding
    A discovered leaked credit card — Luhn-validated PAN substring
    matched against the BIN registry. We never store full PANs;
    only first6 + last4 + sha256 of the full PAN for dedup.

DlpPolicy
    Tenant-defined regex / keyword / yara rule set used to scan
    crawler output and paste sites for sensitive content.

DlpFinding
    A match of a DlpPolicy against some external content.
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
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class CardScheme(str, enum.Enum):
    VISA = "visa"
    MASTERCARD = "mastercard"
    AMEX = "amex"
    DISCOVER = "discover"
    JCB = "jcb"
    UNIONPAY = "unionpay"
    DINERS = "diners"
    OTHER = "other"


class CardType(str, enum.Enum):
    CREDIT = "credit"
    DEBIT = "debit"
    PREPAID = "prepaid"
    UNKNOWN = "unknown"


class LeakageState(str, enum.Enum):
    OPEN = "open"
    NOTIFIED = "notified"
    REISSUED = "reissued"
    DISMISSED = "dismissed"
    CONFIRMED = "confirmed"


class CreditCardBin(Base, UUIDMixin, TimestampMixin):
    """Tenant-scoped or global BIN entry. Tenant-scoped allows banks to
    upload their own internal BIN range list."""

    __tablename__ = "credit_card_bins"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    bin_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(255))
    scheme: Mapped[str] = mapped_column(
        Enum(
            CardScheme,
            name="card_scheme",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=CardScheme.OTHER.value,
        nullable=False,
    )
    card_type: Mapped[str] = mapped_column(
        Enum(
            CardType,
            name="card_type",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=CardType.UNKNOWN.value,
        nullable=False,
    )
    country_code: Mapped[str | None] = mapped_column(String(2))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "bin_prefix",
            name="uq_card_bin_org_prefix",
        ),
        Index("ix_card_bins_prefix", "bin_prefix"),
    )


class CardLeakageFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "card_leakage_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    pan_first6: Mapped[str] = mapped_column(String(8), nullable=False)
    pan_last4: Mapped[str] = mapped_column(String(4), nullable=False)
    pan_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    matched_bin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("credit_card_bins.id", ondelete="SET NULL"),
    )
    issuer: Mapped[str | None] = mapped_column(String(255))
    scheme: Mapped[str] = mapped_column(String(20), nullable=False)
    card_type: Mapped[str] = mapped_column(String(20), nullable=False)

    source_url: Mapped[str | None] = mapped_column(String(500))
    source_kind: Mapped[str | None] = mapped_column(String(40))  # paste, dark_web, stealer_log, manual
    excerpt: Mapped[str | None] = mapped_column(Text)
    expiry: Mapped[str | None] = mapped_column(String(10))  # MM/YY if known

    state: Mapped[str] = mapped_column(
        Enum(
            LeakageState,
            name="leakage_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=LeakageState.OPEN.value,
        nullable=False,
    )
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)
    # Bridge agentic outputs
    classification: Mapped[dict | None] = mapped_column(JSONB)
    correlated_findings: Mapped[dict | None] = mapped_column(JSONB)
    breach_correlations: Mapped[dict | None] = mapped_column(JSONB)
    agent_summary: Mapped[dict | None] = mapped_column(JSONB)
    takedown_draft: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "pan_sha256",
            name="uq_card_leak_org_pan",
        ),
        Index("ix_card_leak_org_state", "organization_id", "state"),
        Index("ix_card_leak_first6", "pan_first6"),
    )


class DlpPolicyKind(str, enum.Enum):
    KEYWORD = "keyword"
    REGEX = "regex"
    YARA = "yara"


class DlpPolicy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "dlp_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(
        Enum(
            DlpPolicyKind,
            name="dlp_policy_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20), default="medium", nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_dlp_policy_org_name"
        ),
        Index("ix_dlp_policies_org_enabled", "organization_id", "enabled"),
    )


class DlpFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "dlp_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_policies.id", ondelete="SET NULL"),
    )
    policy_name: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    source_url: Mapped[str | None] = mapped_column(String(500))
    source_kind: Mapped[str | None] = mapped_column(String(40))
    matched_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    matched_excerpts: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )

    state: Mapped[str] = mapped_column(
        Enum(
            LeakageState,
            name="dlp_finding_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=LeakageState.OPEN.value,
        nullable=False,
    )
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)
    # Bridge agentic outputs
    classification: Mapped[dict | None] = mapped_column(JSONB)
    correlated_findings: Mapped[dict | None] = mapped_column(JSONB)
    breach_correlations: Mapped[dict | None] = mapped_column(JSONB)
    agent_summary: Mapped[dict | None] = mapped_column(JSONB)
    takedown_draft: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_dlp_findings_org_state", "organization_id", "state"),
        Index("ix_dlp_findings_policy", "policy_id"),
    )


__all__ = [
    "CardScheme",
    "CardType",
    "LeakageState",
    "CreditCardBin",
    "CardLeakageFinding",
    "DlpPolicyKind",
    "DlpPolicy",
    "DlpFinding",
]
