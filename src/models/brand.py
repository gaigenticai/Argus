"""Brand Protection models (Phase 3).

BrandTerm
    A per-org watchlist entry — typically the registered brand name
    ("argus", "gaigentic") and the apex domain. Each term seeds the
    typosquat/lookalike scanner and the dark-web search.

SuspectDomain
    A domain observed in the wild that may be impersonating a brand.
    Holds the similarity score against each brand term and the
    classification verdict (open / cleared / takedown_requested /
    confirmed_phishing / dismissed).
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


class BrandTermKind(str, enum.Enum):
    NAME = "name"
    APEX_DOMAIN = "apex_domain"
    PRODUCT = "product"
    EXEC_HANDLE = "exec_handle"
    SLOGAN = "slogan"


class SuspectDomainState(str, enum.Enum):
    OPEN = "open"
    CONFIRMED_PHISHING = "confirmed_phishing"
    TAKEDOWN_REQUESTED = "takedown_requested"
    DISMISSED = "dismissed"
    CLEARED = "cleared"  # legitimate (third-party reseller, partner, etc.)


class SuspectDomainSource(str, enum.Enum):
    DNSTWIST = "dnstwist"
    CERTSTREAM = "certstream"
    WHOISDS = "whoisds"
    MANUAL = "manual"
    SUBDOMAIN_FUZZ = "subdomain_fuzz"
    # Audit B3 — public phishing-feed adapters (free alternatives to
    # Netcraft). Each carries an authoritative "this URL is phishing"
    # signal from the upstream feed; matching it against an org's
    # brand terms surfaces brand-targeted phishing in real time.
    PHISHTANK = "phishtank"
    OPENPHISH = "openphish"
    URLHAUS = "urlhaus"


class BrandTerm(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "brand_terms"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(
        Enum(
            BrandTermKind,
            name="brand_term_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    keywords: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "kind", "value", name="uq_brand_term_org_kind_value"
        ),
        Index("ix_brand_terms_org_active", "organization_id", "is_active"),
    )


class SuspectDomain(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "suspect_domains"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    matched_term_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("brand_terms.id", ondelete="SET NULL"),
    )
    matched_term_value: Mapped[str] = mapped_column(String(255), nullable=False)
    similarity: Mapped[float] = mapped_column(Float, nullable=False)
    permutation_kind: Mapped[str | None] = mapped_column(String(50))
    is_resolvable: Mapped[bool | None] = mapped_column(Boolean)
    a_records: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    mx_records: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    nameservers: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    state: Mapped[str] = mapped_column(
        Enum(
            SuspectDomainState,
            name="suspect_domain_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=SuspectDomainState.OPEN.value,
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        Enum(
            SuspectDomainSource,
            name="suspect_domain_source",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "domain", "matched_term_value",
            name="uq_suspect_org_domain_term",
        ),
        CheckConstraint(
            "similarity >= 0 AND similarity <= 1",
            name="ck_suspect_similarity_range",
        ),
        Index("ix_suspect_org_state", "organization_id", "state"),
        Index("ix_suspect_org_domain", "organization_id", "domain"),
    )


__all__ = [
    "BrandTerm",
    "BrandTermKind",
    "SuspectDomain",
    "SuspectDomainSource",
    "SuspectDomainState",
]
