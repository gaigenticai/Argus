"""Evidence Vault — immutable, hash-addressed blob storage metadata.

Every monitoring finding (phishing screenshot, brand-logo abuse, takedown
proof PDF, WHOIS history snapshot, executive photo for impersonation
matching) needs persistent evidence. The vault stores binary content in
MinIO (or any S3-compatible store) keyed by SHA-256, with this table
holding the metadata + tenant scope + audit trail.

Immutability rules:
    - Content addressed by SHA-256 — any change produces a new blob.
    - Soft delete only (``is_deleted`` flag). Hard delete is reserved for
      retention-policy enforcement, run with explicit operator approval.
    - The same hash within the same org is deduplicated: re-uploading
      identical bytes returns the existing record.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


class EvidenceKind(str, enum.Enum):
    SCREENSHOT = "screenshot"
    HTML_SNAPSHOT = "html_snapshot"
    DOM_TREE = "dom_tree"
    WHOIS_HISTORY = "whois_history"
    DNS_HISTORY = "dns_history"
    CERT_CHAIN = "cert_chain"
    TAKEDOWN_PROOF_PDF = "takedown_proof_pdf"
    EXECUTIVE_PHOTO = "executive_photo"
    BRAND_LOGO = "brand_logo"
    APP_STORE_LISTING = "app_store_listing"
    SOCIAL_PROFILE_SNAPSHOT = "social_profile_snapshot"
    DMARC_REPORT_RAW = "dmarc_report_raw"
    LEAKED_DOCUMENT = "leaked_document"
    SBOM = "sbom"
    NETWORK_PCAP = "network_pcap"
    OTHER = "other"


class EvidenceBlob(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "evidence_blobs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(127), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(
        Enum(
            EvidenceKind,
            name="evidence_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )

    # Where the bytes physically live. ``s3_bucket`` allows future migration
    # to a different bucket without rewriting the table.
    s3_bucket: Mapped[str] = mapped_column(String(127), nullable=False)
    s3_key: Mapped[str] = mapped_column(String(500), nullable=False)

    # Immutability + lifecycle
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    delete_reason: Mapped[str | None] = mapped_column(Text)

    # Audit G4 — legal hold blocks deletion + retention purging.
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    captured_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    capture_source: Mapped[str | None] = mapped_column(String(127))
    description: Mapped[str | None] = mapped_column(Text)
    extra: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        # SHA-256 must be 64 hex chars
        CheckConstraint(
            "char_length(sha256) = 64",
            name="ck_evidence_sha256_length",
        ),
        # Dedup within tenant by hash (active blobs only — soft deletes can
        # coexist as historical records)
        UniqueConstraint(
            "organization_id",
            "sha256",
            name="uq_evidence_org_sha256",
        ),
        Index("ix_evidence_org_kind", "organization_id", "kind"),
        Index("ix_evidence_asset", "asset_id"),
        Index("ix_evidence_captured_at", "captured_at"),
        Index("ix_evidence_sha256", "sha256"),
    )


__all__ = ["EvidenceBlob", "EvidenceKind"]
