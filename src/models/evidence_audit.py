"""Tamper-evident, hash-chained audit log for the Evidence Vault.

Each row's ``payload_hash`` is SHA-256 over the canonical event JSON.
Each row's ``chain_hash`` is SHA-256(prev.chain_hash || self.payload_hash).
The chain head is published periodically (out-of-band timestamping —
e.g. OpenTimestamps / cosign / blockchain anchor) so a verifier can
prove no row has been altered since the head was anchored.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Identity, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class EvidenceAuditChain(Base, UUIDMixin):
    __tablename__ = "evidence_audit_chain"

    sequence: Mapped[int] = mapped_column(
        BigInteger,
        Identity(always=False, start=1, cycle=False),
        unique=True,
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    evidence_blob_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_chain_hash: Mapped[str | None] = mapped_column(String(64))
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    anchor_id: Mapped[str | None] = mapped_column(String(255))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_evidence_audit_org_created", "organization_id", "created_at"),
        Index("ix_evidence_audit_blob", "evidence_blob_id"),
    )


__all__ = ["EvidenceAuditChain"]
