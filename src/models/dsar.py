"""Data Subject Access Request (DSAR) workflow.

GDPR Art.15 (right of access), Art.17 (right to erasure), CCPA
§1798.100 (right to know) require the controller to respond to subject
requests within a defined window. This table backs the DSAR pipeline:
intake → search → review → export → close.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class DsarRequest(Base, UUIDMixin):
    __tablename__ = "dsar_requests"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # Subject identifiers — at least one required.
    subject_email: Mapped[str | None] = mapped_column(String(255))
    subject_name: Mapped[str | None] = mapped_column(String(255))
    subject_phone: Mapped[str | None] = mapped_column(String(64))
    subject_id_other: Mapped[str | None] = mapped_column(String(255))
    # request_type ∈ {access, erasure, portability, rectification, restriction}
    request_type: Mapped[str] = mapped_column(String(40), nullable=False)
    regulation: Mapped[str | None] = mapped_column(String(40))  # gdpr|ccpa|hipaa|...
    # status ∈ {received, scanning, ready_for_review, exported, closed, denied}
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="received")
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Tables searched and rows located. Populated by the DSAR worker.
    matched_tables: Mapped[list] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    match_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    matched_row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Bridge-LLM produced response letter (markdown, awaiting human sign-off).
    draft_response: Mapped[str | None] = mapped_column(Text)
    final_response: Mapped[str | None] = mapped_column(Text)
    export_evidence_blob_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    notes: Mapped[str | None] = mapped_column(Text)
    closed_reason: Mapped[str | None] = mapped_column(String(120))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_dsar_org_status_created", "organization_id", "status", "created_at"),
        Index("ix_dsar_subject_email", "subject_email"),
    )


__all__ = ["DsarRequest"]
