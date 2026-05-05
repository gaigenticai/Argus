"""DMARC forensic (RUF) report storage.

RUA gives counts; RUF gives per-failure samples (Header_From,
Return-Path, original headers, source IP). Forensic reports are how
operators identify spoof campaigns and forwarding-hop misconfigs.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class DmarcForensicReport(Base, UUIDMixin):
    __tablename__ = "dmarc_forensic_reports"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    feedback_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    arrival_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reported_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    original_envelope_from: Mapped[str | None] = mapped_column(String(255))
    original_envelope_to: Mapped[str | None] = mapped_column(String(255))
    original_mail_from: Mapped[str | None] = mapped_column(String(255))
    original_rcpt_to: Mapped[str | None] = mapped_column(String(255))
    auth_failure: Mapped[str | None] = mapped_column(String(255))  # spf|dkim|...
    delivery_result: Mapped[str | None] = mapped_column(String(40))
    raw_headers: Mapped[str | None] = mapped_column(Text)
    dkim_domain: Mapped[str | None] = mapped_column(String(255))
    dkim_selector: Mapped[str | None] = mapped_column(String(120))
    spf_domain: Mapped[str | None] = mapped_column(String(255))
    extras: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    agent_summary: Mapped[dict | None] = mapped_column(JSONB)

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index(
            "ix_dmarc_forensic_org_domain_received",
            "organization_id",
            "domain",
            "received_at",
        ),
        Index("ix_dmarc_forensic_source_ip", "source_ip"),
    )


class DmarcMailboxConfig(Base, UUIDMixin):
    """IMAP credentials for the RUA/RUF mailbox poller, per organisation."""

    __tablename__ = "dmarc_mailbox_configs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, unique=True
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=993)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    # Stored as Fernet ciphertext — never in plaintext.
    password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    folder: Mapped[str] = mapped_column(String(120), nullable=False, default="INBOX")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_uid: Mapped[int | None] = mapped_column(Integer)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

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


__all__ = ["DmarcForensicReport", "DmarcMailboxConfig"]
