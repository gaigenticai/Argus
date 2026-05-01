"""DMARC360 — aggregate (RUA) and forensic (RUF) report storage.

Aggregate report (RUA, XML)
    Sent by mailbox providers daily-ish; summarises pass/fail counts per
    sending source. We store the *parsed* shape so dashboards can chart
    it cheaply, plus the raw XML in evidence vault by hash for audit.

Forensic report (RUF)
    Per-failure forensic copies of bounces. Optional and rarer; we keep
    them too for incident response.

email_authentication_check
    SPF/DKIM/DMARC live DNS-resolution snapshots run hourly per
    email_domain asset. Drift is reported into the AssetChange feed
    (already wired in Phase 1.1 dns_refresh).
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


class DmarcReportKind(str, enum.Enum):
    AGGREGATE = "aggregate"
    FORENSIC = "forensic"


class DmarcDispositionPolicy(str, enum.Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class DmarcReport(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "dmarc_reports"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
    )
    kind: Mapped[str] = mapped_column(
        Enum(
            DmarcReportKind,
            name="dmarc_report_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    org_name: Mapped[str | None] = mapped_column(String(255))  # reporter
    report_id: Mapped[str] = mapped_column(String(255), nullable=False)
    date_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    date_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    policy_p: Mapped[str | None] = mapped_column(String(20))  # none/quarantine/reject
    policy_pct: Mapped[int | None] = mapped_column(Integer)

    total_messages: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    pass_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    fail_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    quarantine_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    reject_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    raw_xml_sha256: Mapped[str | None] = mapped_column(String(64))
    parsed: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "domain",
            "report_id",
            "kind",
            name="uq_dmarc_org_domain_report",
        ),
        Index("ix_dmarc_org_domain", "organization_id", "domain"),
        Index("ix_dmarc_date_begin", "date_begin"),
    )


class DmarcReportRecord(Base, UUIDMixin, TimestampMixin):
    """One ``<record>`` row from an aggregate report — per source IP / count.

    Stored as a child table so we can chart sender-IP trends without
    re-parsing the JSON each time.
    """

    __tablename__ = "dmarc_report_records"

    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dmarc_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    count: Mapped[int] = mapped_column(BigInteger, default=1, nullable=False)
    disposition: Mapped[str | None] = mapped_column(String(20))
    spf_result: Mapped[str | None] = mapped_column(String(20))
    dkim_result: Mapped[str | None] = mapped_column(String(20))
    spf_aligned: Mapped[bool | None] = mapped_column(Boolean)
    dkim_aligned: Mapped[bool | None] = mapped_column(Boolean)
    header_from: Mapped[str | None] = mapped_column(String(255))
    envelope_from: Mapped[str | None] = mapped_column(String(255))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        Index("ix_dmarc_record_report", "report_id"),
        Index("ix_dmarc_record_org_ip", "organization_id", "source_ip"),
    )


__all__ = [
    "DmarcDispositionPolicy",
    "DmarcReport",
    "DmarcReportKind",
    "DmarcReportRecord",
]
