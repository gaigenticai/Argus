"""Compliance Evidence Pack — ORM models (P1 #1.3).

Five tables — see migration f1a2b3c4d5e6 for schema rationale and
RLS policy. The two tenant-scoped tables (ComplianceEvidence,
ComplianceExport) are gated by Postgres RLS via the
``app.current_org`` GUC; callers must use a session that has set the
GUC (see ``src/storage/database.set_session_org``) — the ORM layer
itself does not enforce the filter.

Enums on the migration are CHECK constraints (not Postgres enum
types), so the columns here are plain ``String`` and the canonical
value list lives in the ``*Enum`` Python classes below. Validate via
Pydantic at the API boundary, not on the ORM.
"""

from __future__ import annotations

import enum
import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


# --- Enums (validated at API layer, not stored as Postgres enum types) ---


class SignalKind(str, enum.Enum):
    ALERT_CATEGORY = "alert_category"
    MITRE_TECHNIQUE = "mitre_technique"
    CASE_STATE = "case_state"
    TAG = "tag"


class EvidenceSourceKind(str, enum.Enum):
    ALERT = "alert"
    CASE = "case"
    FINDING = "finding"
    MANUAL = "manual"


class EvidenceStatus(str, enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    SUPERSEDED = "superseded"


class ExportLanguageMode(str, enum.Enum):
    EN = "en"
    AR = "ar"
    BILINGUAL = "bilingual"


class ExportFormat(str, enum.Enum):
    PDF = "pdf"
    JSON = "json"


class ExportStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


# --- Models --------------------------------------------------------------


class ComplianceFramework(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_frameworks"

    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name_en: Mapped[str] = mapped_column(String(255), nullable=False)
    name_ar: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(512))
    source_version_date: Mapped[date | None] = mapped_column(Date)
    description_en: Mapped[str | None] = mapped_column(Text)
    description_ar: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    controls: Mapped[list["ComplianceControl"]] = relationship(
        back_populates="framework",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ComplianceControl(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "control_id",
                         name="uq_compliance_controls_framework_ctrl"),
        Index("ix_compliance_controls_framework_sort",
              "framework_id", "sort_order"),
    )

    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_control_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="SET NULL"),
    )
    title_en: Mapped[str] = mapped_column(Text, nullable=False)
    title_ar: Mapped[str | None] = mapped_column(Text)
    description_en: Mapped[str | None] = mapped_column(Text)
    description_ar: Mapped[str | None] = mapped_column(Text)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    framework: Mapped[ComplianceFramework] = relationship(back_populates="controls")
    mappings: Mapped[list["ComplianceControlMapping"]] = relationship(
        back_populates="control",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ComplianceControlMapping(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_control_mappings"
    __table_args__ = (
        UniqueConstraint("control_id", "signal_kind", "signal_value",
                         name="uq_compliance_mappings_ctrl_kind_val"),
        CheckConstraint(
            "signal_kind IN ('alert_category','mitre_technique','case_state','tag')",
            name="ck_compliance_mappings_signal_kind",
        ),
        Index("ix_compliance_mappings_signal", "signal_kind", "signal_value"),
    )

    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    signal_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    signal_value: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    control: Mapped[ComplianceControl] = relationship(back_populates="mappings")


class ComplianceEvidence(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_evidence"
    __table_args__ = (
        CheckConstraint(
            "source_kind IN ('alert','case','finding','manual')",
            name="ck_compliance_evidence_source_kind",
        ),
        CheckConstraint(
            "status IN ('active','archived','superseded')",
            name="ck_compliance_evidence_status",
        ),
        Index(
            "ix_compliance_evidence_org_framework_captured",
            "organization_id", "framework_id", "captured_at",
        ),
        Index("ix_compliance_evidence_org_control",
              "organization_id", "control_id"),
        Index("ix_compliance_evidence_source",
              "source_kind", "source_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    summary_en: Mapped[str | None] = mapped_column(Text)
    summary_ar: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=EvidenceStatus.ACTIVE.value,
    )

    framework: Mapped[ComplianceFramework] = relationship()
    control: Mapped[ComplianceControl] = relationship()


class ComplianceExport(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_exports"
    __table_args__ = (
        CheckConstraint(
            "language_mode IN ('en','ar','bilingual')",
            name="ck_compliance_exports_language_mode",
        ),
        CheckConstraint(
            "format IN ('pdf','json')",
            name="ck_compliance_exports_format",
        ),
        CheckConstraint(
            "status IN ('pending','running','completed','failed','expired')",
            name="ck_compliance_exports_status",
        ),
        Index("ix_compliance_exports_org_created",
              "organization_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="RESTRICT"),
        nullable=False,
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    language_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    period_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    period_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ExportStatus.PENDING.value,
    )
    object_storage_key: Mapped[str | None] = mapped_column(String(512))
    hash_sha256: Mapped[str | None] = mapped_column(String(64))
    byte_size: Mapped[int | None] = mapped_column(BigInteger)
    error_message: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    framework: Mapped[ComplianceFramework] = relationship()
