"""MITRE ATT&CK first-class models.

Mirrors the MITRE Enterprise / Mobile / ICS matrices into our DB so
analysts can filter, search, and tag findings by tactic and technique
without an external lookup.

Tables
------
mitre_tactics            one row per tactic per matrix
mitre_techniques         techniques + sub-techniques (parent ref by external_id)
mitre_mitigations        course-of-action items
mitre_syncs              one row per import run (audit + version pinning)

attack_technique_attachments
    Polymorphic m:n linking ATT&CK techniques to any first-class Argus
    entity: alert, ioc, actor, finding, case, asset. Tenant-scoped.
    Created by analysts manually or by automation (triage agent, rule).
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
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class MitreMatrix(str, enum.Enum):
    ENTERPRISE = "enterprise"
    MOBILE = "mobile"
    ICS = "ics"


_MATRIX_VALUES = {m.value for m in MitreMatrix}


class AttachmentSource(str, enum.Enum):
    MANUAL = "manual"
    TRIAGE_AGENT = "triage_agent"
    CORRELATION_AGENT = "correlation_agent"
    FEED_RULE = "feed_rule"
    MITRE_GROUP_LINK = "mitre_group_link"
    IMPORT = "import"


class MitreTactic(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mitre_tactics"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # TA0001
    short_name: Mapped[str] = mapped_column(String(100), nullable=False)  # initial-access
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("matrix", "external_id", name="uq_mitre_tactic_matrix_id"),
        CheckConstraint(
            f"matrix IN ({', '.join(repr(v) for v in _MATRIX_VALUES)})",
            name="ck_mitre_tactic_matrix",
        ),
        Index("ix_mitre_tactic_short_name", "short_name"),
    )


class MitreTechnique(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mitre_techniques"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # T1190 / T1190.001
    parent_external_id: Mapped[str | None] = mapped_column(String(20))  # T1190 if this is .001
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    tactics: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    platforms: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    data_sources: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    detection: Mapped[str | None] = mapped_column(Text)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "matrix", "external_id", name="uq_mitre_technique_matrix_id"
        ),
        CheckConstraint(
            f"matrix IN ({', '.join(repr(v) for v in _MATRIX_VALUES)})",
            name="ck_mitre_technique_matrix",
        ),
        Index("ix_mitre_technique_external_id", "external_id"),
        Index("ix_mitre_technique_tactics", "tactics", postgresql_using="gin"),
        Index("ix_mitre_technique_subtech", "parent_external_id"),
        Index(
            "ix_mitre_technique_active",
            "matrix",
            "deprecated",
            "revoked",
        ),
    )


class MitreMitigation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mitre_mitigations"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # M1041
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "matrix", "external_id", name="uq_mitre_mitigation_matrix_id"
        ),
        CheckConstraint(
            f"matrix IN ({', '.join(repr(v) for v in _MATRIX_VALUES)})",
            name="ck_mitre_mitigation_matrix",
        ),
    )


class MitreSync(Base, UUIDMixin, TimestampMixin):
    """One row per attempted matrix import."""

    __tablename__ = "mitre_syncs"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    tactics_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    techniques_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    subtechniques_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mitigations_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    deprecated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_mitre_syncs_matrix_created", "matrix", "created_at"),
        CheckConstraint(
            f"matrix IN ({', '.join(repr(v) for v in _MATRIX_VALUES)})",
            name="ck_mitre_sync_matrix",
        ),
    )


class AttackTechniqueAttachment(Base, UUIDMixin, TimestampMixin):
    """Polymorphic m:n: any Argus entity → MITRE technique.

    ``entity_type`` controls FK semantics. We deliberately avoid a hard
    FK to keep the catalog lean — ownership integrity is enforced by the
    API layer.
    """

    __tablename__ = "attack_technique_attachments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_external_id: Mapped[str] = mapped_column(String(20), nullable=False)

    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    source: Mapped[str] = mapped_column(
        Enum(
            AttachmentSource,
            name="attack_attachment_source",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=AttachmentSource.MANUAL.value,
        nullable=False,
    )
    note: Mapped[str | None] = mapped_column(Text)
    attached_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "entity_type",
            "entity_id",
            "matrix",
            "technique_external_id",
            name="uq_attack_attach_entity_tech",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_attack_attach_confidence_range",
        ),
        Index("ix_attack_attach_entity", "entity_type", "entity_id"),
        Index("ix_attack_attach_org_tech", "organization_id", "technique_external_id"),
    )


# Allowed entity types — kept as a tuple so the API layer can validate
# without DB round-trips and the set is auditable in code review.
ALLOWED_ENTITY_TYPES: tuple[str, ...] = (
    "alert",
    "ioc",
    "actor",
    "case",
    "asset",
    "finding",
    "discovery_job",
)


__all__ = [
    "MitreMatrix",
    "AttachmentSource",
    "MitreTactic",
    "MitreTechnique",
    "MitreMitigation",
    "MitreSync",
    "AttackTechniqueAttachment",
    "ALLOWED_ENTITY_TYPES",
]
