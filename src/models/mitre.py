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


class MitreGroup(Base, UUIDMixin, TimestampMixin):
    """ATT&CK intrusion-set (G####).

    Auto-imported from the STIX bundle. Powers /actors auto-seed and the
    technique→groups pivot on /mitre + /threat-hunter.
    """

    __tablename__ = "mitre_groups"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # G0096
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    aliases: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    country_codes: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    sectors_targeted: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    regions_targeted: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("matrix", "external_id", name="uq_mitre_group_matrix_id"),
        Index("ix_mitre_group_external_id", "external_id"),
        Index("ix_mitre_group_aliases", "aliases", postgresql_using="gin"),
        Index("ix_mitre_group_sectors", "sectors_targeted", postgresql_using="gin"),
        Index("ix_mitre_group_regions", "regions_targeted", postgresql_using="gin"),
    )


class MitreSoftware(Base, UUIDMixin, TimestampMixin):
    """ATT&CK software (S####) — malware + tools."""

    __tablename__ = "mitre_software"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # S0001
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    aliases: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    software_type: Mapped[str] = mapped_column(String(20), nullable=False)  # malware|tool
    description: Mapped[str | None] = mapped_column(Text)
    platforms: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    labels: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("matrix", "external_id", name="uq_mitre_software_matrix_id"),
        Index("ix_mitre_software_external_id", "external_id"),
        Index("ix_mitre_software_name", "name"),
        Index("ix_mitre_software_aliases", "aliases", postgresql_using="gin"),
    )


class MitreDataSource(Base, UUIDMixin, TimestampMixin):
    """ATT&CK data source (DS####) with data components."""

    __tablename__ = "mitre_data_sources"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # DS0009
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    platforms: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    collection_layers: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    data_components: Mapped[list] = mapped_column(
        JSONB, default=list, nullable=False
    )
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("matrix", "external_id", name="uq_mitre_ds_matrix_id"),
    )


class MitreCampaign(Base, UUIDMixin, TimestampMixin):
    """ATT&CK campaign (C####)."""

    __tablename__ = "mitre_campaigns"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(20), nullable=False)  # C0001
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    aliases: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500))
    sync_version: Mapped[str | None] = mapped_column(String(50))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("matrix", "external_id", name="uq_mitre_camp_matrix_id"),
    )


class MitreRelationship(Base, UUIDMixin, TimestampMixin):
    """Unified STIX relationship junction across the ATT&CK graph.

    `relationship_type` examples (STIX-canonical): uses, mitigates,
    detects, attributed-to, subtechnique-of, revoked-by.

    `source_type` / `target_type` examples: technique, group, software,
    mitigation, data-source, data-component, campaign.
    """

    __tablename__ = "mitre_relationships"

    matrix: Mapped[str] = mapped_column(String(20), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_external_id: Mapped[str] = mapped_column(String(20), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_external_id: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    sync_version: Mapped[str | None] = mapped_column(String(50))

    __table_args__ = (
        UniqueConstraint(
            "matrix",
            "source_type",
            "source_external_id",
            "relationship_type",
            "target_type",
            "target_external_id",
            name="uq_mitre_rel_full",
        ),
        Index("ix_mitre_rel_source", "source_type", "source_external_id"),
        Index("ix_mitre_rel_target", "target_type", "target_external_id"),
        Index("ix_mitre_rel_type", "relationship_type"),
    )


class MitreLayer(Base, UUIDMixin, TimestampMixin):
    """Saved Navigator-style coverage layer.

    `technique_scores` is a {T#### -> int 0..100} map. Exported as
    standard ATT&CK Navigator JSON v4.5 by the API.
    """

    __tablename__ = "mitre_layers"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    matrix: Mapped[str] = mapped_column(
        String(20), nullable=False, default=MitreMatrix.ENTERPRISE.value
    )
    technique_scores: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    color_palette: Mapped[dict] = mapped_column(
        JSONB,
        default=lambda: {"low": "#FFE0B2", "med": "#FFAB00", "high": "#FF5630"},
        nullable=False,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (Index("ix_mitre_layers_org", "organization_id"),)


class MitreTechniqueCoverage(Base, UUIDMixin, TimestampMixin):
    """Per-org coverage state per technique — what detects it, how strongly.

    Used to render the "you cover X% of MITRE Top 20" comparison view +
    the green/amber/red heatmap on /mitre.
    """

    __tablename__ = "mitre_technique_coverage"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    matrix: Mapped[str] = mapped_column(
        String(20), nullable=False, default=MitreMatrix.ENTERPRISE.value
    )
    technique_external_id: Mapped[str] = mapped_column(String(20), nullable=False)
    covered_by: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )  # ["sigma", "yara", "edr", "manual"]
    score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0..100
    notes: Mapped[str | None] = mapped_column(Text)
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "matrix",
            "technique_external_id",
            name="uq_mitre_coverage_org_tech",
        ),
        Index(
            "ix_mitre_coverage_org_tech",
            "organization_id",
            "technique_external_id",
        ),
    )


__all__ = [
    "MitreMatrix",
    "AttachmentSource",
    "MitreTactic",
    "MitreTechnique",
    "MitreMitigation",
    "MitreSync",
    "AttackTechniqueAttachment",
    "MitreGroup",
    "MitreSoftware",
    "MitreDataSource",
    "MitreCampaign",
    "MitreRelationship",
    "MitreLayer",
    "MitreTechniqueCoverage",
    "ALLOWED_ENTITY_TYPES",
]
