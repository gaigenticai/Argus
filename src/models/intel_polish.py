"""Phase 6 — TI Polish models.

ActorPlaybook
    Structured per-actor TTP profile. Extends the existing ``actors``
    table by storing curated MITRE-mapped tradecraft, victim sectors,
    associated malware families, infrastructure IOCs.

HardeningRecommendation
    A prioritized remediation playbook generated for a specific
    ExposureFinding. Maps exposure → CIS Controls v8 ID list +
    MITRE D3FEND mitigation IDs.

CveRecord / EpssScore
    Local mirror of NVD CVE metadata + FIRST EPSS exploit-likelihood.
    Lookups by CVE ID join from ExposureFinding.cve_ids.
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


class HardeningStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    DEFERRED = "deferred"


class ActorPlaybook(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "actor_playbooks"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,  # nullable = global / catalog playbook
    )
    actor_alias: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    aliases: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    targeted_sectors: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    targeted_geos: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    attack_techniques: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    associated_malware: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    infra_iocs: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    references: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "actor_alias",
            name="uq_actor_playbook_org_alias",
        ),
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_actor_playbook_risk_range",
        ),
        Index("ix_actor_playbook_alias", "actor_alias"),
    )


class HardeningRecommendation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "hardening_recommendations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    exposure_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("exposure_findings.id", ondelete="CASCADE"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    cis_control_ids: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    d3fend_techniques: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    nist_csf_subcats: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    priority: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    estimated_effort_hours: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(
        Enum(
            HardeningStatus,
            name="hardening_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=HardeningStatus.OPEN.value,
        nullable=False,
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    status_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        Index("ix_hardening_org_status", "organization_id", "status"),
        Index("ix_hardening_finding", "exposure_finding_id"),
    )


class CveRecord(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    cvss3_score: Mapped[float | None] = mapped_column(Float)
    cvss3_vector: Mapped[str | None] = mapped_column(String(80))
    cvss_severity: Mapped[str | None] = mapped_column(String(20))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cwe_ids: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    references: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    cpes: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        Index("ix_cve_published", "published_at"),
        Index("ix_cve_kev", "is_kev"),
        Index("ix_cve_epss_score", "epss_score"),
    )


class IntelSync(Base, UUIDMixin, TimestampMixin):
    """Audit row per NVD/EPSS/KEV ingestion run."""

    __tablename__ = "intel_syncs"

    source: Mapped[str] = mapped_column(String(40), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(500))
    rows_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rows_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_intel_syncs_source_created", "source", "created_at"),
    )


__all__ = [
    "HardeningStatus",
    "ActorPlaybook",
    "HardeningRecommendation",
    "CveRecord",
    "IntelSync",
]
