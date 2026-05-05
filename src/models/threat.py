"""Core threat intelligence models."""

from __future__ import annotations


import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    Boolean,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
try:
    from pgvector.sqlalchemy import Vector
except ImportError:
    Vector = None

from .base import Base, TimestampMixin, UUIDMixin


# Audit D5 — alias to the canonical Severity (see src/models/common.py).
from src.models.common import Severity as ThreatSeverity  # noqa: E402


class ThreatCategory(str, enum.Enum):
    CREDENTIAL_LEAK = "credential_leak"
    DATA_BREACH = "data_breach"
    STEALER_LOG = "stealer_log"
    RANSOMWARE = "ransomware"
    RANSOMWARE_VICTIM = "ransomware_victim"
    ACCESS_SALE = "access_sale"
    EXPLOIT = "exploit"
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    DOXXING = "doxxing"
    INSIDER_THREAT = "insider_threat"
    BRAND_ABUSE = "brand_abuse"
    DARK_WEB_MENTION = "dark_web_mention"
    UNDERGROUND_CHATTER = "underground_chatter"
    INITIAL_ACCESS = "initial_access"


class SourceType(str, enum.Enum):
    TOR_FORUM = "tor_forum"
    TOR_MARKETPLACE = "tor_marketplace"
    I2P = "i2p"
    LOKINET = "lokinet"
    TELEGRAM = "telegram"
    STEALER_LOG = "stealer_log"
    RANSOMWARE_LEAK = "ransomware_leak"
    FORUM_UNDERGROUND = "forum_underground"
    MATRIX = "matrix"
    ACCESS_BROKER = "access_broker"
    SURFACE_WEB = "surface_web"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    NEEDS_REVIEW = "needs_review"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


# --- Organization & Monitoring Targets ---


class Organization(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    domains: Mapped[list] = mapped_column(ARRAY(String), default=list)
    keywords: Mapped[list] = mapped_column(ARRAY(String), default=list)
    industry: Mapped[str | None] = mapped_column(String(100))
    tech_stack: Mapped[dict | None] = mapped_column(JSONB)
    settings: Mapped[dict | None] = mapped_column(JSONB)

    vips = relationship("VIPTarget", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")
    alerts = relationship("Alert", back_populates="organization")


class VIPTarget(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vip_targets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255))
    emails: Mapped[list] = mapped_column(ARRAY(String), default=list)
    usernames: Mapped[list] = mapped_column(ARRAY(String), default=list)
    phone_numbers: Mapped[list] = mapped_column(ARRAY(String), default=list)
    keywords: Mapped[list] = mapped_column(ARRAY(String), default=list)
    social_profiles: Mapped[dict | None] = mapped_column(JSONB)

    organization = relationship("Organization", back_populates="vips")


class Asset(Base, UUIDMixin, TimestampMixin):
    """Polymorphic external entity monitored by Argus.

    Asset types span domain/subdomain/ip/service (EASM targets) plus
    executives, brands, mobile apps, social handles, vendors, code repos,
    and cloud accounts (DRP/TPRM/brand-protection targets).

    Type-specific structured data lives in ``details`` (JSONB) and is
    validated by :mod:`src.models.asset_schemas` at the API layer.
    """

    __tablename__ = "assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB)

    # --- Phase 0 registry extension ---
    criticality: Mapped[str] = mapped_column(
        String(20), default="medium", nullable=False
    )  # crown_jewel | high | medium | low
    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    monitoring_profile: Mapped[dict | None] = mapped_column(JSONB)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    discovery_method: Mapped[str] = mapped_column(
        String(40), default="manual", nullable=False
    )
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_change_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    monitoring_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Phase 1.3 — composite risk score (exploitability × accessibility ×
    # age × criticality). Computed by ``src/easm/risk_scoring.py``;
    # nullable when no scan data yet exists.
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_score_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    # Phase 1.3 — auto-classification by the surface-classifier agent.
    # Shape: ``{"environment": "prod"|"staging"|..., "role": "admin"|...,
    #         "tags": [...], "confidence": 0..1, "rationale": "..."}``
    ai_classification: Mapped[dict | None] = mapped_column(JSONB)
    ai_classified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    organization = relationship("Organization", back_populates="assets")
    parent = relationship(
        "Asset",
        remote_side="Asset.id",
        backref="children",
    )

    __table_args__ = (
        Index("ix_assets_org_type", "organization_id", "asset_type"),
        Index("ix_assets_value", "value"),
        Index("ix_assets_org_value_type", "organization_id", "asset_type", "value", unique=True),
        Index("ix_assets_criticality", "criticality"),
        Index("ix_assets_parent", "parent_asset_id"),
        Index("ix_assets_tags", "tags", postgresql_using="gin"),
    )


# --- Raw Intelligence ---


class RawIntel(Base, UUIDMixin, TimestampMixin):
    """Raw data collected by crawlers before agent processing."""

    __tablename__ = "raw_intel"

    source_type: Mapped[str] = mapped_column(
        Enum(SourceType, name="source_type", values_callable=lambda x: [m.value for m in x]),
        nullable=False,
    )
    source_url: Mapped[str | None] = mapped_column(Text)
    source_name: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str | None] = mapped_column(String(255))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    is_processed: Mapped[bool] = mapped_column(Boolean, default=False)
    # embedding column requires pgvector PostgreSQL extension
    # Uncomment when pgvector is installed: embedding = mapped_column(Vector(1536), nullable=True)

    __table_args__ = (
        Index("ix_raw_intel_source", "source_type", "is_processed"),
        Index("ix_raw_intel_hash", "content_hash"),
    )


# --- Processed Alerts ---


class Alert(Base, UUIDMixin, TimestampMixin):
    """Processed and triaged threat alert."""

    __tablename__ = "alerts"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    raw_intel_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("raw_intel.id")
    )
    category: Mapped[str] = mapped_column(
        Enum(ThreatCategory, name="threat_category", values_callable=lambda x: [m.value for m in x]),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        Enum(ThreatSeverity, name="threat_severity", values_callable=lambda x: [m.value for m in x]),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        Enum(AlertStatus, name="alert_status", values_callable=lambda x: [m.value for m in x]),
        default=AlertStatus.NEW.value,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB)
    matched_entities: Mapped[dict | None] = mapped_column(JSONB)  # what org data matched
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    agent_reasoning: Mapped[str | None] = mapped_column(Text)  # LLM's analysis
    recommended_actions: Mapped[list | None] = mapped_column(JSONB)
    analyst_notes: Mapped[str | None] = mapped_column(Text)

    organization = relationship("Organization", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_org_severity", "organization_id", "severity"),
        Index("ix_alerts_status", "status"),
    )


class Report(Base, UUIDMixin, TimestampMixin):
    """Generated threat intelligence PDF report."""

    __tablename__ = "reports"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    date_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    date_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)

    organization = relationship("Organization")
