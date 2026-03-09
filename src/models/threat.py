"""Core threat intelligence models."""

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
from pgvector.sqlalchemy import Vector

from .base import Base, TimestampMixin, UUIDMixin


class ThreatSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, enum.Enum):
    CREDENTIAL_LEAK = "credential_leak"
    DATA_BREACH = "data_breach"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    DOXXING = "doxxing"
    INSIDER_THREAT = "insider_threat"
    BRAND_ABUSE = "brand_abuse"
    DARK_WEB_MENTION = "dark_web_mention"
    PASTE_LEAK = "paste_leak"
    CODE_LEAK = "code_leak"


class SourceType(str, enum.Enum):
    TOR_FORUM = "tor_forum"
    TOR_MARKETPLACE = "tor_marketplace"
    PASTE_SITE = "paste_site"
    TELEGRAM = "telegram"
    GITHUB = "github"
    CVE_FEED = "cve_feed"
    SURFACE_WEB = "surface_web"
    SOCIAL_MEDIA = "social_media"


class AlertStatus(str, enum.Enum):
    NEW = "new"
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
    __tablename__ = "assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(50))  # domain, subdomain, ip, service
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    organization = relationship("Organization", back_populates="assets")

    __table_args__ = (
        Index("ix_assets_org_type", "organization_id", "asset_type"),
        Index("ix_assets_value", "value"),
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
    embedding = mapped_column(Vector(1536), nullable=True)

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
