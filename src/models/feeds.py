"""Threat feed models — live threat intelligence layers for the globe view."""

from __future__ import annotations


from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


# --- Threat Feed Entries (individual IOCs from external feeds) ---


class ThreatFeedEntry(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "threat_feed_entries"

    feed_name: Mapped[str] = mapped_column(String(100), nullable=False)
    layer: Mapped[str] = mapped_column(String(50), nullable=False)
    entry_type: Mapped[str] = mapped_column(String(20), nullable=False)  # ip, domain, url, hash, victim, cve
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    label: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    country_code: Mapped[str | None] = mapped_column(String(2))
    city: Mapped[str | None] = mapped_column(String(255))
    asn: Mapped[str | None] = mapped_column(String(100))
    feed_metadata: Mapped[dict | None] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("feed_name", "value", name="uq_feed_name_value"),
        Index("ix_threat_feed_entries_layer_expires", "layer", "expires_at"),
        Index("ix_threat_feed_entries_country", "country_code"),
        Index("ix_threat_feed_entries_created", "created_at"),
    )


# --- Threat Layers (configurable map layers) ---


class ThreatLayer(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "threat_layers"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    icon: Mapped[str] = mapped_column(String(50), nullable=False)
    color: Mapped[str] = mapped_column(String(7), nullable=False)  # hex color
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    feed_names: Mapped[list] = mapped_column(ARRAY(String), default=list)
    refresh_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    entry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


# --- Global Threat Status (singleton dashboard state) ---


class GlobalThreatStatus(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "global_threat_status"

    infocon_level: Mapped[str] = mapped_column(String(20), default="green", nullable=False)  # green/yellow/orange/red
    active_ransomware_groups: Mapped[int] = mapped_column(Integer, default=0)
    active_c2_servers: Mapped[int] = mapped_column(Integer, default=0)
    active_phishing_campaigns: Mapped[int] = mapped_column(Integer, default=0)
    exploited_cves_count: Mapped[int] = mapped_column(Integer, default=0)
    tor_exit_nodes_count: Mapped[int] = mapped_column(Integer, default=0)
    malware_urls_count: Mapped[int] = mapped_column(Integer, default=0)
    malicious_ips_count: Mapped[int] = mapped_column(Integer, default=0)
