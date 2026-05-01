"""ORM models for the D3FEND + OSCAL catalog tables (P2 #2.12)."""

from __future__ import annotations

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class D3FENDTechnique(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "d3fend_techniques"

    d3fend_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    definition: Mapped[str | None] = mapped_column(Text)
    tactic: Mapped[str | None] = mapped_column(String(32))
    counters_attack_ids: Mapped[list | None] = mapped_column(JSONB)
    source_url: Mapped[str | None] = mapped_column(String(512))
    source_version: Mapped[str | None] = mapped_column(String(32))


class OscalCatalogEntry(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "oscal_catalog_entries"
    __table_args__ = (
        UniqueConstraint("catalog", "control_id",
                         name="uq_oscal_catalog_control"),
        Index("ix_oscal_catalog_catalog", "catalog"),
    )

    catalog: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    statement: Mapped[str | None] = mapped_column(Text)
    oscal: Mapped[dict | None] = mapped_column(JSONB)
    source_url: Mapped[str | None] = mapped_column(String(512))
    source_version: Mapped[str | None] = mapped_column(String(32))
