"""Advisory ingest health — per-source observability."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class AdvisoryIngestHealth(Base, UUIDMixin):
    __tablename__ = "advisory_ingest_health"

    source: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(500))
    http_status: Mapped[int | None] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    rows_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_parsed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_inserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schema_shape: Mapped[str] = mapped_column(
        String(60), nullable=False, default="unknown"
    )
    missing_fields: Mapped[dict] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    raw_sample: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_advisory_health_source_started", "source", "started_at"),
    )


__all__ = ["AdvisoryIngestHealth"]
