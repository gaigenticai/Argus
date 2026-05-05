"""Pre-purge knowledge preservation.

When the retention scheduler runs, it asks the Bridge LLM to summarise
*what we learned* from the rows about to be deleted, so the wisdom
survives even when the raw data is purged for compliance. The summary
is PII-free by construction (LLM is prompted to drop subject IDs).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class LearningsLog(Base, UUIDMixin):
    __tablename__ = "learnings_log"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    source_table: Mapped[str] = mapped_column(String(80), nullable=False)
    rows_summarised: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary_md: Mapped[str] = mapped_column(Text, nullable=False)
    extracted_iocs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    extracted_actors: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    extracted_techniques: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    model_id: Mapped[str | None] = mapped_column(String(80))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index(
            "ix_learnings_org_table_created",
            "organization_id",
            "source_table",
            "created_at",
        ),
    )


__all__ = ["LearningsLog"]
