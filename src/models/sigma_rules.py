"""Sigma rule catalog (parsed from SigmaHQ/sigma)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class SigmaRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sigma_rules"

    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    level: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str | None] = mapped_column(String(40))
    author: Mapped[str | None] = mapped_column(String(255))
    log_source: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    detection: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    falsepositives: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    technique_ids: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    references: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    source_repo: Mapped[str | None] = mapped_column(String(500))
    source_path: Mapped[str | None] = mapped_column(String(500))
    sha256: Mapped[str | None] = mapped_column(String(64))
    raw_yaml: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_sigma_rules_techniques", "technique_ids", postgresql_using="gin"),
        Index("ix_sigma_rules_tags", "tags", postgresql_using="gin"),
        Index("ix_sigma_rules_level", "level"),
    )


__all__ = ["SigmaRule"]
