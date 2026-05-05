"""Saved searches + scheduled digest deliveries."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class SavedSearch(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "saved_searches"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(String(40), nullable=False)  # cve|article|advisory
    filters: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    digest_frequency: Mapped[str] = mapped_column(
        String(20), nullable=False, default="daily"
    )  # off|daily|weekly
    digest_email: Mapped[str | None] = mapped_column(String(255))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("ix_saved_search_org_active", "organization_id", "active"),
    )


class IntelDigestDelivery(Base, UUIDMixin):
    __tablename__ = "intel_digest_deliveries"

    saved_search_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("saved_searches.id", ondelete="CASCADE"),
        nullable=False,
    )
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    body_markdown: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str | None] = mapped_column(Text)
    delivered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    delivery_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow(),
    )

    __table_args__ = (
        Index("ix_intel_digest_delivered", "delivered", "created_at"),
    )


__all__ = ["SavedSearch", "IntelDigestDelivery"]
