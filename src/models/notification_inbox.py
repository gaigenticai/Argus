"""In-app notification inbox.

Companion to the existing ``notification_deliveries`` table — that
table tracks outbound deliveries to Slack/PagerDuty/etc, this one
tracks per-user in-app notifications that the dashboard displays in
its inbox.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class NotificationInboxItem(Base, UUIDMixin):
    __tablename__ = "notification_inbox"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    event_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    link_path: Mapped[str | None] = mapped_column(String(500))
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index(
            "ix_notification_inbox_org_user_created",
            "organization_id",
            "user_id",
            "created_at",
        ),
        Index(
            "ix_notification_inbox_unread",
            "organization_id",
            "user_id",
            "read_at",
        ),
    )


__all__ = ["NotificationInboxItem"]
