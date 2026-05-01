"""Per-user feed subscriptions (P3 #3.4).

A *feed subscription* is a user-self-service alternative to the org-
scoped ``notification_rules`` system: a saved filter expression on the
alert stream + a list of delivery channels (webhook URL, email, slack
webhook). The user can create, list, and delete their own
subscriptions through the SDK without going through an admin.

The existing org-wide ``NotificationRule`` model remains the right
place for SOC-team rules (asset-criticality gating, multi-channel
fan-out, dedup windows). Feed subscriptions are deliberately simpler
— a single user-owned filter + channel set.

Filter expression shape (JSONB):

  {
    "severity": ["critical", "high"],     # any-of
    "category": ["phishing"],             # any-of
    "tags_any": ["gcc", "banking"],       # any-of
    "min_confidence": 0.6                 # numeric floor
  }

All keys are optional; an empty object matches every alert.

Channels list (JSONB):

  [
    {"type": "webhook", "url": "https://soc.example/argus-hook",
     "secret": "shared-token-for-hmac"},
    {"type": "email", "address": "alice@bank.example"}
  ]

The matcher (``src.core.feed_subscription_match.match_alert``) is the
canonical evaluator and is reused by the alert dispatcher and the
test suite.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class FeedSubscription(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "feed_subscriptions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    filter: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    channels: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_dispatched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_feed_subscriptions_user_active", "user_id", "active"),
        Index("ix_feed_subscriptions_org", "organization_id"),
    )
