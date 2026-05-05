"""Notification Router models.

NotificationChannel
    A configured destination — email, Slack webhook, MS Teams webhook,
    generic webhook, PagerDuty service, Opsgenie team, or Jasmin SMS
    gateway. Credentials stored encrypted (Fernet, see core.crypto).

NotificationRule
    Tenant-scoped trigger: conditions (severity floor, optional category,
    optional tag, optional asset criticality) + a fan-out list of channel
    ids. Multiple rules may match a single event; deliveries are
    deduplicated per (channel_id, event_dedup_key) within a 5-minute
    window to prevent storms.

NotificationDelivery
    Append-only audit row for every adapter invocation: status, latency,
    response/error body, retry count.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


class ChannelKind(str, enum.Enum):
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"
    JASMIN_SMS = "jasmin_sms"


class DeliveryStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"  # rule matched but dedup window suppressed delivery
    DRY_RUN = "dry_run"


class EventKind(str, enum.Enum):
    """High-level taxonomy of things that can trigger a notification."""

    ALERT = "alert"
    CASE_TRANSITION = "case_transition"
    SLA_BREACH = "sla_breach"
    DISCOVERY_FINDING = "discovery_finding"
    SECURITY_RATING_DROP = "security_rating_drop"
    DMARC_FAILURE = "dmarc_failure"
    PHISHING_DETECTION = "phishing_detection"
    IMPERSONATION_DETECTION = "impersonation_detection"
    DATA_LEAKAGE = "data_leakage"
    SYSTEM_HEALTH = "system_health"
    TEST = "test"


class SeverityLevel(str, enum.Enum):
    """Mirrors ThreatSeverity but lives here so the router doesn't depend
    on threat-intel internals.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Numeric ordering for severity comparisons.
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class NotificationChannel(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "notification_channels"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(
        Enum(
            ChannelKind,
            name="notification_channel_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Public config (non-secret) — endpoint URL, recipient list, channel
    # name, etc. Visible in API responses.
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Encrypted secret blob (Fernet). Never returned by the API. Decrypted
    # only at dispatch time.
    secret_ciphertext: Mapped[str | None] = mapped_column(Text)

    description: Mapped[str | None] = mapped_column(Text)

    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(40))
    last_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_notif_channels_org_kind", "organization_id", "kind"),
    )


class NotificationRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "notification_rules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Conditions
    event_kinds: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )  # empty = all kinds match
    min_severity: Mapped[str] = mapped_column(
        String(20), default=SeverityLevel.LOW.value, nullable=False
    )
    asset_criticalities: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )  # empty = all
    asset_types: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    tags_any: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )  # event tags must overlap with this set; empty = any

    # Action — channels to fan out to.
    channel_ids: Mapped[list] = mapped_column(
        ARRAY(UUID(as_uuid=True)), default=list, nullable=False
    )

    # Per-(rule, dedup_key) anti-storm window.
    dedup_window_seconds: Mapped[int] = mapped_column(
        Integer, default=300, nullable=False
    )

    description: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_notif_rules_org", "organization_id", "enabled"),
    )


class NotificationDelivery(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "notification_deliveries"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_rules.id", ondelete="SET NULL"),
    )
    channel_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_channels.id", ondelete="SET NULL"),
    )
    event_kind: Mapped[str] = mapped_column(String(50), nullable=False)
    event_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    event_dedup_key: Mapped[str | None] = mapped_column(String(200))
    event_payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    status: Mapped[str] = mapped_column(
        Enum(
            DeliveryStatus,
            name="notification_delivery_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Channel-Aware Content Agent — per-channel rendered body, runbook,
    # severity reclassifier verdict, dedup-cluster meta.
    rendered_payload: Mapped[dict | None] = mapped_column(JSONB)
    cluster_count: Mapped[int | None] = mapped_column(Integer)
    cluster_dedup_key: Mapped[str | None] = mapped_column(String(200))

    __table_args__ = (
        Index("ix_notif_deliveries_org_kind", "organization_id", "event_kind"),
        Index("ix_notif_deliveries_status", "status"),
        Index(
            "ix_notif_deliveries_dedup",
            "channel_id",
            "event_dedup_key",
            "delivered_at",
        ),
    )


__all__ = [
    "ChannelKind",
    "DeliveryStatus",
    "EventKind",
    "SeverityLevel",
    "SEVERITY_ORDER",
    "NotificationChannel",
    "NotificationRule",
    "NotificationDelivery",
]
