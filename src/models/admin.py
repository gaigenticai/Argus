"""Operator-tunable configuration models.

Settings that an operator changes at runtime — fraud thresholds, rating
weights, brand allowlists, crawler targets — live in the database, not
in env vars or Python constants. The dashboard's admin pages read and
write these tables.

Four tables ship in this module:

    AppSetting              key/value/typed-value config (one row per
                            tunable). Strong typing via ``value_type``;
                            JSONB ``value`` so we can store strings,
                            numbers, booleans, lists, and nested dicts
                            without proliferating columns.

    CrawlerTarget           per-crawler runtime config. The scheduler
                            queries this table on every tick to decide
                            which forums / channels / rooms to crawl.
                            One row = one (kind, identifier) target;
                            ``config`` JSONB holds kind-specific
                            options (selectors, auth tokens, etc.).

    FeedHealth              one row per feed-run, capturing whether
                            the feed actually ran (ok / error /
                            unconfigured / rate_limited / parse_error)
                            and the count of rows it ingested. Replaces
                            the silent-zero pattern where a missing
                            API key produced an empty result with no
                            visible failure.

    SubsidiaryAllowlist     domains and brand names that legitimately
                            belong to the customer (or a subsidiary).
                            The brand-typosquat scanner consults this
                            list before creating a SuspectDomain row,
                            preventing the customer's own assets from
                            self-flagging.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base, TimestampMixin, UUIDMixin


# --- AppSetting --------------------------------------------------------


class AppSettingType(str, enum.Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    JSON = "json"


class AppSettingCategory(str, enum.Enum):
    FRAUD = "fraud"
    IMPERSONATION = "impersonation"
    BRAND = "brand"
    RATING = "rating"
    AUTO_CASE = "auto_case"
    CRAWLER = "crawler"
    GENERAL = "general"


class AppSetting(Base, UUIDMixin, TimestampMixin):
    """A single key/typed-value tuple. Keys are dotted (e.g.
    ``rating.exposure_penalty.critical``) and globally unique."""

    __tablename__ = "app_settings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default=AppSettingCategory.GENERAL.value,
    )
    value_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=AppSettingType.JSON.value,
    )
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024))
    minimum: Mapped[float | None] = mapped_column()
    maximum: Mapped[float | None] = mapped_column()

    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_app_settings_org_key"),
        CheckConstraint(
            "value_type IN ('string','integer','float','boolean','json')",
            name="ck_app_settings_value_type",
        ),
    )

    def coerced_value(self) -> Any:
        """Return ``value`` cast to the type implied by ``value_type``."""
        v = self.value
        if self.value_type == AppSettingType.STRING.value:
            return None if v is None else str(v)
        if self.value_type == AppSettingType.INTEGER.value:
            return None if v is None else int(v)
        if self.value_type == AppSettingType.FLOAT.value:
            return None if v is None else float(v)
        if self.value_type == AppSettingType.BOOLEAN.value:
            return None if v is None else bool(v)
        return v


# --- CrawlerTarget -----------------------------------------------------


class CrawlerKind(str, enum.Enum):
    TOR_FORUM = "tor_forum"
    TOR_MARKETPLACE = "tor_marketplace"
    I2P_EEPSITE = "i2p_eepsite"
    LOKINET_SITE = "lokinet_site"
    TELEGRAM_CHANNEL = "telegram_channel"
    MATRIX_ROOM = "matrix_room"
    FORUM = "forum"
    RANSOMWARE_LEAK_GROUP = "ransomware_leak_group"
    STEALER_MARKETPLACE = "stealer_marketplace"


class CrawlerTarget(Base, UUIDMixin, TimestampMixin):
    """A single crawler target — what to crawl for a given crawler kind.

    The scheduler queries this table at every tick. ``config`` JSONB
    carries kind-specific options (selectors, mirror URLs, channel
    handles, room IDs, search terms) so the same row shape supports
    every crawler.

    ``identifier`` is a stable handle for dedup and UI display
    (e.g. the .onion URL, the @channel name, the !room:server alias).
    """

    __tablename__ = "crawler_targets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_status: Mapped[str | None] = mapped_column(String(40))
    last_run_summary: Mapped[dict | None] = mapped_column(JSONB)
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "kind", "identifier",
            name="uq_crawler_targets_org_kind_identifier",
        ),
        CheckConstraint(
            "kind IN ("
            "'tor_forum','tor_marketplace','i2p_eepsite','lokinet_site',"
            "'telegram_channel','matrix_room','forum','ransomware_leak_group',"
            "'stealer_marketplace')",
            name="ck_crawler_targets_kind",
        ),
    )


# --- FeedHealth --------------------------------------------------------


class FeedHealthStatus(str, enum.Enum):
    OK = "ok"
    UNCONFIGURED = "unconfigured"
    AUTH_ERROR = "auth_error"
    NETWORK_ERROR = "network_error"
    RATE_LIMITED = "rate_limited"
    PARSE_ERROR = "parse_error"
    DISABLED = "disabled"


class FeedHealth(Base, UUIDMixin):
    """One row per feed run.

    The retention engine prunes this table aggressively (default 30 days)
    so it stays fast for the dashboard. ``last_status`` on a particular
    ``feed_name`` row is what the UI highlights as the feed's current
    health badge — derived by query, not stored.
    """

    __tablename__ = "feed_health"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    feed_name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    detail: Mapped[str | None] = mapped_column(String(1024))
    rows_ingested: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_feed_health_feed_observed", "feed_name", "observed_at"),
        CheckConstraint(
            "status IN ('ok','unconfigured','auth_error','network_error',"
            "'rate_limited','parse_error','disabled')",
            name="ck_feed_health_status",
        ),
    )


# --- SubsidiaryAllowlist ----------------------------------------------


class AllowlistKind(str, enum.Enum):
    DOMAIN = "domain"
    BRAND_NAME = "brand_name"
    EMAIL_DOMAIN = "email_domain"


class SubsidiaryAllowlist(Base, UUIDMixin, TimestampMixin):
    """Domains / brand names that belong to the customer or a subsidiary.

    The brand-typosquat scanner consults this list before creating a
    SuspectDomain row. A subsidiary's legitimate domain that closely
    resembles the parent (``example-cards.com`` vs ``example.com``) is
    not a typosquat and shouldn't drown the SOC's queue.
    """

    __tablename__ = "subsidiary_allowlist"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    note: Mapped[str | None] = mapped_column(String(1024))
    added_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "kind", "value",
            name="uq_subsidiary_allowlist_org_kind_value",
        ),
        CheckConstraint(
            "kind IN ('domain','brand_name','email_domain')",
            name="ck_subsidiary_allowlist_kind",
        ),
    )


__all__ = [
    "AppSetting",
    "AppSettingCategory",
    "AppSettingType",
    "CrawlerKind",
    "CrawlerTarget",
    "FeedHealth",
    "FeedHealthStatus",
    "AllowlistKind",
    "SubsidiaryAllowlist",
]
