"""Social media + impersonation models (Phase 4).

VipProfile
    A high-value individual whose impersonation must be detected.
    Stores name, aliases, registered handles, and (optionally) the
    perceptual hash + name-keywords needed by the matcher.

SocialAccount
    A registered legitimate handle the org owns (for executives,
    brands, products). The matcher checks if a discovered account is
    genuinely *this* one or a copycat.

ImpersonationFinding
    A discovered candidate impersonator account, with multi-signal
    similarity score. State machine identical to SuspectDomain so the
    UX is consistent.

MobileAppFinding
    Rogue mobile app discovered on Apple App Store / Google Play that
    matches a brand keyword + non-authorised publisher.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class SocialPlatform(str, enum.Enum):
    TWITTER = "twitter"
    X = "x"
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    LINKEDIN = "linkedin"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    GITHUB = "github"
    REDDIT = "reddit"
    MASTODON = "mastodon"
    BLUESKY = "bluesky"


class ImpersonationState(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    TAKEDOWN_REQUESTED = "takedown_requested"
    DISMISSED = "dismissed"
    CLEARED = "cleared"


class ImpersonationKind(str, enum.Enum):
    EXECUTIVE = "executive"  # exec name/photo on attacker handle
    BRAND_ACCOUNT = "brand_account"  # brand handle/banner on attacker handle
    PRODUCT = "product"


class MobileAppStore(str, enum.Enum):
    APPLE = "apple"
    GOOGLE_PLAY = "google_play"


class MobileAppFindingState(str, enum.Enum):
    OPEN = "open"
    TAKEDOWN_REQUESTED = "takedown_requested"
    DISMISSED = "dismissed"
    CLEARED = "cleared"
    CONFIRMED = "confirmed"


class VipProfile(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vip_profiles"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255))
    aliases: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    bio_keywords: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    photo_evidence_sha256s: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    photo_phashes: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "full_name", name="uq_vip_org_full_name"
        ),
        Index("ix_vip_profiles_org", "organization_id"),
    )


class SocialAccount(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "social_accounts"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vip_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vip_profiles.id", ondelete="SET NULL"),
    )
    platform: Mapped[str] = mapped_column(
        Enum(
            SocialPlatform,
            name="social_platform",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    handle: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_url: Mapped[str | None] = mapped_column(String(500))
    is_official: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    keywords: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "platform", "handle",
            name="uq_social_account_org_platform_handle",
        ),
        Index("ix_social_accounts_org_platform", "organization_id", "platform"),
    )


class ImpersonationFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "impersonation_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vip_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vip_profiles.id", ondelete="SET NULL"),
    )
    matched_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("social_accounts.id", ondelete="SET NULL"),
    )

    kind: Mapped[str] = mapped_column(
        Enum(
            ImpersonationKind,
            name="impersonation_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    platform: Mapped[str] = mapped_column(
        Enum(
            SocialPlatform,
            name="impersonation_platform",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    candidate_handle: Mapped[str] = mapped_column(String(255), nullable=False)
    candidate_display_name: Mapped[str | None] = mapped_column(String(255))
    candidate_bio: Mapped[str | None] = mapped_column(Text)
    candidate_url: Mapped[str | None] = mapped_column(String(500))
    candidate_photo_sha256: Mapped[str | None] = mapped_column(String(64))
    candidate_photo_phash: Mapped[str | None] = mapped_column(String(32))

    name_similarity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    handle_similarity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    bio_similarity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    photo_similarity: Mapped[float | None] = mapped_column(Float)
    aggregate_score: Mapped[float] = mapped_column(Float, nullable=False)
    signals: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )

    state: Mapped[str] = mapped_column(
        Enum(
            ImpersonationState,
            name="impersonation_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=ImpersonationState.OPEN.value,
        nullable=False,
    )
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "platform", "candidate_handle", "kind",
            name="uq_impersonation_org_platform_handle_kind",
        ),
        CheckConstraint(
            "aggregate_score >= 0 AND aggregate_score <= 1",
            name="ck_impersonation_score_range",
        ),
        Index(
            "ix_impersonation_findings_org_state", "organization_id", "state"
        ),
    )


class MobileAppFinding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mobile_app_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    store: Mapped[str] = mapped_column(
        Enum(
            MobileAppStore,
            name="mobile_app_store",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    app_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    publisher: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(500))
    icon_sha256: Mapped[str | None] = mapped_column(String(64))
    rating: Mapped[float | None] = mapped_column(Float)
    install_estimate: Mapped[str | None] = mapped_column(String(40))
    matched_term: Mapped[str] = mapped_column(String(255), nullable=False)
    matched_term_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    is_official_publisher: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    state: Mapped[str] = mapped_column(
        Enum(
            MobileAppFindingState,
            name="mobile_app_finding_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=MobileAppFindingState.OPEN.value,
        nullable=False,
    )
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "store", "app_id",
            name="uq_mobile_app_org_store_app",
        ),
        Index("ix_mobile_app_findings_org_state", "organization_id", "state"),
    )


__all__ = [
    "SocialPlatform",
    "ImpersonationKind",
    "ImpersonationState",
    "MobileAppStore",
    "MobileAppFindingState",
    "VipProfile",
    "SocialAccount",
    "ImpersonationFinding",
    "MobileAppFinding",
]
