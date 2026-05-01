"""Per-tool install state for the OSS-onboarding flow."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class OssToolState(str, enum.Enum):
    PENDING = "pending"
    INSTALLING = "installing"
    INSTALLED = "installed"
    FAILED = "failed"
    DISABLED = "disabled"     # admin opted out


class OssToolInstall(Base, UUIDMixin, TimestampMixin):
    """One row per OSS tool the admin onboarding flow knows about.

    Lifecycle:
      DISABLED (default — admin hasn't selected this tool)
        ↓ admin selects it on the onboarding screen
      PENDING (selection persisted, installer not yet started)
        ↓ installer kicks off
      INSTALLING (docker compose --profile up -d in progress)
        ↓ docker compose returns
      INSTALLED (compose succeeded, ARGUS_*_URL written to .env)
        OR
      FAILED (docker compose stderr captured in error_message)

    The dashboard polls this table to render the install-progress UI.
    """

    __tablename__ = "oss_tool_installs"

    tool_name: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False,
    )
    state: Mapped[str] = mapped_column(
        Enum(
            OssToolState,
            name="oss_tool_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=OssToolState.DISABLED.value,
        nullable=False,
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
    )
    installed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    # Captured stdout / stderr from the docker compose run for the
    # admin-facing log panel.
    log_tail: Mapped[str | None] = mapped_column(Text)
    extras: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_oss_tool_installs_state", "state"),
    )
