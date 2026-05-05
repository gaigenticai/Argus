"""Onboarding & Discovery models.

OnboardingSession — resumable 5-step wizard state. Stored server-side so
analysts can pause and resume from any browser. Each step's payload is
validated only on submission of that step (not on save), matching the
"save without losing data" UX.

DiscoveryJob — queue for Phase 1 EASM auto-discovery. The wizard's last
step can elect to enqueue discovery on confirmed root domains. Phase 1.1
(EASM continuous) consumes from this table.
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
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


class OnboardingState(str, enum.Enum):
    DRAFT = "draft"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class OnboardingSession(Base, UUIDMixin, TimestampMixin):
    """Server-side state for the 5-step onboarding wizard."""

    __tablename__ = "onboarding_sessions"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    started_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    state: Mapped[str] = mapped_column(
        Enum(
            OnboardingState,
            name="onboarding_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=OnboardingState.DRAFT.value,
        nullable=False,
    )
    current_step: Mapped[int] = mapped_column(default=1, nullable=False)
    # step_data keys: org, infra, people_brand, vendors, review
    step_data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_onboarding_state", "state"),
        Index("ix_onboarding_user", "started_by_user_id"),
    )


class DiscoveryJobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscoveryJobKind(str, enum.Enum):
    SUBDOMAIN_ENUM = "subdomain_enum"  # Subfinder + Amass + crt.sh + certspotter
    PORT_SCAN = "port_scan"  # naabu
    HTTPX_PROBE = "httpx_probe"
    CT_LOG_BACKFILL = "ct_log_backfill"
    WHOIS_REFRESH = "whois_refresh"
    DNS_REFRESH = "dns_refresh"
    # Phase 1.2 DeepScan
    VULN_SCAN = "vuln_scan"  # nuclei
    SERVICE_VERSION = "service_version"  # nmap -sV
    TLS_AUDIT = "tls_audit"  # testssl.sh
    # Phase 1.3 visual + DNS detail.
    SCREENSHOT = "screenshot"  # gowitness — visual asset catalog
    DNS_DETAIL = "dns_detail"  # dnsx — DNSSEC + bulk fast resolution


class DiscoveryJob(Base, UUIDMixin, TimestampMixin):
    """Queued auto-discovery work consumed by Phase 1.1 EASM workers.

    Created by the onboarding wizard (or any analyst trigger) and processed
    asynchronously. Results are written back into the Asset Registry as
    new assets with ``discovery_method`` set to the appropriate value.
    """

    __tablename__ = "discovery_jobs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
    )
    kind: Mapped[str] = mapped_column(
        Enum(
            DiscoveryJobKind,
            name="discovery_job_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        Enum(
            DiscoveryJobStatus,
            name="discovery_job_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=DiscoveryJobStatus.QUEUED.value,
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_summary: Mapped[dict | None] = mapped_column(JSONB)
    error_message: Mapped[str | None] = mapped_column(Text)
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    onboarding_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("onboarding_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_discovery_jobs_org_status", "organization_id", "status"),
        Index("ix_discovery_jobs_status_kind", "status", "kind"),
        Index("ix_discovery_jobs_target", "target"),
    )


__all__ = [
    "OnboardingSession",
    "OnboardingState",
    "DiscoveryJob",
    "DiscoveryJobKind",
    "DiscoveryJobStatus",
]
