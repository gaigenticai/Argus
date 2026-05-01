"""EASM (External Attack Surface Management) models.

Companion to the ``DiscoveryJob`` queue introduced in Phase 0.2 onboarding.

AssetChange
    Append-only diff log. Every time the EASM worker sees a meaningful
    change for an asset — a new subdomain, a port opening or closing, a
    cert rotation, an SPF/DMARC drift — a row lands here. Drives the
    ``/attack-surface/changes`` UI and security-rating recompute hooks
    (Phase 1.3).

DiscoveryFinding
    Lightweight record of "the worker observed X". Promoted into the
    Asset Registry as a row when the analyst (or auto-promotion rule)
    confirms it. Keeps unconfirmed observations from polluting the
    primary registry while preserving full provenance.
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
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class ChangeKind(str, enum.Enum):
    ASSET_CREATED = "asset_created"
    ASSET_REVIVED = "asset_revived"  # re-observed after being inactive
    ASSET_INACTIVE = "asset_inactive"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    SERVICE_BANNER_CHANGED = "service_banner_changed"
    HTTP_STATUS_CHANGED = "http_status_changed"
    HTTP_TITLE_CHANGED = "http_title_changed"
    HTTP_TECH_CHANGED = "http_tech_changed"
    TLS_CERT_CHANGED = "tls_cert_changed"
    TLS_EXPIRY_NEAR = "tls_expiry_near"
    DNS_A_CHANGED = "dns_a_changed"
    DNS_MX_CHANGED = "dns_mx_changed"
    DNS_NS_CHANGED = "dns_ns_changed"
    SPF_CHANGED = "spf_changed"
    DKIM_CHANGED = "dkim_changed"
    DMARC_CHANGED = "dmarc_changed"
    WHOIS_REGISTRAR_CHANGED = "whois_registrar_changed"
    WHOIS_EXPIRY_NEAR = "whois_expiry_near"


# Audit D5 — alias to the canonical Severity. The DB enum constraint
# name (`change_severity`) lives on the `sa.Enum(..., name=...)` call
# in the column declaration, not on the Python class, so the alembic
# migration stays stable.
from src.models.common import Severity as ChangeSeverity  # noqa: E402


class FindingState(str, enum.Enum):
    NEW = "new"
    PROMOTED = "promoted"  # turned into a confirmed Asset row
    DISMISSED = "dismissed"
    DUPLICATE = "duplicate"


class AssetChange(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "asset_changes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
    )
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )

    kind: Mapped[str] = mapped_column(
        Enum(
            ChangeKind,
            name="asset_change_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        Enum(
            ChangeSeverity,
            name="asset_change_severity",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=ChangeSeverity.INFO.value,
        nullable=False,
    )

    # Human-readable summary plus the raw before/after snapshots.
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_asset_changes_org_kind", "organization_id", "kind"),
        Index("ix_asset_changes_asset", "asset_id"),
        Index("ix_asset_changes_detected_at", "detected_at"),
    )


class DiscoveryFinding(Base, UUIDMixin, TimestampMixin):
    """Unconfirmed observation produced by an EASM run.

    The worker writes findings here rather than directly into ``assets``
    when the discovery method has any uncertainty (passive subdomain
    enum, CT-log scrape, port-scan banner).  Confirmed findings can be
    promoted into the Asset Registry by an analyst or by an
    auto-promote rule.
    """

    __tablename__ = "discovery_findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_jobs.id", ondelete="SET NULL"),
    )
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
    )

    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB)

    state: Mapped[str] = mapped_column(
        Enum(
            FindingState,
            name="discovery_finding_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=FindingState.NEW.value,
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(default=0.5, nullable=False)
    promoted_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
    )
    discovered_via: Mapped[str | None] = mapped_column(String(80))
    raw: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "asset_type",
            "value",
            "state",
            name="uq_discovery_finding_org_type_value_state",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_discovery_finding_confidence",
        ),
        Index("ix_discovery_findings_org_state", "organization_id", "state"),
        Index("ix_discovery_findings_parent", "parent_asset_id"),
    )


__all__ = [
    "ChangeKind",
    "ChangeSeverity",
    "FindingState",
    "AssetChange",
    "DiscoveryFinding",
]
