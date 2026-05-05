"""Extended intelligence models — IOCs, threat actors, crawler sources, integrations."""

from __future__ import annotations


import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Boolean,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


# --- IOC (Indicators of Compromise) ---


class IOCType(str, enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    BTC_ADDRESS = "btc_address"
    XMR_ADDRESS = "xmr_address"
    CVE = "cve"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CIDR = "cidr"
    ASN = "asn"
    JA3 = "ja3"


class IOC(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "iocs"

    ioc_type: Mapped[str] = mapped_column(
        Enum(IOCType, name="ioc_type", values_callable=lambda x: [m.value for m in x]),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sighting_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    tags: Mapped[list | None] = mapped_column(ARRAY(String))
    context: Mapped[dict | None] = mapped_column(JSONB)  # geo, ASN, WHOIS, etc.
    source_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL")
    )
    source_raw_intel_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("raw_intel.id", ondelete="SET NULL")
    )
    threat_actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="SET NULL")
    )

    # Production fields
    is_allowlisted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    allowlist_reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confidence_half_life_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=365
    )
    enrichment_data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    enrichment_fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    source_feed: Mapped[str | None] = mapped_column(String(50))

    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_iocs_type", "ioc_type"),
        Index("ix_iocs_value", "value"),
        Index("ix_iocs_last_seen", "last_seen"),
        Index("ix_iocs_threat_actor", "threat_actor_id"),
        Index("ix_iocs_allowlist", "is_allowlisted"),
        Index("ix_iocs_expires", "expires_at"),
        Index("ix_iocs_source_feed", "source_feed"),
    )


class IocSighting(Base, UUIDMixin):
    """Per-occurrence audit log for an IOC.

    Created whenever an IOC is observed in a new context (article, alert,
    feed pull, manual entry). Powers the "where was this seen?" view in
    the /iocs detail drawer.
    """

    __tablename__ = "ioc_sightings"

    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(60), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_url: Mapped[str | None] = mapped_column(String(2000))
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    context: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("ioc_id", "source", "source_id", "seen_at", name="uq_ioc_sighting"),
        Index("ix_ioc_sightings_ioc", "ioc_id", "seen_at"),
    )


class IocAudit(Base, UUIDMixin):
    """CRUD + state-change audit trail for IOCs."""

    __tablename__ = "ioc_audit"

    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_ioc_audit_ioc", "ioc_id", "created_at"),
    )


# --- Threat Actors ---


class ThreatActor(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "threat_actors"

    primary_alias: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[list] = mapped_column(ARRAY(String), default=list)
    description: Mapped[str | None] = mapped_column(Text)
    forums_active: Mapped[list] = mapped_column(ARRAY(String), default=list)
    languages: Mapped[list] = mapped_column(ARRAY(String), default=list)
    pgp_fingerprints: Mapped[list] = mapped_column(ARRAY(String), default=list)
    known_ttps: Mapped[list] = mapped_column(ARRAY(String), default=list)  # MITRE ATT&CK IDs
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    total_sightings: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    profile_data: Mapped[dict | None] = mapped_column(JSONB)  # extended metadata

    # MITRE ATT&CK Group cross-reference + enriched profile
    mitre_group_id: Mapped[str | None] = mapped_column(String(20))  # G0096
    country_codes: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    sectors_targeted: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    regions_targeted: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    malware_families: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)

    iocs = relationship("IOC", backref="threat_actor", foreign_keys=[IOC.threat_actor_id])

    __table_args__ = (
        Index("ix_threat_actors_alias", "primary_alias"),
        Index("ix_threat_actors_risk", "risk_score"),
        Index("ix_threat_actor_mitre_group_id", "mitre_group_id"),
        Index(
            "ix_threat_actor_sectors",
            "sectors_targeted",
            postgresql_using="gin",
        ),
    )


# --- Threat Actor Sightings (links actors to raw intel/alerts) ---


class ActorSighting(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "actor_sightings"

    threat_actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False
    )
    raw_intel_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("raw_intel.id", ondelete="SET NULL")
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL")
    )
    source_platform: Mapped[str] = mapped_column(String(255), nullable=False)
    alias_used: Mapped[str] = mapped_column(String(255), nullable=False)
    context: Mapped[dict | None] = mapped_column(JSONB)

    threat_actor = relationship("ThreatActor", backref="sightings")

    __table_args__ = (
        Index("ix_actor_sightings_actor", "threat_actor_id"),
        Index("ix_actor_sightings_alert", "alert_id"),
    )


# --- Crawler Sources (DB-managed, not hardcoded) ---


# --- Triage Feedback (human-in-the-loop) ---


class TriageFeedback(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "triage_feedback"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    original_category: Mapped[str] = mapped_column(String(100), nullable=False)
    original_severity: Mapped[str] = mapped_column(String(50), nullable=False)
    original_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    corrected_category: Mapped[str | None] = mapped_column(String(100))
    corrected_severity: Mapped[str | None] = mapped_column(String(50))
    is_true_positive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    feedback_notes: Mapped[str | None] = mapped_column(Text)

    analyst = relationship("User", back_populates="feedback")

    __table_args__ = (
        UniqueConstraint("alert_id", "analyst_id", name="uq_feedback_alert_analyst"),
        Index("ix_triage_feedback_alert", "alert_id"),
        Index("ix_triage_feedback_analyst", "analyst_id"),
    )


# --- Data Retention Policy ---


class RetentionPolicy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "retention_policies"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE")
    )  # NULL = global default
    raw_intel_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    alerts_days: Mapped[int] = mapped_column(Integer, default=365, nullable=False)
    audit_logs_days: Mapped[int] = mapped_column(Integer, default=730, nullable=False)  # 2 years
    iocs_days: Mapped[int] = mapped_column(Integer, default=365, nullable=False)
    redact_pii: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_cleanup_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_cleanup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Governance: compliance mappings + deletion mode (Phase governance)
    deletion_mode: Mapped[str] = mapped_column(
        String(20), default="hard_delete", nullable=False
    )  # hard_delete | soft_delete | anonymise
    compliance_mappings: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )  # ["gdpr_art_5_1_e", "ccpa_1798_105", "hipaa_164_530_j", "pci_dss_3_1", ...]
    description: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_retention_org", "organization_id"),
    )


# --- Webhook Delivery (integration tracking) ---


class WebhookDeliveryStatus(str, enum.Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


class WebhookEndpoint(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "webhook_endpoints"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    endpoint_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "slack", "siem", "generic"
    secret: Mapped[str | None] = mapped_column(String(500))  # HMAC signing secret
    headers: Mapped[dict | None] = mapped_column(JSONB)  # custom headers
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_severity: Mapped[str] = mapped_column(String(50), default="medium")  # min alert severity to deliver
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE")
    )  # NULL = all orgs
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    deliveries = relationship("WebhookDelivery", back_populates="endpoint", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_webhook_endpoints_type", "endpoint_type"),
        Index("ix_webhook_endpoints_org", "organization_id"),
    )


class WebhookDelivery(Base, UUIDMixin):
    __tablename__ = "webhook_deliveries"

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), nullable=False
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL")
    )
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(WebhookDeliveryStatus, name="webhook_delivery_status", values_callable=lambda x: [m.value for m in x]),
        default=WebhookDeliveryStatus.PENDING.value,
        nullable=False,
    )
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[str | None] = mapped_column(Text)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    endpoint = relationship("WebhookEndpoint", back_populates="deliveries")

    __table_args__ = (
        Index("ix_webhook_deliveries_endpoint", "endpoint_id"),
        Index("ix_webhook_deliveries_status", "status"),
        Index("ix_webhook_deliveries_retry", "next_retry_at"),
    )


# --- Integration Configs (external tool connections) ---


class IntegrationConfig(Base, UUIDMixin, TimestampMixin):
    """Per-tool external integration credentials.

    Adversarial audit D-8 — ``api_key`` stores Fernet ciphertext via
    src/core/crypto. Callers MUST go through ``set_api_key`` / read
    ``api_key_plain`` instead of touching the raw column. The column is
    sized at 2 KiB to accommodate ciphertext + nonce + base64 padding
    while still fitting common third-party token shapes (Wazuh, OpenCTI,
    Shuffle).
    """

    __tablename__ = "integration_configs"

    tool_name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    api_url: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    # NB. column name preserved for migration compatibility — value is now
    # always Fernet ciphertext (or empty / None).
    api_key: Mapped[str | None] = mapped_column(String(2048))
    extra_settings: Mapped[dict | None] = mapped_column(JSONB)
    health_status: Mapped[str] = mapped_column(String(20), default="unconfigured", nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)

    __table_args__ = (
        Index("ix_integration_configs_tool", "tool_name"),
    )

    # --- crypto helpers ------------------------------------------------

    def set_api_key(self, plaintext: str | None) -> None:
        """Encrypt-and-store. Pass ``None`` (or empty) to clear."""
        from src.core.crypto import encrypt

        if plaintext is None or plaintext == "":
            self.api_key = None
            return
        self.api_key = encrypt(plaintext)

    @property
    def api_key_plain(self) -> str | None:
        """Decrypt the stored token. Returns ``None`` when no key is set.

        Falls back to returning the column value as-is when decryption
        fails — this preserves operator access during the rolling upgrade
        in which existing rows still hold plaintext, while the test
        endpoint surfaces a "key needs to be re-saved" warning to ops.
        """
        if not self.api_key:
            return None
        from src.core.crypto import CryptoError, decrypt

        try:
            return decrypt(self.api_key)
        except CryptoError:
            # Pre-D8 row, or key rotation in flight. Caller may treat
            # missing-decrypt as a soft failure and surface in /test.
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "IntegrationConfig %s: api_key not decryptable — re-save the key.",
                self.tool_name,
            )
            return None


# --- Triage Run History ---


class TriageRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "triage_runs"

    trigger: Mapped[str] = mapped_column(String(20), nullable=False)  # manual, scheduled, post_feed
    hours_window: Mapped[int] = mapped_column(Integer, nullable=False)
    entries_processed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    iocs_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)  # running, completed, failed
    error_message: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_triage_runs_status", "status"),
        Index("ix_triage_runs_created", "created_at"),
    )


# --- Vulnerability Scans (Nuclei integration) ---


class VulnerabilityScan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vulnerability_scans"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL")
    )
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    scanner: Mapped[str] = mapped_column(String(50), default="nuclei", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scan_output: Mapped[dict | None] = mapped_column(JSONB)

    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_vuln_scans_org", "organization_id"),
        Index("ix_vuln_scans_status", "status"),
    )


class Vulnerability(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vulnerabilities"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vulnerability_scans.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL")
    )
    template_id: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(2048))
    matched_at: Mapped[str | None] = mapped_column(String(2048))
    remediation: Mapped[str | None] = mapped_column(Text)
    cve_ids: Mapped[list | None] = mapped_column(ARRAY(String))
    raw_output: Mapped[dict | None] = mapped_column(JSONB)

    scan = relationship("VulnerabilityScan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulns_scan", "scan_id"),
        Index("ix_vulns_severity", "severity"),
        Index("ix_vulns_org", "organization_id"),
    )
