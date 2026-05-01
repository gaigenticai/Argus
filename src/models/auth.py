"""Authentication, audit logging, and user models."""

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
    Boolean,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID, ARRAY, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum(UserRole, name="user_role", values_callable=lambda x: [m.value for m in x]),
        default=UserRole.VIEWER.value,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(String(45))

    # Audit D10 — TOTP-based 2FA. The secret is stored as base32; the
    # recovery codes are stored as a JSON array of argon2-hashed strings
    # so a leak doesn't expose them in cleartext.
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    mfa_enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovery_codes_hashed: Mapped[list[str] | None] = mapped_column(JSONB)

    # API keys for external integrations
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    feedback = relationship("TriageFeedback", back_populates="analyst")

    __table_args__ = (
        Index("ix_users_email", "email"),
        Index("ix_users_username", "username"),
    )


class APIKey(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # first 8 chars for identification
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user = relationship("User", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_hash", "key_hash"),
        Index("ix_api_keys_user", "user_id"),
    )


class AuditAction(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    ORG_CREATE = "org_create"
    ORG_UPDATE = "org_update"
    ORG_DELETE = "org_delete"
    ALERT_UPDATE = "alert_update"
    ALERT_CLASSIFY = "alert_classify"
    CRAWLER_TRIGGER = "crawler_trigger"
    CRAWLER_SOURCE_CREATE = "crawler_source_create"
    CRAWLER_SOURCE_UPDATE = "crawler_source_update"
    CRAWLER_SOURCE_DELETE = "crawler_source_delete"
    REPORT_GENERATE = "report_generate"
    REPORT_DOWNLOAD = "report_download"
    API_KEY_CREATE = "api_key_create"
    API_KEY_REVOKE = "api_key_revoke"
    RETENTION_CLEANUP = "retention_cleanup"
    DATA_EXPORT = "data_export"
    SETTINGS_UPDATE = "settings_update"
    WEBHOOK_DELIVER = "webhook_deliver"
    ASSET_CREATE = "asset_create"
    ASSET_UPDATE = "asset_update"
    ASSET_DELETE = "asset_delete"
    ASSET_BULK_IMPORT = "asset_bulk_import"
    ASSET_DISCOVER = "asset_discover"
    ONBOARDING_START = "onboarding_start"
    ONBOARDING_UPDATE = "onboarding_update"
    ONBOARDING_COMPLETE = "onboarding_complete"
    ONBOARDING_ABANDON = "onboarding_abandon"
    DISCOVERY_JOB_ENQUEUE = "discovery_job_enqueue"
    DISCOVERY_JOB_CANCEL = "discovery_job_cancel"
    EVIDENCE_UPLOAD = "evidence_upload"
    EVIDENCE_DOWNLOAD = "evidence_download"
    EVIDENCE_DELETE = "evidence_delete"
    EVIDENCE_RESTORE = "evidence_restore"
    EVIDENCE_PURGE = "evidence_purge"
    CASE_CREATE = "case_create"
    CASE_UPDATE = "case_update"
    CASE_DELETE = "case_delete"
    CASE_TRANSITION = "case_transition"
    CASE_FINDING_LINK = "case_finding_link"
    CASE_FINDING_UNLINK = "case_finding_unlink"
    CASE_COMMENT_ADD = "case_comment_add"
    CASE_COMMENT_EDIT = "case_comment_edit"
    CASE_COMMENT_DELETE = "case_comment_delete"
    MITRE_SYNC = "mitre_sync"
    MITRE_TECHNIQUE_ATTACH = "mitre_technique_attach"
    MITRE_TECHNIQUE_DETACH = "mitre_technique_detach"
    EASM_JOB_RUN = "easm_job_run"
    EASM_JOB_FAIL = "easm_job_fail"
    EASM_FINDING_PROMOTE = "easm_finding_promote"
    EASM_FINDING_DISMISS = "easm_finding_dismiss"
    EXPOSURE_DETECTED = "exposure_detected"
    EXPOSURE_STATE_CHANGE = "exposure_state_change"
    RATING_RECOMPUTE = "rating_recompute"
    DMARC_REPORT_INGEST = "dmarc_report_ingest"
    DMARC_WIZARD_GENERATE = "dmarc_wizard_generate"
    BRAND_TERM_CREATE = "brand_term_create"
    BRAND_TERM_DELETE = "brand_term_delete"
    SUSPECT_DOMAIN_DETECT = "suspect_domain_detect"
    SUSPECT_DOMAIN_STATE_CHANGE = "suspect_domain_state_change"
    LIVE_PROBE_RUN = "live_probe_run"
    BRAND_LOGO_REGISTER = "brand_logo_register"
    BRAND_LOGO_DELETE = "brand_logo_delete"
    LOGO_MATCH_DETECTED = "logo_match_detected"
    VIP_PROFILE_REGISTER = "vip_profile_register"
    SOCIAL_ACCOUNT_REGISTER = "social_account_register"
    IMPERSONATION_DETECT = "impersonation_detect"
    IMPERSONATION_STATE_CHANGE = "impersonation_state_change"
    MOBILE_APP_DETECT = "mobile_app_detect"
    MOBILE_APP_STATE_CHANGE = "mobile_app_state_change"
    FRAUD_FINDING_DETECT = "fraud_finding_detect"
    FRAUD_FINDING_STATE_CHANGE = "fraud_finding_state_change"
    CARD_LEAK_DETECT = "card_leak_detect"
    CARD_LEAK_STATE_CHANGE = "card_leak_state_change"
    CARD_BIN_IMPORT = "card_bin_import"
    DLP_POLICY_CREATE = "dlp_policy_create"
    DLP_POLICY_DELETE = "dlp_policy_delete"
    DLP_FINDING_DETECT = "dlp_finding_detect"
    DLP_FINDING_STATE_CHANGE = "dlp_finding_state_change"
    ACTOR_PLAYBOOK_CREATE = "actor_playbook_create"
    ACTOR_PLAYBOOK_UPDATE = "actor_playbook_update"
    HARDENING_GENERATE = "hardening_generate"
    HARDENING_STATE_CHANGE = "hardening_state_change"
    INTEL_SYNC = "intel_sync"
    VENDOR_SCORECARD_RECOMPUTE = "vendor_scorecard_recompute"
    QUESTIONNAIRE_TEMPLATE_CREATE = "questionnaire_template_create"
    QUESTIONNAIRE_INSTANCE_CREATE = "questionnaire_instance_create"
    QUESTIONNAIRE_INSTANCE_TRANSITION = "questionnaire_instance_transition"
    QUESTIONNAIRE_ANSWER_SUBMIT = "questionnaire_answer_submit"
    VENDOR_ONBOARDING_TRANSITION = "vendor_onboarding_transition"
    NEWS_FEED_REGISTER = "news_feed_register"
    NEWS_FEED_FETCH = "news_feed_fetch"
    ARTICLE_RELEVANCE_RECOMPUTE = "article_relevance_recompute"
    ADVISORY_CREATE = "advisory_create"
    ADVISORY_UPDATE = "advisory_update"
    ADVISORY_PUBLISH = "advisory_publish"
    ADVISORY_REVOKE = "advisory_revoke"
    SLA_POLICY_UPSERT = "sla_policy_upsert"
    SLA_BREACH_RECORDED = "sla_breach_recorded"
    TICKET_BINDING_CREATE = "ticket_binding_create"
    TICKET_BINDING_SYNC = "ticket_binding_sync"
    TAKEDOWN_SUBMIT = "takedown_submit"
    TAKEDOWN_STATE_CHANGE = "takedown_state_change"
    PUBLIC_API_RATE_LIMIT_EXCEEDED = "public_api_rate_limit_exceeded"


class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(__import__("datetime").timezone.utc),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(
        Enum(AuditAction, name="audit_action", values_callable=lambda x: [m.value for m in x]),
        nullable=False,
    )
    resource_type: Mapped[str | None] = mapped_column(String(100))  # "alert", "org", "user", etc.
    resource_id: Mapped[str | None] = mapped_column(String(100))
    details: Mapped[dict | None] = mapped_column(JSONB)
    # Dedicated before/after columns so compliance auditors can run
    # indexed "every change to row X" queries without parsing the
    # ``details`` JSON. Mutators may populate either, both, or neither.
    before_state: Mapped[dict | None] = mapped_column(JSONB)
    after_state: Mapped[dict | None] = mapped_column(JSONB)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))

    # Audit G4 — legal hold blocks retention purging on this row.
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_timestamp", "timestamp"),
        Index("ix_audit_logs_user", "user_id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )
