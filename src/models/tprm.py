"""Phase 7 — Third-Party Risk Management models.

VendorScorecard
    Aggregated risk view for a vendor (asset of type 'vendor').
    Combines security_rating + questionnaire_score + breach signals
    into a single grade for the procurement team.

QuestionnaireTemplate
    A reusable questionnaire definition (SIG Lite, CAIQ v4, custom).
    Questions stored as JSONB list with id, text, answer_kind,
    weight, required.

QuestionnaireInstance
    A single sent-to-vendor questionnaire run.

QuestionnaireResponse
    The vendor's answers + analyst review verdict.

VendorOnboardingWorkflow
    State machine for the vendor lifecycle:
        invited → questionnaire_sent → questionnaire_received →
        analyst_review → approved / rejected
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    Float,
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


class VendorGrade(str, enum.Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class QuestionnaireKind(str, enum.Enum):
    SIG_LITE = "sig_lite"
    SIG_CORE = "sig_core"
    CAIQ_V4 = "caiq_v4"
    CUSTOM = "custom"


class AnswerKind(str, enum.Enum):
    YES_NO = "yes_no"
    YES_NO_NA = "yes_no_na"
    SCALE_1_5 = "scale_1_5"
    FREE_TEXT = "free_text"
    EVIDENCE = "evidence"  # expects evidence file/URL


class QuestionnaireState(str, enum.Enum):
    DRAFT = "draft"
    SENT = "sent"
    RECEIVED = "received"
    REVIEWED = "reviewed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class VendorOnboardingStage(str, enum.Enum):
    INVITED = "invited"
    QUESTIONNAIRE_SENT = "questionnaire_sent"
    QUESTIONNAIRE_RECEIVED = "questionnaire_received"
    ANALYST_REVIEW = "analyst_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ON_HOLD = "on_hold"


class VendorScorecard(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_scorecards"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(
        Enum(
            VendorGrade,
            name="vendor_grade",
            values_callable=lambda x: [m.value for m in x],
        ),
        nullable=False,
    )
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pillar_scores: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index(
            "ix_vendor_scorecard_vendor_current",
            "vendor_asset_id",
            "is_current",
        ),
        CheckConstraint(
            "score >= 0 AND score <= 100",
            name="ck_vendor_scorecard_score_range",
        ),
    )


class QuestionnaireTemplate(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "questionnaire_templates"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(
        Enum(
            QuestionnaireKind,
            name="questionnaire_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=QuestionnaireKind.CUSTOM.value,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(Text)
    questions: Mapped[list] = mapped_column(JSONB, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_questionnaire_template_org_name"
        ),
    )


class QuestionnaireInstance(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "questionnaire_instances"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("questionnaire_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        Enum(
            QuestionnaireState,
            name="questionnaire_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=QuestionnaireState.DRAFT.value,
        nullable=False,
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    score: Mapped[float | None] = mapped_column(Float)
    notes: Mapped[str | None] = mapped_column(Text)

    # Immutable template snapshot for compliance reproducibility — once a
    # questionnaire is sent, the template version + hash + frozen JSON
    # snapshot of every question are pinned. Re-running the template
    # editor never mutates a sent instance.
    template_version: Mapped[int | None] = mapped_column(Integer)
    template_hash: Mapped[str | None] = mapped_column(String(64))
    template_snapshot: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        Index(
            "ix_q_instance_org_state",
            "organization_id",
            "state",
        ),
        Index("ix_q_instance_vendor", "vendor_asset_id"),
        CheckConstraint(
            "score IS NULL OR (score >= 0 AND score <= 100)",
            name="ck_questionnaire_score_range",
        ),
    )


class QuestionnaireAnswer(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "questionnaire_answers"

    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("questionnaire_instances.id", ondelete="CASCADE"),
        nullable=False,
    )
    question_id: Mapped[str] = mapped_column(String(80), nullable=False)
    answer_value: Mapped[str | None] = mapped_column(Text)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    answer_score: Mapped[float | None] = mapped_column(Float)
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint(
            "instance_id", "question_id",
            name="uq_questionnaire_answer_instance_question",
        ),
    )


class VendorOnboardingWorkflow(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_onboarding_workflows"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage: Mapped[str] = mapped_column(
        Enum(
            VendorOnboardingStage,
            name="vendor_onboarding_stage",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=VendorOnboardingStage.INVITED.value,
        nullable=False,
    )
    questionnaire_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("questionnaire_instances.id", ondelete="SET NULL"),
    )
    notes: Mapped[str | None] = mapped_column(Text)
    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    decision_reason: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "vendor_asset_id",
            name="uq_vendor_onboarding_org_vendor",
        ),
        Index("ix_vendor_onboarding_stage", "organization_id", "stage"),
    )


_ALLOWED_STAGE_TRANSITIONS: dict[str, set[str]] = {
    "invited": {"questionnaire_sent", "rejected", "on_hold"},
    "questionnaire_sent": {"questionnaire_received", "on_hold", "rejected"},
    "questionnaire_received": {"analyst_review"},
    "analyst_review": {"approved", "rejected", "on_hold"},
    "on_hold": {"invited", "questionnaire_sent", "analyst_review", "rejected"},
    "approved": {"on_hold"},
    "rejected": {"invited"},
}


def is_stage_transition_allowed(from_stage: str, to_stage: str) -> bool:
    return to_stage in _ALLOWED_STAGE_TRANSITIONS.get(from_stage, set())


# ---------------------------------------------------------------------
# Phase 2 — TPRM full-audit additions: evidence vault, contract vault,
# sanctions checks, posture signals, scorecard history.
# ---------------------------------------------------------------------


class VendorTier(str, enum.Enum):
    TIER_1 = "tier_1"  # critical / annual review
    TIER_2 = "tier_2"  # important / biennial
    TIER_3 = "tier_3"  # standard / on-demand


class VendorCategory(str, enum.Enum):
    PAYMENT_PROCESSOR = "payment_processor"
    CLOUD_PROVIDER = "cloud_provider"
    SECURITY_VENDOR = "security_vendor"
    HR_PAYROLL = "hr_payroll"
    TELECOM = "telecom"
    LEGAL = "legal"
    AUDITOR = "auditor"
    MARKETING_SAAS = "marketing_saas"
    DATA_BROKER = "data_broker"
    OTHER = "other"


class VendorEvidenceFile(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_evidence_files"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    questionnaire_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("questionnaire_instances.id", ondelete="SET NULL"),
    )
    question_id: Mapped[str | None] = mapped_column(String(80))
    file_name: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(120))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    extracted: Mapped[dict | None] = mapped_column(JSONB)


class VendorContract(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_contracts"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    contract_kind: Mapped[str | None] = mapped_column(String(64))  # msa | dpa | nda | sla
    file_name: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    effective_date: Mapped[datetime | None] = mapped_column(Date)
    expiration_date: Mapped[datetime | None] = mapped_column(Date)
    extracted_clauses: Mapped[dict | None] = mapped_column(JSONB)
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class VendorSanctionsCheck(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_sanctions_checks"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # ofac | ofsi | eu_consolidated | un
    matched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    match_score: Mapped[float | None] = mapped_column(Float)
    match_payload: Mapped[dict | None] = mapped_column(JSONB)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class VendorPostureSignal(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_posture_signals"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    # kind = dmarc | spf | dkim | hibp | github_leak | nuclei | typosquat | sanctions | breach
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSONB)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "vendor_asset_id", "kind", name="uq_vendor_posture_kind"
        ),
    )


class VendorScorecardSnapshot(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vendor_scorecard_snapshots"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(4), nullable=False)
    pillar_scores: Mapped[dict] = mapped_column(JSONB, nullable=False)
    snapshot_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


__all__ = [
    "VendorGrade",
    "VendorTier",
    "VendorCategory",
    "QuestionnaireKind",
    "AnswerKind",
    "QuestionnaireState",
    "VendorOnboardingStage",
    "VendorScorecard",
    "VendorScorecardSnapshot",
    "QuestionnaireTemplate",
    "QuestionnaireInstance",
    "QuestionnaireAnswer",
    "VendorOnboardingWorkflow",
    "VendorEvidenceFile",
    "VendorContract",
    "VendorSanctionsCheck",
    "VendorPostureSignal",
    "is_stage_transition_allowed",
]
