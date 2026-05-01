"""Detector-side wrapper around :mod:`src.core.app_settings`.

Detectors call ``await load_detector_settings(db, org_id, "twitter")``
once at the top of their tick and get a typed-and-validated bundle
back. The bundle exposes the well-known knobs each detector pays
attention to — fraud threshold, impersonation cutoff, auto-case
severity floor, and so on — with the in-code defaults baked in.

Why a bundle helper instead of one ``get_setting`` call per knob:

* one DB roundtrip per tick instead of N
* one place to document the knob keys and their defaults
* the bundle's ``__init__`` validates ranges so a
  bad ``AppSetting`` row (e.g. ``fraud.threshold = 1.5``) fails fast
  with a clear error instead of producing weird detector behaviour
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import app_settings as _app_settings
from src.models.admin import AppSetting, AppSettingCategory, AppSettingType


# --- bundle dataclasses -----------------------------------------------


@dataclass
class SocialThresholds:
    """Per-platform fraud + impersonation tuning.

    ``fraud_threshold`` is on the [0, 1] confidence scale produced by
    ``score_fraud_signals``; ``impersonation_threshold`` is on the
    [0, 100] scale produced by ``score_candidate``. ``auto_case_high``
    is the score above which the auto-case severity is HIGH instead
    of MEDIUM.
    """

    fraud_threshold: float = 0.4
    impersonation_threshold: int = 75
    auto_case_high: float = 0.7
    impersonation_auto_case_high: int = 90

    def validate(self) -> None:
        if not 0.0 <= self.fraud_threshold <= 1.0:
            raise ValueError(
                f"fraud_threshold must be in [0,1], got {self.fraud_threshold}"
            )
        if not 0 <= self.impersonation_threshold <= 100:
            raise ValueError(
                f"impersonation_threshold must be in [0,100], "
                f"got {self.impersonation_threshold}"
            )
        if not 0.0 <= self.auto_case_high <= 1.0:
            raise ValueError(
                f"auto_case_high must be in [0,1], got {self.auto_case_high}"
            )
        if not 0 <= self.impersonation_auto_case_high <= 100:
            raise ValueError(
                f"impersonation_auto_case_high must be in [0,100], "
                f"got {self.impersonation_auto_case_high}"
            )


@dataclass
class ImpersonationWeights:
    """Weights for the four impersonation similarity signals.

    Sum is normalised at use-time, so the dashboard can tweak any
    weight without having to recompute the others.
    """

    name: float = 0.45
    handle: float = 0.20
    bio: float = 0.15
    photo: float = 0.20
    confirmed_threshold: float = 0.85
    review_threshold: float = 0.60

    def validate(self) -> None:
        for k, v in (
            ("name", self.name),
            ("handle", self.handle),
            ("bio", self.bio),
            ("photo", self.photo),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{k} weight must be in [0,1], got {v}")
        if not 0.0 <= self.confirmed_threshold <= 1.0:
            raise ValueError("confirmed_threshold must be in [0,1]")
        if not 0.0 <= self.review_threshold <= 1.0:
            raise ValueError("review_threshold must be in [0,1]")


@dataclass
class BrandThresholds:
    """Brand monitoring tuning."""

    domain_match_min_similarity: float = 0.7
    suspect_high_severity_similarity: float = 0.8
    classifier_suspicious_base_confidence: float = 0.55
    classifier_suspicious_per_signal: float = 0.05
    classifier_parked_confidence: float = 0.7
    classifier_benign_confidence: float = 0.6


@dataclass
class AutoCasePolicy:
    """Severity floor at which a finding auto-creates a Case."""

    severities: tuple[str, ...] = ("critical", "high")
    aggregation_window_hours: int = 24


@dataclass
class RatingRubric:
    """Operator-tunable Security Rating rubric.

    The shape mirrors what was previously hardcoded as module-level
    constants in ``src/ratings/engine.py``. Weights are stored as a
    single JSON blob so the dashboard can edit them as one row; the
    loader normalises the dict to ensure all six pillars are present
    and the values sum to 1.0 ± 1e-6.
    """

    pillar_weights: dict[str, float] = field(
        default_factory=lambda: {
            "exposures": 0.35,
            "attack_surface": 0.20,
            "email_auth": 0.15,
            "asset_governance": 0.15,
            "breach_exposure": 0.10,
            "dark_web": 0.05,
        }
    )
    exposure_penalty: dict[str, float] = field(
        default_factory=lambda: {
            "critical": 25.0,
            "high": 12.0,
            "medium": 4.0,
            "low": 1.0,
            "info": 0.25,
        }
    )
    age_decay_days: int = 30
    age_decay_min_factor: float = 0.4

    def validate(self) -> None:
        required = {
            "exposures", "attack_surface", "email_auth",
            "asset_governance", "breach_exposure", "dark_web",
        }
        missing = required - set(self.pillar_weights)
        if missing:
            raise ValueError(f"rating.pillar_weights missing keys: {sorted(missing)}")
        weight_sum = sum(self.pillar_weights[k] for k in required)
        if abs(weight_sum - 1.0) > 1e-6:
            raise ValueError(
                f"rating.pillar_weights must sum to 1.0, got {weight_sum:.6f}"
            )
        if self.age_decay_days <= 0:
            raise ValueError("rating.age_decay_days must be > 0")
        if not 0.0 <= self.age_decay_min_factor <= 1.0:
            raise ValueError("rating.age_decay_min_factor must be in [0,1]")
        for k in ("critical", "high", "medium", "low", "info"):
            if k not in self.exposure_penalty:
                raise ValueError(f"rating.exposure_penalty missing key {k!r}")
            if self.exposure_penalty[k] < 0:
                raise ValueError(f"rating.exposure_penalty[{k!r}] must be >= 0")


@dataclass
class TprmRubric:
    """Operator-tunable TPRM (vendor scorecard) rubric."""

    pillar_weights: dict[str, float] = field(
        default_factory=lambda: {
            "questionnaire": 0.40,
            "security": 0.35,
            "operational": 0.15,
            "breach": 0.10,
        }
    )
    breach_window_days: int = 90
    breach_card_penalty: float = 18.0
    breach_dlp_penalty: dict[str, float] = field(
        default_factory=lambda: {
            "critical": 22.0,
            "high": 12.0,
            "medium": 4.0,
            "low": 1.0,
            "info": 0.25,
        }
    )

    def validate(self) -> None:
        required = {"questionnaire", "security", "operational", "breach"}
        missing = required - set(self.pillar_weights)
        if missing:
            raise ValueError(f"tprm.pillar_weights missing keys: {sorted(missing)}")
        if abs(sum(self.pillar_weights[k] for k in required) - 1.0) > 1e-6:
            raise ValueError("tprm.pillar_weights must sum to 1.0")
        if self.breach_window_days <= 0:
            raise ValueError("tprm.breach_window_days must be > 0")
        if self.breach_card_penalty < 0:
            raise ValueError("tprm.breach_card_penalty must be >= 0")


# --- loader -----------------------------------------------------------


_KNOB_DEFINITIONS: dict[str, list[tuple[str, AppSettingType, AppSettingCategory, str]]] = {
    "twitter": [
        ("social.twitter.fraud_threshold", AppSettingType.FLOAT, AppSettingCategory.FRAUD,
         "Twitter — fraud-signal score above which a finding is recorded (0.0–1.0)"),
        ("social.twitter.impersonation_threshold", AppSettingType.INTEGER, AppSettingCategory.IMPERSONATION,
         "Twitter — impersonation score above which a finding is recorded (0–100)"),
        ("social.twitter.auto_case_high", AppSettingType.FLOAT, AppSettingCategory.AUTO_CASE,
         "Twitter — fraud score above which auto-case severity is HIGH"),
        ("social.twitter.impersonation_auto_case_high", AppSettingType.INTEGER, AppSettingCategory.AUTO_CASE,
         "Twitter — impersonation score above which auto-case severity is HIGH"),
    ],
    "instagram": [
        ("social.instagram.fraud_threshold", AppSettingType.FLOAT, AppSettingCategory.FRAUD, ""),
        ("social.instagram.impersonation_threshold", AppSettingType.INTEGER, AppSettingCategory.IMPERSONATION, ""),
        ("social.instagram.auto_case_high", AppSettingType.FLOAT, AppSettingCategory.AUTO_CASE, ""),
        ("social.instagram.impersonation_auto_case_high", AppSettingType.INTEGER, AppSettingCategory.AUTO_CASE, ""),
    ],
    "tiktok": [
        ("social.tiktok.fraud_threshold", AppSettingType.FLOAT, AppSettingCategory.FRAUD, ""),
        ("social.tiktok.impersonation_threshold", AppSettingType.INTEGER, AppSettingCategory.IMPERSONATION, ""),
        ("social.tiktok.auto_case_high", AppSettingType.FLOAT, AppSettingCategory.AUTO_CASE, ""),
        ("social.tiktok.impersonation_auto_case_high", AppSettingType.INTEGER, AppSettingCategory.AUTO_CASE, ""),
    ],
    "telegram": [
        ("social.telegram.fraud_threshold", AppSettingType.FLOAT, AppSettingCategory.FRAUD, ""),
        ("social.telegram.impersonation_threshold", AppSettingType.INTEGER, AppSettingCategory.IMPERSONATION, ""),
        ("social.telegram.auto_case_high", AppSettingType.FLOAT, AppSettingCategory.AUTO_CASE, ""),
        ("social.telegram.impersonation_auto_case_high", AppSettingType.INTEGER, AppSettingCategory.AUTO_CASE, ""),
    ],
    "linkedin": [
        ("social.linkedin.fraud_threshold", AppSettingType.FLOAT, AppSettingCategory.FRAUD, ""),
        ("social.linkedin.impersonation_threshold", AppSettingType.INTEGER, AppSettingCategory.IMPERSONATION, ""),
        ("social.linkedin.auto_case_high", AppSettingType.FLOAT, AppSettingCategory.AUTO_CASE, ""),
        ("social.linkedin.impersonation_auto_case_high", AppSettingType.INTEGER, AppSettingCategory.AUTO_CASE, ""),
    ],
}


_SOCIAL_DEFAULTS = SocialThresholds()


async def load_social_thresholds(
    db: AsyncSession, organization_id: uuid.UUID, platform: str
) -> SocialThresholds:
    """Load per-platform social-monitor thresholds.

    On first read, missing rows are auto-created with the in-code
    defaults so the dashboard immediately reflects the live value.
    """
    if platform not in _KNOB_DEFINITIONS:
        raise ValueError(f"Unknown social platform: {platform!r}")

    knobs = _KNOB_DEFINITIONS[platform]
    fraud = await _app_settings.get_setting(
        db, organization_id, knobs[0][0],
        default=_SOCIAL_DEFAULTS.fraud_threshold,
        value_type=knobs[0][1].value, category=knobs[0][2].value,
        description=knobs[0][3] or None,
    )
    imp = await _app_settings.get_setting(
        db, organization_id, knobs[1][0],
        default=_SOCIAL_DEFAULTS.impersonation_threshold,
        value_type=knobs[1][1].value, category=knobs[1][2].value,
        description=knobs[1][3] or None,
    )
    auto_high = await _app_settings.get_setting(
        db, organization_id, knobs[2][0],
        default=_SOCIAL_DEFAULTS.auto_case_high,
        value_type=knobs[2][1].value, category=knobs[2][2].value,
        description=knobs[2][3] or None,
    )
    imp_auto_high = await _app_settings.get_setting(
        db, organization_id, knobs[3][0],
        default=_SOCIAL_DEFAULTS.impersonation_auto_case_high,
        value_type=knobs[3][1].value, category=knobs[3][2].value,
        description=knobs[3][3] or None,
    )
    bundle = SocialThresholds(
        fraud_threshold=float(fraud),
        impersonation_threshold=int(imp),
        auto_case_high=float(auto_high),
        impersonation_auto_case_high=int(imp_auto_high),
    )
    bundle.validate()
    return bundle


async def load_impersonation_weights(
    db: AsyncSession, organization_id: uuid.UUID
) -> ImpersonationWeights:
    """Shared across every social monitor (the same scoring function
    is reused). One bundle of six values.
    """
    defaults = ImpersonationWeights()
    keys = (
        ("impersonation.weight.name", "name", AppSettingCategory.IMPERSONATION),
        ("impersonation.weight.handle", "handle", AppSettingCategory.IMPERSONATION),
        ("impersonation.weight.bio", "bio", AppSettingCategory.IMPERSONATION),
        ("impersonation.weight.photo", "photo", AppSettingCategory.IMPERSONATION),
        ("impersonation.confirmed_threshold", "confirmed_threshold", AppSettingCategory.IMPERSONATION),
        ("impersonation.review_threshold", "review_threshold", AppSettingCategory.IMPERSONATION),
    )
    out: dict[str, float] = {}
    for key, attr, category in keys:
        v = await _app_settings.get_setting(
            db, organization_id, key,
            default=getattr(defaults, attr),
            value_type=AppSettingType.FLOAT.value,
            category=category.value,
            description=f"Impersonation scoring — {attr.replace('_', ' ')}",
        )
        out[attr] = float(v)
    bundle = ImpersonationWeights(**out)
    bundle.validate()
    return bundle


async def load_brand_thresholds(
    db: AsyncSession, organization_id: uuid.UUID
) -> BrandThresholds:
    defaults = BrandThresholds()
    keys = (
        ("brand.domain_match_min_similarity", "domain_match_min_similarity", AppSettingCategory.BRAND),
        ("brand.suspect_high_severity_similarity", "suspect_high_severity_similarity", AppSettingCategory.BRAND),
        ("brand.classifier.suspicious_base_confidence", "classifier_suspicious_base_confidence", AppSettingCategory.BRAND),
        ("brand.classifier.suspicious_per_signal", "classifier_suspicious_per_signal", AppSettingCategory.BRAND),
        ("brand.classifier.parked_confidence", "classifier_parked_confidence", AppSettingCategory.BRAND),
        ("brand.classifier.benign_confidence", "classifier_benign_confidence", AppSettingCategory.BRAND),
    )
    out: dict[str, float] = {}
    for key, attr, category in keys:
        v = await _app_settings.get_setting(
            db, organization_id, key,
            default=getattr(defaults, attr),
            value_type=AppSettingType.FLOAT.value,
            category=category.value,
            description=f"Brand scoring — {attr.replace('_', ' ')}",
        )
        out[attr] = float(v)
    return BrandThresholds(**out)


async def load_auto_case_policy(
    db: AsyncSession, organization_id: uuid.UUID
) -> AutoCasePolicy:
    defaults = AutoCasePolicy()
    severities_raw = await _app_settings.get_setting(
        db, organization_id, "auto_case.severities",
        default=list(defaults.severities),
        value_type=AppSettingType.JSON.value,
        category=AppSettingCategory.AUTO_CASE.value,
        description="Severities at or above which a finding auto-opens a Case.",
    )
    aggregation = await _app_settings.get_setting(
        db, organization_id, "auto_case.aggregation_window_hours",
        default=defaults.aggregation_window_hours,
        value_type=AppSettingType.INTEGER.value,
        category=AppSettingCategory.AUTO_CASE.value,
        description="HIGH findings within this window aggregate into one Case.",
    )
    sevs = tuple(str(s).lower() for s in (severities_raw or []))
    return AutoCasePolicy(
        severities=sevs or defaults.severities,
        aggregation_window_hours=int(aggregation),
    )


async def load_rating_rubric(
    db: AsyncSession, organization_id: uuid.UUID
) -> RatingRubric:
    defaults = RatingRubric()
    weights = await _app_settings.get_setting(
        db, organization_id, "rating.pillar_weights",
        default=defaults.pillar_weights,
        value_type=AppSettingType.JSON.value,
        category=AppSettingCategory.RATING.value,
        description="Security rating pillar weights (must sum to 1.0)",
    )
    penalty = await _app_settings.get_setting(
        db, organization_id, "rating.exposure_penalty",
        default=defaults.exposure_penalty,
        value_type=AppSettingType.JSON.value,
        category=AppSettingCategory.RATING.value,
        description="Per-severity penalty subtracted from the exposures pillar",
    )
    decay_days = await _app_settings.get_setting(
        db, organization_id, "rating.age_decay_days",
        default=defaults.age_decay_days,
        value_type=AppSettingType.INTEGER.value,
        category=AppSettingCategory.RATING.value,
        description="Exposures older than N days hit full penalty",
    )
    decay_min = await _app_settings.get_setting(
        db, organization_id, "rating.age_decay_min_factor",
        default=defaults.age_decay_min_factor,
        value_type=AppSettingType.FLOAT.value,
        category=AppSettingCategory.RATING.value,
        description="Brand-new exposures still cost at least this fraction",
    )
    bundle = RatingRubric(
        pillar_weights={k: float(v) for k, v in (weights or {}).items()},
        exposure_penalty={k: float(v) for k, v in (penalty or {}).items()},
        age_decay_days=int(decay_days),
        age_decay_min_factor=float(decay_min),
    )
    bundle.validate()
    return bundle


async def load_tprm_rubric(
    db: AsyncSession, organization_id: uuid.UUID
) -> TprmRubric:
    defaults = TprmRubric()
    weights = await _app_settings.get_setting(
        db, organization_id, "tprm.pillar_weights",
        default=defaults.pillar_weights,
        value_type=AppSettingType.JSON.value,
        category=AppSettingCategory.RATING.value,
        description="TPRM vendor-scorecard pillar weights (sum to 1.0)",
    )
    window = await _app_settings.get_setting(
        db, organization_id, "tprm.breach_window_days",
        default=defaults.breach_window_days,
        value_type=AppSettingType.INTEGER.value,
        category=AppSettingCategory.RATING.value,
        description="Window over which open breach signals impact the breach pillar",
    )
    card_penalty = await _app_settings.get_setting(
        db, organization_id, "tprm.breach_card_penalty",
        default=defaults.breach_card_penalty,
        value_type=AppSettingType.FLOAT.value,
        category=AppSettingCategory.RATING.value,
        description="Penalty per open card-leakage finding tied to vendor",
    )
    dlp_penalty = await _app_settings.get_setting(
        db, organization_id, "tprm.breach_dlp_penalty",
        default=defaults.breach_dlp_penalty,
        value_type=AppSettingType.JSON.value,
        category=AppSettingCategory.RATING.value,
        description="Per-severity penalty per open DLP finding tied to vendor",
    )
    bundle = TprmRubric(
        pillar_weights={k: float(v) for k, v in (weights or {}).items()},
        breach_window_days=int(window),
        breach_card_penalty=float(card_penalty),
        breach_dlp_penalty={k: float(v) for k, v in (dlp_penalty or {}).items()},
    )
    bundle.validate()
    return bundle


__all__ = [
    "SocialThresholds",
    "ImpersonationWeights",
    "BrandThresholds",
    "AutoCasePolicy",
    "RatingRubric",
    "TprmRubric",
    "load_social_thresholds",
    "load_impersonation_weights",
    "load_brand_thresholds",
    "load_auto_case_policy",
    "load_rating_rubric",
    "load_tprm_rubric",
]
