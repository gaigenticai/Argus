"""Impersonation scoring engine.

Multi-signal aggregation (lightweight alternative to InsightFace per
``docs/HARDWARE_DECISIONS.md``):

    name_similarity      rapidfuzz token-set ratio of candidate display
                         name vs VIP full_name + aliases
    handle_similarity    rapidfuzz on candidate handle vs registered
                         official handles
    bio_similarity       Jaccard of brand keywords + VIP bio_keywords
                         intersected with candidate bio tokens
    photo_similarity     pHash hamming distance against any registered
                         photo_phashes (lower = better → mapped to 0..1)

Aggregate score = weighted sum. Verdict thresholds:
    >= 0.80   high confidence impersonation
    >= 0.60   probable impersonation (analyst review)
    <  0.60   ignored
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from rapidfuzz import fuzz

from src.models.social import VipProfile


_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


def _tokens(text: str) -> set[str]:
    if not text:
        return set()
    return {t.lower() for t in _TOKEN_RE.findall(text) if len(t) >= 3}


def _name_similarity(candidate_name: str, vip: VipProfile) -> float:
    if not candidate_name:
        return 0.0
    options = [vip.full_name] + list(vip.aliases or [])
    best = 0
    for opt in options:
        if not opt:
            continue
        score = fuzz.token_set_ratio(candidate_name, opt)
        if score > best:
            best = score
    return best / 100.0


def _handle_similarity(
    candidate_handle: str, official_handles: Iterable[str]
) -> float:
    if not candidate_handle:
        return 0.0
    best = 0
    cand = candidate_handle.lstrip("@").lower()
    for h in official_handles:
        if not h:
            continue
        score = fuzz.ratio(cand, h.lstrip("@").lower())
        if score > best:
            best = score
    return best / 100.0


def _bio_similarity(candidate_bio: str | None, vip: VipProfile) -> float:
    cand = _tokens(candidate_bio or "")
    if not cand:
        return 0.0
    target = _tokens(" ".join(vip.bio_keywords or []) + " " + (vip.title or ""))
    if not target:
        return 0.0
    overlap = cand & target
    return len(overlap) / len(target)


def _photo_similarity(
    candidate_phash: str | None, registered_phashes: Iterable[str]
) -> float | None:
    if not candidate_phash:
        return None
    try:
        import imagehash

        cand = imagehash.hex_to_hash(candidate_phash)
    except Exception:  # noqa: BLE001
        return None
    best = 64  # max distance
    for h in registered_phashes:
        if not h:
            continue
        try:
            ref = imagehash.hex_to_hash(h)
            d = cand - ref
            if d < best:
                best = d
        except Exception:  # noqa: BLE001
            continue
    if best == 64:
        return None
    # Map distance 0..16 to similarity 1..0
    if best > 16:
        return 0.0
    return 1.0 - (best / 16.0)


@dataclass
class ImpersonationScore:
    name_similarity: float
    handle_similarity: float
    bio_similarity: float
    photo_similarity: float | None
    aggregate_score: float
    signals: list[str] = field(default_factory=list)
    verdict: str = "ignore"
    rationale: str = ""


def score_candidate(
    *,
    candidate_handle: str,
    candidate_display_name: str,
    candidate_bio: str | None,
    candidate_photo_phash: str | None,
    vip: VipProfile,
    official_handles: Iterable[str],
    weights: "ImpersonationWeights | None" = None,
) -> ImpersonationScore:
    """Score a candidate against a VIP profile.

    ``weights`` defaults to the standard rubric; the caller (a social
    monitor's tick function) loads the live ``ImpersonationWeights``
    bundle from ``AppSetting`` and passes it in. Standalone callers
    (tests, ad-hoc scripts) get the in-code defaults.
    """
    from src.core.detector_config import ImpersonationWeights as _IW

    if weights is None:
        weights = _IW()

    name = _name_similarity(candidate_display_name, vip)
    handle = _handle_similarity(candidate_handle, official_handles)
    bio = _bio_similarity(candidate_bio, vip)
    photo = _photo_similarity(
        candidate_photo_phash, vip.photo_phashes or []
    )

    w_name, w_handle, w_bio, w_photo = (
        weights.name, weights.handle, weights.bio, weights.photo,
    )

    photo_contrib = (photo if photo is not None else 0.0) * w_photo
    if photo is None:
        # Re-distribute the photo weight across the others if no photo signal.
        denom = (w_name + w_handle + w_bio) or 1.0
        scale = 1.0 / denom
        aggregate = (
            name * w_name + handle * w_handle + bio * w_bio
        ) * scale
    else:
        denom = (w_name + w_handle + w_bio + w_photo) or 1.0
        aggregate = (
            name * w_name + handle * w_handle + bio * w_bio + photo_contrib
        ) / denom

    signals: list[str] = []
    if name >= 0.85:
        signals.append("name_match_strong")
    elif name >= 0.6:
        signals.append("name_match_partial")
    if handle >= 0.85:
        signals.append("handle_match_strong")
    elif handle >= 0.6:
        signals.append("handle_match_partial")
    if bio >= 0.5:
        signals.append("bio_overlap")
    if photo is not None and photo >= 0.7:
        signals.append("photo_match_strong")
    elif photo is not None and photo >= 0.4:
        signals.append("photo_match_partial")

    if aggregate >= weights.confirmed_threshold:
        verdict = "confirmed"
        rationale = f"high-confidence impersonation (score {aggregate:.2f})"
    elif aggregate >= weights.review_threshold:
        verdict = "review"
        rationale = f"probable impersonation, analyst review (score {aggregate:.2f})"
    else:
        verdict = "ignore"
        rationale = f"low score {aggregate:.2f}"

    return ImpersonationScore(
        name_similarity=round(name, 4),
        handle_similarity=round(handle, 4),
        bio_similarity=round(bio, 4),
        photo_similarity=round(photo, 4) if photo is not None else None,
        aggregate_score=round(aggregate, 4),
        signals=signals,
        verdict=verdict,
        rationale=rationale,
    )


__all__ = ["ImpersonationScore", "score_candidate"]
