"""Per-tenant article relevance scoring (lightweight, no LLM).

Inputs (all optional):
    brand_terms     active BrandTerm.value strings
    asset_keywords  derived from Organization.tech_stack + Asset.tags
    kev_cves        set of CVE IDs marked is_kev=True (from CveRecord)

Score ∈ [0, 1]:
    0.40 * (any brand term present)
    0.35 * (any KEV CVE present)
    0.25 * tech-keyword overlap ratio (capped at 1.0)

Above 0.0 → article is "relevant" for that tenant; row written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


_TOKEN_RE = re.compile(r"[A-Za-z0-9.+\-]+")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "")}


@dataclass
class RelevanceScore:
    score: float
    matched_brand_terms: list[str]
    matched_cves: list[str]
    matched_tech_keywords: list[str]


def score_article(
    *,
    title: str,
    summary: str | None,
    cve_ids: Iterable[str],
    brand_terms: Iterable[str],
    asset_keywords: Iterable[str],
    kev_cves: Iterable[str],
) -> RelevanceScore:
    text_tokens = _tokens(title + " " + (summary or ""))

    brand_hits = sorted(
        {b for b in brand_terms if b and len(b) >= 3 and b.lower() in text_tokens}
    )
    cve_set = {c.upper() for c in cve_ids}
    kev_set = {c.upper() for c in kev_cves}
    cve_hits = sorted(cve_set & kev_set)

    asset_kw_set = {k.lower() for k in asset_keywords if k}
    tech_hits = sorted(asset_kw_set & text_tokens)

    score = 0.0
    if brand_hits:
        score += 0.40
    if cve_hits:
        score += 0.35
    if asset_kw_set:
        ratio = min(1.0, len(tech_hits) / max(1, len(asset_kw_set)))
        score += 0.25 * ratio

    return RelevanceScore(
        score=round(min(1.0, score), 4),
        matched_brand_terms=brand_hits,
        matched_cves=cve_hits,
        matched_tech_keywords=tech_hits[:25],
    )


__all__ = ["RelevanceScore", "score_article"]
