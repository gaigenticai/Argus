"""Compute peer percentile rank for a vendor's score.

Two flavours:

  * ``compute_global_percentile(score, all_scores)`` — what % of all
    scored vendors in the org are at-or-below this score.
  * ``compute_category_percentile(score, category, all_scored)`` — same
    but scoped to vendors with the same ``details.category``.

Pure utility — no DB writes."""
from __future__ import annotations

from typing import Any


def _rank_at_or_below(score: float, pool: list[float]) -> float:
    if not pool:
        return 50.0  # nothing to compare against
    pool_sorted = sorted(pool)
    n_at_or_below = sum(1 for s in pool_sorted if s <= score)
    return round(100.0 * n_at_or_below / len(pool_sorted), 1)


def compute_global_percentile(score: float, all_scores: list[float]) -> dict[str, Any]:
    pct = _rank_at_or_below(score, all_scores)
    return {
        "percentile": pct,
        "cohort_size": len(all_scores),
        "label": _percentile_label(pct),
    }


def compute_category_percentile(
    score: float,
    category: str,
    pool: list[tuple[str, float]],
) -> dict[str, Any]:
    same_cat = [s for c, s in pool if c == category]
    pct = _rank_at_or_below(score, same_cat)
    return {
        "percentile": pct,
        "cohort_size": len(same_cat),
        "category": category,
        "label": _percentile_label(pct),
    }


def _percentile_label(p: float) -> str:
    if p >= 90:
        return "top decile"
    if p >= 75:
        return "above peer average"
    if p >= 50:
        return "around peer median"
    if p >= 25:
        return "below peer average"
    return "bottom quartile"


__all__ = ["compute_global_percentile", "compute_category_percentile"]
