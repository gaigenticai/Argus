"""Feed-subscription filter evaluator (P3 #3.4).

Pure function. Given an alert dict and a filter expression, return
``True`` if the alert satisfies every condition in the filter.

Filter expression keys (all optional):

  severity            list[str]   any-of (case-insensitive)
  category            list[str]   any-of (case-insensitive)
  status              list[str]   any-of
  tags_any            list[str]   alert.tags must overlap (case-insens.)
  tags_all            list[str]   alert.tags must contain every tag
  min_confidence      float       alert.confidence ≥ this value
  title_contains      str         substring (case-insensitive)
  title_regex         str         regex match against alert.title

An empty / None filter matches every alert.
"""

from __future__ import annotations

import re
from typing import Any


def _coerce_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v]
    return []


def _lower_set(v: Any) -> set[str]:
    return {x.lower() for x in _coerce_list(v) if x}


def match_alert(alert: dict[str, Any], filt: dict[str, Any] | None) -> bool:
    """Return True iff ``alert`` matches every clause in ``filt``."""
    if not filt:
        return True

    # severity any-of
    if "severity" in filt:
        wanted = _lower_set(filt["severity"])
        if wanted and str(alert.get("severity", "")).lower() not in wanted:
            return False

    # category any-of
    if "category" in filt:
        wanted = _lower_set(filt["category"])
        if wanted and str(alert.get("category", "")).lower() not in wanted:
            return False

    # status any-of
    if "status" in filt:
        wanted = _lower_set(filt["status"])
        if wanted and str(alert.get("status", "")).lower() not in wanted:
            return False

    # tags
    alert_tags = _lower_set(alert.get("tags"))
    if filt.get("tags_any"):
        wanted = _lower_set(filt["tags_any"])
        if wanted and alert_tags.isdisjoint(wanted):
            return False
    if filt.get("tags_all"):
        wanted = _lower_set(filt["tags_all"])
        if wanted and not wanted.issubset(alert_tags):
            return False

    # numeric floor
    if "min_confidence" in filt:
        try:
            floor = float(filt["min_confidence"])
        except (TypeError, ValueError):
            floor = 0.0
        ac = alert.get("confidence")
        if ac is None:
            return False
        try:
            if float(ac) < floor:
                return False
        except (TypeError, ValueError):
            return False

    # title substring
    if filt.get("title_contains"):
        needle = str(filt["title_contains"]).lower()
        if needle and needle not in str(alert.get("title") or "").lower():
            return False

    # title regex
    if filt.get("title_regex"):
        try:
            if not re.search(
                str(filt["title_regex"]),
                str(alert.get("title") or ""),
                re.IGNORECASE,
            ):
                return False
        except re.error:
            # Malformed regex — never matches. (Better than blowing up
            # the matcher loop for every alert.)
            return False

    return True


def filter_subscriptions(
    alert: dict[str, Any],
    subscriptions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convenience: return the subset of ``subscriptions`` whose
    ``filter`` matches ``alert`` AND that are ``active``.
    """
    out: list[dict[str, Any]] = []
    for s in subscriptions:
        if not s.get("active", True):
            continue
        if match_alert(alert, s.get("filter") or {}):
            out.append(s)
    return out
