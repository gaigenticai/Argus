"""Vendor ↔ Case auto-correlation.

When a Case is created (or updated) we scan its title + body + tags for
substrings matching the canonical name or primary_domain of any vendor
Asset in the same org. Matches get persisted as a CaseEvent so the
vendor's scorecard can surface "incident in the last 30 days" without
requiring analysts to manually link.

The match is case-insensitive substring against canonicalised forms
(lowercase, stripped of corp suffixes). False-positive risk is bounded
by requiring (a) match length >= 4 and (b) the match appearing as a
whole word.
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.threat import Asset

_logger = logging.getLogger(__name__)


_SUFFIX_RE = re.compile(
    r"\b(inc|incorporated|corp|corporation|llc|llp|ltd|limited|pte|gmbh|sa|nv|bv|ag|co|company)\.?\b",
    re.I,
)


def _canonical(s: str) -> str:
    s = s.lower()
    s = _SUFFIX_RE.sub("", s)
    s = re.sub(r"[^a-z0-9 ]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _match_in_text(needle: str, haystack: str) -> bool:
    if len(needle) < 4:
        return False
    pattern = r"\b" + re.escape(needle) + r"\b"
    return re.search(pattern, haystack) is not None


async def find_matching_vendors(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    text: str,
) -> list[Asset]:
    """Return vendors in this org whose name or primary_domain appears as
    a whole-word match in ``text``. Bounded by requiring substrings of
    length >= 4 to keep false-positives down."""
    if not text:
        return []
    haystack = _canonical(text)
    if not haystack:
        return []
    rows = (
        await db.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.asset_type == "vendor",
            )
        )
    ).scalars().all()
    matched: list[Asset] = []
    for v in rows:
        candidates = []
        if v.value:
            candidates.append(_canonical(v.value))
        primary = (v.details or {}).get("primary_domain")
        if primary:
            candidates.append(_canonical(primary))
        for cand in candidates:
            if cand and _match_in_text(cand, haystack):
                matched.append(v)
                break
    return matched


async def link_case_to_vendors(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    case_id: uuid.UUID,
    case_title: str,
    case_body: str | None = None,
) -> list[uuid.UUID]:
    """Side-effect: emit a CaseEvent (kind=vendor_correlation) per match
    so the case timeline shows the inferred vendor links and the vendor
    scorecard FE can list recent incidents.

    Returns the matched vendor_ids.
    """
    blob = " ".join(filter(None, [case_title, case_body]))
    matched = await find_matching_vendors(
        db, organization_id=organization_id, text=blob
    )
    if not matched:
        return []
    try:
        from src.models.cases import CaseEvent

        for v in matched:
            db.add(
                CaseEvent(
                    case_id=case_id,
                    organization_id=organization_id,
                    kind="vendor_correlation",
                    summary=f"Auto-correlated to vendor {v.value}",
                    payload={
                        "vendor_id": str(v.id),
                        "vendor_value": v.value,
                        "primary_domain": (v.details or {}).get("primary_domain"),
                        "matched_via": "name_or_domain_substring",
                    },
                )
            )
        await db.flush()
    except Exception:  # noqa: BLE001
        _logger.exception("link_case_to_vendors: persistence failed")
    return [v.id for v in matched]


__all__ = ["find_matching_vendors", "link_case_to_vendors"]
