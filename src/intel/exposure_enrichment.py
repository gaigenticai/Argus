"""Read-time + worker-time enrichment of ``ExposureFinding`` rows from
``CveRecord`` (NVD CVSS / FIRST EPSS / CISA KEV).

Used by:
  * ``src/api/routes/easm.py::list_exposures`` and ``get_exposure`` —
    so the UI sees CVSS / EPSS / KEV signals even on findings whose
    upstream tool (Nuclei) didn't carry them.
  * ``src/workers/maintenance/nuclei_easm.py::_persist_finding`` —
    so newly inserted rows have the signals baked in at write time.

The enrichment is idempotent: it only sets fields that are currently
null/empty on the finding, so analyst overrides (e.g. a manual CVSS
on a finding) are preserved.

A single bulk SELECT covers the whole batch — O(1) round-trips for
``list_exposures`` no matter how many CVEs are referenced.
"""
from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.exposures import ExposureFinding
from src.models.intel_polish import CveRecord


def _norm(cve: str) -> str:
    return cve.strip().upper()


def _collect_cve_ids(findings: Iterable[ExposureFinding]) -> set[str]:
    seen: set[str] = set()
    for f in findings:
        for c in f.cve_ids or []:
            if isinstance(c, str) and c:
                seen.add(_norm(c))
    return seen


async def enrich_findings(
    db: AsyncSession,
    findings: list[ExposureFinding],
) -> int:
    """Hydrate EPSS / KEV / CVSS / references on each finding from CveRecord.

    Returns the number of rows that received at least one enrichment update
    (caller can decide whether to commit; SQLAlchemy will persist any
    in-place mutations on the next flush).
    """
    if not findings:
        return 0
    cve_ids = _collect_cve_ids(findings)
    if not cve_ids:
        return 0

    rows = (
        await db.execute(
            select(CveRecord).where(CveRecord.cve_id.in_(cve_ids))
        )
    ).scalars().all()
    by_id: dict[str, CveRecord] = {_norm(r.cve_id): r for r in rows}
    if not by_id:
        return 0

    enriched_count = 0
    for f in findings:
        matched = [
            by_id[_norm(c)]
            for c in (f.cve_ids or [])
            if isinstance(c, str) and _norm(c) in by_id
        ]
        if not matched:
            continue

        touched = False

        # CVSS — take the *worst* (highest) score across matched CVEs;
        # only overwrite if the finding currently has none. We never
        # overwrite an existing analyst-curated value.
        if f.cvss_score is None:
            scored = [r.cvss3_score for r in matched if r.cvss3_score is not None]
            if scored:
                f.cvss_score = max(scored)
                touched = True

        # EPSS — take the maximum score and its matching percentile.
        if f.epss_score is None:
            epss_rows = [r for r in matched if r.epss_score is not None]
            if epss_rows:
                worst = max(epss_rows, key=lambda r: r.epss_score or 0.0)
                f.epss_score = worst.epss_score
                f.epss_percentile = worst.epss_percentile
                touched = True

        # KEV — any matching CVE on the catalog flips this finding to
        # "actively exploited". We pick the earliest dateAdded so the
        # banner can show "exploited since X".
        if not f.is_kev:
            kev_rows = [r for r in matched if r.is_kev]
            if kev_rows:
                f.is_kev = True
                added = [r.kev_added_at for r in kev_rows if r.kev_added_at]
                if added:
                    f.kev_added_at = min(added)
                touched = True

        # References — Nuclei templates often emit empty references. If
        # we have NVD references and the finding has none, merge in.
        existing_refs = list(f.references or [])
        if not existing_refs:
            merged: list[str] = []
            seen: set[str] = set()
            for r in matched:
                for url in r.references or []:
                    if url and url not in seen:
                        seen.add(url)
                        merged.append(url)
                        if len(merged) >= 50:
                            break
                if len(merged) >= 50:
                    break
            if merged:
                f.references = merged
                touched = True

        if touched:
            enriched_count += 1

    return enriched_count


__all__ = ["enrich_findings"]
