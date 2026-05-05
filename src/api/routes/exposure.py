"""Org-scoped exposure summary for the dashboard's AI Triage Agent card.

The AI Triage Agent card used to surface three GLOBAL counters
(Feed Entries, C2 Servers, Exploited CVEs). Two problems:

1. The numbers are identical across tenants — they describe the
   upstream feed firehose, not the customer's own posture. A CTO
   demo where every customer sees the same "183,840 entries" is a
   credibility hit.
2. They invited the wrong question ("am I in danger from 1,693 CVEs?")
   when the honest answer is "no, your slice is 30-50 — here it is."

This module computes the org-scoped slice:

* ``cves_affecting_you`` — ``exploited_cve`` feed entries whose
  description mentions a vendor/product the org has declared in
  ``tech_stack``. Same matching logic the LLM pre-filter (next
  refactor) will use, so building it here also paves that path.
* ``open_alerts`` — alerts with status NOT IN
  (``resolved``, ``false_positive``) for the current org.
* ``tracked_iocs`` — IOCs linked via ``source_alert_id`` to alerts
  in the current org. (IOCs themselves are global indicators; the
  org-scoped count is "indicators we've created on your behalf.")

Returned together so the dashboard fetches once.
"""

from __future__ import annotations

import logging
from typing import Iterable

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.models.feeds import ThreatFeedEntry
from src.models.intel import IOC
from src.models.threat import Alert, AlertStatus
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CVEPreview(BaseModel):
    """One sample matching CVE for the tile's hover/dropdown."""

    cve_id: str | None
    title: str | None
    severity: str | None
    matched_terms: list[str]


class ExposureResponse(BaseModel):
    """Org-scoped exposure summary for the AI Triage Agent card."""

    org_id: str
    org_name: str
    declared_components: int
    cves_affecting_you: int
    cves_sample: list[CVEPreview]
    open_alerts: int
    tracked_iocs: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flatten_tech_stack(tech_stack: dict | None) -> list[str]:
    """Return a flat lowercased list of every vendor/product term.

    ``tech_stack`` is ``{category: [vendor, ...]}``. Accepts the
    shape but tolerates non-list values defensively (older orgs
    may have malformed JSON).
    """
    out: list[str] = []
    if not tech_stack or not isinstance(tech_stack, dict):
        return out
    for value in tech_stack.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    out.append(item.strip())
    return out


def _cve_match_clause(terms: Iterable[str]):
    """Build an OR-ed ILIKE clause matching feed entry description.

    CVE feed entries (CISA KEV) put the affected product in the
    ``description`` field — e.g. *"Adobe Acrobat and Reader contain
    a prototype pollution vulnerability that allows…"*. So we match
    each declared vendor/product against the description with
    case-insensitive substring search. ``value`` is also
    inspected because some feeds put the CVE ID + product in there.
    """
    clauses = []
    for term in terms:
        # Skip very short terms that would match too many false
        # positives (e.g. ".NET" → matches "internet"). The LLM
        # gets an honest tech-stack list to reason against, but
        # this fast pre-filter needs longer anchors.
        if len(term) < 3:
            continue
        like = f"%{term}%"
        clauses.append(ThreatFeedEntry.description.ilike(like))
        clauses.append(ThreatFeedEntry.value.ilike(like))
    return or_(*clauses) if clauses else None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/exposure", response_model=ExposureResponse)
async def get_dashboard_exposure(
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> ExposureResponse:
    """Return the org-scoped tile data for the AI Triage Agent card.

    Single tenant: resolves to the system organisation. The route
    is read-only and analyst-accessible (no admin required) so
    every operator who can see the dashboard can see the numbers.
    """
    from src.api.routes.organizations import _resolve

    org = await _resolve(db, "current")
    terms = _flatten_tech_stack(org.tech_stack)

    # 1. CVEs affecting the org's declared stack.
    cves_affecting = 0
    cves_sample: list[CVEPreview] = []
    if terms:
        clause = _cve_match_clause(terms)
        if clause is not None:
            count_q = await db.execute(
                select(func.count())
                .select_from(ThreatFeedEntry)
                .where(
                    ThreatFeedEntry.layer == "exploited_cve",
                    clause,
                )
            )
            cves_affecting = count_q.scalar() or 0

            sample_q = await db.execute(
                select(ThreatFeedEntry)
                .where(
                    ThreatFeedEntry.layer == "exploited_cve",
                    clause,
                )
                .order_by(ThreatFeedEntry.severity.desc(), ThreatFeedEntry.confidence.desc())
                .limit(5)
            )
            for entry in sample_q.scalars():
                # Cheap matched-terms attribution: scan the entry
                # text once for any term we declared. Operators see
                # *why* the entry matched without a second LLM call.
                haystack = " ".join(
                    [entry.description or "", entry.value or ""]
                ).lower()
                matched = [t for t in terms if len(t) >= 3 and t.lower() in haystack]
                cves_sample.append(
                    CVEPreview(
                        cve_id=(entry.value or entry.label or None),
                        title=(entry.label or entry.description or "")[:160] or None,
                        severity=entry.severity,
                        matched_terms=matched[:5],
                    )
                )

    # 2. Open alerts for the org. "Open" = not resolved / not FP.
    closed_statuses = {AlertStatus.RESOLVED.value, AlertStatus.FALSE_POSITIVE.value}
    open_q = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            Alert.organization_id == org.id,
            Alert.status.notin_(closed_statuses),
        )
    )
    open_alerts = open_q.scalar() or 0

    # 3. IOCs linked via source_alert_id to this org's alerts.
    #    IOC has no direct org column (intentional — IOCs are global
    #    facts), but the source alert does. Joining gives us the
    #    "indicators created on your behalf" count.
    iocs_q = await db.execute(
        select(func.count(IOC.id.distinct()))
        .join(Alert, Alert.id == IOC.source_alert_id)
        .where(Alert.organization_id == org.id)
    )
    tracked_iocs = iocs_q.scalar() or 0

    return ExposureResponse(
        org_id=str(org.id),
        org_name=org.name,
        declared_components=len(terms),
        cves_affecting_you=cves_affecting,
        cves_sample=cves_sample,
        open_alerts=open_alerts,
        tracked_iocs=tracked_iocs,
    )
