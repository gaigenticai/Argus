"""Subsidiary allowlist helpers.

Per-org allowlist of legitimate domains that the Brand Protection
pipeline should never flag. Operators add patterns from the dashboard
(``Terms & feeds → Allowlist``) and the suspect-ingest paths consult
this module on every new candidate. Matches get the suspect's state
flipped to ``dismissed`` with a structured reason so the audit trail
captures *which* allowlist entry suppressed it.

Pattern grammar (intentionally simple — no regex injection surface):

  * ``corp.example.com``  exact match (case-insensitive).
  * ``*.example.com``     matches any subdomain of example.com to
                          arbitrary depth, including the apex.

Anything else is treated as exact-match. Patterns longer than 255
chars are rejected at the API surface.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("argus.brand.allowlist")


def _norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def matches_pattern(domain: str, pattern: str) -> bool:
    """True iff ``domain`` matches ``pattern`` per the grammar above."""
    d = _norm(domain)
    p = _norm(pattern)
    if not d or not p:
        return False
    if p.startswith("*."):
        suffix = p[2:]
        if not suffix:
            return False
        return d == suffix or d.endswith("." + suffix)
    return d == p


async def find_match(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    domain: str,
):
    """Return the first matching allowlist row (or None) for the org."""
    from src.models.brand import BrandSubsidiaryAllowlist

    rows = list(
        (await session.execute(
            select(BrandSubsidiaryAllowlist).where(
                BrandSubsidiaryAllowlist.organization_id == organization_id
            )
        )).scalars().all()
    )
    for row in rows:
        if matches_pattern(domain, row.pattern):
            return row
    return None


async def auto_dismiss_if_allowlisted(
    session: AsyncSession,
    *,
    suspect,
) -> bool:
    """If the suspect's domain matches any allowlist row, flip state
    to ``dismissed`` with a structured reason. Returns True when a
    match was applied — the caller can short-circuit further work
    (Brand Defender queueing, notifications) on True.

    The agent's previous in-code subsidiary list is now this table; the
    ``check_subsidiary_allowlist`` tool reads the same data so the
    agent's tool answers and the dashboard's auto-dismiss stay in
    sync.
    """
    from src.models.brand import SuspectDomainState

    row = await find_match(
        session,
        organization_id=suspect.organization_id,
        domain=getattr(suspect, "domain", "") or "",
    )
    if row is None:
        return False
    if (suspect.state or "").lower() == SuspectDomainState.DISMISSED.value:
        # Already dismissed — don't churn timestamps / audit notes.
        return True
    from datetime import datetime, timezone

    suspect.state = SuspectDomainState.DISMISSED.value
    note = f"allowlisted: {row.pattern}"
    if row.reason:
        note += f" — {row.reason}"
    # Compose with any prior reason so the trail isn't lost.
    existing = getattr(suspect, "state_reason", None)
    suspect.state_reason = (existing + "\n" + note) if existing else note
    suspect.state_changed_at = datetime.now(timezone.utc)
    suspect.state_changed_by_user_id = None  # auto-applied
    logger.info(
        "[brand-allowlist] auto-dismissed suspect=%s domain=%s by pattern=%s",
        suspect.id, suspect.domain, row.pattern,
    )
    return True


__all__ = [
    "matches_pattern",
    "find_match",
    "auto_dismiss_if_allowlisted",
]
