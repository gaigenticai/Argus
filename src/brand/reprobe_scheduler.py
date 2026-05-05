"""Live-probe re-scheduler.

Typosquats often go live weeks after registration — a clean live-probe
on day 0 doesn't mean the suspect stays clean. This module computes
which open suspects are due for a re-probe and exposes a worker tick
that drains a bounded batch each cycle.

Cadence (per-suspect):

  * never probed                → probe immediately
  * verdict ∈ {benign, parked, unknown} AND age ≥ 7d   → re-probe at 7d
  * verdict ∈ {benign, parked, unknown} AND age ≥ 30d  → re-probe at 30d
  * verdict ∈ {suspicious, unreachable} AND age ≥ 7d   → re-probe at 7d
  * verdict == phishing                                → no auto re-probe
                                                          (analyst owns it)
  * any verdict, suspect already in dismissed/cleared  → skip

The cadence is intentionally simple — keep the queue predictable and
easy for analysts to reason about. More sophisticated decay can come
later as a per-org config knob.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("argus.brand.reprobe")


# --- Cadence policy ---------------------------------------------------


@dataclass
class _Tier:
    """Cadence tier — how long after the last probe to re-probe."""
    after: timedelta
    states_eligible: tuple[str, ...]   # SuspectDomainState values
    last_verdicts: tuple[str, ...]     # LiveProbeVerdict values; "*" = any


# First tier wins. Order matters.
_CADENCE: tuple[_Tier, ...] = (
    # Suspicious / unreachable: re-probe weekly until phishing or dismissed.
    _Tier(timedelta(days=7), ("open",), ("suspicious", "unreachable")),
    # Clean-looking: re-probe at 7d, 30d, then settle.
    _Tier(timedelta(days=7), ("open",), ("benign", "parked", "unknown")),
    _Tier(timedelta(days=30), ("open",), ("benign", "parked", "unknown")),
)


@dataclass
class ScheduledProbe:
    suspect_id: uuid.UUID
    organization_id: uuid.UUID
    domain: str
    last_probed_at: datetime | None
    last_verdict: str | None
    similarity: float
    due_at: datetime           # when this re-probe became eligible
    reason: str                # human-readable why-now line


async def _last_probe(
    session: AsyncSession, *, suspect_id: uuid.UUID
) -> tuple[datetime | None, str | None]:
    """Return (fetched_at, verdict) of the most recent live-probe for
    the suspect, or (None, None) if it's never been probed."""
    from src.models.live_probe import LiveProbe

    row = (
        await session.execute(
            select(LiveProbe.fetched_at, LiveProbe.verdict)
            .where(LiveProbe.suspect_domain_id == suspect_id)
            .order_by(LiveProbe.fetched_at.desc())
            .limit(1)
        )
    ).first()
    if row is None:
        return None, None
    return row.fetched_at, row.verdict


async def compute_reprobe_queue(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID | None = None,
    limit: int = 100,
) -> list[ScheduledProbe]:
    """Return suspects due for a re-probe, ordered by similarity desc
    (operator wants the closest typosquats checked first)."""
    from src.models.brand import SuspectDomain, SuspectDomainState

    q = (
        select(SuspectDomain)
        .where(SuspectDomain.state == SuspectDomainState.OPEN.value)
        .order_by(SuspectDomain.similarity.desc())
    )
    if organization_id is not None:
        q = q.where(SuspectDomain.organization_id == organization_id)
    suspects = list((await session.execute(q)).scalars().all())

    now = datetime.now(timezone.utc)
    out: list[ScheduledProbe] = []
    for s in suspects:
        if len(out) >= limit:
            break
        last_probed_at, last_verdict = await _last_probe(session, suspect_id=s.id)

        # Never probed → eligible immediately.
        if last_probed_at is None:
            out.append(ScheduledProbe(
                suspect_id=s.id,
                organization_id=s.organization_id,
                domain=s.domain,
                last_probed_at=None,
                last_verdict=None,
                similarity=s.similarity,
                due_at=now,
                reason="never probed",
            ))
            continue

        # Phishing verdict → analyst owns it; skip auto re-probe.
        if (last_verdict or "").lower() == "phishing":
            continue

        # Walk the cadence tiers.
        for tier in _CADENCE:
            if (s.state or "").lower() not in tier.states_eligible:
                continue
            if (last_verdict or "").lower() not in tier.last_verdicts and "*" not in tier.last_verdicts:
                continue
            if (now - last_probed_at) >= tier.after:
                out.append(ScheduledProbe(
                    suspect_id=s.id,
                    organization_id=s.organization_id,
                    domain=s.domain,
                    last_probed_at=last_probed_at,
                    last_verdict=last_verdict,
                    similarity=s.similarity,
                    due_at=last_probed_at + tier.after,
                    reason=f"verdict={last_verdict} aged {tier.after.days}d",
                ))
                break  # first tier wins
    return out


async def reprobe_tick(
    session: AsyncSession, *, batch_size: int = 25,
) -> int:
    """Drain up to ``batch_size`` due re-probes. Returns the number
    actually probed. Best-effort — single tool failures don't crash
    the tick."""
    from src.brand.probe import probe_suspect

    queue = await compute_reprobe_queue(session, limit=batch_size)
    if not queue:
        return 0
    logger.info("[reprobe] tick: %d due", len(queue))

    probed = 0
    for entry in queue:
        try:
            await probe_suspect(
                session,
                entry.organization_id,
                entry.suspect_id,
            )
            probed += 1
        except Exception:  # noqa: BLE001
            logger.exception(
                "[reprobe] probe failed for suspect=%s domain=%s",
                entry.suspect_id, entry.domain,
            )
    await session.commit()
    return probed


__all__ = [
    "ScheduledProbe",
    "compute_reprobe_queue",
    "reprobe_tick",
]
