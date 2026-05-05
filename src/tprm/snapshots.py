"""Append-only history of vendor scorecard scores for trend lines."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.tprm import VendorScorecardSnapshot


async def record_snapshot(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    vendor_asset_id: uuid.UUID,
    score: float,
    grade: str,
    pillar_scores: dict[str, float],
) -> VendorScorecardSnapshot:
    snap = VendorScorecardSnapshot(
        organization_id=organization_id,
        vendor_asset_id=vendor_asset_id,
        score=float(score),
        grade=grade,
        pillar_scores=dict(pillar_scores),
        snapshot_at=datetime.now(timezone.utc),
    )
    db.add(snap)
    await db.flush()
    return snap


async def list_snapshots(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    vendor_asset_id: uuid.UUID,
    days: int = 365,
    limit: int = 200,
) -> list[VendorScorecardSnapshot]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        await db.execute(
            select(VendorScorecardSnapshot)
            .where(VendorScorecardSnapshot.organization_id == organization_id)
            .where(VendorScorecardSnapshot.vendor_asset_id == vendor_asset_id)
            .where(VendorScorecardSnapshot.snapshot_at >= cutoff)
            .order_by(VendorScorecardSnapshot.snapshot_at.asc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


def detect_score_drop(
    snapshots: list[VendorScorecardSnapshot],
    *,
    threshold: float = 20.0,
    window_days: int = 7,
) -> dict[str, Any] | None:
    """Returns ``{from, to, delta}`` if the most-recent snapshot dropped
    more than ``threshold`` points within ``window_days`` of the previous
    one. ``None`` otherwise."""
    if len(snapshots) < 2:
        return None
    latest = snapshots[-1]
    cutoff = latest.snapshot_at - timedelta(days=window_days)
    earlier = [s for s in snapshots[:-1] if s.snapshot_at >= cutoff]
    if not earlier:
        earlier = snapshots[:-1]
    prev = earlier[-1]
    delta = latest.score - prev.score
    if delta <= -threshold:
        return {
            "from": prev.score,
            "to": latest.score,
            "delta": round(delta, 2),
            "from_at": prev.snapshot_at.isoformat(),
            "to_at": latest.snapshot_at.isoformat(),
        }
    return None


__all__ = ["record_snapshot", "list_snapshots", "detect_score_drop"]
