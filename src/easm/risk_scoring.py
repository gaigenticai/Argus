"""Per-asset composite risk score.

    risk_score = exploitability × accessibility × age × criticality

Each component is normalised to 0..1 and combined into a 0..100
composite. The score is written to ``Asset.risk_score`` so the surface
table can sort by it without recomputing on every request.

Components
----------

exploitability (0..1)
    max(EPSS) across open ExposureFinding rows linked to this asset
    (or matched by host). Rises with every new vuln discovered against
    the asset.

accessibility (0..1)
    derived from httpx HTTP status:
        2xx → 1.0   (fully accessible)
        3xx → 0.7
        401/403 → 0.4 (gated, but discoverable)
        4xx other → 0.2
        5xx → 0.5 (broken but reachable)
        no probe yet → 0.5 (unknown ≈ neutral)

age (0..1)
    1.0 if the asset has never been scanned, else
    rises linearly from 0.2 → 1.0 over 365 days since last scan.
    Stale assets are riskier — drift accumulates.

criticality (0..1)
    crown_jewel=1.0 / high=0.8 / medium=0.5 / low=0.3.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.exposures import ExposureFinding, ExposureState
from src.models.threat import Asset

_logger = logging.getLogger(__name__)


_CRITICALITY_WEIGHT: dict[str, float] = {
    "crown_jewel": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
}


def _accessibility(asset_details: dict | None) -> float:
    if not asset_details:
        return 0.5
    http = asset_details.get("http") or {}
    status = http.get("status_code")
    if not isinstance(status, int):
        return 0.5
    if 200 <= status < 300:
        return 1.0
    if 300 <= status < 400:
        return 0.7
    if status in (401, 403):
        return 0.4
    if 400 <= status < 500:
        return 0.2
    if 500 <= status < 600:
        return 0.5
    return 0.5


def _age_score(last_scanned_at: datetime | None, now: datetime) -> float:
    if last_scanned_at is None:
        return 1.0
    delta_days = max(0, (now - last_scanned_at).days)
    if delta_days <= 0:
        return 0.2
    if delta_days >= 365:
        return 1.0
    return 0.2 + (delta_days / 365.0) * 0.8


async def _exploitability_for_assets(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_ids: list[uuid.UUID],
    asset_values: list[str],
) -> dict[uuid.UUID, float]:
    """Returns ``{asset_id: max_epss}`` for each asset, computed from
    open exposures linked by asset_id OR with a target string matching
    the asset value.
    """
    out: dict[uuid.UUID, float] = {}
    if not asset_ids:
        return out

    rows = (
        await db.execute(
            select(ExposureFinding.asset_id, ExposureFinding.target, ExposureFinding.epss_score)
            .where(ExposureFinding.organization_id == org_id)
            .where(ExposureFinding.state == ExposureState.OPEN.value)
        )
    ).all()

    # First pass: bind by direct asset_id.
    by_asset: dict[uuid.UUID, float] = {}
    by_host: dict[str, float] = {}
    for r in rows:
        epss = r.epss_score or 0.0
        if r.asset_id is not None:
            cur = by_asset.get(r.asset_id, 0.0)
            if epss > cur:
                by_asset[r.asset_id] = epss
        # Fallback: match by host substring (orphan exposures)
        if r.target:
            host = r.target.lower()
            for prefix in ("https://", "http://"):
                if host.startswith(prefix):
                    host = host[len(prefix):]
            host = host.split("/", 1)[0].split(":", 1)[0]
            cur = by_host.get(host, 0.0)
            if epss > cur:
                by_host[host] = epss

    for asset_id, value in zip(asset_ids, asset_values):
        score = by_asset.get(asset_id, 0.0)
        host = (value or "").lower()
        if host in by_host and by_host[host] > score:
            score = by_host[host]
        out[asset_id] = score
    return out


async def compute_risk_for_org(
    db: AsyncSession, org_id: uuid.UUID
) -> dict[str, int]:
    """Compute and persist ``risk_score`` for every asset in the org.

    Returns a small summary dict for logging / response."""
    rows = (
        await db.execute(
            select(Asset).where(Asset.organization_id == org_id)
        )
    ).scalars().all()
    if not rows:
        return {"updated": 0}

    asset_ids = [a.id for a in rows]
    asset_values = [a.value for a in rows]
    expl_map = await _exploitability_for_assets(
        db, org_id, asset_ids, asset_values
    )

    now = datetime.now(timezone.utc)
    updated = 0
    for a in rows:
        crit = _CRITICALITY_WEIGHT.get((a.criticality or "medium").lower(), 0.5)
        access = _accessibility(a.details)
        age = _age_score(a.last_scanned_at, now)
        expl = expl_map.get(a.id, 0.0)
        # Composite: weight exploitability heaviest because it represents
        # known vulnerable surface; accessibility + age * criticality.
        score = (
            (0.45 * expl)
            + (0.20 * access)
            + (0.15 * age)
            + (0.20 * crit)
        ) * 100.0
        score = round(min(100.0, max(0.0, score)), 2)
        if a.risk_score != score:
            a.risk_score = score
            updated += 1
        a.risk_score_updated_at = now

    await db.commit()
    return {"updated": updated, "total_assets": len(rows)}


async def compute_risk_for_assets(
    db: AsyncSession, org_id: uuid.UUID, asset_ids: Iterable[uuid.UUID]
) -> int:
    """Recompute for a specific subset (used by hot-path callers after
    a finding state changes)."""
    ids = list(asset_ids)
    if not ids:
        return 0
    rows = (
        await db.execute(
            select(Asset).where(
                Asset.organization_id == org_id,
                Asset.id.in_(ids),
            )
        )
    ).scalars().all()
    asset_values = [a.value for a in rows]
    expl_map = await _exploitability_for_assets(
        db, org_id, [a.id for a in rows], asset_values
    )
    now = datetime.now(timezone.utc)
    n = 0
    for a in rows:
        crit = _CRITICALITY_WEIGHT.get((a.criticality or "medium").lower(), 0.5)
        access = _accessibility(a.details)
        age = _age_score(a.last_scanned_at, now)
        expl = expl_map.get(a.id, 0.0)
        score = (
            (0.45 * expl)
            + (0.20 * access)
            + (0.15 * age)
            + (0.20 * crit)
        ) * 100.0
        a.risk_score = round(min(100.0, max(0.0, score)), 2)
        a.risk_score_updated_at = now
        n += 1
    await db.commit()
    return n


__all__ = ["compute_risk_for_org", "compute_risk_for_assets"]
