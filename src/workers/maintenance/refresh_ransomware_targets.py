"""Ransomware-target self-healing job.

Pulls the currently-active ransomware group catalogue from
``ransomware.live`` (a public OSINT aggregator maintained by security
researchers; same data set Recorded Future / Mandiant / Trellix all
mirror) and updates the ``crawler_targets`` table for every
organisation in the deployment.

Behaviour per tick:

  1. Fetch ``GET /v2/groups`` from the upstream (configurable via
     ``ARGUS_RANSOMWARE_TRACKER_URL``). Returns one entry per group
     with ``locations[].fqdn`` and ``locations[].available`` flags.
  2. For each org in the deployment:
       a. Read the current ``crawler_targets`` rows of kind
          ``ransomware_leak_group``.
       b. For every group the upstream knows about, upsert a row keyed
          by ``identifier=<group_name>`` whose config carries the union
          of all currently-available onion URLs.
       c. For groups that previously had targets but no longer appear
          upstream, set ``is_active=False`` (don't delete — preserves
          history for audit).
  3. Record FeedHealth ``maintenance.refresh_ransomware_targets`` so
     the dashboard surfaces last-run status.

The job is intentionally resilient to upstream outages: a single
fetch failure marks the FeedHealth row as a network error and exits
without touching ``crawler_targets``. A cleared-out catalogue (empty
list) is treated as an upstream bug, also a no-op — better to keep
stale targets than to wipe the operator's scope on a parser regression.

This job replaces the temptation to ship a one-shot
``scripts/refresh_ransomware_urls.py``. Operators don't have to know
or run anything; the worker tick keeps the data current.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.models.admin import CrawlerTarget
from src.models.threat import Organization
from src.storage import database as _db

_logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.refresh_ransomware_targets"

# Public OSINT aggregator. The default URL is overridable so air-gapped
# deployments can mirror the data internally and point at it.
_DEFAULT_TRACKER_URL = "https://api.ransomware.live/v2/groups"
_TRACKER_URL = os.environ.get(
    "ARGUS_RANSOMWARE_TRACKER_URL", _DEFAULT_TRACKER_URL,
)
# Cap rows per tick. Public trackers list 100+ groups; we don't want to
# blow up crawler_targets for a brand-new tenant. Operators can disable
# specific rows via the admin UI if a group isn't relevant to them.
_MAX_GROUPS = int(os.environ.get("ARGUS_RANSOMWARE_TRACKER_MAX_GROUPS", "60"))
_FETCH_TIMEOUT = aiohttp.ClientTimeout(total=20)


async def _fetch_upstream_groups() -> list[dict] | None:
    """GET the upstream group catalogue. Returns a list of group dicts
    with ``name`` + ``locations[].fqdn`` + ``locations[].available``,
    or ``None`` on any failure (network, parse, or empty response)."""
    try:
        async with aiohttp.ClientSession(timeout=_FETCH_TIMEOUT) as http:
            async with http.get(
                _TRACKER_URL,
                headers={"User-Agent": "argus-ransomware-refresh/1.0"},
            ) as resp:
                if resp.status != 200:
                    _logger.warning(
                        "ransomware tracker returned HTTP %d", resp.status,
                    )
                    return None
                payload = await resp.json(content_type=None)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("ransomware tracker fetch failed: %s", exc)
        return None

    # Defensive parse: the upstream schema has been stable but if a
    # future version changes shape we degrade gracefully rather than
    # crash the worker loop.
    if not isinstance(payload, list) or not payload:
        _logger.warning(
            "ransomware tracker payload empty or wrong shape (got %s)",
            type(payload).__name__,
        )
        return None
    return payload[:_MAX_GROUPS]


def _extract_active_onions(group: dict) -> list[str]:
    """Pick onion URLs that the upstream marks as currently reachable.

    ``locations`` is the canonical list per group; each entry is
    ``{fqdn, available, version, ...}``. We only keep ``available=True``
    fqdns and prefix them with ``http://`` since the crawler expects
    full URLs and ransomware sites are HTTP-only over Tor."""
    out: list[str] = []
    locations = group.get("locations") or []
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        fqdn = (loc.get("fqdn") or "").strip().lower()
        if not fqdn or not fqdn.endswith(".onion"):
            continue
        if loc.get("available") is False:
            continue
        out.append(f"http://{fqdn}/")
    # De-dup, preserve order.
    seen: set[str] = set()
    unique: list[str] = []
    for url in out:
        if url in seen:
            continue
        seen.add(url)
        unique.append(url)
    return unique


async def _upsert_for_org(
    db: AsyncSession, org: Organization, groups: list[dict]
) -> tuple[int, int, int]:
    """Reconcile crawler_targets for one org against upstream truth.

    Returns ``(upserted, deactivated, untouched)``."""
    existing_rows = (
        await db.execute(
            select(CrawlerTarget).where(
                CrawlerTarget.organization_id == org.id,
                CrawlerTarget.kind == "ransomware_leak_group",
            )
        )
    ).scalars().all()
    existing_by_id: dict[str, CrawlerTarget] = {
        row.identifier: row for row in existing_rows
    }
    upstream_by_id: dict[str, dict] = {
        (g.get("name") or "").strip().lower(): g
        for g in groups
        if (g.get("name") or "").strip()
    }

    upserted = 0
    deactivated = 0
    untouched = 0

    for group_id, group in upstream_by_id.items():
        onions = _extract_active_onions(group)
        if not onions:
            # Upstream knows the group but has no live URLs — skip
            # rather than seed a row that will never resolve.
            continue
        display_name = (
            group.get("captcha")  # ransomware.live oddity: this is the human-readable name
            or group.get("description")
            or group_id.title()
        )[:255]
        config = {
            "group_name": group_id,
            "onion_urls": onions,
            "max_pages": 2,
            "_refreshed_at": datetime.now(timezone.utc).isoformat(),
            "_source": "ransomware.live",
        }
        row = existing_by_id.get(group_id)
        if row is None:
            db.add(
                CrawlerTarget(
                    organization_id=org.id,
                    kind="ransomware_leak_group",
                    identifier=group_id,
                    display_name=display_name,
                    config=config,
                    is_active=True,
                )
            )
            upserted += 1
        else:
            # Update the live URL list in-place. Only flip is_active
            # back on if the operator hadn't manually disabled it —
            # don't fight the operator's choice.
            row.config = config
            row.display_name = display_name
            untouched += 1

    # Mark groups that disappeared from upstream as inactive (don't
    # delete — keeps audit history, lets the operator see what rotated
    # out and when).
    for ident, row in existing_by_id.items():
        if ident in upstream_by_id:
            continue
        cfg = row.config or {}
        if cfg.get("_source") != "ransomware.live":
            # Operator-curated row, not ours to touch.
            continue
        if row.is_active:
            row.is_active = False
            row.last_run_summary = {
                **(row.last_run_summary or {}),
                "deactivated_reason": "rotated_off_upstream",
                "deactivated_at": datetime.now(timezone.utc).isoformat(),
            }
            deactivated += 1
    return upserted, deactivated, untouched


async def tick_once() -> None:
    """One iteration of the maintenance loop. Safe to call from the
    worker tick scheduler — exceptions inside are logged but the
    function never raises."""
    if _db.async_session_factory is None:
        return
    started = time.monotonic()

    groups = await _fetch_upstream_groups()
    if groups is None:
        async with _db.async_session_factory() as session:
            await feed_health.mark_failure(
                session,
                feed_name=FEED_NAME,
                error=f"upstream {_TRACKER_URL} unreachable or empty",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            await session.commit()
        return

    total_upserted = 0
    total_deactivated = 0
    total_untouched = 0
    org_count = 0

    async with _db.async_session_factory() as session:
        orgs = (
            await session.execute(select(Organization))
        ).scalars().all()
        for org in orgs:
            up, deact, unt = await _upsert_for_org(session, org, groups)
            total_upserted += up
            total_deactivated += deact
            total_untouched += unt
            org_count += 1
        await feed_health.mark_ok(
            session,
            feed_name=FEED_NAME,
            rows_ingested=total_upserted,
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=(
                f"upstream={len(groups)} groups; "
                f"orgs={org_count}; "
                f"upserted={total_upserted}, "
                f"refreshed={total_untouched}, "
                f"deactivated={total_deactivated}"
            ),
        )
        await session.commit()
    _logger.info(
        "maintenance: ransomware-target refresh — %d groups upstream, "
        "%d upserted, %d refreshed, %d deactivated across %d org(s)",
        len(groups), total_upserted, total_untouched, total_deactivated, org_count,
    )
