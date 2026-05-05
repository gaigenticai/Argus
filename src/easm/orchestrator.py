"""Auto-orchestrate the post-discovery scan pipeline.

After a ``subdomain_enum`` job finishes successfully, this module
queues a follow-up batch of probes against each newly-discovered
host so the analyst sees a populated /surface page — HTTP status,
ports, services, TLS posture, screenshot — rather than a list of
bare hostnames.

Per-org caps + idempotency:
  * ``ARGUS_AUTO_PIPELINE_MAX_PER_TICK`` (default 25) bounds how many
    new findings get scheduled in one go. The remainder get picked
    up the next time subdomain_enum runs (last-modified ordering).
  * Jobs are inserted with ``status=queued``; we never auto-queue if
    a queued/running job for the same (kind, target) already exists.

Disabling: set ``ARGUS_AUTO_PIPELINE_ENABLED=false`` in env. Useful
when running custom workflows or testing.
"""
from __future__ import annotations

import logging
import os
import uuid
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.easm import DiscoveryFinding, FindingState
from src.models.onboarding import (
    DiscoveryJob,
    DiscoveryJobKind,
    DiscoveryJobStatus,
)

_logger = logging.getLogger(__name__)


# Default pipeline — order matters only for resource pacing; the worker
# picks them up FIFO so light jobs (httpx, dns) get out of the way before
# the heavier ones (vuln, tls, port).
_DEFAULT_PIPELINE = (
    DiscoveryJobKind.HTTPX_PROBE,
    DiscoveryJobKind.DNS_DETAIL,
    DiscoveryJobKind.SCREENSHOT,
    DiscoveryJobKind.PORT_SCAN,
    DiscoveryJobKind.TLS_AUDIT,
    DiscoveryJobKind.VULN_SCAN,
)


def _enabled() -> bool:
    val = os.environ.get("ARGUS_AUTO_PIPELINE_ENABLED", "true").strip().lower()
    return val not in ("false", "0", "no", "off")


def _max_per_tick() -> int:
    try:
        return max(1, int(os.environ.get("ARGUS_AUTO_PIPELINE_MAX_PER_TICK", "25")))
    except ValueError:
        return 25


def _pipeline() -> tuple[DiscoveryJobKind, ...]:
    """Operator can override which kinds get auto-queued.

    Format: comma-separated kind values, e.g.
        ARGUS_AUTO_PIPELINE_KINDS=httpx_probe,dns_detail,screenshot
    """
    raw = os.environ.get("ARGUS_AUTO_PIPELINE_KINDS", "").strip()
    if not raw:
        return _DEFAULT_PIPELINE
    out: list[DiscoveryJobKind] = []
    for token in raw.split(","):
        token = token.strip().lower()
        if not token:
            continue
        try:
            out.append(DiscoveryJobKind(token))
        except ValueError:
            _logger.warning(
                "auto_pipeline: ignoring unknown kind %r in ARGUS_AUTO_PIPELINE_KINDS",
                token,
            )
    return tuple(out) if out else _DEFAULT_PIPELINE


async def _existing_open_job(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    kind: str,
    target: str,
) -> DiscoveryJob | None:
    """Return any queued/running job for the same (org, kind, target).

    Idempotency guard — without this, repeated subdomain_enum sweeps
    would pile up duplicate post-pipeline jobs."""
    stmt = (
        select(DiscoveryJob)
        .where(DiscoveryJob.organization_id == organization_id)
        .where(DiscoveryJob.kind == kind)
        .where(DiscoveryJob.target == target)
        .where(
            DiscoveryJob.status.in_(
                [
                    DiscoveryJobStatus.QUEUED.value,
                    DiscoveryJobStatus.RUNNING.value,
                ]
            )
        )
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def queue_pipeline_for_targets(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    targets: Iterable[str],
    parent_job: DiscoveryJob | None = None,
    pipeline: tuple[DiscoveryJobKind, ...] | None = None,
    requested_by_user_id: uuid.UUID | None = None,
) -> dict[str, int]:
    """Insert ``pipeline`` jobs for every host in ``targets``.

    Returns ``{"queued": N, "skipped": M}``.

    The caller is responsible for committing — we only flush so the
    orchestrator can compose with the worker's outer commit on
    ``execute_job``.
    """
    if not _enabled():
        return {"queued": 0, "skipped": 0, "disabled": 1}

    kinds = pipeline or _pipeline()
    cap = _max_per_tick()
    targets_list = [(t or "").strip().lower() for t in targets if t]
    targets_list = [t for t in targets_list if t]
    if not targets_list:
        return {"queued": 0, "skipped": 0}
    targets_list = targets_list[:cap]

    queued = 0
    skipped = 0
    for tgt in targets_list:
        for kind in kinds:
            existing = await _existing_open_job(
                db,
                organization_id=organization_id,
                kind=kind.value,
                target=tgt,
            )
            if existing is not None:
                skipped += 1
                continue
            job = DiscoveryJob(
                organization_id=organization_id,
                asset_id=None,  # post-pipeline targets may not be Asset rows yet
                kind=kind.value,
                status=DiscoveryJobStatus.QUEUED.value,
                target=tgt,
                parameters={
                    "auto_pipeline": True,
                    "parent_job_id": str(parent_job.id) if parent_job else None,
                },
                requested_by_user_id=requested_by_user_id
                or (parent_job.requested_by_user_id if parent_job else None),
            )
            db.add(job)
            queued += 1
    await db.flush()
    _logger.info(
        "auto_pipeline org=%s queued=%d skipped=%d targets=%d kinds=%d",
        organization_id,
        queued,
        skipped,
        len(targets_list),
        len(kinds),
    )
    return {"queued": queued, "skipped": skipped}


async def queue_pipeline_for_subdomain_enum(
    db: AsyncSession,
    parent_job: DiscoveryJob,
) -> dict[str, int]:
    """Hook called after a subdomain_enum job completes successfully.

    Walks the new ``DiscoveryFinding`` rows attached to ``parent_job``
    and queues the post-pipeline against each.
    """
    if not _enabled():
        return {"queued": 0, "skipped": 0, "disabled": 1}

    rows = (
        await db.execute(
            select(DiscoveryFinding)
            .where(DiscoveryFinding.discovery_job_id == parent_job.id)
            .where(DiscoveryFinding.state == FindingState.NEW.value)
        )
    ).scalars().all()
    targets = [r.value for r in rows]
    return await queue_pipeline_for_targets(
        db,
        organization_id=parent_job.organization_id,
        targets=targets,
        parent_job=parent_job,
    )


__all__ = [
    "queue_pipeline_for_subdomain_enum",
    "queue_pipeline_for_targets",
]
