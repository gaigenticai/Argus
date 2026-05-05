"""Scheduled Nuclei EASM sweep — periodic vulnerability scan over each
organisation's known assets (domains / subdomains / IPs).

Argus already exposes Nuclei as an on-demand scanner via
``/api/v1/integrations`` (driven by the `NucleiScanner` wrapper at
``src/integrations/nuclei/scanner.py``). What this module adds is the
*scheduled* invocation: every ``ARGUS_NUCLEI_EASM_INTERVAL`` seconds
the worker walks each org's monitored assets, runs the scanner against
each, and persists results into ``exposure_findings`` so they show up
on ``/exposures`` without anyone hitting the on-demand endpoint.

Behaviour per tick:

    1. Iterate every Organization in the deployment.
    2. For each org pull active monitored Assets of type
       ``domain`` / ``subdomain`` / ``ip`` (capped at
       ``ARGUS_NUCLEI_EASM_TARGETS_PER_TICK`` so a single sweep can't
       saturate the worker on a brand-new tenant with thousands of
       discovered subdomains — round-robin by ``last_scanned_at`` so
       every asset eventually gets covered).
    3. Run ``NucleiScanner.scan_target`` per target with the bundled
       templates and severity floor configured via env.
    4. For each finding, upsert an ExposureFinding row keyed by
       ``(organization_id, rule_id=template_id, target=url)`` — the
       table's UniqueConstraint makes this an INSERT … ON CONFLICT
       update bumping ``occurrence_count`` and ``last_seen_at``.
    5. Record FeedHealth ``maintenance.nuclei_easm`` with the per-tick
       summary so the Service Inventory shows OK once a tick succeeds.

Resilient to the Nuclei binary being missing (deployment hasn't
installed the dependency yet) — the row stays ``not_installed`` until
the operator builds an image with ``nuclei`` baked in. Resilient to
individual scan failures: one bad target doesn't abort the sweep, it
gets recorded as an extra in feed_health and the loop moves on.

Replaces the temptation to ship ``scripts/nuclei_easm_sweep.py`` —
operators don't have to know the job exists; the worker tick keeps
exposures current.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.integrations.nuclei.scanner import (
    BinaryNotFound,
    NucleiScanner,
    ScanFailed,
    ScanTimedOut,
)
from src.intel.exposure_enrichment import enrich_findings
from src.models.common import Severity
from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSource,
    ExposureState,
)
from src.models.threat import Asset, Organization
from src.storage import database as _db

_logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.nuclei_easm"

# Per-tick caps so a fresh deploy with 10k discovered subdomains
# doesn't peg the worker for hours. Round-robin by last_scanned_at.
_TARGETS_PER_TICK = int(
    os.environ.get("ARGUS_NUCLEI_EASM_TARGETS_PER_TICK", "20")
)
_PER_TARGET_TIMEOUT_S = int(
    os.environ.get("ARGUS_NUCLEI_EASM_TARGET_TIMEOUT", "300")
)
# nuclei -severity floor. Empty string = scan everything.
_SEVERITY_FLOOR = (
    os.environ.get("ARGUS_NUCLEI_EASM_SEVERITY", "medium,high,critical").strip()
    or None
)

_SCANNABLE_ASSET_TYPES = ("domain", "subdomain", "ip")

_NUCLEI_SEVERITY_TO_ENUM: dict[str, str] = {
    "info": Severity.LOW.value,
    "low": Severity.LOW.value,
    "medium": Severity.MEDIUM.value,
    "high": Severity.HIGH.value,
    "critical": Severity.CRITICAL.value,
    "unknown": Severity.LOW.value,
}


def _categorise(template_id: str, name: str) -> str:
    """Best-effort mapping from a Nuclei template_id / name onto our
    ExposureCategory enum. Templates we can't classify fall through to
    OTHER — better than guessing wrong on something an analyst sees."""
    t = (template_id + " " + (name or "")).lower()
    if any(k in t for k in ("cve-", "rce", "sqli", "xxe", "ssrf", "lfi", "rfi", "xss")):
        return ExposureCategory.VULNERABILITY.value
    if any(k in t for k in ("default-", "default_credential", "weak-credential")):
        return ExposureCategory.DEFAULT_CREDENTIAL.value
    if any(k in t for k in ("misconfig", "exposed-config", "exposure")):
        return ExposureCategory.MISCONFIGURATION.value
    if any(k in t for k in ("ssl-", "tls-", "weak-cipher")):
        return ExposureCategory.WEAK_CRYPTO.value
    if any(k in t for k in ("expired-cert", "ssl-issuer", "self-signed")):
        return ExposureCategory.EXPIRED_CERT.value
    if any(k in t for k in ("version", "tech-detect", "fingerprint")):
        return ExposureCategory.VERSION_DISCLOSURE.value
    if any(k in t for k in ("disclosure", "info-leak", "phpinfo")):
        return ExposureCategory.INFORMATION_DISCLOSURE.value
    if any(k in t for k in ("exposed-panel", "exposed-service", "panel")):
        return ExposureCategory.EXPOSED_SERVICE.value
    return ExposureCategory.OTHER.value


async def _persist_finding(
    session: AsyncSession,
    *,
    organization_id,
    asset_id,
    finding: dict[str, Any],
    now: datetime,
) -> None:
    """Upsert one ExposureFinding row keyed by (org, template_id, url).

    Re-observations bump ``occurrence_count`` and ``last_seen_at``;
    state is preserved so an analyst-marked ``accepted_risk`` finding
    isn't reset to OPEN on every sweep.
    """
    template_id = (finding.get("template_id") or "").strip() or "nuclei.unknown"
    target = (finding.get("url") or finding.get("matched_at") or "")[:500]
    if not target:
        return  # nuclei sometimes emits incomplete rows; skip silently

    existing = (
        await session.execute(
            select(ExposureFinding)
            .where(ExposureFinding.organization_id == organization_id)
            .where(ExposureFinding.rule_id == template_id)
            .where(ExposureFinding.target == target)
            .limit(1)
        )
    ).scalar_one_or_none()

    severity = _NUCLEI_SEVERITY_TO_ENUM.get(
        (finding.get("severity") or "").lower(), Severity.LOW.value,
    )
    category = _categorise(template_id, finding.get("name") or "")
    cve_ids = list(finding.get("cve_ids") or [])
    title = (finding.get("name") or template_id)[:500]
    description = finding.get("description") or None

    if existing is None:
        new_row = ExposureFinding(
            organization_id=organization_id,
            asset_id=asset_id,
            severity=severity,
            category=category,
            state=ExposureState.OPEN.value,
            source=ExposureSource.NUCLEI.value,
            rule_id=template_id,
            title=title,
            description=description,
            target=target,
            matched_at=now,
            last_seen_at=now,
            occurrence_count=1,
            cve_ids=cve_ids,
            cwe_ids=[],
            references=[],
            raw=finding,
        )
        session.add(new_row)
        # Hydrate EPSS / KEV / CVSS / NVD references from CveRecord at
        # insert time so the row is "complete" without waiting for the
        # next list_exposures hit. Idempotent — only fills nulls.
        if cve_ids:
            await session.flush()  # surface the new row to the enricher
            await enrich_findings(session, [new_row])
        return

    # Re-observation: bump counters, refresh severity (templates can be
    # re-graded upstream), but never resurrect a terminal-state row
    # back to OPEN — analyst's call sticks until they reopen explicitly.
    existing.last_seen_at = now
    existing.occurrence_count = (existing.occurrence_count or 0) + 1
    existing.severity = severity
    existing.category = category
    if cve_ids and existing.cve_ids != cve_ids:
        existing.cve_ids = cve_ids
        # CVE list changed — re-enrich (nullable fields will refresh, but
        # already-populated fields are preserved).
        await enrich_findings(session, [existing])
    if existing.state == ExposureState.FIXED.value:
        existing.state = ExposureState.REOPENED.value
    existing.raw = finding


async def _scan_org(
    session: AsyncSession,
    org_id,
    scanner: NucleiScanner,
    *,
    targets_remaining: int,
) -> dict[str, int]:
    """Scan up to ``targets_remaining`` assets for one org, persisting
    findings. Returns counters for the tick summary."""
    rows = (
        await session.execute(
            select(Asset)
            .where(Asset.organization_id == org_id)
            .where(Asset.asset_type.in_(_SCANNABLE_ASSET_TYPES))
            .where(Asset.is_active.is_(True))
            .where(Asset.monitoring_enabled.is_(True))
            .order_by(Asset.last_scanned_at.asc().nulls_first())
            .limit(targets_remaining)
        )
    ).scalars().all()

    summary = {"targets": 0, "findings": 0, "errors": 0}
    if not rows:
        return summary

    now = datetime.now(timezone.utc)
    for asset in rows:
        summary["targets"] += 1
        try:
            findings = await scanner.scan_target(
                asset.value,
                severity=_SEVERITY_FLOOR,
                timeout=_PER_TARGET_TIMEOUT_S,
            )
        except (ScanTimedOut, ScanFailed) as exc:
            _logger.warning(
                "nuclei scan failed for %s: %s", asset.value, exc,
            )
            summary["errors"] += 1
            asset.last_scanned_at = now  # don't retry the same asset every tick
            continue
        for f in findings:
            await _persist_finding(
                session,
                organization_id=org_id,
                asset_id=asset.id,
                finding=f,
                now=now,
            )
            summary["findings"] += 1
        asset.last_scanned_at = now

    return summary


async def tick_once() -> None:
    """One sweep across every org. Safe to call repeatedly; per-tick
    caps keep wall-clock bounded."""
    if _db.async_session_factory is None:
        return

    scanner = NucleiScanner()
    # Fast pre-flight: if the binary isn't on the host, mark
    # NOT_INSTALLED on feed_health so the inventory pill says so and
    # exit. No partial work, no failed-task spam.
    if not await scanner.check_installed():
        async with _db.async_session_factory() as session:
            await feed_health.mark_disabled(
                session,
                feed_name=FEED_NAME,
                detail="nuclei binary not detected; install in worker image to enable EASM sweep.",
            )
            await session.commit()
        return

    t0 = time.monotonic()
    totals = {"orgs": 0, "targets": 0, "findings": 0, "errors": 0}

    async with _db.async_session_factory() as session:
        orgs = (await session.execute(select(Organization))).scalars().all()
        budget = _TARGETS_PER_TICK
        for org in orgs:
            if budget <= 0:
                break
            counts = await _scan_org(
                session, org.id, scanner, targets_remaining=budget,
            )
            totals["orgs"] += 1 if counts["targets"] > 0 else 0
            totals["targets"] += counts["targets"]
            totals["findings"] += counts["findings"]
            totals["errors"] += counts["errors"]
            budget -= counts["targets"]
        await session.commit()

    duration_ms = int((time.monotonic() - t0) * 1000)
    detail = (
        f"orgs={totals['orgs']} targets={totals['targets']} "
        f"findings={totals['findings']} errors={totals['errors']} "
        f"duration_ms={duration_ms}"
    )
    async with _db.async_session_factory() as session:
        await feed_health.mark_ok(
            session,
            feed_name=FEED_NAME,
            detail=detail,
            rows_ingested=totals["findings"],
        )
        await session.commit()
    _logger.info("[nuclei_easm] tick complete — %s", detail)
