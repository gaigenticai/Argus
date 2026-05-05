"""Scheduled Prowler cloud-security audit.

Runs the Prowler CLI (already wired at
``src/integrations/prowler/client.py``) against whichever cloud
providers the operator has configured creds for, and persists the
``status="fail"`` findings as ExposureFinding rows.

Provider activation is detected from the standard cloud SDK env vars
that Prowler itself reads:

  * AWS    — ``AWS_ACCESS_KEY_ID`` + ``AWS_SECRET_ACCESS_KEY``
             (or ``AWS_PROFILE`` / IMDS in EC2 deployments)
  * Azure  — ``AZURE_TENANT_ID`` + ``AZURE_CLIENT_ID`` + ``AZURE_CLIENT_SECRET``
  * GCP    — ``GOOGLE_APPLICATION_CREDENTIALS`` pointing at a service-account JSON
  * K8s    — ``KUBECONFIG`` or in-cluster service account

Operators paste these into Settings → Services on the Prowler row;
the integration_keys cache is read first, env-fallback after, so a
DB-stored key wins. The worker doesn't manipulate creds itself — it
just sets them on the subprocess env right before launching Prowler.

Behaviour per tick (default once weekly):

    1. Pre-flight: ``ProwlerRunner.check_installed()``. If absent,
       ``mark_disabled`` and exit (the inventory pill goes to
       not_installed).
    2. For each provider with creds detected, run a scan with the
       configured wall-clock budget.
    3. For findings with ``status="fail"``, upsert into
       exposure_findings keyed by (org, rule_id, target). Re-observed
       findings bump occurrence_count; ``fixed`` rows that flip back
       to fail get reopened.
    4. Record ``maintenance.prowler_audit`` feed_health with the per-
       provider tally so Service Inventory shows OK once a tick lands.

Replaces a one-shot ``scripts/run_prowler.sh`` operator habit — the
worker keeps cloud findings current without anyone touching a CLI.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.integrations.prowler.client import (
    BinaryNotFound,
    ProwlerRunner,
    ScanFailed,
    ScanTimedOut,
)
from src.models.common import Severity
from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSource,
    ExposureState,
)
from src.models.threat import Organization
from src.storage import database as _db

_logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.prowler_audit"

_PER_PROVIDER_TIMEOUT_S = int(
    os.environ.get("ARGUS_PROWLER_TIMEOUT_S", "1800")  # 30min default
)

_PROWLER_SEVERITY_TO_ENUM: dict[str, str] = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "informational": Severity.LOW.value,
    "info": Severity.LOW.value,
}


def _detect_active_providers() -> list[str]:
    """Return the list of cloud providers the operator has configured.

    Inspects standard SDK env vars / config-file presence — same
    discovery Prowler does internally. Returns provider names ready
    to pass to ``ProwlerRunner.run_scan(provider=…)``.
    """
    providers: list[str] = []
    if (
        os.environ.get("AWS_ACCESS_KEY_ID")
        or os.environ.get("AWS_PROFILE")
        or os.environ.get("AWS_ROLE_ARN")
        or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
    ):
        providers.append("aws")
    if (
        os.environ.get("AZURE_TENANT_ID")
        and os.environ.get("AZURE_CLIENT_ID")
        and os.environ.get("AZURE_CLIENT_SECRET")
    ):
        providers.append("azure")
    if (
        os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
    ):
        providers.append("gcp")
    if (
        os.environ.get("KUBECONFIG")
        or os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ):
        providers.append("kubernetes")
    return providers


def _stable_rule_id(provider: str, finding: dict[str, Any]) -> str:
    """Synthesise a stable rule_id Prowler doesn't always supply.

    Prowler's "CheckTitle" is human-friendly but inconsistent across
    versions; the stable identifier is provider+service+title hashed,
    which gives us upsert-safe keys regardless of upstream rewording.
    """
    seed = f"{provider}|{finding.get('service','')}|{finding.get('finding','')}"
    return f"prowler.{provider}." + hashlib.sha1(seed.encode()).hexdigest()[:16]


def _categorise(finding: dict[str, Any]) -> str:
    """Best-effort Prowler→ExposureCategory mapping. Cloud findings
    are mostly misconfigurations + exposed services; rare enough that
    we don't need a long table."""
    title = (finding.get("finding", "") or "").lower()
    if any(k in title for k in ("public", "exposed", "open to internet", "0.0.0.0/0")):
        return ExposureCategory.EXPOSED_SERVICE.value
    if "encryption" in title or "kms" in title or "tls" in title:
        return ExposureCategory.WEAK_CRYPTO.value
    if "credential" in title or "iam" in title and "key" in title:
        return ExposureCategory.DEFAULT_CREDENTIAL.value
    return ExposureCategory.MISCONFIGURATION.value


async def _persist_finding(
    session: AsyncSession,
    *,
    organization_id,
    provider: str,
    finding: dict[str, Any],
    now: datetime,
) -> None:
    rule_id = _stable_rule_id(provider, finding)
    target = (finding.get("resource") or "?")[:500]
    existing = (
        await session.execute(
            select(ExposureFinding)
            .where(ExposureFinding.organization_id == organization_id)
            .where(ExposureFinding.rule_id == rule_id)
            .where(ExposureFinding.target == target)
            .limit(1)
        )
    ).scalar_one_or_none()

    severity = _PROWLER_SEVERITY_TO_ENUM.get(
        (finding.get("severity") or "").lower(), Severity.LOW.value,
    )
    category = _categorise(finding)
    title = (finding.get("finding") or rule_id)[:500]
    description = finding.get("remediation") or None

    if existing is None:
        session.add(ExposureFinding(
            organization_id=organization_id,
            asset_id=None,  # cloud resources aren't in our Asset table yet
            severity=severity,
            category=category,
            state=ExposureState.OPEN.value,
            source=ExposureSource.PROWLER.value,
            rule_id=rule_id,
            title=title,
            description=description,
            target=target,
            matched_at=now,
            last_seen_at=now,
            occurrence_count=1,
            cve_ids=[],
            cwe_ids=[],
            references=[],
            raw=finding,
        ))
        return

    existing.last_seen_at = now
    existing.occurrence_count = (existing.occurrence_count or 0) + 1
    existing.severity = severity
    existing.category = category
    if existing.state == ExposureState.FIXED.value:
        existing.state = ExposureState.REOPENED.value
    existing.raw = finding


async def tick_once() -> None:
    if _db.async_session_factory is None:
        return

    runner = ProwlerRunner()
    if not await runner.check_installed():
        async with _db.async_session_factory() as session:
            await feed_health.mark_disabled(
                session,
                feed_name=FEED_NAME,
                detail="prowler binary not detected; install in worker image to enable cloud audits.",
            )
            await session.commit()
        return

    providers = _detect_active_providers()
    if not providers:
        async with _db.async_session_factory() as session:
            await feed_health.mark_unconfigured(
                session,
                feed_name=FEED_NAME,
                detail=(
                    "No cloud creds detected. Set AWS_*, AZURE_*, "
                    "GOOGLE_APPLICATION_CREDENTIALS, or KUBECONFIG via "
                    "Settings → Services to enable scheduled audits."
                ),
            )
            await session.commit()
        return

    t0 = time.monotonic()
    per_provider: dict[str, dict[str, int]] = {}
    total_findings = 0
    total_errors = 0

    async with _db.async_session_factory() as session:
        # Cloud audits aren't tenant-scoped — tag findings to the
        # system org. If you want per-tenant cloud auditing later,
        # extend this to iterate orgs and read per-org cred bundles.
        from src.core.tenant import get_system_org_id
        org_id = await get_system_org_id(session)

        for provider in providers:
            counts = {"findings": 0, "errors": 0}
            try:
                findings = await runner.run_scan(
                    provider=provider, timeout=_PER_PROVIDER_TIMEOUT_S,
                )
            except (ScanTimedOut, ScanFailed, BinaryNotFound) as exc:
                _logger.warning(
                    "[prowler_audit] %s scan failed: %s", provider, exc,
                )
                counts["errors"] = 1
                total_errors += 1
                per_provider[provider] = counts
                continue

            now = datetime.now(timezone.utc)
            for f in findings:
                if (f.get("status") or "").lower() != "fail":
                    continue
                try:
                    await _persist_finding(
                        session,
                        organization_id=org_id,
                        provider=provider,
                        finding=f,
                        now=now,
                    )
                    counts["findings"] += 1
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "[prowler_audit] %s persist failed: %s", provider, exc,
                    )
                    counts["errors"] += 1
            per_provider[provider] = counts
            total_findings += counts["findings"]
            total_errors += counts["errors"]

        await session.commit()

    duration_ms = int((time.monotonic() - t0) * 1000)
    detail = (
        f"providers={','.join(providers)} findings={total_findings} "
        f"errors={total_errors} duration_ms={duration_ms} "
        + " ".join(f"{p}={c['findings']}/{c['errors']}" for p, c in per_provider.items())
    )
    async with _db.async_session_factory() as session:
        await feed_health.mark_ok(
            session,
            feed_name=FEED_NAME,
            detail=detail,
            rows_ingested=total_findings,
        )
        await session.commit()
    _logger.info("[prowler_audit] tick complete — %s", detail)
