"""DiscoveryJob worker.

Public entry points:

    await claim_one(db)              atomic-claim a single QUEUED job
    await execute_job(db, job)       run the matching runner, persist results
    await tick(db, *, max_jobs=10)   pull and execute up to N jobs in one pass

Persistence rules
-----------------
- Subdomain & port-scan results land in ``DiscoveryFinding`` with
  state=NEW. Auto-promotion is intentionally not done here — Phase 1.2
  will introduce trust rules.
- HTTPX probe enriches an existing ``Asset.details`` payload (if the
  asset is a domain/subdomain/service) and emits ``AssetChange`` rows
  for any meaningful drift (status code, title, tech stack, IPs, TLS
  cert fingerprint).
- DNS refresh updates ``email_domain`` assets in place when present and
  emits SPF/DKIM/DMARC change events.
- WHOIS refresh updates the matching ``domain`` asset's details.

Every code path commits at the end and never raises out of the worker
loop — failures are recorded on the job row.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import and_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.asset_schemas import AssetType, DiscoveryMethod, canonicalize_asset_value
from src.models.easm import (
    AssetChange,
    ChangeKind,
    ChangeSeverity,
    DiscoveryFinding,
    FindingState,
)
from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSeverity,
    ExposureSource,
    ExposureState,
)
from src.models.onboarding import (
    DiscoveryJob,
    DiscoveryJobKind,
    DiscoveryJobStatus,
)
from src.models.threat import Asset

from .runners import RunnerOutput, get_runner_registry


_logger = logging.getLogger(__name__)


# --- Atomic claim ------------------------------------------------------


async def claim_one(db: AsyncSession) -> DiscoveryJob | None:
    """Atomic-claim a single QUEUED job using ``SELECT ... FOR UPDATE SKIP LOCKED``.

    Multiple workers can run safely against the same queue.
    """
    # Postgres-specific. We also require the row to *still* be queued
    # at the moment of UPDATE.
    stmt = text(
        """
        UPDATE discovery_jobs
        SET status = 'running',
            started_at = NOW(),
            updated_at = NOW()
        WHERE id = (
            SELECT id FROM discovery_jobs
            WHERE status = 'queued'
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        RETURNING id
        """
    )
    row = (await db.execute(stmt)).first()
    await db.commit()
    if row is None:
        return None
    return await db.get(DiscoveryJob, row[0])


# --- Result persistence helpers ----------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _record_change(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID | None,
    job_id: uuid.UUID,
    kind: ChangeKind,
    severity: ChangeSeverity,
    summary: str,
    before: Any = None,
    after: Any = None,
) -> AssetChange:
    change = AssetChange(
        organization_id=organization_id,
        asset_id=asset_id,
        discovery_job_id=job_id,
        kind=kind.value,
        severity=severity.value,
        summary=summary,
        before=before if before is None or isinstance(before, dict) else {"value": before},
        after=after if after is None or isinstance(after, dict) else {"value": after},
        detected_at=_now(),
    )
    db.add(change)
    await db.flush()
    return change


async def _existing_asset(
    db: AsyncSession,
    organization_id: uuid.UUID,
    asset_type: AssetType,
    value: str,
) -> Asset | None:
    res = await db.execute(
        select(Asset).where(
            and_(
                Asset.organization_id == organization_id,
                Asset.asset_type == asset_type.value,
                Asset.value == value,
            )
        )
    )
    return res.scalar_one_or_none()


async def _upsert_finding(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    job: DiscoveryJob,
    asset_type: AssetType,
    value: str,
    details: dict | None,
    discovered_via: str,
    confidence: float,
) -> tuple[DiscoveryFinding | None, bool]:
    """Insert a finding if not already present (NEW state). Returns
    (finding, created_new_flag).
    """
    try:
        canonical = canonicalize_asset_value(asset_type, value)
    except ValueError as e:
        _logger.warning("rejecting invalid finding value %r: %s", value, e)
        return None, False

    # Skip if it already exists as a confirmed Asset
    if await _existing_asset(db, organization_id, asset_type, canonical):
        return None, False

    existing = await db.execute(
        select(DiscoveryFinding).where(
            and_(
                DiscoveryFinding.organization_id == organization_id,
                DiscoveryFinding.asset_type == asset_type.value,
                DiscoveryFinding.value == canonical,
                DiscoveryFinding.state == FindingState.NEW.value,
            )
        )
    )
    found = existing.scalar_one_or_none()
    if found is not None:
        # Bump confidence if higher and update raw context.
        if confidence > found.confidence:
            found.confidence = confidence
        return found, False

    finding = DiscoveryFinding(
        organization_id=organization_id,
        discovery_job_id=job.id,
        parent_asset_id=job.asset_id,
        asset_type=asset_type.value,
        value=canonical,
        details=details,
        confidence=confidence,
        discovered_via=discovered_via,
        raw={"job_id": str(job.id)},
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None, False
    return finding, True


# --- Per-kind handlers -------------------------------------------------


async def _handle_subdomain_enum(
    db: AsyncSession, job: DiscoveryJob, output: RunnerOutput
) -> dict[str, Any]:
    new_findings = 0
    for item in output.items:
        host = (item.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        # Skip if it's the apex domain itself
        if host == job.target.lower():
            continue
        finding, created = await _upsert_finding(
            db,
            organization_id=job.organization_id,
            job=job,
            asset_type=AssetType.SUBDOMAIN,
            value=host,
            details={"parent_domain": job.target.lower(), "discovered_via": item.get("source") or "subfinder"},
            discovered_via="subfinder",
            confidence=0.7,
        )
        if created and finding is not None:
            new_findings += 1
            await _record_change(
                db,
                organization_id=job.organization_id,
                asset_id=None,
                job_id=job.id,
                kind=ChangeKind.ASSET_CREATED,
                severity=ChangeSeverity.MEDIUM,
                summary=f"New subdomain discovered: {host}",
                after={"asset_type": "subdomain", "value": host},
            )
    return {"new_findings": new_findings, "total_observations": len(output.items)}


async def _handle_port_scan(
    db: AsyncSession, job: DiscoveryJob, output: RunnerOutput
) -> dict[str, Any]:
    """Each (host, port) becomes a service finding.  Also emits
    PORT_OPENED diff entries against the source asset."""
    new = 0
    for item in output.items:
        host = item.get("host")
        port = item.get("port")
        proto = item.get("protocol", "tcp")
        if not host or not port:
            continue
        value = f"{host.lower()}:{port}"
        finding, created = await _upsert_finding(
            db,
            organization_id=job.organization_id,
            job=job,
            asset_type=AssetType.SERVICE,
            value=value,
            details={"host": host, "port": int(port), "protocol": proto},
            discovered_via="naabu",
            confidence=0.85,
        )
        if created and finding is not None:
            new += 1
            await _record_change(
                db,
                organization_id=job.organization_id,
                asset_id=job.asset_id,
                job_id=job.id,
                kind=ChangeKind.PORT_OPENED,
                severity=ChangeSeverity.HIGH,
                summary=f"Port {port}/{proto} open on {host}",
                after={"host": host, "port": int(port), "protocol": proto},
            )
    return {"new_findings": new, "total_observations": len(output.items)}


_SIGNIFICANT_HTTPX_FIELDS = (
    "status_code",
    "title",
    "tech",
    "ips",
    "tls",
)


async def _handle_httpx_probe(
    db: AsyncSession, job: DiscoveryJob, output: RunnerOutput
) -> dict[str, Any]:
    """Enrich existing assets and emit HTTP_*_CHANGED events when state drifts."""
    enriched = 0
    changes = 0
    for item in output.items:
        host = (item.get("host") or item.get("input") or "").lower().rstrip(".")
        if not host:
            continue
        # Try to bind to an existing domain or subdomain asset.
        asset = None
        for atype in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
            asset = await _existing_asset(db, job.organization_id, atype, host)
            if asset is not None:
                break
        if asset is None:
            # Promote to a finding so the analyst can confirm.
            await _upsert_finding(
                db,
                organization_id=job.organization_id,
                job=job,
                asset_type=AssetType.SUBDOMAIN,
                value=host,
                details={"parent_domain": job.target.lower(), "discovered_via": "httpx"},
                discovered_via="httpx",
                confidence=0.65,
            )
            continue

        before_details = dict(asset.details or {})
        new_details = dict(before_details)
        http_state = {
            "status_code": item.get("status_code"),
            "title": item.get("title"),
            "tech": list(item.get("tech") or []),
            "ips": list(item.get("ips") or []),
            "tls": item.get("tls") or {},
            "url": item.get("url"),
        }
        previous_http = before_details.get("http") or {}
        new_details["http"] = http_state

        diff_kinds: list[tuple[ChangeKind, str, Any, Any]] = []

        if previous_http.get("status_code") != http_state.get("status_code"):
            diff_kinds.append(
                (
                    ChangeKind.HTTP_STATUS_CHANGED,
                    f"HTTP status on {host}: {previous_http.get('status_code')} → {http_state.get('status_code')}",
                    previous_http.get("status_code"),
                    http_state.get("status_code"),
                )
            )
        if (previous_http.get("title") or "") != (http_state.get("title") or ""):
            diff_kinds.append(
                (
                    ChangeKind.HTTP_TITLE_CHANGED,
                    f"HTTP title on {host} changed",
                    previous_http.get("title"),
                    http_state.get("title"),
                )
            )
        if sorted(previous_http.get("tech") or []) != sorted(http_state.get("tech") or []):
            diff_kinds.append(
                (
                    ChangeKind.HTTP_TECH_CHANGED,
                    f"Tech stack on {host} changed",
                    previous_http.get("tech"),
                    http_state.get("tech"),
                )
            )
        if (previous_http.get("tls") or {}).get("fingerprint_sha256") != (
            http_state.get("tls") or {}
        ).get("fingerprint_sha256"):
            diff_kinds.append(
                (
                    ChangeKind.TLS_CERT_CHANGED,
                    f"TLS cert on {host} rotated",
                    (previous_http.get("tls") or {}).get("fingerprint_sha256"),
                    (http_state.get("tls") or {}).get("fingerprint_sha256"),
                )
            )

        asset.details = new_details
        asset.last_scanned_at = _now()
        if diff_kinds:
            asset.last_change_at = _now()
            for kind, summary, before, after in diff_kinds:
                sev = (
                    ChangeSeverity.HIGH
                    if kind == ChangeKind.TLS_CERT_CHANGED
                    else ChangeSeverity.MEDIUM
                )
                await _record_change(
                    db,
                    organization_id=job.organization_id,
                    asset_id=asset.id,
                    job_id=job.id,
                    kind=kind,
                    severity=sev,
                    summary=summary,
                    before={"value": before} if not isinstance(before, dict) else before,
                    after={"value": after} if not isinstance(after, dict) else after,
                )
            changes += len(diff_kinds)
        enriched += 1

    return {"enriched_assets": enriched, "changes_recorded": changes}


async def _handle_dns_refresh(
    db: AsyncSession, job: DiscoveryJob, output: RunnerOutput
) -> dict[str, Any]:
    if not output.items:
        return {"records": 0}
    rec = output.items[0]
    domain = (rec.get("domain") or job.target).lower().rstrip(".")

    # Try email_domain first (DMARC monitoring), then domain.
    asset = await _existing_asset(
        db, job.organization_id, AssetType.EMAIL_DOMAIN, domain
    )
    if asset is None:
        asset = await _existing_asset(
            db, job.organization_id, AssetType.DOMAIN, domain
        )
    if asset is None:
        return {"records": 0, "note": "no matching domain/email_domain asset"}

    before_details = dict(asset.details or {})
    after_details = dict(before_details)
    after_details["dns"] = {
        "a": rec.get("a") or [],
        "aaaa": rec.get("aaaa") or [],
        "mx": rec.get("mx") or [],
        "ns": rec.get("ns") or [],
        "txt": rec.get("txt") or [],
        "spf": rec.get("spf"),
        "dmarc": rec.get("dmarc"),
    }

    changes_made = 0
    prev_dns = before_details.get("dns") or {}

    def _diff(field: str, kind: ChangeKind, severity: ChangeSeverity):
        nonlocal changes_made
        before_v = prev_dns.get(field)
        after_v = after_details["dns"].get(field)
        if before_v != after_v:
            changes_made += 1
            return _record_change(
                db,
                organization_id=job.organization_id,
                asset_id=asset.id,
                job_id=job.id,
                kind=kind,
                severity=severity,
                summary=f"{field.upper()} on {domain} changed",
                before={"value": before_v},
                after={"value": after_v},
            )
        return None

    awaitables = [
        _diff("a", ChangeKind.DNS_A_CHANGED, ChangeSeverity.MEDIUM),
        _diff("mx", ChangeKind.DNS_MX_CHANGED, ChangeSeverity.HIGH),
        _diff("ns", ChangeKind.DNS_NS_CHANGED, ChangeSeverity.HIGH),
        _diff("spf", ChangeKind.SPF_CHANGED, ChangeSeverity.HIGH),
        _diff("dmarc", ChangeKind.DMARC_CHANGED, ChangeSeverity.HIGH),
    ]
    for a in awaitables:
        if a is not None:
            await a

    asset.details = after_details
    asset.last_scanned_at = _now()
    if changes_made:
        asset.last_change_at = _now()
    return {"records": 1, "changes": changes_made}


async def _handle_whois_refresh(
    db: AsyncSession, job: DiscoveryJob, output: RunnerOutput
) -> dict[str, Any]:
    if not output.items:
        return {"records": 0}
    rec = output.items[0]
    domain = (rec.get("domain") or job.target).lower().rstrip(".")
    asset = await _existing_asset(
        db, job.organization_id, AssetType.DOMAIN, domain
    )
    if asset is None:
        return {"records": 0, "note": "no matching domain asset"}

    before = dict(asset.details or {})
    after = dict(before)
    whois_block = {
        "registrar": rec.get("registrar"),
        "creation_date": rec.get("creation_date"),
        "expiration_date": rec.get("expiration_date"),
        "name_servers": sorted(rec.get("name_servers") or []),
        "status": rec.get("status"),
    }
    after["whois"] = whois_block
    prev = before.get("whois") or {}

    if prev.get("registrar") and prev.get("registrar") != whois_block["registrar"]:
        await _record_change(
            db,
            organization_id=job.organization_id,
            asset_id=asset.id,
            job_id=job.id,
            kind=ChangeKind.WHOIS_REGISTRAR_CHANGED,
            severity=ChangeSeverity.HIGH,
            summary=f"Registrar for {domain} changed",
            before={"registrar": prev.get("registrar")},
            after={"registrar": whois_block["registrar"]},
        )

    asset.details = after
    asset.last_scanned_at = _now()
    return {"records": 1}


async def _upsert_exposure(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    job: DiscoveryJob,
    source: ExposureSource,
    rule_id: str,
    title: str,
    description: str | None,
    severity: ExposureSeverity,
    category: ExposureCategory,
    target: str,
    cve_ids: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    cvss_score: float | None = None,
    references: list[str] | None = None,
    matcher_data: dict | None = None,
    raw: dict | None = None,
) -> tuple[ExposureFinding, bool]:
    """Insert-or-bump an ExposureFinding. Returns (row, created_new)."""
    existing = (
        await db.execute(
            select(ExposureFinding).where(
                and_(
                    ExposureFinding.organization_id == organization_id,
                    ExposureFinding.rule_id == rule_id,
                    ExposureFinding.target == target,
                )
            )
        )
    ).scalar_one_or_none()

    now = _now()

    if existing is not None:
        existing.last_seen_at = now
        existing.occurrence_count += 1
        # Re-open if it was previously fixed.
        if existing.state == ExposureState.FIXED.value:
            existing.state = ExposureState.REOPENED.value
            existing.state_changed_at = now
            existing.state_reason = "Re-detected by scanner"
        return existing, False

    asset = await _find_asset_for_target(db, organization_id, target)
    finding = ExposureFinding(
        organization_id=organization_id,
        asset_id=asset.id if asset else None,
        discovery_job_id=job.id,
        severity=severity.value,
        category=category.value,
        state=ExposureState.OPEN.value,
        source=source.value,
        rule_id=rule_id,
        title=title,
        description=description,
        target=target,
        matched_at=now,
        last_seen_at=now,
        occurrence_count=1,
        cvss_score=cvss_score,
        cve_ids=cve_ids or [],
        cwe_ids=cwe_ids or [],
        references=references or [],
        matcher_data=matcher_data,
        raw=raw,
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        # Race; treat as existing
        existing = (
            await db.execute(
                select(ExposureFinding).where(
                    and_(
                        ExposureFinding.organization_id == organization_id,
                        ExposureFinding.rule_id == rule_id,
                        ExposureFinding.target == target,
                    )
                )
            )
        ).scalar_one()
        existing.last_seen_at = now
        existing.occurrence_count += 1
        return existing, False

    # Audit D12 + D13 — auto-link to a Case and dispatch a notification
    # for any newly-detected exposure. Failures here MUST NOT block the
    # exposure insert above, so the helper internally swallows
    # notification errors and the caller's transaction handles commit.
    try:
        from src.cases.auto_link import auto_link_finding

        await auto_link_finding(
            db,
            organization_id=organization_id,
            finding_type="exposure",
            finding_id=finding.id,
            severity=severity.value,
            title=title[:500],
            summary=description,
            event_kind="alert",
            dedup_key=f"exposure:{rule_id}:{target}",
            tags=("exposure", category.value),
        )
    except Exception:  # noqa: BLE001
        _logger.exception("auto_link_finding failed for exposure %s", finding.id)

    return finding, True


async def _find_asset_for_target(
    db: AsyncSession, organization_id: uuid.UUID, target: str
) -> Asset | None:
    """Best-effort match a scan target back to an Asset row.

    Tries exact value match across (domain, subdomain, ip_address, service).
    """
    target = (target or "").lower().strip()
    if not target:
        return None
    candidates = (
        await db.execute(
            select(Asset).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.value == target,
                )
            )
        )
    ).scalars().all()
    if candidates:
        return candidates[0]
    # Strip URL scheme if present.
    if "://" in target:
        from urllib.parse import urlparse

        host = urlparse(target).hostname or ""
        if host:
            return await _find_asset_for_target(db, organization_id, host)
    return None


_NUCLEI_SEVERITY_MAP = {
    "critical": ExposureSeverity.CRITICAL,
    "high": ExposureSeverity.HIGH,
    "medium": ExposureSeverity.MEDIUM,
    "low": ExposureSeverity.LOW,
    "info": ExposureSeverity.INFO,
    "unknown": ExposureSeverity.INFO,
}


def _categorize_nuclei(item: dict) -> ExposureCategory:
    rule_id = (item.get("rule_id") or "").lower()
    tags = [t.lower() for t in (item.get("tags") or [])]
    # CVE → vulnerability is the strongest signal.
    if item.get("cve_ids"):
        return ExposureCategory.VULNERABILITY
    if "default-login" in rule_id or "default-credential" in rule_id:
        return ExposureCategory.DEFAULT_CREDENTIAL
    # Exposed-{thing} rules dominate over the substring "config"; many
    # nuclei templates name themselves "exposed-git-config", "exposed-env"
    # etc. — these are exposure templates, not misconfig templates.
    if (
        "exposed" in rule_id
        or "exposure" in tags
        or rule_id.startswith("exposures/")
    ):
        return ExposureCategory.EXPOSED_SERVICE
    if "misconfig" in rule_id or "misconfig" in tags or "config" in tags:
        return ExposureCategory.MISCONFIGURATION
    if "version" in rule_id or "tech" in tags:
        return ExposureCategory.VERSION_DISCLOSURE
    return ExposureCategory.OTHER


async def _handle_vuln_scan(
    db: AsyncSession, job: DiscoveryJob, output
) -> dict[str, Any]:
    new_count = 0
    for item in output.items:
        target = item.get("matched_at") or item.get("url") or item.get("host") or job.target
        sev_raw = (item.get("severity") or "info").lower()
        severity = _NUCLEI_SEVERITY_MAP.get(sev_raw, ExposureSeverity.INFO)
        category = _categorize_nuclei(item)
        _, created = await _upsert_exposure(
            db,
            organization_id=job.organization_id,
            job=job,
            source=ExposureSource.NUCLEI,
            rule_id=item.get("rule_id") or "unknown",
            title=item.get("name") or item.get("rule_id") or "Nuclei finding",
            description=item.get("description"),
            severity=severity,
            category=category,
            target=target,
            cve_ids=item.get("cve_ids") or [],
            cwe_ids=item.get("cwe_ids") or [],
            cvss_score=item.get("cvss_score"),
            references=item.get("references") or [],
            matcher_data={"tags": item.get("tags") or []},
            raw=item.get("raw"),
        )
        if created:
            new_count += 1
    return {"new_exposures": new_count, "total_observations": len(output.items)}


async def _handle_service_version(
    db: AsyncSession, job: DiscoveryJob, output
) -> dict[str, Any]:
    """Update service-asset details with banner/version. Emit
    SERVICE_BANNER_CHANGED on drift. No exposures created here; the
    sister TLS audit + nuclei jobs do that. We do, however, raise
    ``version_disclosure`` exposures when a banner reveals a precise
    product+version.
    """
    enriched = 0
    new_exposures = 0
    for item in output.items:
        host = item.get("host")
        port = item.get("port")
        if not host or not port:
            continue
        target = f"{host.lower()}:{port}"
        asset = await _existing_asset(
            db, job.organization_id, AssetType.SERVICE, target
        )
        new_banner = {
            "service": item.get("service"),
            "product": item.get("product"),
            "version": item.get("version"),
            "extrainfo": item.get("extrainfo"),
        }
        if asset is not None:
            old_banner = (asset.details or {}).get("banner") or {}
            if old_banner != new_banner:
                new_details = dict(asset.details or {})
                new_details["banner"] = new_banner
                asset.details = new_details
                asset.last_change_at = _now()
                await _record_change(
                    db,
                    organization_id=job.organization_id,
                    asset_id=asset.id,
                    job_id=job.id,
                    kind=ChangeKind.SERVICE_BANNER_CHANGED,
                    severity=ChangeSeverity.MEDIUM,
                    summary=f"Service banner changed on {target}",
                    before=old_banner,
                    after=new_banner,
                )
            asset.last_scanned_at = _now()
            enriched += 1
        if item.get("product") and item.get("version"):
            rule_id = f"nmap:version-disclosure:{item.get('service') or 'unknown'}"
            title = (
                f"{item.get('product')} {item.get('version')} version disclosed"
                f" on {item.get('service')}"
            )
            _, created = await _upsert_exposure(
                db,
                organization_id=job.organization_id,
                job=job,
                source=ExposureSource.NMAP,
                rule_id=rule_id,
                title=title,
                description=(
                    "Service banner reveals a precise product and version, "
                    "aiding attacker reconnaissance."
                ),
                severity=ExposureSeverity.LOW,
                category=ExposureCategory.VERSION_DISCLOSURE,
                target=target,
                matcher_data=new_banner,
            )
            if created:
                new_exposures += 1
    return {"enriched_assets": enriched, "new_exposures": new_exposures}


_TESTSSL_SEV = {
    "high": ExposureSeverity.HIGH,
    "critical": ExposureSeverity.CRITICAL,
    "medium": ExposureSeverity.MEDIUM,
    "warn": ExposureSeverity.MEDIUM,
}


def _categorize_testssl(item: dict) -> ExposureCategory:
    section = (item.get("section") or "").lower()
    rule = (item.get("id") or "").lower()
    if "expired" in rule or "expir" in (item.get("finding") or "").lower():
        return ExposureCategory.EXPIRED_CERT
    if "self-signed" in rule or "self_signed" in rule:
        return ExposureCategory.SELF_SIGNED_CERT
    if section == "vulnerabilities":
        return ExposureCategory.VULNERABILITY
    return ExposureCategory.WEAK_CRYPTO


async def _handle_tls_audit(
    db: AsyncSession, job: DiscoveryJob, output
) -> dict[str, Any]:
    new_count = 0
    for item in output.items:
        target = job.target
        if item.get("ip") and item.get("port"):
            target = f"{item['ip'].lower()}:{item['port']}"
        sev_raw = (item.get("severity") or "info").lower()
        severity = _TESTSSL_SEV.get(sev_raw, ExposureSeverity.INFO)
        if severity == ExposureSeverity.INFO:
            continue
        category = _categorize_testssl(item)
        rule_id = f"testssl:{item.get('id') or 'unknown'}"
        cve_ids = []
        if cve := item.get("cve"):
            cve_ids = [c.strip().upper() for c in cve.split() if c.strip()]
        cwe_ids = []
        if cwe := item.get("cwe"):
            cwe_ids = [c.strip().upper() for c in cwe.split() if c.strip()]
        _, created = await _upsert_exposure(
            db,
            organization_id=job.organization_id,
            job=job,
            source=ExposureSource.TESTSSL,
            rule_id=rule_id,
            title=f"{item.get('id') or 'TLS issue'}: {item.get('finding') or ''}".strip(),
            description=item.get("finding"),
            severity=severity,
            category=category,
            target=target,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            matcher_data={"section": item.get("section")},
            raw=item,
        )
        if created:
            new_count += 1
    return {"new_exposures": new_count, "total_observations": len(output.items)}


_HANDLERS = {
    DiscoveryJobKind.SUBDOMAIN_ENUM.value: _handle_subdomain_enum,
    DiscoveryJobKind.HTTPX_PROBE.value: _handle_httpx_probe,
    DiscoveryJobKind.PORT_SCAN.value: _handle_port_scan,
    DiscoveryJobKind.DNS_REFRESH.value: _handle_dns_refresh,
    DiscoveryJobKind.WHOIS_REFRESH.value: _handle_whois_refresh,
    DiscoveryJobKind.VULN_SCAN.value: _handle_vuln_scan,
    DiscoveryJobKind.SERVICE_VERSION.value: _handle_service_version,
    DiscoveryJobKind.TLS_AUDIT.value: _handle_tls_audit,
}


# --- Execution ---------------------------------------------------------


async def execute_job(db: AsyncSession, job: DiscoveryJob) -> dict[str, Any]:
    """Run the runner for ``job.kind`` and persist results."""
    handler = _HANDLERS.get(job.kind)
    runners = get_runner_registry()
    runner = runners.get(job.kind)

    if handler is None or runner is None:
        await _mark_failed(db, job, f"no handler/runner for kind {job.kind}")
        return {"succeeded": False, "error": f"no handler for {job.kind}"}

    try:
        output = await runner.run(job.target, job.parameters or {})
    except Exception as e:  # noqa: BLE001
        await _mark_failed(db, job, f"runner crashed: {e}")
        return {"succeeded": False, "error": str(e)}

    if not output.succeeded:
        await _mark_failed(db, job, output.error_message or "runner returned no items")
        return {"succeeded": False, "error": output.error_message}

    summary = await handler(db, job, output)

    job.status = DiscoveryJobStatus.SUCCEEDED.value
    job.finished_at = _now()
    job.error_message = None
    job.result_summary = {
        **summary,
        "raw_count": len(output.items),
        "duration_ms": output.duration_ms,
    }
    await db.commit()
    return {"succeeded": True, **summary}


async def _mark_failed(db: AsyncSession, job: DiscoveryJob, message: str) -> None:
    job.status = DiscoveryJobStatus.FAILED.value
    job.finished_at = _now()
    job.error_message = message[:1000]
    await db.commit()


async def tick(db: AsyncSession, *, max_jobs: int = 10) -> list[dict[str, Any]]:
    """Pull and execute up to ``max_jobs`` queued jobs.  Returns per-job summaries."""
    out: list[dict[str, Any]] = []
    for _ in range(max_jobs):
        job = await claim_one(db)
        if job is None:
            break
        result = await execute_job(db, job)
        out.append({"job_id": str(job.id), "kind": job.kind, **result})
    return out


__all__ = ["claim_one", "execute_job", "tick"]
