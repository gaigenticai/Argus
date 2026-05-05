"""Collect every vendor posture signal in one pass.

Wires together:
  * email_security.assess_email_security  (DMARC/SPF/DKIM)
  * breach_hibp.assess_vendor_breach      (HIBP per probable email)
  * sanctions.screen_vendor               (OFAC/OFSI/EU)
  * github_leaks.scan_org                 (when github_org in details)
  * typosquat scan via existing brand suspects (cert-stream signal)
  * nuclei results (already populated by EASM worker; we just count them)

For each signal source the helper UPSERTs a row into
``vendor_posture_signals`` (kind = signal name) so analysts get a
machine-readable trail per vendor.

Returns a dict ``{kind: VendorPostureSignal-shaped dict}`` for the
caller (scorer + scorecard summary).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.threat import Asset
from src.models.tprm import (
    VendorPostureSignal,
    VendorSanctionsCheck,
)
from src.tprm.breach_hibp import assess_vendor_breach
from src.tprm.email_security import assess_email_security
from src.tprm.github_leaks import scan_org as scan_github_org
from src.tprm.github_leaks import severity_to_score
from src.tprm.sanctions import screen_vendor

_logger = logging.getLogger(__name__)


def _severity_for_score(score: float) -> str:
    if score >= 90:
        return "info"
    if score >= 70:
        return "low"
    if score >= 50:
        return "medium"
    if score >= 30:
        return "high"
    return "critical"


async def _upsert_signal(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    vendor_asset_id: uuid.UUID,
    kind: str,
    score: float,
    summary: str,
    evidence: dict[str, Any],
) -> None:
    existing = (
        await db.execute(
            select(VendorPostureSignal).where(
                VendorPostureSignal.vendor_asset_id == vendor_asset_id,
                VendorPostureSignal.kind == kind,
            )
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    sev = _severity_for_score(score)
    if existing is None:
        db.add(
            VendorPostureSignal(
                organization_id=organization_id,
                vendor_asset_id=vendor_asset_id,
                kind=kind,
                severity=sev,
                score=float(score),
                summary=summary[:1000],
                evidence=evidence,
                collected_at=now,
            )
        )
    else:
        existing.score = float(score)
        existing.severity = sev
        existing.summary = summary[:1000]
        existing.evidence = evidence
        existing.collected_at = now


async def collect_vendor_posture(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    vendor: Asset,
    persist: bool = True,
) -> dict[str, dict[str, Any]]:
    """Run every signal source and (optionally) persist to
    ``vendor_posture_signals``. Returns a per-kind summary."""
    details = vendor.details or {}
    primary_domain = (details.get("primary_domain") or "").strip().lower()
    github_org = (details.get("github_org") or "").strip()
    vendor_name = vendor.value or ""

    out: dict[str, dict[str, Any]] = {}

    # 1) DMARC / SPF / DKIM ------------------------------------------
    if primary_domain:
        es_score, es_evidence = await assess_email_security(primary_domain)
    else:
        es_score, es_evidence = 0.0, {"reason": "no primary_domain"}
    out["email_security"] = {"score": es_score, "evidence": es_evidence}
    if persist and primary_domain:
        await _upsert_signal(
            db,
            organization_id=organization_id,
            vendor_asset_id=vendor.id,
            kind="email_security",
            score=es_score,
            summary=f"DMARC={es_evidence.get('dmarc',{}).get('policy')} SPF={es_evidence.get('spf',{}).get('policy')} DKIM={'yes' if es_evidence.get('dkim',{}).get('present') else 'no'}",
            evidence=es_evidence,
        )

    # 2) HIBP per probable vendor email ------------------------------
    hibp_score, hibp_evidence = await assess_vendor_breach(primary_domain)
    out["hibp"] = {"score": hibp_score, "evidence": hibp_evidence}
    if persist:
        await _upsert_signal(
            db,
            organization_id=organization_id,
            vendor_asset_id=vendor.id,
            kind="hibp",
            score=hibp_score,
            summary=(
                f"HIBP probed {len(hibp_evidence.get('probed', []))} addresses; "
                f"{len(hibp_evidence.get('hits', []))} with breaches"
            ),
            evidence=hibp_evidence,
        )

    # 3) Sanctions screening -----------------------------------------
    sanctions_hits = await screen_vendor(vendor_name)
    matched_sources = [h.source for h in sanctions_hits if h.matched]
    sanctions_score = 0.0 if matched_sources else 100.0
    out["sanctions"] = {
        "score": sanctions_score,
        "evidence": {
            "matched_sources": matched_sources,
            "results": [
                {
                    "source": h.source,
                    "matched": h.matched,
                    "score": h.score,
                    "payload": h.payload,
                }
                for h in sanctions_hits
            ],
        },
    }
    if persist:
        await _upsert_signal(
            db,
            organization_id=organization_id,
            vendor_asset_id=vendor.id,
            kind="sanctions",
            score=sanctions_score,
            summary=(
                f"Hits on {','.join(matched_sources)}"
                if matched_sources
                else "Clean across OFAC / OFSI / EU"
            ),
            evidence=out["sanctions"]["evidence"],
        )
        # Also persist per-source rows for the audit log.
        now = datetime.now(timezone.utc)
        for h in sanctions_hits:
            db.add(
                VendorSanctionsCheck(
                    organization_id=organization_id,
                    vendor_asset_id=vendor.id,
                    source=h.source,
                    matched=h.matched,
                    match_score=float(h.score),
                    match_payload=h.payload,
                    checked_at=now,
                )
            )

    # 4) Typosquat exposure (pulled from cert-stream brand pipeline) -
    typo_rows: list[Any] = []
    if primary_domain:
        try:
            from src.models.brand import SuspectDomain

            typo_rows = list(
                (
                    await db.execute(
                        select(SuspectDomain).where(
                            SuspectDomain.organization_id == organization_id,
                            SuspectDomain.matched_term_value.ilike(
                                f"%{primary_domain}%"
                            ),
                        )
                    )
                ).scalars()
            )
        except Exception:  # noqa: BLE001
            typo_rows = []
    typo_count = len(typo_rows)
    typo_score = max(0.0, 100.0 - typo_count * 4.0)
    out["typosquat"] = {
        "score": typo_score,
        "evidence": {
            "count": typo_count,
            "samples": [
                getattr(r, "domain", None) for r in typo_rows[:10]
            ],
            "matched_against": primary_domain,
        },
    }
    if persist and primary_domain:
        await _upsert_signal(
            db,
            organization_id=organization_id,
            vendor_asset_id=vendor.id,
            kind="typosquat",
            score=typo_score,
            summary=f"{typo_count} cert-stream typosquats matching {primary_domain}",
            evidence=out["typosquat"]["evidence"],
        )

    # 5) GitHub org leaks --------------------------------------------
    if github_org:
        try:
            hits = await scan_github_org(github_org)
        except Exception as e:  # noqa: BLE001
            _logger.warning("github scan failed for %s: %s", github_org, e)
            hits = []
        gh_score, by_sev = severity_to_score(hits)
        out["github_leak"] = {
            "score": gh_score,
            "evidence": {
                "org": github_org,
                "hits": [
                    {
                        "pattern": h.pattern,
                        "severity": h.severity,
                        "repo": h.repo,
                        "url": h.url,
                    }
                    for h in hits[:25]
                ],
                "by_severity": by_sev,
            },
        }
        if persist:
            await _upsert_signal(
                db,
                organization_id=organization_id,
                vendor_asset_id=vendor.id,
                kind="github_leak",
                score=gh_score,
                summary=(
                    f"github.com/{github_org}: "
                    + ", ".join(f"{k}:{v}" for k, v in by_sev.items() if v)
                    if any(by_sev.values())
                    else f"github.com/{github_org}: no leak patterns observed"
                ),
                evidence=out["github_leak"]["evidence"],
            )
    else:
        out["github_leak"] = {
            "score": 70.0,
            "evidence": {"reason": "no github_org configured on vendor"},
        }

    # 6) Nuclei vendor-domain probe (idempotent queue) ---------------
    # Reuse the EASM auto-pipeline orchestrator so /surface and /tprm
    # share one set of scan jobs against the vendor's primary_domain.
    # The orchestrator dedups on (kind, target) so re-running this is
    # safe — only newly-changed targets get queued.
    if primary_domain:
        try:
            from src.easm.orchestrator import queue_pipeline_for_targets
            from src.models.onboarding import DiscoveryJobKind

            await queue_pipeline_for_targets(
                db,
                organization_id=organization_id,
                targets=[primary_domain],
                pipeline=(
                    DiscoveryJobKind.HTTPX_PROBE,
                    DiscoveryJobKind.TLS_AUDIT,
                    DiscoveryJobKind.VULN_SCAN,  # nuclei
                ),
            )
            out["nuclei_queue"] = {
                "score": 100.0,
                "evidence": {"queued_for": primary_domain},
            }
        except Exception as e:  # noqa: BLE001
            out["nuclei_queue"] = {
                "score": 100.0,
                "evidence": {"error": str(e)[:200]},
            }

    return out


__all__ = ["collect_vendor_posture"]
