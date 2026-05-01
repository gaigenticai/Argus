"""Hardening recommendation generator.

Maps an :class:`ExposureFinding` to:
    - CIS Controls v8 IDs (the ones whose Safeguards explicitly address
      the exposure category)
    - MITRE D3FEND technique IDs (defensive countermeasures)
    - NIST CSF 2.0 subcategory IDs

The mapping table below is curated (small, auditable) — when a category
isn't recognised we still emit a generic "review and remediate"
recommendation rather than dropping the finding silently.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.exposures import ExposureCategory, ExposureFinding, ExposureSeverity
from src.models.intel_polish import HardeningRecommendation, HardeningStatus


@dataclass
class HardeningTemplate:
    title: str
    summary: str
    cis_control_ids: list[str]
    d3fend_techniques: list[str]
    nist_csf_subcats: list[str]
    estimated_effort_hours: float


# ---------------------------------------------------------------------
# Curated mapping. Each entry references the public CIS Controls v8 IDs
# and MITRE D3FEND technique IDs. Update when the frameworks publish
# revisions.
# ---------------------------------------------------------------------
_TEMPLATES: dict[str, HardeningTemplate] = {
    ExposureCategory.VULNERABILITY.value: HardeningTemplate(
        title="Patch the affected component",
        summary=(
            "Apply the vendor-supplied patch or upgrade. If a patch is not "
            "yet available, deploy a virtual patch via WAF rules and "
            "restrict network access to the asset."
        ),
        cis_control_ids=["7", "7.4", "7.5", "12.1"],
        d3fend_techniques=["D3-PE", "D3-NTA", "D3-RAM"],
        nist_csf_subcats=["PR.IP-12", "ID.RA-1"],
        estimated_effort_hours=4.0,
    ),
    ExposureCategory.MISCONFIGURATION.value: HardeningTemplate(
        title="Correct the misconfiguration and add a regression check",
        summary=(
            "Identify the canonical secure configuration (CIS Benchmarks "
            "for the platform), apply it, and add an IaC / GitOps "
            "guardrail so the misconfiguration cannot reappear."
        ),
        cis_control_ids=["4", "4.1", "4.6", "16.1"],
        d3fend_techniques=["D3-CH", "D3-SCH"],
        nist_csf_subcats=["PR.IP-1", "PR.IP-3"],
        estimated_effort_hours=2.0,
    ),
    ExposureCategory.WEAK_CRYPTO.value: HardeningTemplate(
        title="Disable weak ciphers and pin to TLS 1.2/1.3 strong suites",
        summary=(
            "Disable RC4, 3DES, CBC-only ciphers, and SSLv3/TLS 1.0/1.1. "
            "Configure TLS 1.2 with PFS suites and TLS 1.3 where supported. "
            "Rotate keys if compromise is plausible."
        ),
        cis_control_ids=["3", "3.10", "12.7"],
        d3fend_techniques=["D3-EAL", "D3-CSPP"],
        nist_csf_subcats=["PR.DS-2", "PR.DS-5"],
        estimated_effort_hours=2.0,
    ),
    ExposureCategory.EXPIRED_CERT.value: HardeningTemplate(
        title="Renew the certificate and add monitoring",
        summary=(
            "Issue a new certificate via the org PKI / public CA. Configure "
            "monitoring (e.g., cert-manager + alerting) to surface upcoming "
            "expirations 30+ days in advance."
        ),
        cis_control_ids=["3.10", "8.11"],
        d3fend_techniques=["D3-CV", "D3-EAL"],
        nist_csf_subcats=["PR.DS-2", "DE.CM-3"],
        estimated_effort_hours=1.0,
    ),
    ExposureCategory.SELF_SIGNED_CERT.value: HardeningTemplate(
        title="Replace self-signed certificate with a trusted CA cert",
        summary=(
            "Self-signed certificates on internet-facing services break "
            "trust and enable MITM. Issue a public-CA cert (Let's Encrypt "
            "or commercial)."
        ),
        cis_control_ids=["3.10"],
        d3fend_techniques=["D3-CV"],
        nist_csf_subcats=["PR.DS-2"],
        estimated_effort_hours=1.0,
    ),
    ExposureCategory.EXPOSED_SERVICE.value: HardeningTemplate(
        title="Remove or restrict the exposed service",
        summary=(
            "Either take the service offline if it shouldn't be public, "
            "or front it with authentication + IP allowlisting and add "
            "logging."
        ),
        cis_control_ids=["12", "12.2", "13.1"],
        d3fend_techniques=["D3-NTA", "D3-AC"],
        nist_csf_subcats=["PR.AC-3", "PR.AC-4", "DE.CM-1"],
        estimated_effort_hours=2.0,
    ),
    ExposureCategory.VERSION_DISCLOSURE.value: HardeningTemplate(
        title="Suppress version banners",
        summary=(
            "Configure the service to omit precise product+version "
            "information from banners and HTTP response headers. Reduces "
            "attacker reconnaissance signal."
        ),
        cis_control_ids=["4.6"],
        d3fend_techniques=["D3-DS"],
        nist_csf_subcats=["PR.IP-1"],
        estimated_effort_hours=0.5,
    ),
    ExposureCategory.DEFAULT_CREDENTIAL.value: HardeningTemplate(
        title="Rotate credentials immediately",
        summary=(
            "Default credentials are presumed compromised. Rotate the "
            "credential, enable MFA, restrict authentication endpoints, "
            "and audit any access during the exposure window."
        ),
        cis_control_ids=["5", "5.2", "5.3", "6.1"],
        d3fend_techniques=["D3-MFA", "D3-CR"],
        nist_csf_subcats=["PR.AC-1", "PR.AC-7"],
        estimated_effort_hours=1.5,
    ),
    ExposureCategory.INFORMATION_DISCLOSURE.value: HardeningTemplate(
        title="Remove sensitive information from public-facing surface",
        summary=(
            "Audit the disclosure path, remove the data, and add a "
            "redaction / classification rule to prevent re-disclosure. "
            "Consider notifying impacted parties if the data is regulated."
        ),
        cis_control_ids=["3", "3.3"],
        d3fend_techniques=["D3-DS", "D3-DCR"],
        nist_csf_subcats=["PR.DS-5", "DE.CM-7"],
        estimated_effort_hours=2.0,
    ),
}

_DEFAULT = HardeningTemplate(
    title="Triage and remediate the exposure",
    summary=(
        "Investigate root cause, contain the exposure, and add detective "
        "+ preventive controls."
    ),
    cis_control_ids=["1", "17"],
    d3fend_techniques=[],
    nist_csf_subcats=["RS.AN-1", "RS.MI-1"],
    estimated_effort_hours=2.0,
)


def _priority_for_severity(sev: str) -> str:
    return {
        ExposureSeverity.CRITICAL.value: "critical",
        ExposureSeverity.HIGH.value: "high",
        ExposureSeverity.MEDIUM.value: "medium",
        ExposureSeverity.LOW.value: "low",
    }.get(sev, "medium")


@dataclass
class GeneratedRecommendation:
    finding_id: uuid.UUID
    rec_id: uuid.UUID
    title: str
    priority: str


async def generate_for_finding(
    db: AsyncSession,
    finding: ExposureFinding,
) -> GeneratedRecommendation:
    """Insert (or update) a hardening recommendation for the given exposure."""
    template = _TEMPLATES.get(finding.category, _DEFAULT)
    existing = (
        await db.execute(
            select(HardeningRecommendation).where(
                and_(
                    HardeningRecommendation.organization_id == finding.organization_id,
                    HardeningRecommendation.exposure_finding_id == finding.id,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.title = template.title
        existing.summary = template.summary
        existing.cis_control_ids = template.cis_control_ids
        existing.d3fend_techniques = template.d3fend_techniques
        existing.nist_csf_subcats = template.nist_csf_subcats
        existing.priority = _priority_for_severity(finding.severity)
        existing.estimated_effort_hours = template.estimated_effort_hours
        return GeneratedRecommendation(
            finding_id=finding.id,
            rec_id=existing.id,
            title=existing.title,
            priority=existing.priority,
        )
    rec = HardeningRecommendation(
        organization_id=finding.organization_id,
        exposure_finding_id=finding.id,
        title=template.title,
        summary=template.summary,
        cis_control_ids=template.cis_control_ids,
        d3fend_techniques=template.d3fend_techniques,
        nist_csf_subcats=template.nist_csf_subcats,
        priority=_priority_for_severity(finding.severity),
        estimated_effort_hours=template.estimated_effort_hours,
        status=HardeningStatus.OPEN.value,
    )
    db.add(rec)
    await db.flush()
    return GeneratedRecommendation(
        finding_id=finding.id,
        rec_id=rec.id,
        title=rec.title,
        priority=rec.priority,
    )


async def generate_for_organization(
    db: AsyncSession,
    organization_id: uuid.UUID,
) -> list[GeneratedRecommendation]:
    findings = (
        await db.execute(
            select(ExposureFinding).where(
                and_(
                    ExposureFinding.organization_id == organization_id,
                    ExposureFinding.state.in_(["open", "acknowledged", "reopened"]),
                )
            )
        )
    ).scalars().all()
    out = []
    for f in findings:
        out.append(await generate_for_finding(db, f))
    return out


__all__ = [
    "GeneratedRecommendation",
    "generate_for_finding",
    "generate_for_organization",
]
