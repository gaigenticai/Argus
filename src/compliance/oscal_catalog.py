"""OSCAL machine-readable control catalog ingestion (P2 #2.12).

Loads NIST 800-53 rev 5 (and adjacent NIST CSF / FedRAMP / ISO 27002)
catalogs published by NIST in OSCAL JSON format. Stores the full OSCAL
control object in JSONB so an exporter can round-trip.

  :func:`seed_minimal` — installs a curated 30-row subset of NIST
  800-53 rev 5 covering the most-cited controls (AC-2, AT-2, AU-x,
  CA-x, CM-7, IR-x, RA-5, SI-x, …). Idempotent.

  :func:`refresh_from_upstream` — admin-triggered refresh from the
  NIST OSCAL GitHub mirror. ``json_payload`` arg lets tests inject a
  prefetched catalog without HTTP.

The seeded subset pairs with the P1 #1.3 compliance pack: when a
tenant exports an evidence pack against NIST CSF 2.0 we already have
mappings, and those mappings now resolve to authoritative NIST
control statements rather than the pack's curated text.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.d3fend_oscal import OscalCatalogEntry

logger = logging.getLogger(__name__)


_NIST_53_R5_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
_CATALOG_NIST_53_R5 = "NIST_SP-800-53_rev5"
_CURATED_VERSION = "curated-2026-05-01"
_FULL_VERSION_PREFIX = "upstream"


# 30-row hand-curated subset. (control_id, title, statement)
CURATED_NIST_53_R5: list[tuple[str, str, str]] = [
    ("AC-2", "Account Management",
     "The organization manages information system accounts, including "
     "establishing, activating, modifying, reviewing, disabling, and "
     "removing accounts."),
    ("AC-3", "Access Enforcement",
     "The information system enforces approved authorisations for "
     "logical access to information and system resources."),
    ("AC-6", "Least Privilege",
     "The organization employs the principle of least privilege, "
     "allowing only authorised access for users which are necessary to "
     "accomplish assigned tasks."),
    ("AC-17", "Remote Access",
     "The organization establishes and documents usage restrictions, "
     "configuration / connection requirements, and implementation "
     "guidance for each type of remote access."),
    ("AT-2", "Literacy Training and Awareness",
     "The organization provides basic security literacy training to "
     "information system users (including managers, senior executives, "
     "and contractors)."),
    ("AU-2", "Event Logging",
     "The organization identifies the types of events that the "
     "information system is capable of logging and which event types "
     "must be logged."),
    ("AU-6", "Audit Record Review, Analysis, and Reporting",
     "The organization reviews and analyses information system audit "
     "records for indications of inappropriate or unusual activity."),
    ("AU-12", "Audit Record Generation",
     "The information system provides audit-record-generation "
     "capability for the auditable events defined in AU-2."),
    ("CA-2", "Control Assessments",
     "The organization develops, distributes, and reviews control "
     "assessment plans that describe the scope of the assessment."),
    ("CA-7", "Continuous Monitoring",
     "The organization develops a continuous monitoring strategy and "
     "implements a continuous monitoring program."),
    ("CM-2", "Baseline Configuration",
     "The organization develops, documents, and maintains a current "
     "baseline configuration of the information system."),
    ("CM-7", "Least Functionality",
     "The organization configures the information system to provide "
     "only essential capabilities and explicitly prohibits or "
     "restricts the use of nonessential functions."),
    ("CM-8", "System Component Inventory",
     "The organization develops and documents an inventory of "
     "information system components."),
    ("CP-9", "System Backup",
     "The organization conducts backups of user-level + system-level "
     "information contained in the information system."),
    ("CP-10", "System Recovery and Reconstitution",
     "The organization provides for the recovery and reconstitution of "
     "the information system to a known state after a disruption, "
     "compromise, or failure."),
    ("IA-2", "Identification and Authentication (Organizational Users)",
     "The information system uniquely identifies and authenticates "
     "organisational users."),
    ("IA-5", "Authenticator Management",
     "The organization manages information system authenticators by "
     "verifying identity, establishing initial content, and changing/"
     "refreshing periodically."),
    ("IR-4", "Incident Handling",
     "The organization implements an incident-handling capability for "
     "security incidents that includes preparation, detection and "
     "analysis, containment, eradication, and recovery."),
    ("IR-5", "Incident Monitoring",
     "The organization tracks and documents information system "
     "security incidents."),
    ("IR-6", "Incident Reporting",
     "The organization requires personnel to report suspected security "
     "incidents to the organisational incident-response capability "
     "within an organisation-defined time period."),
    ("IR-8", "Incident Response Plan",
     "The organization develops an incident response plan that "
     "provides the organization with a roadmap for implementing its "
     "incident response capability."),
    ("PE-3", "Physical Access Control",
     "The organization enforces physical access authorisations at "
     "entry/exit points to the facility where the information system "
     "resides."),
    ("RA-3", "Risk Assessment",
     "The organization conducts an assessment of risk, including the "
     "likelihood and magnitude of harm, from the unauthorised access, "
     "use, disclosure, disruption, modification, or destruction of "
     "the information system."),
    ("RA-5", "Vulnerability Monitoring and Scanning",
     "The organization scans for vulnerabilities in the information "
     "system and hosted applications and when new vulnerabilities "
     "potentially affecting the system are identified."),
    ("SC-7", "Boundary Protection",
     "The information system monitors and controls communications at "
     "the external boundary of the system and at key internal boundaries "
     "within the system."),
    ("SC-12", "Cryptographic Key Establishment and Management",
     "The organization establishes and manages cryptographic keys for "
     "required cryptography employed within the information system."),
    ("SC-28", "Protection of Information at Rest",
     "The information system protects the confidentiality and integrity "
     "of information at rest."),
    ("SI-2", "Flaw Remediation",
     "The organization identifies, reports, and corrects information "
     "system flaws."),
    ("SI-3", "Malicious Code Protection",
     "The organization employs malicious code protection mechanisms at "
     "information system entry and exit points."),
    ("SI-4", "System Monitoring",
     "The organization monitors the information system to detect "
     "attacks and indicators of potential attacks."),
]


# ── Seeder ────────────────────────────────────────────────────────────


async def seed_minimal(session: AsyncSession) -> dict[str, int]:
    """Idempotent seed of the curated NIST 800-53 rev 5 subset."""
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for cid, title, statement in CURATED_NIST_53_R5:
        existing = (await session.execute(
            select(OscalCatalogEntry).where(
                OscalCatalogEntry.catalog == _CATALOG_NIST_53_R5,
                OscalCatalogEntry.control_id == cid,
            )
        )).scalar_one_or_none()
        if existing is None:
            session.add(OscalCatalogEntry(
                catalog=_CATALOG_NIST_53_R5,
                control_id=cid,
                title=title,
                statement=statement,
                oscal=None,
                source_url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
                source_version=_CURATED_VERSION,
            ))
            counts["created"] += 1
        else:
            changed = False
            for col, val in (("title", title), ("statement", statement),
                             ("source_version", _CURATED_VERSION)):
                if getattr(existing, col) != val:
                    setattr(existing, col, val)
                    changed = True
            counts["updated" if changed else "unchanged"] += 1
    await session.flush()
    logger.info("oscal NIST 800-53 r5 curated seed: %s", counts)
    return counts


# ── Live upstream refresh ─────────────────────────────────────────────


async def refresh_from_upstream(
    session: AsyncSession,
    *,
    catalog: str = _CATALOG_NIST_53_R5,
    json_payload: dict | None = None,
) -> dict[str, int]:
    """Fetch and ingest a full OSCAL catalog from NIST.

    Currently supports NIST 800-53 rev 5; pass a different ``catalog``
    + ``json_payload`` to ingest other OSCAL catalogs.
    """
    if json_payload is None:
        import aiohttp
        url = _NIST_53_R5_URL if catalog == _CATALOG_NIST_53_R5 else None
        if url is None:
            raise ValueError(f"no upstream URL configured for catalog={catalog!r}")
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as http:
            async with http.get(url) as resp:
                resp.raise_for_status()
                json_payload = await resp.json()

    counts = {"created": 0, "updated": 0, "unchanged": 0}
    version = f"{_FULL_VERSION_PREFIX}-" + datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d")

    cat = json_payload.get("catalog") or {}
    for control in _walk_controls(cat):
        cid = (control.get("id") or "").upper().replace(".", "-")
        if not cid:
            continue
        title = (control.get("title") or "").strip()
        statement = _extract_statement(control)

        existing = (await session.execute(
            select(OscalCatalogEntry).where(
                OscalCatalogEntry.catalog == catalog,
                OscalCatalogEntry.control_id == cid,
            )
        )).scalar_one_or_none()
        if existing is None:
            session.add(OscalCatalogEntry(
                catalog=catalog,
                control_id=cid,
                title=title or cid,
                statement=statement or None,
                oscal=control,
                source_url=_NIST_53_R5_URL,
                source_version=version,
            ))
            counts["created"] += 1
        else:
            existing.title = title or existing.title
            if statement:
                existing.statement = statement
            existing.oscal = control
            existing.source_version = version
            counts["updated"] += 1

    await session.flush()
    logger.info("oscal upstream refresh (%s): %s", catalog, counts)
    return counts


def _walk_controls(catalog_obj: dict) -> Any:
    """Yield every control / sub-control in an OSCAL catalog tree."""
    for group in catalog_obj.get("groups", []) or []:
        yield from _walk_group(group)
    for control in catalog_obj.get("controls", []) or []:
        yield from _walk_control(control)


def _walk_group(group: dict) -> Any:
    for child in group.get("groups", []) or []:
        yield from _walk_group(child)
    for control in group.get("controls", []) or []:
        yield from _walk_control(control)


def _walk_control(control: dict) -> Any:
    yield control
    for child in control.get("controls", []) or []:
        yield from _walk_control(child)


def _extract_statement(control: dict) -> str:
    """OSCAL stores the human-readable statement under ``parts[].prose``."""
    out: list[str] = []
    for part in control.get("parts", []) or []:
        if part.get("name") == "statement":
            prose = (part.get("prose") or "").strip()
            if prose:
                out.append(prose)
            for sub in part.get("parts", []) or []:
                sp = (sub.get("prose") or "").strip()
                if sp:
                    out.append(sp)
    return "\n\n".join(out)


# ── Lookups ───────────────────────────────────────────────────────────


async def lookup(
    session: AsyncSession, *, catalog: str, control_id: str,
) -> OscalCatalogEntry | None:
    return (await session.execute(
        select(OscalCatalogEntry).where(
            OscalCatalogEntry.catalog == catalog,
            OscalCatalogEntry.control_id == control_id,
        )
    )).scalar_one_or_none()
