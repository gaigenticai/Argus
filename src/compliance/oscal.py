"""NIST OSCAL 1.1.2 — Assessment Results emitter.

Produces a JSON document conforming to the OSCAL Assessment Results
schema (oscal_assessment-results_schema.json, version 1.1.2). The
document captures the tenant's evidence for a single framework over
the requested period:

  * one ``observation`` per ``ComplianceEvidence`` row
  * one ``finding`` per control that has at least one observation
  * a single ``result`` covering the period
  * metadata identifying the tenant (party) and the framework

The output is deterministic for a given input set so file hashes are
stable on re-export.

Schema reference:
  https://github.com/usnistgov/OSCAL/blob/main/json/schema/oscal_assessment-results_schema.json
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.compliance import (
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)

logger = logging.getLogger(__name__)


_OSCAL_VERSION = "1.1.2"
_NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")  # stable v5 namespace


def _stable_uuid(*parts: str) -> str:
    """Deterministic UUIDv5 from parts — keeps the document byte-stable
    across re-runs for the same inputs (matters for hash_sha256 + dedup)."""
    name = "|".join(parts)
    return str(uuid.uuid5(_NAMESPACE, name))


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def build_assessment_results(
    session: AsyncSession,
    organization_id: uuid.UUID,
    organization_name: str,
    framework: ComplianceFramework,
    period_from: datetime,
    period_to: datetime,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an OSCAL Assessment Results document.

    Pure function over the DB — does not insert. Caller is responsible
    for serialising the result and persisting the bytes to object
    storage if needed.
    """
    generated_at = generated_at or datetime.now(timezone.utc)

    # Pull active evidence in the period for this framework.
    evidence_rows = (await session.execute(
        select(ComplianceEvidence).where(
            ComplianceEvidence.organization_id == organization_id,
            ComplianceEvidence.framework_id == framework.id,
            ComplianceEvidence.status == "active",
            ComplianceEvidence.captured_at >= period_from,
            ComplianceEvidence.captured_at < period_to,
        ).order_by(ComplianceEvidence.captured_at.asc())
    )).scalars().all()

    # Pull controls referenced by evidence.
    referenced_control_ids = {ev.control_id for ev in evidence_rows}
    controls_by_id: dict[uuid.UUID, ComplianceControl] = {}
    if referenced_control_ids:
        ctrl_rows = (await session.execute(
            select(ComplianceControl).where(
                ComplianceControl.id.in_(referenced_control_ids)
            )
        )).scalars().all()
        controls_by_id = {c.id: c for c in ctrl_rows}

    # Build OSCAL observations + findings.
    observations: list[dict[str, Any]] = []
    obs_uuid_by_evidence: dict[uuid.UUID, str] = {}
    for ev in evidence_rows:
        ctrl = controls_by_id.get(ev.control_id)
        ctrl_label = ctrl.control_id if ctrl else str(ev.control_id)
        obs_uuid = _stable_uuid(
            "observation", str(organization_id), str(ev.id),
        )
        obs_uuid_by_evidence[ev.id] = obs_uuid
        observations.append({
            "uuid": obs_uuid,
            "title": f"Evidence for {framework.code} {ctrl_label}",
            "description": ev.summary_en or f"Evidence row {ev.id}",
            "methods": ["EXAMINE"],
            "types": ["control-objective"],
            "subjects": [{
                "subject-uuid": _stable_uuid(
                    "subject", str(organization_id),
                    ev.source_kind, str(ev.source_id),
                ),
                "type": "component",
            }],
            "collected": _iso(ev.captured_at),
            "props": [
                {"name": "argus.source_kind", "value": ev.source_kind},
                {"name": "argus.source_id", "value": str(ev.source_id)},
                {"name": "argus.evidence_id", "value": str(ev.id)},
            ],
        })

    findings: list[dict[str, Any]] = []
    for ctrl_id in sorted(referenced_control_ids, key=str):
        ctrl = controls_by_id.get(ctrl_id)
        if ctrl is None:
            continue
        related = [
            {"observation-uuid": obs_uuid_by_evidence[ev.id]}
            for ev in evidence_rows if ev.control_id == ctrl_id
        ]
        if not related:
            continue
        findings.append({
            "uuid": _stable_uuid(
                "finding", str(organization_id),
                framework.code, ctrl.control_id,
            ),
            "title": f"{framework.code} — {ctrl.control_id} — {ctrl.title_en}",
            "description": (
                ctrl.description_en
                or f"Evidence captured against {framework.name_en} {ctrl.control_id}."
            ),
            "target": {
                "type": "statement-id",
                "target-id": f"{framework.code}::{ctrl.control_id}",
                "status": {"state": "satisfied"},
            },
            "related-observations": related,
        })

    org_party_uuid = _stable_uuid("party", "organization", str(organization_id))
    assessor_party_uuid = _stable_uuid("party", "assessor", "argus")
    result_uuid = _stable_uuid(
        "result", str(organization_id), framework.code,
        _iso(period_from), _iso(period_to),
    )
    doc_uuid = _stable_uuid(
        "doc", str(organization_id), framework.code,
        _iso(period_from), _iso(period_to), _iso(generated_at),
    )

    return {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": {
                "title": (
                    f"Argus Compliance Evidence Pack — {framework.name_en} "
                    f"({_iso(period_from)[:10]} → {_iso(period_to)[:10]})"
                ),
                "last-modified": _iso(generated_at),
                "version": framework.version,
                "oscal-version": _OSCAL_VERSION,
                "parties": [
                    {
                        "uuid": org_party_uuid,
                        "type": "organization",
                        "name": organization_name,
                    },
                    {
                        "uuid": assessor_party_uuid,
                        "type": "organization",
                        "name": "Argus Threat Intelligence Platform",
                    },
                ],
                "roles": [
                    {"id": "asset-owner", "title": "Asset Owner"},
                    {"id": "assessor", "title": "Assessor"},
                ],
                "responsible-parties": [
                    {
                        "role-id": "asset-owner",
                        "party-uuids": [org_party_uuid],
                    },
                    {
                        "role-id": "assessor",
                        "party-uuids": [assessor_party_uuid],
                    },
                ],
            },
            "import-ap": {
                # We don't ship a separate Assessment Plan — point at the
                # framework's primary source so the regulator can resolve
                # it without a 404. OSCAL allows external URIs here.
                "href": framework.source_url or f"about:argus/{framework.code}",
            },
            "results": [{
                "uuid": result_uuid,
                "title": (
                    f"Continuous monitoring results — {framework.name_en}"
                ),
                "description": (
                    "Evidence collected from Argus alerts, cases, and findings "
                    "during the assessment period."
                ),
                "start": _iso(period_from),
                "end": _iso(period_to),
                "reviewed-controls": {
                    "control-selections": [{
                        "include-controls": [
                            {"control-id": f"{framework.code}::{c.control_id}"}
                            for c in sorted(
                                controls_by_id.values(),
                                key=lambda c: c.control_id,
                            )
                        ] or [{"control-id": "argus::no-controls"}],
                    }],
                },
                "observations": observations,
                "findings": findings,
            }],
        },
    }


def serialise(doc: dict[str, Any]) -> tuple[bytes, str]:
    """JSON-encode deterministically. Returns (bytes, sha256_hex)."""
    payload = json.dumps(
        doc, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return payload, hashlib.sha256(payload).hexdigest()
