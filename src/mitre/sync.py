"""MITRE ATT&CK STIX-bundle sync.

Parses STIX 2.1 bundles published at
https://github.com/mitre/cti and upserts tactics, techniques, and
mitigations into our database. Supports the three official matrices
(enterprise / mobile / ics) plus arbitrary local file paths for tests
and air-gapped deployments.

We deliberately do not depend on ``mitreattack-python``: the STIX 2.1
schema is stable and our needs are narrow (load → upsert → done).
Avoiding the SDK keeps install size and dependency surface small.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.mitre import (
    MitreMatrix,
    MitreMitigation,
    MitreSync,
    MitreTactic,
    MitreTechnique,
)


_logger = logging.getLogger(__name__)


# Default STIX bundle URLs (stable canonical raw paths).
DEFAULT_BUNDLE_URLS: dict[str, str] = {
    MitreMatrix.ENTERPRISE.value: (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    ),
    MitreMatrix.MOBILE.value: (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "mobile-attack/mobile-attack.json"
    ),
    MitreMatrix.ICS.value: (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "ics-attack/ics-attack.json"
    ),
}


@dataclass
class SyncReport:
    matrix: str
    source: str
    sync_version: str | None
    tactics: int = 0
    techniques: int = 0
    subtechniques: int = 0
    mitigations: int = 0
    deprecated: int = 0
    succeeded: bool = False
    error: str | None = None


# --- STIX bundle loading -----------------------------------------------


async def load_bundle(source: str) -> dict[str, Any]:
    """Load a STIX bundle from an HTTP URL or a local file path."""
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(source) as resp:
                resp.raise_for_status()
                return await resp.json(content_type=None)
    # Treat anything else as a local path.
    path = Path(parsed.path or source)
    if not path.is_file():
        raise FileNotFoundError(f"STIX bundle not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# --- Bundle helpers ----------------------------------------------------


def _external_id(stix_obj: dict[str, Any]) -> str | None:
    for ref in stix_obj.get("external_references", []) or []:
        if ref.get("source_name", "").startswith("mitre-attack"):
            ext = ref.get("external_id")
            if ext:
                return ext
    return None


def _external_url(stix_obj: dict[str, Any]) -> str | None:
    for ref in stix_obj.get("external_references", []) or []:
        if ref.get("source_name", "").startswith("mitre-attack"):
            return ref.get("url")
    return None


def _kill_chain_phases(stix_obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for kc in stix_obj.get("kill_chain_phases", []) or []:
        if kc.get("kill_chain_name", "").startswith("mitre"):
            phase = kc.get("phase_name")
            if phase:
                out.append(phase)
    return sorted(set(out))


def _is_attack_pattern(o: dict[str, Any]) -> bool:
    return o.get("type") == "attack-pattern" and bool(_external_id(o))


def _is_tactic(o: dict[str, Any]) -> bool:
    return o.get("type") == "x-mitre-tactic" and bool(_external_id(o))


def _is_mitigation(o: dict[str, Any]) -> bool:
    return o.get("type") == "course-of-action" and bool(_external_id(o))


_VERSION_RE = re.compile(r"^v?\d+(\.\d+)*$")


def _bundle_version(bundle: dict[str, Any]) -> str | None:
    """Best-effort extraction of the matrix version.

    The STIX bundle's ``x-mitre-collection`` object (when present) carries
    a ``x_mitre_version``. Falls back to ``modified`` of any object.
    """
    for o in bundle.get("objects", []) or []:
        if o.get("type") == "x-mitre-collection":
            v = o.get("x_mitre_version") or o.get("version")
            if v:
                return str(v)
    # Fallback: use the first attack-pattern's modified date as a proxy.
    for o in bundle.get("objects", []) or []:
        if o.get("type") == "attack-pattern" and o.get("modified"):
            return o["modified"]
    return None


# --- Sync entry point --------------------------------------------------


async def sync_matrix(
    db: AsyncSession,
    matrix: MitreMatrix,
    *,
    source: str | None = None,
    triggered_by_user_id=None,
) -> SyncReport:
    """Pull the named matrix and upsert into the DB.

    ``source`` may be an HTTP URL or a local file path. If omitted, the
    canonical GitHub URL for the matrix is used.

    Always commits at the end (success or failure). Records a
    :class:`MitreSync` row with the outcome.
    """
    src = source or DEFAULT_BUNDLE_URLS[matrix.value]
    report = SyncReport(matrix=matrix.value, source=src, sync_version=None)

    try:
        bundle = await load_bundle(src)
    except Exception as e:  # noqa: BLE001
        report.error = f"Failed to load bundle: {e}"
        await _record_sync(db, report, triggered_by_user_id)
        return report

    objects = bundle.get("objects") or []
    sync_version = _bundle_version(bundle)
    report.sync_version = sync_version

    try:
        # Pre-load existing rows for this matrix into dicts keyed by external_id.
        existing_tactics = {
            t.external_id: t
            for t in (
                await db.execute(
                    select(MitreTactic).where(MitreTactic.matrix == matrix.value)
                )
            ).scalars()
        }
        existing_techs = {
            t.external_id: t
            for t in (
                await db.execute(
                    select(MitreTechnique).where(
                        MitreTechnique.matrix == matrix.value
                    )
                )
            ).scalars()
        }
        existing_mits = {
            m.external_id: m
            for m in (
                await db.execute(
                    select(MitreMitigation).where(
                        MitreMitigation.matrix == matrix.value
                    )
                )
            ).scalars()
        }

        # Upsert tactics
        for o in objects:
            if not _is_tactic(o):
                continue
            ext_id = _external_id(o)
            short = o.get("x_mitre_shortname") or (o.get("name") or "").lower().replace(" ", "-")
            row = existing_tactics.get(ext_id) or MitreTactic(
                matrix=matrix.value,
                external_id=ext_id,
                short_name=short,
                name=o.get("name") or short,
            )
            row.short_name = short
            row.name = o.get("name") or row.name
            row.description = o.get("description")
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            report.tactics += 1

        # Upsert techniques (incl. sub-techniques)
        for o in objects:
            if not _is_attack_pattern(o):
                continue
            ext_id = _external_id(o)
            is_sub = bool(o.get("x_mitre_is_subtechnique"))
            parent_ext = ext_id.split(".", 1)[0] if "." in (ext_id or "") else None
            tactics_short = _kill_chain_phases(o)
            platforms = sorted(set(o.get("x_mitre_platforms") or []))
            data_sources = sorted(set(o.get("x_mitre_data_sources") or []))
            deprecated = bool(o.get("x_mitre_deprecated"))
            revoked = bool(o.get("revoked"))

            row = existing_techs.get(ext_id) or MitreTechnique(
                matrix=matrix.value,
                external_id=ext_id,
                name=o.get("name") or ext_id,
                is_subtechnique=is_sub,
            )
            row.matrix = matrix.value
            row.is_subtechnique = is_sub
            row.parent_external_id = parent_ext if is_sub else None
            row.name = o.get("name") or ext_id
            row.description = o.get("description")
            row.tactics = tactics_short
            row.platforms = platforms
            row.data_sources = data_sources
            row.detection = o.get("x_mitre_detection")
            row.deprecated = deprecated
            row.revoked = revoked
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            if deprecated or revoked:
                report.deprecated += 1
            if is_sub:
                report.subtechniques += 1
            else:
                report.techniques += 1

        # Upsert mitigations (skip "course-of-action" objects that aren't
        # actually MITRE mitigations — the bundle includes some legacy
        # ones with x_mitre_deprecated=True).
        for o in objects:
            if not _is_mitigation(o):
                continue
            ext_id = _external_id(o)
            row = existing_mits.get(ext_id) or MitreMitigation(
                matrix=matrix.value,
                external_id=ext_id,
                name=o.get("name") or ext_id,
            )
            row.matrix = matrix.value
            row.name = o.get("name") or ext_id
            row.description = o.get("description")
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            report.mitigations += 1

        report.succeeded = True
    except Exception as e:  # noqa: BLE001
        await db.rollback()
        report.error = f"Upsert failed: {e}"
        await _record_sync(db, report, triggered_by_user_id)
        return report

    await _record_sync(db, report, triggered_by_user_id)
    return report


async def _record_sync(
    db: AsyncSession, report: SyncReport, triggered_by_user_id
) -> None:
    sync = MitreSync(
        matrix=report.matrix,
        source_url=report.source,
        sync_version=report.sync_version,
        tactics_count=report.tactics,
        techniques_count=report.techniques,
        subtechniques_count=report.subtechniques,
        mitigations_count=report.mitigations,
        deprecated_count=report.deprecated,
        succeeded=report.succeeded,
        error_message=report.error,
        triggered_by_user_id=triggered_by_user_id,
    )
    db.add(sync)
    await db.commit()


__all__ = [
    "SyncReport",
    "DEFAULT_BUNDLE_URLS",
    "load_bundle",
    "sync_matrix",
]
