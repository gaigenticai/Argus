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
    MitreCampaign,
    MitreDataSource,
    MitreGroup,
    MitreMatrix,
    MitreMitigation,
    MitreRelationship,
    MitreSoftware,
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
    groups: int = 0
    software: int = 0
    data_sources: int = 0
    campaigns: int = 0
    relationships: int = 0
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


def _is_group(o: dict[str, Any]) -> bool:
    return o.get("type") == "intrusion-set" and bool(_external_id(o))


def _is_malware(o: dict[str, Any]) -> bool:
    return o.get("type") == "malware" and bool(_external_id(o))


def _is_tool(o: dict[str, Any]) -> bool:
    return o.get("type") == "tool" and bool(_external_id(o))


def _is_data_source(o: dict[str, Any]) -> bool:
    return o.get("type") == "x-mitre-data-source" and bool(_external_id(o))


def _is_data_component(o: dict[str, Any]) -> bool:
    return o.get("type") == "x-mitre-data-component"


def _is_campaign(o: dict[str, Any]) -> bool:
    return o.get("type") == "campaign" and bool(_external_id(o))


def _is_relationship(o: dict[str, Any]) -> bool:
    return o.get("type") == "relationship"


def _all_external_refs(stix_obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Return external references with non-MITRE source-name first.

    Used to capture published research backing (papers, blogs) for
    actors/groups, since /actors UI surfaces these as the "Reading list".
    """
    out: list[dict[str, Any]] = []
    for ref in stix_obj.get("external_references", []) or []:
        sn = ref.get("source_name") or ""
        if sn.startswith("mitre-attack"):
            continue
        url = ref.get("url")
        if not url:
            continue
        out.append(
            {
                "source_name": sn,
                "description": ref.get("description"),
                "url": url,
                "external_id": ref.get("external_id"),
            }
        )
    return out


def _extract_country_codes(description: str | None) -> list[str]:
    """Heuristic country tag from a MITRE Group description.

    Matches "X-nexus / X-aligned / based in X / believed to be X" against a
    short country dictionary; never makes a hard attribution claim — used
    only as a default tag that analysts can override on the actor record.
    """
    if not description:
        return []
    text = description.lower()
    # Map country / region keyword → ISO 3166 alpha-2
    mapping = {
        "iran": "IR",
        "iranian": "IR",
        "russia": "RU",
        "russian": "RU",
        "china": "CN",
        "chinese": "CN",
        "north korea": "KP",
        "north korean": "KP",
        "dprk": "KP",
        "south korea": "KR",
        "ukraine": "UA",
        "ukrainian": "UA",
        "belarus": "BY",
        "belarusian": "BY",
        "syria": "SY",
        "syrian": "SY",
        "lebanon": "LB",
        "vietnam": "VN",
        "vietnamese": "VN",
        "pakistan": "PK",
        "pakistani": "PK",
        "india": "IN",
        "indian": "IN",
        "turkey": "TR",
        "turkish": "TR",
        "israel": "IL",
        "israeli": "IL",
        "united states": "US",
        "u.s.": "US",
        "brazil": "BR",
        "brazilian": "BR",
    }
    found: list[str] = []
    for kw, code in mapping.items():
        if kw in text and code not in found:
            found.append(code)
    return found


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

        # ----- Groups (intrusion-set, G####) -----
        existing_groups = {
            g.external_id: g
            for g in (
                await db.execute(
                    select(MitreGroup).where(MitreGroup.matrix == matrix.value)
                )
            ).scalars()
        }
        for o in objects:
            if not _is_group(o):
                continue
            ext_id = _external_id(o)
            aliases = sorted(set(o.get("aliases") or []))
            row = existing_groups.get(ext_id) or MitreGroup(
                matrix=matrix.value,
                external_id=ext_id,
                name=o.get("name") or ext_id,
            )
            row.matrix = matrix.value
            row.name = o.get("name") or ext_id
            row.aliases = aliases
            row.description = o.get("description")
            row.country_codes = _extract_country_codes(o.get("description"))
            row.references = _all_external_refs(o)
            row.deprecated = bool(o.get("x_mitre_deprecated"))
            row.revoked = bool(o.get("revoked"))
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            report.groups += 1

        # ----- Software (malware + tool, S####) -----
        existing_sw = {
            s.external_id: s
            for s in (
                await db.execute(
                    select(MitreSoftware).where(MitreSoftware.matrix == matrix.value)
                )
            ).scalars()
        }
        for o in objects:
            if not (_is_malware(o) or _is_tool(o)):
                continue
            ext_id = _external_id(o)
            aliases = sorted(
                set(o.get("aliases") or o.get("x_mitre_aliases") or [])
            )
            row = existing_sw.get(ext_id) or MitreSoftware(
                matrix=matrix.value,
                external_id=ext_id,
                name=o.get("name") or ext_id,
                software_type="malware" if _is_malware(o) else "tool",
            )
            row.matrix = matrix.value
            row.name = o.get("name") or ext_id
            row.aliases = aliases
            row.software_type = "malware" if _is_malware(o) else "tool"
            row.description = o.get("description")
            row.platforms = sorted(set(o.get("x_mitre_platforms") or []))
            row.labels = sorted(set(o.get("labels") or []))
            row.references = _all_external_refs(o)
            row.deprecated = bool(o.get("x_mitre_deprecated"))
            row.revoked = bool(o.get("revoked"))
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            report.software += 1

        # ----- Data sources + components (DS####) -----
        # Components are children of a data source via x_mitre_data_source_ref.
        # We collapse them into the data source's data_components JSONB so
        # the catalog stays one row per DS (matches MITRE Navigator's model).
        components_by_source: dict[str, list[dict[str, Any]]] = {}
        ds_id_to_external: dict[str, str] = {
            o.get("id"): _external_id(o) for o in objects if _is_data_source(o)
        }
        for o in objects:
            if not _is_data_component(o):
                continue
            parent_stix_id = o.get("x_mitre_data_source_ref")
            parent_ext = ds_id_to_external.get(parent_stix_id)
            if not parent_ext:
                continue
            components_by_source.setdefault(parent_ext, []).append(
                {
                    "name": o.get("name"),
                    "description": o.get("description"),
                    "stix_id": o.get("id"),
                }
            )

        existing_ds = {
            d.external_id: d
            for d in (
                await db.execute(
                    select(MitreDataSource).where(
                        MitreDataSource.matrix == matrix.value
                    )
                )
            ).scalars()
        }
        for o in objects:
            if not _is_data_source(o):
                continue
            ext_id = _external_id(o)
            row = existing_ds.get(ext_id) or MitreDataSource(
                matrix=matrix.value,
                external_id=ext_id,
                name=o.get("name") or ext_id,
            )
            row.matrix = matrix.value
            row.name = o.get("name") or ext_id
            row.description = o.get("description")
            row.platforms = sorted(set(o.get("x_mitre_platforms") or []))
            row.collection_layers = sorted(
                set(o.get("x_mitre_collection_layers") or [])
            )
            row.data_components = components_by_source.get(ext_id, [])
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            report.data_sources += 1

        # ----- Campaigns (C####) -----
        existing_camp = {
            c.external_id: c
            for c in (
                await db.execute(
                    select(MitreCampaign).where(MitreCampaign.matrix == matrix.value)
                )
            ).scalars()
        }
        for o in objects:
            if not _is_campaign(o):
                continue
            ext_id = _external_id(o)
            row = existing_camp.get(ext_id) or MitreCampaign(
                matrix=matrix.value,
                external_id=ext_id,
                name=o.get("name") or ext_id,
            )
            row.matrix = matrix.value
            row.name = o.get("name") or ext_id
            row.aliases = sorted(set(o.get("aliases") or []))
            row.description = o.get("description")
            from datetime import datetime as _dt

            def _parse(ts: str | None):
                if not ts:
                    return None
                try:
                    return _dt.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:  # noqa: BLE001
                    return None

            row.first_seen = _parse(o.get("first_seen"))
            row.last_seen = _parse(o.get("last_seen"))
            row.references = _all_external_refs(o)
            row.url = _external_url(o)
            row.sync_version = sync_version
            row.raw = o
            db.add(row)
            report.campaigns += 1

        # ----- Relationships (technique↔group↔software↔mitigation) -----
        # STIX object IDs → (type, external_id) lookup so we can resolve
        # relationship endpoints without a second pass.
        stix_id_index: dict[str, tuple[str, str]] = {}
        for o in objects:
            ext = _external_id(o)
            if not ext:
                continue
            t = o.get("type")
            sid = o.get("id")
            if t == "intrusion-set":
                stix_id_index[sid] = ("group", ext)
            elif t == "attack-pattern":
                stix_id_index[sid] = ("technique", ext)
            elif t == "malware":
                stix_id_index[sid] = ("software", ext)
            elif t == "tool":
                stix_id_index[sid] = ("software", ext)
            elif t == "course-of-action":
                stix_id_index[sid] = ("mitigation", ext)
            elif t == "x-mitre-data-source":
                stix_id_index[sid] = ("data-source", ext)
            elif t == "campaign":
                stix_id_index[sid] = ("campaign", ext)
            elif t == "x-mitre-tactic":
                stix_id_index[sid] = ("tactic", ext)

        # Pre-load existing relationships to avoid N inserts per sync.
        existing_rels = {
            (
                r.source_type,
                r.source_external_id,
                r.relationship_type,
                r.target_type,
                r.target_external_id,
            ): r
            for r in (
                await db.execute(
                    select(MitreRelationship).where(
                        MitreRelationship.matrix == matrix.value
                    )
                )
            ).scalars()
        }
        for o in objects:
            if not _is_relationship(o):
                continue
            src_pair = stix_id_index.get(o.get("source_ref"))
            tgt_pair = stix_id_index.get(o.get("target_ref"))
            if not src_pair or not tgt_pair:
                continue
            rel_type = o.get("relationship_type") or "related-to"
            key = (src_pair[0], src_pair[1], rel_type, tgt_pair[0], tgt_pair[1])
            row = existing_rels.get(key) or MitreRelationship(
                matrix=matrix.value,
                source_type=src_pair[0],
                source_external_id=src_pair[1],
                relationship_type=rel_type,
                target_type=tgt_pair[0],
                target_external_id=tgt_pair[1],
            )
            row.matrix = matrix.value
            row.description = o.get("description")
            row.references = _all_external_refs(o)
            row.sync_version = sync_version
            db.add(row)
            report.relationships += 1

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


# --- Cross-sync derived data: import MITRE Groups → ThreatActor table ----

async def upsert_actors_from_groups(
    db: AsyncSession,
    *,
    organization_id=None,  # accepted for API symmetry; ThreatActor is global
) -> int:
    """Auto-create / update ThreatActor rows from MitreGroup rows.

    Idempotent. Matches on `mitre_group_id` first, then by
    case-insensitive `primary_alias`. Pulls aliases, country/sector
    tags, references, malware families (via relationships) into the
    actor profile so /actors becomes a real Group encyclopedia.

    Note: ThreatActor is a global catalog; ``organization_id`` is
    accepted but not used as a filter — every org sees the same
    catalog and can layer per-org overrides via separate tables.
    """
    from datetime import datetime, timezone

    from src.models.intel import ThreatActor

    groups = (
        await db.execute(
            select(MitreGroup).where(
                MitreGroup.deprecated.is_(False), MitreGroup.revoked.is_(False)
            )
        )
    ).scalars().all()

    # Per-group: pull techniques, software, campaigns it's linked to.
    rels = (
        await db.execute(
            select(MitreRelationship).where(
                MitreRelationship.source_type == "group"
            )
        )
    ).scalars().all()
    by_group: dict[str, dict[str, list[str]]] = {}
    for r in rels:
        bucket = by_group.setdefault(
            r.source_external_id, {"techniques": [], "software": [], "campaigns": []}
        )
        if r.relationship_type == "uses" and r.target_type == "technique":
            bucket["techniques"].append(r.target_external_id)
        elif r.relationship_type == "uses" and r.target_type == "software":
            bucket["software"].append(r.target_external_id)
        elif r.relationship_type == "attributed-to" and r.target_type == "campaign":
            bucket["campaigns"].append(r.target_external_id)

    # Software ext_id → name for the malware_families list on the actor.
    sw_rows = (await db.execute(select(MitreSoftware))).scalars().all()
    sw_name = {s.external_id: s.name for s in sw_rows}

    existing_actors_by_group_id = {}
    existing_actors_by_alias: dict[str, ThreatActor] = {}
    actor_rows = (
        await db.execute(select(ThreatActor))
    ).scalars().all()
    for a in actor_rows:
        if a.mitre_group_id:
            existing_actors_by_group_id[a.mitre_group_id] = a
        if a.primary_alias:
            existing_actors_by_alias[a.primary_alias.lower()] = a

    now = datetime.now(timezone.utc)
    written = 0
    for g in groups:
        actor = existing_actors_by_group_id.get(g.external_id)
        if actor is None:
            actor = existing_actors_by_alias.get((g.name or "").lower())
        if actor is None:
            actor = ThreatActor(
                primary_alias=g.name,
                first_seen=now,
                last_seen=now,
                aliases=g.aliases or [],
            )
        actor.mitre_group_id = g.external_id
        actor.primary_alias = actor.primary_alias or g.name
        actor.description = g.description or actor.description
        # Merge aliases without losing analyst-added ones.
        merged_aliases = sorted(set((actor.aliases or []) + (g.aliases or [])))
        actor.aliases = merged_aliases
        actor.country_codes = g.country_codes or []
        actor.references = g.references or []
        actor.confidence = max(actor.confidence or 0.7, 0.85)
        # Backfill techniques + malware from relationships.
        bucket = by_group.get(g.external_id) or {}
        techs = sorted(set((actor.known_ttps or []) + (bucket.get("techniques") or [])))
        actor.known_ttps = techs
        malware_names = sorted(
            {sw_name[s] for s in (bucket.get("software") or []) if s in sw_name}
        )
        if malware_names:
            actor.malware_families = sorted(
                set((actor.malware_families or []) + malware_names)
            )
        actor.last_seen = now
        db.add(actor)
        written += 1
    await db.commit()
    return written


__all__ = [
    "SyncReport",
    "DEFAULT_BUNDLE_URLS",
    "load_bundle",
    "sync_matrix",
    "upsert_actors_from_groups",
]
