"""SigmaHQ rule ingestion.

Source of truth: github.com/SigmaHQ/sigma — distributed as one YAML file
per rule under ``rules/`` and ``rules-emerging-threats/``. We pull the
tarball of the latest tag (small — ~6 MB compressed), unpack in-memory,
parse each YAML, and upsert to ``sigma_rules``.

Tags of the form ``attack.t1234`` / ``attack.t1234.001`` are parsed out
into ``technique_ids`` so the technique-coverage computation can join
them onto :class:`MitreTechnique` rows.

We also derive per-org coverage rows (ALL orgs see the same Sigma
catalog so we materialise one row per technique into
``mitre_technique_coverage`` per active org).
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import re
import tarfile
from typing import Any

import aiohttp
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.mitre import MitreMatrix, MitreTechniqueCoverage
from src.models.sigma_rules import SigmaRule
from src.models.threat import Organization

_logger = logging.getLogger(__name__)

# Tarball of the master branch — stable URL, ~6 MB.
SIGMA_TARBALL = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"

_TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def _extract_techniques(tags: list[str]) -> list[str]:
    out: list[str] = []
    for t in tags or []:
        m = _TECH_RE.match(t.strip())
        if m:
            out.append(m.group(1).upper())
    return sorted(set(out))


def _parse_rule(yaml_text: str, *, source_path: str) -> dict[str, Any] | None:
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    rid = doc.get("id")
    title = doc.get("title")
    if not rid or not title:
        return None
    tags = [str(t) for t in (doc.get("tags") or []) if isinstance(t, (str, int))]
    return {
        "rule_id": str(rid)[:64],
        "title": str(title)[:500],
        "description": doc.get("description"),
        "level": (doc.get("level") or None) and str(doc.get("level"))[:20],
        "status": (doc.get("status") or None) and str(doc.get("status"))[:40],
        "author": (doc.get("author") or None) and str(doc.get("author"))[:255],
        "log_source": doc.get("logsource") or {},
        "detection": doc.get("detection") or {},
        "falsepositives": [
            str(x) for x in (doc.get("falsepositives") or []) if isinstance(x, str)
        ],
        "tags": tags,
        "technique_ids": _extract_techniques(tags),
        "references": [
            str(x) for x in (doc.get("references") or []) if isinstance(x, str)
        ],
        "source_repo": "github.com/SigmaHQ/sigma",
        "source_path": source_path,
        "sha256": hashlib.sha256(yaml_text.encode("utf-8")).hexdigest(),
        "raw_yaml": yaml_text,
    }


async def _download_tarball() -> bytes:
    timeout = aiohttp.ClientTimeout(total=180)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.get(SIGMA_TARBALL) as r:
            r.raise_for_status()
            return await r.read()


def _iter_rule_yamls(tarball: bytes):
    bio = io.BytesIO(tarball)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or not member.name.endswith(".yml"):
                continue
            # SigmaHQ ships rules under rules/, rules-emerging-threats/,
            # rules-threat-hunting/, rules-compliance/. Skip docs/
            # non-rule yamls.
            if "/rules" not in member.name:
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            try:
                text = f.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            yield member.name, text


async def ingest_sigma_rules(db: AsyncSession) -> dict[str, int]:
    """Idempotent SigmaHQ ingest.

    Strategy: stream tarball → parse YAML → upsert by ``rule_id``.
    A rule whose sha256 matches the existing row is skipped (cheap
    re-runs).
    """
    raw = await _download_tarball()

    existing_rows = (
        await db.execute(select(SigmaRule.rule_id, SigmaRule.sha256))
    ).all()
    existing = {rid: sha for rid, sha in existing_rows}

    inserted = updated = unchanged = 0
    techniques_seen: set[str] = set()
    batch = 0
    for path, text in _iter_rule_yamls(raw):
        rule = _parse_rule(text, source_path=path)
        if rule is None:
            continue
        techniques_seen.update(rule["technique_ids"])
        prior_sha = existing.get(rule["rule_id"])
        if prior_sha == rule["sha256"]:
            unchanged += 1
            continue
        if prior_sha is None:
            db.add(SigmaRule(**rule))
            inserted += 1
        else:
            row = (
                await db.execute(
                    select(SigmaRule).where(SigmaRule.rule_id == rule["rule_id"])
                )
            ).scalar_one_or_none()
            if row is not None:
                for k, v in rule.items():
                    setattr(row, k, v)
                updated += 1
        batch += 1
        if batch % 500 == 0:
            await db.flush()
            await db.commit()
    await db.commit()
    return {
        "inserted": inserted,
        "updated": updated,
        "unchanged": unchanged,
        "techniques_observed": len(techniques_seen),
    }


# --------------------------------------------------------------------
# Per-org technique coverage auto-derive from sigma_rules
# --------------------------------------------------------------------


async def derive_coverage_from_sigma(
    db: AsyncSession,
    *,
    organization_id=None,
) -> dict[str, int]:
    """Compute coverage rows by counting Sigma rules per technique.

    Score = min(100, 30 + 8 * log2(rule_count + 1))
    so 1 rule → 38, 5 rules → 51, 30 rules → 70, 100 rules → 84.

    `covered_by` always includes "sigma" (extend later for yara/edr).
    Idempotent — re-running rebuilds the rows.
    """
    import math

    rows = (
        await db.execute(
            select(SigmaRule.technique_ids).where(
                SigmaRule.technique_ids != []  # noqa: E711
            )
        )
    ).all()
    counts: dict[str, int] = {}
    for (techs,) in rows:
        for t in techs or []:
            counts[t] = counts.get(t, 0) + 1

    org_ids: list = []
    if organization_id is not None:
        org_ids = [organization_id]
    else:
        org_ids = list(
            (await db.execute(select(Organization.id))).scalars().all()
        )

    upserts = 0
    for org_id in org_ids:
        existing = {
            (r.matrix, r.technique_external_id): r
            for r in (
                await db.execute(
                    select(MitreTechniqueCoverage).where(
                        MitreTechniqueCoverage.organization_id == org_id
                    )
                )
            ).scalars().all()
        }
        for tech, cnt in counts.items():
            score = int(min(100, 30 + 8 * math.log2(cnt + 1)))
            key = (MitreMatrix.ENTERPRISE.value, tech)
            row = existing.get(key)
            if row is None:
                db.add(
                    MitreTechniqueCoverage(
                        organization_id=org_id,
                        matrix=MitreMatrix.ENTERPRISE.value,
                        technique_external_id=tech,
                        covered_by=["sigma"],
                        score=score,
                        notes=f"auto-derived from {cnt} Sigma rule(s)",
                    )
                )
            else:
                covered = sorted(set((row.covered_by or []) + ["sigma"]))
                row.covered_by = covered
                row.score = max(row.score or 0, score)
                row.notes = f"auto-derived from {cnt} Sigma rule(s)"
            upserts += 1
    await db.commit()
    return {"upserts": upserts, "techniques": len(counts), "orgs": len(org_ids)}


__all__ = [
    "SIGMA_TARBALL",
    "ingest_sigma_rules",
    "derive_coverage_from_sigma",
]
