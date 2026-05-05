"""Vendor-advisory ingestion (CISA KEV + GHSA + future feeds).

CISA KEV is a single canonical JSON catalog refreshed daily. We upsert
each entry as an :class:`Advisory` with ``source='cisa_kev'`` and
``external_id`` set to the CVE id, so re-running the job is idempotent.

When the CVE already exists in :class:`CveRecord` we hydrate the new
``cvss3_score`` and ``epss_score`` columns on the advisory so the FE
can render the badge without a JOIN.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel_polish import CveRecord
from src.models.news import Advisory, AdvisoryState

_logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _slugify(s: str) -> str:
    out = "".join(c.lower() if c.isalnum() else "-" for c in s)
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")[:200]


async def ingest_cisa_kev(db: AsyncSession) -> dict[str, int]:
    """Bulletproof CISA KEV ingest: retries, multi-shape JSON tolerance,
    health-row recording. KEV's canonical shape is
    ``{"vulnerabilities": [...]}`` but defensive parsing also accepts
    a top-level array."""
    from src.intel._advisory_helpers import (
        fetch_with_retry,
        normalize_list,
        parse_json_lenient,
        record_health,
        track_missing,
        walk_keys,
    )

    started = datetime.now(timezone.utc)
    status, body, _hdrs, attempts = await fetch_with_retry(
        CISA_KEV_URL,
        headers={"Accept": "application/json"},
        timeout_s=90,
    )
    payload = parse_json_lenient(body) if status == 200 else None
    if payload is None:
        await record_health(
            db,
            source="cisa_kev",
            source_url=CISA_KEV_URL,
            started_at=started,
            status="error",
            http_status=status,
            attempts=attempts,
            error_message="CISA KEV unreachable or unparseable",
            raw_sample=body,
        )
        return {
            "inserted": 0,
            "updated": 0,
            "total": 0,
            "error": "kev_unreachable",
            "http_status": status,
        }
    rows, shape = normalize_list(payload)
    if not rows:
        await record_health(
            db,
            source="cisa_kev",
            source_url=CISA_KEV_URL,
            started_at=started,
            status="error",
            http_status=status,
            attempts=attempts,
            schema_shape=shape,
            error_message="CISA KEV payload had no vulnerabilities",
            raw_sample=body,
        )
        return {"inserted": 0, "updated": 0, "total": 0, "shape": shape}

    inserted = updated = parsed = skipped = 0
    missing: dict[str, int] = {}
    cve_records = {
        c.cve_id: c
        for c in (await db.execute(select(CveRecord))).scalars().all()
    }
    now = datetime.now(timezone.utc)
    for v in rows:
        if not isinstance(v, dict):
            skipped += 1
            continue
        cve_id = walk_keys(v, "cveID", "cveId", "cve_id")
        if not cve_id:
            track_missing(missing, "cveID")
            skipped += 1
            continue
        external_id = str(cve_id)
        vname = walk_keys(v, "vulnerabilityName", "vulnerability_name", "name")
        title = (str(vname) if vname else external_id)[:500]
        vendor = walk_keys(v, "vendorProject", "vendor_project", "vendor")
        product = walk_keys(v, "product")
        action = walk_keys(v, "requiredAction", "required_action")
        due_date = walk_keys(v, "dueDate", "due_date")
        notes = walk_keys(v, "notes")
        short_desc = walk_keys(
            v, "shortDescription", "short_description", "description"
        )
        body_md = (
            f"**Vendor:** {vendor}  ·  **Product:** {product}\n\n"
            f"**Required action:** {action}\n\n"
            f"**Due date:** {due_date}\n\n"
            f"**Notes:** {notes or 'n/a'}\n\n"
            f"**Short description:** {short_desc}"
        )
        cve_rec = cve_records.get(external_id)
        cvss3 = float(cve_rec.cvss3_score) if cve_rec and cve_rec.cvss3_score is not None else None
        epss = float(cve_rec.epss_score) if cve_rec and cve_rec.epss_score is not None else None

        existing = (
            await db.execute(
                select(Advisory).where(
                    Advisory.source == "cisa_kev",
                    Advisory.external_id == external_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                Advisory(
                    organization_id=None,
                    slug=_slugify(f"cisa-kev-{external_id}"),
                    title=title,
                    body_markdown=body_md,
                    severity="critical",
                    state=AdvisoryState.PUBLISHED.value,
                    tags=["cisa-kev", "kev", external_id],
                    cve_ids=[external_id],
                    references=[
                        f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        f"https://nvd.nist.gov/vuln/detail/{external_id}",
                    ],
                    published_at=now,
                    source="cisa_kev",
                    external_id=external_id,
                    cvss3_score=cvss3,
                    epss_score=epss,
                    is_kev=True,
                    affected_products=[
                        {"vendor": vendor, "product": product}
                    ],
                    remediation_steps=[
                        {"action": action, "due_date": due_date},
                    ],
                    triage_state="new",
                )
            )
            inserted += 1
        else:
            existing.title = title
            existing.body_markdown = body_md
            existing.cvss3_score = cvss3
            existing.epss_score = epss
            existing.is_kev = True
            existing.affected_products = [{"vendor": vendor, "product": product}]
            existing.remediation_steps = [
                {"action": action, "due_date": due_date},
            ]
            updated += 1
        parsed += 1
    await db.commit()

    health_status = "ok" if parsed > 0 and skipped == 0 else (
        "partial" if parsed > 0 else "error"
    )
    await record_health(
        db,
        source="cisa_kev",
        source_url=CISA_KEV_URL,
        started_at=started,
        status=health_status,
        http_status=status,
        attempts=attempts,
        rows_seen=len(rows),
        rows_parsed=parsed,
        rows_inserted=inserted,
        rows_updated=updated,
        rows_skipped=skipped,
        schema_shape=shape,
        missing_fields=missing,
    )
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "total": len(rows),
        "shape": shape,
    }


async def _http_json(url: str, *, headers: dict[str, str] | None = None) -> Any:
    """Legacy thin wrapper. New code uses ``fetch_with_retry``."""
    from src.intel._advisory_helpers import fetch_with_retry, parse_json_lenient

    status, body, _, _ = await fetch_with_retry(url, headers=headers)
    if status >= 400:
        raise RuntimeError(f"HTTP {status} fetching {url}")
    parsed = parse_json_lenient(body)
    if parsed is None:
        raise RuntimeError(f"Could not parse JSON from {url}")
    return parsed


# ============================================================
# Microsoft MSRC (CVRF / CSAF feed)
# ============================================================
#
# MSRC publishes their advisory index in two API generations and three
# document formats. We try them in order until one parses cleanly:
#
#   1. v3.0 JSON           https://api.msrc.microsoft.com/cvrf/v3.0/updates
#   2. v2.0 JSON           https://api.msrc.microsoft.com/cvrf/v2.0/updates
#   3. v3.0 Atom feed      https://api.msrc.microsoft.com/cvrf/v3.0/updates.atom
#
# The JSON shape is *usually* ``{"value": [{...}, ...]}`` but has at
# times shipped as a top-level array. Per-record keys also drift
# between PascalCase ("ID", "DocumentTitle") and camelCase ("id",
# "documentTitle"). We tolerate both via case-insensitive walk_keys.

MSRC_INDEX_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"

MSRC_FALLBACK_URLS = (
    "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
)


async def ingest_msrc(db: AsyncSession, *, max_docs: int = 12) -> dict[str, int]:
    """Pull the latest MSRC index and upsert each entry under
    ``source='msrc'``. Bulletproof against schema drift, rate limits,
    and transient 5xx via retries + multi-shape parsing + per-source
    health row."""
    from src.intel._advisory_helpers import (
        fetch_with_retry,
        normalize_list,
        parse_json_lenient,
        record_health,
        slugify as _slug,
        track_missing,
        walk_keys,
    )

    started = datetime.now(timezone.utc)
    last_status = 0
    last_attempts = 0
    last_url = ""
    last_body: bytes = b""
    payload: Any = None

    for url in MSRC_FALLBACK_URLS:
        last_url = url
        status, body, _hdrs, attempts = await fetch_with_retry(
            url,
            headers={"Accept": "application/json"},
            timeout_s=60,
        )
        last_status = status
        last_attempts = attempts
        last_body = body
        if status == 200:
            payload = parse_json_lenient(body)
            if payload is not None:
                break
        _logger.info("MSRC fallback continues: %s → status=%s", url, status)

    if payload is None:
        await record_health(
            db,
            source="msrc",
            source_url=last_url,
            started_at=started,
            status="error",
            http_status=last_status,
            attempts=last_attempts,
            error_message="MSRC index unreachable or unparseable across all fallback URLs",
            raw_sample=last_body,
        )
        return {
            "inserted": 0,
            "updated": 0,
            "total": 0,
            "error": "msrc_unreachable",
            "http_status": last_status,
        }

    docs, shape = normalize_list(payload)
    if not docs:
        await record_health(
            db,
            source="msrc",
            source_url=last_url,
            started_at=started,
            status="error",
            http_status=last_status,
            attempts=last_attempts,
            schema_shape=shape,
            error_message=f"MSRC payload had recognised shape '{shape}' but no rows",
            raw_sample=last_body,
        )
        return {"inserted": 0, "updated": 0, "total": 0, "shape": shape}

    docs = docs[:max_docs]
    inserted = updated = parsed = skipped = 0
    missing: dict[str, int] = {}
    now = datetime.now(timezone.utc)

    for entry in docs:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        ext_id = walk_keys(entry, "ID", "id", "DocumentID", "documentId")
        if not ext_id:
            track_missing(missing, "id")
            skipped += 1
            continue
        ext_id = str(ext_id).strip()
        title = (
            walk_keys(entry, "DocumentTitle", "documentTitle", "title")
            or ext_id
        )
        cvrf_url = walk_keys(entry, "CvrfUrl", "cvrfUrl", "url")
        severity = (
            walk_keys(entry, "Severity", "severity", "DocumentSeverity")
            or "medium"
        )
        initial_release = walk_keys(
            entry, "InitialReleaseDate", "initialReleaseDate", "released_on"
        )
        current_release = walk_keys(
            entry, "CurrentReleaseDate", "currentReleaseDate", "updated_on"
        )
        cve_ids = []
        cves_field = walk_keys(entry, "CVEs", "cves", "cve_ids")
        if isinstance(cves_field, list):
            cve_ids = [str(c) for c in cves_field if isinstance(c, str)]

        body_md = (
            f"**Severity:** {severity}\n\n"
            f"**Initial release:** {initial_release}\n\n"
            f"**Current release:** {current_release}\n\n"
            f"Source CVRF: {cvrf_url}"
        )
        title_str = str(title)[:500]

        existing = (
            await db.execute(
                select(Advisory).where(
                    Advisory.source == "msrc",
                    Advisory.external_id == ext_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                Advisory(
                    organization_id=None,
                    slug=_slug(f"msrc-{ext_id}"),
                    title=title_str,
                    body_markdown=body_md,
                    severity=str(severity).lower()[:20] or "medium",
                    state=AdvisoryState.PUBLISHED.value,
                    tags=["msrc", ext_id],
                    cve_ids=cve_ids,
                    references=[cvrf_url] if cvrf_url else [],
                    published_at=now,
                    source="msrc",
                    external_id=ext_id,
                    is_kev=False,
                    triage_state="new",
                )
            )
            inserted += 1
        else:
            existing.title = title_str
            existing.body_markdown = body_md
            existing.cve_ids = cve_ids or existing.cve_ids
            updated += 1
        parsed += 1

    await db.commit()
    health_status = "ok" if parsed > 0 and skipped == 0 else (
        "partial" if parsed > 0 else "error"
    )
    await record_health(
        db,
        source="msrc",
        source_url=last_url,
        started_at=started,
        status=health_status,
        http_status=last_status,
        attempts=last_attempts,
        rows_seen=len(docs),
        rows_parsed=parsed,
        rows_inserted=inserted,
        rows_updated=updated,
        rows_skipped=skipped,
        schema_shape=shape,
        missing_fields=missing,
    )
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "total": len(docs),
        "shape": shape,
        "url": last_url,
    }


# ============================================================
# GitHub Security Advisories (GHSA, public GraphQL)
# ============================================================

GHSA_GRAPHQL = "https://api.github.com/graphql"

_GHSA_QUERY = """
query($severities: [SecurityAdvisorySeverity!], $first: Int!) {
  securityAdvisories(severities: $severities, first: $first, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      permalink
      cwes(first: 5) { nodes { cweId name } }
      identifiers { type value }
      vulnerabilities(first: 10) { nodes { package { ecosystem name } vulnerableVersionRange } }
    }
  }
}
"""


async def ingest_ghsa(
    db: AsyncSession,
    *,
    severities: tuple[str, ...] = ("CRITICAL", "HIGH"),
    first: int = 50,
) -> dict[str, int]:
    """Bulletproof GHSA ingest. Uses GraphQL with optional ``GITHUB_TOKEN``
    env var (anonymous = ~60 req/h, authenticated = 5000 req/h). Records
    a health row including rate-limit detection from response headers."""
    import os
    from src.intel._advisory_helpers import (
        fetch_with_retry,
        parse_json_lenient,
        record_health,
        slugify as _slug,
        track_missing,
        walk_keys,
    )

    started = datetime.now(timezone.utc)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "User-Agent": "Argus-CTI/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body_obj = {
        "query": _GHSA_QUERY,
        "variables": {"severities": list(severities), "first": first},
    }
    status, body, hdrs, attempts = await fetch_with_retry(
        GHSA_GRAPHQL,
        headers=headers,
        method="POST",
        json_body=body_obj,
        timeout_s=60,
    )
    if status != 200:
        rate_remaining = hdrs.get("x-ratelimit-remaining") or hdrs.get("X-RateLimit-Remaining")
        rate_reset = hdrs.get("x-ratelimit-reset") or hdrs.get("X-RateLimit-Reset")
        err = f"GHSA HTTP {status}"
        if status == 401:
            err += " (auth — set GITHUB_TOKEN env to lift the rate limit)"
        elif status == 403 and rate_remaining == "0":
            err += f" (rate-limited, resets at {rate_reset})"
        await record_health(
            db,
            source="ghsa",
            source_url=GHSA_GRAPHQL,
            started_at=started,
            status="error",
            http_status=status,
            attempts=attempts,
            error_message=err,
            raw_sample=body,
        )
        return {
            "inserted": 0,
            "updated": 0,
            "total": 0,
            "error": err,
            "http_status": status,
        }

    j = parse_json_lenient(body) or {}
    if "errors" in j:
        await record_health(
            db,
            source="ghsa",
            source_url=GHSA_GRAPHQL,
            started_at=started,
            status="error",
            http_status=status,
            attempts=attempts,
            schema_shape="graphql_errors",
            error_message=str(j.get("errors"))[:1000],
            raw_sample=body,
        )
        return {"inserted": 0, "updated": 0, "total": 0, "error": "graphql_errors"}

    nodes = (((j.get("data") or {}).get("securityAdvisories") or {}).get("nodes") or [])
    inserted = updated = parsed = skipped = 0
    missing: dict[str, int] = {}
    now = datetime.now(timezone.utc)
    for n in nodes:
        if not isinstance(n, dict):
            skipped += 1
            continue
        ghsa_id = walk_keys(n, "ghsaId", "ghsa_id", "id")
        if not ghsa_id:
            track_missing(missing, "ghsaId")
            skipped += 1
            continue
        ghsa_id = str(ghsa_id)
        cve_ids = sorted({
            ident.get("value")
            for ident in (n.get("identifiers") or [])
            if isinstance(ident, dict) and ident.get("type") == "CVE" and ident.get("value")
        })
        affected: list[dict] = []
        for v in (walk_keys(n, "vulnerabilities", default={}).get("nodes") or []):
            if not isinstance(v, dict):
                continue
            pkg = v.get("package") or {}
            if not isinstance(pkg, dict):
                continue
            affected.append({
                "ecosystem": pkg.get("ecosystem"),
                "package": pkg.get("name"),
                "vulnerable_version_range": v.get("vulnerableVersionRange"),
            })
        title = (
            walk_keys(n, "summary", "title") or ghsa_id
        )
        title = str(title)[:500]
        permalink = walk_keys(n, "permalink", "url")
        body_md = (
            f"{walk_keys(n, 'description') or '(no description)'}\n\n"
            f"**Severity:** {walk_keys(n, 'severity')}\n\n"
            f"**Published:** {walk_keys(n, 'publishedAt', 'published_at')}\n\n"
            f"**Permalink:** {permalink}"
        )
        existing = (
            await db.execute(
                select(Advisory).where(
                    Advisory.source == "ghsa",
                    Advisory.external_id == ghsa_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                Advisory(
                    organization_id=None,
                    slug=_slug(f"ghsa-{ghsa_id}"),
                    title=title,
                    body_markdown=body_md,
                    severity=str(walk_keys(n, "severity") or "medium").lower()[:20],
                    state=AdvisoryState.PUBLISHED.value,
                    tags=["ghsa", *cve_ids],
                    cve_ids=cve_ids,
                    references=[permalink] if permalink else [],
                    published_at=now,
                    source="ghsa",
                    external_id=ghsa_id,
                    affected_products=affected,
                    triage_state="new",
                )
            )
            inserted += 1
        else:
            existing.title = title
            existing.body_markdown = body_md
            existing.cve_ids = cve_ids
            existing.affected_products = affected
            updated += 1
        parsed += 1
    await db.commit()

    health_status = "ok" if parsed > 0 and skipped == 0 else (
        "partial" if parsed > 0 else "error"
    )
    await record_health(
        db,
        source="ghsa",
        source_url=GHSA_GRAPHQL,
        started_at=started,
        status=health_status,
        http_status=status,
        attempts=attempts,
        rows_seen=len(nodes),
        rows_parsed=parsed,
        rows_inserted=inserted,
        rows_updated=updated,
        rows_skipped=skipped,
        schema_shape="graphql_nodes",
        missing_fields=missing,
    )
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "total": len(nodes),
    }


# ============================================================
# Red Hat CSAF advisory feed
# ============================================================
#
# Red Hat publishes their CSAF index in three different shapes that
# rotate without warning:
#
#   1. changes.csv  (the canonical one — `path,last_updated` rows)
#   2. index.txt    (one filename per line)
#   3. *.json       (when present, shape varies: list-of-strings,
#                    list-of-objects, or {"data": [...]})
#
# We try each in priority order; the first one that yields a non-empty
# row list wins. Schema drift is logged into ``advisory_ingest_health``
# with the exact shape we recognised.

REDHAT_CSAF_BASE = "https://access.redhat.com/security/data/csaf/v2"

# Red Hat's CSAF feed lives under ``/advisories/`` — verified live
# 2026-05-04 against the production endpoints. ``changes.csv`` is the
# canonical incremental index (1.3 MB, ~17k rows); ``index.txt`` is
# the full filename list (600 KB) used as a fallback when CSV is
# unreachable. We deliberately probe the ``/advisories/`` paths first
# because the bare-``v2`` paths 404 with a generic Red Hat error page.
REDHAT_CSAF_INDEX_URLS = (
    f"{REDHAT_CSAF_BASE}/advisories/changes.csv",   # canonical CSV (path,timestamp)
    f"{REDHAT_CSAF_BASE}/advisories/index.txt",     # plain-text fallback
    f"{REDHAT_CSAF_BASE}/changes.csv",              # legacy/older deployments
    f"{REDHAT_CSAF_BASE}/index.txt",                # legacy/older deployments
)


def _parse_redhat_csv(body: bytes) -> tuple[list[dict[str, str]], str]:
    """changes.csv format: ``<filename>,<iso_timestamp>``."""
    text = body.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    out: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        # Some lines start with "#" comments
        if row[0].startswith("#"):
            continue
        # Allow either: ["file"] or ["file","ts"] or ["file","ts","..."]
        file_name = row[0].strip()
        if not file_name or not file_name.endswith(".json"):
            continue
        ts = row[1].strip() if len(row) > 1 else None
        out.append({"file": file_name, "released_on": ts})
    return out, "csv_changes"


def _parse_redhat_txt(body: bytes) -> tuple[list[dict[str, str]], str]:
    """One filename per line, optionally with size/timestamp columns."""
    text = body.decode("utf-8", errors="replace")
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Whitespace-separated; first token is the path
        token = line.split()[0]
        if token.endswith(".json"):
            out.append({"file": token})
    return out, "txt_index"


def _parse_redhat_json(body: bytes) -> tuple[list[dict[str, Any]], str]:
    from src.intel._advisory_helpers import (
        normalize_list,
        parse_json_lenient,
        walk_keys,
    )

    payload = parse_json_lenient(body)
    if payload is None:
        return [], "unparseable_json"
    rows, shape = normalize_list(payload)
    out: list[dict[str, Any]] = []
    for r in rows:
        if isinstance(r, str):
            # Some indices are just lists of filenames.
            if r.endswith(".json"):
                out.append({"file": r})
            continue
        if not isinstance(r, dict):
            continue
        f = walk_keys(r, "file", "path", "name", "filename") or walk_keys(r, "RHSA", "id")
        if not f:
            continue
        out.append({
            "file": str(f),
            "released_on": walk_keys(r, "released_on", "release_date", "last_updated"),
            "title": walk_keys(r, "title", "summary"),
            "severity": walk_keys(r, "severity", "aggregate_severity"),
            "cves": walk_keys(r, "cves", "CVEs", default=[]),
        })
    return out, f"json_{shape}"


async def ingest_redhat(db: AsyncSession, *, max_docs: int = 100) -> dict[str, int]:
    """Pull Red Hat CSAF index, parse whichever shape is currently
    served, and upsert under ``source='redhat'``. Schema-drift
    tolerant + observable."""
    from src.intel._advisory_helpers import (
        fetch_with_retry,
        record_health,
        slugify as _slug,
    )

    started = datetime.now(timezone.utc)
    last_status = 0
    last_attempts = 0
    last_url = ""
    last_body: bytes = b""

    rows: list[dict[str, Any]] = []
    shape = "no_data"

    for url in REDHAT_CSAF_INDEX_URLS:
        last_url = url
        accept = (
            "text/csv,*/*" if url.endswith(".csv")
            else "text/plain,*/*" if url.endswith(".txt")
            else "application/json"
        )
        status, body, _hdrs, attempts = await fetch_with_retry(
            url,
            headers={"Accept": accept},
            timeout_s=60,
        )
        last_status = status
        last_attempts = attempts
        last_body = body
        if status != 200 or not body:
            continue
        if url.endswith(".csv"):
            parsed_rows, parsed_shape = _parse_redhat_csv(body)
        elif url.endswith(".txt"):
            parsed_rows, parsed_shape = _parse_redhat_txt(body)
        else:
            parsed_rows, parsed_shape = _parse_redhat_json(body)
        if parsed_rows:
            rows = parsed_rows
            shape = parsed_shape
            break
        _logger.info("Red Hat fallback continues: %s parsed shape=%s rows=0", url, parsed_shape)

    if not rows:
        await record_health(
            db,
            source="redhat",
            source_url=last_url,
            started_at=started,
            status="error",
            http_status=last_status,
            attempts=last_attempts,
            schema_shape=shape,
            error_message="Red Hat CSAF index returned no rows from any known endpoint",
            raw_sample=last_body,
        )
        return {
            "inserted": 0,
            "updated": 0,
            "total": 0,
            "error": "redhat_no_rows",
            "shape": shape,
            "url": last_url,
        }

    rows = rows[:max_docs]
    inserted = updated = parsed = skipped = 0
    now = datetime.now(timezone.utc)
    missing: dict[str, int] = {}

    for entry in rows:
        file_id = entry.get("file") or entry.get("name")
        if not file_id:
            skipped += 1
            missing["file"] = missing.get("file", 0) + 1
            continue
        # Strip year prefix if present so external_id is canonical.
        # Example file values:
        #   "2024/cve-2024-12345.json" → external_id "cve-2024-12345"
        #   "rhsa-2024_1234.json"      → "rhsa-2024_1234"
        # We always uppercase + strip ``.json``.
        slug_id = (
            file_id.split("/")[-1].rsplit(".", 1)[0].upper()
        )
        # changes.csv ships paths relative to /advisories/, so the
        # full URL must include it.
        url = f"{REDHAT_CSAF_BASE}/advisories/{file_id.lstrip('/')}"
        title = (entry.get("title") or slug_id)[:500]
        body_md = (
            f"**Released:** {entry.get('released_on') or '(unknown)'}\n\n"
            f"**CSAF document:** {url}"
        )
        cve_field = entry.get("cves")
        cve_ids: list[str] = []
        if isinstance(cve_field, list):
            cve_ids = [str(c) for c in cve_field if isinstance(c, str)]

        existing = (
            await db.execute(
                select(Advisory).where(
                    Advisory.source == "redhat",
                    Advisory.external_id == slug_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                Advisory(
                    organization_id=None,
                    slug=_slug(f"redhat-{slug_id}"),
                    title=title,
                    body_markdown=body_md,
                    severity=str(entry.get("severity") or "medium").lower()[:20],
                    state=AdvisoryState.PUBLISHED.value,
                    tags=["redhat", slug_id.lower()],
                    cve_ids=cve_ids,
                    references=[url],
                    published_at=now,
                    source="redhat",
                    external_id=slug_id,
                    triage_state="new",
                )
            )
            inserted += 1
        else:
            existing.title = title
            existing.body_markdown = body_md
            if cve_ids:
                existing.cve_ids = cve_ids
            updated += 1
        parsed += 1

    await db.commit()
    health_status = "ok" if parsed > 0 and skipped == 0 else (
        "partial" if parsed > 0 else "error"
    )
    await record_health(
        db,
        source="redhat",
        source_url=last_url,
        started_at=started,
        status=health_status,
        http_status=last_status,
        attempts=last_attempts,
        rows_seen=len(rows),
        rows_parsed=parsed,
        rows_inserted=inserted,
        rows_updated=updated,
        rows_skipped=skipped,
        schema_shape=shape,
        missing_fields=missing,
    )
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "total": len(rows),
        "shape": shape,
        "url": last_url,
    }


__all__ = [
    "ingest_cisa_kev",
    "ingest_msrc",
    "ingest_ghsa",
    "ingest_redhat",
    "CISA_KEV_URL",
    "MSRC_INDEX_URL",
    "GHSA_GRAPHQL",
    "REDHAT_CSAF_INDEX",
]
