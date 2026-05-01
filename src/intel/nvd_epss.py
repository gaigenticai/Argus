"""NVD CVE + FIRST EPSS + CISA KEV ingestion.

Three small, append-and-update parsers. URLs default to the canonical
public endpoints but can be overridden for tests + air-gapped operation.

NVD REST API v2.0     https://services.nvd.nist.gov/rest/json/cves/2.0
EPSS daily CSV (gz)   https://epss.cyentia.com/epss_scores-current.csv.gz
CISA KEV catalog      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import io
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel_polish import CveRecord, IntelSync


_logger = logging.getLogger(__name__)


@dataclass
class SyncReport:
    source: str
    source_url: str | None
    rows_ingested: int
    rows_updated: int
    succeeded: bool
    error: str | None = None


# --- Loaders -----------------------------------------------------------


async def _load_bytes(source: str, *, timeout: float = 120) -> bytes:
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
            async with sess.get(source) as resp:
                resp.raise_for_status()
                return await resp.read()
    p = Path(parsed.path or source)
    return p.read_bytes()


async def _load_text(source: str, *, timeout: float = 120) -> str:
    blob = await _load_bytes(source, timeout=timeout)
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob).decode("utf-8", errors="replace")
    return blob.decode("utf-8", errors="replace")


async def _load_json(source: str, *, timeout: float = 120) -> Any:
    return json.loads(await _load_text(source, timeout=timeout))


# Sentinel substring that distinguishes the NVD 2.0 REST API from a local
# file path or legacy gzip mirror URL.
_NVD_V2_REST_INDICATOR = "services.nvd.nist.gov/rest/json/cves"


async def _fetch_nvd_v2_pages(
    base_url: str,
    *,
    api_key: str | None = None,
    lookback_days: int = 1,
    timeout: float = 120,
) -> list[dict]:
    """Fetch all pages from the NVD 2.0 REST API for the given lookback window.

    Rate limits: 50 req/30s without an API key, 2000 req/30s with one.
    We sleep 0.7s between pages (without key) to stay safely under the limit.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=lookback_days)
    params: dict[str, Any] = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    all_items: list[dict] = []
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
        while True:
            async with sess.get(base_url, params=params, headers=headers) as resp:
                if resp.status == 404:
                    raise ValueError(
                        f"NVD API returned 404 for {base_url!r}. "
                        "The NVD v1.1 feed URLs were retired Dec 2023. "
                        "Ensure ARGUS_WORKER_NVD_URL points to the v2.0 REST API: "
                        "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    )
                resp.raise_for_status()
                data = await resp.json(content_type=None)

            items = data.get("vulnerabilities") or []
            all_items.extend(items)

            total = data.get("totalResults", 0)
            params["startIndex"] += len(items)
            if params["startIndex"] >= total or not items:
                break

            # Respect rate limit: ≥ 0.6s between requests without API key.
            await asyncio.sleep(0.1 if api_key else 0.7)

    return all_items


# --- NVD ---------------------------------------------------------------


def _nvd_severity(metric: dict | None) -> tuple[float | None, str | None, str | None]:
    if not metric:
        return None, None, None
    score = metric.get("cvssData", {}).get("baseScore")
    vec = metric.get("cvssData", {}).get("vectorString")
    sev = metric.get("baseSeverity") or metric.get("cvssData", {}).get("baseSeverity")
    if score is not None:
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None
    return score, vec, sev.lower() if isinstance(sev, str) else None


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


async def sync_nvd(
    db: AsyncSession,
    *,
    source: str,
    triggered_by_user_id=None,
) -> SyncReport:
    """Ingest NVD CVE data. ``source`` is either:
    - The NVD 2.0 REST API base URL (paginated fetch with lookback window), or
    - A local file path / gzip mirror URL (single-shot load for air-gap use).
    """
    report = SyncReport(source="nvd", source_url=source, rows_ingested=0, rows_updated=0, succeeded=False)
    try:
        if _NVD_V2_REST_INDICATOR in source:
            api_key = os.environ.get("ARGUS_NVD_API_KEY") or None
            lookback_days = int(os.environ.get("ARGUS_NVD_LOOKBACK_DAYS", "1"))
            items = await _fetch_nvd_v2_pages(
                source, api_key=api_key, lookback_days=lookback_days
            )
        else:
            bundle = await _load_json(source)
            items = bundle.get("vulnerabilities") or bundle.get("CVE_Items") or []
    except Exception as e:  # noqa: BLE001
        report.error = f"load failed: {e}"
        await _record_sync(db, report, triggered_by_user_id)
        return report
    inserted = 0
    updated = 0

    for entry in items:
        cve = entry.get("cve") or entry
        cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions") or []
        desc = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            None,
        )
        # CVSS — prefer v3.1, else v3.0.
        metrics = cve.get("metrics") or {}
        score, vec, sev = (None, None, None)
        for key in ("cvssMetricV31", "cvssMetricV30"):
            ms = metrics.get(key)
            if ms:
                score, vec, sev = _nvd_severity(ms[0])
                break
        published = _parse_iso(cve.get("published"))
        modified = _parse_iso(cve.get("lastModified"))
        cwes = []
        for w in cve.get("weaknesses") or []:
            for d in w.get("description") or []:
                if d.get("value") and d["value"].startswith("CWE-"):
                    cwes.append(d["value"])
        refs = [r.get("url") for r in cve.get("references") or [] if r.get("url")]
        cpes: list[str] = []
        for cfg in cve.get("configurations") or []:
            nodes = cfg.get("nodes") if isinstance(cfg, dict) else []
            for n in nodes or []:
                for m in n.get("cpeMatch") or []:
                    if m.get("criteria"):
                        cpes.append(m["criteria"])

        existing = (
            await db.execute(
                select(CveRecord).where(CveRecord.cve_id == cve_id)
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                CveRecord(
                    cve_id=cve_id,
                    title=desc[:500] if desc else cve_id,
                    description=desc,
                    cvss3_score=score,
                    cvss3_vector=vec,
                    cvss_severity=sev,
                    published_at=published,
                    last_modified_at=modified,
                    cwe_ids=sorted(set(cwes)),
                    references=refs[:50],
                    cpes=sorted(set(cpes))[:50],
                )
            )
            inserted += 1
        else:
            existing.title = desc[:500] if desc else existing.title
            existing.description = desc or existing.description
            if score is not None:
                existing.cvss3_score = score
                existing.cvss3_vector = vec
                existing.cvss_severity = sev
            if published is not None:
                existing.published_at = published
            if modified is not None:
                existing.last_modified_at = modified
            if cwes:
                existing.cwe_ids = sorted(set(cwes))
            if refs:
                existing.references = refs[:50]
            if cpes:
                existing.cpes = sorted(set(cpes))[:50]
            updated += 1

    report.rows_ingested = inserted
    report.rows_updated = updated
    report.succeeded = True
    await _record_sync(db, report, triggered_by_user_id)
    return report


# --- EPSS --------------------------------------------------------------


async def sync_epss(
    db: AsyncSession,
    *,
    source: str,
    triggered_by_user_id=None,
) -> SyncReport:
    report = SyncReport(source="epss", source_url=source, rows_ingested=0, rows_updated=0, succeeded=False)
    try:
        text = await _load_text(source)
    except Exception as e:  # noqa: BLE001
        report.error = f"load failed: {e}"
        await _record_sync(db, report, triggered_by_user_id)
        return report

    inserted = 0
    updated = 0
    # FIRST EPSS file has 1-2 header lines starting with "#" then CSV.
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.DictReader(lines)
    if not reader.fieldnames or "cve" not in reader.fieldnames:
        report.error = "CSV missing 'cve' column"
        await _record_sync(db, report, triggered_by_user_id)
        return report

    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            score = float(row.get("epss") or 0)
        except ValueError:
            continue
        try:
            pct = float(row.get("percentile") or 0)
        except ValueError:
            pct = 0.0
        existing = (
            await db.execute(
                select(CveRecord).where(CveRecord.cve_id == cve_id)
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                CveRecord(
                    cve_id=cve_id,
                    title=cve_id,
                    epss_score=score,
                    epss_percentile=pct,
                )
            )
            inserted += 1
        else:
            existing.epss_score = score
            existing.epss_percentile = pct
            updated += 1

    report.rows_ingested = inserted
    report.rows_updated = updated
    report.succeeded = True
    await _record_sync(db, report, triggered_by_user_id)
    return report


# --- KEV ---------------------------------------------------------------


async def sync_kev(
    db: AsyncSession,
    *,
    source: str,
    triggered_by_user_id=None,
) -> SyncReport:
    report = SyncReport(source="kev", source_url=source, rows_ingested=0, rows_updated=0, succeeded=False)
    try:
        bundle = await _load_json(source)
    except Exception as e:  # noqa: BLE001
        report.error = f"load failed: {e}"
        await _record_sync(db, report, triggered_by_user_id)
        return report
    items = bundle.get("vulnerabilities") or []
    inserted = 0
    updated = 0
    for it in items:
        cve_id = (it.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        added = it.get("dateAdded")
        added_dt = None
        if added:
            try:
                added_dt = datetime.fromisoformat(added).replace(tzinfo=timezone.utc)
            except ValueError:
                added_dt = None
        existing = (
            await db.execute(
                select(CveRecord).where(CveRecord.cve_id == cve_id)
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                CveRecord(
                    cve_id=cve_id,
                    title=it.get("vulnerabilityName") or cve_id,
                    description=it.get("shortDescription"),
                    is_kev=True,
                    kev_added_at=added_dt,
                )
            )
            inserted += 1
        else:
            existing.is_kev = True
            existing.kev_added_at = existing.kev_added_at or added_dt
            updated += 1

    report.rows_ingested = inserted
    report.rows_updated = updated
    report.succeeded = True
    await _record_sync(db, report, triggered_by_user_id)
    return report


# --- Audit row ---------------------------------------------------------


async def _record_sync(
    db: AsyncSession, report: SyncReport, triggered_by_user_id
) -> None:
    db.add(
        IntelSync(
            source=report.source,
            source_url=report.source_url,
            rows_ingested=report.rows_ingested,
            rows_updated=report.rows_updated,
            succeeded=report.succeeded,
            error_message=report.error,
            triggered_by_user_id=triggered_by_user_id,
        )
    )
    await db.commit()


__all__ = ["SyncReport", "sync_nvd", "sync_epss", "sync_kev"]
