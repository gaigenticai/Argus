"""Defensive HTTP + parsing helpers for advisory ingesters.

Designed for production use against external APIs whose schemas drift
without notice. Key principles:

  * Always retry transient errors (5xx, 408, 429) with exponential backoff
  * Try multiple Accept headers / endpoint variants
  * Tolerate JSON shapes: ``[...]`` / ``{"value": [...]}`` / ``{"data":
    [...]}`` / ``{"entries": [...]}``
  * Tolerate CSV + TXT + JSON for index files
  * Walk per-entry keys via case-tolerant lookup
  * Write a structured ``AdvisoryIngestHealth`` row for every run so
    operators see per-source state from /news/advisories/ingest/health
    instead of grepping logs
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.advisory_health import AdvisoryIngestHealth

_logger = logging.getLogger(__name__)

_DEFAULT_HEADERS = {
    "User-Agent": "Argus-CTI/1.0 (+https://argus.security)",
}

_RETRYABLE_STATUSES = {408, 429, 500, 502, 503, 504}


# ---------------------------------------------------------------- HTTP


async def fetch_with_retry(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    json_body: Any | None = None,
    max_attempts: int = 4,
    base_delay: float = 0.8,
    timeout_s: int = 60,
    expected_status: tuple[int, ...] = (200,),
) -> tuple[int, bytes, dict[str, str], int]:
    """Return ``(http_status, body_bytes, response_headers, attempts)``.

    Retries with exponential backoff on transient errors. Raises on
    network exhaustion only when *every* attempt fails — a non-2xx
    response from the server is still returned (so the caller can
    inspect what came back).
    """
    h = {**_DEFAULT_HEADERS, **(headers or {})}
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    last_status = 0
    last_body = b""
    last_headers: dict[str, str] = {}

    for attempt in range(1, max_attempts + 1):
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=h) as s:
                async with s.request(method, url, json=json_body) as r:
                    last_status = r.status
                    last_headers = {k: v for k, v in r.headers.items()}
                    last_body = await r.read()
                    if r.status in expected_status:
                        return r.status, last_body, last_headers, attempt
                    if r.status not in _RETRYABLE_STATUSES:
                        return r.status, last_body, last_headers, attempt
                    _logger.info(
                        "[advisory-ingest] transient %s on %s (attempt %d/%d)",
                        r.status, url, attempt, max_attempts,
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _logger.info(
                "[advisory-ingest] network error on %s attempt %d/%d: %s",
                url, attempt, max_attempts, e,
            )
        if attempt < max_attempts:
            await asyncio.sleep(base_delay * (2 ** (attempt - 1)))
    return last_status, last_body, last_headers, max_attempts


# ---------------------------------------------------------------- Parsing


def parse_json_lenient(body: bytes) -> Any | None:
    """Try multiple decodings; return ``None`` if none succeed."""
    if not body:
        return None
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return json.loads(body.decode(enc, errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    return None


def normalize_list(payload: Any) -> tuple[list[Any], str]:
    """Pull a list of records out of a JSON payload that could be in any
    of the common shapes. Returns ``(rows, shape_label)`` where the
    label captures which shape we found so health rows can flag drift.
    """
    if isinstance(payload, list):
        return payload, "list_root"
    if not isinstance(payload, dict):
        return [], "scalar_root"
    for key in ("value", "data", "entries", "vulnerabilities", "advisories",
                "items", "results", "documents"):
        v = payload.get(key)
        if isinstance(v, list):
            return v, f"dict_{key}"
    # Fallback: every dict-of-dict where values look like records
    inner = [v for v in payload.values() if isinstance(v, dict)]
    if len(inner) > 0 and all(isinstance(v, dict) for v in inner):
        return inner, "dict_of_records"
    return [], "unknown_dict"


def walk_keys(d: dict[str, Any], *names: str, default: Any = None) -> Any:
    """Case-insensitive multi-key lookup. Returns the first match."""
    if not isinstance(d, dict):
        return default
    lower_index = {k.lower(): k for k in d.keys() if isinstance(k, str)}
    for n in names:
        actual = lower_index.get(n.lower())
        if actual is not None:
            return d[actual]
    return default


def slugify(s: str, *, maxlen: int = 200) -> str:
    out = "".join(c.lower() if c.isalnum() else "-" for c in (s or ""))
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")[:maxlen]


# ---------------------------------------------------------------- Health


async def record_health(
    db: AsyncSession,
    *,
    source: str,
    source_url: str,
    started_at: datetime,
    status: str,
    http_status: int | None = None,
    attempts: int = 1,
    rows_seen: int = 0,
    rows_parsed: int = 0,
    rows_inserted: int = 0,
    rows_updated: int = 0,
    rows_skipped: int = 0,
    schema_shape: str = "unknown",
    missing_fields: dict | None = None,
    error_message: str | None = None,
    raw_sample: bytes | str | None = None,
) -> AdvisoryIngestHealth:
    sample_text: str | None = None
    if raw_sample is not None:
        if isinstance(raw_sample, bytes):
            try:
                sample_text = raw_sample[:2000].decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                sample_text = repr(raw_sample[:2000])
        else:
            sample_text = str(raw_sample)[:2000]
    row = AdvisoryIngestHealth(
        source=source,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        status=status,
        source_url=source_url[:500] if source_url else None,
        http_status=http_status,
        attempts=attempts,
        rows_seen=rows_seen,
        rows_parsed=rows_parsed,
        rows_inserted=rows_inserted,
        rows_updated=rows_updated,
        rows_skipped=rows_skipped,
        schema_shape=schema_shape[:60] if schema_shape else "unknown",
        missing_fields=missing_fields or {},
        error_message=(error_message or None) and str(error_message)[:8000],
        raw_sample=sample_text,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ---------------------------------------------------------------- Schema drift


def track_missing(missing_counts: dict[str, int], *names: str) -> None:
    for n in names:
        missing_counts[n] = missing_counts.get(n, 0) + 1


__all__ = [
    "fetch_with_retry",
    "parse_json_lenient",
    "normalize_list",
    "walk_keys",
    "slugify",
    "record_health",
    "track_missing",
]
