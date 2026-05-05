"""Scheduled Suricata eve.json tail worker.

Argus does not run the Suricata sniffer itself — operators run their
own sensor (with whatever interface visibility their network requires)
and point Argus at the resulting ``eve.json`` log. This worker tails
that file on a tick, parses new alert events, and persists them as
``Alert`` rows on the system organisation so analysts see NSM hits
on /alerts alongside everything else.

Behaviour per tick:

    1. Read ``ARGUS_SURICATA_EVE_PATH`` env var. If unset, mark
       feed_health UNCONFIGURED and exit (Service Inventory pill goes
       to needs_key with the relevant evidence).
    2. Read the byte offset stored in Redis under
       ``argus:suricata:tail_offset:<sha1(path)>``. Seek to that offset
       and read everything written since the last tick.
    3. If the current file size is smaller than the saved offset, the
       file was rotated — reset to 0 and re-read.
    4. Parse each new line as JSON, extract events with
       ``event_type=="alert"``, normalise via ``SuricataIngestor``.
    5. For each alert, INSERT an ``Alert`` row tagged to the system
       organisation. Map Suricata severity (1-4) onto our 4-state
       Severity enum and Suricata category onto ThreatCategory.
    6. Save the new offset, write feed_health
       ``maintenance.suricata_tail`` with the per-tick summary.

Bounded resource use: the worker reads at most
``ARGUS_SURICATA_TAIL_MAX_BYTES`` bytes per tick (default 4 MiB) so
a busy sensor that wrote 500 MB while the worker was sleeping doesn't
make the next tick OOM. Older bytes are skipped on the next file size
check — this is a conscious trade: if you want zero-loss ingestion,
configure your sensor to write smaller eve.json files and rotate hourly.

Replaces the temptation to ship ``scripts/ingest_suricata.py`` —
operators don't run a CLI, they set the env var and the worker
keeps the alerts flowing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from src.core import feed_health
from src.integrations.suricata.client import SuricataIngestor
from src.models.common import Severity
from src.models.threat import Alert, AlertStatus, ThreatCategory
from src.storage import database as _db

_logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.suricata_tail"

_EVE_PATH_ENV = "ARGUS_SURICATA_EVE_PATH"
_MAX_BYTES_PER_TICK = int(
    os.environ.get("ARGUS_SURICATA_TAIL_MAX_BYTES", str(4 * 1024 * 1024))
)
_OFFSET_KEY_PREFIX = "argus:suricata:tail_offset:"

# Suricata's signature.severity is 1 (high) → 4 (low). Map onto our
# enum which goes the opposite direction.
_SURI_SEVERITY_TO_ENUM: dict[int, str] = {
    1: Severity.CRITICAL.value,
    2: Severity.HIGH.value,
    3: Severity.MEDIUM.value,
    4: Severity.LOW.value,
}

# Suricata's classification.category is a free-form string in the
# rules. Map the most common ones onto ThreatCategory; everything
# else falls through to EXPLOIT (closest fit for "the IDS flagged
# something on the wire").
_SURI_CATEGORY_TO_THREAT: dict[str, str] = {
    "trojan-activity": ThreatCategory.EXPLOIT.value,
    "malware-cnc": ThreatCategory.EXPLOIT.value,
    "command-and-control": ThreatCategory.EXPLOIT.value,
    "exploit-kit": ThreatCategory.EXPLOIT.value,
    "attempted-admin": ThreatCategory.INITIAL_ACCESS.value,
    "attempted-user": ThreatCategory.INITIAL_ACCESS.value,
    "credential-theft": ThreatCategory.CREDENTIAL_LEAK.value,
    "phishing": ThreatCategory.PHISHING.value,
    "data-theft": ThreatCategory.DATA_BREACH.value,
}


def _offset_key(path: str) -> str:
    return _OFFSET_KEY_PREFIX + hashlib.sha1(path.encode()).hexdigest()


def _read_new_bytes(path: str, start_offset: int, max_bytes: int) -> tuple[bytes, int]:
    """Read up to ``max_bytes`` from ``path`` starting at ``start_offset``.

    Returns (bytes_read, new_offset). If the file got rotated (size
    shrunk below start_offset), starts over from 0 — we'd rather
    re-process recent events than miss them.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise RuntimeError(f"stat {path}: {exc}") from exc

    if start_offset > size:
        # File rotated / truncated — restart from 0.
        start_offset = 0

    if start_offset >= size:
        return b"", size

    end_offset = min(size, start_offset + max_bytes)
    with open(path, "rb") as fh:
        fh.seek(start_offset)
        data = fh.read(end_offset - start_offset)

    # Trim partial last line — only consume up to the last newline so we
    # never split a JSON record across ticks.
    last_nl = data.rfind(b"\n")
    if last_nl == -1:
        # No newline in the chunk — defer everything to next tick.
        return b"", start_offset
    consumed = last_nl + 1
    return data[:consumed], start_offset + consumed


def _parse_alert_lines(raw: bytes) -> list[dict[str, Any]]:
    """Decode NDJSON, keep only event_type==alert."""
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            _logger.debug("[suricata_tail] skipping malformed line: %.120s", line)
            continue
        if ev.get("event_type") == "alert":
            events.append(ev)
    return events


def _alert_row_from_event(ev: dict[str, Any], org_id) -> Alert:
    alert_meta = ev.get("alert", {}) or {}
    severity_int = alert_meta.get("severity")
    severity = _SURI_SEVERITY_TO_ENUM.get(
        severity_int if isinstance(severity_int, int) else 3,
        Severity.MEDIUM.value,
    )
    cat_raw = (alert_meta.get("category") or "").strip().lower()
    category = _SURI_CATEGORY_TO_THREAT.get(cat_raw, ThreatCategory.EXPLOIT.value)

    src_ip = ev.get("src_ip") or "?"
    dest_ip = ev.get("dest_ip") or "?"
    proto = ev.get("proto") or "?"
    sig = (alert_meta.get("signature") or "Suricata alert")[:480]

    title = f"Suricata: {sig}"[:500]
    summary = (
        f"Suricata signature {alert_meta.get('signature_id', '?')} fired on "
        f"{proto.lower()} {src_ip}:{ev.get('src_port', '?')} → "
        f"{dest_ip}:{ev.get('dest_port', '?')}. "
        f"Category: {alert_meta.get('category') or 'uncategorised'}."
    )

    matched_entities = {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": ev.get("src_port"),
        "dest_port": ev.get("dest_port"),
        "proto": proto,
        "flow_id": ev.get("flow_id"),
        "signature_id": alert_meta.get("signature_id"),
        "rev": alert_meta.get("rev"),
    }

    return Alert(
        organization_id=org_id,
        category=category,
        severity=severity,
        status=AlertStatus.NEW.value,
        title=title,
        summary=summary,
        details={
            "source": "suricata",
            "timestamp": ev.get("timestamp"),
            "in_iface": ev.get("in_iface"),
            "action": alert_meta.get("action"),
            "raw_alert": alert_meta,
        },
        matched_entities=matched_entities,
        confidence=0.7,  # Suricata signatures vary in fidelity; flat 0.7 baseline
    )


async def _load_offset(redis_url: str, key: str) -> int:
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url, decode_responses=True)
    try:
        val = await client.get(key)
        return int(val) if val else 0
    finally:
        await client.aclose()


async def _save_offset(redis_url: str, key: str, offset: int) -> None:
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url, decode_responses=True)
    try:
        await client.set(key, str(offset))
    finally:
        await client.aclose()


async def tick_once() -> None:
    if _db.async_session_factory is None:
        return

    eve_path = (os.environ.get(_EVE_PATH_ENV) or "").strip()
    if not eve_path:
        async with _db.async_session_factory() as session:
            await feed_health.mark_unconfigured(
                session,
                feed_name=FEED_NAME,
                detail=(
                    f"{_EVE_PATH_ENV} unset — point at your Suricata "
                    "eve.json (e.g. /var/log/suricata/eve.json) to enable "
                    "NSM-alert ingestion."
                ),
            )
            await session.commit()
        return

    if not os.path.isfile(eve_path):
        async with _db.async_session_factory() as session:
            await feed_health.mark_unconfigured(
                session,
                feed_name=FEED_NAME,
                detail=f"{_EVE_PATH_ENV}={eve_path!r} does not exist on this host.",
            )
            await session.commit()
        return

    from src.config.settings import settings

    redis_url = settings.redis.url
    offset_key = _offset_key(eve_path)

    t0 = time.monotonic()
    try:
        start_offset = await _load_offset(redis_url, offset_key)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("[suricata_tail] redis offset load failed: %s", exc)
        start_offset = 0

    try:
        raw, new_offset = await asyncio.to_thread(
            _read_new_bytes, eve_path, start_offset, _MAX_BYTES_PER_TICK,
        )
    except Exception as exc:  # noqa: BLE001
        _logger.error("[suricata_tail] read %s: %s", eve_path, exc)
        async with _db.async_session_factory() as session:
            await feed_health.mark_unconfigured(
                session,
                feed_name=FEED_NAME,
                detail=f"read error: {exc}",
            )
            await session.commit()
        return

    events = await asyncio.to_thread(_parse_alert_lines, raw) if raw else []

    persisted = 0
    correlated = 0
    if events:
        # Use the existing ingestor for the parse-then-correlate dance
        # (it already de-dups per signature_id+flow if needed).
        ingestor = SuricataIngestor()
        normalised = await asyncio.to_thread(ingestor.parse_eve_json, events)

        from src.core.tenant import get_system_org_id

        async with _db.async_session_factory() as session:
            org_id = await get_system_org_id(session)
            for ev in events:
                try:
                    session.add(_alert_row_from_event(ev, org_id))
                    persisted += 1
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "[suricata_tail] alert insert failed: %s", exc,
                    )
            correlated = len(normalised)
            await session.commit()

    await _save_offset(redis_url, offset_key, new_offset)

    duration_ms = int((time.monotonic() - t0) * 1000)
    detail = (
        f"path={eve_path} bytes={len(raw)} alerts_parsed={correlated} "
        f"alerts_persisted={persisted} new_offset={new_offset} "
        f"duration_ms={duration_ms}"
    )
    async with _db.async_session_factory() as session:
        await feed_health.mark_ok(
            session,
            feed_name=FEED_NAME,
            detail=detail,
            rows_ingested=persisted,
        )
        await session.commit()
    _logger.info("[suricata_tail] tick complete — %s", detail)
