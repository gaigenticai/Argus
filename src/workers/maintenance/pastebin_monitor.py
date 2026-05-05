"""Pastebin paste-stream monitor.

Polls Pastebin for newly-published pastes, runs every active org's DLP
policies + the BIN-aware credit-card detector against each paste's raw
body, and persists DlpFinding / CardLeakageFinding rows. The
last-seen-paste cursor lives on FeedHealth as ``detail`` so we don't
re-scan pastes across worker restarts.

Two upstreams, picked in order of availability:

  1. Pastebin Pro Scraping API at ``scrape.pastebin.com``. Requires
     ``ARGUS_PASTEBIN_KEY`` (whitelisted IP). Returns up to 250 fresh
     pastes per request as JSON. Preferred when configured.
  2. Public archive page ``https://pastebin.com/archive`` — HTML
     scrape for the ~50 most-recent paste IDs. No key required, but
     the archive shows fewer pastes and is rate-limited. Used as a
     fallback so demo / unconfigured installs still get *some*
     coverage.

Per-tick caps:

  * 50 new pastes processed.
  * 1 raw-body fetch per second (Pastebin's anti-abuse threshold for
    unauthenticated traffic; we apply it even for Pro keys to play
    nice with their infrastructure).

A FeedHealth row is recorded on every tick — ``ok`` / ``unconfigured``
/ ``network_error`` / ``rate_limited`` so the dashboard surfaces what's
actually happening.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.leakage.cards import scan_text as scan_cards
from src.leakage.dlp import scan_text as scan_dlp
from src.llm.agent_queue import enqueue
from src.models.admin import FeedHealth
from src.models.leakage import CardLeakageFinding, DlpFinding, DlpPolicy
from src.models.threat import Organization

logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.pastebin_monitor"

_PRO_API = "https://scrape.pastebin.com/api_scraping.php"
_PUBLIC_ARCHIVE = "https://pastebin.com/archive"
_RAW_TEMPLATE = "https://pastebin.com/raw/{key}"

_MAX_NEW_PER_TICK = 50
_RATE_LIMIT_SECONDS = 1.0
_FETCH_TIMEOUT = aiohttp.ClientTimeout(total=15)
_USER_AGENT = "argus-pastebin-monitor/1.0"

# Public-archive HTML pattern. Pastebin's archive page lists each paste
# as ``<a href="/AbCdEfGh">title</a>``. We extract the path after the
# leading slash; the IDs are 8-char alphanum (the public-archive scheme).
_ARCHIVE_LINK_RE = re.compile(r'<a href="/([A-Za-z0-9]{8})"[^>]*>')


async def _fetch_pro(session: aiohttp.ClientSession, key: str) -> list[dict] | None:
    """Hit the paid scraping API. Returns a list of paste metadata
    dicts or ``None`` on failure."""
    url = f"{_PRO_API}?limit=250"
    headers = {"User-Agent": _USER_AGENT}
    if key:
        # Pastebin's docs show the key passed as a URL parameter for the
        # scrape API; we still let callers run unauth'd against the same
        # endpoint (some operators use the IP-whitelisted variant).
        url += f"&api_key={key}"
    async with session.get(url, headers=headers) as resp:
        if resp.status == 401 or resp.status == 403:
            return None
        if resp.status >= 400:
            logger.warning("pastebin pro api HTTP %d", resp.status)
            return None
        body = await resp.text()
        # On success the API returns a JSON array. On "not whitelisted"
        # it returns plain text; detect and bail.
        if not body.strip().startswith("["):
            return None
        import json as _json

        try:
            payload = _json.loads(body)
        except _json.JSONDecodeError:
            return None
        if not isinstance(payload, list):
            return None
        return payload


async def _fetch_public_archive(session: aiohttp.ClientSession) -> list[str]:
    """Scrape the public archive page for paste IDs. Returns a list of
    8-char paste keys, newest-first as Pastebin lists them."""
    headers = {"User-Agent": _USER_AGENT, "Accept": "text/html"}
    async with session.get(_PUBLIC_ARCHIVE, headers=headers) as resp:
        if resp.status >= 400:
            logger.warning("pastebin archive HTTP %d", resp.status)
            return []
        html = await resp.text()
    # Skip the leading nav links — Pastebin uses 8-char IDs for paste
    # URLs. We dedup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for m in _ARCHIVE_LINK_RE.finditer(html):
        key = m.group(1)
        # Filter common header anchors that happen to match the regex
        # (``archive``, ``signup``, ``terms``, etc are 7-char or contain
        # non-alphanum after a slash; the 8-char filter usually suffices).
        if key in {"archive", "signup", "terms_of"}:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
        if len(out) >= 50:
            break
    return out


async def _fetch_raw(session: aiohttp.ClientSession, key: str) -> str | None:
    headers = {"User-Agent": _USER_AGENT}
    try:
        async with session.get(
            _RAW_TEMPLATE.format(key=key), headers=headers
        ) as resp:
            if resp.status == 429:
                # Rate-limited — caller will see the empty result and
                # skip remaining pastes for this tick.
                return None
            if resp.status >= 400:
                return None
            return await resp.text()
    except aiohttp.ClientError as exc:
        logger.debug("pastebin raw fetch %s failed: %s", key, exc)
        return None


async def _last_seen_keys(db: AsyncSession) -> set[str]:
    """Pull the most-recent N paste keys we already processed. Stored
    as a comma-joined string in the latest FeedHealth row's ``detail``
    field — keeps us from adding a one-row-per-feed state table just
    for this cursor.
    """
    row = (
        await db.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == FEED_NAME)
            .order_by(FeedHealth.observed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None or not row.detail:
        return set()
    # Detail format: ``... seen=KEY1,KEY2,KEY3 ...``
    m = re.search(r"seen=([A-Za-z0-9,]+)", row.detail)
    if not m:
        return set()
    return set(m.group(1).split(","))


async def _orgs_with_active_dlp(db: AsyncSession) -> list[Organization]:
    """Only scan for orgs that actually have at least one enabled DLP
    policy; otherwise we'd be hammering the cards detector against
    every paste with nothing useful to report."""
    rows = (
        await db.execute(
            select(Organization).join(
                DlpPolicy,
                DlpPolicy.organization_id == Organization.id,
            ).where(DlpPolicy.enabled == True)  # noqa: E712
            .distinct()
        )
    ).scalars().all()
    return list(rows)


async def _process_paste(
    db: AsyncSession,
    *,
    key: str,
    body: str,
    orgs: list[Organization],
) -> tuple[int, int]:
    """Run scan_dlp + scan_cards for every org. Returns
    ``(dlp_new, card_new)`` totals across all orgs."""
    source_url = _RAW_TEMPLATE.format(key=key)
    dlp_new = 0
    card_new = 0
    for org in orgs:
        try:
            dlp_report = await scan_dlp(
                db, org.id, body, source_url=source_url, source_kind="paste"
            )
        except Exception:  # noqa: BLE001
            logger.exception("scan_dlp failed for org %s paste %s", org.id, key)
            await db.rollback()
            continue
        try:
            card_report = await scan_cards(
                db, org.id, body, source_url=source_url, source_kind="paste",
                require_bin_match=False,
            )
        except Exception:  # noqa: BLE001
            logger.exception("scan_cards failed for org %s paste %s", org.id, key)
            await db.rollback()
            continue
        dlp_new += dlp_report.findings_created
        card_new += card_report.new_findings

        # Enqueue agent classification + cross-org correlation for every
        # *new* finding from this paste. Recent rows for this org/source
        # serve as the targets — re-runs are dedup'd on (kind, dedup_key).
        if dlp_report.findings_created:
            recent_dlp = (
                await db.execute(
                    select(DlpFinding)
                    .where(
                        DlpFinding.organization_id == org.id,
                        DlpFinding.source_url == source_url,
                    )
                    .order_by(DlpFinding.detected_at.desc())
                    .limit(dlp_report.findings_created)
                )
            ).scalars().all()
            for f in recent_dlp:
                await enqueue(
                    db,
                    kind="leakage_classify",
                    payload={"finding_id": str(f.id), "kind": "dlp"},
                    organization_id=org.id,
                    dedup_key=f"classify:dlp:{f.id}",
                    priority=5,
                )
                await enqueue(
                    db,
                    kind="leakage_correlate_cross_org",
                    payload={"finding_id": str(f.id), "kind": "dlp"},
                    organization_id=org.id,
                    dedup_key=f"correlate:dlp:{f.id}",
                    priority=6,
                )
        if card_report.new_findings:
            recent_card = (
                await db.execute(
                    select(CardLeakageFinding)
                    .where(
                        CardLeakageFinding.organization_id == org.id,
                        CardLeakageFinding.source_url == source_url,
                    )
                    .order_by(CardLeakageFinding.detected_at.desc())
                    .limit(card_report.new_findings)
                )
            ).scalars().all()
            for f in recent_card:
                await enqueue(
                    db,
                    kind="leakage_classify",
                    payload={"finding_id": str(f.id), "kind": "card"},
                    organization_id=org.id,
                    dedup_key=f"classify:card:{f.id}",
                    priority=5,
                )
                await enqueue(
                    db,
                    kind="leakage_correlate_cross_org",
                    payload={"finding_id": str(f.id), "kind": "card"},
                    organization_id=org.id,
                    dedup_key=f"correlate:card:{f.id}",
                    priority=6,
                )
    await db.commit()
    return dlp_new, card_new


async def poll_once(db: AsyncSession) -> None:
    """One iteration of the pastebin maintenance loop.

    Called from the worker tick scheduler; never raises — every error
    path records a FeedHealth row and exits.
    """
    started = time.monotonic()
    pro_key = os.environ.get("ARGUS_PASTEBIN_KEY", "").strip()

    orgs = await _orgs_with_active_dlp(db)
    if not orgs:
        await feed_health.mark_disabled(
            db,
            feed_name=FEED_NAME,
            detail="no organisation has any enabled DLP policy",
        )
        await db.commit()
        return

    seen_before = await _last_seen_keys(db)

    # Step 1: discover paste IDs.
    paste_keys: list[str] = []
    upstream = "public_archive"
    async with aiohttp.ClientSession(timeout=_FETCH_TIMEOUT) as http:
        if pro_key:
            try:
                payload = await _fetch_pro(http, pro_key)
            except aiohttp.ClientError as exc:
                payload = None
                logger.warning("pastebin pro api fetch failed: %s", exc)
            if payload:
                upstream = "pro_api"
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    key = (item.get("key") or "").strip()
                    if key:
                        paste_keys.append(key)
        if not paste_keys:
            try:
                paste_keys = await _fetch_public_archive(http)
            except aiohttp.ClientError as exc:
                logger.warning("pastebin archive fetch failed: %s", exc)
                await feed_health.mark_failure(
                    db,
                    feed_name=FEED_NAME,
                    error=f"archive fetch failed: {exc}",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                await db.commit()
                return

        if not paste_keys:
            await feed_health.mark_failure(
                db,
                feed_name=FEED_NAME,
                error="no paste keys available from upstream",
                duration_ms=int((time.monotonic() - started) * 1000),
                classify="parse_error",
            )
            await db.commit()
            return

        new_keys = [k for k in paste_keys if k not in seen_before][:_MAX_NEW_PER_TICK]

        # Step 2: fetch + scan each new paste, rate-limited.
        total_dlp_new = 0
        total_card_new = 0
        processed_keys: list[str] = []
        rate_limited = False
        for key in new_keys:
            body = await _fetch_raw(http, key)
            if body is None:
                rate_limited = True
                break
            try:
                dn, cn = await _process_paste(db, key=key, body=body, orgs=orgs)
            except Exception:  # noqa: BLE001
                logger.exception("paste processing failed for %s", key)
                await db.rollback()
                continue
            total_dlp_new += dn
            total_card_new += cn
            processed_keys.append(key)
            await asyncio.sleep(_RATE_LIMIT_SECONDS)

    # Step 3: record health. The cursor ("seen=" tail) carries the
    # union of previous + newly-processed keys, capped to 200 entries.
    cursor = sorted(seen_before.union(processed_keys))[-200:]
    detail = (
        f"upstream={upstream}; "
        f"discovered={len(paste_keys)}; "
        f"new={len(new_keys)}; "
        f"processed={len(processed_keys)}; "
        f"dlp_new={total_dlp_new}; "
        f"card_new={total_card_new}; "
        f"seen={','.join(cursor)}"
    )
    if rate_limited:
        await feed_health.mark_failure(
            db,
            feed_name=FEED_NAME,
            error=detail,
            duration_ms=int((time.monotonic() - started) * 1000),
            classify="rate_limited",
        )
    else:
        await feed_health.mark_ok(
            db,
            feed_name=FEED_NAME,
            rows_ingested=total_dlp_new + total_card_new,
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=detail,
        )
    await db.commit()
    logger.info(
        "pastebin: upstream=%s discovered=%d new=%d processed=%d dlp=%d card=%d",
        upstream,
        len(paste_keys),
        len(new_keys),
        len(processed_keys),
        total_dlp_new,
        total_card_new,
    )


__all__ = ["poll_once", "FEED_NAME"]
