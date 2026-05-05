"""Vendor sanctions screening — OFAC / UK OFSI / EU consolidated.

All three lists are free, public, and refresh on a known cadence.
Implementation:

  * **OFAC SDN** — daily-refreshed CSV at
    ``https://www.treasury.gov/ofac/downloads/sdn.csv``
  * **UK OFSI** — JSON consolidated list at
    ``https://ofsistorage.blob.core.windows.net/publishlive/2022format/
    ConList.json`` (no auth, free).
  * **EU consolidated** — XML feed; we use the JSON mirror at
    ``https://data.opensanctions.org/datasets/latest/eu_fsf/targets.simple.json``
    which OpenSanctions republishes daily under a permissive licence.

Each lookup returns a ``(matched, score, payload)`` tuple. We use simple
case-insensitive substring + Levenshtein-light normalisation so a vendor
name like "ACME Corp Pte Ltd" still matches "ACME Corporation".

The lookup is cached in-process for 24h via ``_LIST_CACHE``. The
periodic worker triggers re-fetch.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

_logger = logging.getLogger(__name__)


import os

# Operators can override every list URL via env vars in case upstream
# rotates the path (which OFSI does periodically). Defaults are the
# public, freely-fetchable JSON / CSV endpoints.
_OFAC_URL = os.environ.get(
    "ARGUS_OFAC_URL",
    "https://www.treasury.gov/ofac/downloads/sdn.csv",
)
_OFSI_URL = os.environ.get(
    "ARGUS_OFSI_URL",
    # OFSI's stable JSON endpoint (consolidated list).
    "https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.json",
)
# OpenSanctions republishes the EU + UN consolidated lists as simple JSON.
_EU_URL = os.environ.get(
    "ARGUS_EU_SANCTIONS_URL",
    "https://data.opensanctions.org/datasets/latest/eu_fsf/targets.simple.json",
)


_LIST_TTL_S = 86400  # 24h cache
_LIST_CACHE: dict[str, tuple[float, list[str]]] = {}


def _normalize(name: str) -> str:
    """Lowercase + strip corporate suffixes + collapse whitespace."""
    s = name.lower()
    s = re.sub(
        r"\b(inc|incorporated|corp|corporation|llc|llp|ltd|limited|pte|gmbh|sa|nv|bv|ag|co|company)\.?\b",
        "",
        s,
    )
    s = re.sub(r"[^a-z0-9 ]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


@dataclass
class SanctionsHit:
    source: str
    matched: bool
    score: float  # 0..1 fuzzy
    payload: dict[str, Any]


async def _fetch_text(url: str, timeout: float = 30) -> str | None:
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
            async with sess.get(url) as resp:
                if resp.status != 200:
                    _logger.warning("sanctions: %s HTTP %s", url, resp.status)
                    return None
                return await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _logger.warning("sanctions: %s fetch failed: %s", url, e)
        return None


async def _load_ofac() -> list[str]:
    cached = _LIST_CACHE.get("ofac")
    now = time.time()
    if cached and now - cached[0] < _LIST_TTL_S:
        return cached[1]
    text = await _fetch_text(_OFAC_URL)
    if text is None:
        return cached[1] if cached else []
    names: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        # Column order: ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, ...
        if len(row) >= 2 and row[1]:
            names.append(_normalize(row[1]))
    _LIST_CACHE["ofac"] = (now, names)
    return names


async def _load_ofsi() -> list[str]:
    cached = _LIST_CACHE.get("ofsi")
    now = time.time()
    if cached and now - cached[0] < _LIST_TTL_S:
        return cached[1]
    text = await _fetch_text(_OFSI_URL)
    if text is None:
        return cached[1] if cached else []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return cached[1] if cached else []
    names: list[str] = []
    for entry in data.get("Designations") or data.get("designations") or []:
        n = entry.get("Name6") or entry.get("Names", [{}])[0].get("Name6") or ""
        if n:
            names.append(_normalize(n))
    _LIST_CACHE["ofsi"] = (now, names)
    return names


async def _load_eu() -> list[str]:
    cached = _LIST_CACHE.get("eu_consolidated")
    now = time.time()
    if cached and now - cached[0] < _LIST_TTL_S:
        return cached[1]
    text = await _fetch_text(_EU_URL)
    if text is None:
        return cached[1] if cached else []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return cached[1] if cached else []
    names: list[str] = []
    for entry in data:
        n = entry.get("name") or entry.get("Name") or ""
        if n:
            names.append(_normalize(n))
    _LIST_CACHE["eu_consolidated"] = (now, names)
    return names


def _fuzzy_match(needle: str, candidates: list[str]) -> tuple[bool, float, str | None]:
    if not needle or not candidates:
        return False, 0.0, None
    if needle in candidates:
        return True, 1.0, needle
    # Substring or token-overlap fallback.
    tokens_needle = set(needle.split())
    if not tokens_needle:
        return False, 0.0, None
    best: tuple[float, str | None] = (0.0, None)
    for c in candidates:
        if needle in c or c in needle:
            return True, 0.9, c
        tokens = set(c.split())
        if not tokens:
            continue
        overlap = len(tokens_needle & tokens) / max(
            len(tokens_needle), len(tokens)
        )
        if overlap > best[0]:
            best = (overlap, c)
    if best[0] >= 0.7:
        return True, best[0], best[1]
    return False, best[0], best[1]


async def screen_vendor(name: str) -> list[SanctionsHit]:
    """Run name through OFAC, OFSI and EU lists. Returns a hit per source
    (matched=False when no match)."""
    needle = _normalize(name)
    if not needle:
        return []
    ofac, ofsi, eu = await asyncio.gather(
        _load_ofac(), _load_ofsi(), _load_eu()
    )
    out: list[SanctionsHit] = []
    for src, names in (
        ("ofac", ofac),
        ("ofsi", ofsi),
        ("eu_consolidated", eu),
    ):
        matched, score, m = _fuzzy_match(needle, names)
        out.append(
            SanctionsHit(
                source=src,
                matched=matched,
                score=float(score),
                payload={
                    "name": name,
                    "normalized": needle,
                    "matched_term": m,
                    "list_size": len(names),
                },
            )
        )
    return out


__all__ = ["screen_vendor", "SanctionsHit"]
