"""Pulsedive per-indicator enrichment.

Pulsedive (https://pulsedive.com) aggregates IOCs from 45+ open-source
threat-intel feeds and exposes a free-tier REST API for per-indicator
lookup. Unlike most paid intel platforms, the free tier is genuinely
useful — we get back the recommended risk score, the upstream feeds
that contributed, the threats they're tied to, and any associated
attributes.

API contract (verified May 2026):

    GET https://pulsedive.com/api/indicator.php
        ?indicator=<value>
        &key=<api_key>      (optional — anonymous tier exists)

    Response (top-level):
        indicator, type, risk, risk_recommended,
        stamp_added, stamp_updated, stamp_seen,
        threats: [...], feeds: [...], riskfactors: [...],
        attributes, properties

We cache by (indicator, key) for 24h since Pulsedive's free tier is
~30 req/min and the underlying scoring doesn't change minute-to-minute.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from src.core.http_circuit import get_breaker

logger = logging.getLogger(__name__)


_API_URL = "https://pulsedive.com/api/indicator.php"
_BREAKER = "enrichment:pulsedive"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h
_CACHE_KEY_PREFIX = "argus:pulsedive:"
_TIMEOUT_SECONDS = 8


@dataclass
class PulsediveResult:
    indicator: str
    success: bool
    in_corpus: bool = False
    type: Optional[str] = None
    risk: Optional[str] = None
    risk_recommended: Optional[str] = None
    threats: list[str] = field(default_factory=list)
    feeds: list[str] = field(default_factory=list)
    riskfactors: list[str] = field(default_factory=list)
    stamp_seen: Optional[str] = None
    error: Optional[str] = None
    cached: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "success": self.success,
            "in_corpus": self.in_corpus,
            "type": self.type,
            "risk": self.risk,
            "risk_recommended": self.risk_recommended,
            "threats": self.threats,
            "feeds": self.feeds,
            "riskfactors": self.riskfactors,
            "stamp_seen": self.stamp_seen,
            "error": self.error,
            "cached": self.cached,
        }


def _resolve_key() -> str:
    from src.core import integration_keys
    return (
        integration_keys.get(
            "pulsedive", env_fallback="ARGUS_PULSEDIVE_API_KEY",
        ) or ""
    ).strip()


def _cache_key(indicator: str, key: str) -> str:
    return _CACHE_KEY_PREFIX + ("auth:" if key else "anon:") + indicator


async def _from_cache(cache_key: str) -> Optional[PulsediveResult]:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            raw = await client.get(cache_key)
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        return None
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    return PulsediveResult(
        indicator=d.get("indicator", ""),
        success=bool(d.get("success", True)),
        in_corpus=bool(d.get("in_corpus", False)),
        type=d.get("type"),
        risk=d.get("risk"),
        risk_recommended=d.get("risk_recommended"),
        threats=list(d.get("threats") or []),
        feeds=list(d.get("feeds") or []),
        riskfactors=list(d.get("riskfactors") or []),
        stamp_seen=d.get("stamp_seen"),
        error=d.get("error"),
        cached=True,
        raw=d.get("raw", {}),
    )


async def _store_cache(cache_key: str, result: PulsediveResult) -> None:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            await client.setex(
                cache_key, _CACHE_TTL_SECONDS,
                json.dumps({
                    "indicator": result.indicator,
                    "success": result.success,
                    "in_corpus": result.in_corpus,
                    "type": result.type,
                    "risk": result.risk,
                    "risk_recommended": result.risk_recommended,
                    "threats": result.threats,
                    "feeds": result.feeds,
                    "riskfactors": result.riskfactors,
                    "stamp_seen": result.stamp_seen,
                    "error": result.error,
                    "raw": result.raw,
                }),
            )
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        pass


def is_configured() -> bool:
    """Pulsedive's anonymous tier works (lower rate limits) — we always
    consider this provider 'configured', the API key is opt-in."""
    return True


async def lookup(indicator: str, *, use_cache: bool = True) -> PulsediveResult:
    """Look up ``indicator`` (IP / domain / URL) on Pulsedive."""
    if not indicator:
        return PulsediveResult(
            indicator="", success=False, error="empty indicator",
        )

    key = _resolve_key()
    cache_key = _cache_key(indicator, key)
    if use_cache:
        cached = await _from_cache(cache_key)
        if cached is not None:
            return cached

    params = {"indicator": indicator}
    if key:
        params["key"] = key
    url = f"{_API_URL}?{urllib.parse.urlencode(params)}"

    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=_TIMEOUT_SECONDS)
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(url, headers={
                    "Accept": "application/json",
                    "User-Agent": "argus-threat-intelligence",
                }) as resp:
                    if resp.status == 429:
                        return PulsediveResult(
                            indicator=indicator, success=False,
                            error="HTTP 429 — Pulsedive rate-limited; retry shortly",
                        )
                    if resp.status == 403:
                        return PulsediveResult(
                            indicator=indicator, success=False,
                            error="HTTP 403 — API key invalid or tier insufficient",
                        )
                    if resp.status != 200:
                        return PulsediveResult(
                            indicator=indicator, success=False,
                            error=f"HTTP {resp.status}",
                        )
                    try:
                        payload = await resp.json(content_type=None)
                    except Exception as exc:  # noqa: BLE001
                        return PulsediveResult(
                            indicator=indicator, success=False,
                            error=f"JSON parse: {exc}",
                        )
    except Exception as exc:  # noqa: BLE001
        return PulsediveResult(
            indicator=indicator, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    if not isinstance(payload, dict):
        return PulsediveResult(
            indicator=indicator, success=False, error="unexpected payload",
        )

    # Pulsedive returns a thin "indicator not found" shape — iid==0,
    # risk=="unknown", and stamp_added==null. Treat as a clean miss.
    if not payload.get("iid"):
        result = PulsediveResult(
            indicator=indicator, success=True, in_corpus=False,
            raw=payload,
        )
        await _store_cache(cache_key, result)
        return result

    threats = [
        t.get("name") for t in (payload.get("threats") or [])
        if isinstance(t, dict) and t.get("name")
    ]
    feeds = [
        f.get("name") for f in (payload.get("feeds") or [])
        if isinstance(f, dict) and f.get("name")
    ]
    riskfactors = [
        # The dataclass declares list[str]; coerce rfid (int) to str
        # when description is absent so JSON serialisation stays
        # type-consistent and the frontend doesn't get a mixed list.
        str(rf.get("description") or rf.get("rfid") or "")
        for rf in (payload.get("riskfactors") or [])
        if isinstance(rf, dict)
    ]

    result = PulsediveResult(
        indicator=indicator,
        success=True,
        in_corpus=True,
        type=payload.get("type"),
        risk=payload.get("risk"),
        risk_recommended=payload.get("risk_recommended"),
        threats=[t for t in threats if t],
        feeds=[f for f in feeds if f],
        riskfactors=[rf for rf in riskfactors if rf],
        stamp_seen=payload.get("stamp_seen"),
        raw=payload,
    )
    await _store_cache(cache_key, result)
    return result
