"""GreyNoise community per-IP enrichment.

Why this module exists
----------------------
The bulk ``GreyNoiseFeed`` (``src/feeds/greynoise_feed.py``) calls
the GNQL endpoint ``/v2/experimental/gnql`` which the Community tier
returns 401 on — that endpoint is paywalled to the Enterprise tier.
Operators who paste their **free Community key** into the Settings →
Services drawer would see "needs Enterprise" and conclude the key
they registered is useless.

The Community tier is genuinely useful, just for a different shape:
``/v3/community/{ip}`` returns classification (malicious / benign /
unknown), tags (Mirai, Cobalt Strike, RDP Scanner, …), noise/riot
flags, and last-seen — per-IP, on demand. That's the right shape for
**ingest-time enrichment** of incoming IP IOCs and on-demand lookups
from the IOC detail panel, mirroring ``AbuseIPDBEnricher``.

Caching is essential: 100 IPs/day on the free tier without auth, far
higher with a key, but the same IP repeats constantly across feeds.
24h Redis cache keeps the API cheap.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import aiohttp

from src.core.http_circuit import get_breaker

logger = logging.getLogger(__name__)


_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
_BREAKER = "intel:greynoise-community"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h


@dataclass
class GreyNoiseCommunityResult:
    """Normalised /v3/community/{ip} response.

    Fields mirror what the upstream actually returns; we keep
    ``raw`` so callers can introspect anything we didn't promote.
    """

    ip: str
    success: bool
    classification: Optional[str] = None  # malicious | benign | unknown | None
    name: Optional[str] = None             # human label, e.g. "Censys"
    noise: Optional[bool] = None           # mass-scanner ("internet noise")
    riot: Optional[bool] = None            # known benign service ("Rule It Out")
    last_seen: Optional[datetime] = None
    tags: list[str] = field(default_factory=list)
    link: Optional[str] = None             # viz.greynoise.io permalink
    rate_limited: bool = False
    error: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "success": self.success,
            "classification": self.classification,
            "name": self.name,
            "noise": self.noise,
            "riot": self.riot,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "tags": list(self.tags),
            "link": self.link,
            "rate_limited": self.rate_limited,
            "error": self.error,
            "cached": self.cached,
        }


def _resolve_key() -> str:
    """Look up the operator-saved key first, then env var.

    Mirrors the abuseipdb resolver — same hot-reload semantics. The
    Community endpoint accepts unauthenticated requests too (much
    lower quota) so a missing key is not fatal; we still send the
    header when one is present to lift the limit.
    """
    from src.core import integration_keys
    return (
        integration_keys.get(
            "greynoise", env_fallback="ARGUS_FEED_GREYNOISE_API_KEY",
        ) or ""
    ).strip()


def is_configured() -> bool:
    return bool(_resolve_key())


async def _from_cache(ip: str) -> Optional[GreyNoiseCommunityResult]:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            raw = await client.get(f"greynoise:community:{ip}")
        finally:
            await client.aclose()
        if not raw:
            return None
        data = json.loads(raw)
        last = data.get("last_seen")
        return GreyNoiseCommunityResult(
            ip=ip,
            success=True,
            classification=data.get("classification"),
            name=data.get("name"),
            noise=data.get("noise"),
            riot=data.get("riot"),
            last_seen=datetime.fromisoformat(last) if last else None,
            tags=list(data.get("tags") or []),
            link=data.get("link"),
            cached=True,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("greynoise cache read failed: %s", e)
        return None


async def _to_cache(
    ip: str, result: GreyNoiseCommunityResult, ttl_s: int
) -> None:
    if not result.success or result.error:
        return
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        payload = {
            "classification": result.classification,
            "name": result.name,
            "noise": result.noise,
            "riot": result.riot,
            "last_seen": (
                result.last_seen.isoformat() if result.last_seen else None
            ),
            "tags": list(result.tags),
            "link": result.link,
        }
        try:
            await client.set(
                f"greynoise:community:{ip}", json.dumps(payload), ex=ttl_s,
            )
        finally:
            await client.aclose()
    except Exception as e:  # noqa: BLE001
        logger.debug("greynoise cache store failed: %s", e)


async def check_ip(
    ip: str,
    *,
    cache_ttl_s: int = _CACHE_TTL_SECONDS,
    use_cache: bool = True,
) -> GreyNoiseCommunityResult:
    """Look up an IP against GreyNoise Community.

    Free for commercial use with attribution per GreyNoise ToS as of
    2026-Q1. Cached 24h to keep daily request volume low.

    Returns ``success=True`` even when the IP is unknown to
    GreyNoise (HTTP 404 → classification=None) — the absence of
    information is itself a (weak) signal worth caching.
    """
    ip = (ip or "").strip()
    if not ip:
        return GreyNoiseCommunityResult(ip="", success=False, error="empty IP")

    if use_cache:
        cached = await _from_cache(ip)
        if cached is not None:
            return cached

    key = _resolve_key()
    headers: dict[str, str] = {"Accept": "application/json"}
    if key:
        # Community endpoint accepts ``key`` header on the v3 path
        # to lift the unauthenticated rate limit.
        headers["key"] = key

    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=15)
    url = _COMMUNITY_URL.format(ip=ip)

    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(url, headers=headers) as resp:
                    if resp.status == 429:
                        return GreyNoiseCommunityResult(
                            ip=ip, success=False, rate_limited=True,
                            error=(
                                "HTTP 429 — GreyNoise Community rate limit hit. "
                                "Set ARGUS_FEED_GREYNOISE_API_KEY to lift it."
                            ),
                        )
                    if resp.status == 401:
                        return GreyNoiseCommunityResult(
                            ip=ip, success=False,
                            error="HTTP 401 — API key invalid or revoked",
                        )
                    if resp.status == 404:
                        # IP is not known to GreyNoise. That's a valid
                        # answer — cache it as "no signal" so we don't
                        # re-query for 24h.
                        out = GreyNoiseCommunityResult(
                            ip=ip, success=True, classification=None,
                        )
                        await _to_cache(ip, out, cache_ttl_s)
                        return out
                    if resp.status != 200:
                        text = (await resp.text())[:200]
                        return GreyNoiseCommunityResult(
                            ip=ip, success=False,
                            error=f"HTTP {resp.status}: {text}",
                        )
                    payload = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001
        return GreyNoiseCommunityResult(
            ip=ip, success=False, error=f"{type(e).__name__}: {e}"[:200],
        )

    last_seen = None
    last_str = payload.get("last_seen") or payload.get("last_seen_at")
    if last_str:
        try:
            # GreyNoise returns ISO 8601 with trailing Z.
            last_seen = datetime.fromisoformat(
                str(last_str).replace("Z", "+00:00")
            )
        except ValueError:
            pass

    result = GreyNoiseCommunityResult(
        ip=ip,
        success=True,
        classification=(payload.get("classification") or None),
        name=(payload.get("name") or None),
        noise=payload.get("noise"),
        riot=payload.get("riot"),
        last_seen=last_seen,
        tags=list(payload.get("tags") or []),
        link=(payload.get("link") or None),
        raw=payload,
    )
    await _to_cache(ip, result, cache_ttl_s)
    return result
