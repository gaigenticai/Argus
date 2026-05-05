"""IBM X-Force Exchange per-IP enrichment.

X-Force Exchange (https://exchange.xforce.ibmcloud.com) is IBM's
public threat-intelligence portal. The free tier requires a
registered account but the API is functional for defensive use:
~5,000 lookups/month at the free tier, with a 0-10 risk score per
IP plus categorical labels (Spam, Bots, Malware, etc.).

API contract (verified May 2026):

    GET https://api.xforce.ibmcloud.com/ipr/<ip>
    Auth: HTTP Basic with (api_key, api_password) — both are
          generated together in the X-Force settings UI.

    Response (top-level):
        ip,        score (float 0..10),
        cats (object: {category_name: severity}),
        reason,    reasonDescription,
        subnets,   geo (country/region),
        history (recent activity timeline)

We cache by IP for 24h; X-Force's reputation rarely shifts on
shorter timescales and the free quota is finite.
"""

from __future__ import annotations

import json
import logging
from base64 import b64encode
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from src.core.http_circuit import get_breaker

logger = logging.getLogger(__name__)


_API_URL = "https://api.xforce.ibmcloud.com/ipr/{ip}"
_BREAKER = "enrichment:xforce"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h
_CACHE_KEY_PREFIX = "argus:xforce:"
_TIMEOUT_SECONDS = 8


@dataclass
class XforceResult:
    ip: str
    success: bool
    in_corpus: bool = False
    score: float = 0.0
    reason: Optional[str] = None
    reason_description: Optional[str] = None
    categories: dict[str, Any] = field(default_factory=dict)
    country: Optional[str] = None
    error: Optional[str] = None
    cached: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "success": self.success,
            "in_corpus": self.in_corpus,
            "score": self.score,
            "reason": self.reason,
            "reason_description": self.reason_description,
            "categories": self.categories,
            "country": self.country,
            "error": self.error,
            "cached": self.cached,
        }


def _resolve_creds() -> tuple[str, str]:
    from src.core import integration_keys
    key = (
        integration_keys.get("xforce_key", env_fallback="ARGUS_XFORCE_API_KEY")
        or ""
    ).strip()
    password = (
        integration_keys.get("xforce_password", env_fallback="ARGUS_XFORCE_API_PASSWORD")
        or ""
    ).strip()
    return key, password


def is_configured() -> bool:
    key, password = _resolve_creds()
    return bool(key and password)


async def _from_cache(ip: str) -> Optional[XforceResult]:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            raw = await client.get(_CACHE_KEY_PREFIX + ip)
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
    return XforceResult(
        ip=d.get("ip", ip),
        success=bool(d.get("success", True)),
        in_corpus=bool(d.get("in_corpus", False)),
        score=float(d.get("score") or 0.0),
        reason=d.get("reason"),
        reason_description=d.get("reason_description"),
        categories=dict(d.get("categories") or {}),
        country=d.get("country"),
        error=d.get("error"),
        cached=True,
        raw=d.get("raw", {}),
    )


async def _store_cache(ip: str, result: XforceResult) -> None:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            await client.setex(
                _CACHE_KEY_PREFIX + ip, _CACHE_TTL_SECONDS,
                json.dumps({
                    "ip": result.ip,
                    "success": result.success,
                    "in_corpus": result.in_corpus,
                    "score": result.score,
                    "reason": result.reason,
                    "reason_description": result.reason_description,
                    "categories": result.categories,
                    "country": result.country,
                    "error": result.error,
                    "raw": result.raw,
                }),
            )
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        pass


async def check_ip(ip: str, *, use_cache: bool = True) -> XforceResult:
    if not ip:
        return XforceResult(ip=ip, success=False, error="empty ip")

    key, password = _resolve_creds()
    if not (key and password):
        return XforceResult(
            ip=ip, success=False,
            error="X-Force API key + password not configured",
        )

    if use_cache:
        cached = await _from_cache(ip)
        if cached is not None:
            return cached

    auth_token = b64encode(f"{key}:{password}".encode()).decode()
    url = _API_URL.format(ip=ip)
    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=_TIMEOUT_SECONDS)

    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(url, headers={
                    "Accept": "application/json",
                    "Authorization": f"Basic {auth_token}",
                    "User-Agent": "argus-threat-intelligence",
                }) as resp:
                    if resp.status == 404:
                        # IP not in X-Force corpus — clean miss.
                        result = XforceResult(
                            ip=ip, success=True, in_corpus=False,
                        )
                        await _store_cache(ip, result)
                        return result
                    if resp.status == 401:
                        return XforceResult(
                            ip=ip, success=False,
                            error="HTTP 401 — X-Force creds rejected",
                        )
                    if resp.status == 402 or resp.status == 429:
                        return XforceResult(
                            ip=ip, success=False,
                            error=f"HTTP {resp.status} — X-Force quota exhausted",
                        )
                    if resp.status != 200:
                        return XforceResult(
                            ip=ip, success=False,
                            error=f"HTTP {resp.status}",
                        )
                    try:
                        payload = await resp.json(content_type=None)
                    except Exception as exc:  # noqa: BLE001
                        return XforceResult(
                            ip=ip, success=False,
                            error=f"JSON parse: {exc}",
                        )
    except Exception as exc:  # noqa: BLE001
        return XforceResult(
            ip=ip, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    if not isinstance(payload, dict):
        return XforceResult(
            ip=ip, success=False, error="unexpected payload type",
        )

    geo = payload.get("geo") or {}
    result = XforceResult(
        ip=ip,
        success=True,
        in_corpus=True,
        score=float(payload.get("score") or 0.0),
        reason=payload.get("reason"),
        reason_description=payload.get("reasonDescription"),
        categories=dict(payload.get("cats") or {}),
        country=(geo.get("country") if isinstance(geo, dict) else None),
        raw=payload,
    )
    await _store_cache(ip, result)
    return result
