"""ipinfo.io Lite per-IP enrichment.

The Lite tier of ipinfo.io is free for every registered ipinfo
account and returns country + ASN data with no monthly cap (the
city-level paid tier is unlimited too on Lite — they just dropped
that to country granularity in 2025).

Distinct from MaxMind GeoIP2: ipinfo's ASN database is more current
than the free GeoLite2 ASN snapshot Argus ships, so this is a useful
fallback / cross-check enrichment for IPs.

API contract (verified May 2026):

    GET https://api.ipinfo.io/lite/<ip>?token=<token>

    Response keys:
        ip, asn, as_name, as_domain,
        country_code, country, continent_code, continent

Free tier: requires a token but no monthly cap. Unauthenticated calls
return HTTP 401 (we surface as ``error="needs token"``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from src.core.http_circuit import get_breaker

logger = logging.getLogger(__name__)


_API_URL = "https://api.ipinfo.io/lite/{ip}"
_BREAKER = "enrichment:ipinfo_lite"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h
_CACHE_KEY_PREFIX = "argus:ipinfo_lite:"
_TIMEOUT_SECONDS = 6


@dataclass
class IpinfoLiteResult:
    ip: str
    success: bool
    asn: Optional[str] = None
    as_name: Optional[str] = None
    as_domain: Optional[str] = None
    country_code: Optional[str] = None
    country: Optional[str] = None
    continent_code: Optional[str] = None
    continent: Optional[str] = None
    error: Optional[str] = None
    cached: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "success": self.success,
            "asn": self.asn,
            "as_name": self.as_name,
            "as_domain": self.as_domain,
            "country_code": self.country_code,
            "country": self.country,
            "continent_code": self.continent_code,
            "continent": self.continent,
            "error": self.error,
            "cached": self.cached,
        }


def _resolve_token() -> str:
    from src.core import integration_keys
    return (
        integration_keys.get(
            "ipinfo_lite", env_fallback="ARGUS_IPINFO_LITE_TOKEN",
        ) or ""
    ).strip()


def is_configured() -> bool:
    return bool(_resolve_token())


async def _from_cache(ip: str) -> Optional[IpinfoLiteResult]:
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
    return IpinfoLiteResult(
        ip=d.get("ip", ip),
        success=bool(d.get("success", True)),
        asn=d.get("asn"),
        as_name=d.get("as_name"),
        as_domain=d.get("as_domain"),
        country_code=d.get("country_code"),
        country=d.get("country"),
        continent_code=d.get("continent_code"),
        continent=d.get("continent"),
        error=d.get("error"),
        cached=True,
        raw=d.get("raw", {}),
    )


async def _store_cache(ip: str, result: IpinfoLiteResult) -> None:
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
                    "asn": result.asn,
                    "as_name": result.as_name,
                    "as_domain": result.as_domain,
                    "country_code": result.country_code,
                    "country": result.country,
                    "continent_code": result.continent_code,
                    "continent": result.continent,
                    "error": result.error,
                    "raw": result.raw,
                }),
            )
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        pass


async def lookup(ip: str, *, use_cache: bool = True) -> IpinfoLiteResult:
    if not ip:
        return IpinfoLiteResult(ip=ip, success=False, error="empty ip")

    token = _resolve_token()
    if not token:
        return IpinfoLiteResult(
            ip=ip, success=False,
            error="ARGUS_IPINFO_LITE_TOKEN not set (free at ipinfo.io)",
        )

    if use_cache:
        cached = await _from_cache(ip)
        if cached is not None:
            return cached

    url = _API_URL.format(ip=ip) + f"?token={token}"
    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=_TIMEOUT_SECONDS)

    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(url, headers={
                    "Accept": "application/json",
                    "User-Agent": "argus-threat-intelligence",
                }) as resp:
                    if resp.status == 401:
                        return IpinfoLiteResult(
                            ip=ip, success=False,
                            error="HTTP 401 — ipinfo token rejected",
                        )
                    if resp.status == 429:
                        return IpinfoLiteResult(
                            ip=ip, success=False,
                            error="HTTP 429 — ipinfo rate-limited",
                        )
                    if resp.status != 200:
                        return IpinfoLiteResult(
                            ip=ip, success=False,
                            error=f"HTTP {resp.status}",
                        )
                    try:
                        payload = await resp.json(content_type=None)
                    except Exception as exc:  # noqa: BLE001
                        return IpinfoLiteResult(
                            ip=ip, success=False,
                            error=f"JSON parse: {exc}",
                        )
    except Exception as exc:  # noqa: BLE001
        return IpinfoLiteResult(
            ip=ip, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    if not isinstance(payload, dict):
        return IpinfoLiteResult(
            ip=ip, success=False, error="unexpected payload type",
        )

    result = IpinfoLiteResult(
        ip=ip,
        success=True,
        asn=payload.get("asn"),
        as_name=payload.get("as_name"),
        as_domain=payload.get("as_domain"),
        country_code=payload.get("country_code"),
        country=payload.get("country"),
        continent_code=payload.get("continent_code"),
        continent=payload.get("continent"),
        raw=payload,
    )
    await _store_cache(ip, result)
    return result
