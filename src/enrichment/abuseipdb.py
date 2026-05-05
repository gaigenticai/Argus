"""AbuseIPDB per-IP enrichment.

Replaces the previous bulk ``/blacklist`` poll which the free tier
caps at 5 requests per day (useless). The ``/check`` endpoint allows
1,000 lookups per day on the free tier — orders of magnitude more
useful when applied per-IP-of-interest at ingest time + on demand
from /iocs detail panels.

Resolution + caching:
  - Cache by IP in Redis with a configurable TTL (24h default). One
    real-world abuse score doesn't change every minute; we'd burn the
    free quota re-checking the same IP otherwise.
  - Hot-reload of the API key via the integration_keys cache.
  - Graceful 404 / 429 / network failures → return ``ProviderResult``
    with ``error`` populated, never raise out.
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


_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
_BREAKER = "intel:abuseipdb"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h


@dataclass
class AbuseIpdbResult:
    """Normalised AbuseIPDB /check response."""
    ip: str
    success: bool
    abuse_confidence_score: int = 0
    is_public: bool = False
    is_whitelisted: Optional[bool] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    usage_type: Optional[str] = None
    total_reports: int = 0
    last_reported_at: Optional[datetime] = None
    rate_limited: bool = False
    error: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "success": self.success,
            "abuse_confidence_score": self.abuse_confidence_score,
            "is_public": self.is_public,
            "is_whitelisted": self.is_whitelisted,
            "country_code": self.country_code,
            "isp": self.isp,
            "domain": self.domain,
            "usage_type": self.usage_type,
            "total_reports": self.total_reports,
            "last_reported_at": (
                self.last_reported_at.isoformat() if self.last_reported_at else None
            ),
            "rate_limited": self.rate_limited,
            "error": self.error,
            "cached": self.cached,
        }


def _resolve_key() -> str:
    from src.core import integration_keys
    return (
        integration_keys.get(
            "abuseipdb", env_fallback="ARGUS_FEED_ABUSEIPDB_API_KEY",
        ) or ""
    ).strip()


def is_configured() -> bool:
    return bool(_resolve_key())


async def _from_cache(ip: str) -> Optional[AbuseIpdbResult]:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            raw = await client.get(f"abuseipdb:{ip}")
        finally:
            await client.aclose()
        if not raw:
            return None
        data = json.loads(raw)
        last = data.get("last_reported_at")
        return AbuseIpdbResult(
            ip=ip,
            success=True,
            abuse_confidence_score=data.get("abuse_confidence_score", 0),
            is_public=data.get("is_public", False),
            is_whitelisted=data.get("is_whitelisted"),
            country_code=data.get("country_code"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            usage_type=data.get("usage_type"),
            total_reports=data.get("total_reports", 0),
            last_reported_at=datetime.fromisoformat(last) if last else None,
            cached=True,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("abuseipdb cache miss / error: %s", e)
        return None


async def _store_cache(ip: str, result: AbuseIpdbResult, ttl_s: int) -> None:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        payload = {
            "abuse_confidence_score": result.abuse_confidence_score,
            "is_public": result.is_public,
            "is_whitelisted": result.is_whitelisted,
            "country_code": result.country_code,
            "isp": result.isp,
            "domain": result.domain,
            "usage_type": result.usage_type,
            "total_reports": result.total_reports,
            "last_reported_at": (
                result.last_reported_at.isoformat()
                if result.last_reported_at else None
            ),
        }
        try:
            await client.set(
                f"abuseipdb:{ip}", json.dumps(payload), ex=ttl_s,
            )
        finally:
            await client.aclose()
    except Exception as e:  # noqa: BLE001
        logger.debug("abuseipdb cache store failed: %s", e)


async def check_ip(
    ip: str,
    *,
    max_age_days: int = 90,
    cache_ttl_s: int = _CACHE_TTL_SECONDS,
    use_cache: bool = True,
) -> AbuseIpdbResult:
    """Look up an IP against AbuseIPDB. Cached in Redis for 24h by
    default to avoid burning the free-tier quota.

    ``max_age_days`` controls how far back to consider abuse reports
    (90 is the AbuseIPDB recommended default for ingest enrichment)."""
    ip = (ip or "").strip()
    if not ip:
        return AbuseIpdbResult(ip="", success=False, error="empty IP")

    if use_cache:
        cached = await _from_cache(ip)
        if cached is not None:
            return cached

    key = _resolve_key()
    if not key:
        return AbuseIpdbResult(
            ip=ip, success=False,
            error="ARGUS_FEED_ABUSEIPDB_API_KEY not set",
        )

    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=15)
    headers = {
        "Key": key,
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
    }
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days)}

    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(_CHECK_URL, headers=headers, params=params) as resp:
                    if resp.status == 429:
                        return AbuseIpdbResult(
                            ip=ip, success=False, rate_limited=True,
                            error="HTTP 429 — daily free-tier limit hit (1000/day on /check)",
                        )
                    if resp.status == 401:
                        return AbuseIpdbResult(
                            ip=ip, success=False,
                            error="HTTP 401 — API key invalid or revoked",
                        )
                    if resp.status != 200:
                        text = (await resp.text())[:200]
                        return AbuseIpdbResult(
                            ip=ip, success=False,
                            error=f"HTTP {resp.status}: {text}",
                        )
                    payload = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001
        return AbuseIpdbResult(
            ip=ip, success=False, error=f"{type(e).__name__}: {e}"[:200],
        )

    data = (payload or {}).get("data") or {}
    last_str = data.get("lastReportedAt")
    last_dt: Optional[datetime] = None
    if last_str:
        try:
            last_dt = datetime.fromisoformat(last_str.replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            last_dt = None

    result = AbuseIpdbResult(
        ip=ip,
        success=True,
        abuse_confidence_score=int(data.get("abuseConfidenceScore", 0)),
        is_public=bool(data.get("isPublic", False)),
        is_whitelisted=data.get("isWhitelisted"),
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        domain=data.get("domain"),
        usage_type=data.get("usageType"),
        total_reports=int(data.get("totalReports", 0)),
        last_reported_at=last_dt,
        raw=data,
    )

    if use_cache:
        await _store_cache(ip, result, cache_ttl_s)

    return result
