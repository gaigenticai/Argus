"""Shodan InternetDB per-IP enrichment.

Shodan's InternetDB is the **free** slice of the Shodan corpus
served from a dedicated host (``internetdb.shodan.io``). No API key,
no rate limit on the documented public endpoint — Shodan publishes a
weekly snapshot of every IPv4 they've scanned containing:

  * open ports
  * CPE strings (software fingerprints)
  * CVE IDs (vuln IDs the CPEs match)
  * hostnames (rDNS / cert SANs)
  * tags (Shodan-curated labels: ``honeypot``, ``cdn``, ``vpn``…)

That is a *huge* enrichment win — every IP we already have an Alert /
IOC / EASM finding for becomes annotated with "open ports + known CVEs
+ hostname leakage" without spending a dollar. We cache results 24h
in Redis (the upstream snapshot only refreshes weekly anyway, so no
point hammering it on every page render).

Failure modes (returned as ``error`` on the result, never raised):

  * 404 — IP not in Shodan's corpus (returns the zero-shape payload)
  * 429 — Shodan applied an unannounced limit; safe to retry later
  * network — timeout / DNS / 5xx; safe to retry later
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from src.core.http_circuit import get_breaker

logger = logging.getLogger(__name__)


_BASE_URL = "https://internetdb.shodan.io"
_BREAKER = "enrichment:shodan_internetdb"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h — upstream refreshes weekly
_CACHE_KEY_PREFIX = "argus:shodan_internetdb:"
_TIMEOUT_SECONDS = 8


@dataclass
class ShodanInternetDbResult:
    """Normalised /<ip> response from Shodan InternetDB."""

    ip: str
    success: bool
    in_corpus: bool = False
    ports: list[int] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    error: Optional[str] = None
    cached: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "success": self.success,
            "in_corpus": self.in_corpus,
            "ports": self.ports,
            "cpes": self.cpes,
            "vulns": self.vulns,
            "hostnames": self.hostnames,
            "tags": self.tags,
            "error": self.error,
            "cached": self.cached,
        }


async def _from_cache(ip: str) -> Optional[ShodanInternetDbResult]:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            raw = await client.get(_CACHE_KEY_PREFIX + ip)
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.debug("[shodan_internetdb] cache read failed: %s", exc)
        return None
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    return ShodanInternetDbResult(
        ip=d.get("ip", ip),
        success=bool(d.get("success", True)),
        in_corpus=bool(d.get("in_corpus", False)),
        ports=list(d.get("ports") or []),
        cpes=list(d.get("cpes") or []),
        vulns=list(d.get("vulns") or []),
        hostnames=list(d.get("hostnames") or []),
        tags=list(d.get("tags") or []),
        error=d.get("error"),
        cached=True,
        raw=d.get("raw", {}),
    )


async def _store_cache(ip: str, result: ShodanInternetDbResult) -> None:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        payload = {
            "ip": result.ip,
            "success": result.success,
            "in_corpus": result.in_corpus,
            "ports": result.ports,
            "cpes": result.cpes,
            "vulns": result.vulns,
            "hostnames": result.hostnames,
            "tags": result.tags,
            "error": result.error,
            "raw": result.raw,
        }
        try:
            await client.setex(
                _CACHE_KEY_PREFIX + ip, _CACHE_TTL_SECONDS, json.dumps(payload),
            )
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.debug("[shodan_internetdb] cache write failed: %s", exc)


async def check_ip(
    ip: str, *, use_cache: bool = True,
) -> ShodanInternetDbResult:
    """Look up ``ip`` in Shodan InternetDB.

    Returns ``in_corpus=False`` for IPs Shodan hasn't scanned (clean
    404 from upstream is the canonical "not in corpus" signal). All
    other failures populate ``error`` and ``success=False`` — never
    raises out, so callers can chain enrichments without try/except.
    """
    if not ip:
        return ShodanInternetDbResult(ip=ip, success=False, error="empty ip")

    if use_cache:
        cached = await _from_cache(ip)
        if cached is not None:
            return cached

    url = f"{_BASE_URL}/{ip}"
    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=_TIMEOUT_SECONDS)
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(url, headers={
                    "Accept": "application/json",
                    "User-Agent": "argus-threat-intelligence",
                }) as resp:
                    if resp.status == 404:
                        # Documented "not in corpus" response.
                        result = ShodanInternetDbResult(
                            ip=ip, success=True, in_corpus=False,
                        )
                        await _store_cache(ip, result)
                        return result
                    if resp.status == 429:
                        return ShodanInternetDbResult(
                            ip=ip, success=False,
                            error="HTTP 429 — Shodan rate-limited; retry shortly",
                        )
                    if resp.status != 200:
                        return ShodanInternetDbResult(
                            ip=ip, success=False,
                            error=f"HTTP {resp.status}",
                        )
                    try:
                        payload = await resp.json(content_type=None)
                    except Exception as exc:  # noqa: BLE001
                        return ShodanInternetDbResult(
                            ip=ip, success=False,
                            error=f"JSON parse: {exc}",
                        )
    except Exception as exc:  # noqa: BLE001
        return ShodanInternetDbResult(
            ip=ip, success=False, error=f"{type(exc).__name__}: {exc}"[:200],
        )

    if not isinstance(payload, dict):
        return ShodanInternetDbResult(
            ip=ip, success=False, error="unexpected payload type",
        )

    result = ShodanInternetDbResult(
        ip=ip,
        success=True,
        in_corpus=True,
        ports=sorted({int(p) for p in (payload.get("ports") or []) if isinstance(p, int)}),
        cpes=list(payload.get("cpes") or []),
        vulns=sorted(set(payload.get("vulns") or [])),
        hostnames=list(payload.get("hostnames") or []),
        tags=list(payload.get("tags") or []),
        raw=payload,
    )
    await _store_cache(ip, result)
    return result
