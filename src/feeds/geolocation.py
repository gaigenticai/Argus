"""IP geolocation engine — resolves IPs to lat/lon for the threat map.

Chain: DB-IP Lite MMDB (instant, offline) → ipwho.is (free, commercial OK) → ip-api.com (last resort).
"""

from __future__ import annotations


import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from src.config.settings import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GeoResult:
    latitude: float | None = None
    longitude: float | None = None
    country_code: str | None = None  # ISO 3166-1 alpha-2
    city: str | None = None
    asn: str | None = None


_EMPTY = GeoResult()


class GeoLocator:
    """IP-to-location resolver.

    Primary: DB-IP Lite MMDB (local, instant)
    Fallback 1: ipwho.is (free, HTTPS, no key, commercial use OK)
    Fallback 2: ip-api.com batch (free tier, non-commercial, last resort)
    """

    def __init__(self):
        self._reader = None  # geoip2.database.Reader or None
        self._asn_reader = None
        self._ipapi_semaphore = asyncio.Semaphore(settings.feeds.ipapi_rate_limit)
        self._init_maxmind()

    def _init_maxmind(self):
        """Try to load MMDB geolocation database (DB-IP Lite or MaxMind GeoLite2)."""
        db_path = Path(settings.feeds.maxmind_db_path)
        if not db_path.exists():
            logger.warning(
                "GeoIP MMDB not found at %s — using ip-api.com fallback. "
                "Download DB-IP Lite or MaxMind GeoLite2 for better performance.",
                db_path,
            )
            return
        try:
            import geoip2.database

            self._reader = geoip2.database.Reader(str(db_path))
            # Try ASN DB too (MaxMind format)
            asn_path = db_path.parent / "GeoLite2-ASN.mmdb"
            if asn_path.exists():
                self._asn_reader = geoip2.database.Reader(str(asn_path))
            logger.info("GeoIP MMDB loaded from %s", db_path)
        except (OSError, ImportError) as e:
            # OSError covers a corrupt / truncated MMDB file; ImportError
            # covers the case where geoip2 is missing in a stripped
            # install. Either way, locate() falls back to the network
            # layer.
            logger.warning("Failed to load MaxMind DB: %s", e)

    def _is_public_ip(self, ip_str: str) -> bool:
        """Return True if the IP is a public (globally routable) address."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return addr.is_global
        except ValueError:
            return False

    def locate(self, ip: str) -> GeoResult:
        """Synchronous single-IP lookup from MaxMind local DB.
        Returns GeoResult with coordinates, or empty result if unavailable.
        """
        if not self._is_public_ip(ip):
            return _EMPTY
        if self._reader is None:
            return _EMPTY
        try:
            resp = self._reader.city(ip)
            asn_str = None
            if self._asn_reader:
                try:
                    asn_resp = self._asn_reader.asn(ip)
                    asn_str = (
                        f"AS{asn_resp.autonomous_system_number} "
                        f"{asn_resp.autonomous_system_organization}"
                    )
                except Exception as asn_exc:  # noqa: BLE001
                    # geoip2 raises AddressNotFoundError for IPs the
                    # ASN db doesn't know — common for residential
                    # ranges and not actionable. Log at DEBUG so a
                    # cluster of failures is visible if needed.
                    logger.debug("ASN lookup miss for %s: %s", ip, asn_exc)
            return GeoResult(
                latitude=resp.location.latitude,
                longitude=resp.location.longitude,
                country_code=resp.country.iso_code,
                city=resp.city.name,
                asn=asn_str,
            )
        except Exception as exc:  # noqa: BLE001
            # geoip2 throws a family of exceptions (AddressNotFoundError,
            # InvalidDatabaseError, ValueError on bad IP). Treat them
            # all as "miss" rather than failing the caller — the geo
            # data is best-effort enrichment, not a correctness
            # signal. Logged at DEBUG.
            logger.debug("MMDB lookup miss for %s: %s", ip, exc)
            return _EMPTY

    async def locate_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        """Batch resolve IPs. Chain: MMDB → ip-api.com batch → ipwho.is single."""
        results: dict[str, GeoResult] = {}
        misses: list[str] = []

        # Phase 1: Local MMDB lookups (instant)
        for ip in ips:
            if not self._is_public_ip(ip):
                results[ip] = _EMPTY
                continue
            geo = self.locate(ip)
            if geo.latitude is not None:
                results[ip] = geo
            else:
                misses.append(ip)

        # Phase 2: ipwho.is for misses (free, commercial use OK)
        if misses:
            ipwhois_results = await self._ipwhois_fallback(misses)
            results.update(ipwhois_results)

        # Phase 3: ip-api.com batch as last resort for remaining misses
        still_missing = [ip for ip in misses if results.get(ip, _EMPTY).latitude is None]
        if still_missing:
            api_results = await self._ipapi_batch(still_missing)
            results.update(api_results)

        return results

    async def _ipapi_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        """Resolve IPs via ip-api.com batch endpoint (POST, max 100 per request).

        Adversarial audit D-17 — wrap in the shared circuit breaker so
        an ip-api outage doesn't keep stalling the feed pipeline on
        30s timeouts.
        """
        from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

        results: dict[str, GeoResult] = {}
        batch_size = settings.feeds.ipapi_batch_size
        timeout = aiohttp.ClientTimeout(total=30)
        breaker = get_breaker("geo:ipapi")

        try:
            async with breaker:
                pass  # acquire-release just to short-circuit when open
        except CircuitBreakerOpenError:
            logger.warning("geo:ipapi breaker OPEN — skipping ip-api batch")
            for ip in ips:
                results[ip] = _EMPTY
            return results

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for i in range(0, len(ips), batch_size):
                batch = ips[i : i + batch_size]
                async with self._ipapi_semaphore:
                    try:
                        # ip-api.com batch endpoint: POST to /batch with JSON array
                        # Each item can be a string (IP) or object with fields
                        payload = [
                            {"query": ip, "fields": "status,lat,lon,countryCode,city,as"}
                            for ip in batch
                        ]
                        async with session.post(
                            "http://ip-api.com/batch",
                            json=payload,
                        ) as resp:
                            if resp.status == 429:
                                logger.warning("ip-api.com rate limited (429) — backing off 60s")
                                await asyncio.sleep(60)
                                for ip in batch:
                                    results[ip] = _EMPTY
                                continue
                            if resp.status != 200:
                                logger.warning("ip-api.com batch returned %d", resp.status)
                                for ip in batch:
                                    results[ip] = _EMPTY
                                continue

                            data = await resp.json()
                            for item, ip in zip(data, batch):
                                if item.get("status") == "success":
                                    results[ip] = GeoResult(
                                        latitude=item.get("lat"),
                                        longitude=item.get("lon"),
                                        country_code=item.get("countryCode"),
                                        city=item.get("city"),
                                        asn=item.get("as"),
                                    )
                                else:
                                    results[ip] = _EMPTY
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as e:
                        logger.error("ip-api.com batch failed: %s", e)
                        for ip in batch:
                            results[ip] = _EMPTY

                # Rate limit: ip-api.com allows 15 requests per minute for batch
                if i + batch_size < len(ips):
                    await asyncio.sleep(5.0)  # ~12 per minute (safe margin)

        return results

    async def _ipwhois_fallback(self, ips: list[str]) -> dict[str, GeoResult]:
        """Resolve IPs via ipwho.is — free, HTTPS, no API key required.

        Single-IP endpoint, so we run up to 20 concurrent requests.
        Used as last-resort for IPs that MMDB and ip-api.com both missed.

        Adversarial audit D-17 — gated by the shared circuit breaker so
        an upstream blip doesn't snowball into a global feed stall.
        """
        from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

        results: dict[str, GeoResult] = {}
        sem = asyncio.Semaphore(20)
        timeout = aiohttp.ClientTimeout(total=10)
        breaker = get_breaker("geo:ipwho")
        try:
            async with breaker:
                pass
        except CircuitBreakerOpenError:
            logger.warning("geo:ipwho breaker OPEN — skipping ipwho fallback")
            for ip in ips:
                results[ip] = _EMPTY
            return results

        async def _fetch_one(session: aiohttp.ClientSession, ip: str) -> None:
            async with sem:
                try:
                    async with session.get(f"https://ipwho.is/{ip}") as resp:
                        if resp.status != 200:
                            results[ip] = _EMPTY
                            return
                        data = await resp.json()
                        if data.get("success"):
                            conn = data.get("connection", {})
                            asn_num = conn.get("asn")
                            asn_org = conn.get("org", "")
                            asn_str = f"AS{asn_num} {asn_org}" if asn_num else None
                            results[ip] = GeoResult(
                                latitude=data.get("latitude"),
                                longitude=data.get("longitude"),
                                country_code=data.get("country_code"),
                                city=data.get("city"),
                                asn=asn_str,
                            )
                        else:
                            results[ip] = _EMPTY
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
                    # Per-IP failure isolation — one bad lookup must
                    # never fail the whole batch. ValueError covers
                    # JSON parse / unexpected schema.
                    results[ip] = _EMPTY

        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [_fetch_one(session, ip) for ip in ips[:200]]  # cap at 200
            await asyncio.gather(*tasks)

        resolved = sum(1 for r in results.values() if r.latitude is not None)
        if resolved:
            logger.info("ipwho.is fallback resolved %d/%d IPs", resolved, len(ips))

        return results

    def close(self):
        """Close MMDB readers."""
        if self._reader:
            self._reader.close()
            self._reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None
