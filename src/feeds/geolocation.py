"""IP geolocation engine — resolves IPs to lat/lon for the threat map.

Uses MaxMind GeoLite2 local DB (instant, offline) with ip-api.com batch fallback.
"""

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

    Primary: MaxMind GeoLite2-City.mmdb (local, instant)
    Fallback: ip-api.com batch API (free, 15 req/min, 100 IPs per batch)
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
        except Exception as e:
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
                    asn_str = f"AS{asn_resp.autonomous_system_number} {asn_resp.autonomous_system_organization}"
                except Exception:
                    pass
            return GeoResult(
                latitude=resp.location.latitude,
                longitude=resp.location.longitude,
                country_code=resp.country.iso_code,
                city=resp.city.name,
                asn=asn_str,
            )
        except Exception:
            return _EMPTY

    async def locate_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        """Batch resolve IPs. Uses MaxMind for all available; falls back to ip-api.com for misses."""
        results: dict[str, GeoResult] = {}
        misses: list[str] = []

        # Phase 1: MaxMind local lookups (instant)
        for ip in ips:
            if not self._is_public_ip(ip):
                results[ip] = _EMPTY
                continue
            geo = self.locate(ip)
            if geo.latitude is not None:
                results[ip] = geo
            else:
                misses.append(ip)

        # Phase 2: ip-api.com batch for misses
        if misses:
            api_results = await self._ipapi_batch(misses)
            results.update(api_results)

        return results

    async def _ipapi_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        """Resolve IPs via ip-api.com batch endpoint (POST, max 100 per request)."""
        results: dict[str, GeoResult] = {}
        batch_size = settings.feeds.ipapi_batch_size
        timeout = aiohttp.ClientTimeout(total=30)

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
                    except Exception as e:
                        logger.error("ip-api.com batch failed: %s", e)
                        for ip in batch:
                            results[ip] = _EMPTY

                # Rate limit: ip-api.com allows 15 requests per minute for batch
                if i + batch_size < len(ips):
                    await asyncio.sleep(5.0)  # ~12 per minute (safe margin)

        return results

    def close(self):
        """Close MaxMind readers."""
        if self._reader:
            self._reader.close()
            self._reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None
