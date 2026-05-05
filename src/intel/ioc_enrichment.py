"""IOC enrichment orchestrator.

Fans out concurrent lookups to free OSS / public APIs and merges into
``IOC.enrichment_data`` JSONB. Per-source results live under their own
key so the FE detail row can render badges per provider:

  enrichment_data = {
    "abuseipdb":  {"score": 87, "reports": 412, "last_seen": ...},
    "otx":        {"pulses": 5, "tags": ["ransomware"], "url": ...},
    "urlhaus":    {"threat": "malware_download", "url": ...},
    "threatfox":  {"malware": "AgentTesla", "confidence": 90, ...},
    "shodan":     {"open_ports": [22,80], ...},
    "greynoise":  {"classification": "malicious", ...},
    "circl":      {"hashlookup": {...}, "pdns": {...}},
    "fetched_at": "2026-05-04T...",
  }

Sources used (all free / OSS / no auth required for the listed endpoints):
  * AbuseIPDB     (free 1000 q/day with key, optional)
  * OTX           (AlienVault — free without key for indicator lookup)
  * URLhaus       (abuse.ch — free, no key)
  * ThreatFox     (abuse.ch — free, no key)
  * Shodan        (InternetDB — free, no key)
  * GreyNoise     (community — free, no key)
  * CIRCL         (Hashlookup + PDNS — free, no key for some endpoints)
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import aiohttp

_logger = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Argus-CTI/1.0 (+https://argus.security)"}


async def _otx_indicator(session: aiohttp.ClientSession, ind_type: str, value: str) -> dict[str, Any] | None:
    """AlienVault OTX free indicator lookup."""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{value}/general"
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            pulse_info = data.get("pulse_info") or {}
            return {
                "pulses": pulse_info.get("count", 0),
                "tags": sorted({t for p in pulse_info.get("pulses", []) for t in (p.get("tags") or [])})[:20],
                "malware_families": sorted({m.get("display_name") for p in pulse_info.get("pulses", []) for m in (p.get("malware_families") or []) if isinstance(m, dict) and m.get("display_name")})[:10],
                "url": f"https://otx.alienvault.com/indicator/{ind_type}/{value}",
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        _logger.debug("otx %s lookup failed: %s", ind_type, e)
        return None


async def _urlhaus(session: aiohttp.ClientSession, url_or_host: str, *, by_host: bool = False) -> dict[str, Any] | None:
    """abuse.ch URLhaus free lookup."""
    try:
        api = "https://urlhaus-api.abuse.ch/v1/host/" if by_host else "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"host" if by_host else "url": url_or_host}
        async with session.post(api, data=data) as resp:
            if resp.status != 200:
                return None
            j = await resp.json()
            if j.get("query_status") != "ok":
                return None
            urls = j.get("urls") or []
            if not urls and not j.get("url"):
                return None
            sample = urls[0] if urls else j
            return {
                "threat": sample.get("threat") or j.get("threat"),
                "url_status": sample.get("url_status") or j.get("url_status"),
                "tags": sample.get("tags") or [],
                "first_seen": sample.get("date_added") or j.get("date_added"),
                "url": sample.get("urlhaus_reference") or j.get("urlhaus_reference"),
                "match_count": len(urls) if by_host else 1,
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        _logger.debug("urlhaus lookup failed: %s", e)
        return None


async def _threatfox_ioc(session: aiohttp.ClientSession, value: str) -> dict[str, Any] | None:
    """abuse.ch ThreatFox free IOC lookup."""
    try:
        async with session.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": value},
        ) as resp:
            if resp.status != 200:
                return None
            j = await resp.json()
            if j.get("query_status") != "ok":
                return None
            data = j.get("data") or []
            if not data:
                return None
            head = data[0]
            return {
                "malware": head.get("malware_printable") or head.get("malware"),
                "threat_type": head.get("threat_type"),
                "confidence": head.get("confidence_level"),
                "first_seen": head.get("first_seen"),
                "tags": head.get("tags") or [],
                "url": f"https://threatfox.abuse.ch/ioc/{head.get('id')}",
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        _logger.debug("threatfox lookup failed: %s", e)
        return None


async def _abuseipdb(session: aiohttp.ClientSession, ip: str) -> dict[str, Any] | None:
    """Use existing ``src.enrichment.abuseipdb`` if a key is configured."""
    try:
        from src.enrichment import abuseipdb as ai
        if not ai.is_configured():
            return None
        result = await ai.check_ip(ip)
        if result is None:
            return None
        return {
            "score": result.abuse_confidence_score,
            "reports": result.total_reports,
            "country": result.country_code,
            "isp": result.isp,
            "domain": result.domain,
            "last_reported_at": result.last_reported_at.isoformat() if result.last_reported_at else None,
        }
    except Exception as e:  # noqa: BLE001
        _logger.debug("abuseipdb wrapper failed: %s", e)
        return None


async def _shodan_internetdb(session: aiohttp.ClientSession, ip: str) -> dict[str, Any] | None:
    """No-auth Shodan InternetDB lookup."""
    try:
        async with session.get(f"https://internetdb.shodan.io/{ip}") as resp:
            if resp.status != 200:
                return None
            j = await resp.json()
            return {
                "open_ports": j.get("ports") or [],
                "vulns": (j.get("vulns") or [])[:20],
                "tags": j.get("tags") or [],
                "hostnames": j.get("hostnames") or [],
                "url": f"https://internetdb.shodan.io/{ip}",
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        _logger.debug("shodan internetdb lookup failed: %s", e)
        return None


async def _greynoise(session: aiohttp.ClientSession, ip: str) -> dict[str, Any] | None:
    """GreyNoise community lookup (free, no key)."""
    try:
        async with session.get(f"https://api.greynoise.io/v3/community/{ip}") as resp:
            if resp.status != 200:
                return None
            j = await resp.json()
            return {
                "classification": j.get("classification"),
                "noise": j.get("noise"),
                "riot": j.get("riot"),
                "name": j.get("name"),
                "last_seen": j.get("last_seen"),
                "url": j.get("link"),
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        _logger.debug("greynoise lookup failed: %s", e)
        return None


async def _circl_hashlookup(session: aiohttp.ClientSession, h: str) -> dict[str, Any] | None:
    """CIRCL hashlookup — free, no key."""
    h = h.lower()
    if len(h) == 32:
        endpoint = f"https://hashlookup.circl.lu/lookup/md5/{h}"
    elif len(h) == 40:
        endpoint = f"https://hashlookup.circl.lu/lookup/sha1/{h}"
    elif len(h) == 64:
        endpoint = f"https://hashlookup.circl.lu/lookup/sha256/{h}"
    else:
        return None
    try:
        async with session.get(endpoint) as resp:
            if resp.status != 200:
                return None
            j = await resp.json()
            if j.get("message"):
                return None
            return {
                "filename": j.get("FileName"),
                "filesize": j.get("FileSize"),
                "trust": j.get("hashlookup:trust"),
                "source": j.get("source"),
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        _logger.debug("circl hashlookup failed: %s", e)
        return None


async def enrich_ioc(ioc_type: str, value: str) -> dict[str, Any]:
    """Run every applicable enrichment source concurrently."""
    out: dict[str, Any] = {}
    async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=_HEADERS) as session:
        tasks: list[tuple[str, asyncio.Task[Any]]] = []

        if ioc_type == "ipv4":
            tasks.append(("abuseipdb", asyncio.create_task(_abuseipdb(session, value))))
            tasks.append(("otx", asyncio.create_task(_otx_indicator(session, "IPv4", value))))
            tasks.append(("shodan", asyncio.create_task(_shodan_internetdb(session, value))))
            tasks.append(("greynoise", asyncio.create_task(_greynoise(session, value))))
            tasks.append(("threatfox", asyncio.create_task(_threatfox_ioc(session, value))))
        elif ioc_type == "ipv6":
            tasks.append(("otx", asyncio.create_task(_otx_indicator(session, "IPv6", value))))
            tasks.append(("threatfox", asyncio.create_task(_threatfox_ioc(session, value))))
        elif ioc_type == "domain":
            tasks.append(("otx", asyncio.create_task(_otx_indicator(session, "domain", value))))
            tasks.append(("urlhaus", asyncio.create_task(_urlhaus(session, value, by_host=True))))
            tasks.append(("threatfox", asyncio.create_task(_threatfox_ioc(session, value))))
        elif ioc_type == "url":
            tasks.append(("otx", asyncio.create_task(_otx_indicator(session, "url", value))))
            tasks.append(("urlhaus", asyncio.create_task(_urlhaus(session, value, by_host=False))))
            tasks.append(("threatfox", asyncio.create_task(_threatfox_ioc(session, value))))
        elif ioc_type in ("md5", "sha1", "sha256"):
            otx_kind = {"md5": "file", "sha1": "file", "sha256": "file"}[ioc_type]
            tasks.append(("otx", asyncio.create_task(_otx_indicator(session, otx_kind, value))))
            tasks.append(("circl", asyncio.create_task(_circl_hashlookup(session, value))))
            tasks.append(("threatfox", asyncio.create_task(_threatfox_ioc(session, value))))

        if not tasks:
            return {"fetched_at": datetime.now(timezone.utc).isoformat(), "skipped": True}

        for name, t in tasks:
            try:
                res = await t
                if res:
                    out[name] = res
            except Exception as e:  # noqa: BLE001
                _logger.debug("enricher %s failed: %s", name, e)

    out["fetched_at"] = datetime.now(timezone.utc).isoformat()
    return out


def malicious_score_from(enrichment: dict[str, Any]) -> float | None:
    """Derive a 0..1 malicious score from accumulated enrichment data.

    Rules of thumb:
      * AbuseIPDB confidence ≥ 75       → 0.9
      * OTX pulses ≥ 3                  → 0.7
      * URLhaus active                  → 0.85
      * ThreatFox malware match         → 0.85
      * GreyNoise classification = malicious → 0.85
    Returns the max of any matched signal, or None if no signal.
    """
    candidates: list[float] = []
    abuse = (enrichment or {}).get("abuseipdb") or {}
    if isinstance(abuse.get("score"), (int, float)) and abuse["score"] >= 75:
        candidates.append(0.9)
    elif isinstance(abuse.get("score"), (int, float)) and abuse["score"] >= 25:
        candidates.append(0.6)
    otx = (enrichment or {}).get("otx") or {}
    if isinstance(otx.get("pulses"), int) and otx["pulses"] >= 3:
        candidates.append(0.7)
    if (enrichment or {}).get("urlhaus", {}).get("url_status") == "online":
        candidates.append(0.85)
    if (enrichment or {}).get("threatfox", {}).get("malware"):
        candidates.append(0.85)
    if (enrichment or {}).get("greynoise", {}).get("classification") == "malicious":
        candidates.append(0.85)
    if not candidates:
        return None
    return max(candidates)


__all__ = ["enrich_ioc", "malicious_score_from"]
