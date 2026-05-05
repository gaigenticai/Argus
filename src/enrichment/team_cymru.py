"""Team Cymru IP-to-ASN WHOIS enrichment.

Team Cymru runs a free, unauthenticated WHOIS service for bulk
IP→ASN/BGP-prefix/country/registry lookups. No API key, no monthly
cap — but they explicitly block clients that hammer them with
single-IP queries when they could batch.

Connection:    whois.cymru.com:43 (TCP)
Single query:  " -v 1.2.3.4\\n"           (note leading space + verbose flag)
Bulk query:    "begin\\nverbose\\n1.2.3.4\\n...\\nend\\n"
Response:      pipe-delimited:
               AS | IP | BGP prefix | CC | registry | alloc date | timestamp | AS name

We expose two functions:

  * ``lookup(ip)``        — single-IP lookup with 7d Redis cache.
  * ``lookup_bulk(ips)``  — efficient batched query for the EASM /
                            asset-discovery pipelines that need to
                            enrich hundreds of IPs at a time.

Cache TTL is long (7d) because BGP allocations change rarely and
Team Cymru's data updates are typically only relevant on prefix-
ownership transfer events, which we don't optimise for here.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


_HOST = "whois.cymru.com"
_PORT = 43
_CACHE_TTL_SECONDS = 60 * 60 * 24 * 7  # 7d
_CACHE_KEY_PREFIX = "argus:team_cymru:"
_TIMEOUT_SECONDS = 8


@dataclass
class TeamCymruResult:
    ip: str
    success: bool
    asn: Optional[str] = None
    bgp_prefix: Optional[str] = None
    country_code: Optional[str] = None
    registry: Optional[str] = None
    allocated_at: Optional[str] = None
    as_name: Optional[str] = None
    error: Optional[str] = None
    cached: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "success": self.success,
            "asn": self.asn,
            "bgp_prefix": self.bgp_prefix,
            "country_code": self.country_code,
            "registry": self.registry,
            "allocated_at": self.allocated_at,
            "as_name": self.as_name,
            "error": self.error,
            "cached": self.cached,
        }


def _parse_response_line(line: str) -> Optional[dict[str, str]]:
    """Parse one pipe-delimited verbose response line into a dict.

    Cymru has shipped two field counts over the years:

      Modern (7 fields):
        ``AS | IP | BGP-prefix | CC | registry | alloc-date | AS-name``

      Legacy (8 fields, with an extra "Updated" timestamp):
        ``AS | IP | BGP-prefix | CC | registry | alloc-date | ts | AS-name``

    AS-name is ALWAYS the last field, so we read it as ``parts[-1]``
    rather than assuming a fixed index. Header line (first non-empty
    line on bulk queries) is rejected by checking that the first
    field is numeric.
    """
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 6:
        return None
    asn = parts[0]
    asn_digits = asn.lstrip("AS").strip()
    if not asn_digits or not asn_digits.split()[0].isdigit():
        return None
    return {
        "asn": "AS" + asn if not asn.startswith("AS") else asn,
        "ip": parts[1],
        "bgp_prefix": parts[2] or None,
        "country_code": (parts[3] or "").upper() or None,
        "registry": parts[4] or None,
        "allocated_at": parts[5] or None,
        # AS-name is always the last column regardless of field count.
        "as_name": parts[-1] if len(parts) >= 7 else None,
    }


async def _from_cache(ip: str) -> Optional[TeamCymruResult]:
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
    return TeamCymruResult(
        ip=d.get("ip", ip),
        success=bool(d.get("success", True)),
        asn=d.get("asn"),
        bgp_prefix=d.get("bgp_prefix"),
        country_code=d.get("country_code"),
        registry=d.get("registry"),
        allocated_at=d.get("allocated_at"),
        as_name=d.get("as_name"),
        error=d.get("error"),
        cached=True,
        raw=d.get("raw", {}),
    )


async def _store_cache(ip: str, result: TeamCymruResult) -> None:
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
                    "bgp_prefix": result.bgp_prefix,
                    "country_code": result.country_code,
                    "registry": result.registry,
                    "allocated_at": result.allocated_at,
                    "as_name": result.as_name,
                    "error": result.error,
                    "raw": result.raw,
                }),
            )
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        pass


async def _whois_query(query: str) -> str:
    """Open a TCP connection to whois.cymru.com:43, send ``query`` (must
    end with newline), read the full response, return as decoded text."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(_HOST, _PORT),
        timeout=_TIMEOUT_SECONDS,
    )
    try:
        writer.write(query.encode())
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            chunk = await asyncio.wait_for(
                reader.read(4096), timeout=_TIMEOUT_SECONDS,
            )
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode(errors="replace")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def lookup(ip: str, *, use_cache: bool = True) -> TeamCymruResult:
    """Single-IP lookup. Prefer ``lookup_bulk`` when enriching N≥3."""
    if not ip:
        return TeamCymruResult(ip=ip, success=False, error="empty ip")
    if use_cache:
        cached = await _from_cache(ip)
        if cached is not None:
            return cached

    try:
        # Note the leading space — whois.cymru.com requires it before
        # the verbose flag for single-IP queries.
        text = await _whois_query(f" -v {ip}\n")
    except Exception as exc:  # noqa: BLE001
        return TeamCymruResult(
            ip=ip, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    parsed: Optional[dict[str, str]] = None
    for line in text.splitlines():
        p = _parse_response_line(line)
        if p:
            parsed = p
            break

    if parsed is None:
        result = TeamCymruResult(
            ip=ip, success=True,  # WHOIS responded; just no ASN match
            error="no ASN match (IP may be unallocated / private)",
            raw={"response": text[:500]},
        )
        await _store_cache(ip, result)
        return result

    result = TeamCymruResult(
        ip=ip,
        success=True,
        asn=parsed.get("asn"),
        bgp_prefix=parsed.get("bgp_prefix"),
        country_code=parsed.get("country_code"),
        registry=parsed.get("registry"),
        allocated_at=parsed.get("allocated_at"),
        as_name=parsed.get("as_name"),
        raw={"response": text[:500]},
    )
    await _store_cache(ip, result)
    return result


async def lookup_bulk(
    ips: Iterable[str], *, use_cache: bool = True,
) -> dict[str, TeamCymruResult]:
    """Batched lookup. Single TCP session, all IPs in one query — the
    Cymru-recommended pattern when enriching ≥3 addresses to avoid
    being throttled / blocked.

    Returns a dict keyed by the input IP. IPs already in cache (when
    ``use_cache=True``) skip the network round-trip.
    """
    targets = [ip.strip() for ip in ips if ip and isinstance(ip, str)]
    if not targets:
        return {}

    out: dict[str, TeamCymruResult] = {}
    cache_misses: list[str] = []

    if use_cache:
        for ip in targets:
            hit = await _from_cache(ip)
            if hit is not None:
                out[ip] = hit
            else:
                cache_misses.append(ip)
    else:
        cache_misses = list(targets)

    if not cache_misses:
        return out

    query = "begin\nverbose\n" + "\n".join(cache_misses) + "\nend\n"
    try:
        text = await _whois_query(query)
    except Exception as exc:  # noqa: BLE001
        for ip in cache_misses:
            out.setdefault(ip, TeamCymruResult(
                ip=ip, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            ))
        return out

    parsed_by_ip: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        p = _parse_response_line(line)
        if p and p.get("ip"):
            parsed_by_ip[p["ip"]] = p

    for ip in cache_misses:
        p = parsed_by_ip.get(ip)
        if p is None:
            res = TeamCymruResult(
                ip=ip, success=True,
                error="no ASN match",
                raw={"bulk_response_excerpt": text[:200]},
            )
        else:
            res = TeamCymruResult(
                ip=ip,
                success=True,
                asn=p.get("asn"),
                bgp_prefix=p.get("bgp_prefix"),
                country_code=p.get("country_code"),
                registry=p.get("registry"),
                allocated_at=p.get("allocated_at"),
                as_name=p.get("as_name"),
                raw={},
            )
        await _store_cache(ip, res)
        out[ip] = res

    return out
