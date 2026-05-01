"""CIRCL public-API IOC enrichment (P2 #2.8).

Three free CIRCL services wrapped as async helpers and exposed as
enrichment providers on the IOC detail page + ``investigation_agent``:

  hashlookup      https://hashlookup.circl.lu/
                  Anonymous. POST a hash, get
                  known-good / known-bad / unknown classification.
                  Public NSRL + curated CIRCL data.

  Passive DNS     https://www.circl.lu/services/passive-dns/
                  Free with registration. Domain → historical
                  resolution records (rrname, rrtype, rdata,
                  time_first / time_last).
                  Auth: HTTP Basic via ARGUS_CIRCL_USERNAME / _PASSWORD.

  Passive SSL     https://www.circl.lu/services/passive-ssl/
                  Free with registration. IP → cert history. Same
                  auth as Passive DNS.

All outbound calls are gated by ``src.core.http_circuit.get_breaker``
so a CIRCL outage doesn't tar-pit the rest of the enrichment pipeline.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

logger = logging.getLogger(__name__)


# ── Endpoints ────────────────────────────────────────────────────────


_HASHLOOKUP_URL = "https://hashlookup.circl.lu/lookup"
_PDNS_URL = "https://www.circl.lu/pdns/query"
_PASSIVE_SSL_URL = "https://www.circl.lu/v2pssl/query"

# Anonymous calls are fine for hashlookup; pDNS + Passive SSL require
# the operator to sign up and stash credentials in these env vars. The
# wrappers return ``None`` (configured but no-op) when creds are absent
# rather than failing the whole enrichment chain.
_USERNAME_ENV = "ARGUS_CIRCL_USERNAME"
_PASSWORD_ENV = "ARGUS_CIRCL_PASSWORD"


# ── Result types ─────────────────────────────────────────────────────


@dataclass
class HashlookupResult:
    hash: str
    hash_kind: str  # "sha1" | "md5" | "sha256"
    known: bool
    classification: str  # "known-good" | "known-bad" | "unknown"
    source: str
    raw: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash": self.hash, "hash_kind": self.hash_kind,
            "known": self.known, "classification": self.classification,
            "source": self.source, "raw": self.raw,
        }


@dataclass
class PdnsRecord:
    rrname: str
    rrtype: str
    rdata: str
    time_first: int | None
    time_last: int | None
    count: int | None
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rrname": self.rrname, "rrtype": self.rrtype,
            "rdata": self.rdata, "time_first": self.time_first,
            "time_last": self.time_last, "count": self.count,
            "source": self.source,
        }


@dataclass
class PassiveSslCert:
    fingerprint_sha1: str
    subject: str | None
    issuer: str | None
    not_before: str | None
    not_after: str | None
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint_sha1": self.fingerprint_sha1,
            "subject": self.subject, "issuer": self.issuer,
            "not_before": self.not_before, "not_after": self.not_after,
            "source": self.source,
        }


# ── Helpers ──────────────────────────────────────────────────────────


def _credentials() -> aiohttp.BasicAuth | None:
    user = os.environ.get(_USERNAME_ENV, "").strip()
    pw = os.environ.get(_PASSWORD_ENV, "").strip()
    if not (user and pw):
        return None
    return aiohttp.BasicAuth(user, pw)


def _detect_hash_kind(h: str) -> str | None:
    h = (h or "").strip()
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))


# ── hashlookup ───────────────────────────────────────────────────────


async def hashlookup(file_hash: str) -> HashlookupResult | None:
    """Classify a file hash via CIRCL hashlookup.

    Returns ``None`` if the hash isn't a recognised md5/sha1/sha256
    digest. For unknown hashes the API returns 404 and we surface a
    ``classification='unknown'`` result rather than ``None`` so the
    UI distinguishes "we asked CIRCL and they said no" from "we
    didn't ask".
    """
    kind = _detect_hash_kind(file_hash)
    if kind is None:
        return None

    breaker = get_breaker("circl:hashlookup")
    timeout = aiohttp.ClientTimeout(total=15)
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(
                    f"{_HASHLOOKUP_URL}/{kind}/{file_hash.lower()}",
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status == 404:
                        return HashlookupResult(
                            hash=file_hash, hash_kind=kind,
                            known=False, classification="unknown",
                            source="circl_hashlookup", raw={},
                        )
                    resp.raise_for_status()
                    data = await resp.json()
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        logger.warning("[circl_hashlookup] %s", exc)
        return None

    classification = "known-good" if data.get("KnownMalicious") in (None, False) \
        else "known-bad"
    if data.get("KnownMalicious"):
        classification = "known-bad"
    return HashlookupResult(
        hash=file_hash, hash_kind=kind,
        known=True, classification=classification,
        source="circl_hashlookup", raw=data,
    )


# ── Passive DNS ──────────────────────────────────────────────────────


async def pdns_query(domain: str, *, limit: int = 50) -> list[PdnsRecord]:
    """CIRCL Passive DNS query. Returns historical resolution records."""
    creds = _credentials()
    if creds is None:
        logger.info("[circl_pdns] credentials not configured; skipping")
        return []
    breaker = get_breaker("circl:pdns")
    timeout = aiohttp.ClientTimeout(total=30)
    out: list[PdnsRecord] = []
    try:
        async with breaker:
            async with aiohttp.ClientSession(
                timeout=timeout, auth=creds,
            ) as http:
                async with http.get(
                    f"{_PDNS_URL}/{domain}",
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status == 404:
                        return []
                    resp.raise_for_status()
                    text = await resp.text()
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        logger.warning("[circl_pdns] %s", exc)
        return []

    # CIRCL's pDNS endpoint returns one JSON object per line (NDJSON).
    import json
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        out.append(PdnsRecord(
            rrname=row.get("rrname") or "",
            rrtype=row.get("rrtype") or "",
            rdata=str(row.get("rdata") or ""),
            time_first=row.get("time_first"),
            time_last=row.get("time_last"),
            count=row.get("count"),
            source="circl_pdns",
        ))
        if len(out) >= limit:
            break
    return out


# ── Passive SSL ──────────────────────────────────────────────────────


async def passive_ssl_query(ip: str) -> list[PassiveSslCert]:
    """CIRCL Passive SSL — return cert history for an IP."""
    creds = _credentials()
    if creds is None:
        logger.info("[circl_passive_ssl] credentials not configured; skipping")
        return []
    breaker = get_breaker("circl:passive_ssl")
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with breaker:
            async with aiohttp.ClientSession(
                timeout=timeout, auth=creds,
            ) as http:
                async with http.get(
                    f"{_PASSIVE_SSL_URL}/{ip}",
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status == 404:
                        return []
                    resp.raise_for_status()
                    data = await resp.json()
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        logger.warning("[circl_passive_ssl] %s", exc)
        return []

    out: list[PassiveSslCert] = []
    certs = data.get("certificates") or data.get("hashes") or []
    if isinstance(certs, dict):
        certs = list(certs.values())
    for c in certs:
        if not isinstance(c, dict):
            continue
        out.append(PassiveSslCert(
            fingerprint_sha1=(c.get("hash") or c.get("sha1") or "").lower(),
            subject=c.get("subject"),
            issuer=c.get("issuer"),
            not_before=c.get("not_before"),
            not_after=c.get("not_after"),
            source="circl_passive_ssl",
        ))
    return out
