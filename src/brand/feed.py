"""Newly-registered domain feed processor (Phase 3.2).

Consumes a stream of "domain just appeared" events from any source and
checks each candidate against an organization's :class:`BrandTerm` list.
Hits land in ``suspect_domains`` exactly the same way Phase 3.1's typo-
squat scanner does — single source of truth.

Sources
-------
    certstream    Certificate Transparency WebSocket feed (live).
    whoisds       Daily list of newly-registered domains downloaded as
                  a plain-text or zip file.
    manual        Analyst paste-in for ad-hoc checks.

Matching
--------
    apex_domain term  → Levenshtein similarity against the candidate's
                        whole label (excluding TLD).
    name term         → substring + token match: candidate label or
                        any subdomain piece *contains* the brand name.
                        Similarity is the longest-shared-token ratio.
    others            → ignored at feed time (used by other phases).
"""

from __future__ import annotations

import asyncio
import gzip
import io
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AsyncIterator, Iterable

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.brand import (
    BrandTerm,
    BrandTermKind,
    SuspectDomain,
    SuspectDomainSource,
    SuspectDomainState,
)

from .permutations import domain_similarity


_DOMAIN_SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")


def _split_label(domain: str) -> tuple[str, str]:
    """Split into (label, tld). label is the part before the last dot."""
    domain = domain.lower().rstrip(".")
    if "." not in domain:
        return domain, ""
    label, _, tld = domain.rpartition(".")
    return label, tld


def _label_no_subdomain(domain: str) -> str:
    """Take the registrable label (between last two dots, ignoring TLD)."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


@dataclass
class Match:
    domain: str
    term: BrandTerm
    similarity: float
    permutation_kind: str


_NAME_MIN_TOKEN_LEN = 3


def _name_match(candidate: str, brand_name: str) -> tuple[bool, float, str]:
    """Substring match for a name term.

    A candidate "argus-banking.com" matches brand "argus" with similarity
    based on len(brand) / len(candidate-label). Excludes very-short
    brand names (< 3 chars) to avoid false positives.
    """
    name = brand_name.lower().strip()
    if len(name) < _NAME_MIN_TOKEN_LEN:
        return False, 0.0, "name_short_brand"
    cand_label = _label_no_subdomain(candidate)
    if name not in cand_label:
        # Token-level: split on punctuation and check.
        tokens = re.split(r"[\-._]+", cand_label)
        if name not in tokens:
            return False, 0.0, ""
        kind = "name_token"
    else:
        kind = "name_substring" if name != cand_label else "name_exact"
    similarity = len(name) / max(len(cand_label), 1)
    similarity = min(1.0, similarity)
    return True, similarity, kind


def match_domains(
    candidates: Iterable[str], terms: Iterable[BrandTerm], *, min_similarity: float = 0.7
) -> list[Match]:
    """Pure-function matcher: candidate domains × brand terms → matches."""
    by_kind = {
        BrandTermKind.APEX_DOMAIN.value: [],
        BrandTermKind.NAME.value: [],
        BrandTermKind.PRODUCT.value: [],
    }
    for t in terms:
        by_kind.setdefault(t.kind, []).append(t)

    out: list[Match] = []
    seen: set[tuple[str, str]] = set()  # (domain, term_value) dedup

    for raw in candidates:
        if not raw:
            continue
        candidate = raw.strip().lower().rstrip(".")
        if not _DOMAIN_SAFE_RE.match(candidate):
            continue

        for term in by_kind.get(BrandTermKind.APEX_DOMAIN.value, []):
            sim = domain_similarity(term.value, candidate)
            if sim >= min_similarity:
                key = (candidate, term.value)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Match(
                        domain=candidate,
                        term=term,
                        similarity=sim,
                        permutation_kind="feed_apex_match",
                    )
                )

        for term in (
            by_kind.get(BrandTermKind.NAME.value, [])
            + by_kind.get(BrandTermKind.PRODUCT.value, [])
        ):
            ok, sim, kind = _name_match(candidate, term.value)
            if ok and sim >= 0.0:  # any name hit counts; threshold == 0 here
                key = (candidate, term.value)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Match(
                        domain=candidate,
                        term=term,
                        similarity=sim,
                        permutation_kind=kind,
                    )
                )

    return out


@dataclass
class IngestReport:
    candidates: int
    matches: int
    suspects_created: int
    suspects_seen_again: int
    skipped_invalid: int


async def ingest_candidates(
    db: AsyncSession,
    organization_id,
    candidates: Iterable[str],
    *,
    source: SuspectDomainSource = SuspectDomainSource.CERTSTREAM,
    min_similarity: float | None = None,
) -> IngestReport:
    """Run a batch of newly-seen domains against this org's brand terms,
    persist matches as ``SuspectDomain`` rows. Idempotent.

    ``min_similarity`` defaults to the live
    ``brand.domain_match_min_similarity`` AppSetting (0.7 in code).
    """
    candidates = list(candidates)
    if not candidates:
        return IngestReport(0, 0, 0, 0, 0)

    if min_similarity is None:
        from src.core.detector_config import load_brand_thresholds

        thresholds = await load_brand_thresholds(db, organization_id)
        min_similarity = thresholds.domain_match_min_similarity

    skipped_invalid = sum(
        1 for c in candidates if not c or not _DOMAIN_SAFE_RE.match(c.strip().lower().rstrip("."))
    )

    terms = (
        await db.execute(
            select(BrandTerm).where(
                and_(
                    BrandTerm.organization_id == organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()

    if not terms:
        return IngestReport(
            candidates=len(candidates),
            matches=0,
            suspects_created=0,
            suspects_seen_again=0,
            skipped_invalid=skipped_invalid,
        )

    matches = match_domains(candidates, terms, min_similarity=min_similarity)
    now = datetime.now(timezone.utc)
    created = 0
    bumped = 0

    for m in matches:
        existing = (
            await db.execute(
                select(SuspectDomain).where(
                    and_(
                        SuspectDomain.organization_id == organization_id,
                        SuspectDomain.domain == m.domain,
                        SuspectDomain.matched_term_value == m.term.value,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.last_seen_at = now
            existing.similarity = max(existing.similarity, m.similarity)
            bumped += 1
            continue
        suspect = SuspectDomain(
            organization_id=organization_id,
            domain=m.domain,
            matched_term_id=m.term.id,
            matched_term_value=m.term.value,
            similarity=m.similarity,
            permutation_kind=m.permutation_kind,
            is_resolvable=None,
            a_records=[],
            mx_records=[],
            nameservers=[],
            first_seen_at=now,
            last_seen_at=now,
            state=SuspectDomainState.OPEN.value,
            source=source.value,
            raw={"feed_source": source.value},
        )
        db.add(suspect)
        try:
            await db.flush()
            created += 1
        except IntegrityError:
            await db.rollback()
            continue

        # Brand Defender — queue agentic triage for high-sim suspects.
        # Best-effort; feed ingest never fails because of agent queue.
        try:
            from src.agents.brand_defender_agent import maybe_queue_brand_defence

            await maybe_queue_brand_defence(db, suspect)
        except Exception as _exc:  # noqa: BLE001
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "brand-defender queue failed for %s: %s", suspect.id, _exc
            )

    return IngestReport(
        candidates=len(candidates),
        matches=len(matches),
        suspects_created=created,
        suspects_seen_again=bumped,
        skipped_invalid=skipped_invalid,
    )


# --- WhoisDS daily-list parser -----------------------------------------


def parse_whoisds_blob(blob: bytes) -> list[str]:
    """Accept the WhoisDS daily list as plain-text, gzip, or zip.

    Returns a deduplicated, lowercased list of domains.
    """
    text: str
    if blob[:2] == b"\x1f\x8b":
        text = gzip.decompress(blob).decode("utf-8", errors="replace")
    elif blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for name in z.namelist():
                if name.lower().endswith((".txt", ".csv", ".tsv")):
                    text = z.read(name).decode("utf-8", errors="replace")
                    break
            else:
                raise ValueError("zip archive contains no .txt entry")
    else:
        text = blob.decode("utf-8", errors="replace")

    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip().lower().rstrip(".")
        if not line or line.startswith("#"):
            continue
        # Some lists have CSV-style "domain,date" — split on comma/tab.
        domain = re.split(r"[,\t]", line)[0].strip()
        if _DOMAIN_SAFE_RE.match(domain):
            out.add(domain)
    return sorted(out)


# --- CertStream consumer ------------------------------------------------


async def certstream_iter_messages(
    url: str = "wss://certstream.calidog.io/",
    *,
    timeout: float = 60,
) -> AsyncIterator[dict]:
    """Yield messages from the public CertStream feed.

    Tests do not use this helper; production wires it into a long-running
    daemon that feeds ingest_candidates() as messages arrive.

    Adversarial audit D-25 — CertStream is an unauthenticated public
    feed. A compromised upstream could blast oversized JSON to OOM the
    worker. Cap each message at 1 MiB and skip anything that doesn't
    parse / doesn't match the certstream message shape.
    """
    import aiohttp

    _MAX_MSG_BYTES = 1 * 1024 * 1024

    timeout_cfg = aiohttp.ClientTimeout(total=None, sock_read=timeout)
    async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
        async with sess.ws_connect(url, heartbeat=30, max_msg_size=_MAX_MSG_BYTES) as ws:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    raw = msg.data or ""
                    if len(raw) > _MAX_MSG_BYTES:
                        continue
                    try:
                        parsed = msg.json()
                    except Exception:  # noqa: BLE001
                        continue
                    if not isinstance(parsed, dict):
                        continue
                    # Drop anything that isn't a recognised certstream
                    # frame (heartbeats are fine — they pass through and
                    # downstream filters them on message_type).
                    if "message_type" not in parsed:
                        continue
                    yield parsed
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break


def domains_from_certstream_message(msg: dict) -> list[str]:
    """Extract registrable domains from a CertStream payload."""
    if msg.get("message_type") != "certificate_update":
        return []
    leaf = (msg.get("data") or {}).get("leaf_cert") or {}
    return [
        d.lower().lstrip("*.").rstrip(".")
        for d in (leaf.get("all_domains") or [])
        if d
    ]


__all__ = [
    "Match",
    "IngestReport",
    "match_domains",
    "ingest_candidates",
    "parse_whoisds_blob",
    "certstream_iter_messages",
    "domains_from_certstream_message",
]
