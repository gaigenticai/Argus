"""Brand-protection scanner.

Given an organization with one or more :class:`BrandTerm` rows, generate
typosquat permutations for each apex domain term and check whether each
permutation actually exists. Persist hits as :class:`SuspectDomain`
rows.

Resolution can be plugged at runtime — production uses a real DNS
resolver; tests inject a fake that returns canned results.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

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

from .permutations import (
    Permutation,
    domain_similarity,
    generate_permutations,
)


_logger = logging.getLogger(__name__)


@dataclass
class ResolutionResult:
    domain: str
    is_resolvable: bool
    a_records: list[str]
    mx_records: list[str]
    nameservers: list[str]
    # Audit C4 — distinguish "DNS resolver healthy and the name didn't
    # resolve" (the normal case for a typo) from "DNS resolver itself
    # was broken / unavailable" (operational issue we must surface).
    resolver_error: str | None = None


# A resolver function takes a list of domains and yields ResolutionResult
Resolver = Callable[[list[str]], Awaitable[list[ResolutionResult]]]


async def default_resolver(domains: list[str]) -> list[ResolutionResult]:
    """Resolve domains with dnspython. Returns one entry per input domain.

    Domains that don't resolve produce ``is_resolvable=False``. Domains
    where the resolver itself failed (timeout, no nameservers reachable)
    carry ``resolver_error`` so callers can flag a real DNS outage
    instead of silently treating every typo as "not registered."
    """
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
    except ImportError:
        return [
            ResolutionResult(
                d, False, [], [], [],
                resolver_error="dnspython not installed",
            )
            for d in domains
        ]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    async def _one(d: str) -> ResolutionResult:
        operational_error: str | None = None

        async def _resolve(rtype: str) -> list[str]:
            nonlocal operational_error
            try:
                ans = await asyncio.to_thread(
                    resolver.resolve, d, rtype, raise_on_no_answer=False
                )
                return [r.to_text().strip('"') for r in ans]
            except dns.resolver.NXDOMAIN:
                # Real "this name doesn't exist" answer — not an error.
                return []
            except dns.resolver.NoAnswer:
                return []
            except (
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
                dns.resolver.LifetimeTimeout,
            ) as e:
                operational_error = (
                    operational_error or f"{rtype}: {type(e).__name__}: {e}"
                )
                return []
            except Exception as e:  # noqa: BLE001
                operational_error = operational_error or f"{rtype}: {e}"
                return []

        a = await _resolve("A")
        mx = await _resolve("MX")
        ns = await _resolve("NS")
        return ResolutionResult(
            d, bool(a or mx or ns), a, mx, ns,
            resolver_error=operational_error,
        )

    return await asyncio.gather(*[_one(d) for d in domains])


@dataclass
class ScanReport:
    organization_id: uuid.UUID
    terms_scanned: int
    permutations_generated: int
    candidates_resolved: int
    suspects_created: int
    suspects_seen_again: int
    # Audit C4 — count of domains where the resolver itself was sick.
    # Non-zero on a healthy run almost always means upstream DNS is
    # broken; the dashboard should render this as a banner rather than
    # let the analyst mistake "no typosquats" for "scanner ran clean".
    resolver_errors: int = 0


async def scan_organization(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    resolver: Resolver | None = None,
    max_permutations_per_term: int = 200,
    only_resolvable: bool = True,
) -> ScanReport:
    resolver = resolver or default_resolver

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

    apex_terms = [t for t in terms if t.kind == BrandTermKind.APEX_DOMAIN.value]

    # Pull the customer's subsidiary allowlist once. We exclude any
    # permutation that exactly matches an allowlisted domain, and any
    # permutation whose registrable label matches an allowlisted brand
    # name. This is the brand-protection equivalent of "do not flag
    # the customer's own assets as typosquats" — the single biggest
    # source of false-positive noise in CTM360-class products.
    from src.models.admin import AllowlistKind, SubsidiaryAllowlist

    allowlist_rows = (
        await db.execute(
            select(SubsidiaryAllowlist).where(
                SubsidiaryAllowlist.organization_id == organization_id
            )
        )
    ).scalars().all()
    allowed_domains = {
        r.value.strip().lower()
        for r in allowlist_rows
        if r.kind in (AllowlistKind.DOMAIN.value, AllowlistKind.EMAIL_DOMAIN.value)
    }
    allowed_brand_names = {
        r.value.strip().lower()
        for r in allowlist_rows
        if r.kind == AllowlistKind.BRAND_NAME.value
    }

    permutations: list[tuple[BrandTerm, Permutation]] = []
    for term in apex_terms:
        for p in generate_permutations(
            term.value, max_per_kind=max_permutations_per_term
        ):
            domain_lower = p.domain.lower()
            if domain_lower in allowed_domains:
                continue
            # Strip TLD for brand-name overlap check
            label = domain_lower.split(".", 1)[0]
            if label in allowed_brand_names:
                continue
            permutations.append((term, p))

    if not permutations:
        return ScanReport(
            organization_id=organization_id,
            terms_scanned=len(terms),
            permutations_generated=0,
            candidates_resolved=0,
            suspects_created=0,
            suspects_seen_again=0,
        )

    domains = [p.domain for _, p in permutations]
    resolutions = await resolver(domains)
    res_by_domain = {r.domain: r for r in resolutions}

    now = datetime.now(timezone.utc)
    created = 0
    bumped = 0

    for term, perm in permutations:
        res = res_by_domain.get(perm.domain)
        if res is None:
            continue
        if only_resolvable and not res.is_resolvable:
            continue

        existing = (
            await db.execute(
                select(SuspectDomain).where(
                    and_(
                        SuspectDomain.organization_id == organization_id,
                        SuspectDomain.domain == perm.domain,
                        SuspectDomain.matched_term_value == term.value,
                    )
                )
            )
        ).scalar_one_or_none()
        sim = domain_similarity(term.value, perm.domain)

        if existing is not None:
            existing.last_seen_at = now
            existing.is_resolvable = res.is_resolvable
            existing.a_records = res.a_records
            existing.mx_records = res.mx_records
            existing.nameservers = res.nameservers
            existing.similarity = max(existing.similarity, sim)
            bumped += 1
            continue

        suspect = SuspectDomain(
            organization_id=organization_id,
            domain=perm.domain,
            matched_term_id=term.id,
            matched_term_value=term.value,
            similarity=sim,
            permutation_kind=perm.kind,
            is_resolvable=res.is_resolvable,
            a_records=res.a_records,
            mx_records=res.mx_records,
            nameservers=res.nameservers,
            first_seen_at=now,
            last_seen_at=now,
            state=SuspectDomainState.OPEN.value,
            source=SuspectDomainSource.DNSTWIST.value,
            raw={"permutation": perm.kind, "term_id": str(term.id)},
        )
        db.add(suspect)
        try:
            await db.flush()
            created += 1
        except IntegrityError:
            await db.rollback()
            continue

        # Audit D12 + D13 — resolvable look-alikes are the highest-
        # value brand-protection signal. Resolvable+high-similarity
        # → HIGH (auto-case + page); merely typosquat → MEDIUM
        # (notification only).
        try:
            from src.cases.auto_link import auto_link_finding

            sev = (
                "high"
                if (res.is_resolvable and sim >= 0.8)
                else "medium"
            )
            await auto_link_finding(
                db,
                organization_id=organization_id,
                finding_type="suspect_domain",
                finding_id=suspect.id,
                severity=sev,
                title=f"Suspect domain {perm.domain} (looks like {term.value})",
                summary=(
                    f"Permutation kind={perm.kind}, similarity={sim:.2f}, "
                    f"resolvable={res.is_resolvable}"
                ),
                event_kind="phishing_detection",
                dedup_key=f"suspect_domain:{perm.domain}",
                tags=("suspect_domain", perm.kind),
            )
        except Exception:  # noqa: BLE001
            import logging as _logging
            _logging.getLogger(__name__).exception(
                "auto_link_finding failed for suspect_domain %s", suspect.id
            )

        # Brand Defender agent — queue an agentic run for high-similarity
        # suspects so the dashboard surfaces a recommendation by the time
        # the analyst opens it. Best-effort: never block the scanner
        # commit on it.
        try:
            from src.agents.brand_defender_agent import maybe_queue_brand_defence

            await maybe_queue_brand_defence(db, suspect)
        except Exception as _exc:  # noqa: BLE001
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "brand-defender queue failed for %s: %s", suspect.id, _exc
            )

    resolver_errors = sum(1 for r in resolutions if r.resolver_error)
    if resolver_errors:
        _logger.warning(
            "brand scan: %d/%d resolutions reported a resolver error — "
            "DNS pipeline may be degraded",
            resolver_errors, len(resolutions),
        )
    return ScanReport(
        organization_id=organization_id,
        terms_scanned=len(terms),
        permutations_generated=len(permutations),
        candidates_resolved=sum(1 for r in resolutions if r.is_resolvable),
        suspects_created=created,
        suspects_seen_again=bumped,
        resolver_errors=resolver_errors,
    )


__all__ = [
    "ResolutionResult",
    "ScanReport",
    "default_resolver",
    "scan_organization",
]
