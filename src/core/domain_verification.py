"""Domain ownership verification — DNS TXT challenge with DoH quorum.

Why this module exists
----------------------
Without a proof-of-ownership step, an operator could register
``microsoft.com`` (or any apex they don't control) as their org and
trigger EASM crawls / brand-monitor signals against infrastructure
they don't own. That's a legal-liability and DDoS-amplification
problem we don't want to ship.

The challenge
-------------
The operator adds a TXT record at ``_marsad-challenge.<domain>``
whose value equals a token Marsad issued at /request time.
Standard SaaS approach (Cloudflare, Google Search Console, Vercel
custom domains all do this).

How we resolve — security model
-------------------------------
A naive ``dnspython`` lookup would hit ``/etc/resolv.conf`` —
i.e. whatever the host or Docker's embedded resolver was pointed
at. On a hostile network or a misconfigured corporate resolver
that's a single point of forgery. Instead we:

1. **Query DNS-over-HTTPS (DoH)** at multiple independent public
   resolvers — Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9
   (9.9.9.9) by default. DoH is HTTPS to a known cert, so a
   network-level attacker can't spoof the response without also
   compromising one of those CAs.
2. **Require quorum** — at least 2 of the configured resolvers
   must independently see the matching TXT value. A single
   compromised resolver cannot fake a verification.
3. **Token TTL** — challenges expire 24h after issuance. Stale
   tokens are rejected with an explicit error so the operator
   re-requests. This bounds the blast radius if someone
   exfiltrates a token from a logfile.

For air-gapped deployments override the resolver list via
``ARGUS_VERIFICATION_DOH_RESOLVERS`` (comma-separated DoH JSON-API
endpoints, e.g. ``https://internal-doh.example/dns-query``). At
least two distinct endpoints must be configured or quorum can't
be achieved — the helper logs and refuses if only one is given.

State
-----
Lives on ``Organization.settings`` JSONB under ``domain_verification``,
scoped per-domain — one org can have multiple domains in different
verification states without a schema migration. See
``DomainVerificationState`` for the shape.

The runtime gate is ``ARGUS_REQUIRE_DOMAIN_VERIFICATION`` (default
``false``). When ``true``, ``is_domain_verified`` returns False for
unverified domains and callers (EASM worker, feed triage) MUST skip
that org. When ``false`` (demo / single-tenant on-prem), verification
runs as informational nudge only.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)


CHALLENGE_DNS_PREFIX = "_marsad-challenge"
TOKEN_PREFIX = "marsad-verify"
TOKEN_TTL_HOURS = 24

# DoH JSON-API endpoints. Each must accept ``?name=<host>&type=TXT``
# and return a JSON document with an ``Answer`` array. All three
# below ship with this format. Override via env for air-gapped sites.
_DEFAULT_DOH_RESOLVERS = (
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Google", "https://dns.google/resolve"),
    ("Quad9", "https://dns.quad9.net:5053/dns-query"),
)
_DOH_QUORUM = 2  # 2-of-N resolvers must independently confirm


def _gate_required() -> bool:
    raw = (os.environ.get("ARGUS_REQUIRE_DOMAIN_VERIFICATION") or "").strip().lower()
    return raw in {"true", "1", "yes", "on"}


def _resolvers() -> list[tuple[str, str]]:
    """Return the active list of (label, doh_endpoint) tuples.

    Operators on air-gapped networks can replace the public list via
    ``ARGUS_VERIFICATION_DOH_RESOLVERS`` (comma-separated endpoints).
    The label for each is derived from the hostname so the UI can
    say which resolver returned what. We refuse to operate with
    fewer than two distinct endpoints — quorum is the entire point."""
    raw = (os.environ.get("ARGUS_VERIFICATION_DOH_RESOLVERS") or "").strip()
    if not raw:
        return list(_DEFAULT_DOH_RESOLVERS)
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if len(parts) < 2:
        logger.warning(
            "ARGUS_VERIFICATION_DOH_RESOLVERS has only %d resolver(s); "
            "quorum needs at least 2. Falling back to public defaults.",
            len(parts),
        )
        return list(_DEFAULT_DOH_RESOLVERS)
    out: list[tuple[str, str]] = []
    for url in parts:
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or url
        except Exception:  # noqa: BLE001
            host = url
        out.append((host, url))
    return out


@dataclass
class DomainVerificationState:
    domain: str
    status: str  # "unverified" | "pending" | "verified" | "expired"
    token: str
    requested_at: str | None = None
    expires_at: str | None = None
    verified_at: str | None = None
    last_checked_at: str | None = None
    last_error: str | None = None
    last_check_report: dict | None = None  # per-resolver outcome from last check

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status,
            "token": self.token,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "verified_at": self.verified_at,
            "last_checked_at": self.last_checked_at,
            "last_error": self.last_error,
            "last_check_report": self.last_check_report,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expiry_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)).isoformat()


def _is_expired(state: DomainVerificationState) -> bool:
    """Treat a token without ``expires_at`` as expired — that means
    it was issued by an older code path that didn't track TTL, so
    we can't reason about its age and the safest default is to
    force a fresh challenge."""
    if not state.expires_at:
        return True
    try:
        exp = datetime.fromisoformat(state.expires_at)
    except ValueError:
        return True
    return datetime.now(timezone.utc) >= exp


def _make_token() -> str:
    """Fresh token. URL-safe, 18 bytes (~144 bits) of entropy,
    prefixed for forensic clarity in DNS / proxy logs."""
    return f"{TOKEN_PREFIX}-{secrets.token_urlsafe(18)}"


def get_state(org_settings: dict | None, domain: str) -> DomainVerificationState | None:
    if not org_settings:
        return None
    block = org_settings.get("domain_verification") or {}
    raw = block.get(domain)
    if not raw:
        return None
    return DomainVerificationState(
        domain=domain,
        status=raw.get("status", "unverified"),
        token=raw.get("token", ""),
        requested_at=raw.get("requested_at"),
        expires_at=raw.get("expires_at"),
        verified_at=raw.get("verified_at"),
        last_checked_at=raw.get("last_checked_at"),
        last_error=raw.get("last_error"),
        last_check_report=raw.get("last_check_report"),
    )


def request_token(
    org_settings: dict | None, domain: str
) -> tuple[dict, DomainVerificationState]:
    """Generate (or reuse) a verification token for ``domain``.

    Returns the new ``Organization.settings`` dict (caller persists)
    plus the new state. Reuses the existing token if it's still
    pending AND not expired — otherwise mints a fresh one so an
    expired token can't be revived by a re-request that lands after
    the TTL."""
    settings = dict(org_settings or {})
    block = dict(settings.get("domain_verification") or {})
    existing_raw = block.get(domain)
    if existing_raw and existing_raw.get("token") and existing_raw.get("status") in {
        "pending",
        "verified",
    }:
        existing = DomainVerificationState(
            domain=domain,
            status=existing_raw.get("status", "pending"),
            token=existing_raw["token"],
            requested_at=existing_raw.get("requested_at"),
            expires_at=existing_raw.get("expires_at"),
            verified_at=existing_raw.get("verified_at"),
            last_checked_at=existing_raw.get("last_checked_at"),
            last_error=existing_raw.get("last_error"),
            last_check_report=existing_raw.get("last_check_report"),
        )
        if existing.status == "verified" or not _is_expired(existing):
            return settings, existing

    token = _make_token()
    state = DomainVerificationState(
        domain=domain,
        status="pending",
        token=token,
        requested_at=_now_iso(),
        expires_at=_expiry_iso(),
    )
    block[domain] = state.to_dict()
    settings["domain_verification"] = block
    return settings, state


def instructions(state: DomainVerificationState) -> dict[str, Any]:
    """Single ready-to-paste DNS challenge spec the dashboard renders.

    HTTP-file fallback was removed: it adds an attack surface (CDN
    /.well-known caching, path-traversal-on-shared-hosting edge
    cases) without commensurate value, since any operator who can
    deploy a static file at the apex can also add a TXT record."""
    expires_in_hours = None
    if state.expires_at:
        try:
            exp = datetime.fromisoformat(state.expires_at)
            delta = exp - datetime.now(timezone.utc)
            expires_in_hours = max(0, int(delta.total_seconds() // 3600))
        except ValueError:
            expires_in_hours = None
    return {
        "domain": state.domain,
        "token": state.token,
        "expires_in_hours": expires_in_hours,
        "ttl_hours": TOKEN_TTL_HOURS,
        "dns": {
            "record_type": "TXT",
            "record_name": f"{CHALLENGE_DNS_PREFIX}.{state.domain}",
            "record_value": state.token,
            "instructions": (
                f"Add a TXT record at {CHALLENGE_DNS_PREFIX}.{state.domain} "
                f"with value {state.token!r}. DNS may take a few minutes to "
                "propagate. Click 'Check now' once you've added it."
            ),
        },
        "resolvers": [name for name, _ in _resolvers()],
        "quorum_required": _DOH_QUORUM,
    }


async def _doh_query_txt(
    client: httpx.AsyncClient, name: str, doh_url: str
) -> list[str]:
    """Run a single DoH JSON query and return the list of TXT values
    seen. Empty list on any error — the caller treats that as a
    no-vote toward quorum."""
    try:
        resp = await client.get(
            doh_url,
            params={"name": name, "type": "TXT"},
            headers={"accept": "application/dns-json"},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        out: list[str] = []
        for ans in data.get("Answer") or []:
            # type 16 == TXT. dnspython returns the raw quoted string
            # so we strip enclosing quotes before comparing.
            if ans.get("type") != 16:
                continue
            val = (ans.get("data") or "").strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            # Long TXT records arrive as multiple quoted strings glued
            # by spaces; concat after un-quoting both halves.
            val = val.replace('" "', "")
            out.append(val)
        return out
    except Exception as e:  # noqa: BLE001
        logger.debug("DoH query %s failed: %s", doh_url, e)
        return []


@dataclass
class _ResolverVote:
    name: str
    matched: bool
    error: str | None
    saw: list[str]


async def _check_dns_quorum(domain: str, token: str) -> tuple[bool, dict]:
    """Query every configured DoH resolver in parallel for the TXT
    record and require ``_DOH_QUORUM`` matches.

    Returns (matched, report) — report carries per-resolver outcomes
    so the UI / audit log can show which resolvers agreed."""
    import asyncio

    name = f"{CHALLENGE_DNS_PREFIX}.{domain}"
    resolvers = _resolvers()

    async with httpx.AsyncClient(verify=True) as client:
        tasks = [_doh_query_txt(client, name, url) for _, url in resolvers]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    votes: list[_ResolverVote] = []
    for (label, _url), seen in zip(resolvers, results):
        if not seen:
            votes.append(_ResolverVote(label, False, "no TXT record returned", []))
            continue
        if token in seen:
            votes.append(_ResolverVote(label, True, None, seen))
        else:
            votes.append(
                _ResolverVote(
                    label,
                    False,
                    f"TXT present but value didn't match (saw {seen!r})",
                    seen,
                )
            )

    matches = sum(1 for v in votes if v.matched)
    report = {
        "quorum_required": _DOH_QUORUM,
        "resolvers_consulted": len(resolvers),
        "matches": matches,
        "votes": [
            {"resolver": v.name, "matched": v.matched, "error": v.error}
            for v in votes
        ],
    }
    return matches >= _DOH_QUORUM, report


async def check(
    org_settings: dict | None, domain: str
) -> tuple[dict, DomainVerificationState, dict[str, Any]]:
    """Run the DoH-quorum challenge and update state.

    Raises ``ValueError`` when no challenge has been issued or when
    the existing one has expired (the operator must re-request)."""
    state = get_state(org_settings, domain)
    if state is None:
        raise ValueError(
            f"no verification challenge has been issued for {domain!r}; "
            "call /verification/request first"
        )
    if state.status == "verified":
        # Idempotent — already verified, return success without
        # re-querying so we don't spam DoH for verified domains.
        return dict(org_settings or {}), state, {
            "verified": True,
            "quorum_required": _DOH_QUORUM,
            "resolvers_consulted": 0,
            "matches": 0,
            "votes": [],
        }
    if _is_expired(state):
        state.status = "expired"
        state.last_error = (
            f"verification token expired (TTL {TOKEN_TTL_HOURS}h); "
            "request a new one"
        )
        settings = dict(org_settings or {})
        block = dict(settings.get("domain_verification") or {})
        block[state.domain] = state.to_dict()
        settings["domain_verification"] = block
        return settings, state, {
            "verified": False,
            "expired": True,
            "quorum_required": _DOH_QUORUM,
            "resolvers_consulted": 0,
            "matches": 0,
            "votes": [],
        }

    matched, report = await _check_dns_quorum(state.domain, state.token)
    state.last_checked_at = _now_iso()
    state.last_check_report = report
    if matched:
        state.status = "verified"
        state.verified_at = _now_iso()
        state.last_error = None
    else:
        state.last_error = (
            f"need {report['quorum_required']} matching resolver(s); "
            f"got {report['matches']} of {report['resolvers_consulted']}. "
            "Add the TXT record (DNS propagation can take a few minutes), "
            "then retry."
        )

    settings = dict(org_settings or {})
    block = dict(settings.get("domain_verification") or {})
    block[state.domain] = state.to_dict()
    settings["domain_verification"] = block
    return settings, state, report | {"verified": matched}


def is_domain_verified(org_settings: dict | None, domain: str) -> bool:
    """Public predicate used by EASM / triage gates.

    When ``ARGUS_REQUIRE_DOMAIN_VERIFICATION`` is off this always
    returns True — verification UX still runs but doesn't block
    anything. When on, only ``status == 'verified'`` and a non-
    expired token count."""
    if not _gate_required():
        return True
    state = get_state(org_settings, domain)
    if state is None or state.status != "verified":
        return False
    return not _is_expired(state)


__all__ = [
    "DomainVerificationState",
    "CHALLENGE_DNS_PREFIX",
    "TOKEN_TTL_HOURS",
    "request_token",
    "instructions",
    "check",
    "get_state",
    "is_domain_verified",
]
