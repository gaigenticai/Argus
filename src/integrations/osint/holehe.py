"""Holehe wrapper — "where is this email registered?" exposure surface.

Holehe (https://github.com/megadose/holehe) ships ~120 site-specific
checkers. Each takes an email + an httpx client and reports whether
an account with that email exists on the target service. No password
needed; relies on the site's "forgot-password / sign-up" flows
revealing existence via response shape.

Why this matters next to a breach provider:

  - HudsonRock Cavalier answers "was this credential leaked?"
  - Holehe answers "where is this email REGISTERED at all?" — the
    raw exposure surface, regardless of whether anything's leaked.
  - For a target like ``ceo@enbd.com`` a Holehe pass might surface
    "registered on Spotify, Adobe, GitHub, LinkedIn, Twitter" —
    each one a separate phishing target + breach risk.

Operational notes:

  - Holehe modules occasionally break when sites change response
    shapes. We tolerate per-checker failures (treat as "unknown")
    and never fail the whole call on a single bad checker.
  - Bounded concurrency (``MAX_CONCURRENT_CHECKERS``) so a single
    lookup doesn't fan out to 120 simultaneous outbound requests
    and trip the egress rate limit / WAFs that flag scan patterns.
  - We curate a high-signal subset by default. The full module set
    is selectable via ``check_email(..., full=True)``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Curated subset — high-signal services for enterprise threat-intel.
# The full holehe corpus is ~120 modules; running them all on every
# lookup is slow and noisy. This list focuses on services where
# "this email is registered" is genuinely informative for an analyst:
# major dev/identity platforms, social, file-sharing, e-commerce,
# corporate-collab, banking-adjacent.
_CURATED_MODULES = (
    "adobe", "amazon", "anydo", "atlassian", "bitmoji", "codecademy",
    "coroflot", "dailymotion", "deezer", "discord", "ebay", "evernote",
    "eventbrite", "firefox", "garmin", "github", "gitlab", "gravatar",
    "imgur", "instagram", "lastpass", "lichess", "linkedin", "mail_ru",
    "mailchimp", "microsoft", "myspace", "nike", "office365",
    "patreon", "pinterest", "plurk", "protonmail", "rambler",
    "redbubble", "reddit", "samsung", "seoclerks", "sevencups",
    "smule", "snapchat", "spotify", "strava", "tellonym", "tumblr",
    "twitter", "venmo", "vrbo", "vsco", "xnxx", "xvideos", "yandex",
    "zoho",
)

MAX_CONCURRENT_CHECKERS = 16
HTTP_TIMEOUT_S = 8.0


@dataclass
class HoleheHit:
    """One service-checker result, normalised across holehe's variations."""
    service: str
    domain: Optional[str] = None
    exists: bool = False
    rate_limited: bool = False
    error: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class HoleheReport:
    email: str
    services_checked: int
    hits: list[HoleheHit]
    duration_ms: int
    error: Optional[str] = None

    @property
    def total_exists(self) -> int:
        return sum(1 for h in self.hits if h.exists)

    @property
    def total_rate_limited(self) -> int:
        return sum(1 for h in self.hits if h.rate_limited)

    @property
    def total_errors(self) -> int:
        return sum(1 for h in self.hits if h.error)

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "services_checked": self.services_checked,
            "duration_ms": self.duration_ms,
            "totals": {
                "exists": self.total_exists,
                "rate_limited": self.total_rate_limited,
                "errors": self.total_errors,
            },
            "hits": [
                {
                    "service": h.service,
                    "domain": h.domain,
                    "exists": h.exists,
                    "rate_limited": h.rate_limited,
                    "error": h.error,
                }
                for h in self.hits
            ],
            "error": self.error,
        }


def _import_modules(only: tuple[str, ...] | None) -> list[Any]:
    """Pull the holehe checker callables. Filtered to ``only`` when
    set. Wrapped so a missing package fails clean instead of crashing
    the import."""
    try:
        from holehe.core import get_functions, import_submodules
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(
            f"holehe not installed in this image: {type(e).__name__}: {e}. "
            "Add `holehe>=1.61` to requirements.txt and rebuild."
        ) from e
    modules = import_submodules("holehe.modules")
    funcs = get_functions(modules)
    if only is None:
        return list(funcs)
    name_set = {n.lower() for n in only}
    out = []
    for fn in funcs:
        # holehe modules are functions named after the service.
        # Their __name__ is the bare service name.
        if (fn.__name__ or "").lower() in name_set:
            out.append(fn)
    return out


async def check_email(
    email: str, *, full: bool = False,
    timeout_s: float = HTTP_TIMEOUT_S,
    max_concurrent: int = MAX_CONCURRENT_CHECKERS,
) -> HoleheReport:
    """Run holehe checkers against an email and return a normalised
    report. Per-checker failures are isolated and surfaced as
    ``error`` on individual hits, never raised."""
    import time as _time

    if not email or "@" not in email:
        return HoleheReport(
            email=email or "", services_checked=0, hits=[], duration_ms=0,
            error="empty or malformed email",
        )

    try:
        import httpx  # holehe expects an httpx.AsyncClient
    except Exception as e:  # noqa: BLE001
        return HoleheReport(
            email=email, services_checked=0, hits=[], duration_ms=0,
            error=f"httpx not installed: {e}",
        )

    try:
        funcs = _import_modules(None if full else _CURATED_MODULES)
    except Exception as e:  # noqa: BLE001
        return HoleheReport(
            email=email, services_checked=0, hits=[], duration_ms=0,
            error=str(e),
        )

    sem = asyncio.Semaphore(max_concurrent)
    results: list[dict[str, Any]] = []
    started = _time.monotonic()

    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
        async def _run_one(fn):
            async with sem:
                local_out: list[dict[str, Any]] = []
                try:
                    await asyncio.wait_for(
                        fn(email, client, local_out), timeout=timeout_s + 2,
                    )
                except asyncio.TimeoutError:
                    local_out.append({
                        "name": getattr(fn, "__name__", "unknown"),
                        "rateLimit": False,
                        "exists": False,
                        "_argus_error": f"timeout after {timeout_s + 2}s",
                    })
                except Exception as e:  # noqa: BLE001
                    local_out.append({
                        "name": getattr(fn, "__name__", "unknown"),
                        "rateLimit": False,
                        "exists": False,
                        "_argus_error": f"{type(e).__name__}: {e}"[:120],
                    })
                # Holehe writes to local_out with shape:
                # {"name", "domain", "method", "rateLimit", "exists", ...}
                results.extend(local_out)

        await asyncio.gather(*(_run_one(fn) for fn in funcs))

    duration_ms = int((_time.monotonic() - started) * 1000)
    hits: list[HoleheHit] = []
    for r in results:
        hits.append(HoleheHit(
            service=r.get("name") or "unknown",
            domain=r.get("domain"),
            exists=bool(r.get("exists")),
            rate_limited=bool(r.get("rateLimit") or r.get("frequent_rate_limit")),
            error=r.get("_argus_error"),
            extra={k: r[k] for k in ("emailrecovery", "phoneNumber", "others") if r.get(k)},
        ))
    # Stable order: exists first, then rate-limited, then everything else.
    hits.sort(key=lambda h: (not h.exists, not h.rate_limited, h.service))
    return HoleheReport(
        email=email,
        services_checked=len(funcs),
        hits=hits,
        duration_ms=duration_ms,
    )
