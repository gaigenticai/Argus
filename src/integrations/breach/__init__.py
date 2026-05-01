"""Breach-credential providers (P3 #3.9).

Three commercially-licensable breach data providers behind a single
search surface so the dashboard can query all three and merge results:

  hibp       HIBP Enterprise (Have I Been Pwned)
             Free for non-commercial; **the Enterprise plan** is the
             commercial-licensable tier we expect customers to BYOK.
  intelx    IntelligenceX (intelx.io) — paid tier
  dehashed   Dehashed.com — paid tier

Each provider:
  - reads its own env vars (per-tenant API key)
  - is_configured() / search_email(...) / search_password_hash(...)
  - degrades to ``unavailable`` when keys aren't set
  - goes through src.core.http_circuit so a provider outage doesn't
    block the rest of the search

The unified surface in :func:`search_email_unified` fans out to every
configured provider in parallel and returns a normalised result
shape for the dashboard.
"""

from __future__ import annotations

from .base import BreachProvider, BreachHit, ProviderResult
from .hibp import HibpProvider
from .intelx import IntelxProvider
from .dehashed import DehashedProvider

PROVIDERS: dict[str, type[BreachProvider]] = {
    "hibp":     HibpProvider,
    "intelx":   IntelxProvider,
    "dehashed": DehashedProvider,
}


def get_provider(name: str) -> BreachProvider | None:
    cls = PROVIDERS.get(name)
    if cls is None:
        return None
    return cls()


def list_available() -> list[dict]:
    out = []
    for name, cls in PROVIDERS.items():
        inst = cls()
        out.append({
            "name": name,
            "label": cls.label,
            "configured": inst.is_configured(),
        })
    return out


async def search_email_unified(
    email: str, *, providers: list[str] | None = None,
) -> list[ProviderResult]:
    """Fan out an email search to every configured provider in parallel
    and return one ``ProviderResult`` per attempt.

    Providers that aren't configured contribute a result with
    ``success=False`` + ``note="<name> not configured"`` so the
    dashboard can render a uniform "X / 3 providers responded" tile."""
    import asyncio

    targets = providers or list(PROVIDERS.keys())
    instances = [PROVIDERS[n]() for n in targets if n in PROVIDERS]
    if not instances:
        return []
    results = await asyncio.gather(
        *(p.search_email(email) for p in instances),
        return_exceptions=True,
    )
    out: list[ProviderResult] = []
    for inst, r in zip(instances, results):
        if isinstance(r, Exception):
            out.append(ProviderResult(
                provider=inst.name, success=False, hits=[],
                error=f"{type(r).__name__}: {r}"[:200],
            ))
        else:
            out.append(r)
    return out


__all__ = [
    "BreachProvider",
    "BreachHit",
    "ProviderResult",
    "HibpProvider",
    "IntelxProvider",
    "DehashedProvider",
    "PROVIDERS",
    "get_provider",
    "list_available",
    "search_email_unified",
]
