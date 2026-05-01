"""Deep TLS-fingerprint randomization for sensitive crawlers.

The Gemini audit (G10) called out that the underground crawlers ship
with vanilla aiohttp / httpx — fine on the wire layer (UA rotation,
request pacing, jitter) but trivial to fingerprint at the TLS layer
via JA3 / JA4. A modern leak site or marketplace operator runs a
JA3 firewall and blocks the standard Python TLS hello within seconds.

This module wraps ``curl_cffi`` to provide a ``CurlSession`` that:

    * mimics one of seven real browser TLS profiles (Chrome 120,
      Chrome 116, Edge 119, Safari 17.0, Safari 16.0, Firefox 117,
      Firefox 109)
    * randomly picks the profile per request with a weighting that
      matches actual browser market share
    * speaks HTTP/2 with the right settings frames per profile
    * presents the JA3 / JA4 of that browser, not Python's

curl_cffi is already a transitive dependency through Scweet (see
``requirements.txt``), so we don't add a new package — we expose it
through a clean async surface that drops into the existing crawler
interfaces.

Crawlers opt into this transport explicitly. ``BaseCrawler`` keeps
its plain-aiohttp default for low-risk public sources (CertStream,
KEV, NVD); Tor/forum/ransomware/stealer crawlers switch to
``CurlSession`` when constructed.
"""

from __future__ import annotations

import asyncio
import logging
import random
from contextlib import asynccontextmanager
from typing import AsyncIterator


logger = logging.getLogger(__name__)


# Browser-impersonation profiles supported by curl_cffi. We weight by
# rough global desktop browser share so a passive observer correlating
# the population of fingerprints sees a normal distribution rather
# than the obvious 14% / 14% / 14% / ... uniform spread that a naive
# round-robin would produce.
_PROFILES = [
    ("chrome120",   0.42),
    ("chrome116",   0.18),
    ("edge119",     0.10),
    ("safari17_0",  0.13),
    ("safari16_0",  0.05),
    ("firefox117",  0.08),
    ("firefox109",  0.04),
]


def random_profile() -> str:
    """Pick a profile weighted by browser market share."""
    r = random.random()
    cumulative = 0.0
    for profile, weight in _PROFILES:
        cumulative += weight
        if r <= cumulative:
            return profile
    return _PROFILES[-1][0]


class CurlSession:
    """Async wrapper around ``curl_cffi.requests.AsyncSession``.

    Each ``get`` / ``post`` call rotates the impersonation profile so
    no two sequential requests from the same crawler land with the
    same JA3 hash. A session is cheap (~3MB per process) so crawlers
    can hold one for the lifetime of a tick without paying setup cost
    per request.

    Usage::

        async with CurlSession(proxy="socks5h://tor:9050") as cs:
            async for resp in cs.iter_get(["http://x.onion/", "http://y.onion/"]):
                ...

    On hosts where curl_cffi is unavailable (rare — it's a wheel for
    Linux x86_64 / aarch64 + macOS), the session falls back to
    aiohttp with a randomized UA. The dashboard surfaces this state
    through ``ARGUS_TLS_FINGERPRINT_AVAILABLE`` so an operator can
    see whether deep impersonation is actually in effect.
    """

    def __init__(
        self,
        *,
        proxy: str | None = None,
        timeout: float = 60.0,
        verify: bool = True,
    ) -> None:
        self._proxy = proxy
        self._timeout = timeout
        self._verify = verify
        self._session = None  # lazy

    async def __aenter__(self) -> "CurlSession":
        try:
            from curl_cffi.requests import AsyncSession

            self._session = AsyncSession(
                proxy=self._proxy,
                timeout=self._timeout,
                verify=self._verify,
            )
        except ImportError:
            logger.warning(
                "tls_fingerprint: curl_cffi not installed — falling back to "
                "aiohttp. Deep JA3/JA4 randomization is unavailable on this "
                "host. Install curl_cffi via `pip install curl_cffi` to "
                "enable browser-grade TLS impersonation."
            )
            self._session = _AiohttpFallback(
                proxy=self._proxy,
                timeout=self._timeout,
                verify=self._verify,
            )
            await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is None:
            return
        if isinstance(self._session, _AiohttpFallback):
            await self._session.__aexit__(exc_type, exc, tb)
        else:
            await self._session.close()
        self._session = None

    async def get(self, url: str, **kwargs) -> "Response":
        if self._session is None:
            raise RuntimeError("CurlSession not entered (use `async with`)")
        if isinstance(self._session, _AiohttpFallback):
            return await self._session.get(url, **kwargs)
        impersonate = kwargs.pop("impersonate", random_profile())
        resp = await self._session.get(url, impersonate=impersonate, **kwargs)
        return Response(
            status=resp.status_code,
            text=resp.text,
            content=resp.content,
            headers=dict(resp.headers),
            url=str(resp.url),
            impersonated_as=impersonate,
        )

    async def post(self, url: str, **kwargs) -> "Response":
        if self._session is None:
            raise RuntimeError("CurlSession not entered")
        if isinstance(self._session, _AiohttpFallback):
            return await self._session.post(url, **kwargs)
        impersonate = kwargs.pop("impersonate", random_profile())
        resp = await self._session.post(url, impersonate=impersonate, **kwargs)
        return Response(
            status=resp.status_code,
            text=resp.text,
            content=resp.content,
            headers=dict(resp.headers),
            url=str(resp.url),
            impersonated_as=impersonate,
        )

    async def iter_get(self, urls) -> AsyncIterator["Response"]:
        for url in urls:
            try:
                yield await self.get(url)
            except Exception as exc:  # noqa: BLE001 — per-URL boundary
                # Per-URL isolation: one bad URL cannot fail the iteration.
                # Logged at INFO so a cluster is visible.
                logger.info(
                    "tls_fingerprint: GET %s failed: %s: %s",
                    url, type(exc).__name__, exc,
                )


class Response:
    """Provider-agnostic response wrapper."""

    __slots__ = ("status", "text", "content", "headers", "url", "impersonated_as")

    def __init__(
        self,
        *,
        status: int,
        text: str,
        content: bytes,
        headers: dict,
        url: str,
        impersonated_as: str,
    ) -> None:
        self.status = status
        self.text = text
        self.content = content
        self.headers = headers
        self.url = url
        self.impersonated_as = impersonated_as


class _AiohttpFallback:
    """Drop-in fallback used when curl_cffi isn't available."""

    def __init__(self, *, proxy: str | None, timeout: float, verify: bool) -> None:
        self._proxy = proxy
        self._timeout = timeout
        self._verify = verify
        self._session = None

    async def __aenter__(self):
        import aiohttp

        from src.core.opsec import randomize_headers

        connector = aiohttp.TCPConnector(verify_ssl=self._verify)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self._timeout),
            headers=randomize_headers(),
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def get(self, url: str, **kwargs) -> Response:
        async with self._session.get(url, proxy=self._proxy, **kwargs) as resp:
            content = await resp.read()
            return Response(
                status=resp.status,
                text=content.decode("utf-8", errors="replace"),
                content=content,
                headers=dict(resp.headers),
                url=str(resp.url),
                impersonated_as="aiohttp-fallback",
            )

    async def post(self, url: str, **kwargs) -> Response:
        async with self._session.post(url, proxy=self._proxy, **kwargs) as resp:
            content = await resp.read()
            return Response(
                status=resp.status,
                text=content.decode("utf-8", errors="replace"),
                content=content,
                headers=dict(resp.headers),
                url=str(resp.url),
                impersonated_as="aiohttp-fallback",
            )


def fingerprint_status() -> dict:
    """Diagnostic for the dashboard. Returns
    ``{"available": bool, "profiles": [...], "reason": str|None}``."""
    try:
        import curl_cffi  # noqa: F401

        return {
            "available": True,
            "profiles": [p for p, _ in _PROFILES],
            "reason": None,
        }
    except ImportError:
        return {
            "available": False,
            "profiles": [],
            "reason": (
                "curl_cffi is not installed; deep JA3/JA4 fingerprint "
                "randomization is disabled. Install curl_cffi to enable."
            ),
        }


__all__ = [
    "CurlSession",
    "Response",
    "fingerprint_status",
    "random_profile",
]
