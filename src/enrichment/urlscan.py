"""urlscan.io enrichment (free-tier signup, BYOK).

urlscan.io provides on-demand URL sandboxing + a searchable history
of what other people have submitted. We use it as an *enrichment*
source — not a global feed pull — so two helpers ship here:

  search_recent(target)     ``GET /api/v1/search/?q=<query>`` —
                            historical scan summary for a domain or
                            URL the analyst is investigating.

  submit_scan(url)          ``POST /api/v1/scan/`` — kick off a fresh
                            scan with ``visibility=unlisted`` (so the
                            customer's scan target isn't published to
                            the public feed). Returns the scan UUID +
                            the result URL the analyst can open
                            directly in urlscan's UI.

A free urlscan.io account at https://urlscan.io/user/signup/ gets
~10k scans/day on the API. Set ``ARGUS_URLSCAN_API_KEY`` in ``.env``
or via Helm values.

All outbound calls are gated by the ``intel:urlscan`` circuit
breaker so a urlscan outage doesn't tar-pit the rest of the
enrichment pipeline.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

logger = logging.getLogger(__name__)


_BASE = "https://urlscan.io/api/v1"
_BREAKER = "intel:urlscan"


def _api_key() -> str:
    # Resolve via the integration-keys cache so operators can rotate
    # via Settings → Integrations without restarting the API.
    from src.core import integration_keys
    return (
        integration_keys.get("urlscan", env_fallback="ARGUS_URLSCAN_API_KEY") or ""
    ).strip()


def is_configured() -> bool:
    return bool(_api_key())


def _headers() -> dict[str, str]:
    return {
        "API-Key": _api_key(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


# ── Result dataclasses ─────────────────────────────────────────────


@dataclass
class UrlscanResult:
    """Uniform shape the dashboard / agents consume."""

    available: bool
    success: bool
    note: str | None = None
    error: str | None = None
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "success": self.success,
            "note": self.note,
            "error": self.error,
            "data": self.data,
        }


@dataclass
class UrlscanScanSummary:
    scan_id: str
    task_url: str             # urlscan UUID URL — public scan permalink
    submitted_url: str
    domain: str
    timestamp: str | None = None
    asn: str | None = None
    country: str | None = None
    verdict_score: int | None = None    # 0–100, 100 = malicious
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "task_url": self.task_url,
            "submitted_url": self.submitted_url,
            "domain": self.domain,
            "timestamp": self.timestamp,
            "asn": self.asn,
            "country": self.country,
            "verdict_score": self.verdict_score,
        }


# ── search_recent ───────────────────────────────────────────────────


async def search_recent(
    target: str, *, limit: int = 10,
) -> UrlscanResult:
    """Search historical urlscan scans for a domain / URL.

    Builds a simple ``page.domain:<target>`` query when the input
    looks like a bare domain, else uses ``page.url:<target>``.
    """
    if not target:
        return UrlscanResult(
            available=is_configured(), success=False,
            error="target is required",
        )
    if not is_configured():
        return UrlscanResult(
            available=False, success=False,
            note=("urlscan.io not configured — set ARGUS_URLSCAN_API_KEY "
                  "(free signup at https://urlscan.io/user/signup/)"),
        )

    if "://" in target:
        q = f'page.url:"{target}"'
    elif "/" in target:
        q = f'page.url:"https://{target}"'
    else:
        q = f"page.domain:{target}"
    params = {"q": q, "size": str(max(1, min(limit, 100)))}

    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=20)
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(
                    f"{_BASE}/search/", headers=_headers(), params=params,
                ) as resp:
                    text = await resp.text()
                    if resp.status == 401:
                        return UrlscanResult(
                            available=True, success=False,
                            error="urlscan 401 — check ARGUS_URLSCAN_API_KEY",
                        )
                    if resp.status >= 400:
                        return UrlscanResult(
                            available=True, success=False,
                            error=f"HTTP {resp.status}: {text[:200]}",
                        )
                    import json as _json
                    body = _json.loads(text) if text else {}
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        return UrlscanResult(
            available=True, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    scans: list[dict[str, Any]] = []
    for r in (body.get("results") or [])[:limit]:
        if not isinstance(r, dict):
            continue
        page = r.get("page") or {}
        task = r.get("task") or {}
        verdicts = r.get("verdicts") or {}
        overall = verdicts.get("overall") or {}
        scans.append(UrlscanScanSummary(
            scan_id=str(r.get("_id") or ""),
            task_url=str(task.get("reportURL") or ""),
            submitted_url=str(task.get("url") or page.get("url") or ""),
            domain=str(page.get("domain") or ""),
            timestamp=task.get("time"),
            asn=page.get("asn"),
            country=page.get("country"),
            verdict_score=overall.get("score"),
            raw=r,
        ).to_dict())

    return UrlscanResult(
        available=True, success=True,
        data={
            "query": q,
            "total": int(body.get("total") or 0),
            "results": scans,
        },
    )


# ── submit_scan ─────────────────────────────────────────────────────


async def submit_scan(
    url: str, *, visibility: str = "unlisted",
) -> UrlscanResult:
    """Submit a URL for live scanning.

    ``visibility`` defaults to ``unlisted`` so the customer's scan
    target doesn't end up on urlscan's public feed. Allowed values
    per urlscan's API: ``public``, ``unlisted``, ``private``
    (private requires a paid tier; we surface but don't enforce).
    """
    if not url:
        return UrlscanResult(
            available=is_configured(), success=False,
            error="url is required",
        )
    if not is_configured():
        return UrlscanResult(
            available=False, success=False,
            note=("urlscan.io not configured — set ARGUS_URLSCAN_API_KEY "
                  "(free signup at https://urlscan.io/user/signup/)"),
        )
    if visibility not in {"public", "unlisted", "private"}:
        return UrlscanResult(
            available=True, success=False,
            error=f"visibility must be public/unlisted/private, got {visibility!r}",
        )

    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=30)
    body = {"url": url, "visibility": visibility}
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.post(
                    f"{_BASE}/scan/", headers=_headers(), json=body,
                ) as resp:
                    text = await resp.text()
                    if resp.status == 401:
                        return UrlscanResult(
                            available=True, success=False,
                            error="urlscan 401 — check ARGUS_URLSCAN_API_KEY",
                        )
                    if resp.status == 400:
                        return UrlscanResult(
                            available=True, success=False,
                            error=f"urlscan 400: {text[:200]}",
                        )
                    if resp.status == 429:
                        return UrlscanResult(
                            available=True, success=False,
                            error="urlscan 429 — quota exhausted",
                        )
                    if resp.status >= 400:
                        return UrlscanResult(
                            available=True, success=False,
                            error=f"HTTP {resp.status}: {text[:200]}",
                        )
                    import json as _json
                    j = _json.loads(text) if text else {}
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        return UrlscanResult(
            available=True, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )

    return UrlscanResult(
        available=True, success=True,
        data={
            "uuid": j.get("uuid"),
            "result_url": j.get("result"),
            "api_url": j.get("api"),
            "visibility": j.get("visibility") or visibility,
        },
        note=("Scan queued — urlscan typically completes within 10–30 s. "
              "Fetch the report from data.result_url."),
    )


async def health_check() -> UrlscanResult:
    """Probe urlscan with the user-info endpoint to confirm the key
    works and the breaker is closed."""
    if not is_configured():
        return UrlscanResult(
            available=False, success=False,
            note="urlscan.io not configured",
        )
    breaker = get_breaker(_BREAKER)
    timeout = aiohttp.ClientTimeout(total=15)
    try:
        async with breaker:
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(
                    f"{_BASE}/quotas/", headers=_headers(),
                ) as resp:
                    text = await resp.text()
                    if resp.status == 401:
                        return UrlscanResult(
                            available=True, success=False,
                            error="urlscan 401 — check ARGUS_URLSCAN_API_KEY",
                        )
                    if resp.status >= 400:
                        return UrlscanResult(
                            available=True, success=False,
                            error=f"HTTP {resp.status}: {text[:200]}",
                        )
                    return UrlscanResult(
                        available=True, success=True,
                        note="urlscan.io /quotas reachable",
                    )
    except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
        return UrlscanResult(
            available=True, success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )
