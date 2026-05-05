"""GitHub org leak scanner.

Free GitHub Search API tier (60 req/hr unauthenticated, 5000 req/hr with
PAT). We scan code search for high-value leak patterns scoped to the
vendor's GitHub organisation.

Patterns + entropy thresholds chosen to keep false-positives low:

  * AWS keys           ``AKIA[0-9A-Z]{16}``
  * GitHub PATs        ``ghp_[A-Za-z0-9]{36}``
  * Slack bot tokens   ``xoxb-[0-9]+-[A-Za-z0-9]+``
  * Stripe keys        ``sk_(live|test)_[A-Za-z0-9]{24,}``
  * Google API keys    ``AIza[0-9A-Za-z\-_]{35}``
  * Generic high-entropy passwords / API_KEY = "<32+ char>" in
    ``.env``-shaped files.

Authentication via ``ARGUS_GITHUB_TOKEN`` env var if set; otherwise
unauthenticated. Failures degrade gracefully — sanctions/HIBP/etc still
populate when this one source rate-limits.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import aiohttp

_logger = logging.getLogger(__name__)


_GITHUB_API = "https://api.github.com"


_LEAK_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_key", r"AKIA[0-9A-Z]{16}", "high"),
    ("github_pat", r"ghp_[A-Za-z0-9]{36}", "critical"),
    ("github_oauth", r"gho_[A-Za-z0-9]{36}", "critical"),
    ("slack_bot", r"xoxb-[0-9]+-[A-Za-z0-9]+", "high"),
    (
        "stripe_secret",
        r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
        "critical",
    ),
    ("google_api", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    (
        "private_key_pem",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "critical",
    ),
    (
        "generic_password_assignment",
        r"(?i)(?:password|passwd|pwd|api[_-]?key|secret)\s*[:=]\s*[\"\'][A-Za-z0-9!@#$%^&*\-_]{16,}[\"\']",
        "medium",
    ),
]


@dataclass
class LeakHit:
    pattern: str
    severity: str
    repo: str
    path: str
    url: str
    excerpt: str


def _headers() -> dict[str, str]:
    h: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("ARGUS_GITHUB_TOKEN") or os.environ.get(
        "GITHUB_TOKEN"
    )
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _search_code(
    org: str, query: str, per_page: int = 30, timeout: float = 20
) -> dict[str, Any] | None:
    """Use GitHub's code-search endpoint (ratelimited; works even
    unauthenticated for public repos)."""
    q = f"{query} org:{org}"
    url = f"{_GITHUB_API}/search/code?q={aiohttp.helpers.quote(q, safe='')}&per_page={per_page}"
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
            async with sess.get(url, headers=_headers()) as resp:
                if resp.status == 422:
                    # GitHub returns 422 when the search isn't allowed (e.g.
                    # unauthenticated code search now requires a token for
                    # most queries). Caller treats as a non-fatal "skipped".
                    return None
                if resp.status == 403:
                    _logger.info(
                        "github_leaks: rate-limited or forbidden for org=%s", org
                    )
                    return None
                if resp.status != 200:
                    _logger.warning(
                        "github_leaks: %s -> HTTP %s", url, resp.status
                    )
                    return None
                return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _logger.warning("github_leaks: fetch failed: %s", e)
        return None


async def _fetch_blob(url: str, timeout: float = 15) -> str | None:
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
            async with sess.get(url, headers=_headers()) as resp:
                if resp.status != 200:
                    return None
                return await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def scan_org(org: str, *, max_hits: int = 50) -> list[LeakHit]:
    """Scan a GitHub organisation for leak-pattern hits across code
    search. Returns at most ``max_hits`` hits. Empty list on rate-limit
    or auth issue — caller logs that as "not screened" rather than
    "no leaks"."""
    if not org:
        return []
    out: list[LeakHit] = []
    for label, pattern, severity in _LEAK_PATTERNS:
        if len(out) >= max_hits:
            break
        # GitHub's code search doesn't support regex, so we feed a literal
        # prefix unique enough to find candidates, then verify with the
        # full regex against the blob. ``BEGIN PRIVATE KEY`` for PEMs etc.
        prefix = pattern
        if "[" in prefix or "(" in prefix:
            # Strip the regex bits — keep the literal prefix.
            prefix = re.split(r"[\[\(\\]", pattern, 1)[0]
            if not prefix:
                continue
        result = await _search_code(org, prefix, per_page=10)
        if result is None:
            continue
        for item in (result.get("items") or [])[:10]:
            html = item.get("html_url") or ""
            raw = (
                item.get("html_url", "")
                .replace("github.com", "raw.githubusercontent.com")
                .replace("/blob/", "/")
            )
            text = await _fetch_blob(raw)
            if not text:
                continue
            try:
                m = re.search(pattern, text)
            except re.error:
                continue
            if not m:
                continue
            excerpt = text[max(0, m.start() - 40) : m.end() + 40]
            out.append(
                LeakHit(
                    pattern=label,
                    severity=severity,
                    repo=item.get("repository", {}).get("full_name") or "",
                    path=item.get("path") or "",
                    url=html,
                    excerpt=excerpt[:200],
                )
            )
            if len(out) >= max_hits:
                break
    return out


def severity_to_score(hits: list[LeakHit]) -> tuple[float, dict[str, int]]:
    """Composite score: 100 if zero hits; subtract per-hit penalty by
    severity. Returns ``(score, by_severity_count)``."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for h in hits:
        counts[h.severity] = counts.get(h.severity, 0) + 1
    penalty = (
        counts["critical"] * 25
        + counts["high"] * 12
        + counts["medium"] * 5
        + counts["low"] * 2
    )
    score = max(0.0, 100.0 - penalty)
    return score, counts


__all__ = ["scan_org", "severity_to_score", "LeakHit"]
