"""Fetch + extract clean article body text from a URL.

Uses ``readability-lxml`` if available, falling back to a tag-stripping
heuristic so the worker degrades gracefully on minimal-deps deployments.

The output (``body_text``) is what we feed into the LLM summary +
entity extractor.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Final

import aiohttp

_logger = logging.getLogger(__name__)


_HEADERS: Final[dict[str, str]] = {
    "User-Agent": (
        "Mozilla/5.0 (Argus-CTI; +https://argus.security) "
        "AppleWebKit/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en;q=0.9,*;q=0.8",
}


async def fetch_html(url: str, *, timeout: int = 15) -> str | None:
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj, headers=_HEADERS) as s:
            async with s.get(url, allow_redirects=True) as resp:
                if resp.status >= 400:
                    return None
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "html" not in ctype and "text" not in ctype:
                    return None
                return await resp.text(errors="replace")
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _logger.debug("fetch_html failed for %s: %s", url, e)
        return None


_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<(script|style|noscript)[^>]*>.*?</\1>", re.DOTALL | re.I)
_WS_RE = re.compile(r"\s+")


def _fallback_text(html: str) -> str:
    """Conservative HTML → text. Strips scripts/styles, then collapses
    whitespace. Loses some structure but never hangs."""
    body = _SCRIPT_RE.sub(" ", html)
    body = _TAG_RE.sub(" ", body)
    body = _WS_RE.sub(" ", body).strip()
    return body[:50_000]  # cap so we don't blow tokens on giant pages


def extract_body(html: str) -> str:
    """Return clean article text. Uses readability-lxml when available."""
    try:
        from readability import Document  # type: ignore
        doc = Document(html)
        article_html = doc.summary(html_partial=True)
        return _fallback_text(article_html)
    except ImportError:
        return _fallback_text(html)
    except Exception as e:  # noqa: BLE001
        _logger.debug("readability failed: %s; falling back", e)
        return _fallback_text(html)


async def fetch_and_extract(url: str) -> str | None:
    html = await fetch_html(url)
    if not html:
        return None
    return extract_body(html)


__all__ = ["fetch_html", "extract_body", "fetch_and_extract"]
