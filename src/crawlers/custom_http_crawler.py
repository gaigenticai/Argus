"""Custom HTTP/RSS crawler — operator-configured generic poller.

Why this crawler exists
-----------------------
The other crawler classes in this directory (Tor forum, Matrix, Telegram,
ransomware leak group, …) are tightly coupled to the protocol or page
shape they target — they know how to dial Tor circuits, how to parse
MTProto, how to walk a particular forum's pagination. Adding a new
KIND of source previously required writing a new Python class.

This crawler covers the long tail: any public HTTP page or feed the
operator wants to monitor where the source is "just" an RSS, JSON
endpoint, or a parseable HTML page. Configuration lives entirely in
the ``CrawlerTarget.config`` JSON column so an operator can stand
up a new monitored source from the dashboard in 30 seconds, no
deploy needed.

Supported parsers
-----------------
- ``rss``         (default) — Atom / RSS 2.0 / RDF feeds. Each
                  ``<item>`` / ``<entry>`` becomes a ``CrawlResult``.
- ``json``        — JSON endpoints. Operator supplies a JSONPath-ish
                  selector pointing at the items array, plus a small
                  field map for title / link / pub_date.
- ``html-css``    — Plain HTML pages. Operator supplies a CSS
                  selector that matches one item per page; we extract
                  the title from the matched element's text and the
                  link from its ``href`` (or first descendant anchor).

Defensive-only: the crawler is read-only, respects robots.txt by
default for clearnet hosts, and emits one ``CrawlResult`` per item
which the IngestionPipeline runs through ``extract_iocs`` exactly
the same as every other crawler.
"""

from __future__ import annotations


import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, AsyncIterator, Iterable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from src.models.threat import SourceType

from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


_PARSER_VALUES = ("rss", "json", "html-css")

# Conservative caps so a misconfigured target can't drown the
# ingestion pipeline (e.g. a 100 MB JSON dump or a 5,000-item RSS).
_MAX_ITEMS_PER_RUN = 100
_MAX_PAGE_BYTES = 5 * 1024 * 1024


def _norm_parser(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s if s in _PARSER_VALUES else "rss"


def _extract_jsonpath(payload: Any, path: str) -> Any:
    """Tiny JSONPath subset — supports ``a.b.c``, ``a.b[0].c``,
    bracketed list keys ``a.list[*].name`` (returns list).

    We intentionally don't pull in jsonpath-ng for one feature; the
    syntax operators usually need is dot + index + ``[*]``.
    """
    if not path:
        return payload
    cur: Any = payload
    for part in re.findall(r"[^.\[\]]+|\[[^\]]+\]", path):
        if cur is None:
            return None
        if part.startswith("["):
            inner = part[1:-1]
            if inner == "*":
                if isinstance(cur, list):
                    return cur
                return None
            try:
                idx = int(inner)
            except ValueError:
                return None
            if isinstance(cur, list) and 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
    return cur


def _parse_pub_date(raw: Any) -> datetime | None:
    if not raw:
        return None
    s = str(raw).strip()
    # RFC 2822 (RSS standard) first.
    try:
        dt = parsedate_to_datetime(s)
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError):
        pass
    # ISO 8601 (Atom + most JSON APIs).
    for fmt_in in (s, s.replace("Z", "+00:00")):
        try:
            dt = datetime.fromisoformat(fmt_in)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


class CustomHttpCrawler(BaseCrawler):
    """Generic HTTP/RSS/JSON poller, configured per-target.

    Per-target ``config`` schema:

    ::

        {
          "url": "https://example.com/feed.xml",        # required
          "parser": "rss" | "json" | "html-css",        # default "rss"
          "max_items": 50,                              # optional cap
          # html-css fields:
          "item_selector": "article.post",
          "title_selector": "h2",                       # optional
          "link_selector": "a.read-more",               # optional
          # json fields:
          "items_path": "data.results",                 # JSONPath to array
          "title_field": "title",
          "link_field": "url",
          "pubdate_field": "published_at",
          "summary_field": "summary",
        }

    The crawler accepts ``targets`` as a list of ``CrawlerTarget``
    rows (one per operator-configured site), so a single tick can
    poll many independent feeds.
    """

    name = "custom_http"
    source_type = SourceType.SURFACE_WEB

    def __init__(self, targets: Iterable[dict] | None = None):
        super().__init__()
        # ``targets`` shape mirrors what ``Scheduler._wrap_targets``
        # produces: ``{identifier, display_name, config}``. The
        # scheduler maps the dashboard's ``CrawlerTarget`` rows to
        # this shape so this constructor stays uniform with the rest.
        self.targets: list[dict] = list(targets or [])

    # ----- main entry ------------------------------------------------------

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        for target in self.targets:
            cfg = target  # ``Scheduler._row_to_dict`` spreads config in
            url = (cfg.get("url") or "").strip()
            if not url:
                logger.warning(
                    "[%s] target %r has no ``url``; skipping",
                    self.name, target.get("identifier"),
                )
                continue

            parser = _norm_parser(cfg.get("parser"))
            try:
                if parser == "rss":
                    async for r in self._poll_rss(target, url):
                        yield r
                elif parser == "json":
                    async for r in self._poll_json(target, url):
                        yield r
                else:
                    async for r in self._poll_html_css(target, url):
                        yield r
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "[%s] target %r poll failed: %s",
                    self.name, target.get("identifier"), exc,
                )

    # ----- RSS / Atom ------------------------------------------------------

    async def _poll_rss(
        self, target: dict, url: str,
    ) -> AsyncIterator[CrawlResult]:
        body = await self._fetch_text(url)
        if not body:
            return
        soup = BeautifulSoup(body, "xml")
        # RSS 2.0 uses <item>; Atom uses <entry>; RDF uses <item>.
        items = list(soup.find_all(["item", "entry"]))
        max_items = min(int(target.get("max_items") or _MAX_ITEMS_PER_RUN), _MAX_ITEMS_PER_RUN)
        for el in items[:max_items]:
            title = _text_or_none(el.find("title"))
            link = _text_or_none(el.find("link"))
            if not link:
                # Atom links carry the URL in @href.
                link_el = el.find("link")
                if link_el is not None:
                    link = link_el.get("href")
            pubdate = _parse_pub_date(
                _text_or_none(el.find(["pubDate", "published", "updated", "dc:date"]))
            )
            summary = (
                _text_or_none(el.find(["description", "summary", "content"]))
                or ""
            )
            content = "\n".join(
                filter(None, [title or "", summary, link or ""])
            )
            yield CrawlResult(
                source_type=self.source_type,
                source_url=link,
                source_name=target.get("display_name") or target.get("identifier") or url,
                title=title,
                content=content,
                published_at=pubdate,
                raw_data={
                    "feed_url": url,
                    "target_identifier": target.get("identifier"),
                    "parser": "rss",
                },
            )

    # ----- JSON ------------------------------------------------------------

    async def _poll_json(
        self, target: dict, url: str,
    ) -> AsyncIterator[CrawlResult]:
        cfg = target  # spread by Scheduler._row_to_dict
        body = await self._fetch_text(url)
        if not body:
            return
        try:
            import json as _json
            payload = _json.loads(body)
        except (ValueError, _json.JSONDecodeError) as exc:
            logger.warning(
                "[%s] %r returned non-JSON: %s", self.name, url, exc,
            )
            return

        items_path = (cfg.get("items_path") or "").strip()
        title_field = cfg.get("title_field") or "title"
        link_field = cfg.get("link_field") or "url"
        pub_field = cfg.get("pubdate_field") or "published_at"
        summary_field = cfg.get("summary_field") or "summary"

        candidate = _extract_jsonpath(payload, items_path) if items_path else payload
        if not isinstance(candidate, list):
            logger.warning(
                "[%s] items_path=%r did not yield a list (got %s)",
                self.name, items_path, type(candidate).__name__,
            )
            return

        max_items = min(int(cfg.get("max_items") or _MAX_ITEMS_PER_RUN), _MAX_ITEMS_PER_RUN)
        for item in candidate[:max_items]:
            if not isinstance(item, dict):
                continue
            title = item.get(title_field)
            link = item.get(link_field)
            summary = item.get(summary_field) or ""
            pubdate = _parse_pub_date(item.get(pub_field))
            content = "\n".join(
                filter(None, [str(title or ""), str(summary or ""), str(link or "")])
            )
            yield CrawlResult(
                source_type=self.source_type,
                source_url=str(link) if link else None,
                source_name=target.get("display_name") or target.get("identifier") or url,
                title=str(title) if title else None,
                content=content,
                published_at=pubdate,
                raw_data={
                    "feed_url": url,
                    "target_identifier": target.get("identifier"),
                    "parser": "json",
                },
            )

    # ----- HTML CSS --------------------------------------------------------

    async def _poll_html_css(
        self, target: dict, url: str,
    ) -> AsyncIterator[CrawlResult]:
        cfg = target  # spread by Scheduler._row_to_dict
        item_sel = (cfg.get("item_selector") or "").strip()
        if not item_sel:
            logger.warning(
                "[%s] target %r missing ``item_selector``; skipping",
                self.name, target.get("identifier"),
            )
            return
        title_sel = (cfg.get("title_selector") or "").strip()
        link_sel = (cfg.get("link_selector") or "").strip()

        body = await self._fetch_text(url)
        if not body:
            return
        soup = BeautifulSoup(body, "html.parser")
        items = soup.select(item_sel)
        max_items = min(int(cfg.get("max_items") or _MAX_ITEMS_PER_RUN), _MAX_ITEMS_PER_RUN)
        for el in items[:max_items]:
            title_el = el.select_one(title_sel) if title_sel else el
            link_el = el.select_one(link_sel) if link_sel else el.find("a")
            title = title_el.get_text(strip=True) if title_el else None
            href = None
            if link_el is not None and getattr(link_el, "get", None):
                href = link_el.get("href")
                if href:
                    href = urljoin(url, str(href))
            content = el.get_text(separator="\n", strip=True)
            yield CrawlResult(
                source_type=self.source_type,
                source_url=href,
                source_name=target.get("display_name") or target.get("identifier") or url,
                title=title,
                content=content,
                raw_data={
                    "feed_url": url,
                    "target_identifier": target.get("identifier"),
                    "parser": "html-css",
                    "item_selector": item_sel,
                },
            )

    # ----- shared fetch helper --------------------------------------------

    async def _fetch_text(self, url: str) -> str | None:
        """GET ``url`` and return text. Caps body size so a runaway
        feed can't OOM the worker."""
        try:
            session = await self._get_session(use_tor=self._is_underground_url(url))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[%s] session setup failed for %s: %s", self.name, url, exc)
            return None
        try:
            await self._delay()
            async with session.get(url) as resp:
                if resp.status >= 400:
                    logger.info("[%s] %s returned %s", self.name, url, resp.status)
                    return None
                # Guard against pathological bodies.
                length = int(resp.headers.get("Content-Length") or 0)
                if length and length > _MAX_PAGE_BYTES:
                    logger.warning(
                        "[%s] %s body %d bytes exceeds %d; skipping",
                        self.name, url, length, _MAX_PAGE_BYTES,
                    )
                    return None
                body = await resp.text()
                if len(body) > _MAX_PAGE_BYTES:
                    body = body[:_MAX_PAGE_BYTES]
                return body
        except Exception as exc:  # noqa: BLE001
            logger.warning("[%s] %s fetch failed: %s", self.name, url, exc)
            return None


def _text_or_none(el) -> str | None:
    if el is None:
        return None
    txt = el.get_text(strip=True) if hasattr(el, "get_text") else str(el).strip()
    return txt or None
