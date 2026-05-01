"""RSS/Atom/JSON-Feed parser. Stdlib only — no `feedparser` dep.

Stable enough for the major feed shapes that matter to us:
    RSS 2.0 (CISA, NCSC, vendor PSIRTs, BleepingComputer, Krebs)
    Atom 1.0 (most security blogs)
    JSON Feed v1.1 (a few modern outlets)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable
# Audit B7 — defusedxml is XXE-safe.
import defusedxml.ElementTree as ET  # type: ignore


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


@dataclass
class ParsedArticle:
    url: str
    title: str
    summary: str | None
    author: str | None
    published_at: datetime | None
    cve_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def _to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # ISO 8601
        if "T" in value or "-" in value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        # RFC 822 (RSS)
        return parsedate_to_datetime(value)
    except Exception:  # noqa: BLE001
        return None


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_rss(text: str) -> list[ParsedArticle]:
    out: list[ParsedArticle] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for item in root.iter():
        if _strip_ns(item.tag).lower() != "item":
            continue
        title = ""
        link = ""
        desc = None
        author = None
        pub = None
        cats: list[str] = []
        for child in item:
            t = _strip_ns(child.tag).lower()
            if t == "title":
                title = (child.text or "").strip()
            elif t == "link":
                link = (child.text or "").strip()
            elif t == "description":
                desc = (child.text or "").strip()
            elif t in ("author", "creator"):
                author = (child.text or "").strip()
            elif t in ("pubdate", "published"):
                pub = _to_dt(child.text)
            elif t == "category":
                cats.append((child.text or "").strip())
        if not link or not title:
            continue
        cves = sorted(set(_CVE_RE.findall((title + " " + (desc or "")))))
        out.append(
            ParsedArticle(
                url=link,
                title=title,
                summary=desc,
                author=author,
                published_at=pub,
                cve_ids=[c.upper() for c in cves],
                tags=[c for c in cats if c],
            )
        )
    return out


def parse_atom(text: str) -> list[ParsedArticle]:
    out: list[ParsedArticle] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for entry in root.iter():
        if _strip_ns(entry.tag).lower() != "entry":
            continue
        title = ""
        link = ""
        desc = None
        author = None
        pub = None
        cats: list[str] = []
        for child in entry:
            t = _strip_ns(child.tag).lower()
            if t == "title":
                title = (child.text or "").strip()
            elif t == "link":
                href = child.attrib.get("href")
                if href:
                    link = href
            elif t in ("summary", "content"):
                desc = (child.text or "").strip() if child.text else desc
            elif t == "author":
                for a in child:
                    if _strip_ns(a.tag).lower() == "name" and a.text:
                        author = a.text.strip()
            elif t == "published" or t == "updated":
                if pub is None:
                    pub = _to_dt(child.text)
            elif t == "category":
                term = child.attrib.get("term")
                if term:
                    cats.append(term)
        if not link or not title:
            continue
        cves = sorted(set(_CVE_RE.findall((title + " " + (desc or "")))))
        out.append(
            ParsedArticle(
                url=link,
                title=title,
                summary=desc,
                author=author,
                published_at=pub,
                cve_ids=[c.upper() for c in cves],
                tags=cats,
            )
        )
    return out


def parse_json_feed(text: str) -> list[ParsedArticle]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    items = data.get("items") or []
    out: list[ParsedArticle] = []
    for it in items:
        url = it.get("url") or it.get("external_url")
        title = it.get("title") or url
        if not url or not title:
            continue
        summary = it.get("summary") or it.get("content_text")
        author = (it.get("author") or {}).get("name") if isinstance(it.get("author"), dict) else None
        pub = _to_dt(it.get("date_published") or it.get("date_modified"))
        cves = sorted(set(_CVE_RE.findall((title + " " + (summary or "")))))
        tags = it.get("tags") or []
        out.append(
            ParsedArticle(
                url=url,
                title=title,
                summary=summary,
                author=author,
                published_at=pub,
                cve_ids=[c.upper() for c in cves],
                tags=[t for t in tags if isinstance(t, str)],
            )
        )
    return out


def parse_any(text: str, *, kind_hint: str | None = None) -> list[ParsedArticle]:
    """Sniff format if hint not given. Returns parsed articles."""
    s = (text or "").lstrip()
    if kind_hint == "json_feed" or s.startswith("{"):
        out = parse_json_feed(s)
        if out:
            return out
    if kind_hint == "atom" or "<feed" in s[:200].lower():
        out = parse_atom(s)
        if out:
            return out
    return parse_rss(s)


__all__ = [
    "ParsedArticle",
    "parse_rss",
    "parse_atom",
    "parse_json_feed",
    "parse_any",
]
