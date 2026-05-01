"""Phase 8 — News & Advisories integration tests."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from src.news.parser import parse_atom, parse_json_feed, parse_rss
from src.news.relevance import score_article

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


_RSS_BODY = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Argus Test Feed</title>
  <item>
    <title>CISA adds CVE-2026-1001 to KEV catalog</title>
    <link>https://www.cisa.gov/news/argus-cve-2026-1001</link>
    <description>WidgetSoft Argus integration RCE actively exploited.</description>
    <pubDate>Mon, 28 Apr 2026 12:00:00 GMT</pubDate>
    <category>kev</category>
  </item>
  <item>
    <title>Quarterly cloud security trends</title>
    <link>https://blog.example/cloud-trends-q1</link>
    <description>Latest cloud trends report.</description>
    <pubDate>Sun, 27 Apr 2026 09:00:00 GMT</pubDate>
  </item>
</channel></rss>
"""

_ATOM_BODY = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Feed</title>
  <entry>
    <title>Atom test entry referencing CVE-2025-9999</title>
    <link href="https://example.com/atom-1"/>
    <summary>Atom summary text</summary>
    <updated>2026-04-25T10:00:00Z</updated>
    <author><name>Author A</name></author>
    <category term="advisory"/>
  </entry>
</feed>
"""

_JSON_FEED_BODY = """{
  "version": "https://jsonfeed.org/version/1.1",
  "title": "JSON Feed",
  "items": [
    {
      "id": "1",
      "url": "https://example.com/json-1",
      "title": "JSON test",
      "summary": "Discussing CVE-2026-1001",
      "date_published": "2026-04-26T08:00:00Z",
      "author": {"name": "Author B"},
      "tags": ["security"]
    }
  ]
}
"""


# --- Parser unit tests -------------------------------------------------


def test_parse_rss():
    out = parse_rss(_RSS_BODY)
    assert len(out) == 2
    assert out[0].title.startswith("CISA")
    assert out[0].url == "https://www.cisa.gov/news/argus-cve-2026-1001"
    assert "CVE-2026-1001" in out[0].cve_ids


def test_parse_atom():
    out = parse_atom(_ATOM_BODY)
    assert len(out) == 1
    assert out[0].url == "https://example.com/atom-1"
    assert "CVE-2025-9999" in out[0].cve_ids
    assert out[0].author == "Author A"


def test_parse_json_feed():
    out = parse_json_feed(_JSON_FEED_BODY)
    assert len(out) == 1
    assert out[0].author == "Author B"
    assert "CVE-2026-1001" in out[0].cve_ids


# --- Relevance scoring ------------------------------------------------


def test_relevance_score_brand_match():
    s = score_article(
        title="Argus banking platform vulnerability disclosed",
        summary="Critical RCE in Argus mobile app",
        cve_ids=["CVE-2026-1001"],
        brand_terms=["argus"],
        asset_keywords=[],
        kev_cves=["CVE-2026-1001"],
    )
    assert s.score >= 0.75
    assert "argus" in s.matched_brand_terms
    assert "CVE-2026-1001" in s.matched_cves


def test_relevance_score_no_signals_zero():
    s = score_article(
        title="Tech industry quarterly trends",
        summary="A general blog post",
        cve_ids=[],
        brand_terms=["argus"],
        asset_keywords=["nginx"],
        kev_cves=[],
    )
    assert s.score == 0.0


# --- API: register + ingest -------------------------------------------


async def _seed_brand_term(client, analyst, organization):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "name",
            "value": "argus",
        },
        headers=_hdr(analyst),
    )


async def test_feed_register_and_ingest_creates_articles_and_relevance(
    client: AsyncClient, analyst_user, organization
):
    await _seed_brand_term(client, analyst_user, organization)
    r = await client.post(
        "/api/v1/news/feeds",
        json={
            "organization_id": str(organization["id"]),
            "name": "CISA test",
            "url": "https://www.cisa.gov/news.rss",
            "kind": "rss",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201
    fid = r.json()["id"]

    ingest = await client.post(
        f"/api/v1/news/feeds/{fid}/ingest",
        json={"body": _RSS_BODY, "kind_hint": "rss"},
        headers=_hdr(analyst_user),
    )
    assert ingest.status_code == 200
    body = ingest.json()
    assert body["parsed"] == 2
    # Audit B11 — strict now that the autouse `_scrub_global_tables`
    # fixture wipes news_articles per-test.
    assert body["new_articles"] == 2
    assert body["duplicates"] == 0
    assert body["relevance_rows_created"] >= 1

    relevance = await client.get(
        "/api/v1/news/relevance",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert relevance.status_code == 200
    assert any("argus" in r["matched_brand_terms"] for r in relevance.json())


async def test_feed_ingest_idempotent_on_url(
    client: AsyncClient, analyst_user, organization
):
    # Use unique URLs so no previous test's articles collide with this one.
    suffix = uuid.uuid4().hex[:8]
    body = (
        '<?xml version="1.0"?><rss version="2.0"><channel>'
        f"<title>idem-{suffix}</title>"
        "<item><title>idem item one</title>"
        f"<link>https://idem.example/{suffix}/one</link></item>"
        "<item><title>idem item two</title>"
        f"<link>https://idem.example/{suffix}/two</link></item>"
        "</channel></rss>"
    )
    fid = (
        await client.post(
            "/api/v1/news/feeds",
            json={"name": f"x-{suffix}", "url": f"https://x-{suffix}.example/rss"},
            headers=_hdr(analyst_user),
        )
    ).json()["id"]
    a = await client.post(
        f"/api/v1/news/feeds/{fid}/ingest",
        json={"body": body, "kind_hint": "rss"},
        headers=_hdr(analyst_user),
    )
    b = await client.post(
        f"/api/v1/news/feeds/{fid}/ingest",
        json={"body": body, "kind_hint": "rss"},
        headers=_hdr(analyst_user),
    )
    assert a.json()["new_articles"] == 2
    assert b.json()["new_articles"] == 0
    assert b.json()["duplicates"] == 2


async def test_relevance_read_and_bookmark(
    client: AsyncClient, analyst_user, organization
):
    await _seed_brand_term(client, analyst_user, organization)
    fid = (
        await client.post(
            "/api/v1/news/feeds",
            json={"name": "x", "url": "https://x.example/rss"},
            headers=_hdr(analyst_user),
        )
    ).json()["id"]
    await client.post(
        f"/api/v1/news/feeds/{fid}/ingest",
        json={"body": _RSS_BODY, "kind_hint": "rss"},
        headers=_hdr(analyst_user),
    )
    relevance = await client.get(
        "/api/v1/news/relevance",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    rid = relevance.json()[0]["id"]

    read = await client.post(
        f"/api/v1/news/relevance/{rid}/read",
        headers=_hdr(analyst_user),
    )
    assert read.json()["is_read"] is True

    book = await client.post(
        f"/api/v1/news/relevance/{rid}/bookmark",
        headers=_hdr(analyst_user),
    )
    assert book.json()["bookmarked"] is True


async def test_relevance_recompute_admin_only(
    client: AsyncClient, analyst_user, admin_user, organization
):
    forbidden = await client.post(
        "/api/v1/news/relevance/recompute",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert forbidden.status_code == 403

    ok = await client.post(
        "/api/v1/news/relevance/recompute",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(admin_user),
    )
    assert ok.status_code == 200


# --- Advisories -------------------------------------------------------


async def test_advisory_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    create = await client.post(
        "/api/v1/news/advisories",
        json={
            "organization_id": str(organization["id"]),
            "slug": "argus-2026-001",
            "title": "Internal advisory: critical SSO regression",
            "body_markdown": "# heading\n\nDetails…",
            "severity": "high",
            "tags": ["sso"],
            "cve_ids": ["CVE-2026-1001"],
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 201, create.text
    aid = create.json()["id"]
    assert create.json()["state"] == "draft"

    pub = await client.post(
        f"/api/v1/news/advisories/{aid}/publish",
        headers=_hdr(analyst_user),
    )
    assert pub.status_code == 200
    assert pub.json()["state"] == "published"
    assert pub.json()["published_at"] is not None

    rev = await client.post(
        f"/api/v1/news/advisories/{aid}/revoke",
        json={"reason": "incorrect impact assessment, will reissue"},
        headers=_hdr(analyst_user),
    )
    assert rev.status_code == 200
    assert rev.json()["state"] == "revoked"

    # Editing a revoked advisory is blocked.
    bad = await client.patch(
        f"/api/v1/news/advisories/{aid}",
        json={"title": "new title"},
        headers=_hdr(analyst_user),
    )
    assert bad.status_code == 409


async def test_advisory_duplicate_slug_409(
    client: AsyncClient, analyst_user, organization
):
    payload = {
        "organization_id": str(organization["id"]),
        "slug": "dupe",
        "title": "x",
        "body_markdown": "y",
    }
    a = await client.post(
        "/api/v1/news/advisories", json=payload, headers=_hdr(analyst_user)
    )
    b = await client.post(
        "/api/v1/news/advisories", json=payload, headers=_hdr(analyst_user)
    )
    assert a.status_code == 201
    assert b.status_code == 409
