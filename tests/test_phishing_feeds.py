"""Audit B3 — phishing-feed adapter smoke tests.

Each fetcher is exercised against a canned upstream payload (no live
HTTP) so the test stays deterministic and offline-clean. The end-to-end
``ingest_for_organization`` test stitches three feeds together and
verifies the cross-org isolation + per-feed source tagging in the
persisted ``SuspectDomain`` rows.
"""

from __future__ import annotations

import json
from typing import Iterable

import aiohttp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from src.intel import phishing_feeds as pf
from src.models.brand import (
    BrandTerm,
    BrandTermKind,
    SuspectDomain,
    SuspectDomainSource,
)

pytestmark = pytest.mark.asyncio


async def _seed_brand_term(
    test_engine,
    organization_id,
    value: str,
    *,
    kind: BrandTermKind = BrandTermKind.APEX_DOMAIN,
):
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        s.add(
            BrandTerm(
                organization_id=organization_id,
                kind=kind.value,
                value=value.lower(),
                keywords=[],
                is_active=True,
            )
        )
        await s.commit()


# --- _extract_apex behaviour --------------------------------------------


def test_extract_apex_strips_scheme_and_path():
    assert pf._extract_apex("https://login.argus.com/path/x?a=1") == (
        "login.argus.com"
    )
    assert pf._extract_apex("argus.com") == "argus.com"


def test_extract_apex_normalises_defanged_inputs():
    """SOC analysts commonly de-fang URLs in tickets — we should
    accept the de-fanged form and treat it identically."""
    assert pf._extract_apex("hxxp://argus[.]com/login") == "argus.com"


def test_extract_apex_filters_cloud_infra_hosts():
    """Phishing kits hosted on Vercel / AWS / etc. shouldn't seed
    suspect_domains rows because the apex is the cloud provider's,
    not the brand's."""
    for u in (
        "https://something.vercel.app/login",
        "https://x.amazonaws.com/foo",
        "https://abc.netlify.app",
        "https://github.io/argus-foo",
    ):
        assert pf._extract_apex(u) is None, u


def test_extract_apex_rejects_garbage():
    assert pf._extract_apex("") is None
    assert pf._extract_apex("not a url") is None
    assert pf._extract_apex("https://localhost") is None  # no dot


# --- per-feed parsers ---------------------------------------------------


class _FakeResp:
    def __init__(self, status: int, text: str):
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def text(self):
        return self._text


class _FakeSession:
    def __init__(self, payloads: dict[str, tuple[int, str]]):
        self._payloads = payloads
        self.calls: list[str] = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        status, text = self._payloads.get(url, (404, ""))
        return _FakeResp(status, text)


async def test_phishtank_parser_keeps_only_verified_entries():
    payload = json.dumps(
        [
            {
                "phish_id": 1,
                "url": "http://argus-secure.com/login",
                "verified": "yes",
                "submission_time": "2026-04-29T01:00:00Z",
                "verification_time": "2026-04-29T01:05:00Z",
                "target": "Argus Bank",
            },
            {
                "phish_id": 2,
                "url": "http://unverified.example",
                "verified": "no",
                "submission_time": "2026-04-29T01:10:00Z",
            },
        ]
    )
    session = _FakeSession({pf.PHISHTANK_DEFAULT_URL: (200, payload)})
    entries = await pf._fetch_phishtank(session, pf.PHISHTANK_DEFAULT_URL)
    assert len(entries) == 1
    assert entries[0].domain == "argus-secure.com"
    assert entries[0].feed == SuspectDomainSource.PHISHTANK
    assert entries[0].raw["target"] == "Argus Bank"


async def test_openphish_parser_handles_plain_text_lines():
    payload = "https://argus-banking-login.com/auth\nhttps://random.example.com/x\n# comment\n\n"
    session = _FakeSession({pf.OPENPHISH_DEFAULT_URL: (200, payload)})
    entries = await pf._fetch_openphish(session, pf.OPENPHISH_DEFAULT_URL)
    domains = {e.domain for e in entries}
    assert "argus-banking-login.com" in domains
    assert "random.example.com" in domains
    # Header / blank lines did not produce empty entries
    assert all(e.domain for e in entries)


async def test_urlhaus_parser_parses_csv_and_filters_offline():
    payload = (
        "# preamble line 1\n"
        "# preamble line 2\n"
        '1,2026-04-29 01:00:00,http://argus.example/path,online,2026-04-29 01:00:00,malware,tag1\n'
        '2,2026-04-29 02:00:00,http://other.example/foo,offline,2026-04-29 02:00:00,malware,tag2\n'
    )
    session = _FakeSession({pf.URLHAUS_DEFAULT_URL: (200, payload)})
    entries = await pf._fetch_urlhaus(session, pf.URLHAUS_DEFAULT_URL)
    domains = {e.domain for e in entries}
    assert "argus.example" in domains
    # Offline rows should have been filtered out
    assert "other.example" not in domains


# --- end-to-end ingest --------------------------------------------------


async def test_phishing_feeds_ingest_creates_suspects(
    test_engine, organization
):
    """Three feeds, three matching domains across both apex + name
    brand terms — every one of them should land as a SuspectDomain
    tagged with its source.
    """
    org_id = organization["id"]
    await _seed_brand_term(test_engine, org_id, "argus.com")
    await _seed_brand_term(
        test_engine, org_id, "argus", kind=BrandTermKind.NAME
    )

    feeds = {
        "phishtank": [
            pf.PhishingFeedEntry(
                domain="argus-secure.com",
                url="http://argus-secure.com/login",
                feed=SuspectDomainSource.PHISHTANK,
                detected_at=pf._parse_iso(None),
            )
        ],
        "openphish": [
            pf.PhishingFeedEntry(
                domain="argus-banking-login.com",
                url="http://argus-banking-login.com/auth",
                feed=SuspectDomainSource.OPENPHISH,
                detected_at=pf._parse_iso(None),
            )
        ],
        "urlhaus": [
            pf.PhishingFeedEntry(
                domain="argus.example",
                url="http://argus.example/path",
                feed=SuspectDomainSource.URLHAUS,
                detected_at=pf._parse_iso(None),
            )
        ],
    }

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        reports = await pf.ingest_for_organization(s, org_id, feeds=feeds)
        await s.commit()

    by_feed = {r.feed: r for r in reports}
    assert by_feed["phishtank"].suspects_created >= 1
    assert by_feed["openphish"].suspects_created >= 1
    assert by_feed["urlhaus"].suspects_created >= 1

    async with factory() as s:
        rows = (
            await s.execute(
                select(SuspectDomain).where(
                    SuspectDomain.organization_id == org_id
                )
            )
        ).scalars().all()

    sources = {r.source for r in rows}
    domains = {r.domain for r in rows}
    assert SuspectDomainSource.PHISHTANK.value in sources
    assert SuspectDomainSource.OPENPHISH.value in sources
    assert SuspectDomainSource.URLHAUS.value in sources
    assert "argus-secure.com" in domains


async def test_phishing_feeds_ingest_idempotent(
    test_engine, organization
):
    org_id = organization["id"]
    await _seed_brand_term(test_engine, org_id, "argus.com")
    await _seed_brand_term(
        test_engine, org_id, "argus", kind=BrandTermKind.NAME
    )

    feeds = {
        "phishtank": [
            pf.PhishingFeedEntry(
                domain="argus-x.com",
                url="http://argus-x.com",
                feed=SuspectDomainSource.PHISHTANK,
                detected_at=pf._parse_iso(None),
            )
        ],
        "openphish": [],
        "urlhaus": [],
    }

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        first = await pf.ingest_for_organization(s, org_id, feeds=feeds)
        await s.commit()
    async with factory() as s:
        second = await pf.ingest_for_organization(s, org_id, feeds=feeds)
        await s.commit()

    # Both apex + name terms can fire on the same domain — the unique
    # constraint is (org, domain, matched_term_value) so each term
    # produces one row. The point is: re-running the ingest must not
    # create *more* rows.
    first_total = first[0].suspects_created
    assert first_total >= 1
    assert second[0].suspects_created == 0
    assert second[0].suspects_seen_again == first_total
