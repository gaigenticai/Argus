"""Brand Protection feed (Phase 3.2) — integration tests.

Verifies:
    - apex_domain term matches via Levenshtein on candidate label
    - name term matches via substring (argus → argus-banking.com)
    - name term matches via token (argus → trust-argus.com)
    - very short brand names (< 3 chars) are excluded — anti false-positive
    - feed ingest is idempotent (re-ingest doesn't duplicate suspects)
    - WhoisDS parser handles plain text, gzip, and zip blobs
    - Multipart WhoisDS upload endpoint
    - CertStream message → domain extraction helper
"""

from __future__ import annotations

import gzip
import io
import zipfile

import pytest
from httpx import AsyncClient

from src.brand.feed import (
    domains_from_certstream_message,
    match_domains,
    parse_whoisds_blob,
)
from src.models.brand import BrandTerm, BrandTermKind

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Pure-function matcher --------------------------------------------


def _term(kind: BrandTermKind, value: str) -> BrandTerm:
    """Build an in-memory BrandTerm without persisting it."""
    return BrandTerm(kind=kind.value, value=value.lower(), keywords=[])


def test_matcher_apex_domain_levenshtein_threshold():
    apex = _term(BrandTermKind.APEX_DOMAIN, "argus.com")
    matches = match_domains(
        ["arqus.co", "argu5.com", "totally-unrelated.io"],
        [apex],
        min_similarity=0.7,
    )
    by_domain = {m.domain: m for m in matches}
    assert "argu5.com" in by_domain
    # totally-unrelated has very low similarity to argus.com
    assert "totally-unrelated.io" not in by_domain


def test_matcher_name_substring_and_token():
    name = _term(BrandTermKind.NAME, "argus")
    matches = match_domains(
        [
            "argus-banking.com",   # substring
            "trust-argus.com",     # token (after split on -)
            "argusbanking.com",    # substring
            "abc.com",             # no match
        ],
        [name],
    )
    by_domain = {m.domain for m in matches}
    assert "argus-banking.com" in by_domain
    assert "trust-argus.com" in by_domain
    assert "argusbanking.com" in by_domain
    assert "abc.com" not in by_domain


def test_matcher_short_name_avoids_false_positives():
    # Brand "ai" would be everywhere — must be excluded.
    name = _term(BrandTermKind.NAME, "ai")
    matches = match_domains(
        ["openai.com", "argus.com", "ai-startup.io"],
        [name],
    )
    assert matches == []


def test_matcher_strips_invalid_input():
    apex = _term(BrandTermKind.APEX_DOMAIN, "argus.com")
    matches = match_domains(
        ["", "  ", "not a domain", "argu5.com", None],  # noqa
        [apex],
        min_similarity=0.7,
    )
    domains = {m.domain for m in matches if m.domain}
    assert "argu5.com" in domains
    assert "not a domain" not in domains


# --- WhoisDS parser ---------------------------------------------------


def test_whoisds_plain_text():
    blob = b"argusbank.com\nfakerargus.io\n# comment\n\nbadargus.online\n"
    domains = parse_whoisds_blob(blob)
    assert "argusbank.com" in domains
    assert "fakerargus.io" in domains
    assert "badargus.online" in domains
    assert "# comment" not in " ".join(domains)


def test_whoisds_csv_style():
    blob = b"argusbank.com,2026-04-28\nfakerargus.io\t2026-04-28\n"
    domains = parse_whoisds_blob(blob)
    assert "argusbank.com" in domains
    assert "fakerargus.io" in domains


def test_whoisds_gzip():
    blob = gzip.compress(b"argusbank.com\n")
    assert parse_whoisds_blob(blob) == ["argusbank.com"]


def test_whoisds_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("nrd-2026-04-28.txt", "argusbank.com\nfakerargus.io\n")
    assert sorted(parse_whoisds_blob(buf.getvalue())) == [
        "argusbank.com",
        "fakerargus.io",
    ]


def test_whoisds_zip_without_txt_raises():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.md", "no domains here")
    with pytest.raises(ValueError):
        parse_whoisds_blob(buf.getvalue())


# --- CertStream helper ------------------------------------------------


def test_certstream_extracts_san_domains():
    msg = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": [
                    "argus-banking.com",
                    "*.argus-banking.com",
                    "www.example.org.",
                ]
            }
        },
    }
    domains = domains_from_certstream_message(msg)
    assert sorted(domains) == [
        "argus-banking.com",
        "argus-banking.com",
        "www.example.org",
    ]


def test_certstream_ignores_non_cert_messages():
    assert domains_from_certstream_message({"message_type": "heartbeat"}) == []


# --- API: feed/ingest -------------------------------------------------


async def test_feed_ingest_creates_suspects(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "name",
            "value": "argus",
        },
        headers=_hdr(analyst_user),
    )
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "argus.com",
        },
        headers=_hdr(analyst_user),
    )

    r = await client.post(
        "/api/v1/brand/feed/ingest",
        json={
            "organization_id": str(organization["id"]),
            "source": "certstream",
            "domains": [
                "argus-banking.com",   # name match
                "argu5.com",           # apex match
                "irrelevant.io",       # nope
                "argusbankgroup.io",   # name match
            ],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["candidates"] == 4
    assert body["suspects_created"] >= 3

    listed = await client.get(
        "/api/v1/brand/suspects",
        params={
            "organization_id": str(organization["id"]),
            "source": "certstream",
        },
        headers=_hdr(analyst_user),
    )
    domains = {s["domain"] for s in listed.json()}
    assert {"argus-banking.com", "argu5.com", "argusbankgroup.io"} <= domains
    assert "irrelevant.io" not in domains


async def test_feed_ingest_idempotent(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "name",
            "value": "argus",
        },
        headers=_hdr(analyst_user),
    )
    payload = {
        "organization_id": str(organization["id"]),
        "source": "manual",
        "domains": ["argus-victim.com"],
    }
    first = await client.post(
        "/api/v1/brand/feed/ingest", json=payload, headers=_hdr(analyst_user)
    )
    second = await client.post(
        "/api/v1/brand/feed/ingest", json=payload, headers=_hdr(analyst_user)
    )
    assert first.json()["suspects_created"] == 1
    assert second.json()["suspects_created"] == 0
    assert second.json()["suspects_seen_again"] >= 1


async def test_feed_ingest_no_terms_returns_empty(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/brand/feed/ingest",
        json={
            "organization_id": str(organization["id"]),
            "source": "manual",
            "domains": ["whatever.com"],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["candidates"] == 1
    assert body["suspects_created"] == 0


async def test_feed_whoisds_multipart(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "name",
            "value": "argus",
        },
        headers=_hdr(analyst_user),
    )
    blob = (
        "argus-victim.com\n"
        "fakerargus.io\n"
        "totally-unrelated.com\n"
    ).encode()
    r = await client.post(
        "/api/v1/brand/feed/whoisds",
        data={"organization_id": str(organization["id"])},
        files={"file": ("nrd.txt", io.BytesIO(blob), "text/plain")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["candidates"] == 3
    assert body["suspects_created"] == 2  # the unrelated one is dropped

    listed = await client.get(
        "/api/v1/brand/suspects",
        params={
            "organization_id": str(organization["id"]),
            "source": "whoisds",
        },
        headers=_hdr(analyst_user),
    )
    assert {s["domain"] for s in listed.json()} == {
        "argus-victim.com",
        "fakerargus.io",
    }


async def test_feed_ingest_tenant_scoped(
    client: AsyncClient, analyst_user, organization, second_organization
):
    # Org A has the term
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "name",
            "value": "argus",
        },
        headers=_hdr(analyst_user),
    )
    # Org B has a different one
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(second_organization["id"]),
            "kind": "name",
            "value": "totallyother",
        },
        headers=_hdr(analyst_user),
    )

    domains = ["argus-bait.com"]
    a = await client.post(
        "/api/v1/brand/feed/ingest",
        json={"organization_id": str(organization["id"]), "source": "manual", "domains": domains},
        headers=_hdr(analyst_user),
    )
    b = await client.post(
        "/api/v1/brand/feed/ingest",
        json={"organization_id": str(second_organization["id"]), "source": "manual", "domains": domains},
        headers=_hdr(analyst_user),
    )
    assert a.json()["suspects_created"] == 1
    assert b.json()["suspects_created"] == 0
