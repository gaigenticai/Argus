"""TAXII 2.1 publish surface (P3 #3.4) — integration tests.

Exercises the IOC → STIX 2.1 indicator translator (pure function),
plus every TAXII 2.1 endpoint against a real Postgres + a real
FastAPI app via the asgi-lifespan harness.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations.taxii_publish import (
    api_root_resource,
    collection_id_for_org,
    discovery_resource,
    envelope,
    fetch_indicators,
    ioc_to_stix_indicator,
    parse_added_after,
)
from src.models.intel import IOC

pytestmark = pytest.mark.asyncio


# ── IOC → STIX indicator pure-function ───────────────────────────────


class _StubIOC:
    """Minimal duck-type for ioc_to_stix_indicator's input contract."""

    def __init__(
        self, ioc_type: str, value: str,
        *,
        confidence: float = 0.9,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        tags: list[str] | None = None,
        ioc_id: str | None = None,
    ):
        self.id = ioc_id or "test-ioc-id"
        self.ioc_type = ioc_type
        self.value = value
        self.confidence = confidence
        now = datetime.now(timezone.utc)
        self.first_seen = first_seen or now
        self.last_seen = last_seen or now
        self.tags = tags or []


@pytest.mark.parametrize("ioc_type,value,pattern", [
    ("ipv4", "203.0.113.7", "[ipv4-addr:value = '203.0.113.7']"),
    ("ipv6", "::1", "[ipv6-addr:value = '::1']"),
    ("domain", "evil.example.com",
     "[domain-name:value = 'evil.example.com']"),
    ("url", "https://evil/login", "[url:value = 'https://evil/login']"),
    ("md5", "a" * 32, f"[file:hashes.MD5 = '{'a' * 32}']"),
    ("sha1", "b" * 40, f"[file:hashes.'SHA-1' = '{'b' * 40}']"),
    ("sha256", "c" * 64, f"[file:hashes.'SHA-256' = '{'c' * 64}']"),
    ("email", "phisher@example",
     "[email-addr:value = 'phisher@example']"),
])
def test_ioc_to_stix_pattern(ioc_type, value, pattern):
    ioc = _StubIOC(ioc_type, value)
    sdo = ioc_to_stix_indicator(ioc)
    assert sdo is not None
    assert sdo["pattern"] == pattern
    assert sdo["pattern_type"] == "stix"
    assert sdo["spec_version"] == "2.1"
    assert sdo["type"] == "indicator"
    assert sdo["id"].startswith("indicator--")


def test_ioc_to_stix_unsupported_type_returns_none():
    ioc = _StubIOC("btc_address", "1A1zP1...")
    assert ioc_to_stix_indicator(ioc) is None


def test_ioc_indicator_id_is_stable_across_calls():
    """A stable id is required so subscribers dedup by id alone."""
    ioc = _StubIOC("ipv4", "1.2.3.4", ioc_id="fixed-id")
    a = ioc_to_stix_indicator(ioc)
    b = ioc_to_stix_indicator(ioc)
    assert a["id"] == b["id"]


def test_ioc_indicator_confidence_int_0_100():
    ioc = _StubIOC("ipv4", "1.2.3.4", confidence=0.42)
    sdo = ioc_to_stix_indicator(ioc)
    assert sdo["confidence"] == 42


def test_ioc_indicator_quotes_apostrophes_in_value():
    ioc = _StubIOC("domain", "ev'il.example.com")
    sdo = ioc_to_stix_indicator(ioc)
    assert "ev''il.example.com" in sdo["pattern"]


# ── Discovery / API root resources ──────────────────────────────────


def test_discovery_resource_shape():
    d = discovery_resource(base_url="https://argus.example.com")
    assert d["title"]
    assert d["default"].endswith("/taxii2/api/")
    assert d["api_roots"] == [d["default"]]


def test_api_root_resource_advertises_2_1():
    r = api_root_resource()
    assert "taxii-2.1" in r["versions"]
    assert r["max_content_length"] >= 1024 * 1024


# ── added_after parsing ─────────────────────────────────────────────


@pytest.mark.parametrize("s,ok", [
    ("2026-04-30T12:00:00Z", True),
    ("2026-04-30T12:00:00.123Z", True),
    ("2026-04-30T12:00:00+00:00", True),
    ("2026-04-30T12:00:00", True),
    ("2026/04/30 12:00:00", False),     # wrong separator
    ("not-a-date", False),
    ("", False),
    (None, False),
])
def test_parse_added_after(s, ok):
    out = parse_added_after(s)
    if ok:
        assert isinstance(out, datetime)
    else:
        assert out is None


# ── Real DB fetch_indicators ─────────────────────────────────────────


async def test_fetch_indicators_filters_by_added_after(
    session: AsyncSession, organization,
):
    now = datetime.now(timezone.utc)
    # Two IOCs, one old one fresh.
    session.add(IOC(
        ioc_type="ipv4", value="198.51.100.1",
        confidence=0.9,
        first_seen=now - timedelta(days=10),
        last_seen=now - timedelta(days=10),
    ))
    session.add(IOC(
        ioc_type="domain", value="evil.example.com",
        confidence=0.9,
        first_seen=now - timedelta(days=1),
        last_seen=now - timedelta(days=1),
    ))
    await session.flush()

    all_iocs = await fetch_indicators(
        session, organization_id=organization["id"],
    )
    assert len(all_iocs) >= 2

    fresh_only = await fetch_indicators(
        session,
        organization_id=organization["id"],
        added_after=now - timedelta(days=3),
    )
    fresh_values = {i.get("name") for i in fresh_only}
    assert any("evil.example.com" in v for v in fresh_values)
    assert not any("198.51.100.1" in v for v in fresh_values)


async def test_fetch_indicators_drops_unsupported_ioc_types(
    session: AsyncSession, organization,
):
    now = datetime.now(timezone.utc)
    session.add(IOC(
        ioc_type="btc_address", value="1A1zP1...",
        confidence=0.5,
        first_seen=now, last_seen=now,
    ))
    await session.flush()
    out = await fetch_indicators(
        session, organization_id=organization["id"],
    )
    # btc_address has no STIX 2.1 mapping → filtered out.
    for ind in out:
        assert "btc_address" not in ind.get("name", "")


# ── Envelope ────────────────────────────────────────────────────────


def test_envelope_wraps_objects():
    env = envelope(indicators=[
        {"id": "indicator--1", "type": "indicator"},
        {"id": "indicator--2", "type": "indicator"},
    ])
    assert env["more"] is False
    assert len(env["objects"]) == 2


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_taxii_discovery_route(client, analyst_user):
    r = await client.get("/taxii2/", headers=analyst_user["headers"])
    assert r.status_code == 200
    body = r.json()
    assert "api_roots" in body
    assert body["default"].endswith("/taxii2/api/")


async def test_taxii_api_root_route(client, analyst_user):
    r = await client.get("/taxii2/api/", headers=analyst_user["headers"])
    assert r.status_code == 200
    assert "taxii-2.1" in r.json()["versions"]


async def test_taxii_collections_list(client, analyst_user):
    r = await client.get(
        "/taxii2/api/collections/", headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["collections"]) == 1


async def test_taxii_collection_objects_includes_iocs(
    client, analyst_user, test_engine,
):
    """Insert one IOC tied to the system org, then assert the TAXII
    objects endpoint surfaces it as a STIX indicator."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    from src.core.tenant import get_system_org_id

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        org_id = await get_system_org_id(s)
        now = datetime.now(timezone.utc)
        s.add(IOC(
            ioc_type="ipv4",
            value=f"203.0.113.{(int(uuid.uuid4()) % 250) + 1}",
            confidence=0.9, first_seen=now, last_seen=now,
        ))
        await s.commit()

    cid = collection_id_for_org(org_id)
    r = await client.get(
        f"/taxii2/api/collections/{cid}/objects/?limit=10",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "objects" in body
    # All returned objects are STIX 2.1 indicator SDOs.
    for obj in body["objects"]:
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"


async def test_taxii_collection_404_for_unknown_id(client, analyst_user):
    bogus = "00000000-0000-0000-0000-000000000000"
    r = await client.get(
        f"/taxii2/api/collections/{bogus}/",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_taxii_invalid_added_after_returns_400(
    client, analyst_user, test_engine,
):
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    from src.core.tenant import get_system_org_id

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        org_id = await get_system_org_id(s)
    cid = collection_id_for_org(org_id)
    r = await client.get(
        f"/taxii2/api/collections/{cid}/objects/?added_after=not-iso",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 400


async def test_taxii_route_requires_auth(client):
    r = await client.get("/taxii2/")
    assert r.status_code in (401, 403)


# ── TAXII 2.1 §1.6.6 content negotiation ────────────────────────────


async def test_taxii_response_content_type_is_versioned(client, analyst_user):
    """Discovery returns Content-Type: application/taxii+json;version=2.1."""
    r = await client.get("/taxii2/", headers=analyst_user["headers"])
    assert r.status_code == 200
    ct = r.headers["content-type"].lower().replace(" ", "")
    assert ct.startswith("application/taxii+json"), ct
    assert "version=2.1" in ct, ct


async def test_taxii_accept_versioned_taxii_json(client, analyst_user):
    r = await client.get(
        "/taxii2/api/",
        headers={
            **analyst_user["headers"],
            "Accept": "application/taxii+json;version=2.1",
        },
    )
    assert r.status_code == 200
    ct = r.headers["content-type"].lower().replace(" ", "")
    assert "application/taxii+json" in ct


async def test_taxii_rejects_incompatible_accept_header(
    client, analyst_user,
):
    r = await client.get(
        "/taxii2/api/",
        headers={
            **analyst_user["headers"],
            "Accept": "application/xml",
        },
    )
    assert r.status_code == 406


async def test_taxii_objects_accepts_stix_media_type(
    client, analyst_user, session,
):
    """Objects endpoint accepts application/stix+json;version=2.1 and
    advertises that media-type when the client requests it."""
    org_id = await _system_org(session)
    cid = collection_id_for_org(org_id)
    r = await client.get(
        f"/taxii2/api/collections/{cid}/objects/",
        headers={
            **analyst_user["headers"],
            "Accept": "application/stix+json;version=2.1",
        },
    )
    assert r.status_code == 200
    ct = r.headers["content-type"].lower().replace(" ", "")
    assert "application/stix+json" in ct, ct


async def test_taxii_objects_rejects_xml_accept(client, analyst_user, session):
    org_id = await _system_org(session)
    cid = collection_id_for_org(org_id)
    r = await client.get(
        f"/taxii2/api/collections/{cid}/objects/",
        headers={
            **analyst_user["headers"],
            "Accept": "text/xml",
        },
    )
    assert r.status_code == 406


async def test_taxii_objects_emits_date_added_headers(
    client, analyst_user, session, organization,
):
    """X-TAXII-Date-Added-First / Last headers must be set when the
    response carries indicators (TAXII 2.1 §5.4 Table 18)."""
    from datetime import datetime, timedelta, timezone
    from src.models.intel import IOC, IOCType

    org_id = await _system_org(session)
    now = datetime.now(timezone.utc)
    for i, val in enumerate(("9.9.9.1", "9.9.9.2", "9.9.9.3")):
        session.add(IOC(
            ioc_type=IOCType.IPV4, value=val,
            confidence=0.9,
            first_seen=now - timedelta(hours=10),
            last_seen=now - timedelta(minutes=i * 5),
        ))
    await session.commit()

    cid = collection_id_for_org(org_id)
    r = await client.get(
        f"/taxii2/api/collections/{cid}/objects/?limit=50",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert "x-taxii-date-added-first" in r.headers
    assert "x-taxii-date-added-last" in r.headers
    # Newest-first ordering — the "last" timestamp should be ≥ "first".
    first = r.headers["x-taxii-date-added-first"]
    last = r.headers["x-taxii-date-added-last"]
    assert first <= last, (first, last)


async def test_taxii_objects_omits_date_added_when_empty(
    client, analyst_user, session,
):
    """No X-TAXII-Date-Added-* headers when the envelope is empty —
    avoids advertising a fake pagination cursor."""
    org_id = await _system_org(session)
    cid = collection_id_for_org(org_id)
    # Use an added_after far in the future so no indicators match.
    r = await client.get(
        f"/taxii2/api/collections/{cid}/objects/"
        "?added_after=2099-01-01T00:00:00Z",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert "x-taxii-date-added-first" not in r.headers
    assert "x-taxii-date-added-last" not in r.headers


async def test_taxii_accepts_no_explicit_accept_header(client, analyst_user):
    """Curl-style requests with no Accept header still work — only an
    *explicit* incompatible Accept gets a 406."""
    headers = dict(analyst_user["headers"])
    headers.pop("Accept", None)
    r = await client.get("/taxii2/", headers=headers)
    assert r.status_code == 200


async def _system_org(session):
    from src.core.tenant import get_system_org_id
    return await get_system_org_id(session)
