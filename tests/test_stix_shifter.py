"""STIX-Shifter translation (P2 #2.5) — tests.

Pure unit tests on :func:`stix_pattern_for_ioc`, integration tests on
:func:`translate_pattern` against the four installed modules, plus
HTTP route smoke tests.
"""

from __future__ import annotations

import pytest

from src.intel.stix_shifter import (
    available_modules,
    stix_pattern_for_ioc,
    translate_for_ioc,
    translate_pattern,
)

pytestmark = pytest.mark.asyncio


# ── Module discovery ─────────────────────────────────────────────────


def test_at_least_three_modules_register():
    ids = {m["id"] for m in available_modules()}
    # Splunk + Elastic + QRadar are the minimum installed set for CI.
    assert "splunk" in ids
    assert "elastic_ecs" in ids
    assert "qradar" in ids


# ── IOC → STIX pattern ───────────────────────────────────────────────


@pytest.mark.parametrize("ioc_type,value,expected", [
    ("ip", "203.0.113.7", "[ipv4-addr:value = '203.0.113.7']"),
    ("ipv6", "::1", "[ipv6-addr:value = '::1']"),
    ("domain", "evil.example.com",
     "[domain-name:value = 'evil.example.com']"),
    ("url", "https://evil/login",
     "[url:value = 'https://evil/login']"),
    ("email", "phisher@evil.example",
     "[email-addr:value = 'phisher@evil.example']"),
])
def test_stix_pattern_for_simple_iocs(ioc_type, value, expected):
    assert stix_pattern_for_ioc(ioc_type, value) == expected


@pytest.mark.parametrize("digest,algo_field", [
    ("a" * 32, "MD5"),
    ("b" * 40, "'SHA-1'"),
    ("c" * 64, "'SHA-256'"),
])
def test_stix_pattern_routes_hash_by_length(digest, algo_field):
    p = stix_pattern_for_ioc("hash", digest)
    assert algo_field in p
    assert digest in p


def test_stix_pattern_quotes_apostrophes():
    p = stix_pattern_for_ioc("domain", "ex'ample.com")
    assert "ex''ample.com" in p


# ── Real translations ────────────────────────────────────────────────


def test_translate_ip_to_splunk():
    result = translate_pattern(
        "[ipv4-addr:value = '203.0.113.7']", modules=["splunk"],
    )
    assert len(result) == 1
    assert result[0].error is None
    assert any("203.0.113.7" in q for q in result[0].queries)


def test_translate_ip_to_all_available():
    result = translate_pattern(
        "[ipv4-addr:value = '203.0.113.7']",
    )
    by_module = {r.module: r for r in result}
    assert {"splunk", "elastic_ecs", "qradar"} <= by_module.keys()
    # Every successful module's first query mentions the IOC.
    for module in ("splunk", "elastic_ecs", "qradar"):
        if by_module[module].error:
            continue
        assert by_module[module].queries, f"{module} returned empty"
        assert "203.0.113.7" in by_module[module].queries[0]


def test_translate_domain_to_elastic():
    result = translate_pattern(
        "[domain-name:value = 'evil.example.com']", modules=["elastic_ecs"],
    )
    assert result[0].error is None
    assert any("evil.example.com" in q for q in result[0].queries)


def test_translate_invalid_pattern_captures_error():
    result = translate_pattern(
        "::: not a stix pattern :::", modules=["splunk"],
    )
    assert result[0].error is not None
    assert result[0].queries == []


def test_translate_for_ioc_one_shot():
    pattern, results = translate_for_ioc("domain", "x.example.com",
                                          modules=["splunk"])
    assert "x.example.com" in pattern
    assert results[0].error is None


# ── HTTP routes ──────────────────────────────────────────────────────


async def test_stix_modules_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/stix-shifter/modules",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    ids = {m["id"] for m in r.json()["modules"]}
    assert "splunk" in ids


async def test_stix_translate_route(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/stix-shifter/translate",
        json={"stix_pattern": "[ipv4-addr:value = '1.2.3.4']",
              "modules": ["splunk"]},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stix_pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert body["translations"][0]["queries"]
    assert "1.2.3.4" in body["translations"][0]["queries"][0]


async def test_stix_from_ioc_route(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/stix-shifter/from-ioc",
        json={"ioc_type": "ip", "ioc_value": "5.6.7.8",
              "modules": ["splunk"]},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "5.6.7.8" in body["stix_pattern"]
    assert "5.6.7.8" in body["translations"][0]["queries"][0]


async def test_stix_route_requires_auth(client):
    r = await client.get("/api/v1/intel/stix-shifter/modules")
    assert r.status_code in (401, 403)
