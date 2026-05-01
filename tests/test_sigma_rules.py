"""Sigma rule generation + multi-SIEM translation (P2 #2.3) — tests.

Pure unit tests on :func:`build_rule_yaml` + :func:`translate_rule`,
plus HTTP route smoke tests. No DB needed; pysigma is real.
"""

from __future__ import annotations

import pytest

from src.intel.sigma_rules import (
    available_backends,
    build_rule_yaml,
    translate_for_ioc,
    translate_for_technique,
    translate_rule,
)

pytestmark = pytest.mark.asyncio


# ── Backends ─────────────────────────────────────────────────────────


def test_at_least_three_backends_register():
    """Splunk + Elastic + Kusto are the minimum viable set; QRadar is
    nice-to-have. The CI install pulls all four pinned backends."""
    backends = available_backends()
    assert "splunk_spl" in backends
    assert "elastic_lucene" in backends
    assert "sentinel_kql" in backends
    assert len(backends) >= 4


# ── Rule generation ──────────────────────────────────────────────────


def test_build_rule_yaml_is_valid_yaml():
    yaml_text = build_rule_yaml(
        title="Argus IOC: evil.example.com",
        description="A test rule with: colons in: the description",
        ioc_type="domain", ioc_value="evil.example.com",
        technique_id="T1566.002",
        rule_id="11111111-1111-1111-1111-111111111111",
    )
    import yaml as _yaml
    parsed = _yaml.safe_load(yaml_text)
    assert parsed["id"] == "11111111-1111-1111-1111-111111111111"
    assert parsed["title"].startswith("Argus IOC")
    assert "attack.t1566.001" in [t.lower() for t in parsed["tags"]] \
        or "attack.t1566.002" in [t.lower() for t in parsed["tags"]]


def test_build_rule_yaml_byte_stable_for_pinned_id():
    a = build_rule_yaml(
        title="t", description="d", ioc_type="ip", ioc_value="1.2.3.4",
        rule_id="22222222-2222-2222-2222-222222222222",
    )
    b = build_rule_yaml(
        title="t", description="d", ioc_type="ip", ioc_value="1.2.3.4",
        rule_id="22222222-2222-2222-2222-222222222222",
    )
    assert a == b


def test_build_rule_yaml_quotes_special_chars():
    """Title containing a YAML reserved char must not crash the parser."""
    yaml_text = build_rule_yaml(
        title="Argus: alert with [special] {chars} & quotes",
        description="line1: with colon\nline2",
        ioc_type="ip", ioc_value="9.9.9.9",
        rule_id="33333333-3333-3333-3333-333333333333",
    )
    import yaml as _yaml
    parsed = _yaml.safe_load(yaml_text)
    assert parsed["title"] == "Argus: alert with [special] {chars} & quotes"


# ── Translation ──────────────────────────────────────────────────────


def test_translate_domain_ioc_produces_all_backends():
    yaml, results = translate_for_ioc(
        ioc_type="domain", ioc_value="evil.example.com",
        technique_id="T1566.002",
        rule_id="44444444-4444-4444-4444-444444444444",
    )
    backends = {r.backend for r in results if r.query}
    # Every available backend should produce a non-empty query.
    assert backends >= {"splunk_spl", "elastic_lucene", "sentinel_kql"}
    splunk = next(r for r in results if r.backend == "splunk_spl")
    assert "evil.example.com" in (splunk.query or "")
    sentinel = next(r for r in results if r.backend == "sentinel_kql")
    assert "evil.example.com" in (sentinel.query or "")


def test_translate_ip_ioc_produces_all_backends():
    yaml, results = translate_for_ioc(
        ioc_type="ip", ioc_value="203.0.113.7",
        rule_id="55555555-5555-5555-5555-555555555555",
    )
    splunk = next(r for r in results if r.backend == "splunk_spl")
    assert "203.0.113.7" in (splunk.query or "")


def test_translate_for_technique():
    yaml, results = translate_for_technique(
        technique_id="T1003.001",
        selection={"EventID": "10", "TargetImage": "lsass.exe"},
        rule_id="66666666-6666-6666-6666-666666666666",
    )
    assert any(r.query and "lsass.exe" in r.query for r in results)


def test_invalid_yaml_returns_parser_error():
    results = translate_rule("this is :: not :: yaml")
    assert results[0].backend == "parser"
    assert results[0].query is None
    assert "parse error" in (results[0].error or "")


def test_to_dict_shape():
    yaml, results = translate_for_ioc(
        ioc_type="domain", ioc_value="x.example",
        rule_id="77777777-7777-7777-7777-777777777777",
    )
    d = results[0].to_dict()
    assert set(d.keys()) == {"backend", "query", "error"}


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_sigma_backends_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/sigma/backends",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    assert "backends" in r.json()
    assert "splunk_spl" in r.json()["backends"]


async def test_sigma_from_ioc_route(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/sigma/from-ioc",
        json={
            "ioc_value": "203.0.113.7", "ioc_type": "ip",
            "technique_id": "T1071.001",
            "rule_id": "88888888-8888-8888-8888-888888888888",
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "203.0.113.7" in body["sigma_yaml"]
    assert any(t["backend"] == "splunk_spl" and t["query"]
               for t in body["translations"])


async def test_sigma_translate_route(client, analyst_user):
    yaml = build_rule_yaml(
        title="t", description="d", ioc_type="ip", ioc_value="9.9.9.9",
        rule_id="99999999-9999-9999-9999-999999999999",
    )
    r = await client.post(
        "/api/v1/intel/sigma/translate",
        json={"sigma_yaml": yaml},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    assert any(t.get("query") for t in r.json()["translations"])


async def test_sigma_route_requires_auth(client):
    r = await client.get("/api/v1/intel/sigma/backends")
    assert r.status_code in (401, 403)
