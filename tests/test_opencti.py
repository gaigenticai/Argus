"""OpenCTI integration (P2 #2.1) — unit tests with stubbed pycti.

We don't hit a live OpenCTI server. The wrapper's high-level entry
points are tested by stubbing :func:`get_client` to return a fake that
implements the parts of pycti's surface we use.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.integrations.opencti import projection as opencti_mod
from src.integrations.opencti import (
    GraphEdge,
    GraphNode,
    Neighbourhood,
    ProjectionResult,
    _stix_pattern_for,
    fetch_neighbourhood,
    is_configured,
    project_actor,
    project_alert,
    project_case,
    project_ioc,
)

pytestmark = pytest.mark.asyncio


# ── Configuration ────────────────────────────────────────────────────


def test_is_configured_false_without_env(monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    assert is_configured() is False


def test_is_configured_true_with_env(monkeypatch):
    monkeypatch.setenv("ARGUS_OPENCTI_URL", "https://opencti.example.org")
    monkeypatch.setenv("ARGUS_OPENCTI_TOKEN", "fake-token")
    opencti_mod.reset_client()
    assert is_configured() is True


def test_get_client_returns_none_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    assert opencti_mod.get_client() is None


# ── STIX pattern map ────────────────────────────────────────────────


@pytest.mark.parametrize("ioc_type,value,expected", [
    ("ipv4", "203.0.113.7", "[ipv4-addr:value = '203.0.113.7']"),
    ("ipv6", "::1", "[ipv6-addr:value = '::1']"),
    ("domain", "evil.example.com",
     "[domain-name:value = 'evil.example.com']"),
    ("url", "https://evil/login", "[url:value = 'https://evil/login']"),
    ("md5", "a" * 32, f"[file:hashes.MD5 = '{'a' * 32}']"),
    ("sha1", "b" * 40, f"[file:hashes.'SHA-1' = '{'b' * 40}']"),
    ("sha256", "c" * 64, f"[file:hashes.'SHA-256' = '{'c' * 64}']"),
    ("email", "phisher@evil",
     "[email-addr:value = 'phisher@evil']"),
])
def test_stix_pattern_known_types(ioc_type, value, expected):
    assert _stix_pattern_for(ioc_type, value) == expected


def test_stix_pattern_unknown_type_returns_none():
    assert _stix_pattern_for("btc_address", "1A1z…") is None


def test_stix_pattern_quotes_apostrophes():
    p = _stix_pattern_for("domain", "ev'il.example.com")
    assert "ev''il.example.com" in p


# ── Stubbed pycti client ────────────────────────────────────────────


class _Stub:
    def __init__(self, response):
        self.response = response
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response

    def list(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class _FakeOpenCTIClient:
    def __init__(self):
        self.indicator = _Stub({"standard_id": "indicator--abc"})
        self.threat_actor = _Stub({"standard_id": "threat-actor--def"})
        self.note = _Stub({"standard_id": "note--ghi"})
        self.case_incident = _Stub({"standard_id": "case-incident--jkl"})
        self.stix_core_relationship = _Stub({"standard_id": "rel--mno"})


@pytest.fixture
def stub_client(monkeypatch):
    monkeypatch.setenv("ARGUS_OPENCTI_URL", "https://opencti.example.org")
    monkeypatch.setenv("ARGUS_OPENCTI_TOKEN", "fake-token")
    opencti_mod.reset_client()
    fake = _FakeOpenCTIClient()
    with patch.object(opencti_mod, "get_client", lambda: fake):
        yield fake


# ── Projection ──────────────────────────────────────────────────────


def test_project_ioc_creates_indicator(stub_client):
    r = project_ioc(ioc_type="ipv4", value="203.0.113.7", confidence=80)
    assert isinstance(r, ProjectionResult)
    assert r.success is True
    assert r.stix_id == "indicator--abc"
    # Pattern got synthesised correctly.
    call = stub_client.indicator.calls[0]
    assert call["pattern"] == "[ipv4-addr:value = '203.0.113.7']"
    assert call["confidence"] == 80


def test_project_ioc_with_actor_alias_creates_relationship(stub_client):
    r = project_ioc(ioc_type="domain", value="evil.example.com",
                     actor_alias="APT34")
    assert r.success is True
    # Relationship was attempted.
    rel_calls = stub_client.stix_core_relationship.calls
    assert len(rel_calls) == 1
    assert rel_calls[0]["relationship_type"] == "indicates"
    assert rel_calls[0]["fromId"] == "indicator--abc"
    assert rel_calls[0]["toId"] == "threat-actor--def"


def test_project_ioc_unsupported_type_fails_softly(stub_client):
    r = project_ioc(ioc_type="btc_address", value="1A1zP1...")
    assert r.success is False
    assert r.error and "unsupported" in r.error.lower()


def test_project_ioc_unconfigured_returns_note(monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    r = project_ioc(ioc_type="ipv4", value="1.2.3.4")
    assert r.success is False
    assert "not configured" in (r.note or "").lower()


def test_project_actor(stub_client):
    r = project_actor(primary_alias="APT34", aliases=["OilRig"],
                       description="Iranian state actor")
    assert r.success is True
    assert r.stix_id == "threat-actor--def"
    call = stub_client.threat_actor.calls[0]
    assert call["name"] == "APT34"
    assert call["aliases"] == ["OilRig"]


def test_project_alert(stub_client):
    r = project_alert(
        alert_id="alert-uuid", title="Phishing wave",
        summary="Spearphishing detected", severity="high",
        category="phishing",
    )
    assert r.success is True
    assert r.stix_id == "note--ghi"
    call = stub_client.note.calls[0]
    assert call["confidence"] == 80  # high → 80
    assert call["x_opencti_argus_alert_id"] == "alert-uuid"


def test_project_case(stub_client):
    r = project_case(case_id="case-uuid", title="Investigate APT34",
                      severity="critical")
    assert r.success is True
    assert r.stix_id == "case-incident--jkl"


# ── Read-only graph proxy ───────────────────────────────────────────


def test_fetch_neighbourhood_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    n = fetch_neighbourhood(stix_id="indicator--abc")
    assert isinstance(n, Neighbourhood)
    assert n.root is None
    assert n.nodes == []
    assert n.edges == []
    assert n.note and "not configured" in n.note.lower()


def test_fetch_neighbourhood_normalises_relationships(stub_client):
    stub_client.stix_core_relationship.response = [
        {
            "relationship_type": "indicates",
            "from": {"standard_id": "indicator--abc",
                      "entity_type": "Indicator",
                      "value": "203.0.113.7"},
            "to": {"standard_id": "threat-actor--def",
                    "entity_type": "Threat-Actor", "name": "APT34"},
        },
        {
            "relationship_type": "uses",
            "from": {"standard_id": "threat-actor--def",
                      "entity_type": "Threat-Actor", "name": "APT34"},
            "to": {"standard_id": "attack-pattern--xyz",
                    "entity_type": "Attack-Pattern", "name": "T1071"},
        },
    ]
    n = fetch_neighbourhood(stix_id="threat-actor--def")
    assert len(n.nodes) == 3
    assert len(n.edges) == 2
    assert isinstance(n.nodes[0], GraphNode)
    assert any(e.relationship_type == "uses" for e in n.edges)
    # Root is the requested entity.
    assert n.root is not None
    assert n.root.id == "threat-actor--def"


def test_fetch_neighbourhood_handles_upstream_error(stub_client):
    def _boom(**kwargs):
        raise RuntimeError("opencti unreachable")
    stub_client.stix_core_relationship.list = _boom  # type: ignore[method-assign]
    n = fetch_neighbourhood(stix_id="indicator--abc")
    assert n.note and "fetch failed" in n.note.lower()
    assert n.nodes == []


# ── HTTP routes ──────────────────────────────────────────────────────


async def test_opencti_availability_route(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    r = await client.get(
        "/api/v1/intel/opencti/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json() == {"configured": False}


async def test_opencti_graph_route_unconfigured(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    r = await client.get(
        "/api/v1/intel/opencti/graph/indicator--abc",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == []
    assert "not configured" in (body["note"] or "").lower()


async def test_opencti_project_ioc_unconfigured(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_OPENCTI_URL", raising=False)
    monkeypatch.delenv("ARGUS_OPENCTI_TOKEN", raising=False)
    opencti_mod.reset_client()
    r = await client.post(
        "/api/v1/intel/opencti/project/ioc",
        json={"ioc_type": "ipv4", "value": "203.0.113.7"},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_opencti_route_requires_auth(client):
    r = await client.get("/api/v1/intel/opencti/availability")
    assert r.status_code in (401, 403)
