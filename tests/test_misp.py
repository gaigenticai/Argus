"""PyMISP integration (P2 #2.11) — unit tests with stubbed MISP.

Real PyMISP isn't called against a live server; the wrapper is
exercised by stubbing :func:`get_client` to return a fake that mimics
the parts of the PyMISP surface we use.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.integrations import misp as misp_mod
from src.integrations.misp import (
    MispAttribute,
    MispEvent,
    MispGalaxyCluster,
    fetch_event_attributes,
    fetch_galaxy_clusters,
    fetch_recent_events,
    is_configured,
)

pytestmark = pytest.mark.asyncio


# ── Configuration ────────────────────────────────────────────────────


def test_is_configured_false_without_env(monkeypatch):
    monkeypatch.delenv("ARGUS_MISP_URL", raising=False)
    monkeypatch.delenv("ARGUS_MISP_KEY", raising=False)
    misp_mod.reset_client()
    assert is_configured() is False


def test_is_configured_true_with_env(monkeypatch):
    monkeypatch.setenv("ARGUS_MISP_URL", "https://misp.example.org")
    monkeypatch.setenv("ARGUS_MISP_KEY", "fakekey")
    misp_mod.reset_client()
    assert is_configured() is True


def test_get_client_returns_none_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_MISP_URL", raising=False)
    monkeypatch.delenv("ARGUS_MISP_KEY", raising=False)
    misp_mod.reset_client()
    assert misp_mod.get_client() is None


def test_fetch_returns_empty_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_MISP_URL", raising=False)
    monkeypatch.delenv("ARGUS_MISP_KEY", raising=False)
    misp_mod.reset_client()
    assert fetch_recent_events() == []
    assert fetch_event_attributes("any-uuid") == []
    assert fetch_galaxy_clusters() == []


# ── Stubbed PyMISP client ────────────────────────────────────────────


class _FakeClient:
    """Records the calls made and returns canned responses."""

    def __init__(self, *, events=None, event_detail=None, clusters=None):
        self._events = events or []
        self._event_detail = event_detail or {}
        self._clusters = clusters or []
        self.last_search_kwargs = None
        self.last_event_uuid = None
        self.last_galaxy = None

    def search(self, **kwargs):
        self.last_search_kwargs = kwargs
        return self._events

    def get_event(self, uuid, pythonify=True):
        self.last_event_uuid = uuid
        return self._event_detail

    def search_galaxy_clusters(self, galaxy, pythonify=True):
        self.last_galaxy = galaxy
        return self._clusters


@pytest.fixture
def stub_client(monkeypatch):
    monkeypatch.setenv("ARGUS_MISP_URL", "https://misp.example.org")
    monkeypatch.setenv("ARGUS_MISP_KEY", "fakekey")
    misp_mod.reset_client()
    fake = _FakeClient()
    with patch.object(misp_mod, "get_client", lambda: fake):
        yield fake


# ── Events ───────────────────────────────────────────────────────────


def test_fetch_events_with_tag_passes_through(stub_client):
    stub_client._events = [
        {"Event": {
            "uuid": "ev-1", "info": "MuddyWater spearphishing wave",
            "threat_level_id": "1", "date": "2026-04-30",
            "attribute_count": 12,
            "Tag": [{"name": "tlp:green"},
                    {"name": "misp-galaxy:threat-actor=\"MuddyWater\""}],
        }},
    ]
    events = fetch_recent_events(days=14, tag="tlp:green", limit=20)
    assert len(events) == 1
    assert isinstance(events[0], MispEvent)
    assert events[0].uuid == "ev-1"
    assert "tlp:green" in events[0].tags
    assert events[0].attribute_count == 12

    # Verify the stub got the right search args.
    sk = stub_client.last_search_kwargs
    assert sk["tags"] == "tlp:green"
    assert sk["limit"] == 20
    assert sk["last"] == "14d"


def test_fetch_events_handles_search_failure(stub_client):
    def _boom(**kwargs):
        raise RuntimeError("MISP unreachable")
    stub_client.search = _boom  # type: ignore[method-assign]
    assert fetch_recent_events() == []


def test_fetch_events_to_dict_round_trip(stub_client):
    stub_client._events = [
        {"Event": {"uuid": "ev-1", "info": "x", "date": "2026-01-01",
                    "attribute_count": 0}},
    ]
    events = fetch_recent_events()
    d = events[0].to_dict()
    assert set(d.keys()) >= {"uuid", "info", "tags", "attribute_count"}


# ── Attributes ───────────────────────────────────────────────────────


def test_fetch_event_attributes_filters_to_ids(stub_client):
    stub_client._event_detail = {
        "Event": {
            "uuid": "ev-1", "info": "x", "date": "2026-01-01",
            "Attribute": [
                {"uuid": "a-1", "type": "ip-dst", "category": "Network activity",
                 "value": "203.0.113.7", "comment": "C2", "to_ids": True,
                 "Tag": [{"name": "tlp:amber"}]},
                {"uuid": "a-2", "type": "filename", "value": "ignored.txt",
                 "comment": None, "to_ids": False},
            ],
        },
    }
    attrs = fetch_event_attributes("ev-1")
    assert len(attrs) == 1
    assert attrs[0].uuid == "a-1"
    assert attrs[0].type == "ip-dst"
    assert "tlp:amber" in attrs[0].tags
    # to_ids_only=False returns both.
    attrs_all = fetch_event_attributes("ev-1", to_ids_only=False)
    assert len(attrs_all) == 2


# ── Galaxy clusters ──────────────────────────────────────────────────


def test_fetch_galaxy_clusters(stub_client):
    stub_client._clusters = [
        {"GalaxyCluster": {
            "uuid": "cl-1", "value": "APT34",
            "description": "Iranian state actor",
        }},
        {"GalaxyCluster": {"uuid": "cl-2", "value": "MuddyWater"}},
    ]
    clusters = fetch_galaxy_clusters("threat-actor")
    assert len(clusters) == 2
    assert isinstance(clusters[0], MispGalaxyCluster)
    assert clusters[0].name == "APT34"
    assert stub_client.last_galaxy == "threat-actor"


# ── HTTP routes ──────────────────────────────────────────────────────


async def test_misp_availability_route(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_MISP_URL", raising=False)
    monkeypatch.delenv("ARGUS_MISP_KEY", raising=False)
    misp_mod.reset_client()
    r = await client.get(
        "/api/v1/intel/misp/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json() == {"configured": False}


async def test_misp_events_route_when_unconfigured(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_MISP_URL", raising=False)
    monkeypatch.delenv("ARGUS_MISP_KEY", raising=False)
    misp_mod.reset_client()
    r = await client.get(
        "/api/v1/intel/misp/events?days=7&limit=10",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json() == {"events": []}


async def test_misp_route_requires_auth(client):
    r = await client.get("/api/v1/intel/misp/availability")
    assert r.status_code in (401, 403)
