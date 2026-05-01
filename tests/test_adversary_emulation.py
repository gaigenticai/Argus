"""Adversary-emulation validation loop (P3 #3.5) — unit + HTTP-route tests.

Covers three pieces:
  - Atomic Red Team curated catalog + filesystem loader
  - Caldera REST client (stubbed aiohttp)
  - Coverage scorer (pure compute)
  - /api/v1/intel/adversary-emulation/* HTTP routes
"""

from __future__ import annotations

import contextlib
import json
import os
from unittest.mock import patch

import pytest

from src.integrations.adversary_emulation import (
    atomic_list_techniques,
    atomic_red_team_available,
    atomic_tests_for,
    caldera_configured,
    coverage_score,
)
from src.integrations.adversary_emulation import atomic_red_team as art_module
from src.integrations.adversary_emulation import caldera as caldera_module
from src.integrations.adversary_emulation.coverage import (
    CoverageEntry,
    CoverageReport,
)

pytestmark = pytest.mark.asyncio


# ── Aiohttp double ──────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = (
            text_body if text_body is not None
            else (json.dumps(json_body) if json_body is not None else "")
        )
        self.request_url: str | None = None
        self.request_method: str | None = None
        self.request_body = None
        self.request_headers: dict[str, str] | None = None
        self.request_params: dict[str, str] | None = None

    async def json(self):
        return self._json

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResp):
        self._response = response

    def get(self, url, **kw):
        return self._call("GET", url, kw)

    def post(self, url, **kw):
        return self._call("POST", url, kw)

    def request(self, method, url, **kw):
        return self._call(method, url, kw)

    def _call(self, method, url, kw):
        self._response.request_method = method
        self._response.request_url = url
        body = kw.get("data") or kw.get("json")
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
        self._response.request_body = body
        self._response.request_headers = kw.get("headers")
        self._response.request_params = kw.get("params")
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(resp: _FakeResp):
    import aiohttp

    def factory(*a, **k):
        return _FakeSession(resp)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


# ── Atomic Red Team — curated catalog ───────────────────────────────


def test_curated_catalog_is_indexed_by_technique(monkeypatch):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    techniques = atomic_list_techniques()
    assert "T1059.001" in techniques
    assert "T1003.001" in techniques
    assert "T1486" in techniques
    # Multiple tests can map to one technique.
    t1059 = atomic_tests_for("T1059.001")
    assert len(t1059) >= 2
    for test in t1059:
        assert test.technique_id == "T1059.001"
        assert test.executor_command
        assert test.executor_type in {
            "powershell", "command_prompt", "bash", "sh",
        }


def test_curated_test_to_dict_round_trip(monkeypatch):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    tests = atomic_tests_for("T1486")
    assert len(tests) == 1
    d = tests[0].to_dict()
    assert d["technique_id"] == "T1486"
    assert "encrypt" in d["description"].lower()
    assert d["source"] == "argus_curated"


def test_unknown_technique_returns_empty_list(monkeypatch):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    assert atomic_tests_for("T9999") == []


def test_available_metadata_reports_curated_state(monkeypatch):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    meta = atomic_red_team_available()
    assert meta["filesystem_path"] is None
    assert meta["filesystem_active"] is False
    assert meta["curated_count"] >= 14
    assert meta["techniques_indexed"] >= 1


def test_filesystem_loader_picks_up_repo(tmp_path, monkeypatch):
    """When ARGUS_ATOMIC_RED_TEAM_PATH points at a real Atomic Red Team
    checkout, that catalog wins over the curated set."""
    pytest.importorskip("yaml")
    import yaml as _yaml

    technique_dir = tmp_path / "T9999"
    technique_dir.mkdir()
    (technique_dir / "T9999.yaml").write_text(_yaml.dump({
        "attack_technique": "T9999",
        "atomic_tests": [{
            "name": "Made-up test",
            "description": "synthetic",
            "supported_platforms": ["linux"],
            "executor": {"name": "bash", "command": "echo synthetic"},
        }],
    }))
    monkeypatch.setenv("ARGUS_ATOMIC_RED_TEAM_PATH", str(tmp_path))
    art_module.reset_cache()
    techniques = atomic_list_techniques()
    assert techniques == ["T9999"]
    tests = atomic_tests_for("T9999")
    assert len(tests) == 1
    assert tests[0].source == "atomic_red_team_filesystem"
    assert tests[0].executor_command == "echo synthetic"
    art_module.reset_cache()


# ── Caldera REST client ─────────────────────────────────────────────


def test_caldera_unconfigured(monkeypatch):
    for k in ("ARGUS_CALDERA_URL", "ARGUS_CALDERA_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert caldera_configured() is False


async def test_caldera_list_abilities_unconfigured(monkeypatch):
    for k in ("ARGUS_CALDERA_URL", "ARGUS_CALDERA_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = await caldera_module.list_abilities()
    assert r.success is False
    assert "not configured" in (r.note or "").lower()


async def test_caldera_list_abilities(monkeypatch):
    monkeypatch.setenv("ARGUS_CALDERA_URL", "https://caldera.test:8888")
    monkeypatch.setenv("ARGUS_CALDERA_API_KEY", "red-key")
    body = [
        {"ability_id": "a-1", "technique_id": "T1059.001",
         "name": "PowerShell IEX"},
        {"ability_id": "a-2", "technique_id": "T1003.001",
         "name": "LSASS Dump"},
    ]
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await caldera_module.list_abilities()
    assert r.success is True
    assert resp.request_method == "GET"
    assert resp.request_url == "https://caldera.test:8888/api/v2/abilities"
    assert resp.request_headers["KEY"] == "red-key"
    assert len(r.data) == 2


async def test_caldera_list_abilities_with_tactic_filter(monkeypatch):
    monkeypatch.setenv("ARGUS_CALDERA_URL", "https://caldera.test:8888")
    monkeypatch.setenv("ARGUS_CALDERA_API_KEY", "red-key")
    resp = _FakeResp(status=200, json_body=[])
    with _patch_session(resp):
        await caldera_module.list_abilities(tactic="execution")
    assert resp.request_params == {"tactic": "execution"}


async def test_caldera_start_operation(monkeypatch):
    monkeypatch.setenv("ARGUS_CALDERA_URL", "https://caldera.test:8888")
    monkeypatch.setenv("ARGUS_CALDERA_API_KEY", "red-key")
    resp = _FakeResp(status=200, json_body={
        "id": "op-123", "name": "argus-adv-1",
    })
    with _patch_session(resp):
        r = await caldera_module.start_operation(
            adversary_id="adv-1", group="red", planner="atomic",
        )
    assert r.success is True
    assert resp.request_method == "POST"
    body = json.loads(resp.request_body)
    assert body["adversary"] == {"adversary_id": "adv-1"}
    assert body["planner"] == {"id": "atomic"}
    assert body["auto_close"] is True
    assert body["group"] == "red"


async def test_caldera_http_error_surfaces(monkeypatch):
    monkeypatch.setenv("ARGUS_CALDERA_URL", "https://caldera.test:8888")
    monkeypatch.setenv("ARGUS_CALDERA_API_KEY", "red-key")
    resp = _FakeResp(status=403, text_body="forbidden")
    with _patch_session(resp):
        r = await caldera_module.list_operations()
    assert r.success is False
    assert "HTTP 403" in (r.error or "")


async def test_caldera_health_check_unconfigured(monkeypatch):
    for k in ("ARGUS_CALDERA_URL", "ARGUS_CALDERA_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = await caldera_module.health_check()
    assert r.success is False


# ── Coverage scorer ─────────────────────────────────────────────────


def test_coverage_basic_math():
    r = coverage_score(
        executed={"T1059.001": 4, "T1003.001": 2, "T1486": 1},
        detected={"T1059.001": 4, "T1003.001": 1, "T1486": 0},
    )
    assert isinstance(r, CoverageReport)
    by_t = {e.technique_id: e for e in r.entries}
    assert by_t["T1059.001"].coverage == 1.0
    assert by_t["T1059.001"].status == "covered"
    assert by_t["T1003.001"].coverage == 0.5
    assert by_t["T1003.001"].status == "partial"
    assert by_t["T1486"].coverage == 0.0
    assert by_t["T1486"].status == "gap"
    # 5 detected / 7 executed
    assert abs(r.overall - (5 / 7)) < 1e-6
    assert r.gaps == ["T1486"]
    assert r.covered == ["T1059.001"]


def test_coverage_handles_empty_inputs():
    r = coverage_score({}, {})
    assert r.overall == 0.0
    assert r.entries == []


def test_coverage_clamps_at_one_for_excess_detections():
    """If the SIEM fires multiple alerts per atomic test, coverage shouldn't
    inflate past 1.0."""
    r = coverage_score(
        executed={"T1486": 1},
        detected={"T1486": 5},
    )
    assert r.overall == 1.0
    assert r.entries[0].coverage == 1.0


def test_coverage_records_detection_without_execution():
    """A SIEM hit with no matching atomic execution gets executed=0 —
    surfaces as 'untested' so reviewers can audit unexpected noise."""
    r = coverage_score({}, {"T1547.001": 3})
    assert len(r.entries) == 1
    e = r.entries[0]
    assert e.executed == 0
    assert e.detected == 3
    assert e.coverage == 0.0
    assert e.status == "untested"


def test_coverage_to_dict_shape():
    r = coverage_score({"T1059.001": 1}, {"T1059.001": 1})
    d = r.to_dict()
    assert d["overall"] == 1.0
    assert d["techniques_total"] == 1
    assert d["techniques_covered"] == 1
    assert d["entries"][0]["status"] == "covered"


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_route_availability(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/adversary-emulation/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert "atomic_red_team" in body
    assert "caldera" in body
    assert body["caldera"]["configured"] in (True, False)


async def test_route_atomic_techniques(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    r = await client.get(
        "/api/v1/intel/adversary-emulation/atomic/techniques",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    techs = r.json()["techniques"]
    assert "T1059.001" in techs


async def test_route_atomic_tests_for_technique(
    client, analyst_user, monkeypatch,
):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    r = await client.get(
        "/api/v1/intel/adversary-emulation/atomic/T1003.001",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["technique_id"] == "T1003.001"
    assert len(body["tests"]) >= 1
    assert all(t["technique_id"] == "T1003.001" for t in body["tests"])


async def test_route_atomic_tests_unknown_technique_returns_empty(
    client, analyst_user, monkeypatch,
):
    monkeypatch.delenv("ARGUS_ATOMIC_RED_TEAM_PATH", raising=False)
    art_module.reset_cache()
    r = await client.get(
        "/api/v1/intel/adversary-emulation/atomic/T9999",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["tests"] == []


async def test_route_caldera_abilities_unconfigured(
    client, analyst_user, monkeypatch,
):
    for k in ("ARGUS_CALDERA_URL", "ARGUS_CALDERA_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = await client.get(
        "/api/v1/intel/adversary-emulation/caldera/abilities",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_route_coverage_score(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/adversary-emulation/coverage/score",
        headers=analyst_user["headers"],
        json={
            "executed": {"T1059.001": 4, "T1003.001": 2},
            "detected": {"T1059.001": 4, "T1003.001": 1},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["techniques_total"] == 2
    assert body["techniques_covered"] == 1


async def test_route_caldera_start_requires_admin(client, analyst_user):
    """Analyst can't kick off Caldera operations — admin-gated because
    operations execute attacker behaviour on customer endpoints."""
    r = await client.post(
        "/api/v1/intel/adversary-emulation/caldera/operations",
        headers=analyst_user["headers"],
        json={"adversary_id": "adv-1"},
    )
    assert r.status_code in (401, 403)


async def test_route_requires_auth(client):
    r = await client.get("/api/v1/intel/adversary-emulation/availability")
    assert r.status_code in (401, 403)
