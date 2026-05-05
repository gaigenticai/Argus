"""Cuckoo3 sandbox connector — fixture tests.

Pins the get_report normaliser, verdict-from-score thresholds, and
the running-state / no-tasks defensive paths.

Realistic shapes mirror Cuckoo3 web-api docs (cuckoo-hatch.cert.ee,
May 2026).
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

from src.integrations.sandbox.cuckoo3 import (
    Cuckoo3Connector,
    _verdict_from_score,
)
from src.integrations.sandbox.base import (
    AnalysisReport,
    SandboxResult,
)

pytestmark = pytest.mark.asyncio


# ── _verdict_from_score thresholds ──────────────────────────────────


def test_verdict_thresholds():
    """Matches the thresholds CAPEv2 uses — analysts compare verdicts
    across both sandboxes, so the cutoffs must agree."""
    assert _verdict_from_score(9.5) == "malicious"
    assert _verdict_from_score(8.0) == "malicious"
    assert _verdict_from_score(7.99) == "suspicious"
    assert _verdict_from_score(4.0) == "suspicious"
    assert _verdict_from_score(3.99) == "clean"
    assert _verdict_from_score(0.5) == "clean"
    assert _verdict_from_score(0.0) == "unknown"


# ── Test doubles for the two-call get_report flow ──────────────────


class _FakeResp:
    def __init__(self, *, status=200, text_body=""):
        self.status = status
        self._text = text_body

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Routes get/post by URL substring so one session can serve the
    /analysis/<id> + /post call chain."""

    def __init__(self, route_table: dict[str, _FakeResp]):
        self._table = route_table

    def _resp_for(self, url: str) -> _FakeResp:
        for needle, resp in self._table.items():
            if needle in url:
                return resp
        return _FakeResp(status=404, text_body="no matching mock")

    def get(self, url, *args, **kwargs):
        return self._resp_for(url)

    def post(self, url, *args, **kwargs):
        return self._resp_for(url)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(route_table: dict[str, _FakeResp]):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(route_table)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


def _connector(monkeypatch):
    monkeypatch.setenv("ARGUS_CUCKOO3_URL", "http://cuckoo3.test:8090")
    monkeypatch.setenv("ARGUS_CUCKOO3_API_KEY", "test-token")
    return Cuckoo3Connector()


# ── Realistic Cuckoo3 analysis payload ──────────────────────────────


_FINISHED_ANALYSIS = """\
{
  "id": "20260501-ABCDEF",
  "state": "finished",
  "score": 8.5,
  "tasks": [
    {"id": "task-1", "state": "finished", "platform": "windows10"}
  ],
  "target": {
    "file": {"sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
             "filename": "loader.exe"}
  },
  "tags": ["malware", "stealer"]
}
"""


_POST_REPORT = """\
{
  "score": 8.5,
  "signatures": [
    {
      "name": "credential_dump_lsass",
      "severity": 3,
      "description": "Process accessed lsass.exe",
      "ttp": ["T1003.001"]
    },
    {
      "name": "registry_persistence",
      "severity": 2,
      "description": "Wrote autorun key",
      "ttp": ["T1547.001"]
    }
  ],
  "tags": ["malware", "exe"]
}
"""


# ── Happy path ──────────────────────────────────────────────────────


async def test_get_report_finished_analysis(monkeypatch):
    conn = _connector(monkeypatch)
    routes = {
        "/post": _FakeResp(status=200, text_body=_POST_REPORT),
        "/analysis/20260501-ABCDEF": _FakeResp(status=200, text_body=_FINISHED_ANALYSIS),
    }
    with _patch_session(routes):
        result = await conn.get_report("20260501-ABCDEF")

    assert result.success is True
    assert isinstance(result.data, AnalysisReport)
    report = result.data
    assert report.sandbox == "cuckoo3"
    assert report.verdict == "malicious"
    assert report.score == 0.85  # 8.5 / 10
    assert report.sample_sha256 == "deadbeef" * 8  # 64 hex chars
    assert len(report.signatures) == 2
    sig_names = [s.name for s in report.signatures]
    assert "credential_dump_lsass" in sig_names
    # Severity int → enum mapping pinned
    high_sig = next(s for s in report.signatures if s.name == "credential_dump_lsass")
    assert high_sig.severity == "high"
    medium_sig = next(s for s in report.signatures if s.name == "registry_persistence")
    assert medium_sig.severity == "medium"
    # ATT&CK techniques rolled up
    assert "T1003.001" in report.attack_techniques
    assert "T1547.001" in report.attack_techniques


# ── State guards ────────────────────────────────────────────────────


async def test_get_report_running_state_returns_helpful_error(monkeypatch):
    """In-progress analyses should fail cleanly with state info, not
    crash trying to fetch /post on incomplete data."""
    conn = _connector(monkeypatch)
    running_payload = """{"id": "x", "state": "running", "tasks": []}"""
    routes = {
        "/analysis/x": _FakeResp(status=200, text_body=running_payload),
    }
    with _patch_session(routes):
        result = await conn.get_report("x")
    assert result.success is False
    assert "state='running'" in (result.error or "") or "not yet ready" in (result.error or "")


async def test_get_report_no_tasks(monkeypatch):
    conn = _connector(monkeypatch)
    payload = """{"id": "x", "state": "finished", "tasks": []}"""
    routes = {"/analysis/x": _FakeResp(status=200, text_body=payload)}
    with _patch_session(routes):
        result = await conn.get_report("x")
    assert result.success is False
    assert "no tasks" in (result.error or "").lower()


async def test_get_report_404_analysis_not_found(monkeypatch):
    conn = _connector(monkeypatch)
    routes = {}  # default route_table returns 404
    with _patch_session(routes):
        result = await conn.get_report("nonexistent")
    assert result.success is False
    assert "not found" in (result.error or "").lower()


async def test_get_report_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_CUCKOO3_URL", raising=False)
    conn = Cuckoo3Connector()
    result = await conn.get_report("anything")
    assert result.success is False
    assert "not configured" in (result.note or "").lower()


# ── submit_file ─────────────────────────────────────────────────────


async def test_submit_file_returns_analysis_id(monkeypatch):
    conn = _connector(monkeypatch)
    submit_payload = """{"analysis_id": "20260501-XYZ", "settings": {}}"""
    routes = {"/submit/file": _FakeResp(status=200, text_body=submit_payload)}
    with _patch_session(routes):
        result = await conn.submit_file(
            sample_bytes=b"MZ\x90\x00fake-pe", filename="t.exe",
        )
    assert result.success is True
    assert result.data["analysis_id"] == "20260501-XYZ"
    assert "sample_sha256" in result.data


async def test_submit_file_no_analysis_id_in_response(monkeypatch):
    conn = _connector(monkeypatch)
    routes = {"/submit/file": _FakeResp(status=200, text_body="{}")}
    with _patch_session(routes):
        result = await conn.submit_file(sample_bytes=b"data", filename="t")
    assert result.success is False
    assert "no analysis_id" in (result.error or "").lower()


async def test_submit_file_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_CUCKOO3_URL", raising=False)
    conn = Cuckoo3Connector()
    result = await conn.submit_file(sample_bytes=b"x", filename="x")
    assert result.success is False
    assert "not configured" in (result.note or "").lower()


# ── Auth header pinning ─────────────────────────────────────────────


async def test_auth_header_uses_token_scheme(monkeypatch):
    """Cuckoo3 expects ``Authorization: token <key>`` — lowercase
    'token', not 'Bearer'. Pin so it doesn't drift to the more-common
    Bearer scheme."""
    conn = _connector(monkeypatch)
    h = conn._headers()
    assert h["Authorization"] == "token test-token"


# ── ATT&CK technique extraction defends against missing fields ────


async def test_signatures_handle_missing_ttp_field(monkeypatch):
    """If a Cuckoo3 signature omits ttp / attck, we should not raise
    and the report should just have an empty attack_techniques list."""
    conn = _connector(monkeypatch)
    finished = """{"id": "x", "state": "finished", "score": 5.0,
                   "tasks": [{"id": "t", "state": "finished"}],
                   "target": {"file": {"sha256": "a"}}}"""
    post = """{"signatures": [{"name": "thin_sig", "severity": 1}]}"""
    routes = {
        "/analysis/x/task/t/post": _FakeResp(status=200, text_body=post),
        "/analysis/x": _FakeResp(status=200, text_body=finished),
    }
    with _patch_session(routes):
        result = await conn.get_report("x")
    assert result.success is True
    assert result.data.attack_techniques == []
    assert result.data.signatures[0].attack == []
