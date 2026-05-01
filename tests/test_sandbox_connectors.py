"""Sandbox detonation connectors (P3 #3.6) — unit + HTTP-route tests.

Stubs aiohttp the same way ``tests/test_siem_connectors.py`` and
``tests/test_soar_connectors.py`` do. Each connector's submit / report
/ health request shape is verified against a deterministic fake.
"""

from __future__ import annotations

import base64
import contextlib
import json
from unittest.mock import patch

import pytest

from src.integrations.sandbox import (
    CapeConnector,
    HybridAnalysisConnector,
    JoeSandboxConnector,
    VirusTotalConnector,
    list_available,
)
from src.integrations.sandbox.base import (
    AnalysisReport,
    SandboxResult,
    SignatureHit,
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
        self.request_body: Any = None
        self.request_headers: dict[str, str] | None = None

    async def json(self):
        return self._json

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


from typing import Any  # noqa: E402


class _FakeSession:
    def __init__(self, response: _FakeResp):
        self._response = response

    def get(self, url, **kwargs):
        return self._call(url, kwargs)

    def post(self, url, **kwargs):
        return self._call(url, kwargs)

    def _call(self, url, kwargs):
        self._response.request_url = url
        body = kwargs.get("data") or kwargs.get("json")
        # Don't try to stringify multipart FormData; just record its
        # presence so tests can assert on it.
        self._response.request_body = body
        self._response.request_headers = kwargs.get("headers")
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(response: _FakeResp):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


# ── Registry ─────────────────────────────────────────────────────────


def test_list_available_lists_all_four():
    out = list_available()
    names = {c["name"] for c in out}
    assert names == {"cape", "joe", "hybrid", "virustotal"}
    for c in out:
        assert c["configured"] is False  # no creds set in CI


def test_signature_hit_to_dict_shape():
    s = SignatureHit(name="x", severity="high",
                     description="d", attack=["T1071"])
    d = s.to_dict()
    assert set(d.keys()) == {"name", "severity", "description", "attack"}


def test_analysis_report_to_dict_shape():
    r = AnalysisReport(
        sandbox="cape", analysis_id="42", sample_sha256="a" * 64,
        verdict="malicious", score=0.85, signatures=[], tags=["pe"],
        attack_techniques=["T1486"],
    )
    d = r.to_dict()
    assert d["verdict"] == "malicious"
    assert d["score"] == 0.85
    assert d["attack_techniques"] == ["T1486"]


# ── CAPE ────────────────────────────────────────────────────────────


async def test_cape_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_CAPE_URL", raising=False)
    conn = CapeConnector()
    r = await conn.submit_file(sample_bytes=b"x", filename="x")
    assert r.success is False


async def test_cape_submit_returns_task_id(monkeypatch):
    monkeypatch.setenv("ARGUS_CAPE_URL", "https://cape.internal:8000")
    monkeypatch.setenv("ARGUS_CAPE_API_KEY", "fake-cape")
    conn = CapeConnector()
    resp = _FakeResp(status=200, json_body={"task_id": 1234})
    with _patch_session(resp):
        r = await conn.submit_file(sample_bytes=b"PE\x00bytes",
                                    filename="sample.exe")
    assert r.success is True
    assert r.data["analysis_id"] == "1234"
    assert len(r.data["sample_sha256"]) == 64
    assert resp.request_url.endswith("/apiv2/tasks/create/file/")
    assert resp.request_headers["Authorization"] == "Token fake-cape"


async def test_cape_get_report_normalises(monkeypatch):
    monkeypatch.setenv("ARGUS_CAPE_URL", "https://cape.internal:8000")
    conn = CapeConnector()
    body = {
        "info": {"id": 1234, "tags": ["pe", "windows"]},
        "target": {"file": {"sha256": "a" * 64}},
        "malscore": 8.5,
        "signatures": [
            {"name": "ransomware_files", "severity": 3,
             "description": "encrypts files in place",
             "ttp": ["T1486"]},
            {"name": "anti_vm", "severity": 1,
             "description": "detects VM env"},
        ],
    }
    with _patch_session(_FakeResp(status=200, json_body=body)):
        r = await conn.get_report("1234")
    assert r.success is True
    rep = r.data
    assert isinstance(rep, AnalysisReport)
    assert rep.verdict == "malicious"
    assert 0.0 < rep.score <= 1.0
    assert "T1486" in rep.attack_techniques
    assert any(s.name == "ransomware_files" for s in rep.signatures)


async def test_cape_oversized_sample_rejected(monkeypatch):
    monkeypatch.setenv("ARGUS_CAPE_URL", "https://cape.internal:8000")
    conn = CapeConnector()
    big = b"\x00" * (70 * 1024 * 1024)  # 70 MB > 64 MB ceiling
    r = await conn.submit_file(sample_bytes=big, filename="big.bin")
    assert r.success is False
    assert "ceiling" in (r.error or "").lower()


# ── Joe Sandbox ─────────────────────────────────────────────────────


async def test_joe_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_JOE_API_KEY", raising=False)
    r = await JoeSandboxConnector().submit_file(
        sample_bytes=b"x", filename="x",
    )
    assert r.success is False


async def test_joe_submit(monkeypatch):
    monkeypatch.setenv("ARGUS_JOE_API_KEY", "fake-joe")
    body = {"data": {"submission_id": 9876}}
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await JoeSandboxConnector().submit_file(
            sample_bytes=b"PE\x00", filename="x.exe",
        )
    assert r.success is True
    assert r.data["analysis_id"] == "9876"


async def test_joe_get_report(monkeypatch):
    monkeypatch.setenv("ARGUS_JOE_API_KEY", "fake-joe")
    body = {"data": {"analysis": {
        "detection": "malicious", "score": 9, "sha256": "a" * 64,
        "tags": ["banker"],
        "signatures": [
            {"name": "TrickBot loader", "severity": 4,
             "description": "TrickBot family signature",
             "mitre": ["T1071", "T1003"]},
        ],
        "reporturl": "https://jbxcloud.joesecurity.org/analysis/1",
    }}}
    with _patch_session(_FakeResp(status=200, json_body=body)):
        r = await JoeSandboxConnector().get_report("1")
    assert r.success is True
    rep = r.data
    assert rep.verdict == "malicious"
    assert "T1071" in rep.attack_techniques
    assert rep.artifacts_url.endswith("/analysis/1")


# ── Hybrid-Analysis ─────────────────────────────────────────────────


async def test_hybrid_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_HYBRID_API_KEY", raising=False)
    r = await HybridAnalysisConnector().submit_file(
        sample_bytes=b"x", filename="x",
    )
    assert r.success is False


async def test_hybrid_submit(monkeypatch):
    monkeypatch.setenv("ARGUS_HYBRID_API_KEY", "fake-ha")
    body = {"job_id": "abc-123"}
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await HybridAnalysisConnector().submit_file(
            sample_bytes=b"PE\x00", filename="x.exe",
        )
    assert r.success is True
    assert r.data["analysis_id"] == "abc-123"
    assert resp.request_headers["api-key"] == "fake-ha"


async def test_hybrid_report_verdict_thresholds(monkeypatch):
    monkeypatch.setenv("ARGUS_HYBRID_API_KEY", "fake-ha")
    body = {
        "sha256": "a" * 64, "threat_score": 80, "vx_family": "Emotet",
        "mitre_attcks": ["T1059.001", "T1071"],
        "signatures": [
            {"name": "Emotet sig", "threat_level": 4,
             "description": "Emotet pattern", "attck_id": ["T1071"]},
        ],
        "link": "https://www.hybrid-analysis.com/sample/abc",
    }
    with _patch_session(_FakeResp(status=200, json_body=body)):
        r = await HybridAnalysisConnector().get_report("abc-123")
    rep = r.data
    assert rep.verdict == "malicious"      # threat_score >= 75
    assert rep.score == 0.8
    assert "T1059.001" in rep.attack_techniques
    assert rep.artifacts_url.startswith("https://www.hybrid-analysis.com/")


# ── VirusTotal (strict BYOK) ────────────────────────────────────────


async def test_virustotal_strict_byok(monkeypatch):
    """Without ARGUS_VT_ENTERPRISE=true the connector must refuse,
    even with a key set — the free-tier ToS forbids commercial use."""
    monkeypatch.setenv("ARGUS_VT_API_KEY", "looks-legit")
    monkeypatch.delenv("ARGUS_VT_ENTERPRISE", raising=False)
    conn = VirusTotalConnector()
    assert conn.is_configured() is False
    r = await conn.submit_file(sample_bytes=b"x", filename="x")
    assert r.success is False
    assert "commercial" in (r.note or "").lower()


async def test_virustotal_enabled_with_attestation(monkeypatch):
    monkeypatch.setenv("ARGUS_VT_API_KEY", "fake-vt")
    monkeypatch.setenv("ARGUS_VT_ENTERPRISE", "true")
    conn = VirusTotalConnector()
    assert conn.is_configured() is True
    body = {"data": {"id": "analysis-xyz"}}
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await conn.submit_file(sample_bytes=b"PE\x00", filename="x.exe")
    assert r.success is True
    assert r.data["analysis_id"] == "analysis-xyz"
    assert resp.request_headers["x-apikey"] == "fake-vt"


async def test_virustotal_report_normalises(monkeypatch):
    monkeypatch.setenv("ARGUS_VT_API_KEY", "fake-vt")
    monkeypatch.setenv("ARGUS_VT_ENTERPRISE", "true")
    conn = VirusTotalConnector()
    body = {"data": {"attributes": {
        "sha256": "a" * 64,
        "tags": ["assembly", "peexe"],
        "last_analysis_stats": {
            "harmless": 30, "malicious": 25, "suspicious": 5,
            "undetected": 10, "timeout": 0,
        },
        "sandbox_verdicts": {
            "Microsoft Sysinternals": {
                "mitre_attack_techniques": ["T1486", "T1490"],
            },
        },
        "crowdsourced_yara_results": [
            {"rule_name": "MAL_RANSOM_GENERIC",
             "description": "generic ransomware rule"},
        ],
    }}}
    sha = "a" * 64
    with _patch_session(_FakeResp(status=200, json_body=body)):
        r = await conn.get_report(sha)
    rep = r.data
    assert rep.verdict == "malicious"
    assert rep.score >= 0.3
    assert "T1486" in rep.attack_techniques
    assert rep.artifacts_url == f"https://www.virustotal.com/gui/file/{sha}"


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_sandbox_connectors_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/sandbox/connectors",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    names = {c["name"] for c in r.json()["connectors"]}
    assert names == {"cape", "joe", "hybrid", "virustotal"}


async def test_sandbox_unknown_connector_404(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/sandbox/nope/health",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_sandbox_submit_invalid_b64(client, admin_user):
    # /sandbox/{name}/submit is admin-gated (C6) — exfil to external sandbox.
    r = await client.post(
        "/api/v1/intel/sandbox/cape/submit",
        json={"filename": "x.exe", "sample_b64": "%%%not-base64%%%"},
        headers=admin_user["headers"],
    )
    assert r.status_code == 400


async def test_sandbox_submit_rejects_analyst(client, analyst_user):
    """C6 — analysts cannot upload customer files to external sandboxes."""
    r = await client.post(
        "/api/v1/intel/sandbox/cape/submit",
        json={"filename": "x.exe", "sample_b64": "AAAA"},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 403


async def test_sandbox_route_requires_auth(client):
    r = await client.get("/api/v1/intel/sandbox/connectors")
    assert r.status_code in (401, 403)
