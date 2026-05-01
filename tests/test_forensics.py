"""IR / forensics workbench (P3 #3.11) — unit + HTTP-route tests.

Both Volatility 3 and Velociraptor are opt-in: the wrappers degrade
gracefully when the tools aren't installed / configured, and that's
what the CI venv looks like. We exercise:

  - The unavailable / unconfigured paths (no Volatility binary, no
    Velociraptor URL+token)
  - Volatility against a stub CLI script (exits 0, emits canned JSON)
  - Velociraptor against a stubbed aiohttp surface
  - HTTP routes for both
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from unittest.mock import patch

import pytest

from src.integrations.forensics import (
    volatility_run_plugin,
    velociraptor_list_clients,
    velociraptor_schedule_collection,
)
from src.integrations.forensics.volatility import is_available as vol_available
from src.integrations.forensics.velociraptor import is_configured as velo_configured

pytestmark = pytest.mark.asyncio


# ── Aiohttp double (Velociraptor) ───────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = (
            text_body if text_body is not None
            else (json.dumps(json_body) if json_body is not None else "")
        )
        self.request_url: str | None = None
        self.request_body: str | None = None
        self.request_headers: dict[str, str] | None = None

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

    def get(self, url, **kwargs):
        return self._call(url, kwargs)

    def post(self, url, **kwargs):
        return self._call(url, kwargs)

    def _call(self, url, kwargs):
        self._response.request_url = url
        body = kwargs.get("json") or kwargs.get("data")
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
        elif isinstance(body, dict):
            body = json.dumps(body, default=str)
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


# ── Volatility ──────────────────────────────────────────────────────


async def test_volatility_unavailable_when_no_cli(monkeypatch):
    monkeypatch.setenv("ARGUS_VOLATILITY_CLI", "/no/such/path/vol")
    info = vol_available()
    assert info["available"] is False
    r = await volatility_run_plugin(
        plugin="windows.pslist", image_path="/tmp/image.raw",
    )
    assert r.available is False
    assert r.note and "not installed" in r.note.lower()


async def test_volatility_image_must_be_absolute(monkeypatch, tmp_path):
    fake_cli = tmp_path / "vol_stub"
    fake_cli.write_text("#!/bin/sh\necho '[]'\n")
    fake_cli.chmod(0o755)
    monkeypatch.setenv("ARGUS_VOLATILITY_CLI", str(fake_cli))

    r = await volatility_run_plugin(
        plugin="windows.pslist", image_path="relative/path.raw",
    )
    assert r.available is True
    assert "must be absolute" in (r.error or "")


async def test_volatility_runs_stub_cli(monkeypatch, tmp_path):
    image = tmp_path / "memory.raw"
    image.write_bytes(b"\x00" * 16)

    fake_cli = tmp_path / "vol_stub"
    fake_cli.write_text(
        "#!/bin/sh\n"
        "cat <<EOF\n"
        "["
        "{\"PID\": 4, \"Name\": \"System\"},"
        "{\"PID\": 1024, \"Name\": \"explorer.exe\"}"
        "]\n"
        "EOF\n"
        "exit 0\n"
    )
    fake_cli.chmod(0o755)
    monkeypatch.setenv("ARGUS_VOLATILITY_CLI", str(fake_cli))

    r = await volatility_run_plugin(
        plugin="windows.pslist", image_path=str(image),
        timeout_seconds=10,
    )
    assert r.available is True
    assert r.returncode == 0
    assert len(r.rows) == 2
    assert r.rows[0]["Name"] == "System"


async def test_volatility_handles_invalid_json(monkeypatch, tmp_path):
    image = tmp_path / "memory.raw"
    image.write_bytes(b"\x00")

    fake_cli = tmp_path / "vol_stub"
    fake_cli.write_text("#!/bin/sh\necho 'not json'\nexit 0\n")
    fake_cli.chmod(0o755)
    monkeypatch.setenv("ARGUS_VOLATILITY_CLI", str(fake_cli))

    r = await volatility_run_plugin(
        plugin="windows.pslist", image_path=str(image),
        timeout_seconds=10,
    )
    assert r.available is True
    assert "failed to parse" in (r.error or "")


# ── Velociraptor ────────────────────────────────────────────────────


async def test_velociraptor_unconfigured(monkeypatch):
    for k in ("ARGUS_VELOCIRAPTOR_URL", "ARGUS_VELOCIRAPTOR_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    assert velo_configured() is False
    r = await velociraptor_list_clients()
    assert r.available is False
    r = await velociraptor_schedule_collection(
        client_id="C.123", artifact="Windows.System.Pslist",
    )
    assert r.available is False


async def test_velociraptor_list_clients_parses_response(monkeypatch):
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_URL", "https://velo.example:8000")
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_TOKEN", "fake-token")
    payload = {"items": [
        {"client_id": "C.1", "os_info": {"hostname": "host1", "system": "windows"},
         "labels": ["prod"], "last_seen_at": "2026-05-01T10:00:00Z"},
        {"client_id": "C.2", "os_info": {"hostname": "host2", "system": "linux"},
         "labels": [], "last_seen_at": "2026-05-01T11:00:00Z"},
    ]}
    resp = _FakeResp(status=200, json_body=payload)
    with _patch_session(resp):
        r = await velociraptor_list_clients(search="host:*")
    assert r.available is True
    assert r.success is True
    assert len(r.data) == 2
    assert r.data[0]["hostname"] == "host1"
    assert resp.request_url.endswith("/api/v1/SearchClients")


async def test_velociraptor_schedule_collection(monkeypatch):
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_URL", "https://velo.example:8000")
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_TOKEN", "fake-token")
    resp = _FakeResp(status=200, json_body={"flow_id": "F.987"})
    with _patch_session(resp):
        r = await velociraptor_schedule_collection(
            client_id="C.1", artifact="Windows.System.Pslist",
            parameters={"max_processes": "100"},
        )
    assert r.success is True
    assert r.data["flow_id"] == "F.987"
    body = json.loads(resp.request_body)
    assert body["client_id"] == "C.1"
    assert body["artifacts"] == ["Windows.System.Pslist"]


async def test_velociraptor_handles_4xx(monkeypatch):
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_URL", "https://velo.example:8000")
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_TOKEN", "fake-token")
    with _patch_session(_FakeResp(status=403, text_body="forbidden")):
        r = await velociraptor_list_clients()
    assert r.success is False
    assert "HTTP 403" in (r.error or "")


async def test_velociraptor_schedule_validates_inputs(monkeypatch):
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_URL", "https://velo.example:8000")
    monkeypatch.setenv("ARGUS_VELOCIRAPTOR_TOKEN", "fake-token")
    r = await velociraptor_schedule_collection(client_id="", artifact="X")
    assert r.success is False
    assert "client_id" in (r.error or "").lower()


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_forensics_availability_route(client, analyst_user, monkeypatch):
    for k in ("ARGUS_VELOCIRAPTOR_URL", "ARGUS_VELOCIRAPTOR_TOKEN",
              "ARGUS_VOLATILITY_CLI"):
        monkeypatch.delenv(k, raising=False)
    r = await client.get(
        "/api/v1/intel/forensics/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert "volatility" in body
    assert body["velociraptor"]["configured"] is False


async def test_forensics_velociraptor_route_unconfigured(client, analyst_user, monkeypatch):
    for k in ("ARGUS_VELOCIRAPTOR_URL", "ARGUS_VELOCIRAPTOR_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    r = await client.get(
        "/api/v1/intel/forensics/velociraptor/clients",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False


async def test_forensics_route_requires_auth(client):
    r = await client.get("/api/v1/intel/forensics/availability")
    assert r.status_code in (401, 403)
