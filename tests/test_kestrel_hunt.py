"""Kestrel hunting DSL wrapper (P2 #2.4) — tests.

Pure-function tests on :func:`render_hunt` (works without Kestrel
installed) plus integration tests on the availability detection and
execution path. Kestrel itself isn't bundled — these tests verify the
graceful no-op when it's absent.
"""

from __future__ import annotations

import os

import pytest

from src.intel.kestrel_hunt import (
    HuntScript,
    execute_hunt,
    is_available,
    render_hunt,
)

pytestmark = pytest.mark.asyncio


# ── Availability ─────────────────────────────────────────────────────


def test_is_available_returns_dict():
    info = is_available()
    assert set(info.keys()) == {"available", "cli_path", "module_importable"}


def test_is_available_kestrel_not_installed_in_test_env():
    """The CI venv intentionally doesn't bundle kestrel — verify."""
    info = is_available()
    assert info["module_importable"] is False


def test_cli_override_pointing_at_missing_path(monkeypatch):
    monkeypatch.setenv("ARGUS_KESTREL_CLI", "/no/such/path/kestrel")
    info = is_available()
    assert info["cli_path"] is None


# ── Hunt-script rendering ────────────────────────────────────────────


def test_render_simple_ip_hunt():
    h = render_hunt(
        title="APT34 OilRig — exec callback",
        source_name="splunk",
        iocs=[("ip", "203.0.113.7")],
        technique_id="T1071.001",
    )
    assert isinstance(h, HuntScript)
    assert "203.0.113.7" in h.script
    assert "T1071.001" in h.script
    assert "stixshifter://splunk" in h.script
    assert "DISP" in h.script


def test_render_routes_hash_by_length():
    md5 = render_hunt(
        title="t", source_name="splunk",
        iocs=[("hash", "a" * 32)],
    )
    sha1 = render_hunt(
        title="t", source_name="splunk",
        iocs=[("hash", "b" * 40)],
    )
    sha256 = render_hunt(
        title="t", source_name="splunk",
        iocs=[("hash", "c" * 64)],
    )
    assert "hashes.MD5" in md5.script
    assert "'SHA-1'" in sha1.script
    assert "'SHA-256'" in sha256.script


def test_render_unions_multiple_iocs():
    h = render_hunt(
        title="multi", source_name="elastic_ecs",
        iocs=[("ip", "1.1.1.1"), ("domain", "evil.example.com")],
    )
    assert " OR " in h.script
    assert "1.1.1.1" in h.script
    assert "evil.example.com" in h.script


def test_render_quotes_apostrophes():
    h = render_hunt(
        title="t", source_name="splunk",
        iocs=[("domain", "ev'il.example.com")],
    )
    assert "ev''il.example.com" in h.script


def test_render_requires_at_least_one_ioc():
    with pytest.raises(ValueError):
        render_hunt(title="t", source_name="splunk", iocs=[])


def test_render_to_dict_shape():
    h = render_hunt(
        title="t", source_name="splunk", iocs=[("ip", "1.2.3.4")],
    )
    d = h.to_dict()
    assert set(d.keys()) >= {"title", "source_name", "iocs", "script"}


# ── Execution ────────────────────────────────────────────────────────


async def test_execute_hunt_unavailable_when_no_kestrel(monkeypatch):
    """Without ``kestrel`` on PATH and no ARGUS_KESTREL_CLI override,
    execution must return available=False rather than crashing."""
    monkeypatch.delenv("ARGUS_KESTREL_CLI", raising=False)
    # Force shutil.which to return None even if some random binary
    # named 'kestrel' happens to exist on a dev machine.
    import src.intel.kestrel_hunt as kh

    monkeypatch.setattr(kh, "_kestrel_cli_path", lambda: None)

    h = render_hunt(
        title="t", source_name="splunk", iocs=[("ip", "1.2.3.4")],
    )
    result = await execute_hunt(h.script, timeout_seconds=5)
    assert result.available is False
    assert "203.0" not in result.script  # script preserved as-is
    assert result.script == h.script
    assert result.note and "not installed" in result.note.lower()


async def test_execute_hunt_with_fake_cli(monkeypatch, tmp_path):
    """Stub the CLI with a tiny shell script that echoes the hunt file
    path. Verifies the subprocess plumbing without needing real
    Kestrel."""
    fake_cli = tmp_path / "fake_kestrel"
    fake_cli.write_text(
        "#!/bin/sh\n"
        "echo 'Kestrel ran:'\n"
        "echo \"input=$1\"\n"
        "exit 0\n"
    )
    fake_cli.chmod(0o755)
    monkeypatch.setenv("ARGUS_KESTREL_CLI", str(fake_cli))

    h = render_hunt(
        title="t", source_name="splunk", iocs=[("ip", "9.9.9.9")],
    )
    result = await execute_hunt(h.script, timeout_seconds=10)
    assert result.available is True
    assert result.returncode == 0
    assert "Kestrel ran:" in (result.stdout or "")


# ── HTTP routes ──────────────────────────────────────────────────────


async def test_kestrel_availability_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/kestrel/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert "available" in r.json()


async def test_kestrel_render_route(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/kestrel/render",
        json={
            "title": "APT34 hunt",
            "source_name": "splunk",
            "iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "technique_id": "T1071.001",
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "203.0.113.7" in body["script"]
    assert body["technique_id"] == "T1071.001"


async def test_kestrel_render_rejects_empty_iocs(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/kestrel/render",
        json={"title": "t", "source_name": "splunk", "iocs": []},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 400


async def test_kestrel_route_requires_auth(client):
    r = await client.get("/api/v1/intel/kestrel/availability")
    assert r.status_code in (401, 403)
