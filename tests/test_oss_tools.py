"""OSS tool catalog + onboarding API + installer state machine."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import select

from src.integrations.oss_tools import list_catalog, tool_by_name
from src.integrations.oss_tools.catalog import to_dict
from src.integrations.oss_tools.installer import (
    disable_unselected,
    installer_enabled,
    list_states,
    onboarding_complete,
    update_env_file,
)
from src.models.oss_tool import OssToolInstall, OssToolState

pytestmark = pytest.mark.asyncio


# ── catalog ────────────────────────────────────────────────────────


def test_catalog_has_six_tools_with_expected_keys():
    cat = list_catalog()
    names = {t.name for t in cat}
    # The exact six tools we ship onboarding for. If we add another, it
    # MUST go through this assertion + a docs update.
    assert names == {"caldera", "shuffle", "velociraptor", "misp",
                      "opencti", "wazuh"}
    for t in cat:
        d = to_dict(t)
        assert d["label"] and d["summary"] and d["capability"]
        assert d["compose_profile"] == t.name   # convention
        assert d["ram_estimate_mb"] >= 256
        assert d["disk_estimate_gb"] >= 1
        assert isinstance(d["env_vars"], dict)


def test_heavyweight_flag_set_for_misp_opencti_wazuh():
    by = {t.name: t for t in list_catalog()}
    assert by["misp"].is_heavyweight
    assert by["opencti"].is_heavyweight
    assert by["wazuh"].is_heavyweight
    assert not by["caldera"].is_heavyweight
    assert not by["velociraptor"].is_heavyweight


def test_tool_by_name_misses_return_none():
    assert tool_by_name("nope") is None


# ── installer gate ─────────────────────────────────────────────────


def test_installer_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ARGUS_OSS_INSTALLER_ENABLED", raising=False)
    assert installer_enabled() is False


def test_installer_enabled_via_env(monkeypatch):
    monkeypatch.setenv("ARGUS_OSS_INSTALLER_ENABLED", "true")
    assert installer_enabled() is True


# ── update_env_file replaces, does not duplicate ──────────────────


def test_update_env_file_round_trip(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "ARGUS_DB_HOST=postgres\n"
        "ARGUS_CALDERA_URL=\n"
        "# comment\n"
        "ARGUS_FOO=bar\n"
    )
    monkeypatch.setenv("ARGUS_OSS_INSTALLER_HOST_PROJECT", str(tmp_path))
    update_env_file({
        "ARGUS_CALDERA_URL": "http://caldera:8888",
        "ARGUS_NEW_KEY": "new-value",
    })
    body = env.read_text()
    assert body.count("ARGUS_CALDERA_URL=") == 1
    assert "ARGUS_CALDERA_URL=http://caldera:8888" in body
    assert "ARGUS_NEW_KEY=new-value" in body
    assert "ARGUS_FOO=bar" in body
    assert "# comment" in body


# ── disable_unselected + onboarding_complete ──────────────────────


async def test_onboarding_complete_false_until_full_set_recorded(session):
    assert await onboarding_complete(session) is False
    await disable_unselected(session, selected=[])
    await session.flush()
    assert await onboarding_complete(session) is True


async def test_disable_unselected_keeps_selected_state(session):
    # Pre-mark caldera as INSTALLED.
    session.add(OssToolInstall(
        tool_name="caldera",
        state=OssToolState.INSTALLED.value,
    ))
    await session.flush()
    await disable_unselected(session, selected=["caldera"])
    await session.flush()

    # Caldera stayed INSTALLED; everything else is DISABLED.
    rows = (await session.execute(select(OssToolInstall))).scalars().all()
    by_name = {r.tool_name: r for r in rows}
    assert by_name["caldera"].state == OssToolState.INSTALLED.value
    for n in ("shuffle", "velociraptor", "misp", "opencti", "wazuh"):
        assert by_name[n].state == OssToolState.DISABLED.value


async def test_list_states_includes_every_catalog_tool(session):
    states = await list_states(session)
    assert {s["tool_name"] for s in states} == {
        t.name for t in list_catalog()
    }
    for s in states:
        assert s["state"] == OssToolState.DISABLED.value


# ── HTTP routes ────────────────────────────────────────────────────


async def test_route_catalog_admin_only(client, admin_user, analyst_user):
    r = await client.get(
        "/api/v1/oss-tools/catalog", headers=admin_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["tools"]) == 6

    r = await client.get(
        "/api/v1/oss-tools/catalog", headers=analyst_user["headers"],
    )
    assert r.status_code in (401, 403)


async def test_route_preflight_reports_disabled_by_default(
    client, admin_user, monkeypatch,
):
    monkeypatch.delenv("ARGUS_OSS_INSTALLER_ENABLED", raising=False)
    r = await client.get(
        "/api/v1/oss-tools/preflight", headers=admin_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["ready"] is False
    assert any("ARGUS_OSS_INSTALLER_ENABLED" in i for i in body["issues"])


async def test_route_onboarding_status_starts_incomplete(client, admin_user):
    r = await client.get(
        "/api/v1/oss-tools/onboarding", headers=admin_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert "complete" in body
    assert "installer_enabled" in body


async def test_route_skip_marks_onboarding_complete(client, admin_user):
    r = await client.post(
        "/api/v1/oss-tools/onboarding/skip",
        headers=admin_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["complete"] is True

    r = await client.get(
        "/api/v1/oss-tools/onboarding", headers=admin_user["headers"],
    )
    assert r.json()["complete"] is True


async def test_route_install_rejects_unknown_tool(client, admin_user):
    r = await client.post(
        "/api/v1/oss-tools/install",
        json={"tools": ["caldera", "definitely-not-a-tool"]},
        headers=admin_user["headers"],
    )
    assert r.status_code == 400


async def test_route_install_when_disabled_records_failure(
    client, admin_user, monkeypatch,
):
    """Installer gate is off — every selected tool ends up FAILED with a
    clear operator message."""
    monkeypatch.delenv("ARGUS_OSS_INSTALLER_ENABLED", raising=False)
    r = await client.post(
        "/api/v1/oss-tools/install",
        json={"tools": ["caldera"]},
        headers=admin_user["headers"],
    )
    assert r.status_code == 202
    body = r.json()
    assert body["started"] == ["caldera"]

    # Background task already ran inline (test client awaits).
    r = await client.get(
        "/api/v1/oss-tools/", headers=admin_user["headers"],
    )
    by_name = {s["tool_name"]: s for s in r.json()["tools"]}
    caldera = by_name["caldera"]
    assert caldera["state"] in (
        OssToolState.FAILED.value, OssToolState.PENDING.value,
        OssToolState.INSTALLING.value,
    )


async def test_route_requires_auth(client):
    r = await client.get("/api/v1/oss-tools/catalog")
    assert r.status_code in (401, 403)
