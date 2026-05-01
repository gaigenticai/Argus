"""Notification Router — full integration tests.

Verifies:
    - encrypted credential storage (round-trip)
    - channel CRUD + secret rotation + secret-clear
    - rule CRUD + tenant isolation on channel_ids
    - rule matching: severity floor, event kinds, asset criticality,
      asset_types, tags_any
    - dispatch fan-out with real adapters:
        Slack, Teams, generic webhook (HMAC), PagerDuty, Opsgenie,
        Jasmin SMS — all hit a mock HTTP server we start in-process
        Email — hits a real aiosmtpd in-process SMTP server
    - dedup window suppresses repeats
    - dry_run produces deliveries without firing adapters
    - test endpoint sends a synthetic event through one channel
    - delivery list filters
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import socket
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from aiohttp import web

pytestmark = pytest.mark.asyncio


# --- Mock HTTP server fixture ------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockHTTPServer:
    """In-process aiohttp server. Records every request and replies based
    on a per-path map set by the test.
    """

    def __init__(self, port: int):
        self.port = port
        self.received: list[dict[str, Any]] = []
        self._handlers: dict[str, Any] = {}
        self._app = web.Application()
        self._app.router.add_route("*", "/{tail:.*}", self._dispatch)
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await self._site.start()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    def url(self, path: str = "/") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def set_handler(self, path: str, handler):
        self._handlers[path] = handler

    def reset(self) -> None:
        self.received.clear()
        self._handlers.clear()

    async def _dispatch(self, request: web.Request):
        body_bytes = await request.read()
        try:
            body_json = json.loads(body_bytes) if body_bytes else None
        except Exception:
            body_json = None
        record = {
            "method": request.method,
            "path": request.path,
            "query": dict(request.query),
            "headers": dict(request.headers),
            "body": body_bytes,
            "body_json": body_json,
        }
        self.received.append(record)

        handler = self._handlers.get(request.path)
        if handler is None:
            return web.json_response({"ok": True}, status=200)
        return handler(request, record)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def mock_http():
    """Single mock HTTP server reused across notification tests."""
    server = MockHTTPServer(_free_port())
    await server.start()
    yield server
    await server.stop()


# --- aiosmtpd in-process SMTP -------------------------------------------


class _SMTPSink:
    def __init__(self):
        self.messages: list[dict[str, Any]] = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(
            {
                "from": envelope.mail_from,
                "to": list(envelope.rcpt_tos),
                "data": envelope.content.decode("utf-8", errors="replace"),
            }
        )
        return "250 OK"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def smtp_server():
    from aiosmtpd.controller import Controller

    sink = _SMTPSink()
    port = _free_port()
    controller = Controller(sink, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        yield {"host": "127.0.0.1", "port": port, "sink": sink}
    finally:
        controller.stop()


# --- Helpers ------------------------------------------------------------


def _hdr(user) -> dict:
    return user["headers"]


async def _create_channel(client, analyst, organization, **kwargs):
    payload = {
        "organization_id": str(organization["id"]),
        "name": kwargs.pop("name", "test channel"),
        "kind": kwargs.pop("kind", "webhook"),
        "config": kwargs.pop("config", {}),
        "secret": kwargs.pop("secret", None),
        "enabled": kwargs.pop("enabled", True),
    }
    payload.update(kwargs)
    r = await client.post(
        "/api/v1/notifications/channels", json=payload, headers=_hdr(analyst)
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _create_rule(client, analyst, organization, channel_ids, **kwargs):
    payload = {
        "organization_id": str(organization["id"]),
        "name": kwargs.pop("name", "rule"),
        "channel_ids": [str(c) for c in channel_ids],
        "min_severity": kwargs.pop("min_severity", "low"),
        "event_kinds": kwargs.pop("event_kinds", ["alert"]),
        "tags_any": kwargs.pop("tags_any", []),
        "asset_criticalities": kwargs.pop("asset_criticalities", []),
        "asset_types": kwargs.pop("asset_types", []),
        "dedup_window_seconds": kwargs.pop("dedup_window_seconds", 300),
        "enabled": kwargs.pop("enabled", True),
    }
    payload.update(kwargs)
    r = await client.post(
        "/api/v1/notifications/rules", json=payload, headers=_hdr(analyst)
    )
    assert r.status_code == 201, r.text
    return r.json()


# --- Tests --------------------------------------------------------------


async def test_adapters_listing(client, analyst_user):
    r = await client.get("/api/v1/notifications/adapters", headers=_hdr(analyst_user))
    assert r.status_code == 200
    kinds = r.json()["kinds"]
    assert {"email", "slack", "teams", "webhook", "pagerduty", "opsgenie", "jasmin_sms"} <= set(kinds)


async def test_create_channel_with_secret_round_trip(
    client, analyst_user, organization
):
    r = await client.post(
        "/api/v1/notifications/channels",
        json={
            "organization_id": str(organization["id"]),
            "name": "slack-prod",
            "kind": "slack",
            "config": {},
            "secret": "https://hooks.slack.com/services/T/B/SECRET",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201
    body = r.json()
    assert body["has_secret"] is True
    # Secret never returned
    assert "secret" not in body and "secret_ciphertext" not in body


async def test_channel_secret_rotate_and_clear(
    client, analyst_user, organization
):
    ch = await _create_channel(
        client, analyst_user, organization, kind="webhook", secret="initial"
    )

    rot = await client.patch(
        f"/api/v1/notifications/channels/{ch['id']}",
        json={"secret": "rotated-value"},
        headers=_hdr(analyst_user),
    )
    assert rot.status_code == 200
    assert rot.json()["has_secret"] is True

    clr = await client.patch(
        f"/api/v1/notifications/channels/{ch['id']}",
        json={"rotate_clear": True},
        headers=_hdr(analyst_user),
    )
    assert clr.status_code == 200
    assert clr.json()["has_secret"] is False


async def test_rule_rejects_channel_in_other_org(
    client, analyst_user, organization, second_organization
):
    other_ch = await _create_channel(
        client, analyst_user, second_organization, kind="webhook",
        config={"url": "http://127.0.0.1:9999/x"},
    )
    r = await client.post(
        "/api/v1/notifications/rules",
        json={
            "organization_id": str(organization["id"]),
            "name": "cross-tenant",
            "channel_ids": [other_ch["id"]],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422


# --- Adapter integration tests against mock HTTP / real SMTP -----------


async def test_dispatch_webhook_with_hmac(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()
    secret = "shared-hmac-secret"
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="webhook",
        config={"url": mock_http.url("/hook"), "headers": {"X-Tenant": "demo"}},
        secret=secret,
    )
    await _create_rule(
        client, analyst_user, organization, [ch["id"]], min_severity="medium"
    )

    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "Webhook fan-out",
            "summary": "deep web mention detected",
            "tags": ["dark-web"],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert len(r.json()) == 1
    delivery = r.json()[0]
    assert delivery["status"] == "succeeded"
    assert delivery["response_status"] == 200

    assert len(mock_http.received) == 1
    req = mock_http.received[0]
    assert req["method"] == "POST"
    assert req["headers"].get("X-Tenant") == "demo"
    assert req["headers"].get("X-Argus-Signature", "").startswith("sha256=")

    # Verify HMAC matches the body the server actually saw.
    payload_bytes = json.dumps(req["body_json"], separators=(",", ":"), sort_keys=True).encode()
    expected = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    assert req["headers"]["X-Argus-Signature"] == f"sha256={expected}"


async def test_dispatch_slack(client, analyst_user, organization, mock_http):
    mock_http.reset()
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="slack",
        secret=mock_http.url("/slack"),
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "critical",
            "title": "ransomware leak",
            "summary": "victim entry on Lockbit blog",
        },
        headers=_hdr(analyst_user),
    )
    assert any(r["path"] == "/slack" for r in mock_http.received)
    slack_req = next(r for r in mock_http.received if r["path"] == "/slack")
    assert slack_req["body_json"]["text"].startswith("*[CRITICAL]*")
    assert slack_req["body_json"]["blocks"][0]["type"] == "header"


async def test_dispatch_teams(client, analyst_user, organization, mock_http):
    mock_http.reset()
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="teams",
        secret=mock_http.url("/teams"),
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "Phishing site",
            "summary": "lookalike domain registered",
        },
        headers=_hdr(analyst_user),
    )
    teams_req = next(r for r in mock_http.received if r["path"] == "/teams")
    assert teams_req["body_json"]["@type"] == "MessageCard"
    assert teams_req["body_json"]["themeColor"]


async def test_dispatch_pagerduty(client, analyst_user, organization, mock_http):
    mock_http.reset()
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="pagerduty",
        config={"events_url": mock_http.url("/pd")},
        secret="ROUTING-KEY-XYZ",
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "critical",
            "title": "C2 callback",
            "summary": "egress to known C2",
            "dedup_key": "asset:42:c2",
        },
        headers=_hdr(analyst_user),
    )
    pd = next(r for r in mock_http.received if r["path"] == "/pd")
    assert pd["body_json"]["routing_key"] == "ROUTING-KEY-XYZ"
    assert pd["body_json"]["event_action"] == "trigger"
    assert pd["body_json"]["dedup_key"] == "asset:42:c2"
    assert pd["body_json"]["payload"]["severity"] == "critical"


async def test_dispatch_opsgenie(client, analyst_user, organization, mock_http):
    mock_http.reset()
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="opsgenie",
        config={"alerts_url": mock_http.url("/og")},
        secret="OG-API-KEY",
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "DMARC failure spike",
            "summary": "p=quarantine domain failing",
        },
        headers=_hdr(analyst_user),
    )
    og = next(r for r in mock_http.received if r["path"] == "/og")
    assert og["headers"]["Authorization"] == "GenieKey OG-API-KEY"
    assert og["body_json"]["priority"] == "P2"
    assert og["body_json"]["message"].startswith("DMARC failure")


async def test_dispatch_jasmin_sms(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()

    def jasmin_handler(request, record):
        # Jasmin's response is "Success ..." on accepted send.
        return web.Response(text="Success \"abcdef\"", status=200)

    mock_http.set_handler("/send", jasmin_handler)

    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="jasmin_sms",
        config={
            "endpoint": mock_http.url(""),
            "username": "argus",
            "recipients": ["+97312345678", "+97388889999"],
            "coding": 0,
        },
        secret="jasmin-password",
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "critical",
            "title": "wire fraud attempt",
            "summary": "payment gateway anomaly",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    delivery = r.json()[0]
    assert delivery["status"] == "succeeded"

    sends = [rec for rec in mock_http.received if rec["path"] == "/send"]
    assert len(sends) == 2  # one per recipient
    for s in sends:
        assert s["query"]["username"] == "argus"
        assert s["query"]["password"] == "jasmin-password"
        assert s["query"]["to"] in {"+97312345678", "+97388889999"}
        assert "[Argus][CRITICAL]" in s["query"]["content"]


async def test_dispatch_email_real_smtp(
    client, analyst_user, organization, smtp_server
):
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="email",
        config={
            "smtp_host": smtp_server["host"],
            "smtp_port": smtp_server["port"],
            "from_address": "argus@argus.test",
            "recipients": ["alerts@argus.test", "soc@argus.test"],
        },
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    sink = smtp_server["sink"]
    before = len(sink.messages)

    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "Brand impersonation",
            "summary": "logo abuse on lookalike domain",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()[0]["status"] == "succeeded"
    assert len(sink.messages) == before + 1
    msg = sink.messages[-1]
    assert "alerts@argus.test" in msg["to"]
    assert "[Argus][HIGH] Brand impersonation" in msg["data"]


# --- Routing semantics --------------------------------------------------


async def test_severity_floor_blocks_low_events(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="webhook",
        config={"url": mock_http.url("/floor")},
    )
    await _create_rule(
        client, analyst_user, organization, [ch["id"]], min_severity="high"
    )

    # low severity → no delivery
    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "low",
            "title": "nothing major",
            "summary": "x",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json() == []
    assert not any(rec["path"] == "/floor" for rec in mock_http.received)


async def test_dedup_window_skips_repeats(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()
    ch = await _create_channel(
        client, analyst_user, organization, kind="webhook",
        config={"url": mock_http.url("/dedup")},
    )
    await _create_rule(
        client, analyst_user, organization, [ch["id"]], dedup_window_seconds=600
    )

    payload = {
        "organization_id": str(organization["id"]),
        "kind": "alert",
        "severity": "high",
        "title": "repeat",
        "summary": "same dedup",
        "dedup_key": "evt-X",
    }
    first = await client.post(
        "/api/v1/notifications/dispatch", json=payload, headers=_hdr(analyst_user)
    )
    assert first.status_code == 200
    assert first.json()[0]["status"] == "succeeded"

    second = await client.post(
        "/api/v1/notifications/dispatch", json=payload, headers=_hdr(analyst_user)
    )
    assert second.status_code == 200
    assert second.json()[0]["status"] == "skipped"

    # Only ONE actual outgoing HTTP call
    assert sum(1 for r in mock_http.received if r["path"] == "/dedup") == 1


async def test_tag_and_criticality_routing(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()
    ch = await _create_channel(
        client,
        analyst_user,
        organization,
        kind="webhook",
        config={"url": mock_http.url("/crown")},
    )
    await _create_rule(
        client,
        analyst_user,
        organization,
        [ch["id"]],
        asset_criticalities=["crown_jewel"],
        tags_any=["dark-web"],
    )

    # Wrong criticality
    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "no match",
            "summary": "low-crit",
            "asset_criticality": "low",
            "tags": ["dark-web"],
        },
        headers=_hdr(analyst_user),
    )
    assert r.json() == []

    # Wrong tags
    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "no match",
            "summary": "boring tag",
            "asset_criticality": "crown_jewel",
            "tags": ["unrelated"],
        },
        headers=_hdr(analyst_user),
    )
    assert r.json() == []

    # Both match
    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "matches",
            "summary": "fire",
            "asset_criticality": "crown_jewel",
            "tags": ["dark-web", "extra"],
        },
        headers=_hdr(analyst_user),
    )
    assert len(r.json()) == 1
    assert r.json()[0]["status"] == "succeeded"


async def test_dry_run_does_not_call_adapter(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()
    ch = await _create_channel(
        client, analyst_user, organization, kind="webhook",
        config={"url": mock_http.url("/dry")},
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    r = await client.post(
        "/api/v1/notifications/dispatch",
        json={
            "organization_id": str(organization["id"]),
            "kind": "alert",
            "severity": "high",
            "title": "dry",
            "summary": "x",
            "dry_run": True,
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()[0]["status"] == "dry_run"
    assert not any(rec["path"] == "/dry" for rec in mock_http.received)


async def test_test_endpoint(client, analyst_user, organization, mock_http):
    mock_http.reset()
    ch = await _create_channel(
        client, analyst_user, organization, kind="webhook",
        config={"url": mock_http.url("/test-endpoint")},
    )
    r = await client.post(
        f"/api/v1/notifications/channels/{ch['id']}/test",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "succeeded"
    assert any(rec["path"] == "/test-endpoint" for rec in mock_http.received)


async def test_deliveries_list_filters(
    client, analyst_user, organization, mock_http
):
    mock_http.reset()
    ch = await _create_channel(
        client, analyst_user, organization, kind="webhook",
        config={"url": mock_http.url("/dl")},
    )
    await _create_rule(client, analyst_user, organization, [ch["id"]])
    for i in range(3):
        await client.post(
            "/api/v1/notifications/dispatch",
            json={
                "organization_id": str(organization["id"]),
                "kind": "alert",
                "severity": "high",
                "title": f"evt-{i}",
                "summary": "x",
                "dedup_key": f"evt-{i}",
            },
            headers=_hdr(analyst_user),
        )
    listed = await client.get(
        "/api/v1/notifications/deliveries",
        params={"organization_id": str(organization["id"]), "channel_id": ch["id"]},
        headers=_hdr(analyst_user),
    )
    assert listed.status_code == 200
    assert len(listed.json()) >= 3


async def test_unauthenticated_rejected(client):
    r = await client.get("/api/v1/notifications/adapters")
    assert r.status_code in (401, 403)
