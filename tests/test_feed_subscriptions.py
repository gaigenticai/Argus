"""Feed-subscription matcher + CRUD routes (P3 #3.4)."""

from __future__ import annotations

import pytest

from src.core.feed_subscription_match import filter_subscriptions, match_alert

pytestmark = pytest.mark.asyncio


# ── Matcher unit tests ──────────────────────────────────────────────


def test_empty_filter_matches_everything():
    assert match_alert({"severity": "low"}, {}) is True
    assert match_alert({"severity": "critical"}, None) is True
    assert match_alert({}, {}) is True


def test_severity_any_of():
    f = {"severity": ["critical", "high"]}
    assert match_alert({"severity": "critical"}, f) is True
    assert match_alert({"severity": "high"}, f) is True
    assert match_alert({"severity": "low"}, f) is False


def test_severity_case_insensitive():
    f = {"severity": ["CRITICAL"]}
    assert match_alert({"severity": "Critical"}, f) is True


def test_category_filter():
    f = {"category": ["phishing", "malware"]}
    assert match_alert({"category": "phishing"}, f) is True
    assert match_alert({"category": "ransomware"}, f) is False


def test_tags_any_overlap():
    f = {"tags_any": ["gcc", "banking"]}
    assert match_alert({"tags": ["gcc", "iran"]}, f) is True
    assert match_alert({"tags": ["unrelated"]}, f) is False
    # Missing tags field → can't overlap.
    assert match_alert({}, f) is False


def test_tags_all_must_contain_every():
    f = {"tags_all": ["gcc", "banking"]}
    assert match_alert({"tags": ["gcc", "banking", "extra"]}, f) is True
    assert match_alert({"tags": ["gcc"]}, f) is False


def test_min_confidence_floor():
    f = {"min_confidence": 0.7}
    assert match_alert({"confidence": 0.9}, f) is True
    assert match_alert({"confidence": 0.5}, f) is False
    # Missing confidence → fails strict floor.
    assert match_alert({}, f) is False


def test_title_contains_substring():
    f = {"title_contains": "lockbit"}
    assert match_alert({"title": "LockBit affiliate post"}, f) is True
    assert match_alert({"title": "different stuff"}, f) is False


def test_title_regex_match():
    f = {"title_regex": r"\bCVE-2026-\d{4,}\b"}
    assert match_alert({"title": "Patch CVE-2026-12345 today"}, f) is True
    assert match_alert({"title": "no match here"}, f) is False


def test_title_regex_malformed_never_matches():
    """A bad regex shouldn't blow up the matcher loop — it just never
    matches."""
    f = {"title_regex": "(unclosed"}
    assert match_alert({"title": "anything"}, f) is False


def test_combined_clauses_all_must_pass():
    f = {
        "severity": ["critical"],
        "tags_any": ["gcc"],
        "min_confidence": 0.7,
    }
    a = {"severity": "critical", "tags": ["gcc", "banking"], "confidence": 0.9}
    assert match_alert(a, f) is True
    # Drop one clause's compatibility — fails.
    assert match_alert({**a, "severity": "low"}, f) is False
    assert match_alert({**a, "tags": ["other"]}, f) is False
    assert match_alert({**a, "confidence": 0.5}, f) is False


def test_filter_subscriptions_skips_inactive_and_non_matching():
    alert = {"severity": "critical", "category": "phishing"}
    subs = [
        {"id": "1", "active": True,
         "filter": {"severity": ["critical"]}},
        {"id": "2", "active": False,
         "filter": {"severity": ["critical"]}},   # inactive
        {"id": "3", "active": True,
         "filter": {"category": ["malware"]}},     # wrong category
        {"id": "4", "active": True, "filter": {}}, # empty matches all
    ]
    out = filter_subscriptions(alert, subs)
    assert {s["id"] for s in out} == {"1", "4"}


# ── HTTP routes — CRUD lifecycle ────────────────────────────────────


async def test_create_list_get_delete_round_trip(client, analyst_user):
    body = {
        "name": "Critical phishing",
        "description": "Test sub",
        "filter": {"severity": ["critical"], "category": ["phishing"]},
        "channels": [
            {"type": "webhook",
             "url": "https://soc.example/argus", "secret": "abc"},
        ],
        "active": True,
    }
    r = await client.post(
        "/api/v1/feed-subscriptions", json=body,
        headers=analyst_user["headers"],
    )
    assert r.status_code == 201, r.text
    created = r.json()
    sub_id = created["id"]
    assert created["name"] == "Critical phishing"
    assert created["channels"][0]["type"] == "webhook"

    r = await client.get(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    items = r.json()
    assert any(s["id"] == sub_id for s in items)

    r = await client.get(
        f"/api/v1/feed-subscriptions/{sub_id}",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["id"] == sub_id

    r = await client.delete(
        f"/api/v1/feed-subscriptions/{sub_id}",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 204

    r = await client.get(
        f"/api/v1/feed-subscriptions/{sub_id}",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_patch_updates_filter_and_active(client, analyst_user):
    r = await client.post(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
        json={"name": "v1", "filter": {"severity": ["low"]}, "channels": []},
    )
    assert r.status_code == 201
    sub_id = r.json()["id"]
    r = await client.patch(
        f"/api/v1/feed-subscriptions/{sub_id}",
        headers=analyst_user["headers"],
        json={"filter": {"severity": ["critical"]}, "active": False},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["filter"] == {"severity": ["critical"]}
    assert body["active"] is False


async def test_invalid_channel_type_rejected(client, analyst_user):
    r = await client.post(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
        json={
            "name": "bad", "filter": {},
            "channels": [{"type": "carrier-pigeon", "url": "https://x"}],
        },
    )
    assert r.status_code == 422


async def test_webhook_channel_requires_url(client, analyst_user):
    r = await client.post(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
        json={
            "name": "no url", "filter": {},
            "channels": [{"type": "webhook"}],
        },
    )
    assert r.status_code == 422


async def test_email_channel_requires_address(client, analyst_user):
    r = await client.post(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
        json={
            "name": "no addr", "filter": {},
            "channels": [{"type": "email"}],
        },
    )
    assert r.status_code == 422


async def test_test_endpoint_dry_runs_match(client, analyst_user):
    r = await client.post(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
        json={
            "name": "match-test",
            "filter": {"severity": ["critical"]},
            "channels": [],
        },
    )
    assert r.status_code == 201
    sub_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/feed-subscriptions/{sub_id}/test",
        headers=analyst_user["headers"],
        json={"alert": {"severity": "critical", "title": "yes"}},
    )
    assert r.status_code == 200
    assert r.json()["matches"] is True

    r = await client.post(
        f"/api/v1/feed-subscriptions/{sub_id}/test",
        headers=analyst_user["headers"],
        json={"alert": {"severity": "low"}},
    )
    assert r.status_code == 200
    assert r.json()["matches"] is False


async def test_user_cannot_see_other_users_subscriptions(
    client, analyst_user, test_engine,
):
    """Subscription listing is scoped to the authenticated user.
    Creating a sub as user A and listing as user B must not surface it."""
    import uuid as _uuid

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from src.core.auth import UserRole, create_access_token, hash_password
    from src.models.auth import User

    factory = async_sessionmaker(test_engine, class_=AsyncSession,
                                  expire_on_commit=False)
    async with factory() as s:
        suffix = _uuid.uuid4().hex[:8]
        u = User(
            email=f"other-{suffix}@argus.test",
            username=f"other_{suffix}",
            password_hash=hash_password("pw"),
            display_name="Other",
            role=UserRole.ANALYST.value,
            is_active=True,
        )
        s.add(u)
        await s.commit()
        await s.refresh(u)
    other_token = create_access_token(
        str(u.id), UserRole.ANALYST.value, u.email,
    )
    other_headers = {"Authorization": f"Bearer {other_token}"}

    # User A creates a sub.
    r = await client.post(
        "/api/v1/feed-subscriptions",
        headers=analyst_user["headers"],
        json={"name": "A-only", "filter": {}, "channels": []},
    )
    assert r.status_code == 201
    sub_id = r.json()["id"]

    # User B lists — must not see it.
    r = await client.get(
        "/api/v1/feed-subscriptions", headers=other_headers,
    )
    assert r.status_code == 200
    assert all(s["id"] != sub_id for s in r.json())

    # User B fetches by id — must 404.
    r = await client.get(
        f"/api/v1/feed-subscriptions/{sub_id}", headers=other_headers,
    )
    assert r.status_code == 404


async def test_requires_auth(client):
    r = await client.get("/api/v1/feed-subscriptions")
    assert r.status_code in (401, 403)
