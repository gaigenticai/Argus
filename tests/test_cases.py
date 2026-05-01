"""Case Management — integration tests.

Lifecycle: create → patch → transition → link/unlink alerts → comments
→ close → reopen → delete.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Create + read ------------------------------------------------------


async def test_create_case_with_initial_findings(
    client: AsyncClient, analyst_user, organization, make_alert
):
    h = _hdr(analyst_user)
    a1 = await make_alert(organization["id"])
    a2 = await make_alert(organization["id"], severity="critical")

    r = await client.post(
        "/api/v1/cases",
        json={
            "organization_id": str(organization["id"]),
            "title": "Phishing campaign — Argus impersonation",
            "summary": "Multiple lookalike domains targeting our brand.",
            "severity": "high",
            "tags": ["phishing", "brand"],
            "initial_alert_ids": [str(a1), str(a2)],
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    case = r.json()
    assert case["state"] == "open"
    assert case["severity"] == "high"
    assert case["owner_user_id"] is not None

    # Detail view shows the linked findings + initial state transition
    detail = await client.get(f"/api/v1/cases/{case['id']}", headers=h)
    assert detail.status_code == 200
    assert {f["alert_id"] for f in detail.json()["findings"]} == {str(a1), str(a2)}
    assert len(detail.json()["transitions"]) == 1
    assert detail.json()["transitions"][0]["to_state"] == "open"


async def test_create_rejects_alert_in_wrong_org(
    client: AsyncClient, analyst_user, organization, second_organization, make_alert
):
    h = _hdr(analyst_user)
    foreign = await make_alert(second_organization["id"])
    r = await client.post(
        "/api/v1/cases",
        json={
            "organization_id": str(organization["id"]),
            "title": "wrong-org test",
            "initial_alert_ids": [str(foreign)],
        },
        headers=h,
    )
    assert r.status_code == 422


# --- Filters + counts ---------------------------------------------------


async def test_list_filters_and_counts(
    client: AsyncClient, analyst_user, organization
):
    h = _hdr(analyst_user)
    org_id = str(organization["id"])

    seed = [
        {"title": "filter-A", "severity": "high", "tags": ["alpha"]},
        {"title": "filter-B", "severity": "low", "tags": ["beta"]},
        {"title": "filter-C", "severity": "critical", "tags": ["alpha"]},
    ]
    ids = []
    for s in seed:
        r = await client.post(
            "/api/v1/cases",
            json={"organization_id": org_id, **s},
            headers=h,
        )
        ids.append(r.json()["id"])

    only_alpha = await client.get(
        "/api/v1/cases", params={"organization_id": org_id, "tag": "alpha"}, headers=h
    )
    titles = {c["title"] for c in only_alpha.json()}
    assert "filter-A" in titles and "filter-C" in titles and "filter-B" not in titles

    only_critical = await client.get(
        "/api/v1/cases",
        params={"organization_id": org_id, "severity": "critical"},
        headers=h,
    )
    assert {c["title"] for c in only_critical.json()} >= {"filter-C"}

    counts = await client.get(
        "/api/v1/cases/count", params={"organization_id": org_id}, headers=h
    )
    assert counts.status_code == 200
    body = counts.json()
    assert body["total"] >= 3
    assert body["by_severity"].get("critical", 0) >= 1


# --- State machine ------------------------------------------------------


async def test_full_state_machine_progression(
    client: AsyncClient, analyst_user, organization
):
    h = _hdr(analyst_user)
    org_id = str(organization["id"])

    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": org_id, "title": "state machine"},
        headers=h,
    )
    case_id = create.json()["id"]

    sequence = ["triaged", "in_progress", "remediated", "verified", "closed"]
    for to in sequence:
        r = await client.post(
            f"/api/v1/cases/{case_id}/transitions",
            json={"to_state": to, "reason": f"moving to {to}"},
            headers=h,
        )
        assert r.status_code == 200, f"{to} failed: {r.text}"
        assert r.json()["state"] == to

    # Closed: comments and edits forbidden
    bad_comment = await client.post(
        f"/api/v1/cases/{case_id}/comments", json={"body": "nope"}, headers=h
    )
    assert bad_comment.status_code == 409

    # Reopen requires reason
    no_reason = await client.post(
        f"/api/v1/cases/{case_id}/transitions",
        json={"to_state": "open"},
        headers=h,
    )
    assert no_reason.status_code == 422

    reopen = await client.post(
        f"/api/v1/cases/{case_id}/transitions",
        json={"to_state": "open", "reason": "false positive caught in QA"},
        headers=h,
    )
    assert reopen.status_code == 200
    assert reopen.json()["state"] == "open"
    assert reopen.json()["closed_at"] is None

    # Detail view exposes full history
    detail = await client.get(f"/api/v1/cases/{case_id}", headers=h)
    states = [t["to_state"] for t in detail.json()["transitions"]]
    assert states[0] == "open"  # initial
    assert states[-1] == "open"  # reopen
    assert "closed" in states


async def test_invalid_transition_blocked(
    client: AsyncClient, analyst_user, organization
):
    h = _hdr(analyst_user)
    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "skip-test"},
        headers=h,
    )
    case_id = create.json()["id"]
    # open → in_progress is not allowed (must triage first)
    bad = await client.post(
        f"/api/v1/cases/{case_id}/transitions",
        json={"to_state": "in_progress"},
        headers=h,
    )
    assert bad.status_code == 422


# --- Findings linking ---------------------------------------------------


async def test_link_unlink_finding(
    client: AsyncClient, analyst_user, organization, make_alert
):
    h = _hdr(analyst_user)
    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "link test"},
        headers=h,
    )
    case_id = create.json()["id"]
    alert_id = str(await make_alert(organization["id"]))

    link = await client.post(
        f"/api/v1/cases/{case_id}/findings",
        json={"alert_id": alert_id, "is_primary": True, "reason": "primary IOC"},
        headers=h,
    )
    assert link.status_code == 201

    # Duplicate link is rejected
    dup = await client.post(
        f"/api/v1/cases/{case_id}/findings",
        json={"alert_id": alert_id},
        headers=h,
    )
    assert dup.status_code == 409

    # Unlink
    unlink = await client.delete(
        f"/api/v1/cases/{case_id}/findings/{alert_id}", headers=h
    )
    assert unlink.status_code == 204


# --- Comments -----------------------------------------------------------


async def test_comments_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    h = _hdr(analyst_user)
    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "comments"},
        headers=h,
    )
    case_id = create.json()["id"]

    add = await client.post(
        f"/api/v1/cases/{case_id}/comments",
        json={"body": "initial finding looks consistent with FIN7"},
        headers=h,
    )
    assert add.status_code == 201
    comment_id = add.json()["id"]

    edit = await client.patch(
        f"/api/v1/cases/{case_id}/comments/{comment_id}",
        json={"body": "edited: looks like FIN7 sub-cluster"},
        headers=h,
    )
    assert edit.status_code == 200
    assert edit.json()["edited_at"] is not None

    # Soft-delete
    rm = await client.delete(
        f"/api/v1/cases/{case_id}/comments/{comment_id}", headers=h
    )
    assert rm.status_code == 204

    # Subsequent edit on deleted comment 404s
    edit2 = await client.patch(
        f"/api/v1/cases/{case_id}/comments/{comment_id}",
        json={"body": "still here?"},
        headers=h,
    )
    assert edit2.status_code == 404

    # Detail view hides soft-deleted
    detail = await client.get(f"/api/v1/cases/{case_id}", headers=h)
    assert all(c["id"] != comment_id for c in detail.json()["comments"])


async def test_comment_edit_requires_author(
    client: AsyncClient, analyst_user, organization, admin_user
):
    h_owner = _hdr(analyst_user)
    h_admin = _hdr(admin_user)

    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "author guard"},
        headers=h_owner,
    )
    case_id = create.json()["id"]
    add = await client.post(
        f"/api/v1/cases/{case_id}/comments",
        json={"body": "owner comment"},
        headers=h_owner,
    )
    comment_id = add.json()["id"]

    # admin cannot edit (author-only)
    edit = await client.patch(
        f"/api/v1/cases/{case_id}/comments/{comment_id}",
        json={"body": "admin override"},
        headers=h_admin,
    )
    assert edit.status_code == 403

    # admin CAN delete (admin override permitted for delete)
    rm = await client.delete(
        f"/api/v1/cases/{case_id}/comments/{comment_id}",
        headers=h_admin,
    )
    assert rm.status_code == 204


# --- Auth + delete authority -------------------------------------------


async def test_unauthenticated_rejected(client: AsyncClient, organization):
    r = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "anon"},
    )
    assert r.status_code in (401, 403)


async def test_delete_requires_owner_or_admin(
    client: AsyncClient, analyst_user, organization, test_engine, admin_user
):
    """Owner can delete. Other analyst cannot. Admin can."""
    h = _hdr(analyst_user)

    # Create a case as the analyst (becomes owner)
    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "owner delete"},
        headers=h,
    )
    case_id = create.json()["id"]

    # Make a SECOND analyst (non-owner)
    from src.core.auth import create_access_token, hash_password
    from src.models.auth import User, UserRole

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        suffix = uuid.uuid4().hex[:8]
        other = User(
            email=f"other-{suffix}@argus.test",
            username=f"other_{suffix}",
            password_hash=hash_password("x"),
            display_name=f"Other {suffix}",
            role=UserRole.ANALYST.value,
            is_active=True,
        )
        s.add(other)
        await s.commit()
        await s.refresh(other)

    other_token = create_access_token(str(other.id), UserRole.ANALYST.value, other.email)
    other_h = {"Authorization": f"Bearer {other_token}"}

    forbidden = await client.delete(f"/api/v1/cases/{case_id}", headers=other_h)
    assert forbidden.status_code == 403

    # Admin can delete
    ok_admin_delete = await client.delete(
        f"/api/v1/cases/{case_id}", headers=_hdr(admin_user)
    )
    assert ok_admin_delete.status_code == 204


async def test_audit_log_records_lifecycle(
    client: AsyncClient, analyst_user, organization, test_engine, make_alert
):
    h = _hdr(analyst_user)
    create = await client.post(
        "/api/v1/cases",
        json={"organization_id": str(organization["id"]), "title": "audit"},
        headers=h,
    )
    case_id = create.json()["id"]
    alert = str(await make_alert(organization["id"]))
    await client.post(
        f"/api/v1/cases/{case_id}/findings", json={"alert_id": alert}, headers=h
    )
    await client.post(
        f"/api/v1/cases/{case_id}/transitions",
        json={"to_state": "triaged"},
        headers=h,
    )
    await client.post(
        f"/api/v1/cases/{case_id}/comments",
        json={"body": "noted"},
        headers=h,
    )

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        result = await s.execute(
            select(AuditLog.action).where(
                AuditLog.action.in_([
                    AuditAction.CASE_CREATE.value,
                    AuditAction.CASE_FINDING_LINK.value,
                    AuditAction.CASE_TRANSITION.value,
                    AuditAction.CASE_COMMENT_ADD.value,
                ])
            )
        )
        actions = {row[0] for row in result.all()}

    assert AuditAction.CASE_CREATE.value in actions
    assert AuditAction.CASE_FINDING_LINK.value in actions
    assert AuditAction.CASE_TRANSITION.value in actions
    assert AuditAction.CASE_COMMENT_ADD.value in actions
