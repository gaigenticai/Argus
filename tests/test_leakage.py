"""Phase 5 — Data Leakage tests (CC + DLP)."""

from __future__ import annotations

import io
import uuid

import pytest
from httpx import AsyncClient

from src.leakage.cards import _luhn, extract_candidates

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# Real test PAN: standard test card 4111 1111 1111 1111 (Luhn-valid)
_TEST_PAN_VISA = "4111111111111111"
_TEST_PAN_MC = "5454545454545454"
_TEST_PAN_AMEX = "378282246310005"
_NOT_A_PAN = "1234567812345678"  # fails Luhn


# --- Pure ----------------------------------------------------------


def test_luhn_validates_test_pans():
    assert _luhn(_TEST_PAN_VISA)
    assert _luhn(_TEST_PAN_MC)
    assert _luhn(_TEST_PAN_AMEX)
    assert not _luhn(_NOT_A_PAN)
    assert not _luhn("12")  # too short


def test_extract_candidates_luhn_filters():
    text = (
        f"Leaked dump: {_TEST_PAN_VISA[:4]} {_TEST_PAN_VISA[4:8]} "
        f"{_TEST_PAN_VISA[8:12]} {_TEST_PAN_VISA[12:]} 03/26 cvv 123. "
        f"Also {_NOT_A_PAN} (not luhn)."
    )
    cands = extract_candidates(text)
    assert len(cands) == 1
    assert cands[0].pan == _TEST_PAN_VISA
    assert cands[0].first6 == "411111"
    assert cands[0].last4 == "1111"
    assert cands[0].scheme_hint == "visa"


# --- BIN import + scan ----------------------------------------------


async def _import_test_bins(client, analyst, organization_id):
    csv_data = (
        "bin_prefix,issuer,scheme,card_type,country_code\n"
        "411111,Argus Bank,visa,credit,US\n"
        "545454,Acme MC,mastercard,debit,GB\n"
    )
    return await client.post(
        "/api/v1/leakage/bins/import",
        data={"organization_id": str(organization_id)},
        files={"file": ("bins.csv", io.BytesIO(csv_data.encode()), "text/csv")},
        headers=_hdr(analyst),
    )


async def test_bin_import_persists_rows(
    client: AsyncClient, analyst_user, organization
):
    r = await _import_test_bins(client, analyst_user, organization["id"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 2

    listed = await client.get(
        "/api/v1/leakage/bins",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert listed.status_code == 200
    prefixes = {b["bin_prefix"] for b in listed.json()}
    assert {"411111", "545454"} <= prefixes


async def test_card_scan_creates_finding_with_bin_match(
    client: AsyncClient, analyst_user, organization
):
    await _import_test_bins(client, analyst_user, organization["id"])
    text = (
        f"Stealer dump: {_TEST_PAN_VISA[:4]} {_TEST_PAN_VISA[4:8]} "
        f"{_TEST_PAN_VISA[8:12]} {_TEST_PAN_VISA[12:]} exp 12/27 cvv 999"
    )
    r = await client.post(
        "/api/v1/leakage/cards/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": text,
            "source_url": "https://paste.example/abcd",
            "source_kind": "paste",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    assert r.json()["new_findings"] == 1

    listed = await client.get(
        "/api/v1/leakage/cards",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    f = next(iter(listed.json()))
    assert f["pan_first6"] == "411111"
    assert f["pan_last4"] == "1111"
    assert f["issuer"] == "Argus Bank"
    assert f["scheme"] == "visa"
    # PAN redaction guarantee lives in the structured fields above
    # (pan_first6 / pan_last4). The excerpt deliberately preserves the
    # source data so analysts can see context — see card_leakage_findings
    # docstring. There is no excerpt-redaction assertion here on purpose.


async def test_card_scan_skips_unknown_bin_when_required(
    client: AsyncClient, analyst_user, organization
):
    # No BIN imported. require_bin_match=True (default) → 0 findings.
    text = f"PAN: {_TEST_PAN_VISA}"
    r = await client.post(
        "/api/v1/leakage/cards/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": text,
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()["candidates"] == 1
    assert r.json()["new_findings"] == 0

    # Now allow unknown BIN
    r2 = await client.post(
        "/api/v1/leakage/cards/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": text,
            "require_bin_match": False,
        },
        headers=_hdr(analyst_user),
    )
    assert r2.json()["new_findings"] == 1


async def test_card_scan_idempotent(
    client: AsyncClient, analyst_user, organization
):
    await _import_test_bins(client, analyst_user, organization["id"])
    text = f"PAN {_TEST_PAN_VISA}"
    payload = {
        "organization_id": str(organization["id"]),
        "text": text,
        "source_url": "https://paste.example/x",
    }
    a = await client.post(
        "/api/v1/leakage/cards/scan", json=payload, headers=_hdr(analyst_user)
    )
    b = await client.post(
        "/api/v1/leakage/cards/scan", json=payload, headers=_hdr(analyst_user)
    )
    assert a.json()["new_findings"] == 1
    assert b.json()["new_findings"] == 0
    assert b.json()["seen_again"] == 1


async def test_card_state_change(
    client: AsyncClient, analyst_user, organization
):
    await _import_test_bins(client, analyst_user, organization["id"])
    await client.post(
        "/api/v1/leakage/cards/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": f"Card: {_TEST_PAN_VISA}",
        },
        headers=_hdr(analyst_user),
    )
    listed = await client.get(
        "/api/v1/leakage/cards",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    fid = listed.json()[0]["id"]
    no_reason = await client.post(
        f"/api/v1/leakage/cards/{fid}/state",
        json={"to_state": "notified"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422
    ok = await client.post(
        f"/api/v1/leakage/cards/{fid}/state",
        json={"to_state": "notified", "reason": "issuer notified, awaiting reissue"},
        headers=_hdr(analyst_user),
    )
    assert ok.status_code == 200
    assert ok.json()["state"] == "notified"


# --- DLP --------------------------------------------------------------


async def _create_policy(client, analyst, organization, **kwargs):
    payload = {
        "organization_id": str(organization["id"]),
        "name": kwargs.pop("name", "test"),
        "kind": kwargs.pop("kind", "keyword"),
        "pattern": kwargs.pop("pattern", "secret"),
        "severity": kwargs.pop("severity", "high"),
    }
    payload.update(kwargs)
    return await client.post(
        "/api/v1/leakage/policies", json=payload, headers=_hdr(analyst)
    )


async def test_dlp_keyword_policy(
    client: AsyncClient, analyst_user, organization
):
    await _create_policy(
        client, analyst_user, organization,
        name="bank-internal", kind="keyword", pattern="ARGUS-INTERNAL", severity="high",
    )
    r = await client.post(
        "/api/v1/leakage/dlp/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": "Some leaked doc says ARGUS-INTERNAL Project Stealth, deadline 2026-Q3.",
            "source_url": "https://paste.example/leak",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()["findings_created"] == 1


async def test_dlp_regex_policy(
    client: AsyncClient, analyst_user, organization
):
    # Match Argus internal employee ID format ARGEMP-12345
    await _create_policy(
        client, analyst_user, organization,
        name="emp-id", kind="regex", pattern=r"ARGEMP-\d{5}", severity="medium",
    )
    r = await client.post(
        "/api/v1/leakage/dlp/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": "Resume mentions ARGEMP-04812 and ARGEMP-99001 leaked from HR system.",
        },
        headers=_hdr(analyst_user),
    )
    assert r.json()["findings_created"] == 1
    assert r.json()["matches_found"] >= 2


async def test_dlp_invalid_regex_rejected(
    client: AsyncClient, analyst_user, organization
):
    r = await _create_policy(
        client, analyst_user, organization,
        name="bad", kind="regex", pattern="[unclosed",
    )
    assert r.status_code == 422


async def test_dlp_test_endpoint(
    client: AsyncClient, analyst_user, organization
):
    create = await _create_policy(
        client, analyst_user, organization,
        name="alpha", kind="keyword", pattern="alpha",
    )
    pid = create.json()["id"]
    r = await client.post(
        f"/api/v1/leakage/policies/{pid}/test",
        json={"text": "alpha bravo alpha charlie"},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()["matched"] == 2


async def test_dlp_state_change(
    client: AsyncClient, analyst_user, organization
):
    await _create_policy(
        client, analyst_user, organization,
        name="confidential", kind="keyword", pattern="CONFIDENTIAL",
    )
    await client.post(
        "/api/v1/leakage/dlp/scan",
        json={
            "organization_id": str(organization["id"]),
            "text": "CONFIDENTIAL: do not redistribute",
        },
        headers=_hdr(analyst_user),
    )
    listed = await client.get(
        "/api/v1/leakage/dlp",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    fid = listed.json()[0]["id"]
    ok = await client.post(
        f"/api/v1/leakage/dlp/{fid}/state",
        json={"to_state": "notified", "reason": "exec briefed"},
        headers=_hdr(analyst_user),
    )
    assert ok.status_code == 200
    assert ok.json()["state"] == "notified"


async def test_dlp_tenant_isolation(
    client: AsyncClient, analyst_user, organization, second_organization
):
    await _create_policy(
        client, analyst_user, organization,
        name="X", kind="keyword", pattern="leak",
    )
    # Org B has no policies — scan returns 0
    r = await client.post(
        "/api/v1/leakage/dlp/scan",
        json={
            "organization_id": str(second_organization["id"]),
            "text": "this leak should not match",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()["findings_created"] == 0
