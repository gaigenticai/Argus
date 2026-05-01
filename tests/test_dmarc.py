"""DMARC360 (Phase 2) — full integration tests against real RUA XML.

Verifies:
    - real-shaped Google-style RUA XML is parsed correctly (header + records)
    - report ingestion is idempotent on (org, domain, report_id)
    - email_domain asset's policy gets enriched from observed RUA
    - gzipped RUA is accepted
    - reports list filters by domain
    - records endpoint surfaces per-IP counts
    - wizard outputs valid SPF + DMARC progression records
    - audit log emitted on ingest and wizard
"""

from __future__ import annotations

import gzip
import io
import textwrap

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


def _rua_xml(
    domain: str = "argus.test",
    report_id: str = "argus-rua-1",
    p: str = "quarantine",
    pct: int = 100,
    org_name: str = "google.com",
) -> bytes:
    return textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>{org_name}</org_name>
            <email>noreply-dmarc-support@google.com</email>
            <report_id>{report_id}</report_id>
            <date_range>
              <begin>1714435200</begin>
              <end>1714521600</end>
            </date_range>
          </report_metadata>
          <policy_published>
            <domain>{domain}</domain>
            <adkim>r</adkim>
            <aspf>r</aspf>
            <p>{p}</p>
            <sp>{p}</sp>
            <pct>{pct}</pct>
          </policy_published>
          <record>
            <row>
              <source_ip>209.85.220.41</source_ip>
              <count>43</count>
              <policy_evaluated>
                <disposition>none</disposition>
                <dkim>pass</dkim>
                <spf>pass</spf>
              </policy_evaluated>
            </row>
            <identifiers>
              <header_from>{domain}</header_from>
              <envelope_from>{domain}</envelope_from>
            </identifiers>
            <auth_results>
              <dkim>
                <domain>{domain}</domain>
                <result>pass</result>
              </dkim>
              <spf>
                <domain>{domain}</domain>
                <result>pass</result>
              </spf>
            </auth_results>
          </record>
          <record>
            <row>
              <source_ip>198.51.100.7</source_ip>
              <count>5</count>
              <policy_evaluated>
                <disposition>quarantine</disposition>
                <dkim>fail</dkim>
                <spf>fail</spf>
              </policy_evaluated>
            </row>
            <identifiers>
              <header_from>{domain}</header_from>
            </identifiers>
            <auth_results>
              <dkim>
                <domain>some-spoofer</domain>
                <result>fail</result>
              </dkim>
              <spf>
                <domain>some-spoofer</domain>
                <result>fail</result>
              </spf>
            </auth_results>
          </record>
        </feedback>
        """
    ).encode("utf-8")


# --- Parser ------------------------------------------------------------


def test_parser_handles_inline_xml():
    from src.dmarc.parser import parse_aggregate

    parsed = parse_aggregate(_rua_xml())
    assert parsed.domain == "argus.test"
    assert parsed.report_id == "argus-rua-1"
    assert parsed.policy_p == "quarantine"
    assert parsed.policy_pct == 100
    assert parsed.total_messages == 48
    assert len(parsed.records) == 2
    by_ip = {r.source_ip: r for r in parsed.records}
    assert by_ip["209.85.220.41"].count == 43
    assert by_ip["209.85.220.41"].spf_aligned is True
    assert by_ip["198.51.100.7"].disposition == "quarantine"


def test_parser_handles_gzip():
    from src.dmarc.parser import parse_aggregate

    blob = gzip.compress(_rua_xml())
    parsed = parse_aggregate(blob)
    assert parsed.domain == "argus.test"
    assert parsed.total_messages == 48


def test_parser_rejects_missing_report_id():
    from src.dmarc.parser import parse_aggregate

    bad = _rua_xml().replace(b"<report_id>argus-rua-1</report_id>", b"<report_id></report_id>")
    with pytest.raises(ValueError, match="report_id"):
        parse_aggregate(bad)


# --- Ingestion ---------------------------------------------------------


async def test_ingest_aggregate_persists_report_and_records(
    client: AsyncClient, analyst_user, organization
):
    blob = _rua_xml()
    r = await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(blob), "application/xml")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["domain"] == "argus.test"
    assert body["total_messages"] == 48
    assert body["pass_count"] == 43
    assert body["fail_count"] == 5
    assert body["quarantine_count"] == 5
    report_id = body["id"]

    records = await client.get(
        f"/api/v1/dmarc/reports/{report_id}/records",
        headers=_hdr(analyst_user),
    )
    assert records.status_code == 200
    assert len(records.json()) == 2


async def test_ingest_idempotent(
    client: AsyncClient, analyst_user, organization
):
    blob = _rua_xml(report_id="dedup-1")
    first = await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(blob), "application/xml")},
        headers=_hdr(analyst_user),
    )
    assert first.status_code == 201
    second = await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(blob), "application/xml")},
        headers=_hdr(analyst_user),
    )
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]


async def test_ingest_enriches_email_domain_asset(
    client: AsyncClient, analyst_user, organization
):
    # Seed asset with old policy
    await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "email_domain",
            "value": "enrich.test",
            "details": {"domain": "enrich.test", "dmarc_policy": "none"},
        },
        headers=_hdr(analyst_user),
    )
    blob = _rua_xml(domain="enrich.test", report_id="enrich-1", p="reject")
    r = await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(blob), "application/xml")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201

    listed = await client.get(
        "/api/v1/assets",
        params={
            "organization_id": str(organization["id"]),
            "asset_type": "email_domain",
            "q": "enrich.test",
        },
        headers=_hdr(analyst_user),
    )
    assert listed.status_code == 200
    asset = next(a for a in listed.json() if a["value"] == "enrich.test")
    assert asset["details"]["dmarc_policy"] == "reject"


async def test_ingest_invalid_xml_returns_422(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(b"<not_xml"), "application/xml")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422


async def test_ingest_empty_upload_rejected(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(b""), "application/xml")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422


async def test_list_filters_by_domain(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("a.xml", io.BytesIO(_rua_xml(domain="a.test", report_id="a")), "application/xml")},
        headers=_hdr(analyst_user),
    )
    await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("b.xml", io.BytesIO(_rua_xml(domain="b.test", report_id="b")), "application/xml")},
        headers=_hdr(analyst_user),
    )
    only_a = await client.get(
        "/api/v1/dmarc/reports",
        params={"organization_id": str(organization["id"]), "domain": "a.test"},
        headers=_hdr(analyst_user),
    )
    assert only_a.status_code == 200
    assert {r["domain"] for r in only_a.json()} == {"a.test"}


# --- Wizard ------------------------------------------------------------


async def test_wizard_generates_progression(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/dmarc/wizard/argus.test",
        json={
            "sending_ips": ["203.0.113.10"],
            "sending_includes": ["_spf.google.com"],
            "dkim_selectors": ["s1", "s2"],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "v=spf1" in body["spf_record"]
    assert "ip4:203.0.113.10" in body["spf_record"]
    assert "include:_spf.google.com" in body["spf_record"]
    assert body["spf_record"].endswith("-all")

    selectors = {d["name"] for d in body["dkim_records"]}
    assert {"s1._domainkey.argus.test", "s2._domainkey.argus.test"} <= selectors

    stages = [s["stage"] for s in body["dmarc_records_progression"]]
    assert stages[0].startswith("1.")
    assert "reject" in stages[-1]
    assert "v=DMARC1" in body["dmarc_records_progression"][0]["value"]
    assert "p=reject" in body["dmarc_records_progression"][-1]["value"]


async def test_wizard_rejects_invalid_domain(
    client: AsyncClient, analyst_user
):
    r = await client.post(
        "/api/v1/dmarc/wizard/not a domain",
        json={},
        headers=_hdr(analyst_user),
    )
    # FastAPI URL path encoding: spaces in path → 422 from Pydantic validation
    # Either route returns 422 or our wizard ValueError → 422
    assert r.status_code in (404, 422)


async def test_audit_log_for_ingest_and_wizard(
    client: AsyncClient, analyst_user, organization, test_engine
):
    blob = _rua_xml(report_id="audit-rua")
    await client.post(
        "/api/v1/dmarc/reports/aggregate",
        data={"organization_id": str(organization["id"])},
        files={"file": ("rua.xml", io.BytesIO(blob), "application/xml")},
        headers=_hdr(analyst_user),
    )
    await client.post(
        "/api/v1/dmarc/wizard/argus.test",
        json={},
        headers=_hdr(analyst_user),
    )

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        rows = await s.execute(
            select(AuditLog.action).where(
                AuditLog.action.in_(
                    [
                        AuditAction.DMARC_REPORT_INGEST.value,
                        AuditAction.DMARC_WIZARD_GENERATE.value,
                    ]
                )
            )
        )
        actions = {row[0] for row in rows.all()}
    assert AuditAction.DMARC_REPORT_INGEST.value in actions
    assert AuditAction.DMARC_WIZARD_GENERATE.value in actions


async def test_unauthenticated_rejected(client: AsyncClient):
    r = await client.post(
        "/api/v1/dmarc/wizard/argus.test", json={}
    )
    assert r.status_code in (401, 403)
