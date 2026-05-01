"""DMARC report ingestion — converts parsed RUA → DB rows + asset enrichment.

Public API:

    await ingest_aggregate(db, organization_id, blob)

Returns the persisted :class:`DmarcReport` and a list of new
``DmarcReportRecord`` rows.

Side effects
------------
- If an ``email_domain`` asset matches the report's ``policy_published``
  domain, we update its ``details.dmarc_policy`` / ``dmarc_pct`` to
  match the *observed* policy (not the recommended one). This keeps the
  Security Rating's email_auth pillar accurate.
- Idempotent on (organization_id, domain, report_id, kind): re-ingesting
  the same report returns the existing row.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.dmarc import DmarcReport, DmarcReportKind, DmarcReportRecord
from src.models.threat import Asset

from .parser import parse_aggregate, ParsedDmarcReport


async def ingest_aggregate(
    db: AsyncSession,
    organization_id: uuid.UUID,
    blob: bytes,
) -> tuple[DmarcReport, int]:
    parsed = parse_aggregate(blob)
    raw_sha = hashlib.sha256(blob).hexdigest()

    existing = (
        await db.execute(
            select(DmarcReport).where(
                and_(
                    DmarcReport.organization_id == organization_id,
                    DmarcReport.domain == parsed.domain,
                    DmarcReport.report_id == parsed.report_id,
                    DmarcReport.kind == DmarcReportKind.AGGREGATE.value,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, 0

    asset = (
        await db.execute(
            select(Asset).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.asset_type == "email_domain",
                    Asset.value == parsed.domain,
                )
            )
        )
    ).scalar_one_or_none()

    pass_count = sum(
        r.count for r in parsed.records if (r.spf_aligned or r.dkim_aligned)
    )
    fail_count = parsed.total_messages - pass_count
    quarantine_count = sum(
        r.count for r in parsed.records if r.disposition == "quarantine"
    )
    reject_count = sum(
        r.count for r in parsed.records if r.disposition == "reject"
    )

    report = DmarcReport(
        organization_id=organization_id,
        asset_id=asset.id if asset else None,
        kind=DmarcReportKind.AGGREGATE.value,
        domain=parsed.domain,
        org_name=parsed.org_name,
        report_id=parsed.report_id,
        date_begin=parsed.date_begin,
        date_end=parsed.date_end,
        policy_p=parsed.policy_p,
        policy_pct=parsed.policy_pct,
        total_messages=parsed.total_messages,
        pass_count=pass_count,
        fail_count=fail_count,
        quarantine_count=quarantine_count,
        reject_count=reject_count,
        raw_xml_sha256=raw_sha,
        parsed={
            "org_name": parsed.org_name,
            "policy_p": parsed.policy_p,
            "policy_pct": parsed.policy_pct,
        },
    )
    db.add(report)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        # Race; re-fetch
        return (
            (
                await db.execute(
                    select(DmarcReport).where(
                        and_(
                            DmarcReport.organization_id == organization_id,
                            DmarcReport.domain == parsed.domain,
                            DmarcReport.report_id == parsed.report_id,
                        )
                    )
                )
            ).scalar_one(),
            0,
        )

    for rec in parsed.records:
        db.add(
            DmarcReportRecord(
                report_id=report.id,
                organization_id=organization_id,
                domain=parsed.domain,
                source_ip=rec.source_ip,
                count=rec.count,
                disposition=rec.disposition,
                spf_result=rec.spf_result,
                dkim_result=rec.dkim_result,
                spf_aligned=rec.spf_aligned,
                dkim_aligned=rec.dkim_aligned,
                header_from=rec.header_from,
                envelope_from=rec.envelope_from,
            )
        )

    # Enrich the asset's policy snapshot
    if asset is not None and parsed.policy_p is not None:
        details = dict(asset.details or {})
        details["dmarc_policy"] = parsed.policy_p
        if parsed.policy_pct is not None:
            details["dmarc_pct"] = parsed.policy_pct
        asset.details = details
        asset.last_change_at = datetime.now(timezone.utc)

    await db.flush()
    return report, len(parsed.records)


__all__ = ["ingest_aggregate"]
