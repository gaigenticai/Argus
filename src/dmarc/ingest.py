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
from src.models.dmarc_forensic import DmarcForensicReport
from src.models.threat import Asset

from .parser import (
    ParsedDmarcReport,
    ParsedForensic,
    parse_aggregate,
    parse_forensic,
)


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

    # Fan out RCA agents for every misaligned record (cap so a noisy
    # report doesn't bloat the queue).
    try:
        await _enqueue_alignment_rca(db, organization_id, report.id, parsed.records)
    except Exception:  # noqa: BLE001 — never fail ingest because the queue is wedged
        pass

    return report, len(parsed.records)


async def _enqueue_alignment_rca(
    db: AsyncSession,
    organization_id: uuid.UUID,
    report_id: uuid.UUID,
    records: list,
    *,
    cap: int = 50,
) -> None:
    from src.llm.agent_queue import enqueue

    failing = [
        r for r in records if (r.spf_aligned is False or r.dkim_aligned is False)
    ]
    for rec in failing[:cap]:
        await enqueue(
            db,
            kind="dmarc_alignment_rca",
            payload={
                "report_id": str(report_id),
                "source_ip": rec.source_ip,
                "header_from": rec.header_from,
                "envelope_from": rec.envelope_from,
                "spf_result": rec.spf_result,
                "dkim_result": rec.dkim_result,
                "spf_aligned": rec.spf_aligned,
                "dkim_aligned": rec.dkim_aligned,
                "count": rec.count,
            },
            organization_id=organization_id,
            dedup_key=f"rca:{report_id}:{rec.source_ip}",
            priority=6,
        )


async def ingest_forensic(
    db: AsyncSession,
    organization_id: uuid.UUID,
    blob: bytes,
) -> tuple[list[DmarcForensicReport], int]:
    """Idempotently insert RUF rows and enqueue lookalike-detect agents.

    Returns ``(rows, inserted_count)``. We dedup on
    (organization_id, source_ip, reported_domain, arrival_date,
    original_mail_from) — DMARC RUFs from the same incident often get
    re-sent by the receiver.
    """
    parsed_list = parse_forensic(blob)
    inserted: list[DmarcForensicReport] = []
    skipped = 0
    for p in parsed_list:
        domain = (p.reported_domain or "").lower() or "unknown"
        # Best-effort idempotency
        existing_q = select(DmarcForensicReport).where(
            and_(
                DmarcForensicReport.organization_id == organization_id,
                DmarcForensicReport.domain == domain,
                DmarcForensicReport.source_ip == p.source_ip,
                DmarcForensicReport.original_mail_from == p.original_mail_from,
                DmarcForensicReport.arrival_date == p.arrival_date,
            )
        )
        existing = (await db.execute(existing_q)).scalar_one_or_none()
        if existing is not None:
            skipped += 1
            inserted.append(existing)
            continue

        row = DmarcForensicReport(
            organization_id=organization_id,
            domain=domain,
            feedback_type=p.feedback_type,
            arrival_date=p.arrival_date,
            source_ip=p.source_ip,
            reported_domain=p.reported_domain,
            original_envelope_from=p.original_envelope_from,
            original_envelope_to=p.original_envelope_to,
            original_mail_from=p.original_mail_from,
            original_rcpt_to=p.original_rcpt_to,
            auth_failure=p.auth_failure,
            delivery_result=p.delivery_result,
            raw_headers=p.raw_headers,
            dkim_domain=p.dkim_domain,
            dkim_selector=p.dkim_selector,
            spf_domain=p.spf_domain,
            extras=p.extras or {},
        )
        db.add(row)
        await db.flush()
        inserted.append(row)

        # Enqueue lookalike detection — cheap dedup so the same spoof
        # source doesn't multiply.
        try:
            from src.llm.agent_queue import enqueue

            await enqueue(
                db,
                kind="dmarc_lookalike_detect",
                payload={
                    "forensic_id": str(row.id),
                    "domain": domain,
                    "source_ip": p.source_ip,
                    "original_mail_from": p.original_mail_from,
                    "spf_domain": p.spf_domain,
                    "dkim_domain": p.dkim_domain,
                },
                organization_id=organization_id,
                dedup_key=f"lookalike:{row.id}",
                priority=5,
            )
        except Exception:  # noqa: BLE001
            pass

    return inserted, len(inserted) - skipped


__all__ = ["ingest_aggregate", "ingest_forensic"]
