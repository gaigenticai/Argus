"""Phase 11 — Monthly executive report (PDF).

Generates a one-page PDF summary using ``reportlab`` (already in
requirements). Aggregates the org's current security rating, exposure
totals by severity, suspect-domain count, takedown ticket counts, and
recent SLA breach count over a configurable window.

Endpoint
--------
    GET /reports/exec-summary?organization_id=…&days=30   (PDF download)
"""

from __future__ import annotations

import io
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.brand import SuspectDomain, SuspectDomainState
from src.models.cases import Case, CaseState
from src.models.exposures import ExposureFinding, ExposureSeverity, ExposureState
from src.models.ratings import SecurityRating
from src.models.sla import SlaBreachEvent
from src.models.takedown import TakedownState, TakedownTicket
from src.models.threat import Organization
from src.storage.database import get_session

router = APIRouter(prefix="/exec-summary", tags=["Compliance & DLP"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# Audit D15 — pluggable PDF font. If `ARGUS_PDF_FONT_PATH` points at a
# .ttf file (typically Inter-Regular.ttf), we register it as the body
# font and Inter-Bold for headings. Falls back to Helvetica when the
# env var is unset or the file is missing — Helvetica is bundled with
# reportlab so the report always renders.
_FONT_REGISTERED: tuple[str, str] | None = None


def _resolve_fonts() -> tuple[str, str]:
    """Return ``(regular, bold)`` font names to use in this process."""
    global _FONT_REGISTERED
    if _FONT_REGISTERED is not None:
        return _FONT_REGISTERED

    import os
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font_path = os.environ.get("ARGUS_PDF_FONT_PATH")
    bold_path = os.environ.get("ARGUS_PDF_FONT_BOLD_PATH") or font_path
    if font_path and os.path.exists(font_path):
        try:
            pdfmetrics.registerFont(TTFont("ArgusBody", font_path))
            if bold_path and os.path.exists(bold_path):
                pdfmetrics.registerFont(TTFont("ArgusBodyBold", bold_path))
                _FONT_REGISTERED = ("ArgusBody", "ArgusBodyBold")
            else:
                _FONT_REGISTERED = ("ArgusBody", "ArgusBody")
            return _FONT_REGISTERED
        except Exception:  # noqa: BLE001 — invalid TTF, fall through
            pass
    _FONT_REGISTERED = ("Helvetica", "Helvetica-Bold")
    return _FONT_REGISTERED


def _render_pdf(
    org_name: str,
    window_days: int,
    rating_score: float | None,
    rating_grade: str | None,
    exposure_counts: dict[str, int],
    suspect_open: int,
    cases_open: int,
    sla_breaches: int,
    takedowns_open: int,
    takedowns_succeeded: int,
    generated_at: datetime,
    *,
    org_logo_bytes: bytes | None = None,
) -> bytes:
    """Render a one-page exec summary PDF. Uses reportlab. Pure-Python.

    ``org_logo_bytes`` is an optional PNG/JPEG/GIF blob that gets
    embedded in the header band. Image-format support is whatever
    Pillow / reportlab.lib.utils.ImageReader handles natively.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    body_font, bold_font = _resolve_fonts()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title=f"Argus Exec Summary — {org_name}",
        author="Argus",
    )
    styles = getSampleStyleSheet()
    # Override the default font on every style so every line renders in
    # Inter (or whatever ARGUS_PDF_FONT_PATH is) instead of Helvetica.
    H1 = ParagraphStyle(
        "ArgusH1",
        parent=styles["Heading1"],
        fontName=bold_font,
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1C252E"),
    )
    H2 = ParagraphStyle(
        "ArgusH2",
        parent=styles["Heading2"],
        fontName=bold_font,
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1C252E"),
    )
    NORM = ParagraphStyle(
        "ArgusBody",
        parent=styles["BodyText"],
        fontName=body_font,
        fontSize=10,
        leading=13,
    )

    story = []

    # --- Header band: org logo (if provided) + report title --------
    title_para = Paragraph("Argus — Executive Security Summary", H1)
    if org_logo_bytes:
        try:
            img = Image(ImageReader(io.BytesIO(org_logo_bytes)))
            # Constrain to 1 inch tall, preserve aspect ratio.
            w, h = img.imageWidth, img.imageHeight
            scale = min(1.0 * inch / max(h, 1), 1.5 * inch / max(w, 1))
            img.drawHeight = h * scale
            img.drawWidth = w * scale
            header = Table(
                [[img, title_para]],
                colWidths=[1.6 * inch, 5.0 * inch],
            )
            header.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ]
                )
            )
            story.append(header)
        except Exception:  # noqa: BLE001 — fall back to title-only on bad image
            story.append(title_para)
    else:
        story.append(title_para)

    story.append(
        Paragraph(
            f"<b>Organization:</b> {org_name} &nbsp; "
            f"<b>Window:</b> last {window_days} days &nbsp; "
            f"<b>Generated:</b> {generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            NORM,
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    rating_str = (
        f"{rating_score:.1f} ({rating_grade})"
        if rating_score is not None
        else "Not yet computed"
    )
    headline = [
        ["Security Rating", rating_str],
        ["Open Exposures (any sev)", str(sum(exposure_counts.values()))],
        ["Open Suspect Domains", str(suspect_open)],
        ["Open Cases", str(cases_open)],
        ["SLA Breaches in window", str(sla_breaches)],
        ["Takedowns — open / succeeded", f"{takedowns_open} / {takedowns_succeeded}"],
    ]
    t = Table(headline, colWidths=[2.6 * inch, 4.0 * inch])
    t.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, -1), body_font, 10),
                ("FONT", (0, 0), (0, -1), bold_font, 10),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F6F8")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t)

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Exposure breakdown by severity", H2))

    # Audit D16 — pie chart of exposures by severity, side-by-side with
    # the count table. No matplotlib — reportlab.graphics ships native
    # Pie + VerticalBarChart primitives so we stay lightweight.
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing, String

    _SEV_COLORS = {
        "critical": colors.HexColor("#B91C1C"),
        "high": colors.HexColor("#EA580C"),
        "medium": colors.HexColor("#D97706"),
        "low": colors.HexColor("#16A34A"),
        "info": colors.HexColor("#2563EB"),
    }

    sev_data = [(sev, exposure_counts.get(sev, 0)) for sev in
                ("critical", "high", "medium", "low", "info")]
    pie_drawing = Drawing(2.4 * inch, 2.0 * inch)
    if sum(c for _, c in sev_data):
        pie = Pie()
        pie.x = 0.4 * inch
        pie.y = 0.2 * inch
        pie.width = 1.6 * inch
        pie.height = 1.6 * inch
        pie.data = [c for _, c in sev_data]
        pie.labels = [s for s, _ in sev_data]
        pie.slices.strokeColor = colors.white
        pie.slices.strokeWidth = 1
        for i, (sev, _) in enumerate(sev_data):
            pie.slices[i].fillColor = _SEV_COLORS.get(sev, colors.grey)
            pie.slices[i].fontName = body_font
            pie.slices[i].fontSize = 8
        pie_drawing.add(pie)
    else:
        pie_drawing.add(String(
            0.4 * inch, 1.0 * inch, "No exposures recorded",
            fontName=body_font, fontSize=10,
        ))

    sev_rows = [["Severity", "Count"]] + [[s, str(c)] for s, c in sev_data]
    st = Table(sev_rows, colWidths=[1.4 * inch, 1.0 * inch])
    st.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, -1), body_font, 10),
                ("FONT", (0, 0), (-1, 0), bold_font, 10),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C252E")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    sbs = Table([[pie_drawing, st]], colWidths=[2.6 * inch, 3.4 * inch])
    sbs.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(sbs)

    # --- Page 2: trend bar chart ------------------------------------
    from reportlab.platypus import PageBreak

    story.append(PageBreak())
    story.append(Paragraph("Operational signals", H2))
    story.append(
        Paragraph(
            "Counts of operationally significant events tracked over the "
            f"last {window_days} days. Driven by the same SLA + takedown "
            "+ case data as the headline table on page 1.",
            NORM,
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    bar_drawing = Drawing(6.5 * inch, 2.5 * inch)
    bar = VerticalBarChart()
    bar.x = 0.6 * inch
    bar.y = 0.4 * inch
    bar.width = 5.5 * inch
    bar.height = 1.8 * inch
    bar.data = [[
        cases_open,
        sla_breaches,
        takedowns_open,
        takedowns_succeeded,
        suspect_open,
    ]]
    bar.categoryAxis.categoryNames = [
        "Open cases",
        "SLA breaches",
        "Takedowns open",
        "Takedowns succeeded",
        "Suspect domains",
    ]
    bar.bars[0].fillColor = colors.HexColor("#1C252E")
    bar.categoryAxis.labels.fontName = body_font
    bar.categoryAxis.labels.fontSize = 9
    bar.valueAxis.labels.fontName = body_font
    bar.valueAxis.labels.fontSize = 9
    bar.valueAxis.valueMin = 0
    bar_drawing.add(bar)
    story.append(bar_drawing)

    story.append(Spacer(1, 0.25 * inch))
    story.append(
        Paragraph(
            "<i>This is an automated summary. For full investigations, "
            "case detail, and analyst notes, log into the Argus dashboard.</i>",
            NORM,
        )
    )
    doc.build(story)
    return buf.getvalue()


async def _load_org_logo_bytes(
    db: AsyncSession, organization_id: uuid.UUID
) -> bytes | None:
    """Audit D15 — fetch the most recently registered BrandLogo for the
    org and return its image bytes. Returns ``None`` on any failure
    (no logo registered, MinIO unreachable, decode error). Logo
    embedding is best-effort cosmetic — never block the PDF on it.
    """
    try:
        from src.models.logo import BrandLogo
        from src.models.evidence import EvidenceBlob
        from src.storage import evidence_store

        logo_row = (
            await db.execute(
                select(BrandLogo)
                .where(BrandLogo.organization_id == organization_id)
                .order_by(BrandLogo.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if logo_row is None:
            return None
        evidence = (
            await db.execute(
                select(EvidenceBlob).where(
                    and_(
                        EvidenceBlob.organization_id == organization_id,
                        EvidenceBlob.sha256 == logo_row.image_evidence_sha256,
                    )
                )
            )
        ).scalar_one_or_none()
        if evidence is None:
            return None
        from src.config.settings import settings as _s
        return evidence_store.get(_s.evidence.bucket, evidence.s3_key)
    except Exception:  # noqa: BLE001
        return None


@router.get("")
async def exec_summary_pdf(
    organization_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    days: Annotated[int, Query(ge=1, le=365)] = 30,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    # Rating
    sr = (
        await db.execute(
            select(SecurityRating).where(
                and_(
                    SecurityRating.organization_id == organization_id,
                    SecurityRating.is_current == True,  # noqa: E712
                )
            )
        )
    ).scalar_one_or_none()
    rating_score = sr.score if sr else None
    rating_grade = sr.grade if sr else None

    # Exposures by severity (open + acknowledged + reopened)
    sev_rows = (
        await db.execute(
            select(ExposureFinding.severity, func.count())
            .where(
                and_(
                    ExposureFinding.organization_id == organization_id,
                    ExposureFinding.state.in_(
                        [
                            ExposureState.OPEN.value,
                            ExposureState.ACKNOWLEDGED.value,
                            ExposureState.REOPENED.value,
                        ]
                    ),
                )
            )
            .group_by(ExposureFinding.severity)
        )
    ).all()
    exposure_counts = {sev: cnt for sev, cnt in sev_rows}

    # Suspects
    suspect_open = (
        await db.execute(
            select(func.count())
            .select_from(SuspectDomain)
            .where(
                and_(
                    SuspectDomain.organization_id == organization_id,
                    SuspectDomain.state == SuspectDomainState.OPEN.value,
                )
            )
        )
    ).scalar() or 0

    # Cases
    cases_open = (
        await db.execute(
            select(func.count())
            .select_from(Case)
            .where(
                and_(
                    Case.organization_id == organization_id,
                    Case.state != CaseState.CLOSED.value,
                )
            )
        )
    ).scalar() or 0

    # SLA breaches in window
    sla_breaches = (
        await db.execute(
            select(func.count())
            .select_from(SlaBreachEvent)
            .where(
                and_(
                    SlaBreachEvent.organization_id == organization_id,
                    SlaBreachEvent.detected_at >= window_start,
                )
            )
        )
    ).scalar() or 0

    # Takedowns
    td_open = (
        await db.execute(
            select(func.count())
            .select_from(TakedownTicket)
            .where(
                and_(
                    TakedownTicket.organization_id == organization_id,
                    TakedownTicket.state.in_(
                        [
                            TakedownState.SUBMITTED.value,
                            TakedownState.ACKNOWLEDGED.value,
                            TakedownState.IN_PROGRESS.value,
                        ]
                    ),
                )
            )
        )
    ).scalar() or 0
    td_done = (
        await db.execute(
            select(func.count())
            .select_from(TakedownTicket)
            .where(
                and_(
                    TakedownTicket.organization_id == organization_id,
                    TakedownTicket.state == TakedownState.SUCCEEDED.value,
                    TakedownTicket.succeeded_at >= window_start,
                )
            )
        )
    ).scalar() or 0

    pdf = _render_pdf(
        org_name=org.name,
        window_days=days,
        rating_score=rating_score,
        rating_grade=rating_grade,
        exposure_counts=exposure_counts,
        suspect_open=suspect_open,
        cases_open=cases_open,
        sla_breaches=sla_breaches,
        takedowns_open=td_open,
        takedowns_succeeded=td_done,
        generated_at=now,
        org_logo_bytes=await _load_org_logo_bytes(db, organization_id),
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.REPORT_GENERATE,
        user=analyst,
        resource_type="exec_summary",
        resource_id=str(organization_id),
        details={"window_days": days, "size_bytes": len(pdf)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()

    return StreamingResponse(
        io.BytesIO(pdf),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="argus-exec-summary-{org.name.replace(" ", "_")}-{now.strftime("%Y%m%d")}.pdf"'
            ),
            "Content-Length": str(len(pdf)),
        },
    )
