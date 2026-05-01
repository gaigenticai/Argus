"""Bilingual PDF exporter for Compliance Evidence Packs.

Three language modes:

  * ``en``        — entire document in English
  * ``ar``        — entire document in Arabic
  * ``bilingual`` — Arabic executive summary, English technical body
                    (the regulator-facing default for GCC banking)

Implementation uses ReportLab Platypus (already a project dep), with
``arabic-reshaper`` + ``python-bidi`` to apply Unicode UAX #9 bidi
reordering and Arabic letter-form shaping before drawing — ReportLab
itself is bidi-naïve.

Arabic font: tries Noto Naskh Arabic / Noto Sans Arabic from the host
font directories (Debian: ``fonts-noto-core``, baked into the runtime
image; macOS dev: ``/System/Library/Fonts``). Falls back to Helvetica
with a logged warning when no Arabic-capable font is found —
Latin/digits still render, Arabic glyphs render as boxes; this is
better than refusing to export.
"""

from __future__ import annotations

import io
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.compliance import (
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)

logger = logging.getLogger(__name__)


# Brand-aligned with src/core/report_generator.py. Marsad rebrand
# happens at the customer-visible string layer (cover title, footer);
# colour palette stays.
_DARK = colors.HexColor("#141A21")
_ACCENT = colors.HexColor("#FF4F00")
_LIGHT_BG = colors.HexColor("#F4F0E6")
_BORDER = colors.HexColor("#D7CDB8")


_LANG_EN = "en"
_LANG_AR = "ar"
_LANG_BI = "bilingual"


# --- Arabic shaping ----------------------------------------------------


def _shape_arabic(text: str) -> str:
    """Apply Arabic letter shaping + bidi reordering for ReportLab.

    Returns text with the visual letter-forms ReportLab can draw
    left-to-right while still producing a correct right-to-left visual
    layout. Pure no-op for ASCII / Latin strings.
    """
    if not text:
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError:
        logger.warning("arabic-reshaper / python-bidi missing; "
                       "Arabic text will not render correctly")
        return text
    try:
        reshaped = arabic_reshaper.reshape(text)
        return get_display(reshaped)
    except Exception as exc:  # pragma: no cover — shaping should never crash
        logger.warning("arabic shaping failed: %s; rendering raw", exc)
        return text


# --- Font registration -------------------------------------------------


_ARABIC_FONT_NAME = "ArgusArabic"
_ARABIC_FONT_REGISTERED: bool | None = None


_ARABIC_FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/noto/NotoNaskhArabic-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoNaskhArabic-Regular.otf",
    "/usr/share/fonts/opentype/noto/NotoSansArabic-Regular.otf",
    # macOS dev path
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
)


def _ensure_arabic_font() -> str:
    """Register an Arabic-capable TTF on first use; cache the outcome.

    Returns the font name to use for Arabic strings — the registered
    Argus font when available, ``Helvetica`` otherwise. Helvetica
    fallback won't render Arabic glyphs but won't crash either.
    """
    global _ARABIC_FONT_REGISTERED
    if _ARABIC_FONT_REGISTERED is True:
        return _ARABIC_FONT_NAME
    if _ARABIC_FONT_REGISTERED is False:
        return "Helvetica"
    for path in _ARABIC_FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont(_ARABIC_FONT_NAME, path))
                _ARABIC_FONT_REGISTERED = True
                logger.info("compliance PDF: registered Arabic font %s", path)
                return _ARABIC_FONT_NAME
            except Exception as exc:
                logger.warning("failed registering %s: %s", path, exc)
                continue
    _ARABIC_FONT_REGISTERED = False
    logger.warning(
        "compliance PDF: no Arabic-capable font found in standard paths; "
        "Arabic glyphs will render as Helvetica fallback. Install "
        "fonts-noto-core or set ARGUS_ARABIC_FONT_PATH."
    )
    return "Helvetica"


# --- Style builder -----------------------------------------------------


def _build_styles(language_mode: str) -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    arabic_font = _ensure_arabic_font()

    styles: dict[str, ParagraphStyle] = {
        "cover_title_en": ParagraphStyle(
            "cover_title_en", parent=base["Title"],
            fontName="Helvetica-Bold", fontSize=28, leading=34,
            textColor=_DARK, alignment=TA_CENTER, spaceAfter=12,
        ),
        "cover_subtitle_en": ParagraphStyle(
            "cover_subtitle_en", parent=base["Normal"],
            fontName="Helvetica", fontSize=14, leading=20,
            textColor=_DARK, alignment=TA_CENTER,
        ),
        "h1_en": ParagraphStyle(
            "h1_en", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=18, leading=24, textColor=_DARK, spaceBefore=12,
            spaceAfter=8,
        ),
        "h2_en": ParagraphStyle(
            "h2_en", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=13, leading=18, textColor=_ACCENT, spaceBefore=8,
            spaceAfter=4,
        ),
        "body_en": ParagraphStyle(
            "body_en", parent=base["BodyText"], fontName="Helvetica",
            fontSize=10, leading=14, textColor=_DARK, alignment=TA_LEFT,
        ),
        "small_en": ParagraphStyle(
            "small_en", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8, leading=11, textColor=colors.HexColor("#5F6B73"),
        ),
        "title_ar": ParagraphStyle(
            "title_ar", parent=base["Title"], fontName=arabic_font,
            fontSize=26, leading=34, textColor=_DARK,
            alignment=TA_CENTER, wordWrap="RTL",
        ),
        "h1_ar": ParagraphStyle(
            "h1_ar", parent=base["Heading1"], fontName=arabic_font,
            fontSize=18, leading=26, textColor=_DARK, alignment=TA_RIGHT,
            wordWrap="RTL", spaceBefore=12, spaceAfter=8,
        ),
        "body_ar": ParagraphStyle(
            "body_ar", parent=base["BodyText"], fontName=arabic_font,
            fontSize=11, leading=18, textColor=_DARK, alignment=TA_RIGHT,
            wordWrap="RTL",
        ),
    }
    return styles


# --- Strings -----------------------------------------------------------


_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "doc_title": "Compliance Evidence Pack",
        "framework": "Framework",
        "period": "Reporting period",
        "organization": "Organisation",
        "generated": "Generated",
        "exec_summary": "Executive Summary",
        "evidence_total": "Total evidence captured",
        "controls_covered": "Controls with evidence",
        "alerts_observed": "Alerts contributing evidence",
        "cases_observed": "Cases contributing evidence",
        "controls_section": "Controls and Evidence",
        "no_evidence": "No evidence captured for this period.",
        "appendix_title": "Appendix — Source identifiers",
        "footer": "Marsad — Compliance Evidence Pack",
    },
    "ar": {
        "doc_title": "حزمة أدلة الامتثال",
        "framework": "الإطار",
        "period": "الفترة المشمولة بالتقرير",
        "organization": "المؤسسة",
        "generated": "تاريخ الإصدار",
        "exec_summary": "الملخص التنفيذي",
        "evidence_total": "مجموع الأدلة المسجلة",
        "controls_covered": "الضوابط ذات الأدلة",
        "alerts_observed": "التنبيهات المساهمة",
        "cases_observed": "الحالات المساهمة",
        "controls_section": "الضوابط والأدلة",
        "no_evidence": "لا توجد أدلة مسجلة للفترة المحددة.",
        "appendix_title": "ملحق — معرّفات المصدر",
        "footer": "مرصد — حزمة أدلة الامتثال",
    },
}


def _t(language: str, key: str) -> str:
    return _STRINGS.get(language, _STRINGS["en"]).get(key, key)


def _ar(text: str) -> str:
    return _shape_arabic(text)


# --- Renderer ----------------------------------------------------------


async def render_evidence_pack_pdf(
    session: AsyncSession,
    organization_id: uuid.UUID,
    organization_name: str,
    framework: ComplianceFramework,
    period_from: datetime,
    period_to: datetime,
    language_mode: str,
    generated_at: datetime | None = None,
) -> bytes:
    """Render the evidence pack PDF and return the bytes.

    The rendered document is deterministic up to the timestamp shown on
    the cover; SHA-256 hash stability requires the caller to pin
    ``generated_at``.
    """
    if language_mode not in (_LANG_EN, _LANG_AR, _LANG_BI):
        raise ValueError(f"unknown language_mode {language_mode!r}")
    generated_at = generated_at or datetime.now(timezone.utc)

    # Fetch evidence + controls.
    ev_rows = (await session.execute(
        select(ComplianceEvidence).where(
            ComplianceEvidence.organization_id == organization_id,
            ComplianceEvidence.framework_id == framework.id,
            ComplianceEvidence.status == "active",
            ComplianceEvidence.captured_at >= period_from,
            ComplianceEvidence.captured_at < period_to,
        ).order_by(ComplianceEvidence.captured_at.desc())
    )).scalars().all()

    referenced_ctrl_ids = {ev.control_id for ev in ev_rows}
    controls_by_id: dict[uuid.UUID, ComplianceControl] = {}
    if referenced_ctrl_ids:
        ctrl_rows = (await session.execute(
            select(ComplianceControl).where(
                ComplianceControl.id.in_(referenced_ctrl_ids)
            ).order_by(ComplianceControl.sort_order, ComplianceControl.control_id)
        )).scalars().all()
        controls_by_id = {c.id: c for c in ctrl_rows}

    alerts_count = sum(1 for ev in ev_rows if ev.source_kind == "alert")
    cases_count = sum(1 for ev in ev_rows if ev.source_kind == "case")

    styles = _build_styles(language_mode)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title=_t("en", "doc_title"),
        author="Marsad",
    )

    story: list[Any] = []

    # ── Cover ──────────────────────────────────────────────────────────
    cover_lang = _LANG_AR if language_mode == _LANG_AR else _LANG_EN
    if cover_lang == _LANG_AR:
        story.append(Paragraph(_ar(_t("ar", "doc_title")), styles["title_ar"]))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'framework')}: {framework.name_ar or framework.name_en}"),
            styles["body_ar"],
        ))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'organization')}: {organization_name}"),
            styles["body_ar"],
        ))
        story.append(Paragraph(
            _ar(
                f"{_t('ar', 'period')}: "
                f"{period_from.date()} → {period_to.date()}"
            ),
            styles["body_ar"],
        ))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'generated')}: {generated_at.date()}"),
            styles["body_ar"],
        ))
    else:
        story.append(Paragraph(_t("en", "doc_title"), styles["cover_title_en"]))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph(
            f"<b>{_t('en', 'framework')}:</b> {framework.name_en} "
            f"(v{framework.version})",
            styles["cover_subtitle_en"],
        ))
        story.append(Paragraph(
            f"<b>{_t('en', 'organization')}:</b> {organization_name}",
            styles["cover_subtitle_en"],
        ))
        story.append(Paragraph(
            f"<b>{_t('en', 'period')}:</b> "
            f"{period_from.date()} → {period_to.date()}",
            styles["cover_subtitle_en"],
        ))
        story.append(Paragraph(
            f"<b>{_t('en', 'generated')}:</b> {generated_at.date()}",
            styles["cover_subtitle_en"],
        ))

    story.append(PageBreak())

    # ── Executive summary ──────────────────────────────────────────────
    exec_lang = _LANG_AR if language_mode in (_LANG_AR, _LANG_BI) else _LANG_EN
    if exec_lang == _LANG_AR:
        story.append(Paragraph(_ar(_t("ar", "exec_summary")), styles["h1_ar"]))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'evidence_total')}: {len(ev_rows)}"),
            styles["body_ar"],
        ))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'controls_covered')}: {len(referenced_ctrl_ids)}"),
            styles["body_ar"],
        ))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'alerts_observed')}: {alerts_count}"),
            styles["body_ar"],
        ))
        story.append(Paragraph(
            _ar(f"{_t('ar', 'cases_observed')}: {cases_count}"),
            styles["body_ar"],
        ))
    else:
        story.append(Paragraph(_t("en", "exec_summary"), styles["h1_en"]))
        kpi = [
            [_t("en", "evidence_total"), str(len(ev_rows))],
            [_t("en", "controls_covered"), str(len(referenced_ctrl_ids))],
            [_t("en", "alerts_observed"), str(alerts_count)],
            [_t("en", "cases_observed"), str(cases_count)],
        ]
        tbl = Table(kpi, colWidths=[110 * mm, 50 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _LIGHT_BG),
            ("TEXTCOLOR", (0, 0), (-1, -1), _DARK),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 11),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("BOX", (0, 0), (-1, -1), 0.5, _BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, _BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(tbl)

    story.append(Spacer(1, 8 * mm))

    # ── Controls + evidence (technical body) ───────────────────────────
    body_lang = _LANG_AR if language_mode == _LANG_AR else _LANG_EN
    if body_lang == _LANG_AR:
        story.append(Paragraph(_ar(_t("ar", "controls_section")), styles["h1_ar"]))
    else:
        story.append(Paragraph(_t("en", "controls_section"), styles["h1_en"]))

    if not ev_rows:
        if body_lang == _LANG_AR:
            story.append(Paragraph(_ar(_t("ar", "no_evidence")), styles["body_ar"]))
        else:
            story.append(Paragraph(_t("en", "no_evidence"), styles["body_en"]))
    else:
        # Group evidence by control.
        ev_by_ctrl: dict[uuid.UUID, list[ComplianceEvidence]] = {}
        for ev in ev_rows:
            ev_by_ctrl.setdefault(ev.control_id, []).append(ev)
        for ctrl_id, evs in ev_by_ctrl.items():
            ctrl = controls_by_id.get(ctrl_id)
            if ctrl is None:
                continue
            if body_lang == _LANG_AR:
                title = ctrl.title_ar or ctrl.title_en
                story.append(Paragraph(
                    _ar(f"{ctrl.control_id} — {title}"),
                    styles["h1_ar"],
                ))
                if ctrl.description_ar or ctrl.description_en:
                    story.append(Paragraph(
                        _ar(ctrl.description_ar or ctrl.description_en or ""),
                        styles["body_ar"],
                    ))
                for ev in evs:
                    story.append(Paragraph(
                        _ar(f"• [{ev.captured_at.date()}] "
                            f"{ev.summary_ar or ev.summary_en or ''}"),
                        styles["body_ar"],
                    ))
            else:
                story.append(Paragraph(
                    f"<b>{ctrl.control_id}</b> — {ctrl.title_en}",
                    styles["h2_en"],
                ))
                if ctrl.description_en:
                    story.append(Paragraph(ctrl.description_en, styles["body_en"]))
                for ev in evs:
                    story.append(Paragraph(
                        f"• [{ev.captured_at.date()}] "
                        f"{ev.summary_en or ev.summary_ar or ''}",
                        styles["body_en"],
                    ))
            story.append(Spacer(1, 4 * mm))

    # ── Appendix — raw source identifiers (always English) ─────────────
    story.append(PageBreak())
    story.append(Paragraph(_t("en", "appendix_title"), styles["h1_en"]))
    if ev_rows:
        appx_rows: list[list[str]] = [
            ["Captured at (UTC)", "Source kind", "Source ID", "Control"],
        ]
        for ev in ev_rows:
            ctrl = controls_by_id.get(ev.control_id)
            appx_rows.append([
                ev.captured_at.strftime("%Y-%m-%d %H:%M"),
                ev.source_kind,
                str(ev.source_id),
                ctrl.control_id if ctrl else str(ev.control_id),
            ])
        tbl = Table(appx_rows, colWidths=[35 * mm, 22 * mm, 70 * mm, 35 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), _LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, _BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, _BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph(_t("en", "no_evidence"), styles["small_en"]))

    doc.build(story)
    return buf.getvalue()
