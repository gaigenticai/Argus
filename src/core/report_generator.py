"""Executive-grade threat intelligence PDF report generator.

Uses reportlab to produce branded, color-coded Argus reports with
cover pages, charts, severity tables, and full alert appendices.
"""

import io
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from reportlab.graphics import renderPDF
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String as RLString
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Brand colors
# ---------------------------------------------------------------------------
ARGUS_DARK = colors.HexColor("#141A21")
ARGUS_ACCENT = colors.HexColor("#00A76F")
ARGUS_WHITE = colors.white
ARGUS_LIGHT_BG = colors.HexColor("#F4F6F8")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#FF5630"),
    "high": colors.HexColor("#FFAB00"),
    "medium": colors.HexColor("#FFC107"),
    "low": colors.HexColor("#00BBD9"),
    "info": colors.HexColor("#919EAB"),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

_base_styles = getSampleStyleSheet()


def _build_styles() -> dict[str, ParagraphStyle]:
    """Return a dict of custom paragraph styles."""
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=_base_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=32,
            leading=38,
            textColor=ARGUS_WHITE,
            alignment=TA_CENTER,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            parent=_base_styles["Normal"],
            fontName="Helvetica",
            fontSize=16,
            leading=22,
            textColor=colors.HexColor("#C4CDD5"),
            alignment=TA_CENTER,
        ),
        "cover_org": ParagraphStyle(
            "cover_org",
            parent=_base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=26,
            textColor=ARGUS_ACCENT,
            alignment=TA_CENTER,
        ),
        "section_heading": ParagraphStyle(
            "section_heading",
            parent=_base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=24,
            textColor=ARGUS_DARK,
            spaceAfter=10,
            spaceBefore=20,
        ),
        "sub_heading": ParagraphStyle(
            "sub_heading",
            parent=_base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=18,
            textColor=colors.HexColor("#454F5B"),
            spaceAfter=6,
            spaceBefore=12,
        ),
        "body": ParagraphStyle(
            "body",
            parent=_base_styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#212B36"),
        ),
        "body_bold": ParagraphStyle(
            "body_bold",
            parent=_base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#212B36"),
        ),
        "table_header": ParagraphStyle(
            "table_header",
            parent=_base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=ARGUS_WHITE,
        ),
        "table_cell": ParagraphStyle(
            "table_cell",
            parent=_base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#212B36"),
        ),
        "classification": ParagraphStyle(
            "classification",
            parent=_base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=SEVERITY_COLORS["critical"],
            alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "footer",
            parent=_base_styles["Normal"],
            fontName="Helvetica",
            fontSize=7,
            textColor=colors.HexColor("#919EAB"),
            alignment=TA_RIGHT,
        ),
        "stat_number": ParagraphStyle(
            "stat_number",
            parent=_base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            alignment=TA_CENTER,
        ),
        "stat_label": ParagraphStyle(
            "stat_label",
            parent=_base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#637381"),
            alignment=TA_CENTER,
        ),
    }


STYLES = _build_styles()


# ---------------------------------------------------------------------------
# Page decorations
# ---------------------------------------------------------------------------


def _header_footer(canvas, doc):
    """Draw branded header bar and page numbers on content pages."""
    canvas.saveState()
    width, height = A4

    # Header bar
    canvas.setFillColor(ARGUS_DARK)
    canvas.rect(0, height - 40, width, 40, fill=True, stroke=False)

    # Header text
    canvas.setFillColor(ARGUS_ACCENT)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawString(20, height - 28, "ARGUS")
    canvas.setFillColor(colors.HexColor("#919EAB"))
    canvas.setFont("Helvetica", 9)
    canvas.drawString(80, height - 26, "THREAT INTELLIGENCE REPORT")

    # Footer line
    canvas.setStrokeColor(colors.HexColor("#DFE3E8"))
    canvas.setLineWidth(0.5)
    canvas.line(30, 35, width - 30, 35)

    # Page number
    canvas.setFillColor(colors.HexColor("#919EAB"))
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 30, 22, f"Page {doc.page}")

    # Classification marking
    canvas.setFillColor(SEVERITY_COLORS["critical"])
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawCentredString(width / 2, 22, doc._argus_classification.upper())

    canvas.restoreState()


def _cover_page(canvas, doc):
    """Draw the cover page background — no header/footer."""
    canvas.saveState()
    width, height = A4

    # Full dark background
    canvas.setFillColor(ARGUS_DARK)
    canvas.rect(0, 0, width, height, fill=True, stroke=False)

    # Accent bar top
    canvas.setFillColor(ARGUS_ACCENT)
    canvas.rect(0, height - 8, width, 8, fill=True, stroke=False)

    # Accent bar bottom
    canvas.rect(0, 0, width, 4, fill=True, stroke=False)

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------


def _severity_bar_chart(by_severity: dict[str, int], width_px: int = 400, height_px: int = 200) -> Drawing:
    """Horizontal bar chart of alerts by severity."""
    drawing = Drawing(width_px, height_px)

    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.width = width_px - 80
    chart.height = height_px - 60

    data_values = [by_severity.get(s, 0) for s in SEVERITY_ORDER]
    chart.data = [data_values]
    chart.categoryAxis.categoryNames = [s.capitalize() for s in SEVERITY_ORDER]
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 8

    # Color each bar by severity
    for i, sev in enumerate(SEVERITY_ORDER):
        chart.bars[0].fillColor = SEVERITY_COLORS.get(sev, colors.grey)
        # Per-bar colors via bar properties
    # reportlab VerticalBarChart uses series-level coloring;
    # we use a single series and color all bars via the series color,
    # but apply per-bar via a custom approach:
    bar_colors = [SEVERITY_COLORS.get(s, colors.grey) for s in SEVERITY_ORDER]
    for i, c in enumerate(bar_colors):
        chart.bars[(0, i)].fillColor = c

    drawing.add(chart)
    return drawing


def _category_table(by_category: dict[str, int]) -> Table:
    """Styled table of alerts by threat category."""
    header = [
        Paragraph("Category", STYLES["table_header"]),
        Paragraph("Count", STYLES["table_header"]),
    ]
    rows = [header]
    sorted_cats = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
    for cat, count in sorted_cats:
        rows.append([
            Paragraph(cat.replace("_", " ").title(), STYLES["table_cell"]),
            Paragraph(str(count), STYLES["table_cell"]),
        ])

    col_widths = [300, 80]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), ARGUS_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), ARGUS_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    # Alternating row colors
    for i in range(1, len(rows)):
        bg = ARGUS_LIGHT_BG if i % 2 == 0 else ARGUS_WHITE
        style_commands.append(("BACKGROUND", (0, i), (-1, i), bg))

    t.setStyle(TableStyle(style_commands))
    return t


def _severity_badge(severity: str) -> Paragraph:
    """Inline colored severity label."""
    color_hex = {
        "critical": "#FF5630",
        "high": "#FFAB00",
        "medium": "#FFC107",
        "low": "#00BBD9",
        "info": "#919EAB",
    }.get(severity, "#919EAB")
    return Paragraph(
        f'<font color="{color_hex}"><b>{severity.upper()}</b></font>',
        STYLES["body_bold"],
    )


# ---------------------------------------------------------------------------
# Stat card helper
# ---------------------------------------------------------------------------


def _stat_cards(stats: dict[str, tuple[str, str]]) -> Table:
    """Row of stat cards.  stats = {label: (value, color_hex)}."""
    top_row = []
    bot_row = []
    for label, (value, color_hex) in stats.items():
        style = ParagraphStyle(
            f"stat_{label}",
            parent=STYLES["stat_number"],
            textColor=colors.HexColor(color_hex),
        )
        top_row.append(Paragraph(str(value), style))
        bot_row.append(Paragraph(label, STYLES["stat_label"]))

    t = Table([top_row, bot_row], colWidths=[110] * len(stats))
    t.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
        ("TOPPADDING", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
    ]))
    return t


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------


class ArgusReportGenerator:
    """Builds an executive-grade threat intelligence PDF report."""

    def __init__(
        self,
        organization_name: str,
        date_from: datetime,
        date_to: datetime,
        classification: str = "CONFIDENTIAL",
    ):
        self.org_name = organization_name
        self.date_from = date_from
        self.date_to = date_to
        self.classification = classification

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        alerts: list[dict[str, Any]],
        assets: list[dict[str, Any]] | None = None,
        vips: list[dict[str, Any]] | None = None,
        executive_summary_text: str | None = None,
    ) -> bytes:
        """Generate the complete PDF report.

        Args:
            alerts: list of alert dicts (from DB rows).
            assets: optional list of asset dicts.
            vips: optional list of VIP dicts.
            executive_summary_text: optional LLM-generated summary.

        Returns:
            Raw PDF bytes.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            topMargin=60,
            bottomMargin=50,
            leftMargin=30,
            rightMargin=30,
        )
        doc._argus_classification = self.classification

        story = []

        # Build sections
        story += self._cover_section()
        story += self._executive_summary_section(alerts, executive_summary_text)
        story += self._threat_overview_section(alerts)
        story += self._critical_high_section(alerts)
        story += self._attack_surface_section(assets or [])
        story += self._vip_section(alerts, vips or [])
        story += self._appendix_section(alerts)

        # Build with page templates
        width, height = A4
        content_frame = Frame(
            30, 50, width - 60, height - 110,
            id="content",
        )
        cover_frame = Frame(
            30, 50, width - 60, height - 70,
            id="cover",
        )
        doc.addPageTemplates([
            PageTemplate(id="cover", frames=[cover_frame], onPage=_cover_page),
            PageTemplate(id="content", frames=[content_frame], onPage=_header_footer),
        ])

        doc.build(story)
        return buffer.getvalue()

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def _cover_section(self) -> list:
        elements = []
        elements.append(NextPageTemplate("cover"))
        elements.append(Spacer(1, 120))

        elements.append(Paragraph("ARGUS", ParagraphStyle(
            "cover_brand",
            parent=STYLES["cover_title"],
            fontSize=48,
            leading=54,
            textColor=ARGUS_ACCENT,
        )))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("THREAT INTELLIGENCE REPORT", STYLES["cover_title"]))
        elements.append(Spacer(1, 40))
        elements.append(Paragraph(self.org_name, STYLES["cover_org"]))
        elements.append(Spacer(1, 20))

        date_range = (
            f"{self.date_from.strftime('%B %d, %Y')} &mdash; "
            f"{self.date_to.strftime('%B %d, %Y')}"
        )
        elements.append(Paragraph(date_range, STYLES["cover_subtitle"]))
        elements.append(Spacer(1, 30))

        generated = f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y %H:%M UTC')}"
        elements.append(Paragraph(generated, STYLES["cover_subtitle"]))
        elements.append(Spacer(1, 40))

        elements.append(Paragraph(
            f"CLASSIFICATION: {self.classification}",
            ParagraphStyle(
                "cover_class",
                parent=STYLES["classification"],
                textColor=SEVERITY_COLORS["critical"],
                fontSize=12,
            ),
        ))

        elements.append(NextPageTemplate("content"))
        elements.append(PageBreak())
        return elements

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _executive_summary_section(
        self, alerts: list[dict], summary_text: str | None
    ) -> list:
        elements = []
        elements.append(Paragraph("1. Executive Summary", STYLES["section_heading"]))
        elements.append(Spacer(1, 8))

        # Severity counts
        sev_counts: dict[str, int] = Counter()
        for a in alerts:
            sev_counts[a.get("severity", "info")] += 1

        total = len(alerts)
        stat_data = {
            "Total Alerts": (str(total), "#212B36"),
            "Critical": (str(sev_counts.get("critical", 0)), "#FF5630"),
            "High": (str(sev_counts.get("high", 0)), "#FFAB00"),
            "Medium": (str(sev_counts.get("medium", 0)), "#FFC107"),
            "Low": (str(sev_counts.get("low", 0)), "#00BBD9"),
        }
        elements.append(_stat_cards(stat_data))
        elements.append(Spacer(1, 14))

        if summary_text:
            elements.append(Paragraph("Key Findings", STYLES["sub_heading"]))
            for para in summary_text.strip().split("\n\n"):
                para = para.strip()
                if para:
                    elements.append(Paragraph(para, STYLES["body"]))
                    elements.append(Spacer(1, 6))
        else:
            # Auto-generated brief summary
            crit = sev_counts.get("critical", 0)
            high = sev_counts.get("high", 0)
            summary = (
                f"During the reporting period, Argus identified <b>{total}</b> threat "
                f"intelligence alerts across all monitored sources. "
                f"Of these, <b>{crit}</b> were classified as critical and "
                f"<b>{high}</b> as high severity, requiring immediate attention."
            )
            elements.append(Paragraph(summary, STYLES["body"]))

        elements.append(Spacer(1, 6))
        return elements

    # ------------------------------------------------------------------
    # Threat overview (charts + tables)
    # ------------------------------------------------------------------

    def _threat_overview_section(self, alerts: list[dict]) -> list:
        elements = []
        elements.append(Paragraph("2. Threat Overview", STYLES["section_heading"]))
        elements.append(Spacer(1, 8))

        sev_counts: dict[str, int] = Counter()
        cat_counts: dict[str, int] = Counter()
        for a in alerts:
            sev_counts[a.get("severity", "info")] += 1
            cat_counts[a.get("category", "unknown")] += 1

        # Severity distribution chart
        elements.append(Paragraph("Severity Distribution", STYLES["sub_heading"]))
        chart = _severity_bar_chart(sev_counts)
        elements.append(chart)
        elements.append(Spacer(1, 14))

        # Category breakdown table
        elements.append(Paragraph("Alerts by Category", STYLES["sub_heading"]))
        elements.append(_category_table(cat_counts))
        elements.append(Spacer(1, 10))

        # Trend summary (daily counts)
        daily: dict[str, int] = Counter()
        for a in alerts:
            created = a.get("created_at")
            if created:
                if isinstance(created, str):
                    try:
                        dt = datetime.fromisoformat(created)
                    except Exception:
                        continue
                elif isinstance(created, datetime):
                    dt = created
                else:
                    continue
                daily[dt.strftime("%Y-%m-%d")] += 1

        if daily:
            elements.append(Paragraph("Daily Alert Volume", STYLES["sub_heading"]))
            header = [
                Paragraph("Date", STYLES["table_header"]),
                Paragraph("Alerts", STYLES["table_header"]),
            ]
            rows = [header]
            for date_str in sorted(daily.keys()):
                rows.append([
                    Paragraph(date_str, STYLES["table_cell"]),
                    Paragraph(str(daily[date_str]), STYLES["table_cell"]),
                ])

            t = Table(rows, colWidths=[200, 80], repeatRows=1)
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), ARGUS_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), ARGUS_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ]
            for i in range(1, len(rows)):
                bg = ARGUS_LIGHT_BG if i % 2 == 0 else ARGUS_WHITE
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
            t.setStyle(TableStyle(style_cmds))
            elements.append(t)
            elements.append(Spacer(1, 10))

        return elements

    # ------------------------------------------------------------------
    # Critical & high alerts detail
    # ------------------------------------------------------------------

    def _critical_high_section(self, alerts: list[dict]) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(
            "3. Critical &amp; High Severity Alerts", STYLES["section_heading"]
        ))
        elements.append(Spacer(1, 8))

        urgent = [
            a for a in alerts
            if a.get("severity") in ("critical", "high")
        ]
        urgent.sort(
            key=lambda a: (0 if a.get("severity") == "critical" else 1, a.get("created_at", "")),
        )

        if not urgent:
            elements.append(Paragraph(
                "No critical or high severity alerts during this period.",
                STYLES["body"],
            ))
            return elements

        for i, alert in enumerate(urgent, 1):
            severity = alert.get("severity", "unknown")
            color_hex = {
                "critical": "#FF5630",
                "high": "#FFAB00",
            }.get(severity, "#919EAB")

            title_text = (
                f'{i}. <font color="{color_hex}">[{severity.upper()}]</font> '
                f'{_escape(alert.get("title", "Untitled"))}'
            )
            elements.append(Paragraph(title_text, STYLES["sub_heading"]))

            # Summary
            summary = alert.get("summary", "")
            if summary:
                elements.append(Paragraph(summary, STYLES["body"]))
                elements.append(Spacer(1, 4))

            # Metadata table
            meta_rows = []
            if alert.get("category"):
                meta_rows.append(["Category", alert["category"].replace("_", " ").title()])
            if alert.get("created_at"):
                ts = alert["created_at"]
                if isinstance(ts, datetime):
                    ts = ts.strftime("%Y-%m-%d %H:%M UTC")
                meta_rows.append(["Detected", str(ts)])
            if alert.get("confidence") is not None:
                meta_rows.append(["Confidence", f"{alert['confidence']:.0%}"])
            if alert.get("matched_entities"):
                entities = alert["matched_entities"]
                if isinstance(entities, dict):
                    meta_rows.append(["Matched Entities", ", ".join(
                        f"{k}: {v}" for k, v in entities.items()
                    )])

            if meta_rows:
                t = Table(
                    [[Paragraph(r[0], STYLES["body_bold"]),
                      Paragraph(str(r[1]), STYLES["body"])]
                     for r in meta_rows],
                    colWidths=[120, 400],
                )
                t.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]))
                elements.append(t)
                elements.append(Spacer(1, 4))

            # Agent reasoning
            reasoning = alert.get("agent_reasoning")
            if reasoning:
                elements.append(Paragraph("<b>Analysis:</b>", STYLES["body_bold"]))
                elements.append(Paragraph(reasoning, STYLES["body"]))
                elements.append(Spacer(1, 4))

            # Recommended actions
            actions = alert.get("recommended_actions")
            if actions and isinstance(actions, list):
                elements.append(Paragraph("<b>Recommended Actions:</b>", STYLES["body_bold"]))
                for action in actions:
                    elements.append(Paragraph(
                        f"&bull; {_escape(str(action))}", STYLES["body"]
                    ))
                elements.append(Spacer(1, 4))

            elements.append(Spacer(1, 10))

        return elements

    # ------------------------------------------------------------------
    # Attack surface
    # ------------------------------------------------------------------

    def _attack_surface_section(self, assets: list[dict]) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("4. Attack Surface", STYLES["section_heading"]))
        elements.append(Spacer(1, 8))

        if not assets:
            elements.append(Paragraph(
                "No asset data available for this reporting period.",
                STYLES["body"],
            ))
            return elements

        # Group by type
        by_type: dict[str, list] = {}
        for asset in assets:
            atype = asset.get("asset_type", "other")
            by_type.setdefault(atype, []).append(asset)

        elements.append(Paragraph(
            f"<b>{len(assets)}</b> discovered assets across "
            f"<b>{len(by_type)}</b> categories.",
            STYLES["body"],
        ))
        elements.append(Spacer(1, 10))

        for atype, items in sorted(by_type.items()):
            elements.append(Paragraph(
                f"{atype.replace('_', ' ').title()} ({len(items)})",
                STYLES["sub_heading"],
            ))
            header = [
                Paragraph("Value", STYLES["table_header"]),
                Paragraph("Active", STYLES["table_header"]),
                Paragraph("Last Scanned", STYLES["table_header"]),
            ]
            rows = [header]
            for item in items[:50]:  # Cap at 50 per type
                last_scan = item.get("last_scanned_at", "—")
                if isinstance(last_scan, datetime):
                    last_scan = last_scan.strftime("%Y-%m-%d")
                rows.append([
                    Paragraph(_escape(str(item.get("value", ""))), STYLES["table_cell"]),
                    Paragraph("Yes" if item.get("is_active") else "No", STYLES["table_cell"]),
                    Paragraph(str(last_scan), STYLES["table_cell"]),
                ])

            t = Table(rows, colWidths=[260, 60, 120], repeatRows=1)
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), ARGUS_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), ARGUS_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ]
            for i in range(1, len(rows)):
                bg = ARGUS_LIGHT_BG if i % 2 == 0 else ARGUS_WHITE
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
            t.setStyle(TableStyle(style_cmds))
            elements.append(t)
            elements.append(Spacer(1, 10))

        return elements

    # ------------------------------------------------------------------
    # VIP monitoring
    # ------------------------------------------------------------------

    def _vip_section(self, alerts: list[dict], vips: list[dict]) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("5. VIP Monitoring", STYLES["section_heading"]))
        elements.append(Spacer(1, 8))

        if not vips:
            elements.append(Paragraph(
                "No VIP targets configured for this organization.",
                STYLES["body"],
            ))
            return elements

        elements.append(Paragraph(
            f"Monitoring <b>{len(vips)}</b> VIP targets.",
            STYLES["body"],
        ))
        elements.append(Spacer(1, 8))

        # Build a set of VIP identifiers for matching
        vip_identifiers: set[str] = set()
        for vip in vips:
            vip_identifiers.add(vip.get("name", "").lower())
            for email in (vip.get("emails") or []):
                vip_identifiers.add(email.lower())
            for uname in (vip.get("usernames") or []):
                vip_identifiers.add(uname.lower())

        # VIP overview table
        header = [
            Paragraph("Name", STYLES["table_header"]),
            Paragraph("Title", STYLES["table_header"]),
            Paragraph("Monitored Identifiers", STYLES["table_header"]),
        ]
        rows = [header]
        for vip in vips:
            identifiers = []
            identifiers.extend(vip.get("emails") or [])
            identifiers.extend(vip.get("usernames") or [])
            rows.append([
                Paragraph(_escape(vip.get("name", "")), STYLES["table_cell"]),
                Paragraph(_escape(vip.get("title", "—")), STYLES["table_cell"]),
                Paragraph(_escape(", ".join(identifiers) or "—"), STYLES["table_cell"]),
            ])

        t = Table(rows, colWidths=[140, 120, 260], repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), ARGUS_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), ARGUS_WHITE),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ]
        for i in range(1, len(rows)):
            bg = ARGUS_LIGHT_BG if i % 2 == 0 else ARGUS_WHITE
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
        t.setStyle(TableStyle(style_cmds))
        elements.append(t)
        elements.append(Spacer(1, 14))

        # VIP-related alerts
        vip_alerts = []
        for a in alerts:
            matched = a.get("matched_entities") or {}
            title_lower = (a.get("title") or "").lower()
            summary_lower = (a.get("summary") or "").lower()

            # Check if any VIP identifier appears in matched entities, title, or summary
            hit = False
            for ident in vip_identifiers:
                if not ident:
                    continue
                if ident in str(matched).lower() or ident in title_lower or ident in summary_lower:
                    hit = True
                    break
            # Also check categories that are VIP-relevant
            if a.get("category") in ("doxxing", "impersonation"):
                hit = True
            if hit:
                vip_alerts.append(a)

        if vip_alerts:
            elements.append(Paragraph(
                f"<b>{len(vip_alerts)}</b> alerts related to VIP targets:",
                STYLES["body"],
            ))
            elements.append(Spacer(1, 6))
            for a in vip_alerts[:20]:
                sev = a.get("severity", "info")
                color_hex = {
                    "critical": "#FF5630", "high": "#FFAB00",
                    "medium": "#FFC107", "low": "#00BBD9", "info": "#919EAB",
                }.get(sev, "#919EAB")
                elements.append(Paragraph(
                    f'<font color="{color_hex}">[{sev.upper()}]</font> '
                    f'{_escape(a.get("title", "Untitled"))}',
                    STYLES["body"],
                ))
                elements.append(Spacer(1, 3))
        else:
            elements.append(Paragraph(
                "No alerts directly matched VIP targets during this period.",
                STYLES["body"],
            ))

        return elements

    # ------------------------------------------------------------------
    # Appendix — full alert listing
    # ------------------------------------------------------------------

    def _appendix_section(self, alerts: list[dict]) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("6. Appendix — Full Alert Listing", STYLES["section_heading"]))
        elements.append(Spacer(1, 8))

        if not alerts:
            elements.append(Paragraph("No alerts in this period.", STYLES["body"]))
            return elements

        header = [
            Paragraph("Severity", STYLES["table_header"]),
            Paragraph("Category", STYLES["table_header"]),
            Paragraph("Title", STYLES["table_header"]),
            Paragraph("Status", STYLES["table_header"]),
            Paragraph("Date", STYLES["table_header"]),
        ]
        rows = [header]

        sorted_alerts = sorted(
            alerts,
            key=lambda a: (SEVERITY_ORDER.index(a.get("severity", "info")), a.get("created_at", "")),
        )

        for a in sorted_alerts:
            sev = a.get("severity", "info")
            color_hex = {
                "critical": "#FF5630", "high": "#FFAB00",
                "medium": "#FFC107", "low": "#00BBD9", "info": "#919EAB",
            }.get(sev, "#919EAB")

            ts = a.get("created_at", "")
            if isinstance(ts, datetime):
                ts = ts.strftime("%Y-%m-%d %H:%M")

            rows.append([
                Paragraph(f'<font color="{color_hex}"><b>{sev.upper()}</b></font>', STYLES["table_cell"]),
                Paragraph(a.get("category", "").replace("_", " ").title(), STYLES["table_cell"]),
                Paragraph(_escape(a.get("title", "")[:80]), STYLES["table_cell"]),
                Paragraph(a.get("status", "").replace("_", " ").title(), STYLES["table_cell"]),
                Paragraph(str(ts), STYLES["table_cell"]),
            ])

        col_widths = [60, 100, 220, 70, 80]
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), ARGUS_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), ARGUS_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DFE3E8")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ]
        for i in range(1, len(rows)):
            bg = ARGUS_LIGHT_BG if i % 2 == 0 else ARGUS_WHITE
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))

        t.setStyle(TableStyle(style_cmds))
        elements.append(t)

        return elements


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _escape(text: str) -> str:
    """Escape XML special characters for reportlab Paragraph."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
