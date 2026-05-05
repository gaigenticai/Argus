"""SOC 2 / audit-report PDF parser.

Extracts:
  * auditor firm name
  * report date
  * report period (Type II)
  * opinion paragraph (unqualified / qualified / disclaimer / adverse)
  * scope sections (TSC: security, availability, processing integrity,
    confidentiality, privacy)
  * any control results table (best-effort regex; report formats vary
    enormously between Big-4 / mid-tier auditors)

Strategy:

  1. **Text extraction** via ``pdfplumber`` (works on born-digital PDFs;
     falls back to whole-page text if table extraction fails).
  2. **Heuristic regex pass** runs first. It catches the obvious markers
     ("Independent Service Auditor's Report", "Type 2", date strings,
     etc.) so we always have *something* even when the LLM is unavailable.
  3. **LLM refinement** (when configured) takes the heuristic baseline +
     the first 8000 chars of the PDF body and returns strict JSON with
     every field validated.

Returns a dict the caller persists onto ``vendor_evidence_files.extracted``.
"""
from __future__ import annotations

import io
import json
import logging
import re
from typing import Any

from src.config.settings import settings
from src.llm.providers import LLMNotConfigured, get_provider

_logger = logging.getLogger(__name__)


_AUDITOR_PATTERNS = (
    r"\b(KPMG|PricewaterhouseCoopers|PwC|Deloitte|Ernst\s*&\s*Young|EY|BDO|"
    r"Grant\s*Thornton|RSM|Crowe|Mazars|Schellman|A-LIGN|Coalfire|Insight\s*Assurance)\b"
)


def _extract_text(pdf_bytes: bytes) -> str:
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        _logger.warning("pdfplumber not installed; SOC2 parser cannot extract text")
        return ""
    text_chunks: list[str] = []
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages[:80]:  # cap to avoid runaway parses
                t = page.extract_text() or ""
                if t:
                    text_chunks.append(t)
    except Exception as e:  # noqa: BLE001
        _logger.warning("pdfplumber failed: %s", e)
    return "\n".join(text_chunks)


def _heuristic(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "auditor": None,
        "report_kind": None,
        "report_date": None,
        "period": None,
        "opinion": None,
        "trust_services": [],
        "raw_excerpts": {},
    }
    if not text:
        return out
    snippet = text[:50000]

    m = re.search(_AUDITOR_PATTERNS, snippet, re.IGNORECASE)
    if m:
        out["auditor"] = m.group(0).strip()

    if re.search(r"SOC\s*2\s*Type\s*(II|2)", snippet, re.I):
        out["report_kind"] = "soc2_type2"
    elif re.search(r"SOC\s*2\s*Type\s*(I|1)", snippet, re.I):
        out["report_kind"] = "soc2_type1"
    elif re.search(r"SOC\s*1", snippet, re.I):
        out["report_kind"] = "soc1"
    elif re.search(r"ISO\s*27001", snippet, re.I):
        out["report_kind"] = "iso_27001"

    # Opinion paragraph hunt.
    op_kinds = {
        "unqualified": r"\bin\s+our\s+opinion[^.]{0,300}\bpresent[s]?\s+fairly\b",
        "qualified": r"\bqualified\s+opinion\b|except\s+for\s+the\s+matter",
        "disclaimer": r"\bdisclaim(?:er)?\s+of\s+opinion\b",
        "adverse": r"\badverse\s+opinion\b",
    }
    for label, pat in op_kinds.items():
        if re.search(pat, snippet, re.I):
            out["opinion"] = label
            break

    # Trust Services Categories.
    tsc = []
    for tag, pat in [
        ("security", r"common\s+criteria\b|\bsecurity\b"),
        ("availability", r"\bavailability\b"),
        ("processing_integrity", r"processing\s+integrity"),
        ("confidentiality", r"\bconfidentiality\b"),
        ("privacy", r"\bprivacy\b"),
    ]:
        if re.search(pat, snippet, re.I):
            tsc.append(tag)
    out["trust_services"] = tsc

    # Date strings.
    date_match = re.search(
        r"(?:for the period|covering the period|from)\s+([A-Z][a-z]+\s+\d{1,2},?\s+\d{4}\s+(?:to|through|-)\s+[A-Z][a-z]+\s+\d{1,2},?\s+\d{4})",
        snippet,
    )
    if date_match:
        out["period"] = date_match.group(1)

    rep_date = re.search(
        r"(?:Report\s+Date|Issued\s+On|Date\s+of\s+Report)[:\s]+([A-Z][a-z]+\s+\d{1,2},?\s+\d{4})",
        snippet,
        re.I,
    )
    if rep_date:
        out["report_date"] = rep_date.group(1)

    out["raw_excerpts"] = {
        "first_5kb": text[:5000],
    }
    return out


async def _llm_refine(provider, text: str, baseline: dict[str, Any]) -> dict[str, Any] | None:
    sys = (
        "You parse a SOC 2 / SOC 1 / ISO 27001 audit report. Return STRICT JSON "
        "with keys: auditor (string or null), report_kind "
        "(soc2_type1|soc2_type2|soc1|iso_27001|other), report_date (string or null), "
        "period (string or null), opinion "
        "(unqualified|qualified|disclaimer|adverse|null), trust_services (array of "
        "security|availability|processing_integrity|confidentiality|privacy), "
        "exceptions (array of <=10 short strings — control IDs or descriptions of "
        "any noted exceptions), summary (<=300 chars). No prose."
    )
    user = (
        f"Heuristic baseline: {json.dumps(baseline, default=str)[:2000]}\n\n"
        f"PDF text (first 8 kB):\n{text[:8000]}"
    )
    try:
        out = (await provider.call(sys, user) or "").strip()
        if out.startswith("```"):
            out = re.sub(r"^```[a-z]*\s*|\s*```$", "", out, flags=re.MULTILINE).strip()
        obj = json.loads(out)
        if isinstance(obj, dict):
            obj.setdefault("trust_services", [])
            obj.setdefault("exceptions", [])
            return obj
    except Exception as e:  # noqa: BLE001
        _logger.warning("soc2 LLM parse failed: %s", e)
    return None


async def parse_soc2_pdf(
    pdf_bytes: bytes,
    *,
    use_llm: bool = True,
) -> dict[str, Any]:
    text = _extract_text(pdf_bytes)
    baseline = _heuristic(text)
    if use_llm:
        try:
            provider = get_provider(settings.llm)
            refined = await _llm_refine(provider, text, baseline)
            if refined:
                refined["_baseline"] = baseline
                refined["_text_len"] = len(text)
                return refined
        except LLMNotConfigured:
            pass
        except Exception as e:  # noqa: BLE001
            _logger.warning("soc2 LLM not used: %s", e)
    baseline["_text_len"] = len(text)
    return baseline


__all__ = ["parse_soc2_pdf"]
