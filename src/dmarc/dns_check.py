"""DMARC / BIMI / MTA-STS / TLS-RPT live DNS health check.

One synchronous-look-and-feel async call per domain that returns
everything needed to render the **DNS Health** tab on the DMARC page:

    {
      "domain": ...,
      "record_present": bool,
      "raw_record": str | None,
      "parsed_tags": {v, p, sp, rua, ruf, pct, fo, aspf, adkim, rf, ri},
      "warnings": [str],
      "bimi_present": bool,
      "mta_sts_present": bool,
      "tls_rpt_present": bool,
      "age_unknown_or_seconds": int | None,
      "recommendations": [str],
    }

Pure dnspython — no third-party DMARC libraries (parsedmarc's tag
parser regularly drifts and we need M3AAWG-aligned validation).

Used by:
    GET /dmarc/check?domain=...
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

_logger = logging.getLogger(__name__)

# RFC 7489 §6.3 — full tag list, with allowed values.
_DMARC_ALLOWED_TAGS: dict[str, set[str] | None] = {
    "v": {"DMARC1"},
    "p": {"none", "quarantine", "reject"},
    "sp": {"none", "quarantine", "reject"},
    "pct": None,  # 0..100
    "rua": None,  # mailto: URI list
    "ruf": None,
    "fo": {"0", "1", "d", "s"},
    "aspf": {"r", "s"},
    "adkim": {"r", "s"},
    "rf": {"afrf", "iodef"},
    "ri": None,  # int seconds, default 86400
    "adkim": {"r", "s"},
}


async def _resolve_txt(name: str, *, timeout: float = 5.0) -> list[str]:
    try:
        import dns.exception  # type: ignore
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = await asyncio.to_thread(
            resolver.resolve, name, "TXT", raise_on_no_answer=False
        )
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    for r in answers:
        try:
            # rdata.strings is a tuple of bytes for TXT records.
            chunks = [c.decode("utf-8", errors="replace") for c in r.strings]
            out.append("".join(chunks).strip())
        except Exception:  # noqa: BLE001
            out.append(r.to_text().strip('"'))
    return out


def _parse_dmarc(record: str) -> tuple[dict[str, str], list[str]]:
    """Parse a raw DMARC TXT record into tag dict + warnings."""
    warnings: list[str] = []
    tags: dict[str, str] = {}
    for raw in record.split(";"):
        seg = raw.strip()
        if not seg:
            continue
        if "=" not in seg:
            warnings.append(f"malformed segment '{seg}' (no '=')")
            continue
        k, v = seg.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in tags:
            warnings.append(f"duplicate tag {k!r}")
        tags[k] = v

    if tags.get("v") != "DMARC1":
        warnings.append("v= tag must be 'DMARC1'")
    if "p" not in tags:
        warnings.append("missing required p= tag")
    elif tags["p"].lower() not in {"none", "quarantine", "reject"}:
        warnings.append(f"invalid p= value {tags['p']!r}")
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if not 0 <= pct <= 100:
                warnings.append(f"pct out of range: {pct}")
        except ValueError:
            warnings.append(f"pct not an integer: {tags['pct']!r}")
    if "sp" in tags and tags["sp"].lower() not in {"none", "quarantine", "reject"}:
        warnings.append(f"invalid sp= value {tags['sp']!r}")
    for align_tag in ("aspf", "adkim"):
        if align_tag in tags and tags[align_tag].lower() not in {"r", "s"}:
            warnings.append(f"invalid {align_tag}= value {tags[align_tag]!r}")
    if "fo" in tags:
        for ch in tags["fo"].split(":"):
            if ch.strip().lower() not in {"0", "1", "d", "s"}:
                warnings.append(f"invalid fo= component {ch!r}")
    if "rua" in tags and "mailto:" not in tags["rua"].lower():
        warnings.append("rua= should contain a mailto: URI")
    if "ruf" in tags and "mailto:" not in tags["ruf"].lower():
        warnings.append("ruf= should contain a mailto: URI")
    return tags, warnings


def _recommendations(
    tags: dict[str, str],
    bimi: bool,
    mta_sts: bool,
    tls_rpt: bool,
) -> list[str]:
    recs: list[str] = []
    p = (tags.get("p") or "").lower()
    if p == "none":
        recs.append(
            "Policy is p=none — actively monitoring only. Once 30+ days of clean RUA "
            "reports observed, advance to p=quarantine pct=25."
        )
    elif p == "quarantine":
        try:
            pct = int(tags.get("pct", "100"))
            if pct < 100:
                recs.append(f"Quarantine ramp at pct={pct}; raise to 100 once stable.")
            else:
                recs.append("Quarantine pct=100 stable — plan move to p=reject.")
        except ValueError:
            pass
    elif p == "reject":
        recs.append("Policy at p=reject. Mature posture.")
    if "rua" not in tags:
        recs.append("Add rua= so receivers send aggregate reports.")
    if "ruf" not in tags:
        recs.append("Optionally add ruf= for per-failure forensic samples.")
    if tags.get("aspf", "r").lower() == "r":
        recs.append("Consider stricter SPF alignment (aspf=s) for sensitive domains.")
    if tags.get("adkim", "r").lower() == "r":
        recs.append("Consider stricter DKIM alignment (adkim=s).")
    if not bimi:
        recs.append(
            "No BIMI record at default._bimi — once at p=quarantine/reject, publish "
            "BIMI for branded inbox indicators."
        )
    if not mta_sts:
        recs.append(
            "No MTA-STS at _mta-sts — publish to enforce inbound TLS for your "
            "domain's MX records."
        )
    if not tls_rpt:
        recs.append("No TLS-RPT at _smtp._tls — publish to receive TLS failure reports.")
    return recs


async def check_dmarc(domain: str) -> dict[str, Any]:
    """Live-check the DMARC posture of a domain.

    Pure DNS, no auth required. Defensive: callers should never see
    an exception even when DNS times out or the domain is malformed.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {
            "domain": "",
            "record_present": False,
            "raw_record": None,
            "parsed_tags": {},
            "warnings": ["empty domain"],
            "bimi_present": False,
            "mta_sts_present": False,
            "tls_rpt_present": False,
            "age_unknown_or_seconds": None,
            "recommendations": [],
        }

    try:
        dmarc_records, bimi_records, mta_records, tls_records = await asyncio.gather(
            _resolve_txt(f"_dmarc.{domain}"),
            _resolve_txt(f"default._bimi.{domain}"),
            _resolve_txt(f"_mta-sts.{domain}"),
            _resolve_txt(f"_smtp._tls.{domain}"),
        )
    except Exception as exc:  # noqa: BLE001
        _logger.warning("dns_check %s — gather failed: %s", domain, exc)
        dmarc_records, bimi_records, mta_records, tls_records = [], [], [], []

    raw_dmarc = next(
        (r for r in dmarc_records if r.lower().lstrip().startswith("v=dmarc1")),
        None,
    )
    parsed_tags: dict[str, str] = {}
    warnings: list[str] = []
    if raw_dmarc:
        parsed_tags, warnings = _parse_dmarc(raw_dmarc)
    else:
        warnings.append("No _dmarc TXT record found.")

    bimi_present = any("v=bmi1" in r.lower() or "v=bimi1" in r.lower() for r in bimi_records)
    mta_sts_present = any("v=stsv1" in r.lower() for r in mta_records)
    tls_rpt_present = any("v=tlsrpt" in r.lower().replace(" ", "") or "v=tlsrptv1" in r.lower() for r in tls_records)

    return {
        "domain": domain,
        "record_present": raw_dmarc is not None,
        "raw_record": raw_dmarc,
        "parsed_tags": parsed_tags,
        "warnings": warnings,
        "bimi_present": bimi_present,
        "mta_sts_present": mta_sts_present,
        "tls_rpt_present": tls_rpt_present,
        # Without HISTORY data we can't know the record's age. Surface
        # ``None`` and let the dashboard render "unknown".
        "age_unknown_or_seconds": None,
        "recommendations": _recommendations(parsed_tags, bimi_present, mta_sts_present, tls_rpt_present),
    }


__all__ = ["check_dmarc"]
