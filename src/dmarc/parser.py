"""DMARC aggregate (RUA) report parser.

Pure stdlib so we never depend on parsedmarc's evolving public surface.
Aggregate XML schema is stable and trivially parseable.

Input: bytes of the (decompressed) RUA XML.
Output: ``ParsedDmarcReport`` dataclass with header + ``records`` list.

We deliberately accept either:
    - an XML string already decompressed
    - a gzip-compressed bytes blob
    - a zip-archived blob (we use the first .xml entry inside)
"""

from __future__ import annotations

import gzip
import io
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
# Audit B7 — defusedxml is XXE-safe.
import defusedxml.ElementTree as ET  # type: ignore


@dataclass
class ParsedDmarcRecord:
    source_ip: str
    count: int
    disposition: str | None
    spf_result: str | None
    dkim_result: str | None
    spf_aligned: bool | None
    dkim_aligned: bool | None
    header_from: str | None
    envelope_from: str | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedDmarcReport:
    org_name: str | None
    report_id: str
    domain: str
    date_begin: datetime
    date_end: datetime
    policy_p: str | None
    policy_pct: int | None
    records: list[ParsedDmarcRecord]
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def total_messages(self) -> int:
        return sum(r.count for r in self.records)


def _maybe_decompress(blob: bytes) -> bytes:
    """Accept gzip / zip / plain XML and return raw XML bytes."""
    if blob[:2] == b"\x1f\x8b":  # gzip magic
        return gzip.decompress(blob)
    if blob[:2] == b"PK":  # zip magic
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for name in z.namelist():
                if name.lower().endswith(".xml"):
                    return z.read(name)
            raise ValueError("zip archive contains no .xml entry")
    return blob


def _txt(node, tag: str) -> str | None:
    el = node.find(tag)
    if el is None or el.text is None:
        return None
    return el.text.strip() or None


def parse_aggregate(blob: bytes) -> ParsedDmarcReport:
    xml = _maybe_decompress(blob)
    root = ET.fromstring(xml)

    md = root.find("report_metadata")
    pp = root.find("policy_published")
    org_name = _txt(md, "org_name") if md is not None else None
    report_id = _txt(md, "report_id") if md is not None else ""
    if not report_id:
        raise ValueError("DMARC RUA missing <report_id>")
    drange = md.find("date_range") if md is not None else None
    db = int(_txt(drange, "begin")) if drange is not None else 0
    de = int(_txt(drange, "end")) if drange is not None else 0

    domain = _txt(pp, "domain") if pp is not None else None
    if not domain:
        raise ValueError("DMARC RUA missing policy_published.domain")
    policy_p = _txt(pp, "p") if pp is not None else None
    pct_raw = _txt(pp, "pct") if pp is not None else None
    try:
        policy_pct = int(pct_raw) if pct_raw is not None else None
    except ValueError:
        policy_pct = None

    records: list[ParsedDmarcRecord] = []
    for rec in root.findall("record"):
        row = rec.find("row")
        identifiers = rec.find("identifiers")
        auth = rec.find("auth_results")
        source_ip = _txt(row, "source_ip") if row is not None else None
        count_raw = _txt(row, "count") if row is not None else "0"
        try:
            count = int(count_raw or "0")
        except ValueError:
            count = 0
        po = row.find("policy_evaluated") if row is not None else None
        disposition = _txt(po, "disposition") if po is not None else None
        spf_aligned = _txt(po, "spf") if po is not None else None
        dkim_aligned = _txt(po, "dkim") if po is not None else None
        header_from = _txt(identifiers, "header_from") if identifiers is not None else None
        env_from = _txt(identifiers, "envelope_from") if identifiers is not None else None

        spf_node = auth.find("spf") if auth is not None else None
        dkim_node = auth.find("dkim") if auth is not None else None
        spf_result = _txt(spf_node, "result") if spf_node is not None else None
        dkim_result = _txt(dkim_node, "result") if dkim_node is not None else None

        if not source_ip:
            continue
        records.append(
            ParsedDmarcRecord(
                source_ip=source_ip,
                count=count,
                disposition=disposition,
                spf_result=spf_result,
                dkim_result=dkim_result,
                spf_aligned=(spf_aligned == "pass") if spf_aligned else None,
                dkim_aligned=(dkim_aligned == "pass") if dkim_aligned else None,
                header_from=header_from,
                envelope_from=env_from,
            )
        )

    return ParsedDmarcReport(
        org_name=org_name,
        report_id=report_id,
        domain=domain.lower(),
        date_begin=datetime.fromtimestamp(db, tz=timezone.utc),
        date_end=datetime.fromtimestamp(de, tz=timezone.utc),
        policy_p=policy_p,
        policy_pct=policy_pct,
        records=records,
    )


__all__ = ["ParsedDmarcRecord", "ParsedDmarcReport", "parse_aggregate"]
