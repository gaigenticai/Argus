"""DMARC aggregate (RUA) + forensic (RUF) report parsers.

Pure stdlib so we never depend on parsedmarc's evolving public surface.
Aggregate XML schema is stable and trivially parseable.

Input: bytes of the (decompressed) RUA / RUF blob.
Output: ``ParsedDmarcReport`` (RUA) or ``list[ParsedForensic]`` (RUF).

We deliberately accept either:
    - an XML string already decompressed
    - a gzip-compressed bytes blob
    - a zip-archived blob (we use the first .xml entry inside)
    - for RUF: an AFRF (RFC 5965) ``message/feedback-report`` email blob
"""

from __future__ import annotations

import email
import email.parser
import email.policy
import gzip
import io
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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


# ---------------------------------------------------------------- RUF
#
# Forensic reports come in two on-the-wire shapes:
#
# 1. RFC 6591 / RFC 5965 multipart email — Content-Type:
#    multipart/report; report-type=feedback-report. The middle part is
#    a ``message/feedback-report`` with header-style key:value lines:
#
#         Feedback-Type: auth-failure
#         User-Agent: ...
#         Source-IP: 192.0.2.42
#         Auth-Failure: dmarc
#         Original-Mail-From: <attacker@spoofed.example>
#         Reported-Domain: example.com
#         DKIM-Domain: example.com
#         DKIM-Selector: s1
#         SPF-Domain: spoofed.example
#         Delivery-Result: reject
#
#    The third part embeds the original message headers we want to
#    keep verbatim for IR.
#
# 2. Some receivers (Gmail, Yahoo) ship the same data inside a small
#    XML envelope `<feedback>` directly. We cover both.

@dataclass
class ParsedForensic:
    feedback_type: str | None
    arrival_date: datetime | None
    source_ip: str | None
    reported_domain: str | None
    original_envelope_from: str | None
    original_envelope_to: str | None
    original_mail_from: str | None
    original_rcpt_to: str | None
    auth_failure: str | None
    delivery_result: str | None
    dkim_domain: str | None
    dkim_selector: str | None
    spf_domain: str | None
    raw_headers: str | None
    extras: dict[str, Any] = field(default_factory=dict)


def _detect_ruf_or_rua(blob: bytes) -> str:
    """Return ``'rua'`` / ``'ruf_xml'`` / ``'ruf_email'`` / ``'unknown'``."""
    head = blob.lstrip()[:2048].lower()
    if head.startswith(b"<?xml") or head.startswith(b"<feedback"):
        # XML — RUA has <record><row><source_ip> chain; RUF can use
        # <feedback> root with <feedback_type>/<source_ip> children.
        try:
            txt = head.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            txt = ""
        if "<feedback_type" in txt or "<auth_failure" in txt or "<original_mail_from" in txt:
            return "ruf_xml"
        return "rua"
    if b"feedback-type:" in head or b"auth-failure:" in head or b"source-ip:" in head:
        return "ruf_email"
    if head.startswith(b"received:") or head.startswith(b"return-path:") or head.startswith(b"from:"):
        return "ruf_email"
    return "unknown"


def _parse_ruf_xml(blob: bytes) -> list[ParsedForensic]:
    xml = _maybe_decompress(blob)
    root = ET.fromstring(xml)
    out: list[ParsedForensic] = []

    # Two shapes: a root <feedback> with one report (most common), or
    # a <feedback> with multiple <record>-style children.
    nodes = [root]
    if root.tag.lower() == "feedback":
        # Look for explicit <forensic_record> children
        children = list(root.findall("forensic_record"))
        if children:
            nodes = children
    for n in nodes:
        out.append(
            ParsedForensic(
                feedback_type=_txt(n, "feedback_type"),
                arrival_date=_parse_arrival(_txt(n, "arrival_date")),
                source_ip=_txt(n, "source_ip"),
                reported_domain=_txt(n, "reported_domain"),
                original_envelope_from=_txt(n, "original_envelope_id")
                or _txt(n, "original_envelope_from"),
                original_envelope_to=_txt(n, "original_envelope_to"),
                original_mail_from=_txt(n, "original_mail_from"),
                original_rcpt_to=_txt(n, "original_rcpt_to"),
                auth_failure=_txt(n, "auth_failure") or _txt(n, "authentication_results"),
                delivery_result=_txt(n, "delivery_result"),
                dkim_domain=_txt(n, "dkim_domain"),
                dkim_selector=_txt(n, "dkim_selector"),
                spf_domain=_txt(n, "spf_domain") or _txt(n, "identity_alignment"),
                raw_headers=_txt(n, "reported_headers"),
                extras={},
            )
        )
    return out


def _parse_arrival(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None


def _afrf_kv(text: str) -> dict[str, str]:
    """Parse the ``message/feedback-report`` body — RFC 5965 key:value
    pairs, header-style. Tolerant of folded continuation lines.
    """
    parser = email.parser.HeaderParser(policy=email.policy.default)
    msg = parser.parsestr(text)
    out: dict[str, str] = {}
    for k, v in msg.items():
        out[k.lower().strip()] = (v or "").strip()
    # Some senders skip the email parser by emitting raw lines without
    # MIME wrapping; fall back to manual scan if HeaderParser ate too much.
    if not out:
        for line in text.splitlines():
            if ":" in line and not line.startswith((" ", "\t")):
                k, _, v = line.partition(":")
                out[k.lower().strip()] = v.strip()
    return out


def _parse_ruf_email(blob: bytes) -> list[ParsedForensic]:
    """Parse an AFRF (RFC 5965) feedback-report email."""
    text = blob.decode("utf-8", errors="replace") if isinstance(blob, (bytes, bytearray)) else blob
    msg = email.message_from_string(text, policy=email.policy.default)

    # Find the message/feedback-report part (or use the whole message
    # if it isn't multipart).
    fb_text: str | None = None
    raw_orig_headers: str | None = None

    def _flatten_payload_to_str(part: email.message.Message) -> str:
        """Best-effort string representation of any sub-part body —
        ``message/feedback-report`` is officially multipart in Python's
        email policy, so its key:value lines live one layer deeper.
        """
        payload = part.get_payload(decode=True)
        if isinstance(payload, (bytes, bytearray)):
            return payload.decode("utf-8", errors="replace")
        inner = part.get_payload()
        if isinstance(inner, str):
            return inner
        if isinstance(inner, list):
            chunks: list[str] = []
            for child in inner:
                if isinstance(child, email.message.Message):
                    # AFRF tags live in the child's *headers*, not its
                    # body — Python's email policy promotes those lines
                    # into header objects. Always emit the full
                    # serialised form so ``_afrf_kv`` can re-parse them
                    # uniformly. Fall back to the decoded payload only
                    # if serialisation fails.
                    try:
                        chunks.append(child.as_string(unixfrom=False))
                    except Exception:  # noqa: BLE001
                        cp = child.get_payload(decode=True)
                        if isinstance(cp, (bytes, bytearray)):
                            chunks.append(cp.decode("utf-8", errors="replace"))
                        else:
                            chunks.append(str(cp or child))
                else:
                    chunks.append(str(child))
            return "\n".join(chunks)
        return ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype == "message/feedback-report":
                fb_text = _flatten_payload_to_str(part)
            elif ctype in {"message/rfc822", "text/rfc822-headers"}:
                if raw_orig_headers is None:
                    raw_orig_headers = _flatten_payload_to_str(part)
    if fb_text is None:
        # Treat the entire blob as a flat key:value report.
        fb_text = text

    kv = _afrf_kv(fb_text)

    return [
        ParsedForensic(
            feedback_type=kv.get("feedback-type"),
            arrival_date=_parse_arrival(kv.get("arrival-date") or msg.get("Date")),
            source_ip=kv.get("source-ip"),
            reported_domain=kv.get("reported-domain"),
            original_envelope_from=kv.get("original-envelope-from"),
            original_envelope_to=kv.get("original-envelope-to") or kv.get("original-rcpt-to"),
            original_mail_from=kv.get("original-mail-from"),
            original_rcpt_to=kv.get("original-rcpt-to"),
            auth_failure=kv.get("auth-failure") or kv.get("authentication-results"),
            delivery_result=kv.get("delivery-result"),
            dkim_domain=kv.get("dkim-domain"),
            dkim_selector=kv.get("dkim-selector"),
            spf_domain=kv.get("spf-domain"),
            raw_headers=raw_orig_headers,
            extras={k: v for k, v in kv.items() if k.startswith("x-")},
        )
    ]


def parse_forensic(blob: bytes) -> list[ParsedForensic]:
    """Defensive RUF parser — accepts XML, gzip/zip-wrapped XML, or AFRF email."""
    if not blob:
        raise ValueError("empty RUF blob")
    blob = _maybe_decompress(blob)
    kind = _detect_ruf_or_rua(blob)
    if kind == "ruf_xml":
        return _parse_ruf_xml(blob)
    if kind == "ruf_email":
        return _parse_ruf_email(blob)
    if kind == "rua":
        # RUA wrongly fed in. Tell the caller.
        raise ValueError("blob looks like an RUA aggregate XML, not RUF")
    # Last-ditch: try email parser then XML.
    try:
        return _parse_ruf_email(blob)
    except Exception:  # noqa: BLE001
        pass
    return _parse_ruf_xml(blob)


def detect_kind(blob: bytes) -> str:
    """Public wrapper for callers that want to decide RUA vs RUF."""
    return _detect_ruf_or_rua(_maybe_decompress(blob))


__all__ = [
    "ParsedDmarcRecord",
    "ParsedDmarcReport",
    "ParsedForensic",
    "parse_aggregate",
    "parse_forensic",
    "detect_kind",
]
