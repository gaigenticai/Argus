"""Rspamd email-gateway connector — OSS phishing-IOC source.

Rspamd is the modern OSS spam/phishing scanner that powers Mailcow,
Mailu, docker-mailserver, and many bespoke OSS mail stacks. It exposes
a controller HTTP API on port 11334 (default) including a ``/history``
endpoint that returns recent scan results — sender, recipient, subject,
score, the rules that fired (symbols), and the URLs Rspamd extracted.

This connector wraps that history endpoint as an
EmailGatewayConnector so a customer running Rspamd anywhere on their
network gets the same contract Argus uses for Proofpoint / Mimecast /
Abnormal — and for free.

Auth: Rspamd's controller takes a password header (``Password: ...``).
The ``enable_password`` form unlocks write operations like fuzzy ham/
spam learning; we don't need that for read-only history fetches.

Operator config:

    ARGUS_RSPAMD_URL          base URL (e.g. http://mail.internal:11334)
    ARGUS_RSPAMD_PASSWORD     controller password
    ARGUS_RSPAMD_VERIFY_SSL   "false" for self-signed
    ARGUS_RSPAMD_HISTORY_LIMIT  max history rows per fetch (default 100)

Rspamd does NOT expose a programmatic blocklist write API in the
controller worker — operators add custom blocklists via the multimap
or fuzzy storage (separate config), so ``push_blocklist`` returns a
structured no-op pointing the operator at the right docs.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import (
    EmailBlocklistItem,
    EmailGatewayConnector,
    EmailGatewayResult,
    EmailThreatEvent,
)

logger = logging.getLogger(__name__)


# Rspamd actions that we map to the EmailThreatEvent.classification
# enum. "rewrite subject" and "soft reject" are graded warnings —
# Rspamd thinks these are likely-but-not-certain phishing/spam.
_ACTION_TO_CLASS: dict[str, str] = {
    "reject": "phish",
    "soft reject": "phish",
    "rewrite subject": "spam",
    "add header": "spam",
    "greylist": "spam",
    "no action": "other",
}

# Rspamd symbol-name fragments that strongly indicate phishing
# regardless of the action verdict. Catches custom rule sets where
# the action mapping is non-default.
_PHISHING_SYMBOLS = (
    "PHISHING", "PHISH_", "DCC_PHISH", "RBL_PHISH", "URIBL_PHISH",
    "MALWARE", "VIRUS", "HFILTER_URL_PHISHED",
)


class RspamdConnector(EmailGatewayConnector):
    name = "rspamd"
    label = "Rspamd (OSS — self-hosted)"
    supports_blocklist_push = False

    def __init__(self):
        self._url = (os.environ.get("ARGUS_RSPAMD_URL") or "") \
            .strip().rstrip("/")
        self._password = (os.environ.get("ARGUS_RSPAMD_PASSWORD") or "").strip()
        self._verify_ssl = (
            os.environ.get("ARGUS_RSPAMD_VERIFY_SSL") or "true"
        ).strip().lower() not in {"false", "0", "no", "off"}
        try:
            self._limit = int(os.environ.get("ARGUS_RSPAMD_HISTORY_LIMIT") or "100")
        except ValueError:
            self._limit = 100

    def is_configured(self) -> bool:
        # The Rspamd controller can be configured passwordless on
        # private networks; we accept the URL alone but warn loudly
        # if no password is set.
        return bool(self._url)

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self._password:
            h["Password"] = self._password
        return h

    async def fetch_threats(
        self, *, since_iso: str | None = None,
    ) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="rspamd not configured — set ARGUS_RSPAMD_URL",
            )

        url = f"{self._url}/history"
        breaker = get_breaker("email_gateway:rspamd")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status == 401 or resp.status == 403:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error="rspamd controller rejected the password",
                            )
                        if resp.status >= 400:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        try:
                            payload = json.loads(text) if text else {}
                        except json.JSONDecodeError as exc:
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error=f"JSON parse: {exc}",
                            )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        # Rspamd's /history payload shape varies by version: the modern
        # controller returns ``{"version":4,"rows":[…]}`` while older
        # versions returned a bare array. Handle both.
        if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
            rows = payload["rows"]
        elif isinstance(payload, list):
            rows = payload
        else:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"unexpected history payload shape: {type(payload).__name__}",
                raw={"sample": str(payload)[:200]},
            )

        events: list[EmailThreatEvent] = []
        skipped = 0
        for row in rows[: self._limit]:
            if not isinstance(row, dict):
                skipped += 1
                continue
            action = (row.get("action") or "").lower()
            symbols = row.get("symbols") or {}
            sym_names = (
                list(symbols.keys()) if isinstance(symbols, dict)
                else []
            )

            classification = _ACTION_TO_CLASS.get(action, "other")
            # Phishing-symbol override — even if action='no action',
            # treat as phish if a phishing-flavoured symbol fired.
            if any(any(p in s.upper() for p in _PHISHING_SYMBOLS) for s in sym_names):
                classification = "phish"

            if classification == "other":
                continue  # skip clean / mostly-spam rows; we want phish/malware

            # Extract the first URL Rspamd saw — the rest live in
            # raw for richer downstream analysis.
            urls = row.get("urls") or []
            threat_url = (
                str(urls[0]) if isinstance(urls, list) and urls else None
            )

            event_id = str(
                row.get("message-id")
                or row.get("id")
                or row.get("message_id")
                or f"{row.get('unix_time', 0)}-{row.get('subject', '')[:32]}"
            )[:240]

            events.append(EmailThreatEvent(
                gateway=self.name,
                event_id=event_id,
                classification=classification,
                sender=(row.get("sender_smtp") or row.get("sender_mime") or None),
                recipient=(row.get("rcpt_smtp") or [None])[0]
                    if isinstance(row.get("rcpt_smtp"), list)
                    else row.get("rcpt_smtp"),
                subject=row.get("subject") or None,
                threat_url=threat_url,
                threat_hash=None,
                occurred_at=row.get("time_real") or str(row.get("unix_time") or ""),
                raw={
                    "action": action,
                    "score": row.get("score"),
                    "required_score": row.get("required_score"),
                    "symbols": sym_names[:30],
                    "urls": list(urls)[:20] if isinstance(urls, list) else [],
                },
            ))

        return EmailGatewayResult(
            gateway=self.name, success=True, events=events,
            note=(
                f"fetched {len(rows)} history row(s); "
                f"{len(events)} phish/malware; {skipped} skipped"
            ),
        )

    async def push_blocklist(
        self, items: list[EmailBlocklistItem],
    ) -> EmailGatewayResult:
        return EmailGatewayResult(
            gateway=self.name, success=False,
            note=(
                "Rspamd doesn't expose a programmatic blocklist write API. "
                "Add entries to your multimap (e.g. /etc/rspamd/local.d/multimap.conf) "
                "or fuzzy storage. See https://rspamd.com/doc/modules/multimap.html"
            ),
        )

    async def health_check(self) -> EmailGatewayResult:
        if not self.is_configured():
            return EmailGatewayResult(
                gateway=self.name, success=False,
                note="rspamd not configured",
            )
        # /ping returns "pong\r\n" with a 200 — cheaper than fetching
        # the full history just to verify liveness.
        url = f"{self._url}/ping"
        breaker = get_breaker("email_gateway:rspamd")
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        if resp.status >= 400:
                            text = await resp.text()
                            return EmailGatewayResult(
                                gateway=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return EmailGatewayResult(
                            gateway=self.name, success=True,
                            note="rspamd /ping reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return EmailGatewayResult(
                gateway=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
