"""Cortex (TheHive Project) connector.

Cortex is the analyzer/responder engine from TheHive Project — an
Apache-2.0 OSS framework with 200+ community-maintained analyzers
(MISP, MaxMind, MaxMind, urlscan, AbuseIPDB, VirusTotal, Hybrid-
Analysis, Shodan, etc.) and active responders (firewall block,
disable user, sinkhole DNS).

Two integration modes wired here:

  1. **push_events** — same SoarConnector contract as XSOAR / Tines /
     Splunk SOAR. For each Argus alert we extract the matched
     observables (IPs, domains, hashes from ``matched_entities``) and
     fan them out to the configured default analyzer pipeline.
     Bulk operator-facing path used by ``core.auto_fanout``.

  2. **run_analyzer / get_job** — explicit per-call API the case
     copilot agent can drive as a tool, e.g. "run AbuseIPDB on this
     observable, then fold the report into the case timeline".

API contract (verified May 2026 — docs.strangebee.com/cortex/api):

    GET  /api/analyzer                    list available analyzers
    POST /api/analyzer/<id>/run           submit a job (json body)
    GET  /api/job/<id>                    poll job status
    GET  /api/job/<id>/report             retrieve the analyzer report

    Auth: ``Authorization: Bearer <api_key>`` on every request.

Operator config:

    ARGUS_CORTEX_URL              base URL (e.g. https://cortex.internal:9001)
    ARGUS_CORTEX_API_KEY          bearer token
    ARGUS_CORTEX_DEFAULT_ANALYZER analyzer ID to invoke from push_events
                                  (defaults to "AbuseIPDB_1_0" — the most
                                  universally-installed free analyzer)
    ARGUS_CORTEX_VERIFY_SSL       "false" for self-signed
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import SoarConnector, SoarPushResult

logger = logging.getLogger(__name__)


# Mapping from observable values in our alert.matched_entities
# payload to Cortex `dataType` strings. Cortex is strict about this.
_DATATYPE_MAP: dict[str, str] = {
    "ip": "ip",
    "ipv4": "ip",
    "domain": "domain",
    "fqdn": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "email": "mail",
    "hash": "hash",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
}


class CortexConnector(SoarConnector):
    name = "cortex"
    label = "Cortex (TheHive Project)"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_CORTEX_URL") or "").strip().rstrip("/")
        self._key = (os.environ.get("ARGUS_CORTEX_API_KEY") or "").strip()
        self._default_analyzer = (
            os.environ.get("ARGUS_CORTEX_DEFAULT_ANALYZER")
            or "AbuseIPDB_1_0"
        ).strip()
        self._verify_ssl = (
            os.environ.get("ARGUS_CORTEX_VERIFY_SSL") or "true"
        ).strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url and self._key)

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._key}",
        }
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    # ------------------------------------------------------------------
    # Mode 1: push_events (SoarConnector contract)
    # ------------------------------------------------------------------

    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(
                success=False, note="cortex not configured",
            )
        if not events:
            return SoarPushResult(
                success=True, pushed_count=0, note="no events",
            )

        submitted = 0
        job_ids: list[str] = []
        errors: list[str] = []

        for ev in events:
            for observable_dt, observable_value in self._extract_observables(ev):
                res = await self.run_analyzer(
                    self._default_analyzer,
                    data=observable_value,
                    data_type=observable_dt,
                    tlp=2,  # AMBER — operator's data
                    message=f"Argus alert {ev.get('id', '?')}: {ev.get('title', '')[:80]}",
                )
                if res.success and res.remote_ids:
                    job_ids.extend(res.remote_ids)
                    submitted += 1
                elif res.error:
                    errors.append(res.error[:120])

        if submitted == 0 and errors:
            return SoarPushResult(
                success=False,
                error="; ".join(errors[:3]),
                pushed_count=0,
            )
        return SoarPushResult(
            success=True,
            pushed_count=submitted,
            remote_ids=job_ids,
            note=(
                f"Cortex: submitted {submitted} analyzer job(s) via "
                f"{self._default_analyzer!r}"
                + (f" ({len(errors)} skipped: {errors[0]})" if errors else "")
            ),
        )

    @staticmethod
    def _extract_observables(event: dict[str, Any]) -> list[tuple[str, str]]:
        """Pull observable (dataType, value) pairs out of an Argus
        alert dict. We look at ``matched_entities`` first (canonical
        per-alert metadata) and ``details`` as fallback. Returns a
        list of pairs Cortex's analyzer can chew on."""
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        sources = []
        if isinstance(event.get("matched_entities"), dict):
            sources.append(event["matched_entities"])
        if isinstance(event.get("details"), dict):
            sources.append(event["details"])

        for src in sources:
            for k, v in src.items():
                if not isinstance(v, str) or not v.strip():
                    continue
                kl = k.lower()
                # Fast key-name → dataType mapping for the common cases.
                for hint, dt in (
                    ("ip", "ip"),
                    ("domain", "domain"),
                    ("hostname", "domain"),
                    ("url", "url"),
                    ("email", "mail"),
                    ("sha256", "hash"),
                    ("sha1", "hash"),
                    ("md5", "hash"),
                    ("hash", "hash"),
                ):
                    if hint in kl:
                        pair = (dt, v.strip())
                        if pair not in seen:
                            seen.add(pair)
                            out.append(pair)
                        break
        return out

    # ------------------------------------------------------------------
    # Mode 2: explicit analyzer calls (case_copilot tool surface)
    # ------------------------------------------------------------------

    async def list_analyzers(self) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(
                success=False, note="cortex not configured",
            )
        url = f"{self._url}/api/analyzer"
        breaker = get_breaker("soar:cortex")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SoarPushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        body = json.loads(text) if text else []
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SoarPushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )
        ids = [
            a.get("id") for a in (body or [])
            if isinstance(a, dict) and a.get("id")
        ]
        return SoarPushResult(
            success=True,
            remote_ids=ids,
            note=f"{len(ids)} analyzer(s) installed",
            raw={"analyzers": body},
        )

    async def run_analyzer(
        self,
        analyzer_id: str,
        *,
        data: str,
        data_type: str,
        tlp: int = 2,
        message: str | None = None,
    ) -> SoarPushResult:
        """Submit one observable to one analyzer. Returns the Cortex
        ``jobId`` in remote_ids on success — poll with ``get_job``."""
        if not self.is_configured():
            return SoarPushResult(
                success=False, note="cortex not configured",
            )
        normalised_dt = _DATATYPE_MAP.get((data_type or "").lower())
        if not normalised_dt:
            return SoarPushResult(
                success=False,
                error=f"unsupported dataType {data_type!r}",
            )

        url = f"{self._url}/api/analyzer/{analyzer_id}/run"
        body = {
            "data": data,
            "dataType": normalised_dt,
            "tlp": int(tlp),
        }
        if message:
            body["message"] = message[:500]

        breaker = get_breaker("soar:cortex")
        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.post(
                        url,
                        headers=self._headers(json_body=True),
                        json=body,
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SoarPushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        payload = json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SoarPushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )

        job_id = payload.get("id") or payload.get("_id")
        if not job_id:
            return SoarPushResult(
                success=False, error="cortex returned no job id",
                raw=payload,
            )
        return SoarPushResult(
            success=True, pushed_count=1,
            remote_ids=[str(job_id)],
            raw=payload,
        )

    async def get_job(self, job_id: str, *, with_report: bool = True) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(
                success=False, note="cortex not configured",
            )
        url = (
            f"{self._url}/api/job/{job_id}/report" if with_report
            else f"{self._url}/api/job/{job_id}"
        )
        breaker = get_breaker("soar:cortex")
        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status == 404:
                            return SoarPushResult(
                                success=False, error="job not found",
                            )
                        if resp.status >= 400:
                            return SoarPushResult(
                                success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        payload = json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SoarPushResult(
                success=False, error=f"{type(exc).__name__}: {exc}"[:200],
            )
        return SoarPushResult(
            success=True, raw=payload,
            note=f"job status: {payload.get('status', 'unknown')}",
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> SoarPushResult:
        # list_analyzers doubles as a liveness probe — the API rejects
        # bad creds with 401 before doing real work.
        return await self.list_analyzers()
