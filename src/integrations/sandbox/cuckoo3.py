"""Cuckoo3 sandbox connector.

Cuckoo3 is CERT-EE's Python-3 rewrite of the original Cuckoo Sandbox.
It's actively maintained (unlike the legacy Cuckoo branch), has cleaner
internals, and is the recommended modern OSS sandbox alongside CAPEv2.
Both are Apache-2.0; they detonate samples in the same way; we wire
them as peers so the operator can run either (or both for consensus).

API contract (verified May 2026 — cuckoo-hatch.cert.ee/static/docs):

    POST /submit/file                          → returns analysis_id
    GET  /analysis/<analysis_id>                → status + score + tasks
    GET  /analysis/<analysis_id>/task/<task_id>/post  → full report

    Auth: ``Authorization: token <key>`` header on every request.

Operator config:

    ARGUS_CUCKOO3_URL          base URL (e.g. http://cuckoo3.internal:8090)
    ARGUS_CUCKOO3_API_KEY      auth token
    ARGUS_CUCKOO3_VERIFY_SSL   "false" for self-signed
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

import aiohttp

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

from .base import (
    AnalysisReport,
    SandboxConnector,
    SandboxResult,
    SignatureHit,
)

logger = logging.getLogger(__name__)


def _verdict_from_score(score: float) -> str:
    if score >= 8.0:
        return "malicious"
    if score >= 4.0:
        return "suspicious"
    if score > 0.0:
        return "clean"
    return "unknown"


class Cuckoo3Connector(SandboxConnector):
    name = "cuckoo3"
    label = "Cuckoo3 (self-hosted)"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_CUCKOO3_URL") or "") \
            .strip().rstrip("/")
        self._key = (os.environ.get("ARGUS_CUCKOO3_API_KEY") or "").strip()
        self._verify_ssl = (
            os.environ.get("ARGUS_CUCKOO3_VERIFY_SSL") or "true"
        ).strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url)

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Accept": "application/json"}
        if self._key:
            h["Authorization"] = f"token {self._key}"
        return h

    async def submit_file(
        self, *, sample_bytes: bytes, filename: str,
    ) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(
                sandbox=self.name, success=False,
                note="cuckoo3 not configured",
            )
        size_err = self._check_size(sample_bytes)
        if size_err:
            return SandboxResult(
                sandbox=self.name, success=False, error=size_err,
            )
        sha = hashlib.sha256(sample_bytes).hexdigest()

        url = f"{self._url}/submit/file"
        breaker = get_breaker("sandbox:cuckoo3")
        timeout = aiohttp.ClientTimeout(total=120)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                form = aiohttp.FormData()
                form.add_field(
                    "file", sample_bytes, filename=filename,
                    content_type="application/octet-stream",
                )
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.post(
                        url, headers=self._headers(), data=form,
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        body = json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        analysis_id = body.get("analysis_id")
        if not analysis_id:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="cuckoo3 returned no analysis_id",
                raw=body,
            )
        return SandboxResult(
            sandbox=self.name, success=True,
            data={"analysis_id": str(analysis_id), "sample_sha256": sha},
        )

    async def _get_analysis(self, analysis_id: str) -> dict[str, Any] | str:
        """Internal: GET /analysis/<id>. Returns parsed dict on 200,
        an error string on failure."""
        url = f"{self._url}/analysis/{analysis_id}"
        breaker = get_breaker("sandbox:cuckoo3")
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
                            return "analysis not found / not finished"
                        if resp.status >= 400:
                            return f"HTTP {resp.status}: {text[:200]}"
                        return json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return f"{type(exc).__name__}: {exc}"[:200]

    async def get_report(self, analysis_id: str) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(
                sandbox=self.name, success=False,
                note="cuckoo3 not configured",
            )

        analysis = await self._get_analysis(analysis_id)
        if isinstance(analysis, str):
            return SandboxResult(
                sandbox=self.name, success=False, error=analysis,
            )

        state = analysis.get("state") or "unknown"
        if state not in ("finished", "stopped"):
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"analysis state={state!r}; not yet ready",
            )

        # Cuckoo3 splits the report across "tasks" — pull the first
        # completed task's post-analysis bundle for the verdict.
        tasks = analysis.get("tasks") or []
        if not isinstance(tasks, list) or not tasks:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="analysis has no tasks",
            )
        primary_task = next(
            (t for t in tasks if isinstance(t, dict) and t.get("state") in ("finished", "stopped")),
            tasks[0] if isinstance(tasks[0], dict) else None,
        )
        if not isinstance(primary_task, dict):
            return SandboxResult(
                sandbox=self.name, success=False,
                error="analysis tasks malformed",
            )
        task_id = primary_task.get("id") or primary_task.get("task_id")
        if not task_id:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="primary task has no id",
            )

        post_url = f"{self._url}/analysis/{analysis_id}/task/{task_id}/post"
        breaker = get_breaker("sandbox:cuckoo3")
        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(
                        post_url, headers=self._headers(),
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        post = json.loads(text) if text else {}
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

        score = float(analysis.get("score") or post.get("score") or 0.0)
        target = analysis.get("target") or {}
        target_file = target.get("file") or target.get("submitted") or {}

        signatures: list[SignatureHit] = []
        for s in (post.get("signatures") or []):
            if not isinstance(s, dict):
                continue
            sev_int = s.get("severity") or 1
            sev_map = {1: "low", 2: "medium", 3: "high"}
            signatures.append(SignatureHit(
                name=s.get("name", "") or (s.get("description", "") or "")[:80],
                severity=sev_map.get(sev_int, "low"),
                description=s.get("description") or None,
                attack=list(s.get("ttp") or s.get("attck") or []),
            ))

        techniques: list[str] = []
        for s in signatures:
            techniques.extend(t for t in s.attack if t)

        return SandboxResult(
            sandbox=self.name, success=True,
            data=AnalysisReport(
                sandbox=self.name,
                analysis_id=str(analysis_id),
                sample_sha256=target_file.get("sha256"),
                verdict=_verdict_from_score(score),
                score=min(score / 10.0, 1.0) if score else 0.0,
                signatures=signatures,
                tags=list(post.get("tags") or analysis.get("tags") or []),
                attack_techniques=sorted(set(techniques)),
                raw={"analysis": analysis, "post": post},
            ),
        )

    async def health_check(self) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(
                sandbox=self.name, success=False,
                note="cuckoo3 not configured",
            )
        # Cuckoo3 doesn't expose a dedicated /status endpoint; the
        # ``/analysis`` collection root returns a 200 even on an empty
        # corpus, so we use that as the liveness probe.
        url = f"{self._url}/analysis"
        breaker = get_breaker("sandbox:cuckoo3")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(
                        url, headers=self._headers(),
                    ) as resp:
                        if resp.status >= 400:
                            text = await resp.text()
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SandboxResult(
                            sandbox=self.name, success=True,
                            note="cuckoo3 /analysis reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
