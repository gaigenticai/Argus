"""Hybrid-Analysis (CrowdStrike Falcon Sandbox) connector (P3 #3.6).

Endpoint: https://www.hybrid-analysis.com/api/v2
Auth: ``api-key: <key>`` header.

Submit:  POST /submit/file
Status:  GET  /submit/<id>/state
Report:  GET  /report/<job_id>/summary

Operator config:
  ARGUS_HYBRID_API_KEY     paid HA / Falcon Intel key
  ARGUS_HYBRID_BASE_URL    override (default: https://www.hybrid-analysis.com/api/v2)

  Default Falcon Sandbox environment IDs:
    100  Windows 7 32-bit
    110  Windows 7 64-bit
    120  Windows 10 64-bit
    300  Linux Ubuntu 16.04
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


_DEFAULT_BASE = "https://www.hybrid-analysis.com/api/v2"
_DEFAULT_ENV = 120   # Windows 10 64-bit


def _verdict_from_threat_score(score: int) -> str:
    if score >= 75:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score > 0:
        return "clean"
    return "unknown"


class HybridAnalysisConnector(SandboxConnector):
    name = "hybrid"
    label = "Hybrid-Analysis (Falcon Sandbox)"

    def __init__(self):
        self._key = (os.environ.get("ARGUS_HYBRID_API_KEY") or "").strip()
        self._base = (os.environ.get("ARGUS_HYBRID_BASE_URL") or _DEFAULT_BASE) \
            .strip().rstrip("/")
        try:
            self._env_id = int(os.environ.get("ARGUS_HYBRID_ENV_ID")
                                or _DEFAULT_ENV)
        except ValueError:
            self._env_id = _DEFAULT_ENV

    def is_configured(self) -> bool:
        return bool(self._key)

    def _headers(self) -> dict[str, str]:
        return {
            "api-key": self._key,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        }

    async def submit_file(
        self, *, sample_bytes: bytes, filename: str,
    ) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="hybrid not configured")
        size_err = self._check_size(sample_bytes)
        if size_err:
            return SandboxResult(sandbox=self.name, success=False,
                                  error=size_err)
        sha = hashlib.sha256(sample_bytes).hexdigest()

        breaker = get_breaker("sandbox:hybrid")
        timeout = aiohttp.ClientTimeout(total=120)
        url = f"{self._base}/submit/file"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    form = aiohttp.FormData()
                    form.add_field("environment_id", str(self._env_id))
                    form.add_field("file", sample_bytes,
                                    filename=filename,
                                    content_type="application/octet-stream")
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

        job_id = body.get("job_id") or body.get("submission_id")
        if not job_id:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="hybrid returned no job_id",
                raw=body,
            )
        return SandboxResult(
            sandbox=self.name, success=True,
            data={"analysis_id": str(job_id), "sample_sha256": sha},
        )

    async def get_report(self, analysis_id: str) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="hybrid not configured")
        breaker = get_breaker("sandbox:hybrid")
        timeout = aiohttp.ClientTimeout(total=60)
        url = f"{self._base}/report/{analysis_id}/summary"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status == 404:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error="job not found / not finished",
                            )
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

        threat_score = int(body.get("threat_score") or 0)
        signatures: list[SignatureHit] = []
        for s in body.get("signatures", []) or []:
            if not isinstance(s, dict):
                continue
            signatures.append(SignatureHit(
                name=s.get("name") or "",
                description=s.get("description") or None,
                severity=({5: "critical", 4: "high", 3: "medium",
                           2: "low", 1: "info"}.get(
                    int(s.get("threat_level") or 1), "low"
                )),
                attack=list(s.get("attck_id", []) or []),
            ))
        return SandboxResult(
            sandbox=self.name, success=True,
            data=AnalysisReport(
                sandbox=self.name,
                analysis_id=analysis_id,
                sample_sha256=body.get("sha256"),
                verdict=_verdict_from_threat_score(threat_score),
                score=min(threat_score / 100.0, 1.0),
                signatures=signatures,
                tags=list(body.get("vx_family") and [body["vx_family"]] or []),
                attack_techniques=list(body.get("mitre_attcks") or []),
                artifacts_url=body.get("link"),
                raw=body,
            ),
        )

    async def health_check(self) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="hybrid not configured")
        breaker = get_breaker("sandbox:hybrid")
        timeout = aiohttp.ClientTimeout(total=15)
        url = f"{self._base}/key/current"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SandboxResult(
                            sandbox=self.name, success=True,
                            note="hybrid /key/current reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
