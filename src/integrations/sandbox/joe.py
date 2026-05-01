"""Joe Sandbox Cloud connector (P3 #3.6).

Endpoint: https://jbxcloud.joesecurity.org/api
Auth: ``apikey`` form field on every call.

Submit:  POST /v2/submission/new      multipart file
         POST /v2/submission/new_url  url field
Status:  POST /v2/analysis/info
Report:  POST /v2/analysis/download (json)

Operator config:
  ARGUS_JOE_API_KEY   paid Joe Sandbox Cloud key
  ARGUS_JOE_BASE_URL  override (defaults to jbxcloud.joesecurity.org)
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


_DEFAULT_BASE = "https://jbxcloud.joesecurity.org/api"


class JoeSandboxConnector(SandboxConnector):
    name = "joe"
    label = "Joe Sandbox Cloud"

    def __init__(self):
        self._key = (os.environ.get("ARGUS_JOE_API_KEY") or "").strip()
        self._base = (os.environ.get("ARGUS_JOE_BASE_URL") or _DEFAULT_BASE) \
            .strip().rstrip("/")

    def is_configured(self) -> bool:
        return bool(self._key)

    async def submit_file(
        self, *, sample_bytes: bytes, filename: str,
    ) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="joe not configured")
        size_err = self._check_size(sample_bytes)
        if size_err:
            return SandboxResult(sandbox=self.name, success=False,
                                  error=size_err)
        sha = hashlib.sha256(sample_bytes).hexdigest()

        breaker = get_breaker("sandbox:joe")
        timeout = aiohttp.ClientTimeout(total=120)
        url = f"{self._base}/v2/submission/new"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    form = aiohttp.FormData()
                    form.add_field("apikey", self._key)
                    form.add_field("accept-tac", "1")
                    form.add_field("sample", sample_bytes,
                                    filename=filename,
                                    content_type="application/octet-stream")
                    async with http.post(url, data=form) as resp:
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

        sub_id = ((body.get("data") or {}).get("submission_id")
                  or body.get("submission_id"))
        if not sub_id:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="joe returned no submission_id",
                raw=body,
            )
        return SandboxResult(
            sandbox=self.name, success=True,
            data={"analysis_id": str(sub_id), "sample_sha256": sha},
        )

    async def get_report(self, analysis_id: str) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="joe not configured")

        breaker = get_breaker("sandbox:joe")
        timeout = aiohttp.ClientTimeout(total=60)
        url = f"{self._base}/v2/analysis/info"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(url, data={
                        "apikey": self._key, "webid": analysis_id,
                    }) as resp:
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

        analysis = (body.get("data") or {}).get("analysis") or {}
        if not analysis:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="joe returned empty analysis",
                raw=body,
            )
        # Joe Sandbox detection: clean / suspicious / malicious / unknown
        verdict = (analysis.get("detection") or "unknown").lower()
        score = float(analysis.get("score") or 0)  # 0-10
        signatures: list[SignatureHit] = []
        for sig in analysis.get("signatures", []) or []:
            if not isinstance(sig, dict):
                continue
            signatures.append(SignatureHit(
                name=sig.get("name") or "",
                description=sig.get("description"),
                severity={5: "critical", 4: "high",
                          3: "medium", 2: "low", 1: "info"}.get(
                    int(sig.get("severity") or 1), "low"
                ),
                attack=list(sig.get("mitre", []) or []),
            ))
        return SandboxResult(
            sandbox=self.name, success=True,
            data=AnalysisReport(
                sandbox=self.name,
                analysis_id=analysis_id,
                sample_sha256=analysis.get("sha256"),
                verdict=verdict,
                score=min(score / 10.0, 1.0),
                signatures=signatures,
                tags=list(analysis.get("tags") or []),
                attack_techniques=sorted(set(
                    t for s in signatures for t in s.attack
                )),
                artifacts_url=analysis.get("reporturl"),
                raw=analysis,
            ),
        )

    async def health_check(self) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="joe not configured")
        breaker = get_breaker("sandbox:joe")
        timeout = aiohttp.ClientTimeout(total=15)
        url = f"{self._base}/v2/server/online"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.post(
                        url, data={"apikey": self._key},
                    ) as resp:
                        text = await resp.text()
                        if resp.status >= 400:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SandboxResult(
                            sandbox=self.name, success=True,
                            note="joe server online",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
