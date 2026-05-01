"""CAPEv2 connector (P3 #3.6).

CAPEv2 is the open-source community fork of Cuckoo Sandbox. Operators
typically self-host it next to Argus (it requires hypervisor + VM
templates). We talk to its REST API.

Endpoints:
  POST /apiv2/tasks/create/file/   submit
  GET  /apiv2/tasks/view/{task_id}/  status
  GET  /apiv2/tasks/get/report/{task_id}/  full report

Auth: optional API key via header ``Authorization: Token <key>``.
Many self-hosted CAPE installs run with auth disabled inside a private
network — we support both modes.

Operator config:
  ARGUS_CAPE_URL          base URL (e.g. https://cape.internal:8000)
  ARGUS_CAPE_API_KEY      optional auth token
  ARGUS_CAPE_VERIFY_SSL   "false" for self-signed
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


class CapeConnector(SandboxConnector):
    name = "cape"
    label = "CAPEv2 (self-hosted)"

    def __init__(self):
        self._url = (os.environ.get("ARGUS_CAPE_URL") or "") \
            .strip().rstrip("/")
        self._key = (os.environ.get("ARGUS_CAPE_API_KEY") or "").strip()
        self._verify_ssl = (os.environ.get("ARGUS_CAPE_VERIFY_SSL") or "true") \
            .strip().lower() not in {"false", "0", "no", "off"}

    def is_configured(self) -> bool:
        return bool(self._url)

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Accept": "application/json"}
        if self._key:
            h["Authorization"] = f"Token {self._key}"
        return h

    async def submit_file(
        self, *, sample_bytes: bytes, filename: str,
    ) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="cape not configured")
        size_err = self._check_size(sample_bytes)
        if size_err:
            return SandboxResult(sandbox=self.name, success=False,
                                  error=size_err)
        sha = hashlib.sha256(sample_bytes).hexdigest()

        url = f"{self._url}/apiv2/tasks/create/file/"
        breaker = get_breaker("sandbox:cape")
        timeout = aiohttp.ClientTimeout(total=120)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                form = aiohttp.FormData()
                form.add_field("file", sample_bytes, filename=filename,
                                content_type="application/octet-stream")
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

        task_id = body.get("task_id") or (body.get("data") or {}).get("task_id")
        if not task_id:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="cape returned no task_id",
                raw=body,
            )
        return SandboxResult(
            sandbox=self.name, success=True,
            data={"analysis_id": str(task_id), "sample_sha256": sha},
        )

    async def get_report(self, analysis_id: str) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="cape not configured")
        url = f"{self._url}/apiv2/tasks/get/report/{analysis_id}/"
        breaker = get_breaker("sandbox:cape")
        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(
                        url, headers=self._headers(),
                    ) as resp:
                        text = await resp.text()
                        if resp.status == 404:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error="task not found / not finished",
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

        info = body.get("info") or {}
        target = body.get("target") or {}
        target_file = target.get("file") or {}
        score = float(body.get("malscore") or 0.0)
        signatures = []
        for s in body.get("signatures", []) or []:
            if not isinstance(s, dict):
                continue
            sev_int = s.get("severity") or 1
            sev_map = {1: "low", 2: "medium", 3: "high"}
            signatures.append(SignatureHit(
                name=s.get("name", "") or s.get("description", "")[:80],
                severity=sev_map.get(sev_int, "low"),
                description=s.get("description") or None,
                attack=list(s.get("ttp") or []),
            ))
        techniques: list[str] = []
        for s in signatures:
            techniques.extend(t for t in s.attack if t)
        return SandboxResult(
            sandbox=self.name, success=True,
            data=AnalysisReport(
                sandbox=self.name,
                analysis_id=str(info.get("id") or analysis_id),
                sample_sha256=target_file.get("sha256"),
                verdict=_verdict_from_score(score),
                score=min(score / 10.0, 1.0),
                signatures=signatures,
                tags=list(info.get("tags") or []),
                attack_techniques=sorted(set(techniques)),
                raw=body,
            ),
        )

    async def health_check(self) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="cape not configured")
        url = f"{self._url}/apiv2/cuckoo/status/"
        breaker = get_breaker("sandbox:cape")
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with breaker:
                connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector,
                ) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        if resp.status >= 400:
                            text = await resp.text()
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SandboxResult(
                            sandbox=self.name, success=True,
                            note="cape /cuckoo/status reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
