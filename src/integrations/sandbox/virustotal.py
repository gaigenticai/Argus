"""VirusTotal Premium / Enterprise connector (P3 #3.6).

**Strict BYOK** — VirusTotal's free-tier ToS forbids commercial-product
use. This connector deliberately refuses to run without a key set in
``ARGUS_VT_API_KEY``, AND requires the operator to explicitly opt-in
to "I have a paid Enterprise/Premium key" via
``ARGUS_VT_ENTERPRISE=true``. Without both, ``is_configured()`` returns
False and every entry-point no-ops.

Endpoint: https://www.virustotal.com/api/v3
Auth: ``x-apikey: <key>`` header.

Submit:  POST /files
File report by analysis id:    GET /analyses/{id}
File report by sha256:         GET /files/{sha256}

Operator config:
  ARGUS_VT_API_KEY      Enterprise / Premium API key (BYOK)
  ARGUS_VT_ENTERPRISE   "true" — operator attests to paid licensing
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


_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalConnector(SandboxConnector):
    name = "virustotal"
    label = "VirusTotal Premium / Enterprise (BYOK)"

    def __init__(self):
        self._key = (os.environ.get("ARGUS_VT_API_KEY") or "").strip()
        self._enterprise = (os.environ.get("ARGUS_VT_ENTERPRISE") or "") \
            .strip().lower() in {"true", "1", "yes", "on"}

    def is_configured(self) -> bool:
        # Both checks intentional — see module docstring.
        return bool(self._key and self._enterprise)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._key, "Accept": "application/json"}

    async def submit_file(
        self, *, sample_bytes: bytes, filename: str,
    ) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(
                sandbox=self.name, success=False,
                note=("virustotal disabled — set ARGUS_VT_API_KEY AND "
                      "ARGUS_VT_ENTERPRISE=true (free tier ToS forbids "
                      "commercial product use)"),
            )
        size_err = self._check_size(sample_bytes)
        if size_err:
            return SandboxResult(sandbox=self.name, success=False,
                                  error=size_err)
        sha = hashlib.sha256(sample_bytes).hexdigest()

        breaker = get_breaker("sandbox:virustotal")
        timeout = aiohttp.ClientTimeout(total=120)
        url = f"{_BASE}/files"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    form = aiohttp.FormData()
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

        analysis_id = (body.get("data") or {}).get("id")
        if not analysis_id:
            return SandboxResult(
                sandbox=self.name, success=False,
                error="virustotal returned no analysis id",
                raw=body,
            )
        return SandboxResult(
            sandbox=self.name, success=True,
            data={"analysis_id": str(analysis_id), "sample_sha256": sha},
        )

    async def get_report(self, analysis_id: str) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="virustotal not configured")
        breaker = get_breaker("sandbox:virustotal")
        timeout = aiohttp.ClientTimeout(total=60)
        # Heuristic: a 64-char hex string is a SHA-256, otherwise an
        # analysis id. Both endpoints exist.
        is_sha256 = (len(analysis_id) == 64 and
                     all(c in "0123456789abcdefABCDEF" for c in analysis_id))
        url = (f"{_BASE}/files/{analysis_id.lower()}" if is_sha256
               else f"{_BASE}/analyses/{analysis_id}")
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status == 404:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error="analysis not found",
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

        attrs = (body.get("data") or {}).get("attributes") or {}
        # File-resource shape: stats are under last_analysis_stats.
        # Analysis-resource shape: stats are under stats.
        stats = (attrs.get("last_analysis_stats")
                 or attrs.get("stats") or {})
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values()) or 1
        score = (malicious + 0.5 * suspicious) / total
        if malicious > 0 and score >= 0.1:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        # ATT&CK techniques live under crowdsourced_yara / sigma /
        # crowdsourced_ai when the vendor has populated them; the
        # canonical place is sandbox_verdicts → mitre_attack_techniques.
        techniques: list[str] = []
        for v in (attrs.get("sandbox_verdicts") or {}).values():
            if isinstance(v, dict):
                techniques.extend(v.get("malware_classification", []) or [])
                techniques.extend(v.get("mitre_attack_techniques", []) or [])

        # Crowd-sourced YARA / Sigma signatures are already structured.
        signatures: list[SignatureHit] = []
        for sig in (attrs.get("crowdsourced_yara_results") or []):
            if isinstance(sig, dict):
                signatures.append(SignatureHit(
                    name=sig.get("rule_name") or "",
                    description=sig.get("description"),
                ))
        for sig in (attrs.get("sigma_analysis_results") or []):
            if isinstance(sig, dict):
                signatures.append(SignatureHit(
                    name=sig.get("rule_title") or "",
                    description=sig.get("rule_description"),
                ))

        return SandboxResult(
            sandbox=self.name, success=True,
            data=AnalysisReport(
                sandbox=self.name,
                analysis_id=analysis_id,
                sample_sha256=attrs.get("sha256"),
                verdict=verdict,
                score=min(score, 1.0),
                signatures=signatures,
                tags=list(attrs.get("tags") or []),
                attack_techniques=sorted(set(techniques)),
                artifacts_url=(
                    f"https://www.virustotal.com/gui/file/{attrs.get('sha256')}"
                    if attrs.get("sha256") else None
                ),
                raw=attrs,
            ),
        )

    async def health_check(self) -> SandboxResult:
        if not self.is_configured():
            return SandboxResult(sandbox=self.name, success=False,
                                  note="virustotal not configured")
        breaker = get_breaker("sandbox:virustotal")
        timeout = aiohttp.ClientTimeout(total=15)
        url = f"{_BASE}/users/current"
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout) as http:
                    async with http.get(url, headers=self._headers()) as resp:
                        text = await resp.text()
                        if resp.status == 401:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error="virustotal 401 — check ARGUS_VT_API_KEY",
                            )
                        if resp.status >= 400:
                            return SandboxResult(
                                sandbox=self.name, success=False,
                                error=f"HTTP {resp.status}: {text[:200]}",
                            )
                        return SandboxResult(
                            sandbox=self.name, success=True,
                            note="virustotal /users/current reachable",
                        )
        except (CircuitBreakerOpenError, aiohttp.ClientError) as exc:
            return SandboxResult(
                sandbox=self.name, success=False,
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
