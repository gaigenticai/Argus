"""theHarvester wrapper — passive OSINT recon for a target domain.

theHarvester (https://github.com/laramies/theHarvester) is a passive
recon CLI that scrapes ~30 public sources for emails, subdomains,
hosts, and people associated with a domain. Sources include search
engines (Bing, DuckDuckGo), CT log mirrors (crtsh, certspotter),
code search (GitHub), and threat-intel feeds (OTX, urlscan, hunter).

Why we wrap it (and not just call its Python lib):

  - Its public API is unstable across versions; the CLI's ``--json``
    output is the most stable contract.
  - Many sources have rate limits + flaky third-party APIs; the CLI
    handles per-source isolation already.
  - Operators frequently install custom theHarvester forks/patches —
    treating it as a bin under ``$PATH`` keeps the integration
    forward-compatible.

How Marsad uses the output:

  - Onboarding asset discovery — given the operator's primary
    domain, surface candidate subdomains + email patterns.
  - ``/exposures`` — feed subdomains into the EASM queue.
  - ``/brand`` — exec-email seeding (then pipe through Cavalier +
    Holehe).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Curated source set — every one is free / no-key + relatively
# rate-limit-tolerant. The full theHarvester source list includes
# paid options (Hunter, Censys, Shodan) which we only enable when
# the operator sets the matching API key.
_DEFAULT_SOURCES = (
    "anubis",
    "bevigil",
    "bing",
    "certspotter",
    "crtsh",
    "duckduckgo",
    "github-code",
    "hackertarget",
    "otx",
    "rapiddns",
    "subdomaincenter",
    "subdomainfinderc99",
    "threatminer",
    "urlscan",
    "yahoo",
)

# Domain → sources mapping for sources that need an API key. We
# include them only when the corresponding env var is non-empty so
# theHarvester doesn't error out on a missing credential.
_KEYED_SOURCES = {
    "hunter": "ARGUS_HUNTER_API_KEY",
    "censys": "ARGUS_CENSYS_API_KEY",
    "shodan": "ARGUS_SHODAN_API_KEY",
    "github-key": "ARGUS_GITHUB_TOKEN",
    "fullhunt": "ARGUS_FULLHUNT_API_KEY",
}


_HARVESTER_BIN = os.environ.get("ARGUS_THEHARVESTER_BIN", "theHarvester")
_DEFAULT_TIMEOUT_S = int(os.environ.get("ARGUS_THEHARVESTER_TIMEOUT_S", "180"))


@dataclass
class HarvestReport:
    """Normalised harvest output across theHarvester versions."""
    domain: str
    sources: list[str]
    emails: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    duration_ms: int = 0
    raw_path: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "sources": list(self.sources),
            "totals": {
                "emails": len(self.emails),
                "hosts": len(self.hosts),
                "ips": len(self.ips),
                "asns": len(self.asns),
            },
            "emails": list(self.emails),
            "hosts": list(self.hosts),
            "ips": list(self.ips),
            "asns": list(self.asns),
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


def is_installed() -> bool:
    return shutil.which(_HARVESTER_BIN) is not None


def _build_sources(extra: list[str] | None = None) -> list[str]:
    sources = list(_DEFAULT_SOURCES)
    for name, env in _KEYED_SOURCES.items():
        if (os.environ.get(env) or "").strip():
            sources.append(name)
    if extra:
        for s in extra:
            s = (s or "").strip()
            if s and s not in sources:
                sources.append(s)
    return sources


async def harvest(
    domain: str,
    *,
    sources: list[str] | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    limit: int = 500,
) -> HarvestReport:
    """Run theHarvester against ``domain`` and return a normalised
    report. Per-source failures are absorbed by theHarvester itself;
    a hard timeout caps total wall time so a stuck source can't wedge
    the worker.

    Returns a ``HarvestReport`` with ``error`` set when invocation
    failed entirely; partial successes are non-fatal."""
    import time as _time

    domain = (domain or "").strip().lower()
    if not domain or "." not in domain:
        return HarvestReport(
            domain=domain, sources=[], error="empty or malformed domain",
        )
    if not is_installed():
        return HarvestReport(
            domain=domain, sources=[],
            error=(
                f"{_HARVESTER_BIN} binary not found in PATH. Rebuild the "
                "image (Dockerfile installs it from git) or `pip install "
                "git+https://github.com/laramies/theHarvester.git`."
            ),
        )

    src_list = sources if sources else _build_sources()
    src_arg = ",".join(src_list)

    started = _time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        out_base = os.path.join(tmp, "harvest")
        cmd = [
            _HARVESTER_BIN,
            "-d", domain,
            "-b", src_arg,
            "-l", str(limit),
            "-f", out_base,  # theHarvester writes <base>.json + .xml
        ]
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=10,
            )
        except Exception as e:  # noqa: BLE001
            return HarvestReport(
                domain=domain, sources=src_list,
                error=f"failed to spawn theHarvester: {type(e).__name__}: {e}",
            )

        try:
            _stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return HarvestReport(
                domain=domain, sources=src_list,
                duration_ms=int((_time.monotonic() - started) * 1000),
                error=f"theHarvester timed out after {timeout_s}s",
            )

        duration_ms = int((_time.monotonic() - started) * 1000)
        if proc.returncode and proc.returncode != 0:
            err = (stderr or b"").decode("utf-8", errors="ignore")[:400]
            logger.warning(
                "theHarvester exit=%d for %s: %s",
                proc.returncode, domain, err,
            )
            # Non-zero exit but JSON may still exist for partial success.

        json_path = out_base + ".json"
        report = HarvestReport(
            domain=domain, sources=src_list, duration_ms=duration_ms,
            raw_path=None,
        )
        if not os.path.exists(json_path):
            report.error = (
                "theHarvester produced no JSON output; check worker logs "
                "for per-source errors"
            )
            return report

        try:
            with open(json_path) as f:
                payload = json.load(f)
        except Exception as e:  # noqa: BLE001
            report.error = f"failed to parse theHarvester JSON: {e}"
            return report

    # theHarvester JSON shape varies by version — normalise:
    report.emails = _dedup_lower(payload.get("emails") or [])
    hosts_raw = payload.get("hosts") or []
    # Hosts are sometimes ``"name:1.2.3.4"`` — split.
    hosts: list[str] = []
    ips: list[str] = []
    for h in hosts_raw:
        if not isinstance(h, str):
            continue
        if ":" in h:
            host, ip = h.split(":", 1)
            hosts.append(host.strip().lower())
            if _looks_like_ip(ip):
                ips.append(ip.strip())
        else:
            hosts.append(h.strip().lower())
    report.hosts = sorted(set(hosts))
    # Plus any explicit "ips" list (newer versions).
    for ip in payload.get("ips") or []:
        if isinstance(ip, str) and _looks_like_ip(ip):
            ips.append(ip.strip())
    report.ips = sorted(set(ips))
    report.asns = sorted({
        a for a in (payload.get("asns") or [])
        if isinstance(a, str) and a
    })
    return report


def _dedup_lower(seq) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if not isinstance(item, str):
            continue
        v = item.strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_ip(s: str) -> bool:
    return bool(_IP_RE.match((s or "").strip()))
