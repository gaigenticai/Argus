"""External-tool runners for EASM workers.

Each runner is a coroutine ``async def run(target, parameters) ->
RunnerOutput`` that wraps a real OSS binary (subfinder, httpx, naabu)
or a Python library (dnspython, python-whois). Output is normalized to
typed dataclasses so the worker's persistence path stays free of
binary-output parsing concerns.

Test injection
--------------
The worker resolves runners through :func:`get_runner_registry`. Tests
override the registry via :func:`set_runner_registry` to inject fakes
that return canned output — exercising the full DB-write + change-
detection path without requiring binaries on the test host.
"""

from __future__ import annotations

import abc
import asyncio
import json
import logging
import shlex
import shutil
from dataclasses import dataclass, field
from typing import Any, Iterable

_logger = logging.getLogger(__name__)


# --- DTOs --------------------------------------------------------------


@dataclass
class RunnerOutput:
    """Generic envelope returned by every runner."""

    succeeded: bool
    items: list[dict[str, Any]] = field(default_factory=list)
    raw_stdout: str | None = None
    raw_stderr: str | None = None
    error_message: str | None = None
    duration_ms: int | None = None


# --- Subprocess helper -------------------------------------------------


async def _exec(
    cmd: list[str],
    *,
    stdin: str | None = None,
    timeout: float = 600,
    readonly_binds: tuple[str, ...] = (),
    share_net: bool = True,
) -> tuple[int, str, str]:
    """Run a subprocess inside a Bubblewrap sandbox. Returns
    ``(returncode, stdout, stderr)``.

    The sandbox bounds the binary's read access to /usr + /etc/ssl,
    runs it with a fresh PID/IPC/UTS namespace, and uses an isolated
    /tmp. Templates / rule files needed by the runner are exposed via
    ``readonly_binds``. Network defaults to "shared" because EASM
    tools must reach their targets; pass ``share_net=False`` for
    tools that genuinely don't need network (e.g. yara on local files).

    Raises ``FileNotFoundError`` if the binary is missing.
    Raises ``asyncio.TimeoutError`` if the wall-clock budget elapses.
    """
    from src.core.sandbox import SandboxPolicy, run_sandboxed

    policy = SandboxPolicy(
        share_net=share_net,
        readonly_binds=readonly_binds,
        timeout_seconds=timeout,
    )
    rc, out, err = await run_sandboxed(
        cmd,
        policy=policy,
        stdin=stdin.encode() if stdin else None,
    )
    return (
        rc,
        out.decode("utf-8", errors="replace"),
        err.decode("utf-8", errors="replace"),
    )


# --- Base --------------------------------------------------------------


class Runner(abc.ABC):
    kind: str

    @abc.abstractmethod
    async def run(
        self, target: str, parameters: dict[str, Any] | None = None
    ) -> RunnerOutput: ...


# --- Subfinder (subdomain enumeration) ---------------------------------


class SubfinderRunner(Runner):
    """ProjectDiscovery subfinder. JSON-lines output."""

    kind = "subdomain_enum"

    def __init__(self, binary: str = "subfinder", extra_args: Iterable[str] = ()):
        self.binary = binary
        self.extra_args = list(extra_args)

    async def run(self, target, parameters=None):
        params = parameters or {}
        cmd = [self.binary, "-d", target, "-silent", "-oJ"]
        cmd += list(self.extra_args)
        if params.get("all_sources"):
            cmd.append("-all")
        try:
            import time as _t

            t0 = _t.perf_counter()
            rc, out, err = await _exec(cmd, timeout=float(params.get("timeout", 300)))
            dt = int((_t.perf_counter() - t0) * 1000)
        except FileNotFoundError as e:
            return RunnerOutput(succeeded=False, error_message=str(e))
        except asyncio.TimeoutError:
            return RunnerOutput(succeeded=False, error_message="subfinder timed out")

        if rc != 0:
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message=f"subfinder exit code {rc}",
            )

        items = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Older subfinder versions emit one host per line in -silent
                items.append({"host": line, "source": "subfinder"})
                continue
            host = obj.get("host") or obj.get("name")
            if host:
                items.append(
                    {
                        "host": host.lower().rstrip("."),
                        "source": obj.get("source") or "subfinder",
                    }
                )
        return RunnerOutput(succeeded=True, items=items, raw_stdout=out, duration_ms=dt)


# --- httpx (HTTP probe) ------------------------------------------------


class HttpxRunner(Runner):
    """ProjectDiscovery httpx — probes hosts, returns status, title, tech, ip, tls."""

    kind = "httpx_probe"

    def __init__(self, binary: str = "httpx", extra_args: Iterable[str] = ()):
        self.binary = binary
        self.extra_args = list(extra_args)

    async def run(self, target, parameters=None):
        params = parameters or {}
        # ``target`` can be one host or a newline-delimited list piped via stdin.
        hosts = params.get("hosts") or [target]
        stdin_data = "\n".join(hosts) + "\n"
        cmd = [
            self.binary,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-tls-grab",
            "-ip",
            "-no-color",
        ] + list(self.extra_args)

        import time as _t

        t0 = _t.perf_counter()
        try:
            rc, out, err = await _exec(
                cmd, stdin=stdin_data, timeout=float(params.get("timeout", 300))
            )
        except FileNotFoundError as e:
            return RunnerOutput(succeeded=False, error_message=str(e))
        dt = int((_t.perf_counter() - t0) * 1000)

        if rc != 0:
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message=f"httpx exit code {rc}",
            )

        items = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input")
            if not url:
                continue
            items.append(
                {
                    "url": url,
                    "input": obj.get("input"),
                    "host": obj.get("host"),
                    "status_code": obj.get("status_code") or obj.get("status-code"),
                    "title": obj.get("title"),
                    "tech": obj.get("tech") or obj.get("technologies") or [],
                    "ips": obj.get("a") or obj.get("ip") or [],
                    "tls": obj.get("tls") or obj.get("tls-grab"),
                    "scheme": obj.get("scheme"),
                    "port": obj.get("port"),
                    "content_length": obj.get("content_length")
                    or obj.get("content-length"),
                }
            )
        return RunnerOutput(succeeded=True, items=items, raw_stdout=out, duration_ms=dt)


# --- naabu (port scan) -------------------------------------------------


class NaabuRunner(Runner):
    """ProjectDiscovery naabu. JSON output, one (host, port) per line."""

    kind = "port_scan"

    def __init__(self, binary: str = "naabu", extra_args: Iterable[str] = ()):
        self.binary = binary
        self.extra_args = list(extra_args)

    async def run(self, target, parameters=None):
        params = parameters or {}
        ports = params.get("ports", "top-100")
        cmd = [
            self.binary,
            "-host",
            target,
            "-silent",
            "-json",
            "-no-color",
            "-p",
            str(ports),
        ] + list(self.extra_args)
        if params.get("rate"):
            cmd += ["-rate", str(params["rate"])]
        import time as _t

        t0 = _t.perf_counter()
        try:
            rc, out, err = await _exec(
                cmd, timeout=float(params.get("timeout", 600))
            )
        except FileNotFoundError as e:
            return RunnerOutput(succeeded=False, error_message=str(e))
        dt = int((_t.perf_counter() - t0) * 1000)
        if rc != 0:
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message=f"naabu exit code {rc}",
            )
        items = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host") or obj.get("ip")
            port = obj.get("port")
            if host and port:
                items.append(
                    {
                        "host": host,
                        "port": int(port),
                        "protocol": obj.get("protocol", "tcp"),
                    }
                )
        return RunnerOutput(succeeded=True, items=items, raw_stdout=out, duration_ms=dt)


# --- DNS refresh (pure Python) -----------------------------------------


class DnsRefreshRunner(Runner):
    """Resolves A/AAAA/MX/NS/TXT and SPF/DMARC for a domain via dnspython."""

    kind = "dns_refresh"

    async def run(self, target, parameters=None):
        try:
            import dns.resolver  # type: ignore
            import dns.exception  # type: ignore
        except ImportError:
            return RunnerOutput(
                succeeded=False, error_message="dnspython is not installed"
            )

        resolver = dns.resolver.Resolver()
        resolver.lifetime = float((parameters or {}).get("timeout", 5))

        out: dict[str, Any] = {"domain": target}

        async def _resolve(name: str, rtype: str) -> list[str]:
            try:
                answers = await asyncio.to_thread(
                    resolver.resolve, name, rtype, raise_on_no_answer=False
                )
                return [r.to_text().strip('"') for r in answers]
            except (dns.exception.DNSException, Exception):  # noqa: BLE001
                return []

        out["a"] = await _resolve(target, "A")
        out["aaaa"] = await _resolve(target, "AAAA")
        out["mx"] = await _resolve(target, "MX")
        out["ns"] = await _resolve(target, "NS")
        txts = await _resolve(target, "TXT")
        out["txt"] = txts

        spf = next(
            (
                t
                for t in txts
                if t.lower().startswith("v=spf1") or "v=spf1" in t.lower()
            ),
            None,
        )
        out["spf"] = spf

        dmarc_txts = await _resolve(f"_dmarc.{target}", "TXT")
        dmarc = next(
            (t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None
        )
        out["dmarc"] = dmarc

        return RunnerOutput(succeeded=True, items=[out])


# --- WHOIS refresh -----------------------------------------------------


class WhoisRefreshRunner(Runner):
    kind = "whois_refresh"

    async def run(self, target, parameters=None):
        try:
            import whois  # type: ignore
        except ImportError:
            return RunnerOutput(
                succeeded=False, error_message="python-whois is not installed"
            )

        try:
            data = await asyncio.to_thread(whois.whois, target)
        except Exception as e:  # noqa: BLE001
            return RunnerOutput(succeeded=False, error_message=str(e)[:300])

        def _flat(v):
            if isinstance(v, list) and v:
                return v[0]
            return v

        item = {
            "domain": target,
            "registrar": _flat(data.get("registrar")),
            "creation_date": str(_flat(data.get("creation_date")) or ""),
            "expiration_date": str(_flat(data.get("expiration_date")) or ""),
            "name_servers": list({(ns or "").lower() for ns in (data.get("name_servers") or [])}),
            "status": data.get("status"),
            "raw": dict(data) if hasattr(data, "items") else None,
        }
        return RunnerOutput(succeeded=True, items=[item])


# --- Nuclei (vulnerability templates) ----------------------------------


class NucleiRunner(Runner):
    """ProjectDiscovery nuclei. JSON-lines output (`-jsonl`)."""

    kind = "vuln_scan"

    def __init__(self, binary: str = "nuclei", extra_args: Iterable[str] = ()):
        self.binary = binary
        self.extra_args = list(extra_args)

    async def run(self, target, parameters=None):
        params = parameters or {}
        cmd = [
            self.binary,
            "-target",
            target,
            "-silent",
            "-jsonl",
            "-disable-update-check",
            "-no-color",
        ]
        if templates := params.get("templates"):
            cmd += ["-t", str(templates)]
        if severity := params.get("severity"):
            cmd += ["-severity", str(severity)]
        if rate := params.get("rate"):
            cmd += ["-rl", str(rate)]
        cmd += list(self.extra_args)

        import time as _t

        t0 = _t.perf_counter()
        try:
            rc, out, err = await _exec(
                cmd, timeout=float(params.get("timeout", 900))
            )
        except FileNotFoundError as e:
            return RunnerOutput(succeeded=False, error_message=str(e))
        dt = int((_t.perf_counter() - t0) * 1000)

        # nuclei exits non-zero when nothing matches but stdout is empty.
        # Treat empty stdout + rc!=0 as success-with-no-findings.
        if rc != 0 and out.strip():
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message=f"nuclei exit code {rc}",
            )
        items: list[dict[str, Any]] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info") or {}
            classification = info.get("classification") or {}
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            cwe_ids = classification.get("cwe-id") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            cvss_metrics = classification.get("cvss-score") or classification.get(
                "cvss_score"
            )
            try:
                cvss_score = float(cvss_metrics) if cvss_metrics is not None else None
            except (TypeError, ValueError):
                cvss_score = None
            items.append(
                {
                    "rule_id": obj.get("template-id") or obj.get("template_id") or "unknown",
                    "name": info.get("name") or "Nuclei finding",
                    "description": info.get("description"),
                    "severity": (info.get("severity") or "info").lower(),
                    "tags": info.get("tags") or [],
                    "matched_at": obj.get("matched-at") or obj.get("matched_at"),
                    "host": obj.get("host"),
                    "url": obj.get("url"),
                    "cve_ids": [str(c).upper() for c in cve_ids],
                    "cwe_ids": [str(c).upper() for c in cwe_ids],
                    "cvss_score": cvss_score,
                    "references": info.get("reference") or [],
                    "raw": obj,
                }
            )
        return RunnerOutput(succeeded=True, items=items, raw_stdout=out, duration_ms=dt)


# --- Nmap service-version detection -----------------------------------


class NmapServiceVersionRunner(Runner):
    """Nmap with -sV (service detection). XML output parsed in stdlib."""

    kind = "service_version"

    def __init__(self, binary: str = "nmap", extra_args: Iterable[str] = ()):
        self.binary = binary
        self.extra_args = list(extra_args)

    async def run(self, target, parameters=None):
        params = parameters or {}
        ports = str(params.get("ports", "22,80,443,8080,8443,3389,5900"))
        cmd = [
            self.binary,
            "-sV",
            "-Pn",
            "-T4",
            "-oX",
            "-",
            "-p",
            ports,
            target,
        ] + list(self.extra_args)

        import time as _t

        t0 = _t.perf_counter()
        try:
            rc, out, err = await _exec(
                cmd, timeout=float(params.get("timeout", 600))
            )
        except FileNotFoundError as e:
            return RunnerOutput(succeeded=False, error_message=str(e))
        dt = int((_t.perf_counter() - t0) * 1000)
        if rc != 0:
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message=f"nmap exit code {rc}",
            )

        items = _parse_nmap_xml(out, target)
        return RunnerOutput(succeeded=True, items=items, raw_stdout=out, duration_ms=dt)


def _parse_nmap_xml(xml: str, target: str) -> list[dict[str, Any]]:
    """Pull (host, port, protocol, service, product, version) tuples
    from nmap XML output. Audit B7 — defusedxml for XXE safety.
    """
    import defusedxml.ElementTree as ET  # type: ignore

    items: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return items
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else target
        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service = port.find("service")
            items.append(
                {
                    "host": host_addr,
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                }
            )
    return items


# --- testssl.sh TLS posture audit -------------------------------------


class TestSslRunner(Runner):
    """testssl.sh in JSON mode. Parses the ``--jsonfile-pretty`` shape.

    Maps each finding to an exposure category:
        - severity HIGH/CRITICAL  → ``weak_crypto`` / ``vulnerability``
        - any cert finding        → ``expired_cert`` / ``self_signed_cert`` if matched
    """

    kind = "tls_audit"

    def __init__(self, binary: str = "testssl.sh", extra_args: Iterable[str] = ()):
        self.binary = binary
        self.extra_args = list(extra_args)

    async def run(self, target, parameters=None):
        params = parameters or {}
        # testssl.sh writes JSON to a file. Use stdout-only minimal output via
        # `--quiet --jsonfile-pretty=/dev/stdout` if supported; fall back to
        # `--quiet --jsonfile=/dev/stdout`. Behavior varies — accept both.
        cmd = [
            self.binary,
            "--quiet",
            "--color",
            "0",
            "--jsonfile",
            "/dev/stdout",
            target,
        ] + list(self.extra_args)
        import time as _t

        t0 = _t.perf_counter()
        try:
            rc, out, err = await _exec(
                cmd, timeout=float(params.get("timeout", 900))
            )
        except FileNotFoundError as e:
            return RunnerOutput(succeeded=False, error_message=str(e))
        dt = int((_t.perf_counter() - t0) * 1000)
        if rc != 0 and not out.strip():
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message=f"testssl.sh exit code {rc}",
            )
        try:
            obj = json.loads(out)
        except json.JSONDecodeError:
            return RunnerOutput(
                succeeded=False,
                raw_stdout=out,
                raw_stderr=err,
                duration_ms=dt,
                error_message="testssl.sh did not produce valid JSON",
            )
        scan_results = obj if isinstance(obj, list) else obj.get("scanResult", [])
        items: list[dict[str, Any]] = []
        for entry in scan_results:
            findings: list[dict[str, Any]] = []
            for sect_name, sect_value in entry.items():
                if not isinstance(sect_value, list):
                    continue
                for f in sect_value:
                    sev = (f.get("severity") or "INFO").lower()
                    if sev in ("ok", "info", "low"):
                        # only collect non-trivial issues
                        continue
                    findings.append(
                        {
                            "id": f.get("id"),
                            "section": sect_name,
                            "severity": sev,
                            "finding": f.get("finding"),
                            "ip": entry.get("targetHost") or entry.get("ip"),
                            "port": entry.get("port"),
                            "cve": f.get("cve"),
                            "cwe": f.get("cwe"),
                        }
                    )
            for f in findings:
                items.append(f)
        return RunnerOutput(succeeded=True, items=items, raw_stdout=out, duration_ms=dt)


# --- Registry ----------------------------------------------------------


_REGISTRY: dict[str, Runner] = {
    "subdomain_enum": SubfinderRunner(),
    "httpx_probe": HttpxRunner(),
    "port_scan": NaabuRunner(),
    "dns_refresh": DnsRefreshRunner(),
    "whois_refresh": WhoisRefreshRunner(),
    "vuln_scan": NucleiRunner(),
    "service_version": NmapServiceVersionRunner(),
    "tls_audit": TestSslRunner(),
}


def get_runner_registry() -> dict[str, Runner]:
    return _REGISTRY


def set_runner_registry(new: dict[str, Runner]) -> None:
    """Replace the global registry. Used by tests for fake runners."""
    global _REGISTRY
    _REGISTRY = new


def reset_runner_registry() -> None:
    set_runner_registry(
        {
            "subdomain_enum": SubfinderRunner(),
            "httpx_probe": HttpxRunner(),
            "port_scan": NaabuRunner(),
            "dns_refresh": DnsRefreshRunner(),
            "whois_refresh": WhoisRefreshRunner(),
            "vuln_scan": NucleiRunner(),
            "service_version": NmapServiceVersionRunner(),
            "tls_audit": TestSslRunner(),
        }
    )


__all__ = [
    "Runner",
    "RunnerOutput",
    "SubfinderRunner",
    "HttpxRunner",
    "NaabuRunner",
    "DnsRefreshRunner",
    "WhoisRefreshRunner",
    "NucleiRunner",
    "NmapServiceVersionRunner",
    "TestSslRunner",
    "get_runner_registry",
    "set_runner_registry",
    "reset_runner_registry",
]
