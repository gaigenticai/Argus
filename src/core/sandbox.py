"""Sandboxed subprocess execution for OSS binary runners.

Argus shells out to nuclei, subfinder, naabu, nmap, httpx, and
testssl. The Gemini audit (G1) flagged that these calls had no real
isolation — a malicious target name or template injection could
escape into the runner's own filesystem. This module wraps every
binary invocation in `bwrap` (Bubblewrap) on Linux with:

    * a read-only bind of /usr, /etc/ssl, /etc/resolv.conf
    * a private /tmp inside the sandbox
    * a fresh PID + IPC + UTS namespace
    * `--unshare-user` for unprivileged isolation
    * an explicit working directory the binary cannot escape
    * inherited network namespace by default (EASM tools must reach
      their targets) — callers that don't need network pass
      ``share_net=False`` to drop networking entirely

Falls back gracefully on hosts without bwrap installed: log a WARNING
once at startup, run the binary directly, and let the operator know
sandboxing is degraded. We do NOT silently disable sandboxing — the
scheduler's FeedHealth surface picks up the warning so the dashboard
shows "sandbox unavailable" instead of pretending isolation works.

Why bwrap and not Docker / gVisor:
    * Docker-in-Docker requires privileged access to /var/run/docker.sock
      and an extra container per call; bwrap is one syscall.
    * gVisor (runsc) has the same isolation properties but adds ~50ms
      cold-start per process; bwrap adds ~1ms.
    * AppArmor / seccomp profiles via systemd are operator-specific
      and not portable across distros.

For Mac / Windows hosts (dev), the bwrap binary is absent. We detect
this and run the command unsandboxed with a one-time warning. CI on
Linux always has bwrap.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Sequence


logger = logging.getLogger(__name__)


_BWRAP_BINARY: str | None = None
_BWRAP_LOOKUP_DONE = False
_BWRAP_WARNING_LOGGED = False


def _detect_bwrap() -> str | None:
    """One-shot bwrap binary lookup, cached."""
    global _BWRAP_BINARY, _BWRAP_LOOKUP_DONE
    if _BWRAP_LOOKUP_DONE:
        return _BWRAP_BINARY
    _BWRAP_LOOKUP_DONE = True
    candidate = shutil.which("bwrap")
    _BWRAP_BINARY = candidate
    return candidate


def sandbox_available() -> bool:
    """True iff bwrap is installed on this host. Routes / health
    checks expose this so the dashboard can show whether subprocess
    isolation is real or degraded."""
    return _detect_bwrap() is not None


@dataclass
class SandboxPolicy:
    """Configures how `bwrap` is invoked for a single subprocess call.

    Defaults are set for the EASM use case: read-only system paths,
    private tmp, no host home, network on. Tools that read templates
    or rule files (nuclei, yara) pass ``readonly_binds`` to expose
    the dataset directory.
    """

    share_net: bool = True
    share_dev: bool = False
    readonly_binds: tuple[str, ...] = ()
    writable_tmp: bool = True
    chdir: str | None = None
    proc: bool = True
    extra_args: tuple[str, ...] = ()
    timeout_seconds: float = 600.0


def _build_bwrap_argv(
    bwrap: str,
    cmd: Sequence[str],
    policy: SandboxPolicy,
) -> list[str]:
    argv: list[str] = [
        bwrap,
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--clearenv",
        # Minimal env passthrough — PATH and LANG only. Anything tool-
        # specific (e.g. ARGUS_INT_NUCLEI_TEMPLATES) should be expanded
        # into argv by the caller, not leaked through env.
        "--setenv", "PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "--setenv", "LANG", os.environ.get("LANG", "C.UTF-8"),
        "--setenv", "HOME", "/sandbox-home",
        # Read-only OS image. We bind the host's standard system paths
        # rather than re-creating them — bwrap's --ro-bind is cheap and
        # the binary needs at least libc + ssl certs to do its job.
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
        "--ro-bind-try", "/etc/ssl", "/etc/ssl",
        "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
        "--ro-bind-try", "/etc/pki", "/etc/pki",
        "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
        # Per-call writable home (fresh tmpfs, not bound to host).
        "--tmpfs", "/sandbox-home",
    ]

    if policy.writable_tmp:
        argv += ["--tmpfs", "/tmp"]
    if policy.proc:
        argv += ["--proc", "/proc"]
    if not policy.share_net:
        argv += ["--unshare-net"]
    if not policy.share_dev:
        argv += ["--dev", "/dev"]
    else:
        argv += ["--dev-bind", "/dev", "/dev"]

    for path in policy.readonly_binds:
        if not path:
            continue
        argv += ["--ro-bind-try", path, path]

    if policy.chdir:
        argv += ["--chdir", policy.chdir]

    argv += list(policy.extra_args)
    argv += ["--"]
    argv += list(cmd)
    return argv


async def run_sandboxed(
    cmd: Sequence[str],
    *,
    policy: SandboxPolicy | None = None,
    stdin: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    """Run ``cmd`` under bwrap (when available) and return
    ``(returncode, stdout, stderr)``.

    Raises ``FileNotFoundError`` if the binary itself isn't on PATH —
    that's a deployment misconfiguration, not a sandbox failure.
    Raises ``asyncio.TimeoutError`` when the call exceeds
    ``policy.timeout_seconds``.

    On hosts without bwrap (typically dev macOS), we log the warning
    once and run the command directly. The first time this happens
    in a process is a loud WARNING; subsequent calls are silent.
    """
    if not cmd:
        raise ValueError("cmd must not be empty")

    policy = policy or SandboxPolicy()

    real_path = shutil.which(cmd[0])
    if real_path is None:
        raise FileNotFoundError(
            f"Required binary {cmd[0]!r} not on PATH. "
            f"Install it in the runtime image."
        )

    bwrap = _detect_bwrap()
    if bwrap is None:
        global _BWRAP_WARNING_LOGGED
        if not _BWRAP_WARNING_LOGGED:
            logger.warning(
                "sandbox: bwrap not installed on this host. "
                "Subprocess isolation is degraded — install "
                "`bubblewrap` to enforce read-only bind mounts and "
                "namespaced PID/IPC/UTS. Falling back to direct "
                "subprocess execution.",
            )
            _BWRAP_WARNING_LOGGED = True
        argv = list(cmd)
    else:
        # bwrap needs an absolute path or the binary in the bound /usr;
        # passing the resolved path avoids ambiguity.
        argv = _build_bwrap_argv(
            bwrap, [real_path, *cmd[1:]], policy,
        )

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=stdin),
            timeout=policy.timeout_seconds,
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:  # noqa: BLE001
            # The kill handshake can race with normal exit.
            pass
        raise
    return proc.returncode or 0, out, err


__all__ = [
    "SandboxPolicy",
    "run_sandboxed",
    "sandbox_available",
]
