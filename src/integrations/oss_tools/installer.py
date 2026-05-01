"""Drive `docker compose --profile X up -d` from inside the api container.

The api container needs:

  1. The host's docker.sock mounted at ``/var/run/docker.sock`` so it
     can talk to the host docker daemon.
  2. The host project root mounted read-only at ``/app/host-project``
     so docker compose can read ``compose.optional.yml`` and the
     templated ``docker-compose.yml`` env interpolation.

Both mounts only matter on installs where the operator has flipped
``ARGUS_OSS_INSTALLER_ENABLED=true`` — the default is false, and the
installer fails closed with a clear admin-facing error so a
misconfigured deploy can't accidentally launch privileged subprocesses.

When the gate is open, ``install_selected`` runs the docker-compose
subprocess, captures stdout/stderr into the ``OssToolInstall`` row,
appends the chosen ``ARGUS_*_URL`` env vars to the host ``.env``, and
flips the row's state to ``installed``.

Failure modes are surfaced to the dashboard via the row's
``error_message`` + ``log_tail`` columns; nothing throws past the
caller. On success, the API process auto-reloads the env vars so the
matching connector starts working without a full container restart.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.oss_tool import OssToolInstall, OssToolState

from .catalog import OssTool, tool_by_name

logger = logging.getLogger(__name__)


# ── Config ─────────────────────────────────────────────────────────


_HOST_PROJECT_DEFAULT = "/app/host-project"
_DOCKER_COMPOSE_FILE = "docker-compose.yml"
_DOCKER_COMPOSE_OPTIONAL = "compose.optional.yml"
_DOCKER_TIMEOUT_SECONDS = 600     # docker pulls can be slow


def installer_enabled() -> bool:
    """Master gate. Off by default — operator must explicitly opt in
    by flipping ``ARGUS_OSS_INSTALLER_ENABLED=true`` in .env, which
    also requires that they've mounted /var/run/docker.sock + the
    host project dir into the api container."""
    val = (os.environ.get("ARGUS_OSS_INSTALLER_ENABLED") or "") \
        .strip().lower()
    return val in {"true", "1", "yes", "on"}


def host_project_path() -> Path:
    raw = (os.environ.get("ARGUS_OSS_INSTALLER_HOST_PROJECT")
           or _HOST_PROJECT_DEFAULT).strip()
    return Path(raw)


def env_file_path() -> Path:
    """Path to the host .env that docker-compose reads. Inside the api
    container this is the mounted host project's .env."""
    return host_project_path() / ".env"


# ── Sanity preflight ──────────────────────────────────────────────


def preflight_status() -> dict[str, object]:
    """What the dashboard renders on the onboarding screen so the admin
    can see why the installer is or isn't ready before they hit
    Install."""
    proj = host_project_path()
    docker_sock = Path("/var/run/docker.sock")
    issues: list[str] = []
    if not installer_enabled():
        issues.append(
            "ARGUS_OSS_INSTALLER_ENABLED=true is not set; the installer "
            "will refuse to start subprocesses until it is."
        )
    if not docker_sock.exists():
        issues.append(
            f"/var/run/docker.sock is not mounted into the api "
            f"container; mount the host docker socket so we can drive "
            f"docker compose."
        )
    if not proj.exists():
        issues.append(
            f"Host project dir not mounted at {proj}; the installer "
            f"can't read compose.optional.yml without it."
        )
    elif not (proj / _DOCKER_COMPOSE_OPTIONAL).exists():
        issues.append(
            f"{proj / _DOCKER_COMPOSE_OPTIONAL} not found — "
            f"compose.optional.yml is the install vehicle."
        )
    return {
        "enabled": installer_enabled(),
        "host_project": str(proj),
        "host_project_mounted": proj.exists(),
        "docker_sock_mounted": docker_sock.exists(),
        "ready": not issues,
        "issues": issues,
    }


# ── Per-tool DB helpers ───────────────────────────────────────────


async def _row_for(session: AsyncSession, tool: OssTool) -> OssToolInstall:
    """Get-or-create the per-tool row with default state ``disabled``."""
    res = await session.execute(
        select(OssToolInstall).where(OssToolInstall.tool_name == tool.name)
    )
    row = res.scalar_one_or_none()
    if row is None:
        row = OssToolInstall(
            tool_name=tool.name, state=OssToolState.DISABLED.value,
        )
        session.add(row)
        await session.flush()
    return row


async def upsert_state(
    session: AsyncSession,
    tool: OssTool,
    *,
    state: OssToolState,
    requested_by_user_id=None,
    error_message: str | None = None,
    log_tail: str | None = None,
    installed_at: datetime | None = None,
) -> OssToolInstall:
    row = await _row_for(session, tool)
    row.state = state.value
    if requested_by_user_id is not None:
        row.requested_by_user_id = requested_by_user_id
    if error_message is not None:
        row.error_message = error_message[:4000] if error_message else None
    if log_tail is not None:
        row.log_tail = log_tail[-8000:]   # cap to keep the row small
    if state == OssToolState.INSTALLING:
        row.last_attempt_at = datetime.now(timezone.utc)
    if installed_at is not None:
        row.installed_at = installed_at
    return row


async def list_states(session: AsyncSession) -> list[dict]:
    """Per-tool current state for the dashboard. Tools that don't have
    a row yet show as ``disabled``."""
    rows = (await session.execute(select(OssToolInstall))).scalars().all()
    by_name = {r.tool_name: r for r in rows}
    out: list[dict] = []
    from .catalog import list_catalog
    for t in list_catalog():
        row = by_name.get(t.name)
        out.append({
            "tool_name": t.name,
            "state": row.state if row else OssToolState.DISABLED.value,
            "installed_at": (
                row.installed_at.isoformat() if row and row.installed_at else None
            ),
            "last_attempt_at": (
                row.last_attempt_at.isoformat()
                if row and row.last_attempt_at else None
            ),
            "error_message": row.error_message if row else None,
        })
    return out


# ── docker-compose driver ─────────────────────────────────────────


async def _run_compose(
    profiles: Iterable[str],
    *,
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run ``docker compose -f docker-compose.yml -f compose.optional.yml
    --profile <p>... up -d``. Returns (returncode, stdout, stderr)."""
    proj = host_project_path()
    profile_args: list[str] = []
    for p in profiles:
        profile_args.extend(["--profile", p])

    cmd = [
        "docker", "compose",
        "-f", str(proj / _DOCKER_COMPOSE_FILE),
        "-f", str(proj / _DOCKER_COMPOSE_OPTIONAL),
        *profile_args,
        "up", "-d",
    ]
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    logger.info("[oss-installer] running: %s", " ".join(shlex.quote(c) for c in cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(proj),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_DOCKER_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"docker compose timed out after {_DOCKER_TIMEOUT_SECONDS}s"
    return (
        proc.returncode or 0,
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
    )


# ── .env writer ────────────────────────────────────────────────────


def update_env_file(env_vars: dict[str, str]) -> None:
    """Append-or-replace ARGUS_*=value lines in the host .env file.

    We rewrite the file rather than append-only so that re-running the
    installer doesn't pile up duplicate lines for the same key.
    """
    path = env_file_path()
    if not path.exists():
        return
    existing = path.read_text(encoding="utf-8").splitlines()
    keys_seen = set()
    out: list[str] = []
    for line in existing:
        stripped = line.strip()
        if (not stripped) or stripped.startswith("#"):
            out.append(line)
            continue
        if "=" not in line:
            out.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in env_vars:
            out.append(f"{key}={env_vars[key]}")
            keys_seen.add(key)
        else:
            out.append(line)
    for key, val in env_vars.items():
        if key not in keys_seen:
            out.append(f"{key}={val}")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    # Also update the running process env so the connectors pick up
    # the new values without a full container restart.
    for key, val in env_vars.items():
        os.environ[key] = val


# ── Top-level driver ──────────────────────────────────────────────


async def install_selected(
    session_factory,
    *,
    tool_names: list[str],
    requested_by_user_id=None,
) -> list[dict]:
    """Install the named tools. Idempotent: tools that are already
    ``installed`` skip straight to success.

    Runs as a single ``docker compose up -d`` for all selected tools so
    pulls + container starts happen in parallel. Per-tool state is
    written to ``oss_tool_installs`` rows for the dashboard to render.
    """
    from .catalog import tool_by_name

    if not installer_enabled():
        # Mark every requested tool failed with the same operator-facing
        # message; the dashboard preflight already shows the issue.
        async with session_factory() as session:
            for name in tool_names:
                t = tool_by_name(name)
                if t is None:
                    continue
                await upsert_state(
                    session, t,
                    state=OssToolState.FAILED,
                    requested_by_user_id=requested_by_user_id,
                    error_message=(
                        "OSS installer is disabled. Set "
                        "ARGUS_OSS_INSTALLER_ENABLED=true in .env, mount "
                        "/var/run/docker.sock + the host project dir "
                        "into the api container, and retry."
                    ),
                )
            await session.commit()
        return await _final_states(session_factory, tool_names)

    selected_tools: list[OssTool] = []
    for name in tool_names:
        t = tool_by_name(name)
        if t is None:
            logger.warning("[oss-installer] unknown tool %r — skipped", name)
            continue
        selected_tools.append(t)
    if not selected_tools:
        return []

    # Phase 1 — flip every selected row to INSTALLING so the dashboard
    # can show progress while docker pulls run.
    async with session_factory() as session:
        for t in selected_tools:
            await upsert_state(
                session, t,
                state=OssToolState.INSTALLING,
                requested_by_user_id=requested_by_user_id,
            )
        await session.commit()

    # Phase 2 — drive docker compose for every profile in one shot so
    # multi-tool installs share a single image-pull pipeline.
    profiles = [t.compose_profile for t in selected_tools]
    rc, stdout, stderr = await _run_compose(profiles)

    # Phase 3 — record per-tool result. We don't have per-profile rc
    # from a single ``up -d`` command, so any failure marks every
    # selected tool as failed with the captured stderr; the operator
    # can re-run the install once they fix the underlying issue.
    async with session_factory() as session:
        if rc == 0:
            # Update env in one pass so connectors pick up all the
            # newly-reachable services together.
            combined: dict[str, str] = {}
            for t in selected_tools:
                combined.update(t.env_vars)
            try:
                update_env_file(combined)
            except OSError as exc:
                logger.warning(
                    "[oss-installer] failed to update host .env: %s", exc,
                )
            for t in selected_tools:
                await upsert_state(
                    session, t,
                    state=OssToolState.INSTALLED,
                    installed_at=datetime.now(timezone.utc),
                    log_tail=(stdout + "\n" + stderr).strip(),
                )
        else:
            tail = (stderr or stdout or "").strip()
            for t in selected_tools:
                await upsert_state(
                    session, t,
                    state=OssToolState.FAILED,
                    error_message=(
                        f"docker compose returned {rc}: "
                        + tail.splitlines()[-1] if tail else f"rc={rc}"
                    ),
                    log_tail=tail,
                )
        await session.commit()

    return await _final_states(session_factory, [t.name for t in selected_tools])


async def _final_states(session_factory, names: list[str]) -> list[dict]:
    async with session_factory() as session:
        rows = (await session.execute(
            select(OssToolInstall).where(OssToolInstall.tool_name.in_(names))
        )).scalars().all()
        return [
            {
                "tool_name": r.tool_name,
                "state": r.state,
                "installed_at": (
                    r.installed_at.isoformat() if r.installed_at else None
                ),
                "error_message": r.error_message,
            }
            for r in rows
        ]


async def disable_unselected(
    session: AsyncSession,
    *,
    selected: list[str],
) -> None:
    """When the admin completes onboarding, every tool they DIDN'T
    select is recorded as DISABLED so the dashboard knows the
    onboarding step is done and doesn't re-prompt."""
    from .catalog import list_catalog

    selected_set = set(selected)
    for t in list_catalog():
        if t.name in selected_set:
            continue
        await upsert_state(session, t, state=OssToolState.DISABLED)


async def onboarding_complete(session: AsyncSession) -> bool:
    """Return True iff every catalog tool has at least one row (any
    state). The admin onboarding flow writes the full set on submit;
    if every tool has a row we don't show the wizard again."""
    from .catalog import list_catalog
    rows = (await session.execute(select(OssToolInstall))).scalars().all()
    seen = {r.tool_name for r in rows}
    return all(t.name in seen for t in list_catalog())
