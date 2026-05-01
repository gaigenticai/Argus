#!/usr/bin/env bash
# scripts/bridge_host.sh — launch bridge.py as a HOST-NATIVE python process.
#
# Why this exists: on macOS / Apple Silicon the ``claude`` CLI is a
# Mach-O arm64 binary (Anthropic's v2.x installer). It cannot exec
# inside a Linux container, so the docker-compose ``bridge`` profile
# fails with "Exec format error" when launched on a Mac host. The
# clean alternative is to run the bridge worker directly on the
# operator's host: it finds ``claude`` via PATH, dials Redis on
# 127.0.0.1:6379 (already exposed by docker compose), and drains the
# shared ai_tasks queue. Brain-side callers are unchanged.
#
# Usage:
#   ./scripts/bridge_host.sh start    # launch + daemonize
#   ./scripts/bridge_host.sh stop     # kill a running host bridge
#   ./scripts/bridge_host.sh status   # report running state
#
# start.sh invokes ``start`` automatically when the operator picks the
# Claude Code bridge LLM option on Darwin.

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PID_FILE="logs/bridge-host.pid"
LOG_FILE="logs/bridge-host.log"
READY_FILE="logs/bridge-host.ready"
VENV_PY="$REPO_ROOT/.venv/bin/python3"

mkdir -p logs

_cmd="${1:-status}"

_require_deps() {
  # The host venv exists if the operator ever ran the legacy start.sh
  # python flow; otherwise this script creates a tiny one.
  if [[ ! -x "$VENV_PY" ]]; then
    echo "[bridge-host] creating .venv (one-time)"
    python3 -m venv "$REPO_ROOT/.venv"
  fi
  if ! "$VENV_PY" -c "import redis" 2>/dev/null; then
    echo "[bridge-host] installing redis client into .venv"
    "$VENV_PY" -m pip install --quiet 'redis>=5.2.0'
  fi
  if ! command -v claude >/dev/null 2>&1; then
    echo "[bridge-host] FATAL: 'claude' CLI not on PATH." >&2
    echo "  Install Claude Code from https://claude.com/claude-code first." >&2
    exit 10
  fi
}

_is_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

_start() {
  if _is_running; then
    echo "[bridge-host] already running (PID $(cat "$PID_FILE"))"
    return 0
  fi
  _require_deps

  # Compose exposes redis on 127.0.0.1:6379 by default. The brain-side
  # caller (BridgeLLM) talks to the same redis via the compose-internal
  # hostname ``redis`` — both routes hit the same instance, so the
  # worker (here) and the API (in container) share the same queue.
  local redis_password
  redis_password="$(grep -E '^ARGUS_REDIS_PASSWORD=' "$REPO_ROOT/.env" 2>/dev/null | cut -d= -f2- || true)"

  rm -f "$READY_FILE"

  # Pick the redis port the caller advertised (start.sh exports
  # ARGUS_HOST_REDIS_PORT after auto-allocation). Falls back to 6379
  # for legacy callers / direct manual launches.
  local bridge_redis_port="${ARGUS_HOST_REDIS_PORT:-${REDIS_PORT:-6379}}"

  REDIS_HOST=127.0.0.1 \
  REDIS_PORT="$bridge_redis_port" \
  REDIS_PASSWORD="$redis_password" \
  BRIDGE_MODE=host-native \
  BRIDGE_READY_MARKER="$READY_FILE" \
  nohup "$VENV_PY" "$REPO_ROOT/bridge/bridge.py" \
      >"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "[bridge-host] started PID $(cat "$PID_FILE") — log $LOG_FILE"

  # Wait up to 10s for the worker to reach its ready state. The marker
  # is touched after redis ping + claude CLI resolution succeed.
  for _ in $(seq 1 10); do
    if [[ -f "$READY_FILE" ]]; then
      echo "[bridge-host] ready"
      return 0
    fi
    if ! _is_running; then
      echo "[bridge-host] FATAL: worker exited before becoming ready" >&2
      tail -n 20 "$LOG_FILE" >&2
      return 1
    fi
    sleep 1
  done
  echo "[bridge-host] WARN: ready marker not seen in 10s; check $LOG_FILE"
}

_stop() {
  if ! _is_running; then
    echo "[bridge-host] not running"
    rm -f "$PID_FILE" "$READY_FILE"
    return 0
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  echo "[bridge-host] stopping PID $pid"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 10); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE" "$READY_FILE"
  echo "[bridge-host] stopped"
}

_status() {
  if _is_running; then
    echo "[bridge-host] running (PID $(cat "$PID_FILE"))"
    [[ -f "$READY_FILE" ]] && echo "[bridge-host] ready" || echo "[bridge-host] starting up"
  else
    echo "[bridge-host] not running"
  fi
}

case "$_cmd" in
  start)  _start ;;
  stop)   _stop ;;
  status) _status ;;
  restart) _stop; _start ;;
  *) echo "usage: $0 {start|stop|status|restart}" >&2; exit 2 ;;
esac
