#!/usr/bin/env bash
# Argus — single-command launcher.
#
#   ./start.sh                  # interactive boot — prompts for LLM + seed mode
#                               # (defaults are pre-filled from .env so Enter
#                               # keeps the previous choice)
#   ./start.sh --yes            # non-interactive: accept saved defaults
#   ./start.sh --reconfigure    # alias for plain ./start.sh (kept for muscle memory)
#   ./start.sh stop             # docker compose down (keeps volumes)
#   ./start.sh wipe             # docker compose down -v (DESTROYS data)
#   ./start.sh --no-open        # don't auto-open the browser
#   ./start.sh --seed realistic # override seed mode (minimal|realistic|none)
#   ./start.sh --with caldera   # bring up opt-in OSS sidekicks alongside
#                                  Argus. Comma-separated. Names map to
#                                  profiles in compose.optional.yml:
#                                    caldera     → MITRE Caldera 5.x
#                                    shuffle     → Shuffle SOAR
#                                    velociraptor → Velociraptor IR
#                                    misp        → MISP threat-sharing
#                                  Each ``--with NAME`` also fills the
#                                  matching ARGUS_*_URL env var so the
#                                  connector finds the in-network host.
#
# Idempotent: re-running with no flags brings up the existing stack
# without re-prompting.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# --- pretty output ---------------------------------------------------

if [ -t 1 ]; then
  R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'
  C=$'\033[0;36m'; B=$'\033[1m';   D=$'\033[2m';   NC=$'\033[0m'
else
  R=''; G=''; Y=''; C=''; B=''; D=''; NC=''
fi
log()  { printf "${G}[+]${NC} %s\n" "$1"; }
warn() { printf "${Y}[!]${NC} %s\n" "$1"; }
err()  { printf "${R}[x]${NC} %s\n" "$1" >&2; }
hdr()  { printf "\n${B}${C}== %s ==${NC}\n" "$1"; }
ask()  { printf "${B}${C}? ${NC}${B}%s${NC}" "$1"; }

# --- arg parsing -----------------------------------------------------

NO_OPEN=0
NO_PROMPT=0
SEED_OVERRIDE=""
SUBCMD=""
EXTRA_PROFILES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reconfigure)  shift ;;            # legacy no-op — every run reconfigures
    --yes|-y)       NO_PROMPT=1; shift ;;
    --no-open)      NO_OPEN=1; shift ;;
    --seed)         SEED_OVERRIDE="$2"; shift 2 ;;
    --seed=*)       SEED_OVERRIDE="${1#*=}"; shift ;;
    --with)         EXTRA_PROFILES="$2"; shift 2 ;;
    --with=*)       EXTRA_PROFILES="${1#*=}"; shift ;;
    stop|wipe|logs|status) SUBCMD="$1"; shift ;;
    -h|--help)
      # Print the leading comment block (the file header) as the
      # canonical help text. Stop at the first blank-after-comments line
      # so we don't dump shell code into the user's terminal.
      awk '
        NR==1 { next }
        /^#/ { sub(/^# ?/, ""); print; next }
        /^$/ && NR>2 { exit }
      ' "$0"
      exit 0 ;;
    *) err "unknown option: $1"; exit 2 ;;
  esac
done

# --- subcommands -----------------------------------------------------

# Compose interpolates ``${MEILI_MASTER_KEY:?...}`` etc. against the
# combined env. ``stop`` / ``logs`` / ``status`` would otherwise abort
# on a freshly-cloned repo with no .env, so we touch the file and fill
# in any missing required secrets up front. The full wizard still runs
# only on a true first start.
ENV_FILE="$ROOT/.env"
ENV_EXAMPLE="$ROOT/.env.example"

case "$SUBCMD" in
  stop|wipe|logs|status)
    # Defer to the helpers below for env_set/env_get/ensure_required_secrets.
    SUBCMD_DEFERRED="$SUBCMD"
    SUBCMD=""
    ;;
esac

# --- preflight -------------------------------------------------------

hdr "Argus — Threat Intelligence Platform"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "'$1' is required but not installed. $2"
    exit 1
  fi
}

need_cmd docker      "Install Docker Desktop or your distro's docker engine."
need_cmd node        "Install Node.js 18+."
need_cmd npm         "Install npm (bundled with Node.js)."

# Docker compose v2 is invoked via 'docker compose' (no hyphen). Verify
# it works without leaking the user-facing version output.
if ! docker compose version >/dev/null 2>&1; then
  err "'docker compose' subcommand is required (Compose v2). Update Docker."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  err "docker daemon is not reachable. Start Docker Desktop / dockerd and retry."
  exit 1
fi

log "docker, node, npm — OK"

# --- env helpers -----------------------------------------------------

# Read a single value from .env. Returns empty string if absent.
#
# The trailing ``|| true`` matters: ``grep`` exits 1 when the key is
# missing, which combined with ``set -o pipefail`` + ``set -e`` would
# silently kill the entire script at the call site (bash 5 propagates
# errexit through ``var=$(cmd)``). We swallow that so a missing key is
# indistinguishable from a key with empty value — both yield "".
env_get() {
  local key="$1"
  [ -f "$ENV_FILE" ] || { printf ""; return 0; }
  grep -E "^${key}=" "$ENV_FILE" | head -n1 | cut -d= -f2- || true
}

# Set or replace a key in .env. Quotes the value as-is (no escaping
# beyond what the operator typed). Creates the file if missing.
env_set() {
  local key="$1" val="$2"
  touch "$ENV_FILE"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    # Use awk for in-place rewrite that survives values with /, &, etc.
    awk -v k="$key" -v v="$val" '
      BEGIN { found=0 }
      $0 ~ "^"k"=" { print k"="v; found=1; next }
      { print }
      END { if (!found) print k"="v }
    ' "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
  else
    printf "%s=%s\n" "$key" "$val" >> "$ENV_FILE"
  fi
}

# --- auto port allocation --------------------------------------------
#
# argus would otherwise pin host ports (5432, 6379, 8000, etc.). When
# another stack on the same machine already binds one of those, compose
# fails halfway through with "Bind for 127.0.0.1:X failed: port is
# already allocated" — leaving half-started containers behind. Instead
# of forcing the operator to stop the other stack, we probe each port
# and bump to the next free one if it's in use. Compose reads the
# ``ARGUS_HOST_*_PORT`` env vars; ``start.sh`` exports the values it
# settled on, the banner shows them, and the dashboard's API URL is
# derived from ``ARGUS_HOST_API_PORT`` so the browser can reach it.
#
# stop/wipe/logs/status don't allocate ports, so they skip this.

# Is the host port available? 0 = free, 1 = held.
port_free() {
  local port="$1"
  # Try IPv4 + IPv6 binds. ``nc -z`` returns 0 if it could connect,
  # which means *something is listening* — i.e. the port is NOT free.
  if command -v nc >/dev/null 2>&1; then
    if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then return 1; fi
  fi
  # ``lsof`` is available on macOS by default and catches more cases
  # than nc (sockets bound to 0.0.0.0, IPv6, raw, etc.). When neither
  # tool is present we optimistically say "free" and let compose error.
  if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q .; then
      return 1
    fi
  fi
  return 0
}

# Find a free TCP port starting at $1. Scans up to 200 ports forward.
# (Local declarations are split because ``set -u`` evaluates same-line
# arithmetic before the prior ``local name=value`` finishes binding.)
pick_free_port() {
  local desired="$1"
  local port="$1"
  local max=$((desired + 200))
  while [ "$port" -lt "$max" ]; do
    if port_free "$port"; then
      printf "%s" "$port"
      return 0
    fi
    port=$((port + 1))
  done
  err "could not find a free port near $desired (scanned $desired–$max)"
  return 1
}

# Track ports we've already handed out in this run so two services
# don't both grab the same next-free slot before either is bound.
ALLOCATED_PORTS=" "

# Wrapper: a port is "free" only if it's not in the allocated set AND
# the OS doesn't show it as listening.
port_available() {
  local port="$1"
  case "$ALLOCATED_PORTS" in
    *" $port "*) return 1 ;;
  esac
  port_free "$port"
}

pick_free_port_uniq() {
  local desired="$1"
  local port="$1"
  local max=$((desired + 200))
  while [ "$port" -lt "$max" ]; do
    if port_available "$port"; then
      printf "%s" "$port"
      return 0
    fi
    port=$((port + 1))
  done
  err "could not find a free port near $desired (scanned $desired–$max)"
  return 1
}

# Resolve and export ``ARGUS_HOST_<svc>_PORT`` for each service. The
# chosen values flow into compose (host-side of the port mapping) and
# into the rest of this script (banner, /health probe, dashboard
# NEXT_PUBLIC_API_URL). On a clean machine every default is free and
# nothing changes; with conflicts we bump up.
allocate_ports() {
  local svc default actual var
  for entry in \
      POSTGRES:5432 REDIS:6379 \
      TOR_SOCKS:9050 TOR_CTRL:9051 \
      MEILI:7700 OLLAMA:11434 \
      MINIO_S3:9000 MINIO_CONSOLE:9001 \
      VLLM:8001 \
      API:8000 DASHBOARD:3000; do
    svc="${entry%%:*}"
    default="${entry##*:}"
    var="ARGUS_HOST_${svc}_PORT"
    actual=""
    eval "actual=\${$var:-}"
    if [ -n "$actual" ] && port_available "$actual"; then
      :
    else
      actual="$(pick_free_port_uniq "$default")" || exit 1
    fi
    ALLOCATED_PORTS="${ALLOCATED_PORTS}${actual} "
    export "$var=$actual"
    # Persist into .env so a follow-up ``docker compose ...`` that the
    # operator runs out-of-band (e.g. ``docker compose restart argus-api``
    # in another shell) inherits the same port choices and doesn't try
    # to bind the canonical default behind our back. ``env_set`` is a
    # no-op when the .env doesn't exist yet (subcommand mode skips
    # this whole function).
    if [ -f "$ENV_FILE" ]; then
      env_set "$var" "$actual"
    fi
    if [ "$actual" != "$default" ]; then
      log "port: $svc default=$default → using $actual (default in use)"
    fi
  done
}

if [ -z "${SUBCMD_DEFERRED:-}" ]; then
  allocate_ports
fi

# --- secret helpers --------------------------------------------------

# Cryptographically random hex of N bytes. Falls back to /dev/urandom
# if openssl is missing (rare on dev machines but possible on minimal
# Linux images).
rand_hex() {
  local bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    head -c "$bytes" /dev/urandom | xxd -p | tr -d '\n'
  fi
}

# Detect host platform for the LLM-bridge URL hint. macOS/Windows
# Docker Desktop expose ``host.docker.internal`` automatically; we
# patched compose with extra_hosts so Linux now does too.
DEFAULT_BRIDGE_URL="http://host.docker.internal:8082"

# --- wizard ----------------------------------------------------------

# Bootstrap .env from .env.example the first time the user runs us.
# Ensures every key the compose file requires is present (even if blank).
#
# When we copy from .env.example, blank out the LLM provider/model
# fields so the wizard reliably fires on first run. .env.example ships
# them pre-filled (ollama / llama3.1:8b) as documentation, but treating
# those as the operator's choice would silently skip the picker.
bootstrap_env_file() {
  if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
      cp "$ENV_EXAMPLE" "$ENV_FILE"
      env_set ARGUS_LLM_PROVIDER ""
      env_set ARGUS_LLM_MODEL    ""
      env_set ARGUS_LLM_BASE_URL ""
      env_set ARGUS_LLM_API_KEY  ""
      log ".env created from .env.example"
    else
      touch "$ENV_FILE"
      warn ".env.example missing — created an empty .env"
    fi
  fi
}

# Generate any missing required secrets so compose interpolation succeeds.
ensure_required_secrets() {
  local k v
  declare -A required=(
    [ARGUS_DB_PASSWORD]="hex32"
    [ARGUS_JWT_SECRET]="hex64"
    [ARGUS_TOR_CONTROL_PASSWORD]="hex16"
    [MEILI_MASTER_KEY]="hex32"
    [MINIO_ROOT_USER]="literal:argus"
    [MINIO_ROOT_PASSWORD]="hex24"
  )
  for k in "${!required[@]}"; do
    v="$(env_get "$k")"
    if [ -z "$v" ]; then
      case "${required[$k]}" in
        hex16) env_set "$k" "$(rand_hex 16)" ;;
        hex24) env_set "$k" "$(rand_hex 24)" ;;
        hex32) env_set "$k" "$(rand_hex 32)" ;;
        hex64) env_set "$k" "$(rand_hex 64)" ;;
        literal:*) env_set "$k" "${required[$k]#literal:}" ;;
      esac
      log "generated $k"
    fi
  done
  # Pydantic-settings parses these as JSON lists; empty strings break
  # the parser. Default to ``[]`` if the operator left them blank.
  #
  # The ``if`` block (rather than ``&& env_set``) matters: when every
  # key is already populated, the && short-circuits and the loop body
  # exits 1, which becomes the function's return code and trips
  # ``set -e`` at the call site. Bash's exemption for AND-OR lists
  # doesn't extend to the loop's overall status.
  for k in ARGUS_CORS_ORIGINS ARGUS_NOTIFY_EMAIL_TO \
           ARGUS_TAKEDOWN_INTERNAL_LEGAL_SMTP_RECIPIENTS; do
    if [ -z "$(env_get "$k")" ]; then
      env_set "$k" "[]"
    fi
  done
  return 0
}

# --- handle deferred subcommands now that helpers exist ------------

if [ -n "${SUBCMD_DEFERRED:-}" ]; then
  bootstrap_env_file
  ensure_required_secrets
  case "$SUBCMD_DEFERRED" in
    stop)
      hdr "Stopping Argus stack"
      "$ROOT/scripts/bridge_host.sh" stop 2>/dev/null || true
      docker compose down
      log "Stack stopped (volumes kept)."
      exit 0 ;;
    wipe)
      hdr "Destroying Argus stack + data volumes"
      printf "${R}This will DELETE postgres / minio / redis / ollama data. Type 'wipe' to confirm: ${NC}"
      read -r confirm
      [ "$confirm" = "wipe" ] || { warn "aborted"; exit 1; }
      "$ROOT/scripts/bridge_host.sh" stop 2>/dev/null || true
      docker compose down -v
      # Clear the seeded flag so the next ./start.sh re-runs the seed
      # against the fresh volumes.
      if [ -f "$ENV_FILE" ]; then
        env_set ARGUS_SEEDED ""
      fi
      log "Stack and volumes destroyed."
      exit 0 ;;
    logs)   exec docker compose logs -f --tail=200 ;;
    status) exec docker compose ps ;;
  esac
fi

bootstrap_env_file

# --- interactive picker (canopy-style) -------------------------------
#
# Every run prompts for both LLM provider and seed mode. The default in
# brackets reflects the current .env value, so hitting Enter keeps the
# previous choice — operators only have to type when they want to
# change something. ``--yes`` skips the prompts entirely and uses the
# saved defaults (handy for CI / automation).

# Map the saved provider tuple onto a 1–4 menu number so the default
# we offer matches what the operator picked last time.
saved_provider="$(env_get ARGUS_LLM_PROVIDER)"
saved_base_url="$(env_get ARGUS_LLM_BASE_URL)"
case "$saved_provider" in
  bridge)    DEFAULT_LLM_CHOICE=1 ;;
  anthropic) DEFAULT_LLM_CHOICE=2 ;;
  ollama)    DEFAULT_LLM_CHOICE=3 ;;
  openai)
    case "$saved_base_url" in
      *argus-vllm*|*vllm:*) DEFAULT_LLM_CHOICE=4 ;;
      *) DEFAULT_LLM_CHOICE=2 ;;
    esac
    ;;
  *) DEFAULT_LLM_CHOICE=1 ;;
esac

LLM_PROFILE=""
BRIDGE_HOST_NATIVE=0

hdr "Configure runtime"
echo ""
echo "  ${B}LLM provider${NC} — used by triage / correlation / brand defender / case copilot:"
echo "    ${B}1${NC}) Claude Code bridge      ${D}— host 'claude' CLI via Redis worker. No key, no billing.${NC}"
echo "    ${B}2${NC}) Anthropic API (cloud)   ${D}— direct https://api.anthropic.com (needs ANTHROPIC_API_KEY).${NC}"
echo "    ${B}3${NC}) Local Ollama            ${D}— bundled ollama container, default tag gemma3:27b (~17 GB).${NC}"
echo "    ${B}4${NC}) Gemma 4 31B via vLLM    ${D}— NVIDIA GPU + ./models/gemma-4-31b-it/.${NC}"

LLM_CHOICE="$DEFAULT_LLM_CHOICE"
if [ "$NO_PROMPT" -eq 0 ]; then
  while true; do
    printf "  ${B}${C}?${NC} Enter choice [1/2/3/4] (default: %s): " "$DEFAULT_LLM_CHOICE"
    read -r LLM_CHOICE
    LLM_CHOICE="${LLM_CHOICE:-$DEFAULT_LLM_CHOICE}"
    case "$LLM_CHOICE" in 1|2|3|4) break ;; *) warn "enter 1, 2, 3, or 4" ;; esac
  done
else
  log "non-interactive: using saved LLM provider (choice $DEFAULT_LLM_CHOICE)"
fi

case "$LLM_CHOICE" in
  1)  # Claude Code bridge
      if ! command -v claude >/dev/null 2>&1; then
        warn "'claude' CLI not on PATH (install: https://claude.com/claude-code)"
      fi
      saved_model="$(env_get ARGUS_LLM_MODEL)"
      [ -z "$saved_model" ] || [ "$saved_provider" != "bridge" ] && saved_model="claude-sonnet-4-6"
      bridge_model="$saved_model"
      if [ "$NO_PROMPT" -eq 0 ]; then
        printf "  ${B}${C}?${NC} Model id (audit only — bridge uses CLI default) [%s]: " "$saved_model"
        read -r bridge_model
        bridge_model="${bridge_model:-$saved_model}"
      fi
      env_set ARGUS_LLM_PROVIDER  "bridge"
      env_set ARGUS_LLM_BASE_URL  ""
      env_set ARGUS_LLM_MODEL     "$bridge_model"
      env_set ARGUS_LLM_API_KEY   ""
      BRIDGE_HOST_NATIVE=1
      LLM_LABEL="Claude Code bridge ($bridge_model)"
      ;;
  2)  # Anthropic cloud
      saved_key="$(env_get ARGUS_LLM_API_KEY)"
      saved_model="$(env_get ARGUS_LLM_MODEL)"
      [ -z "$saved_model" ] || [ "$saved_provider" != "anthropic" ] && saved_model="claude-sonnet-4-6"
      cloud_model="$saved_model"
      api_key="$saved_key"
      if [ "$NO_PROMPT" -eq 0 ]; then
        if [ -n "$saved_key" ] && [ "$saved_provider" = "anthropic" ]; then
          printf "  ${B}${C}?${NC} ANTHROPIC_API_KEY [keep saved key, press Enter]: "
        else
          printf "  ${B}${C}?${NC} Paste ANTHROPIC_API_KEY (sk-ant-...): "
        fi
        read -rs api_key_in; printf "\n"
        api_key="${api_key_in:-$saved_key}"
        printf "  ${B}${C}?${NC} Model [%s]: " "$saved_model"
        read -r cloud_model
        cloud_model="${cloud_model:-$saved_model}"
      fi
      if [ -z "$api_key" ]; then
        err "Anthropic API key is required for option 2."
        exit 1
      fi
      env_set ARGUS_LLM_PROVIDER  "anthropic"
      env_set ARGUS_LLM_BASE_URL  "https://api.anthropic.com"
      env_set ARGUS_LLM_MODEL     "$cloud_model"
      env_set ARGUS_LLM_API_KEY   "$api_key"
      LLM_LABEL="Anthropic cloud ($cloud_model)"
      ;;
  3)  # Local Ollama
      saved_model="$(env_get ARGUS_LLM_MODEL)"
      [ -z "$saved_model" ] || [ "$saved_provider" != "ollama" ] && saved_model="gemma3:27b"
      ollama_tag="$saved_model"
      if [ "$NO_PROMPT" -eq 0 ]; then
        printf "  ${B}${C}?${NC} Ollama model tag [%s]: " "$saved_model"
        read -r ollama_tag
        ollama_tag="${ollama_tag:-$saved_model}"
      fi
      env_set ARGUS_LLM_PROVIDER  "ollama"
      env_set ARGUS_LLM_BASE_URL  "http://ollama:11434"
      env_set ARGUS_LLM_MODEL     "$ollama_tag"
      env_set ARGUS_LLM_API_KEY   ""
      LLM_PROFILE="local-llm"
      LLM_LABEL="local Ollama ($ollama_tag)"
      ;;
  4)  # vLLM Gemma
      if ! docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
        warn "NVIDIA docker runtime not detected — vLLM needs a GPU"
      fi
      if [ ! -f "$ROOT/models/gemma-4-31b-it/config.json" ]; then
        warn "weights at ./models/gemma-4-31b-it/ not found"
      fi
      saved_model="$(env_get ARGUS_LLM_MODEL)"
      [ -z "$saved_model" ] || [ "$saved_provider" != "openai" ] && saved_model="gemma-4-31b-it"
      served_name="$saved_model"
      if [ "$NO_PROMPT" -eq 0 ]; then
        printf "  ${B}${C}?${NC} Served model name [%s]: " "$saved_model"
        read -r served_name
        served_name="${served_name:-$saved_model}"
      fi
      env_set ARGUS_LLM_PROVIDER  "openai"
      env_set ARGUS_LLM_BASE_URL  "http://argus-vllm:8000/v1"
      env_set ARGUS_LLM_MODEL     "$served_name"
      env_set ARGUS_LLM_API_KEY   "vllm-no-key"
      LLM_PROFILE="gemma"
      LLM_LABEL="Gemma 4 31B via vLLM ($served_name)"
      ;;
esac

# Mac-specific: in-container bridge can't exec a Mach-O CLI.
if [ "$LLM_PROFILE" = "bridge" ] && [ "$(uname -s)" = "Darwin" ]; then
  LLM_PROFILE=""
  BRIDGE_HOST_NATIVE=1
fi

echo ""
echo "  ${B}Seed mode${NC} — what data the database boots with:"
echo "    ${B}1${NC}) realistic    ${D}— full demo dataset across every screen (4 orgs, IOCs, MITRE, etc.)${NC}"
echo "    ${B}2${NC}) minimal      ${D}— just the system org + admin user (production-style)${NC}"
saved_seed="$(env_get ARGUS_SEED_MODE)"
case "$saved_seed" in
  minimal)   DEFAULT_SEED_CHOICE=2 ;;
  *)         DEFAULT_SEED_CHOICE=1 ;;
esac
SEED_CHOICE="$DEFAULT_SEED_CHOICE"
if [ -n "$SEED_OVERRIDE" ]; then
  case "$SEED_OVERRIDE" in
    minimal)   SEED_CHOICE=2 ;;
    realistic) SEED_CHOICE=1 ;;
    *) err "--seed must be 'minimal' or 'realistic'"; exit 2 ;;
  esac
  log "seed mode override via --seed: $SEED_OVERRIDE"
elif [ "$NO_PROMPT" -eq 0 ]; then
  while true; do
    printf "  ${B}${C}?${NC} Enter choice [1/2] (default: %s): " "$DEFAULT_SEED_CHOICE"
    read -r SEED_CHOICE
    SEED_CHOICE="${SEED_CHOICE:-$DEFAULT_SEED_CHOICE}"
    case "$SEED_CHOICE" in 1|2) break ;; *) warn "enter 1 or 2" ;; esac
  done
fi
case "$SEED_CHOICE" in
  2) env_set ARGUS_SEED_MODE "minimal";   SEED_LABEL="minimal" ;;
  *) env_set ARGUS_SEED_MODE "realistic"; SEED_LABEL="realistic" ;;
esac

ensure_required_secrets

echo ""
log "LLM provider: $LLM_LABEL"
log "Seed mode:    $SEED_LABEL"
[ "$BRIDGE_HOST_NATIVE" -eq 1 ] && log "Bridge:       host-native (scripts/bridge_host.sh)"
[ -n "$LLM_PROFILE" ] && log "Compose profile: $LLM_PROFILE"

# --- numbered boot steps ---------------------------------------------
#
# Total step count is dynamic so the operator sees an honest [N/M].
# Mandatory: build, compose-up + seed wait, dashboard.
# Optional: ollama model pull, host-native bridge launch.
TOTAL_STEPS=3
[ "$LLM_PROFILE" = "local-llm" ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
[ "$BRIDGE_HOST_NATIVE" -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
STEP=0
step() { STEP=$((STEP + 1)); printf "\n  ${B}[${STEP}/${TOTAL_STEPS}]${NC} %s\n" "$1"; }

# Hand-off env var so docker-compose picks the right profile. Exporting
# rather than prepending means subsequent ``docker compose logs/exec``
# invocations inherit it without the operator typing it again.
#
# The "seed" profile activates argus-seed only on the first boot (or after
# a wipe). Once the API is healthy we write ARGUS_SEEDED=1 to .env so
# subsequent runs skip the seed container entirely — data lives in the
# postgres named volume and persists across restarts.
ARGUS_SEEDED_FLAG="$(env_get ARGUS_SEEDED)"
if [ "$ARGUS_SEEDED_FLAG" = "1" ]; then
  NEED_SEED=0
else
  NEED_SEED=1
fi

PROFILES="${LLM_PROFILE:-}"
if [ "$NEED_SEED" -eq 1 ]; then
  if [ -n "$PROFILES" ]; then
    PROFILES="${PROFILES},seed"
  else
    PROFILES="seed"
  fi
fi

# --with caldera,shuffle,velociraptor,misp brings up the matching
# opt-in OSS sidekicks from compose.optional.yml. Each profile name
# also auto-populates the matching ARGUS_*_URL env var so the
# connector finds the service at its in-network hostname.
COMPOSE_FILES="-f docker-compose.yml"
if [ -n "$EXTRA_PROFILES" ]; then
  COMPOSE_FILES="$COMPOSE_FILES -f compose.optional.yml"
  for prof in $(echo "$EXTRA_PROFILES" | tr ',' ' '); do
    case "$prof" in
      caldera)
        env_set ARGUS_CALDERA_URL "http://caldera:8888"
        log "  ↪ caldera profile — set ARGUS_CALDERA_URL"
        ;;
      shuffle)
        env_set ARGUS_SHUFFLE_URL "http://shuffle-frontend:80"
        log "  ↪ shuffle profile — set ARGUS_SHUFFLE_URL"
        ;;
      velociraptor)
        env_set ARGUS_VELOCIRAPTOR_URL "https://velociraptor:8889"
        env_set ARGUS_VELOCIRAPTOR_VERIFY_SSL "false"
        log "  ↪ velociraptor profile — set ARGUS_VELOCIRAPTOR_URL"
        ;;
      misp)
        env_set ARGUS_MISP_URL "https://misp"
        env_set ARGUS_MISP_VERIFY_SSL "false"
        warn "  ↪ misp profile — generate the API key in MISP's web UI (https://localhost:8443) and put it in ARGUS_MISP_API_KEY"
        ;;
      opencti)
        warn "  ↪ opencti profile — uncomment the opencti block in compose.optional.yml first (8 GB RAM)"
        ;;
      *)
        warn "  ↪ unknown profile '$prof' — ignored"
        ;;
    esac
    if [ -n "$PROFILES" ]; then
      PROFILES="${PROFILES},$prof"
    else
      PROFILES="$prof"
    fi
  done
fi

if [ -n "$PROFILES" ]; then
  export COMPOSE_PROFILES="$PROFILES"
fi

# Re-export so all subsequent ``docker compose`` invocations see the
# multi-file flag set when --with was used.
export COMPOSE_FILE_OVERRIDE="$COMPOSE_FILES"
dc() { docker compose $COMPOSE_FILE_OVERRIDE "$@"; }

step "Building images (cached layers will be skipped)"
# Show progress so a long ``pip wheel`` rebuild — triggered whenever
# requirements.txt changes — doesn't look like a hang. ``--progress
# plain`` is a goes-before-build global flag in compose v2.
log "build can take 5-10 min on the first run after a requirements.txt change"
dc --progress plain build
log "build complete"

if [ "$NEED_SEED" -eq 1 ]; then
  step "Bringing up backend stack (postgres, redis, minio, api, worker) + seeding DB"
else
  step "Bringing up backend stack (postgres, redis, minio, api, worker)"
fi
dc up -d
log "containers running — waiting for API to pass /health"
if [ "$NEED_SEED" -eq 1 ]; then
  log "  • argus-seed runs first; realistic mode takes ~60s, minimal ~10s"
  log "  • tail with: docker compose logs -f argus-seed argus-api"
fi
api_url="http://localhost:${ARGUS_HOST_API_PORT}"
api_ready=0
for i in $(seq 1 90); do
  if curl -fsS "${api_url}/health" >/dev/null 2>&1; then
    api_ready=1
    break
  fi
  sleep 2
done
if [ "$api_ready" -eq 1 ]; then
  log "API is ready (${api_url})"
  # Record that the DB has been seeded so subsequent ./start.sh runs skip
  # the seed container. Data lives in the postgres named volume and persists
  # across restarts. Only ./start.sh wipe clears this flag.
  if [ "$NEED_SEED" -eq 1 ]; then
    env_set ARGUS_SEEDED "1"
    log "DB seeded — future restarts will skip the seed step"
  fi
else
  warn "API didn't become ready in 180s; check 'docker compose logs argus-api'"
fi

# --- optional: pull Ollama model ------------------------------------

if [ "$LLM_PROFILE" = "local-llm" ]; then
  ollama_model="$(env_get ARGUS_LLM_MODEL)"
  step "Ensuring Ollama has '$ollama_model' (idempotent — skips layers already present)"
  for i in $(seq 1 60); do
    if curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1; then break; fi
    sleep 2
  done
  if curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1; then
    log "ollama is up; pulling $ollama_model"
    docker compose exec -T ollama ollama pull "$ollama_model" || \
      warn "model pull failed — retry with: docker compose exec ollama ollama pull $ollama_model"
  else
    warn "ollama didn't come up in 120s — skipping model pull"
  fi
fi

# --- optional: host-native Claude bridge worker (macOS path) --------

if [ "$BRIDGE_HOST_NATIVE" -eq 1 ]; then
  step "Launching host-native Claude bridge worker"
  if "$ROOT/scripts/bridge_host.sh" start; then
    log "bridge worker draining ai_tasks queue (log: $ROOT/logs/bridge-host.log)"
  else
    warn "bridge worker failed to start — LLM-dependent agents will error"
    warn "tail $ROOT/logs/bridge-host.log for details"
  fi
fi

# --- dashboard -------------------------------------------------------

dashboard_url="http://localhost:${ARGUS_HOST_DASHBOARD_PORT}"
step "Starting dashboard (Next.js → ${dashboard_url})"

cd "$ROOT/dashboard"
if [ ! -d node_modules ]; then
  log "installing npm dependencies (one-time, ~30s)"
  npm install --silent
fi

# Tell the dashboard which API to talk to. Required by ``src/lib/api.ts``
# which reads ``NEXT_PUBLIC_API_URL`` at build time. Exporting before
# ``npm run dev`` ensures the chosen port flows into the bundle.
export NEXT_PUBLIC_API_URL="${api_url}/api/v1"
export PORT="${ARGUS_HOST_DASHBOARD_PORT}"

DASHBOARD_PID=""
cleanup() {
  echo ""
  if [ -n "$DASHBOARD_PID" ] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    warn "stopping dashboard"
    kill "$DASHBOARD_PID" 2>/dev/null || true
  fi
  echo ""
  printf "%sBackend stack is still running.%s Stop it with %s./start.sh stop%s\n" \
    "$Y" "$NC" "$B" "$NC"
  exit 0
}
trap cleanup INT TERM

# Run dashboard in background so we can wait for it AND open a browser.
npm run dev >"$ROOT/.dashboard.log" 2>&1 &
DASHBOARD_PID=$!

# Wait for Next.js to compile and respond.
dashboard_ready=0
for i in $(seq 1 60); do
  if curl -fsS "${dashboard_url}" >/dev/null 2>&1; then
    dashboard_ready=1
    break
  fi
  if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    err "dashboard process exited unexpectedly. Last 30 lines:"
    tail -n 30 "$ROOT/.dashboard.log" >&2
    exit 1
  fi
  sleep 2
done
if [ "$dashboard_ready" -eq 1 ]; then
  log "dashboard is ready"
else
  warn "dashboard didn't respond in 120s; tailing $ROOT/.dashboard.log may help"
fi

# --- open browser & banner -------------------------------------------

if [ "$NO_OPEN" -eq 0 ] && [ "$dashboard_ready" -eq 1 ]; then
  if command -v open >/dev/null 2>&1; then
    open "${dashboard_url}" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${dashboard_url}" >/dev/null 2>&1 || true
  fi
fi

cd "$ROOT"

ADMIN_EMAIL_DEFAULT="admin@argus.local"
ADMIN_PASS_DEFAULT="ChangeMe-On-First-Login!"
ADMIN_EMAIL="$(env_get ARGUS_BOOTSTRAP_ADMIN_EMAIL)"
ADMIN_PASS="$(env_get ARGUS_BOOTSTRAP_ADMIN_PASSWORD)"
[ -z "$ADMIN_EMAIL" ] && ADMIN_EMAIL="$ADMIN_EMAIL_DEFAULT"
[ -z "$ADMIN_PASS" ]  && ADMIN_PASS="$ADMIN_PASS_DEFAULT"

if [ "$api_ready" -eq 1 ]; then
  STATUS_API="${G}ready${NC}"
else
  STATUS_API="${Y}not yet ready — check logs${NC}"
fi
if [ "$dashboard_ready" -eq 1 ]; then
  STATUS_DASH="${G}ready${NC}"
else
  STATUS_DASH="${Y}not yet ready — check $ROOT/.dashboard.log${NC}"
fi

cat <<EOF

${B}${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${B}  Argus is running${NC}

  ${C}URLs${NC}
    Dashboard      ${dashboard_url}           [${STATUS_DASH}]
    API            ${api_url}/api/v1    [${STATUS_API}]
    API docs       ${api_url}/docs

  ${C}Configuration${NC}
    LLM provider   ${LLM_LABEL}
    Seed mode      ${SEED_LABEL}
EOF
[ "$BRIDGE_HOST_NATIVE" -eq 1 ] && \
  printf "    Bridge         host-native (scripts/bridge_host.sh)\n"
[ -n "$LLM_PROFILE" ] && \
  printf "    Compose profile  %s\n" "$LLM_PROFILE"
cat <<EOF

  ${C}Login${NC}
    Email          ${B}${ADMIN_EMAIL}${NC}
    Password       ${D}${ADMIN_PASS}${NC}

  ${C}Logs${NC}
    Backend stack  docker compose logs -f
    API only       docker compose logs -f argus-api
    Worker         docker compose logs -f argus-worker
    Seed run       docker compose logs argus-seed
    Dashboard      tail -f $ROOT/.dashboard.log
EOF
[ "$BRIDGE_HOST_NATIVE" -eq 1 ] && \
  printf "    Bridge         tail -f %s/logs/bridge-host.log\n" "$ROOT"
cat <<EOF

  ${Y}Stop dashboard${NC}   Ctrl+C  ${D}(backend stack keeps running)${NC}
  ${Y}Stop everything${NC}  ./start.sh stop
  ${Y}Reconfigure${NC}      ./start.sh        ${D}(every run prompts for LLM/seed)${NC}
  ${Y}Status${NC}           ./start.sh status
${B}${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

EOF

# Tail dashboard logs so the operator sees Next.js compile errors etc.
# in the same terminal until they Ctrl+C.
wait "$DASHBOARD_PID" 2>/dev/null || true
cleanup
