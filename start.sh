#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m' C='\033[0;36m' NC='\033[0m' B='\033[1m'

log()  { echo -e "${G}[✓]${NC} $1"; }
warn() { echo -e "${Y}[!]${NC} $1"; }
err()  { echo -e "${R}[✗]${NC} $1"; }
head() { echo -e "\n${B}${C}$1${NC}"; }

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo ""
  warn "Shutting down..."
  [ -n "$BACKEND_PID" ]  && kill "$BACKEND_PID"  2>/dev/null && log "Backend stopped"
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null && log "Dashboard stopped"
  exit 0
}
trap cleanup SIGINT SIGTERM

# ─── Preflight checks ───────────────────────────────────────────────

head "Argus — Threat Intelligence Platform"

# Python
if ! command -v python3 &>/dev/null; then
  err "python3 not found. Install Python 3.11+."
  exit 1
fi

# Node
if ! command -v node &>/dev/null; then
  err "node not found. Install Node.js 18+."
  exit 1
fi

# PostgreSQL
if ! pg_isready -q 2>/dev/null; then
  warn "PostgreSQL doesn't appear to be running. Attempting to start..."
  if command -v brew &>/dev/null; then
    brew services start postgresql@14 2>/dev/null || brew services start postgresql 2>/dev/null || true
    sleep 2
  fi
  if ! pg_isready -q 2>/dev/null; then
    err "PostgreSQL is not running. Start it manually and retry."
    exit 1
  fi
fi
log "PostgreSQL is running"

# ─── Backend setup ───────────────────────────────────────────────────

head "Setting up backend..."

if [ ! -d "$ROOT/.venv" ]; then
  warn "No virtualenv found — creating .venv"
  python3 -m venv "$ROOT/.venv"
fi

source "$ROOT/.venv/bin/activate"
log "Activated virtualenv"

# Install deps if needed (skip if already satisfied)
if ! python3 -c "import fastapi, sqlalchemy, httpx" 2>/dev/null; then
  warn "Installing Python dependencies..."
  pip install -q -r "$ROOT/requirements.txt"
fi
log "Python dependencies OK"

# Load .env if present
if [ -f "$ROOT/.env" ]; then
  set -a; source "$ROOT/.env"; set +a
  log "Loaded .env"
fi

# Init DB tables
python3 -c "
import asyncio
from src.storage.database import init_db
asyncio.run(init_db())
print('Database tables ready')
" 2>/dev/null && log "Database initialized" || warn "DB init skipped (may already exist)"

# Seed demo data (optional, idempotent)
if [ "${SEED:-0}" = "1" ]; then
  head "Seeding demo data..."
  python3 -m scripts.seed_demo && log "Demo data seeded" || warn "Seed script had issues"
fi

# Start backend
head "Starting backend API on :8000..."
uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --log-level info &
BACKEND_PID=$!
sleep 2

if kill -0 "$BACKEND_PID" 2>/dev/null; then
  log "Backend running (PID $BACKEND_PID)"
else
  err "Backend failed to start. Check logs above."
  exit 1
fi

# ─── Frontend setup ──────────────────────────────────────────────────

head "Setting up dashboard..."

cd "$ROOT/dashboard"

if [ ! -d "node_modules" ]; then
  warn "Installing Node dependencies..."
  npm install --silent
fi
log "Node dependencies OK"

head "Starting dashboard on :3000..."
npm run dev &
FRONTEND_PID=$!
sleep 3

if kill -0 "$FRONTEND_PID" 2>/dev/null; then
  log "Dashboard running (PID $FRONTEND_PID)"
else
  err "Dashboard failed to start."
  cleanup
fi

# ─── Ready ───────────────────────────────────────────────────────────

cd "$ROOT"
echo ""
echo -e "${B}${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${B}  Argus is running${NC}"
echo -e "  ${C}Dashboard${NC}  →  http://localhost:3000"
echo -e "  ${C}API${NC}        →  http://localhost:8000/api/v1"
echo -e "  ${C}API docs${NC}   →  http://localhost:8000/docs"
echo -e ""
echo -e "  ${Y}Tip:${NC} Run with ${B}SEED=1 ./start.sh${NC} to load demo data"
echo -e "  ${Y}Stop:${NC} Press ${B}Ctrl+C${NC}"
echo -e "${B}${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Wait for either process to exit
wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
warn "A process exited unexpectedly"
cleanup
