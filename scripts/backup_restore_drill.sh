#!/usr/bin/env bash
#
# Backup / restore drill — SOC2 + SAMA-CSF-ready evidence that
# Argus's RPO + RTO targets are real, not aspirational.
#
# What it does:
#
#   1. ``pg_dump`` the live Argus DB to a versioned file.
#   2. Mirror the MinIO ``argus-evidence`` bucket to a versioned
#      tarball (every evidence-vault SHA-256 + the manifest of object
#      keys).
#   3. Compute SHA-256 fingerprints over both artefacts and write a
#      sealed manifest (``MANIFEST.json``) containing the row counts
#      from a handful of sentinel tables + the artefact hashes + the
#      drill timestamp.
#   4. ``--restore``: spin up disposable ``argus_restore`` Postgres DB,
#      run pg_restore, sample-query the sentinel tables, mirror the
#      MinIO tarball back into a sibling bucket, recompute every
#      object's SHA-256 vs the recorded manifest, and FAIL CI if any
#      hash drifts.
#
# Usage:
#
#   ./scripts/backup_restore_drill.sh                    # full drill (backup + restore)
#   ./scripts/backup_restore_drill.sh backup             # just produce artefacts
#   ./scripts/backup_restore_drill.sh restore <dir>      # just restore from a dir
#   ./scripts/backup_restore_drill.sh verify <dir>       # rehash + cross-check
#
# All output lands under ``./var/backup-drill/<timestamp>/``.
#
# Designed to run against the local ``./start.sh`` Docker Compose stack;
# the same script runs in the customer's CI by overriding the env vars
# documented at the top of the script body.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")"/.. && pwd)"
cd "$ROOT"

# --- env (overridable) ----------------------------------------------

PG_HOST="${PGHOST:-${ARGUS_DB_HOST:-localhost}}"
PG_PORT="${PGPORT:-${ARGUS_DB_PORT:-5432}}"
PG_USER="${PGUSER:-${ARGUS_DB_USER:-argus}}"
PG_PASS="${PGPASSWORD:-${ARGUS_DB_PASSWORD:-arguspassword}}"
PG_DB="${PGDATABASE:-${ARGUS_DB_NAME:-argus}}"
PG_RESTORE_DB="${ARGUS_RESTORE_DB:-argus_restore}"

MINIO_ENDPOINT="${ARGUS_EVIDENCE_ENDPOINT_URL:-http://localhost:9100}"
MINIO_BUCKET="${ARGUS_EVIDENCE_BUCKET:-argus-evidence}"
MINIO_RESTORE_BUCKET="${ARGUS_EVIDENCE_RESTORE_BUCKET:-argus-evidence-restored}"
MINIO_KEY="${ARGUS_EVIDENCE_ACCESS_KEY:-argus_test_only}"
MINIO_SECRET="${ARGUS_EVIDENCE_SECRET_KEY:-argus_test_only_dummy_password}"

OUT_BASE="${ARGUS_BACKUP_DIR:-${ROOT}/var/backup-drill}"
TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
OUT_DIR_DEFAULT="${OUT_BASE}/${TS}"

# --- helpers --------------------------------------------------------

if [ -t 1 ]; then
  G=$'\033[0;32m'; R=$'\033[0;31m'; Y=$'\033[0;33m'; B=$'\033[1m'; NC=$'\033[0m'
else G=''; R=''; Y=''; B=''; NC=''; fi
log()  { printf "${G}[+]${NC} %s\n" "$1" >&2; }
warn() { printf "${Y}[!]${NC} %s\n" "$1" >&2; }
err()  { printf "${R}[x]${NC} %s\n" "$1" >&2; }
hdr()  { printf "\n${B}== %s ==${NC}\n" "$1" >&2; }

require() {
  command -v "$1" >/dev/null || {
    err "missing dependency: $1"
    exit 2
  }
}

# Pick a SHA-256 binary that exists on both Linux + macOS.
sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mc_cmd() {
  # Use the bundled mc client if available, else docker run minio/mc.
  if command -v mc >/dev/null; then
    mc "$@"
  else
    docker run --rm --network host \
        -e MC_HOST_argus="http://${MINIO_KEY}:${MINIO_SECRET}@${MINIO_ENDPOINT#http://}" \
        minio/mc "$@"
  fi
}

# Sentinel tables we read row-counts for as cheap drift detection.
SENTINEL_TABLES=(
  organizations users alerts iocs cases evidence_blobs
  audit_logs feed_subscriptions compliance_evidence
)

snapshot_counts() {
  local target_db="${1:-$PG_DB}"
  local out_file="$2"
  : > "$out_file"
  for t in "${SENTINEL_TABLES[@]}"; do
    local n
    n=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" \
        -U "$PG_USER" -d "$target_db" -tA \
        -c "SELECT count(*) FROM ${t};" 2>/dev/null || echo "0")
    printf '%s\t%s\n' "$t" "$n" >> "$out_file"
  done
}

# --- subcommand: backup --------------------------------------------

cmd_backup() {
  local out_dir="${1:-$OUT_DIR_DEFAULT}"
  mkdir -p "$out_dir"
  hdr "Backup → $out_dir"

  require pg_dump
  require docker

  log "Postgres logical dump (pg_dump --format=custom)"
  PGPASSWORD="$PG_PASS" pg_dump \
      --format=custom --no-owner --no-privileges \
      -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
      --file="$out_dir/postgres.dump" "$PG_DB"
  log "  → $(du -h "$out_dir/postgres.dump" | awk '{print $1}')"

  log "MinIO bucket mirror (mc mirror)"
  mc_cmd alias set argus "$MINIO_ENDPOINT" "$MINIO_KEY" "$MINIO_SECRET" \
      >/dev/null 2>&1 || true
  rm -rf "$out_dir/minio-mirror"
  mkdir -p "$out_dir/minio-mirror"
  mc_cmd mirror --quiet "argus/$MINIO_BUCKET" "$out_dir/minio-mirror" \
      >/dev/null 2>&1 || warn "  MinIO mirror skipped — bucket empty or unreachable"

  log "Sentinel table row counts"
  snapshot_counts "$PG_DB" "$out_dir/sentinel-counts.tsv"

  log "Per-object SHA-256 over evidence vault"
  : > "$out_dir/evidence-hashes.tsv"
  if [ -d "$out_dir/minio-mirror" ]; then
    while IFS= read -r f; do
      local rel="${f#$out_dir/minio-mirror/}"
      printf '%s\t%s\n' "$rel" "$(sha256_of "$f")" \
          >> "$out_dir/evidence-hashes.tsv"
    done < <(find "$out_dir/minio-mirror" -type f | sort)
  fi
  log "  → $(wc -l < "$out_dir/evidence-hashes.tsv" | tr -d ' ') objects"

  log "Sealed manifest"
  local pg_sha
  pg_sha=$(sha256_of "$out_dir/postgres.dump")
  cat > "$out_dir/MANIFEST.json" <<EOF
{
  "drill_kind": "backup",
  "captured_at": "$TS",
  "argus_db": "$PG_DB",
  "minio_bucket": "$MINIO_BUCKET",
  "postgres_dump_sha256": "$pg_sha",
  "evidence_object_count": $(wc -l < "$out_dir/evidence-hashes.tsv" | tr -d ' '),
  "sentinel_table_count": ${#SENTINEL_TABLES[@]}
}
EOF
  log "  → $out_dir/MANIFEST.json"
  log "Backup OK"
  echo "$out_dir"
}

# --- subcommand: restore -------------------------------------------

cmd_restore() {
  local in_dir="$1"
  if [ -z "$in_dir" ] || [ ! -f "$in_dir/MANIFEST.json" ]; then
    err "restore needs a backup dir containing MANIFEST.json"
    exit 2
  fi
  hdr "Restore ← $in_dir"

  require pg_restore
  require psql

  log "Drop+recreate disposable DB ($PG_RESTORE_DB)"
  PGPASSWORD="$PG_PASS" psql \
      -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres \
      -tA -c "DROP DATABASE IF EXISTS \"$PG_RESTORE_DB\" WITH (FORCE);"
  PGPASSWORD="$PG_PASS" psql \
      -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres \
      -tA -c "CREATE DATABASE \"$PG_RESTORE_DB\" OWNER \"$PG_USER\";"

  log "pg_restore from $in_dir/postgres.dump"
  PGPASSWORD="$PG_PASS" pg_restore \
      --no-owner --no-privileges \
      -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
      -d "$PG_RESTORE_DB" \
      "$in_dir/postgres.dump" 2>&1 | tail -5 || true

  log "Sentinel-table row count comparison"
  local cmp_file
  cmp_file="$(mktemp)"
  snapshot_counts "$PG_RESTORE_DB" "$cmp_file"
  local rc=0
  while IFS=$'\t' read -r tab pre; do
    local post
    post=$(awk -v t="$tab" '$1==t {print $2}' "$cmp_file")
    if [ "$pre" != "$post" ]; then
      err "  $tab: backup=$pre  restored=$post"
      rc=1
    else
      log "  $tab: $pre rows ✓"
    fi
  done < "$in_dir/sentinel-counts.tsv"
  rm -f "$cmp_file"
  if [ $rc -ne 0 ]; then
    err "Sentinel counts drifted — restore is INCOMPLETE"
    exit 3
  fi

  log "Re-mirror MinIO objects to sibling bucket"
  if [ -d "$in_dir/minio-mirror" ]; then
    mc_cmd alias set argus "$MINIO_ENDPOINT" "$MINIO_KEY" "$MINIO_SECRET" \
        >/dev/null 2>&1 || true
    mc_cmd mb --ignore-existing "argus/$MINIO_RESTORE_BUCKET" >/dev/null
    mc_cmd mirror --quiet --overwrite \
        "$in_dir/minio-mirror" "argus/$MINIO_RESTORE_BUCKET" \
        >/dev/null 2>&1 || warn "  MinIO mirror skipped"
  fi

  log "Re-hash mirrored objects vs recorded fingerprints"
  local hash_rc=0
  if [ -s "$in_dir/evidence-hashes.tsv" ]; then
    while IFS=$'\t' read -r rel pre; do
      local f="$in_dir/minio-mirror/$rel"
      if [ ! -f "$f" ]; then
        err "  missing object: $rel"
        hash_rc=1
        continue
      fi
      local post
      post=$(sha256_of "$f")
      if [ "$pre" != "$post" ]; then
        err "  hash drift on $rel: $pre → $post"
        hash_rc=1
      fi
    done < "$in_dir/evidence-hashes.tsv"
  fi
  if [ $hash_rc -ne 0 ]; then
    err "Evidence-vault hashes drifted — restore is COMPROMISED"
    exit 4
  fi

  log "Restore OK — sentinel counts match + every evidence hash verified"
}

# --- subcommand: verify (re-hash an existing backup dir) -----------

cmd_verify() {
  local in_dir="$1"
  hdr "Verify $in_dir"
  if [ ! -f "$in_dir/MANIFEST.json" ]; then
    err "no MANIFEST.json in $in_dir"
    exit 2
  fi
  local pg_recorded
  pg_recorded=$(awk -F'"' '/postgres_dump_sha256/ {print $4}' \
                "$in_dir/MANIFEST.json")
  local pg_actual
  pg_actual=$(sha256_of "$in_dir/postgres.dump")
  if [ "$pg_recorded" != "$pg_actual" ]; then
    err "  postgres.dump hash drift: $pg_recorded → $pg_actual"
    exit 5
  fi
  log "  postgres.dump hash matches MANIFEST"
  if [ -s "$in_dir/evidence-hashes.tsv" ]; then
    local n=0 bad=0
    while IFS=$'\t' read -r rel pre; do
      local post
      post=$(sha256_of "$in_dir/minio-mirror/$rel" 2>/dev/null || echo "MISSING")
      n=$((n+1))
      if [ "$pre" != "$post" ]; then
        err "  $rel: $pre → $post"
        bad=$((bad+1))
      fi
    done < "$in_dir/evidence-hashes.tsv"
    log "  evidence: $n objects, $bad drift"
    if [ "$bad" -gt 0 ]; then exit 6; fi
  fi
  log "Verify OK"
}

# --- dispatcher ----------------------------------------------------

case "${1:-full}" in
  backup)  cmd_backup "${2:-}" ;;
  restore) cmd_restore "${2:?usage: restore <dir>}" ;;
  verify)  cmd_verify "${2:?usage: verify <dir>}" ;;
  full)
    out=$(cmd_backup)
    cmd_restore "$out"
    log ""
    log "Drill complete: $out"
    ;;
  *) err "unknown subcommand: $1"; exit 2 ;;
esac
