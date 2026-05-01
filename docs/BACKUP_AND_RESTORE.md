# Backup & Restore

Argus has two stateful systems: **Postgres** (relational data, audit log,
all findings) and **MinIO / S3** (evidence vault — uploaded files, PDFs,
brand-logo blobs). Both must be backed up; losing either leaves the
product in an inconsistent state where the DB references S3 keys whose
objects are gone (and vice versa).

This document is the SOC2 / bank-CISO-ready answer to "what's your
backup story."

---

## RPO / RTO targets

| Tier | Target |
|---|---|
| Recovery Point Objective (data loss tolerance) | **15 minutes** |
| Recovery Time Objective (downtime tolerance) | **2 hours** for cold-start, **15 minutes** for managed-Postgres point-in-time recovery |

Tested **2026-04-28** against the local `argus` Docker Compose project. Re-run the drill quarterly.

---

## Postgres

### Default deploy (Railway managed Postgres)

Railway's managed Postgres ships with continuous WAL archiving and
point-in-time-recovery (PITR). Enable retention to **7 days** in the
Railway plugin settings; for production tier customers, raise to **30
days**.

Daily logical dump as defense-in-depth:

```bash
pg_dump --format=custom --no-owner --no-privileges \
        --file=/backups/argus-$(date -u +%Y-%m-%dT%H-%M).dump \
        "$DATABASE_URL"
```

Drive this from a Railway cron service or an external scheduler. Push
the dump to a separate object store (R2 bucket, Backblaze B2) so a
Railway-side incident doesn't lose both the DB and its backups.

### Self-hosted

For on-prem Postgres, use either:

- **WAL-G** to a private S3-compatible bucket (continuous archiving + base backups)
- **pg_basebackup** + `archive_command = 'cp %p /backups/wal/%f'` (simpler, slower restore)

Document the chosen setup in the customer runbook.

---

## MinIO / Evidence vault

### Default deploy (MinIO on Railway volume)

```bash
mc mirror --remove --overwrite \
   argus/argus-evidence  backup/argus-evidence-mirror
```

Schedule daily; a separate weekly `--quiet --json` integrity scan
guards against silent corruption. Mirror to a different cloud
provider (R2 → B2, or vice versa) so a single-vendor incident doesn't
take both copies down.

### Cloudflare R2 / AWS S3 / Backblaze B2

These ship versioning + lifecycle. Enable:

- **Object versioning** (so an accidental delete is recoverable)
- **Lifecycle rule**: transition objects > 90 days to Glacier/Deep tier; expire delete-markers > 365 days
- **Cross-region replication** for tier-1 customers

---

## Restore drill

Run **at least quarterly**. The drill is the only way you find out
whether the backup is actually usable.

### Drill: full cold-start restore

1. Spin up a clean Postgres + MinIO (e.g. `docker compose -p argus-restore -f docker-compose.test.yml up -d`).
2. Restore the latest Postgres dump:
   ```bash
   pg_restore --no-owner --no-privileges \
              --dbname=postgresql://argus:argus@localhost:55432/argus_test \
              /backups/argus-LATEST.dump
   ```
3. Mirror the evidence bucket back:
   ```bash
   mc mirror --overwrite backup/argus-evidence-mirror argus-restore/argus-evidence
   ```
4. Run `alembic upgrade head` against the restored DB to confirm schema is clean.
5. Boot Argus pointing at the restored stack: `docker compose -p argus-restore up -d argus-api`.
6. Smoke-test from a browser:
   - `/health` returns `200`
   - `/api/v1/evidence/<known-id>/download` returns the same SHA-256 as the original
   - One representative case loads with all its findings + comments
7. Record the wall-clock time from "start" to "smoke test passes" — that's your **measured RTO**.

### Drill: PITR rewind

1. Create a sentinel record: `INSERT INTO audit_logs (action, ...) VALUES ('drill', ...)` and note the timestamp.
2. Wait 5 minutes.
3. Issue Railway PITR rewind to **timestamp − 1 minute**.
4. Confirm the sentinel row is gone and the rest of the DB is intact.
5. Record the wall-clock time — that's your **measured PITR RTO**.

---

## What is *not* backed up

- **Redis** — rate-limit windows, account lockout counters. Loss is acceptable; both rebuild from scratch within the next window.
- **Local Tor / Ollama / Meilisearch** state — derived from Postgres; rebuilt on first run.

---

## Audit trail

Every backup and restore action must be logged:

```sql
INSERT INTO audit_logs (action, resource_type, details, ...)
VALUES ('backup_run', 'postgres', '{"size_bytes":..., "duration_ms":...}'::jsonb, ...);
```

We intentionally do not let retention prune `backup_run` rows (override
in `RetentionPolicy.audit_logs_days` = 3650 if any customer demands it).

---

## Automated drill — `scripts/backup_restore_drill.sh`

Exec'able end-to-end drill that satisfies the SOC2 / SAMA "we tested
restore on $DATE" evidence ask. Run quarterly + as part of every
release-readiness check:

```bash
# Full drill — backup, restore into argus_restore, verify
./scripts/backup_restore_drill.sh full

# Just produce versioned artefacts under var/backup-drill/<TS>/
./scripts/backup_restore_drill.sh backup

# Restore from an existing backup dir
./scripts/backup_restore_drill.sh restore var/backup-drill/2026-05-01T11-00-00Z

# Re-hash artefacts vs the sealed MANIFEST.json
./scripts/backup_restore_drill.sh verify var/backup-drill/2026-05-01T11-00-00Z
```

What the drill verifies:

1. `pg_dump` against the live `argus` DB succeeds.
2. Every object in the `argus-evidence` MinIO bucket is mirrored and
   SHA-256'd; the manifest records each object's pre-mirror hash.
3. A disposable `argus_restore` Postgres DB is dropped, recreated, and
   `pg_restore`d from the captured dump.
4. Sentinel-table row counts (`organizations`, `users`, `alerts`,
   `iocs`, `cases`, `evidence_blobs`, `audit_logs`,
   `feed_subscriptions`, `compliance_evidence`) match between the
   source and the restore — non-zero exit if any drifts.
5. The MinIO mirror is replayed into a sibling bucket and every
   object's SHA-256 is recomputed and compared against the manifest —
   non-zero exit if any hash drifts.

The drill leaves a sealed `MANIFEST.json` next to the artefacts that
records the timestamp + the dump's SHA-256 + the per-object hashes;
attach this to your SOC2 audit binder as the per-quarter evidence row.
