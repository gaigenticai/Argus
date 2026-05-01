# Deployment & Rollback

This document covers (1) the standard release flow and (2) what to do
when something breaks. It is the playbook the on-call engineer should
have open during every deploy.

---

## Release flow

1. **Pre-flight**
   - Tag passing CI on the release commit.
   - Confirm `alembic upgrade head --sql` produces clean SQL with no
     destructive ops (`DROP COLUMN`, `DROP TABLE`) — review in the PR.
   - Confirm `docs/HARDWARE_DECISIONS.md` is unchanged or has a new
     entry for any heavy dep added.

2. **Apply database migration first**
   ```bash
   docker compose run --rm argus-api alembic upgrade head
   ```
   This is idempotent. Run it on a freshly-snapshotted DB if you can.

3. **Deploy API + worker together**
   ```bash
   docker compose up -d argus-api argus-worker
   ```
   The API healthcheck (`/health`) and the worker healthcheck (heartbeat
   file, see `src/workers/healthcheck.py`) must go green within 60s.

4. **Smoke test**
   - `curl /health` returns 200
   - `curl /metrics` returns Prometheus exposition (no `unknown` paths)
   - Authenticate as admin, hit `/api/v1/easm/worker/tick` — should
     return an empty results list (or drained jobs) without erroring
   - One known-good case loads at `/api/v1/cases/{id}` with all
     findings + comments

5. **Tag the release** in git. Push tag.

---

## Rollback

The blast radius depends on what was deployed. Decision tree:

### Code-only change (no migration in this release)

```bash
docker compose down argus-api argus-worker
git checkout <previous-tag>
docker compose up -d argus-api argus-worker
```

This is the safe fast-path. ≤ 2 minutes.

### Migration ran successfully but the new code is broken

The migration is *additive* by convention (add column / table / enum
value, never drop). Roll the code back; the new schema is harmless to
the old code. No DB action needed.

```bash
git checkout <previous-tag>
docker compose up -d argus-api argus-worker
```

### Migration failed halfway through

Postgres runs each Alembic migration in its own transaction. A failure
should leave the DB at the previous revision automatically — verify:

```bash
docker compose run --rm argus-api alembic current
```

If the revision matches the previous release, you're fine. Roll the
code back as above.

If the revision DID advance but the migration left the schema in a
broken state (rare — usually only happens with multi-statement
migrations that touch system catalogues), use **PITR rewind** rather
than running ad-hoc `DROP` / `ALTER` by hand. See
`docs/BACKUP_AND_RESTORE.md` for the rewind procedure.

### Migration ran AND code deployed AND we discover data loss

This is the worst case — the new code may have written rows that
encode the new schema's semantics, and rolling forward those rows
through the old code may not be safe.

1. **Stop writes.** Take API + worker offline immediately.
2. **PITR rewind to the point just before the migration ran.** See
   `docs/BACKUP_AND_RESTORE.md`.
3. **Document the incident** — what was lost, what wasn't.
4. **Plan a fix-forward migration** rather than re-attempting the
   broken one.

This path is a customer-comms incident; the engineer running it
should not also be the one writing the post-mortem.

---

## What we never do during a rollback

- `git push --force` to a release tag
- `DROP COLUMN` / `DROP TABLE` to "undo" an additive migration —
  leave the column, the old code ignores it
- Re-run a migration that failed halfway without first restoring the
  DB to the pre-migration state
- Skip the smoke test "because it's just a hotfix"

---

## Related runbooks

- `docs/BACKUP_AND_RESTORE.md` — Postgres + MinIO backup + restore drills (RPO 15min / RTO 2h)
- `docs/HARDWARE_DECISIONS.md` — every place we picked a lightweight option over a heavy ML dep
- `docs/ADVERSIAL_AUDIT.md` — the full self-audit + remediation log
