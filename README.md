# Argus

**The All-Seeing Guardian** — Digital Risk Protection + Threat Intelligence platform.

Argus is **single-tenant, on-prem only**. One customer per docker install (or any docker-compatible cloud — Railway, Fly, ECS, GKE Autopilot, k3s on a VPS). The customer owns the Postgres, the MinIO, the Ollama, and every container. There is no shared SaaS data plane. There is no multi-tenant SaaS roadmap; this is not the product. The Postgres schema carries an `Organization` row because every domain table FKs it, but operationally there is exactly one such row per install, derived from the system tenant context — the API never accepts `org_id` from clients.

## Capability matrix

| Phase | Module | Status | Notes |
|---|---|---|---|
| 0.1 | Asset registry + onboarding wizard | ✅ Backend | Domains, IPs, services, exec profiles, social handles, mobile apps |
| 1.1 | EASM (subdomain / ports / HTTPX / DNS / WHOIS / TLS / vuln scan) | ✅ Backend | subfinder + naabu + httpx + nmap + nuclei + testssl runners. All five binaries are pinned and installed in the runtime image. |
| 1.2 | Discovery findings → asset promotion | ✅ Backend | NEW → CONFIRMED workflow + AssetChange diff log |
| 1.3 | Security ratings (org + vendor) | ✅ Backend | Multi-pillar rubric v1.1; breach + dark-web pillars are computed against real card-leakage / DLP / DMARC / raw-intel data — no placeholder constants. |
| 2.1 | Threat-intel feeds (KEV, EPSS, NVD, GreyNoise, OTX, Ransomware, Stealer) | ✅ Backend | Polling + dedup + IOC normalisation. Missing API keys persist a `feed_health` row (`status=unconfigured`) so a misconfigured feed surfaces in the dashboard, never as a silent zero. |
| 2.2 | Underground crawlers (Tor, I2P, Lokinet, Telegram, Matrix, ransomware leak sites, stealer markets, forums) | ✅ Backend | The scheduler reads `crawler_targets` rows from the database on every tick. With no targets registered, the crawler skips and writes a `feed_health` row of `status=unconfigured` rather than running with empty configs. Targets are managed via `/api/v1/admin/crawler-targets`. |
| 3.1 | DMARC360 — DMARC/SPF/DKIM ingestion + scoring | ✅ Backend | Aggregate report parser, wizard generator |
| 3.2 | Brand protection — typosquats, suspect domains, CertStream | ✅ Backend | DNSTwist permutations driven by the Public Suffix List (~1500 TLDs) instead of a 23-entry hardcoded tuple. Subsidiary allowlist consulted before creating a SuspectDomain row, so the customer's own subsidiaries don't self-flag. |
| 3.3 | Phishing/abuse classification | ✅ Backend | Pure-Python heuristic. CLIP/DistilBERT swappable — see `docs/HARDWARE_DECISIONS.md`. |
| 3.4 | Logo abuse | ✅ Backend | pHash + dHash + aHash + colour-histogram. Brand overview surfaces a `logo_corpus_health` field so an empty logo corpus produces a visible warning instead of silent "no matches". |
| 4.1 | Social impersonation matcher | ✅ Backend | rapidfuzz over name/handle/bio + photo hash; verified-account suppression. |
| 4.2 | VIP / executive impersonation | ✅ Backend (lightweight) | Scoring is rapidfuzz + photo pHash, ~85% recall per `docs/HARDWARE_DECISIONS.md`. The InsightFace upgrade path is documented but not in the default deploy — operators who need face-recognition-grade accuracy enable it via that doc. |
| 4.4 | Mobile app store coverage | ⚠️ Schema + scrapers | Google Play scraper integrated; iOS via iTunes Search API. Customer-configured per-org. |
| 5.1 | Card / BIN leakage | ✅ Backend | Luhn + DB-backed BIN registry + lifecycle state machine. PAN regex matches space, hyphen, dot, and Unicode-dash separators (e.g. `4111.1111.1111.1111`). Full PAN never persisted — only `sha256(PAN) + first6 + last4`. |
| 5.2 | Custom DLP regex policies | ✅ Backend | Static rejector covers nested quantifiers, alternation overlap (`(a\|aa)+`), backreference repetition, and a complexity budget. Runtime evaluation under a 0.5 s wall-clock cap; offending policy auto-disables. |
| 6   | NVD + EPSS hardening recommendations | ✅ Backend | CVE → product mapping, hardening playbook |
| 7   | TPRM (vendor scorecards + questionnaires) | ✅ Backend | Vendor-scoped exposures + governance pillars |
| 8   | News & advisories | ✅ Backend | RSS/Atom/JSON-Feed parser, relevance scoring |
| 9   | SLA + Cases + Tickets | ✅ Backend | Per-severity SLA policy, breach evaluation, MITRE attach |
| 10  | Takedown + escalation | ✅ Backend | Five real adapters: `manual`, `netcraft` (REST), `phishlabs` (RFC-822 mailbox submission), `group_ib` (RFC-822 mailbox submission), `internal_legal` (multi-recipient SMTP + Jira issue). Each adapter refuses to dispatch when its credentials are missing — no silent successes. |
| 11  | Notifications | ✅ Backend | Email, Slack, Teams, Webhook, PagerDuty, Opsgenie, Jasmin SMS. SSRF guards on save and update. |
| 12  | Frontend | ⚠️ In progress | Onboarding + admin settings; remaining phases pending. |

## Production posture

- **Single-tenant runtime context.** The API derives the active organisation from `src/core/tenant.py` — clients never pass `org_id`. `/organizations/` returns the single row; `/organizations/current` and `/organizations/{id}` resolve to the same record.
- **LLM defaults to local Ollama.** `ARGUS_LLM_PROVIDER=ollama` in `.env.example`; raw intel and asset metadata never leave the host on a default install. Pointing the LLM at any third-party SaaS requires the operator to set both `ARGUS_LLM_BASE_URL` and `ARGUS_LLM_API_KEY` — agents refuse to dispatch without credentials.
- **Auth.** JWT (HS256 pinned) + Argon2id (t=3, m=64 MiB, p=4) password hashing; the API refuses to start without `ARGUS_JWT_SECRET`. TOTP-based 2FA via `pyotp`; recovery codes argon2-hashed at rest.
- **Schema.** alembic-managed; `metadata.create_all` removed from production boot. The latest migration adds the four operator-tunable runtime tables: `app_settings`, `crawler_targets`, `feed_health`, `subsidiary_allowlist`.
- **Telemetry.** Structured JSON logs (request-id bound), Prometheus `/metrics` endpoint with HTTP histogram + worker counters.
- **Security headers.** HSTS, CSP `default-src 'none'`, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy `no-referrer`, Permissions-Policy, COOP, CORP — installed by middleware on every response.
- **Secrets.** `docker-compose.yml` uses fail-closed `${VAR:?}` references; no committed defaults.
- **SSRF guards.** Notification webhook URLs validated against private/loopback/link-local/AWS+GCP+Azure metadata IPs on save and update; cloud-metadata hostnames blocked.
- **Upload safety.** python-magic byte sniffing, denylist for executables; per-route size limits + global 64 MB body cap.
- **XML safety.** defusedxml everywhere a feed or DMARC report is parsed.
- **No silent zeros.** Every feed run records a `FeedHealth` row (`ok`, `unconfigured`, `auth_error`, `network_error`, `rate_limited`, `parse_error`, `disabled`). Every nuclei / prowler scan failure raises `ScanFailed`/`BinaryNotFound`/`ScanTimedOut` — callers can no longer mistake "no findings" for "binary missing". Brand overview reports `logo_corpus_health` so an empty corpus surfaces visibly.
- **No hardcoded thresholds.** Operator-tunable values (fraud thresholds, impersonation cutoffs, rating pillar weights, brand similarity cutoffs, classifier confidence floors, auto-case severities) live in the `app_settings` table and are edited via the admin dashboard. Detector code reads via `src.core.app_settings.get_setting(db, org, key, default=…)` — the in-code default ships as the seed value, but every value is live-editable.
- **Subsidiary allowlist.** The brand-typosquat scanner consults `subsidiary_allowlist` before creating a `SuspectDomain` row; the customer's own subsidiaries (and any explicitly-trusted domains) are excluded from the result set.
- **Public Suffix List.** TLD-swap permutations span the full PSL ICANN suffix universe (1500+ entries) plus a phisher-favourite bias list — the previous 23-entry hardcoded tuple is gone.

## Deployment

Self-hosted via Docker Compose. The customer owns Postgres, MinIO, Ollama, and every running container.

```bash
cp .env.example .env
# Required values:
#   ARGUS_JWT_SECRET                    (≥ 64 hex chars)
#   ARGUS_DB_PASSWORD                   (Postgres)
#   MINIO_ROOT_USER, MINIO_ROOT_PASSWORD
#   ARGUS_EVIDENCE_ACCESS_KEY/SECRET_KEY
docker compose up -d
docker compose run --rm argus-api alembic upgrade head
# Bootstrap the (single) Organization row:
curl -X POST http://localhost:8000/api/v1/organizations/ \
    -H "Authorization: Bearer $ADMIN_JWT" \
    -d '{"name":"My Bank","domains":["mybank.com"]}'
```

## Operator-facing admin endpoints

All runtime configuration is DB-driven and exposed via `/api/v1/admin/`:

- `GET  /admin/settings`              list every tuned threshold/weight
- `PUT  /admin/settings/{key}`        upsert a typed setting (string/int/float/bool/json)
- `DELETE /admin/settings/{key}`      remove a setting (revert to in-code default)
- `GET  /admin/crawler-targets`       list registered crawler targets
- `POST /admin/crawler-targets`       register a target (kind + identifier + JSON config)
- `PATCH /admin/crawler-targets/{id}` update display name / config / activation
- `DELETE /admin/crawler-targets/{id}`
- `GET  /admin/feed-health`           latest health row per feed (drives the dashboard panel)
- `GET  /admin/feed-health/{feed}`    history for one feed (default 100 rows)
- `GET  /admin/subsidiary-allowlist`  list trusted brand names / domains
- `POST /admin/subsidiary-allowlist`  add a row (kind: `domain` / `brand_name` / `email_domain`)
- `DELETE /admin/subsidiary-allowlist/{id}`

Every mutation is audit-logged with full before/after JSON.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Dashboard (Next.js)                     │
├────────────────────────────────────────────────────────────┤
│                    API (FastAPI)                           │
│   /api/v1/{assets, easm, dmarc, brand, social, leakage,    │
│           tprm, news, sla, takedown, ratings, admin, ...}  │
├──────────────────────┬─────────────────────────────────────┤
│       Worker         │            Storage                  │
│  EASM tick + SLA     │  Postgres + pgvector + MinIO (S3)   │
│  evaluation +        │  Redis (rate-limit + dedupe)        │
│  crawler scheduler   │  Ollama (local LLM, optional)       │
├──────────────────────┴─────────────────────────────────────┤
│          Pluggable Adapters / OSS Runners                  │
│  subfinder · naabu · httpx · nmap · nuclei · testssl       │
│  DNSTwist · CertStream · YARA · Sigma                      │
└────────────────────────────────────────────────────────────┘
```

## Development

```bash
scripts/test-up.sh
source scripts/test-env.sh
pip install -r requirements.txt
pytest tests/
scripts/test-down.sh
```

## Tech stack

| Component | Technology |
|-----------|-----------|
| API | FastAPI (Python 3.12) |
| ORM | SQLAlchemy 2 async + asyncpg |
| Migrations | Alembic |
| Database | Postgres 16 + pgvector |
| Object storage | MinIO (S3-compatible; swappable for AWS S3 / R2 / B2) |
| Worker | Pure-asyncio loop (`python -m src.workers`) |
| Crawlers | Python + Tor (SOCKS) + httpx + Matrix Client-Server API |
| LLM | Ollama (default) — any OpenAI-compatible endpoint or Anthropic via env override |
| Search | Meilisearch |
| Dashboard | Next.js |
| Telemetry | stdlib JSON logs + `prometheus_client` |

## License

Proprietary — see `LICENSE`. Open-source dependencies retain their upstream licenses; nuclei templates pinned to a specific release tag for reproducible builds.
