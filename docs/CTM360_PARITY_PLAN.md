# Argus → CTM360 Parity Plan

**Companion to:** `CTM360_GAP_ANALYSIS.md`
**Author:** Arjun
**Date:** 2026-04-28
**Goal:** Achieve full software parity with CTM360, sequentially, with zero stubs.

---

## 0. Guiding Principles (non-negotiable)

1. **No stubs, no mocks, no "TODO later".** Every shipped module:
   - Persists to real Postgres tables
   - Has full CRUD API with auth + tenant scoping
   - Has a working dashboard page (Next.js, design-system compliant)
   - Has integration tests against a real test DB (no in-memory shortcuts)
   - Has at least one end-to-end happy-path test
   - Has structured logs + Prometheus metrics
   - Has docs in `/docs/modules/<name>.md` (dev + ops)
2. **Argus is proprietary IP.** OSS components are *libraries / dependencies* (MIT/Apache only — no AGPL/GPL contamination of core). Copyleft tools that we *use as separate services* (e.g. nothing planned currently) must be reviewed legally before adoption.
3. **OSS-first toolbelt.** Every external need is satisfied by OSS unless explicitly justified.
4. **Tenant-isolated by default.** Every new model gets `organization_id` + RLS policy + tested isolation.
5. **Production-grade from commit #1.** No "we'll harden later." Configs, secrets, retries, timeouts, idempotency, observability — baked in.
6. **Demo-able at the end of every phase.** Each phase ends with a demo script in `/scripts/demo/<phase>.sh` that boots clean and shows the new capability.
7. **Sequential, not parallel.** One phase at a time. We finish, harden, demo, then move on.

---

## 1. Dependency Graph (why this order)

```
Phase 0 ── Foundations ─────────────────────────────────────────┐
   ├─ Asset Registry (X1)         everything below needs this   │
   ├─ Onboarding Wizard (X2)      way to get assets in          │
   ├─ Evidence Vault (X3)         proof storage for findings    │
   ├─ Case Management (X4)        workflow on findings          │
   ├─ Notification Router (X5)    delivery layer                │
   └─ MITRE ATT&CK Taxonomy (M20) tagging for everything below  │
                                                                │
Phase 1 ── External Surface ────── needs Phase 0 ───────────────┤
   ├─ EASM continuous (M1)                                      │
   ├─ DeepScan (M3)                                             │
   └─ Security Rating engine (M2) needs M1 + DMARC + breaches   │
                                                                │
Phase 2 ── DMARC360 (M23-M27) ─── independent ─────────────────┤
                                                                │
Phase 3 ── Brand Protection ────── needs Phase 0 ───────────────┤
   ├─ Newly-registered domains (M14)                            │
   ├─ Typosquat / lookalike (M9)                                │
   ├─ Live phishing classifier (M8)                             │
   ├─ Logo / visual abuse (M10)                                 │
   └─ Brand Protection umbrella view (M7)                       │
                                                                │
Phase 4 ── Social & Impersonation ─ needs Phase 0+3 ────────────┤
   ├─ Social media scrapers (M11)                               │
   ├─ Executive impersonation (M12)                             │
   ├─ Online anti-fraud (M13)                                   │
   └─ Mobile app store (M17)                                    │
                                                                │
Phase 5 ── Data Leakage Hardening ─ enhances existing ──────────┤
   ├─ Credit card leakage (M15)                                 │
   └─ External DLP w/ customer policies (M16)                   │
                                                                │
Phase 6 ── Threat Intel Polish ──── needs M20 ──────────────────┤
   ├─ Actor playbooks (M18)                                     │
   ├─ Hardening guidelines agent (M19)                          │
   ├─ Cloud hunt library (M22)                                  │
   └─ NVD+EPSS feed (M34)                                       │
                                                                │
Phase 7 ── GRC / TPRM ───────────── needs Phase 0 ──────────────┤
   ├─ Vendor model + scorecard (M28)                            │
   ├─ Supply chain monitor (M29)                                │
   ├─ ESPM rollup (M30)                                         │
   ├─ Questionnaires (M31)                                      │
   └─ Vendor onboarding workflow (M32)                          │
                                                                │
Phase 8 ── News & Advisories ───── independent ────────────────┤
   ├─ News aggregator (M33)                                     │
   └─ Advisories publishing (M35)                               │
                                                                │
Phase 9 ── Lifecycle ────────────── needs Phase 0 ──────────────┤
   └─ Issue mgmt SLA + ticketing (M36)                          │
                                                                │
Phase 10 ── External Surfaces ─── productization ──────────────┤
   ├─ Public API + rate limits (M40)                            │
   └─ Takedown partner integration (M38)                        │
                                                                │
Phase 11 ── Cross-cutting Hardening ───────────────────────────┘
   ├─ SLA + exec PDF reports (X6)
   ├─ RLS audit + tenant isolation tests (X8)
   └─ Compliance hooks: SOC2/ISO27001 evidence (X9)
```

**Service-only items deferred indefinitely:** M37 (24/7 CIRT staffing), M39 (sinkhole authority), M41 (Community Edition — marketing decision).

---

## 2. Per-Phase Plan

Each phase below has the same structure:
- **Scope** — exactly what ships
- **OSS libraries** — pinned dependencies (versions resolved at start of phase)
- **DB models** — new tables/columns
- **API routes** — new endpoints
- **Dashboard pages** — new UI
- **Background jobs** — schedulers/workers
- **Tests** — what must pass
- **Exit criteria** — demo bar before moving on

---

### PHASE 0 — Foundations (≈ 2 weeks)

**Why first:** Every later phase needs an asset to monitor, a place to store evidence, a workflow to manage findings, and a way to tag with ATT&CK. Building these later means rewriting earlier code.

**Scope**
- **Asset Registry (X1):** unified entity model — domain, ip_range, executive, brand, mobile_app, social_handle, vendor, email_domain. Each with ownership, tags, criticality, monitoring profile.
- **Onboarding Wizard (X2):** 5-step Next.js flow — org details → domains → executives → brands → vendors. Persists to Asset Registry. Bulk CSV import + validation. Auto-discovery offer (kicks off Amass on confirmed root domain).
- **Evidence Vault (X3):** S3-compatible storage abstraction (default: filesystem, optional MinIO). Stores: screenshots (Playwright), HTML snapshots, WHOIS history JSON, DNS history, takedown proof PDFs. Hash-addressed, immutable, audit-logged.
- **Case Management (X4):** Case = group of related findings. States: `open → triaged → in_progress → remediated → verified → closed`. Analyst assignment, comment thread, audit trail. Findings auto-link via correlation_agent.
- **Notification Router (X5):** Severity-based fanout via pluggable adapters: email (SMTP), Slack (webhook), Microsoft Teams (webhook), generic webhook, **Jasmin SMS Gateway** (self-hosted, Apache 2.0 — sovereign SMS via customer's own SMPP carrier link), PagerDuty (webhook), Opsgenie (webhook). Per-tenant rules: `if severity >= high AND asset.criticality == crown_jewel → page on-call`. No proprietary SMS providers (Twilio, etc.) — sovereignty mandate.
- **MITRE ATT&CK Taxonomy (M20):** Sync MITRE Enterprise + Mobile + ICS matrices via `mitreattack-python`. First-class table. Every Alert, IOC, Actor, Finding gets `attack_techniques: text[]`. Triage agent enforced to populate. Dashboard filters by tactic/technique.

**OSS libraries**
- `mitreattack-python` (Apache 2.0)
- `boto3` (Apache 2.0) for S3-compatible client → MinIO server (Apache 2.0, deployed in docker-compose)
- `jasmin-sms-gateway` (Apache 2.0) — deployed in docker-compose with SMPP route to customer's carrier
- `slack-sdk`, `pdpyras` (PagerDuty), `opsgenie-sdk` (all MIT/Apache 2.0)
- `playwright` (Apache 2.0) for screenshots
- `python-whois` + `dnspython` (BSD/MIT)

**DB models (new tables)**
- `assets` (polymorphic via `asset_type`)
- `asset_relationships`
- `evidence_blobs` (hash, type, blob_uri, captured_at, finding_id)
- `cases`, `case_findings`, `case_comments`, `case_audit_log`
- `notification_rules`, `notification_deliveries`
- `mitre_techniques`, `mitre_tactics`, `mitre_mitigations`

**API routes**
- `/v1/assets` (CRUD + bulk + discover)
- `/v1/onboarding/{step}`
- `/v1/evidence/{hash}` (GET, signed URL)
- `/v1/cases` + `/v1/cases/{id}/findings`, `/comments`, `/transitions`
- `/v1/notifications/rules` + `/test`
- `/v1/mitre/techniques`, `/tactics`

**Dashboard pages**
- `/onboarding` — wizard
- `/assets` — table + detail + bulk import
- `/cases` — kanban + list + detail
- `/settings/notifications`
- Existing `/alerts` enhanced: ATT&CK badge column + filter

**Background jobs**
- MITRE sync — daily cron
- Asset health check — hourly (resolves DNS, refreshes WHOIS)

**Tests**
- pytest: 90%+ coverage on new modules
- Integration: full onboarding flow E2E (Playwright on dashboard)
- Tenant isolation: cross-tenant access denied test on every new endpoint

**Exit criteria**
1. Can onboard a new org from scratch in <5 min via wizard
2. Asset shows up, asset health job runs, evidence captured on first finding
3. A finding flows: alert → case → notification → analyst → close, with ATT&CK tag
4. `scripts/demo/phase0.sh` runs clean on fresh `docker compose up`

---

### PHASE 1 — External Surface Mastery (≈ 2 weeks)

**Scope**
- **EASM continuous (M1):** Amass + Subfinder + httpx + naabu pipeline. Per-asset scheduled discovery (subdomains, live hosts, open ports, tech stack via httpx + Wappalyzer fingerprints). Diff-based change detection → alert on new asset/cert/port. Asset graph visualizer.
- **DeepScan (M3):** Nuclei (already integrated) extended with scheduled profiles per asset criticality. Adds `nmap` for service-version + `testssl.sh` for cert/cipher posture.
- **Security Rating (M2):** A–F letter grade per org and per vendor. Inputs: open ports, expired/weak certs, exposed admin panels, known CVEs on detected versions, DMARC posture (Phase 2 hook), breach data exposure, dark-web mentions. Documented scoring rubric + per-factor weights, all visible in UI ("why is my grade B?").

**OSS libraries**
- `amass`, `subfinder`, `httpx`, `naabu`, `nuclei` (ProjectDiscovery, MIT)
- `nmap` (binary) + `python-nmap` wrapper
- `testssl.sh` (GPLv2 — used as binary, not linked, OK)
- `wappalyzer-python` (MIT)

**DB models**
- `easm_scans`, `easm_findings`, `asset_changes`
- `security_ratings` (org_id, score, grade, factors_json, computed_at)

**API routes**
- `/v1/easm/scan` (manual trigger), `/v1/easm/findings`
- `/v1/ratings/self`, `/v1/ratings/{vendor_id}`
- `/v1/ratings/{id}/explain` (factor breakdown)

**Dashboard pages**
- `/attack-surface` — graph + list, change feed
- `/security-rating` — grade badge, factor breakdown chart, history line

**Background jobs**
- EASM scan scheduler (per-asset cadence)
- Rating recompute (nightly + on-finding-change)

**Tests**
- Real Amass run in CI against a controlled test domain
- Rating reproducibility: same inputs → same grade

**Exit criteria**
1. Add a new domain → 1 hour later attack-surface populated, security rating computed
2. Introduce a deliberate exposure (open port) → next scan flags it, rating drops, alert fires, case opens
3. Rating UI explains every factor

---

### PHASE 2 — DMARC360 (≈ 1.5 weeks)

**Scope**
- **DMARC RUA/RUF ingestion (M25):** SMTP receiver (`aiosmtpd`) + IMAP poller. `parsedmarc` for parsing. Forensic + aggregate reports stored.
- **DMARC implementation wizard (M23):** UI walks user through SPF/DKIM/DMARC records for a domain. Generates exact DNS records.
- **DMARC optimization engine (M24):** Recommends `p=none → quarantine → reject` progression based on alignment trends.
- **SPF/DKIM live validation (M27):** dnspython-based checker, run hourly, alert on drift.
- **Email sending trends (M26):** dashboards on top of M25.

**OSS libraries**
- `parsedmarc` (Apache 2.0), `aiosmtpd` (Apache 2.0), `dnspython` (ISC), `imap-tools` (Apache 2.0)

**DB models**
- `dmarc_reports_aggregate`, `dmarc_reports_forensic`, `email_auth_status`

**API routes**
- `/v1/dmarc/reports` + filters
- `/v1/dmarc/wizard/{domain}` (returns recommended records)
- `/v1/dmarc/optimize/{domain}` (recommendation)

**Dashboard pages**
- `/dmarc` — overview, per-domain detail, RUA timeline, sources map, wizard, optimization recommendation

**Background jobs**
- IMAP poller (every 5 min)
- SPF/DKIM hourly validation per domain

**Exit criteria**
1. Customer points DMARC RUA mailbox at our endpoint, reports appear within 1 hour
2. Wizard generates correct records that pass external validators (Mxtoolbox)
3. SPF drift introduced → alert fires within 1 hour

---

### PHASE 3 — Brand Protection (≈ 3 weeks)

**Scope**
- **Newly-registered domain feed (M14):** CertStream WS consumer + WhoisDS daily list. All new domains hit a per-tenant matcher.
- **Typosquat/lookalike/homoglyph (M9):** dnstwist for permutation generation. Match against new domains in real-time.
- **Live phishing classifier (M8):** When a suspect domain appears, headless Playwright fetch, screenshot, HTML, DOM. Classifier: keyword + ML (lightweight DistilBERT fine-tuned on PhishTank dataset, run locally via HF transformers — Apache 2.0).
- **Logo / visual abuse (M10):** OpenCLIP embeddings of the suspect page screenshot vs registered customer logos. FAISS cosine search. Threshold-tuned alert.
- **Brand Protection umbrella view (M7):** dashboard rolling up M8–M10 + M14 + M11 (Phase 4).

**OSS libraries**
- `certstream-python` (MIT), `dnstwist` (Apache 2.0), `playwright`, `transformers` + `torch` (Apache 2.0/BSD), `open_clip_torch` (MIT), `faiss-cpu` (MIT)

**DB models**
- `brand_assets` (logo blobs, registered name strings)
- `domain_observations` (every newly-seen domain)
- `phishing_findings`
- `logo_match_findings`
- `clip_embeddings` (vector via pgvector)

**API routes**
- `/v1/brand/assets`
- `/v1/brand/findings`
- `/v1/domains/observations`

**Dashboard pages**
- `/brand-protection` — overview
- `/brand-protection/domains`, `/phishing`, `/logo-abuse`

**Background jobs**
- CertStream consumer (always-on)
- WhoisDS daily downloader
- Phishing fetch+classify worker

**Exit criteria**
1. Register `argus-test-typo.com` (or controlled lookalike) → it appears as a finding within 60s of cert issuance
2. Stand up a fake phishing page using customer logo → logo match flags it, screenshot captured in evidence vault, case opened
3. False positive rate <10% on a 100-domain canary set

---

### PHASE 4 — Social & Impersonation (≈ 3 weeks)

**Scope**
- **Social media scrapers (M11):** snscrape (Twitter/X), Telethon (Telegram public), instaloader (Instagram public), discord.py (public servers Argus is invited to), tiktok-api, youtube-search-python. Per-platform worker. Rate-limit safe.
- **Executive impersonation (M12):** VIP registry (Phase 0 asset type). For each VIP: name, aliases, photos. InsightFace face embeddings. Match against scraped profile photos. Bio fuzzy match (rapidfuzz).
- **Online anti-fraud (M13):** Investment-scam keyword classifier + crypto wallet/Telegram channel watcher (cross-ref TRM/Chainalysis OSS lists where free).
- **Mobile app store (M17):** google-play-scraper + app-store-scraper. Daily search by brand name + developer name. Match unauthorized apps.

**OSS libraries**
- `snscrape` (GPLv3 — *used as binary CLI subprocess only, no link contamination, but reviewed*)
  - **License risk:** snscrape is GPLv3. Decision: invoke as subprocess only, never import. Document this carefully. **Alt path:** drop snscrape and use Twitter/X API w/ paid tier — slower to implement but cleaner. **Krishna decision needed at start of Phase 4.**
- `Telethon` (MIT), `instaloader` (MIT), `discord.py` (MIT), `google-play-scraper` (MIT), `app-store-scraper` (MIT)
- `insightface` (MIT), `rapidfuzz` (MIT)

**DB models**
- `social_handles` (asset_type extension), `vip_profiles`, `impersonation_findings`
- `face_embeddings` (pgvector)
- `app_store_findings`

**Dashboard pages**
- `/impersonation` — exec impersonation, social fraud, rogue apps tabs

**Exit criteria**
1. Register a VIP with photo → create impersonation profile on Twitter test account → flagged within 1 hour
2. Publish a controlled lookalike app → detected on next daily run
3. Investment-scam Telegram channel using brand name → flagged

---

### PHASE 5 — Data Leakage Hardening (≈ 1.5 weeks)

**Scope**
- **Credit card leakage (M15):** BIN database (free Bin-list-data dataset). Stealer crawler enriched: extract CC numbers (Luhn-validated), match BIN → bank → tenant. Per-bank dashboard.
- **External DLP w/ customer policies (M16):** Tenant-defined keywords/regex/yara rules. Engine runs against paste sites, dark web, public GitHub (already partial), code-search APIs.

**OSS libraries**
- `bin-list-data` (CC0), `yara-python` (Apache 2.0)
- GitHub search via PAT (free tier sufficient)

**Exit criteria**
1. Plant a known test CC (controlled) on monitored paste site → flagged + bank-tagged within 30 min
2. Customer creates a custom regex policy → next match alerts within crawl cycle

---

### PHASE 6 — Threat Intel Polish (≈ 2 weeks)

**Scope**
- **Actor playbooks (M18):** Per-actor structured profile: aliases, TTPs (ATT&CK techniques), associated malware, victim list (sectors + geos), known infra IOCs. Auto-populated from MITRE Groups + correlation agent.
- **Hardening guidelines agent (M19):** LLM agent maps detected exposures → CIS Controls v8 + MITRE D3FEND mitigations. Output: prioritized remediation playbook per finding.
- **Cloud hunt library (M22):** Curated Sigma + Prowler + CloudSploit checks bundled as "hunts." Schedulable.
- **NVD + EPSS feed (M34):** Full NVD JSON 2.0 mirror. EPSS daily download. CVE detail page with exploit-likelihood.

**OSS libraries**
- `mitreattack-python` (already in P0), CIS Controls JSON (open), D3FEND ttl mappings (open)
- `nvdlib` (MIT), EPSS CSV (FIRST.org)

**Exit criteria**
1. Pick any actor in `/actors/{id}` → playbook page shows full TTP profile
2. Any finding has a "Hardening" tab with prioritized actions
3. Search any CVE → see EPSS score + KEV status + version-aware affected assets

---

### PHASE 7 — GRC / TPRM (≈ 4 weeks)

**Scope**
- **Vendor model + scorecard (M28):** Vendor as a first-class asset (already in P0 registry). Auto-EASM + DMARC + ratings on vendor's external footprint. Vendor scorecard = security rating + questionnaire score + breach exposure.
- **Supply chain monitor (M29):** Vendor's vendors (4th party) discovery via tech-stack fingerprinting (httpx + builtwith).
- **ESPM rollup (M30):** Combined view across all vendors.
- **Questionnaires (M31):** Form builder. Templates: SIG Lite, SIG Core, CAIQ v4, custom. Send → vendor portal → fills → evidence upload → analyst review.
- **Vendor onboarding workflow (M32):** Multi-step: invite → questionnaire → review → score → approve/reject. Reuse Shuffle integration as workflow substrate where appropriate (or native FastAPI workflow if cleaner).

**OSS libraries**
- SIG/CAIQ public templates (open standards)
- `pydantic` form schemas, native React form builder

**Exit criteria**
1. Add vendor → trigger SIG Lite → vendor receives portal link → fills → analyst reviews → scorecard published
2. ESPM rollup shows portfolio of 10 vendors with grades

---

### PHASE 8 — News & Advisories (≈ 1 week)

**Scope**
- **News aggregator (M33):** RSS pull from CISA, US-CERT, NCSC, vendor PSIRTs, Krebs, BleepingComputer, TheHackerNews. LLM relevance scoring per tenant (matches their tech stack from EASM).
- **Custom advisories (M35):** Editorial CMS. Argus team can publish advisories. Tenants subscribe.

**OSS libraries**
- `feedparser` (BSD)

**Exit criteria**
1. CISA publishes a KEV addition → relevant tenants notified within 1 hour, scored by relevance to their stack

---

### PHASE 9 — Lifecycle & Issue Management (≈ 1.5 weeks)

**Scope**
- **Issue mgmt SLA + ticketing (M36):** Hard SLAs per severity (e.g., critical = 4h ack, 24h remediate). Breach alerts. Jira/ServiceNow/Linear bidirectional sync (OSS clients). Closed-loop verification: re-scan after remediated → auto-verify or re-open.

**Exit criteria**
1. Critical finding → SLA timer starts → Jira ticket opens → analyst remediates → re-scan verifies → case closes, all logged

---

### PHASE 10 — External Surfaces (≈ 2 weeks)

**Scope**
- **Public API (M40):** Rate-limited, API-key auth, full OpenAPI spec. SDKs for Python + Go (auto-gen from OpenAPI).
- **Takedown partner integration (M38):** Adapter pattern. Phase-1 partner = Netcraft (or chosen vendor). Submit-takedown action from any phishing/impersonation finding → routes to partner API → tracks status → stores proof in evidence vault. *Bundle commercial as "unlimited managed takedowns" — Krishna negotiates partner terms separately.*

**Exit criteria**
1. External developer hits public API w/ key, retrieves their findings
2. From a phishing finding, click "Takedown" → ticket created at partner → status tracked → proof stored on success

---

### PHASE 11 — Cross-cutting Hardening (≈ 2 weeks)

**Scope**
- **SLA + exec PDF reports (X6):** Monthly KPI digest (PDF + email). Custom reports via existing `reports` route.
- **RLS audit + tenant isolation tests (X8):** Property-based tests proving no cross-tenant leak on every endpoint. Postgres RLS enforced.
- **Compliance hooks (X9):** Audit log shape compatible with SOC2 evidence export. Backup/restore docs. Encryption-at-rest verified.

**Exit criteria**
1. SOC2 readiness checklist 100% green
2. Pen-test of tenant isolation passes
3. Exec PDF auto-mails on the 1st of each month

---

## 3. Total Realistic Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| 0 | 2.0 wks | 2 |
| 1 | 2.0 wks | 4 |
| 2 | 1.5 wks | 5.5 |
| 3 | 3.0 wks | 8.5 |
| 4 | 3.0 wks | 11.5 |
| 5 | 1.5 wks | 13 |
| 6 | 2.0 wks | 15 |
| 7 | 4.0 wks | 19 |
| 8 | 1.0 wks | 20 |
| 9 | 1.5 wks | 21.5 |
| 10 | 2.0 wks | 23.5 |
| 11 | 2.0 wks | **~25.5 weeks** |

**~6 months end-to-end for full CTM360 software parity, no shortcuts, prod-grade.** Phase 0–3 (≈ 8.5 wks) gives a *demo-credible product* for the lead.

---

## 4. Decisions Needed From Krishna Before Starting

These will block specific phases — get answers in writing before each phase starts.

1. **[Now / Phase 0]** Confirm proprietary license stays on Argus, OSS used as deps only — **CONFIRMED 2026-04-28**.
2. **[Phase 0]** SMS provider — **DECIDED: Jasmin SMS Gateway** (OSS, self-hosted, sovereign).
3. **[Phase 0]** Evidence vault — **DECIDED: MinIO** from day one (build-for-the-future doctrine, no filesystem fallback).
4. **[Phase 1]** Security Rating rubric — **DECIDED: production rubric grounded in Mozilla Observatory + SSL Labs + NIST CSF 2.0 + MITRE D3FEND + CISA KEV + FIRST EPSS.** Documented in `/docs/security-rating-rubric.md`, no draft phase.
5. **[Phase 4]** snscrape (GPLv3 subprocess) vs paid Twitter/X API. Recommend Twitter API official to keep license clean. Cost + decision needed.
6. **[Phase 4]** VIP photos — who registers them and how is consent + data-retention handled?
7. **[Phase 7]** Questionnaire vendor portal — does it need its own domain (e.g., `vendors.argus.gaigentic.ai`)?
8. **[Phase 10]** Takedown partner — Netcraft / PhishLabs / regional. Krishna negotiates.

---

## 5. Working Convention

- Branches: `phase-N/<module>-<slug>` (e.g., `phase-0/asset-registry`)
- One PR per module within a phase. PR template includes: scope, OSS deps added, migrations, tests, demo screenshot.
- Phase completion = a tagged release `v0.<phase>.0` + merged demo script.
- Daily ChaosBird update from me to Krishna with commits + blockers.

---

*Plan complete. Sequential. No stubs. OSS as dependencies. Argus stays proprietary IP.*
