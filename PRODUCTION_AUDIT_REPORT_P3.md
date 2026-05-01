# Argus / Marsad — Phase 3 Production-Readiness Audit

**Worktree:** `worktree-agent-a4141d326588ca1ed`
**Scope:** P3.2 EDR · P3.3 Email Gateway · P3.4 OpenAPI/SDKs/Feed-Sub/TAXII · P3.5 Adversary Emulation · P3.6 Sandbox · P3.7 SOAR · P3.8 Sovereign Deploy · P3.9 Breach · P3.10 Telegram · P3.11 Forensics
**Method:** Code-evidence-driven adversarial review against the C1–C15 quality gates. Auto-fixes were committed where root cause was clear and single/two-file in scope. Larger findings are reported for founder triage.

---

## 1. Executive Summary

| Severity | Count | Auto-fixed |
| --- | --- | --- |
| Showstopper | **6** | 1 (SDK TAXII path) + 1 (C6 admin gates, batched) = **2** |
| Embarrassment | **9** | 1 (MDE/Mimecast misleading-success) = **1** |
| Minor | 7 | 0 |
| Informational | 4 | 0 |

**Deal-killing? — YES, in current state.** Three independent reasons:

1. **Helm chart does not template a single P3 connector secret.** Every customer that deploys via `helm install` (which is the supported path per the spec) gets a system where EDR / email-gateway / sandbox / SOAR / breach / Telegram / forensics is silently disabled because none of `ARGUS_FALCON_*`, `ARGUS_MDE_*`, `ARGUS_HIBP_*`, `ARGUS_TELEGRAM_*`, `ARGUS_VT_*`, `ARGUS_VELOCIRAPTOR_*`, etc. are wired through `helm/argus/templates/secret.yaml`. The connectors are reachable in Docker but not in the canonical K8s deploy. **A bank trying to demo the full P3 surface from a Helm install will discover this in their first hour.**

2. **No dashboard UI for any P3 connector surface.** Search of `dashboard/src/app/**` and `dashboard/src/lib/api.ts` finds zero references to `edr`, `email-gateway`, `sandbox`, `soar`, `breach`, `forensics`, `adversary`, or `telegram`. The integrations page (`dashboard/src/app/integrations/page.tsx`) does not list any of the new P3 connectors. A CISO desk demo cannot show EDR push, sandbox detonate, breach search, or coverage scoring — only a curl-based exec can. The features exist; they are invisible.

3. **OpenAPI spec lies about TAXII path AND omits every P3 endpoint.** `clients/openapi/argus.openapi.json` advertises `/api/v1/taxii/collections/...` (the real path is `/taxii2/api/collections/...`); it contains zero `/intel/edr/*`, `/intel/email-gateway/*`, `/intel/sandbox/*`, `/intel/breach/*`, `/intel/soar/*`, `/intel/forensics/*`, `/intel/adversary-emulation/*`, `/intel/telegram/*`, or `/feed-subscriptions/*` entries. Anyone using `openapi-generator` to spin up a third-party client (which is the literal point of shipping an OpenAPI doc) gets a client that can't reach P3 at all. The two hand-written SDKs only paper over part of the surface.

The connectors themselves are well-structured, type-aware, circuit-breakered, and degrade-cleanly when unconfigured. The defects are concentrated in **the seams between code and ship-vehicle** (Helm, OpenAPI, dashboard) plus a clean cluster of **C6 admin-gating gaps** that I auto-fixed.

---

## 2. Section-per-P3-Item Findings

### P3.2 — EDR connectors

`src/integrations/edr/{base,crowdstrike,sentinelone,mde}.py` plus `src/api/routes/intel.py` lines 719–782.

- **[showstopper, FIXED]** `/intel/edr/{name}/iocs/push` and `/intel/edr/{name}/isolate` were analyst-gated. Per audit brief C6, "EDR IOC push to vendor" must be admin-gated. Pushed to admin in commit `audit-fix(P3): C6 — admin-gate vendor-side push and host-action routes`.
- **[embarrassment, FIXED]** `src/integrations/edr/mde.py:154-157` — when every supplied IOC is filtered out by `_MDE_TYPE_MAP` (e.g. `ja3`, `btc_address`, `email`), the MDE connector returned `success=True, pushed_count=0` because `success=len(ids) > 0 or first_error is None`. That tells the case copilot the push landed when nothing was posted. Now returns `success=False` with a note. Same bug pattern in `mimecast.py:193-199` — also fixed.
- **[showstopper]** No audit-log entry on EDR push or EDR isolate. Compare to `src/api/routes/auth.py` — bootstrap admin sign-in writes `AuditAction.LOGIN`. EDR isolate kicks a customer endpoint off the network and leaves no Argus-side trail. SAMA / NCA-ECC / SOC2 will fail the moment a regulator asks "who triggered the contain on host X". **Founder-triage:** add `audit_log(AuditAction.EDR_PUSH | EDR_ISOLATE, ...)` on these routes plus the corresponding migration to extend `AuditAction`.
- **[minor]** `_FALCON_TYPE_MAP` does not include `url` (line 36–43). CrowdStrike Falcon's IOC v1 surface accepts `url` (per their API docs); silently dropping it is not strictly a bug, but customer expectation is that "I push a URL IOC, it ends up on the EDR's blocklist". Tighten by adding `"url": "url"` to the Falcon map.
- **[informational]** `_TOKEN_CACHE` is a class-level dict (`crowdstrike.py:50`, `mde.py:55`). In a multi-process gunicorn deploy each worker has its own cache; the worst case is N×token-fetches-per-30-min instead of 1, well within Falcon's quota. Document or move to Redis if scaling.

### P3.3 — Email gateway connectors

`src/integrations/email_gateway/{proofpoint,mimecast,abnormal}.py` + routes `intel.py` 657–716.

- **[showstopper, FIXED]** `/intel/email-gateway/{name}/blocklist` was analyst-gated. Now admin.
- **[embarrassment]** `proofpoint.py:123-132` and `abnormal.py:121-134` — both `push_blocklist` are documented no-ops (the vendors don't expose a programmatic blocklist API). `list_available()` and `health_check` make all three connectors look equivalent. **Customer experience:** SOC analyst configures Abnormal, clicks "Push to blocklist" (when the dashboard ships), gets `success=False` despite credentials being correct. Recommend extending `list_available()` to expose `{supports_blocklist_push: bool}` so the dashboard can grey out the button. Founder-triage.
- **[informational]** Mimecast HMAC: `_headers` signs `f"{date}:{request_id}:{self._app_key}:{uri}"` per Mimecast 2.0 spec — verified correct. Header order matches Mimecast docs. No issue.

### P3.4 — OpenAPI · Python SDK · TS SDK · Feed subs · TAXII

This bucket has the worst delivery quality of P3.

- **[showstopper, FIXED]** Both Python SDK (`clients/python/argus_sdk/client.py:140,335`) and TypeScript SDK (`clients/typescript/argus-sdk/src/index.ts:254`) called `/taxii2/collections/`. The actual route is `/taxii2/api/collections/` — confirmed by `tests/test_taxii_publish.py:226,256,271,290`. Calling `client.intel.taxii_collections()` 404'd in production. Fixed in commit `audit-fix(P3): C8 — SDK TAXII path corrected`.
- **[showstopper]** `clients/openapi/argus.openapi.json` is misleading and stale:
  - Advertises `/api/v1/taxii/collections/...` (line 1 of paths grep) — wrong base path; real one is `/taxii2/...`.
  - Contains **zero** P3 connector endpoints. Search returned no `/intel/edr/*`, `/intel/email-gateway/*`, `/intel/sandbox/*`, `/intel/breach/*`, `/intel/soar/*`, `/intel/forensics/*`, `/intel/adversary-emulation/*`, `/intel/telegram/*`, or `/feed-subscriptions/*`.
  - The MEGA_PHASE deliverable for #3.4 was "OpenAPI **plus** Python SDK **plus** TS SDK". The OpenAPI artefact is only ~30% of the actual surface. **Founder-triage:** regenerate via `app.openapi()` dump or hand-add the P3 paths.
- **[showstopper]** TAXII content negotiation. `src/api/routes/taxii.py` does not enforce `Accept: application/taxii+json;version=2.1` on requests, nor does it set `Content-Type: application/taxii+json;version=2.1` on responses. Strict TAXII clients (Anomali ThreatStream, OpenCTI's TAXII consumer) reject responses lacking the precise MIME type. The deliverable is "Argus-as-a-feed beats RecordedFuture's $150K/yr Risk List subscription"; that doesn't work if Anomali can't parse the response. **Founder-triage:** `taxii.py` should `Response(media_type="application/taxii+json;version=2.1")`.
- **[embarrassment]** Missing `X-TAXII-Date-Added-First` / `X-TAXII-Date-Added-Last` response headers on `/api/collections/{id}/objects/`. Without them, polling subscribers can't compute their next `?added_after` window — they may miss IOCs whose `last_seen` was inside the cutoff window. The envelope says `more=false` so subscribers fall back to `added_after`, but they need the timestamps to set it correctly.
- **[minor]** `taxii_publish.py:47` — `_NAMESPACE = uuid.UUID("12345678-aaaa-bbbb-cccc-aaaaaaaaaaaa")`. Stable but looks like placeholder text. A real namespace UUID would project more confidence (e.g. `uuid5(uuid.NAMESPACE_URL, "argus.gaigenticai.com")`).
- **[minor]** `taxii_publish.py:111` — `x_argus_ioc_id` field on every published indicator exposes the Argus DB primary key to TAXII subscribers. Not strictly secret, but it's a database identifier; if a subscriber is compromised, the attacker now has Argus IDs they can use in a follow-up exploit. Replace with a hashed/derived id or remove.
- **[showstopper]** Feed subscriptions have **no audit log entry** on create / update / delete. Same regulator-trail problem as EDR push. `src/api/routes/feed_subscriptions.py:136-212` writes the row + commits and returns. No `AuditAction.SUBSCRIPTION_*`.
- Feed subscription tenant isolation **passes** — `_load_owned` correctly checks `sub.user_id != user_id` and 404s. `tests/test_feed_subscriptions.py:246-298` exercises this.
- Matcher (`src/core/feed_subscription_match.py`) **passes** — malformed regex fails-closed via `re.error` catch (line 104-107); missing fields default-to-None safely; `min_confidence` failure path is correct.

### P3.5 — Adversary emulation

`src/integrations/adversary_emulation/{atomic_red_team,caldera,coverage}.py`.

- **Caldera `start_operation` IS admin-gated** (intel.py:1445-1456). Verified.
- **[informational]** Curated test count check: docstring says "14-test starter set"; counted 14 entries in `_CURATED_TESTS`. Truth-in-docstring passes.
- **[minor]** `atomic_red_team.py:67` — `executor_command` includes `https://example.invalid/x.ps1`. If an analyst executes this in their lab, `example.invalid` is a non-routable TLD by RFC, so it will resolve nowhere — but it WILL trigger NXDOMAIN, EDR DNS-suspicious-domain alerts, and customer SIEM noise. That's actually the *point* of an adversary-emulation test, but document it so the operator doesn't think their EDR is broken when it fires on the curated tests.
- **[informational]** `T1078.004 (AWS ListBuckets)` and `T1110.003 (Password spray)` test commands assume the host has `aws` CLI / `curl` installed. No precondition check. Atomic Red Team's real corpus has `prereqs:` blocks that we don't honour. Acceptable for v1.

### P3.6 — Sandbox

`src/integrations/sandbox/{cape,joe,hybrid,virustotal}.py`.

- **[showstopper, FIXED]** `/intel/sandbox/{name}/submit` admin-gated (was analyst). The sandbox submit uploads the customer's binary to a third-party vendor — it's the textbook "data leaving the tenant boundary" decision.
- **VirusTotal legal gate is correctly enforced** — `is_configured()` requires both `ARGUS_VT_API_KEY` AND `ARGUS_VT_ENTERPRISE=true` (virustotal.py:56-58). Submit / report / health all fail-closed when either is missing. ✅ C12.
- **[informational]** `virustotal.py:125-128` — SHA256 detection heuristic uses `len == 64` + hex-digit check. Will mismatch for VT analysis IDs that *happen* to be 64 hex chars (none currently exist; analysis IDs are base64 of GUIDs). Acceptable.

### P3.7 — SOAR connectors

`src/integrations/soar/{xsoar,tines,splunk_soar}.py`.

- **[showstopper, FIXED]** `/intel/soar/{name}/push` admin-gated.
- **[minor]** XSOAR push does one POST per event in a loop (`xsoar.py:72-108`) inside a single circuit-breaker scope. If event #5 of 100 trips the breaker, events 6-100 are skipped and only first_error is reported. Ideally either fail-fast on the first error OR aggregate all errors. Founder-triage.

### P3.8 — Sovereign deploy guides

`docs/deploy/sovereign/{ksa,uae,qatar,eu,railway}.md` + `helm/argus/`.

- **[showstopper]** `helm/argus/templates/secret.yaml` does not pass through ANY P3 vendor env var. Searched every line — only `ARGUS_JWT_SECRET`, `ARGUS_BOOTSTRAP_*`, `ARGUS_DB_*`, `ARGUS_REDIS_URL`, `MEILI_MASTER_KEY`, `ARGUS_EVIDENCE_*`, `ARGUS_LLM_*` are templated. Missing: every `ARGUS_FALCON_*`, `ARGUS_S1_*`, `ARGUS_MDE_*`, `ARGUS_PROOFPOINT_*`, `ARGUS_MIMECAST_*`, `ARGUS_ABNORMAL_*`, `ARGUS_HIBP_*`, `ARGUS_INTELX_*`, `ARGUS_DEHASHED_*`, `ARGUS_VT_*`, `ARGUS_CALDERA_*`, `ARGUS_TELEGRAM_*`, `ARGUS_VELOCIRAPTOR_*`, `ARGUS_XSOAR_*`, `ARGUS_TINES_*`, `ARGUS_SPLUNK_SOAR_*`, `ARGUS_CAPE_*`, `ARGUS_JOE_*`, `ARGUS_HYBRID_*`. Customer must hand-patch the rendered Secret post-install. **Founder-triage:** extend `values.yaml` with a `connectors:` map and template the Secret accordingly.
- **[embarrassment]** `helm/argus/values.yaml:17,88,120,132` ships `CHANGE_ME_*` defaults. If the operator forgets to override, Helm install succeeds with a known-default JWT secret + Postgres password + Meili master key + MinIO root password in the cluster. This is an OWASP A05:2021 default-creds class issue. Founder-triage: change to `required` template directives that fail `helm install` when not overridden.
- **[informational]** Sovereign deploy guides do not mention any P3 connector envs (no grep hit for `ARGUS_FALCON / VT / TELEGRAM`). KSA/UAE customers wanting to wire Crowdstrike + Telegram won't find guidance.

### P3.9 — Breach providers

`src/integrations/breach/{hibp,intelx,dehashed}.py`.

- All three providers are circuit-breakered, fail-closed when unconfigured, parse the vendor's response shape correctly.
- HIBP password endpoint (`hibp.py:111-167`) correctly uses k-anonymity (only first-5-of-SHA1 leaves the host).
- `search_email_unified` (`__init__.py:57-85`) uses `asyncio.gather(return_exceptions=True)` so a single provider failure doesn't poison the fan-out. ✅
- **[minor]** `breach_search_password` route (`intel.py:946-956`) is analyst-gated. Defensible — k-anonymity means no PII leaves Argus — but the input is *the candidate password's SHA1*. An analyst with API access can iterate against employee passwords. Founder-triage: rate-limit per analyst to N/min.

### P3.10 — Telegram collector

`src/integrations/telegram_collector/{client,channels,language,pipeline}.py`.

- **Legal gate is correct** (`client.py:60-73`) — `is_configured()` requires `ARGUS_TELEGRAM_ENABLED=true` AND all three credential vars; integer parse on `_api_id` is hardened. Each fail-mode emits a different `_unconfigured_note()` so the dashboard can render the right CTA. ✅ C12.
- `/intel/telegram/fetch` IS admin-gated (intel.py:1531-1534). ✅ C6.
- **[minor]** `client.py:124,194` constructs `TelegramClient(_session_path(), int(_api_id()), _api_hash())` — Telethon writes to the session DB on disk. If the path is `/tmp/...`, the session can be hijacked by another tenant on a multi-tenant host. Mitigation: deploy guides should require `_session_path()` under a 0700 dir.
- **[informational]** No circuit breaker on Telethon — Telethon does its own MTProto reconnect backoff. Acceptable.

### P3.11 — Forensics tools

`src/integrations/forensics/{volatility,velociraptor}.py`.

- **[showstopper, FIXED]** `/intel/forensics/volatility/run` and `/intel/forensics/velociraptor/schedule` admin-gated.
- **[showstopper]** `volatility.run_plugin` (`volatility.py:77-164`) accepts `image_path`, `plugin`, and `extra_args` directly from the request body and passes them to a subprocess. Even with admin gating:
  - `image_path` can point at any host file the api process has read on (the `os.path.exists` check just confirms readability). An admin can effectively dump arbitrary host paths through the plugin engine.
  - `extra_args` is appended raw. Volatility 3 has flags that *write* output (`--output-dir`, `--write-config`). An admin can write attacker-chosen content to attacker-chosen host paths.
  - This is privilege amplification, even from an admin. Founder-triage: validate `plugin` against an allowlist (`{windows.pslist, windows.netscan, windows.malfind, linux.pslist, linux.bash, ...}`); reject `extra_args` items containing `/` or starting with `--output`/`--config`/`--write`; require `image_path` under a chroot directory (e.g. `ARGUS_FORENSICS_IMAGE_DIR`).
- **[minor]** `velociraptor.schedule_collection` accepts `artifact: str` and `parameters: dict[str,str]` directly. VQL artifact names are namespaced (e.g. `Windows.Sys.Programs`) but the connector does no allowlist. An admin who can SSH onto a Velociraptor server already has more power; this is defence-in-depth. Founder-triage.

---

## 3. Cross-Cutting Findings (C1–C15)

| Gate | Status | Evidence |
| --- | --- | --- |
| **C1 route registration** | ✅ Pass | `intel.py` carries every P3 endpoint; `feed_subscriptions` and `taxii_routes` are mounted at `app.py:389,413`. |
| **C3 agent boundary** | ✅ Pass | No P3 module imports `src/agents/*` or hosts an HTTP-LLM call. |
| **C6 admin auth** | ❌ → ✅ Fixed | Seven P3 routes were analyst-gated despite triggering vendor-side action; auto-fix commit promoted them to admin. |
| **C7 tenant isolation** | ✅ Pass | `feed_subscriptions.py` uses `get_system_org_id(db)` + `user_id` ownership check. `taxii.py` uses `get_system_org_id(db)`. No request-supplied `organization_id`. |
| **C8 Pydantic↔TS contract** | ⚠️ Partial | SDK TAXII path mismatch (FIXED). OpenAPI omits all P3 endpoints (NOT fixed — too large to auto-regen safely). |
| **C12 secrets surface** | ⚠️ Mixed | Connectors don't log keys ✅; Helm chart does not pass connector secrets through ❌; values.yaml ships default `CHANGE_ME_*` passwords ❌. |
| **C13 Optional[None] hardening** | ✅ Pass | aiohttp JSON parsers consistently use `(body or {}).get(...)` and `(payload or {}).get(...)`. Spot-checked Mimecast, Caldera, MDE, Velociraptor — all defensive. |
| **C14 docstring truth** | ✅ Pass | "14-test starter set" matches actual count; `_FALCON_TYPE_MAP`, `_S1_TYPE_MAP`, `_MDE_TYPE_MAP` describe the real allowlist. No P3 docstring lies found. |
| **C15 circuit breaker / rate limit** | ✅ Pass | All 17 P3 connectors that make outbound HTTP calls go through `src.core.http_circuit.get_breaker(...)`. Subprocess (Volatility) and Telethon (own backoff) excused. |

**Audit-log surface (NEW finding, C-class equivalent):** Every external-effect P3 route should write `audit_log` entries. None do. Adding this requires extending `AuditAction` enum + a migration. **Founder-triage** — most-pressing punch-list item.

---

## 4. Demo-Killer UX Inventory

1. **No dashboard surface for any P3 connector.** Cannot demo EDR push, sandbox detonate, breach search, coverage scoring, Telegram intake, Velociraptor task scheduling, or SOAR hand-off without curl. (showstopper-class for a CISO desk demo).
2. **No dashboard surface for feed subscriptions.** The whole "self-service SDK + dashboard" narrative misses the dashboard half — analysts can't see their own subscriptions in the UI.
3. **No dashboard surface for TAXII discovery.** Customer who buys "Argus as a feed" expects a "Subscribe to TAXII" page that copies the discovery URL + bearer token. Doesn't exist.
4. **No "configure connector" wizard.** Operator must hand-edit `.env` and restart. The integrations page (`dashboard/src/app/integrations/page.tsx`) doesn't offer per-connector config UX.
5. **Helm install ships default secrets without a fail-fast.** Misconfigured prod gets a JWT signing secret of `CHANGE_ME_dev_only_jwt_secret_at_least_32_chars_long` — an OWASP-tier embarrassment if the customer's SOC pen-tester finds it.
6. **`success=False, note="not configured"` is the everyday response.** With Helm not passing connector secrets, every `is_configured()` returns False, and every health/push/fetch endpoint surfaces `success=False, note="<vendor> not configured"`. The dashboard would render this everywhere by default, suggesting "the platform is broken" until the operator manually wires every Secret.

---

## 5. Final Verdict + Pre-Go-Live Punch List

**Verdict:** P3 connector code quality is solid. The deal-killers are **NOT** in the connectors — they're in the **shipping path** (Helm + OpenAPI + dashboard). Six showstoppers remain, of which two were auto-fixed; the remaining four are non-trivial to fix automatically (involve regenerating OpenAPI, building dashboard pages, extending Helm templates, extending the AuditAction model + migration).

**Before-go-live punch list (priority order):**

1. **Helm secret pass-through.** Extend `helm/argus/values.yaml` with a `connectors:` map and template every `ARGUS_*` env var into `helm/argus/templates/secret.yaml`. Without this, P3 is dark-launched on every K8s install. (~4 hours)
2. **Helm default-secret fail-fast.** Replace `CHANGE_ME_*` defaults with `required` template directives so unconfigured Helm install fails loudly rather than shipping known-default JWT/DB/MinIO passwords. (~1 hour)
3. **Audit-log every P3 push/isolate/submit/schedule route.** Extend `AuditAction` enum + alembic migration; add `audit_log(...)` calls to the seven external-effect routes. SAMA / NCA-ECC / SOC2 require this. (~3 hours)
4. **OpenAPI regeneration.** Either dump from `app.openapi()` at build-time, or hand-add the missing P3 paths to `clients/openapi/argus.openapi.json`. Also fix the `/api/v1/taxii/*` → `/taxii2/*` paths. (~3 hours)
5. **TAXII content negotiation.** Set `Content-Type: application/taxii+json;version=2.1` on collection / discovery / objects responses. Optionally enforce `Accept` header. (~1 hour)
6. **Dashboard P3 surface.** At minimum: a connector-status page that lists every connector's `is_configured()` + `health_check` outcome with a "wire credentials" CTA. Stretch: per-vendor flow pages. (~2-3 days)
7. **Volatility plugin allowlist + path chroot.** `volatility.py` accepts arbitrary plugin / extra_args / image_path. Validate plugin against `{windows.pslist, windows.netscan, windows.malfind, linux.pslist, linux.bash}`-style allowlist, reject suspicious flags, require `image_path` under `ARGUS_FORENSICS_IMAGE_DIR`. (~2 hours)

**Auto-fixed in this audit (commits on this worktree):**

- `audit-fix(P3): C8 — SDK TAXII path corrected to /taxii2/api/collections/`
- `audit-fix(P3): C6 — admin-gate vendor-side push and host-action routes` (also includes MDE/Mimecast misleading-success fix)

The platform is two solid weeks from "demo at the CISO's desk" — the connectors work, the gates fail-closed, the legal gates are honest. The shell is what's missing.
