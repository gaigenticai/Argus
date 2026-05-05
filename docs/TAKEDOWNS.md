# Takedowns — Architecture, Automation Plan & Partner Research

> Read-only audit + automation planning session. Current as of 2026-05-04.

---

## 1. What the Feature Does Today

The takedowns module is a complete ticketing system for tracking removal requests to external registrars, hosting providers, and partner abuse desks. It is **not** automated end-to-end — most steps require an analyst to click a button.

### Current Manual Workflow

| Step | Who does it | Automation hook exists? |
|---|---|---|
| File a ticket | Analyst clicks Submit | Brand Defender can auto-file (confidence ≥ 0.95) |
| Poll partner for state | Analyst clicks SYNC | No background job — purely on-demand |
| Advance state | Analyst clicks ADVANCE | Manual only |
| Escalate stale tickets | Nobody | No SLA tracking at all |
| Re-open after rejection | Analyst manually | No retry logic |

---

## 2. Full Data Model

**Core ORM Entity: `TakedownTicket`** (`src/models/takedown.py`)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK |
| `organization_id` | UUID FK | Multi-tenant scoping |
| `partner` | Enum | netcraft, phishlabs, group_ib, internal_legal, manual |
| `state` | Enum | submitted, acknowledged, in_progress, succeeded, rejected, failed, withdrawn |
| `target_kind` | Enum | suspect_domain, impersonation, mobile_app, fraud, other |
| `target_identifier` | String(500) | Domain, handle, app ID, URL, etc. |
| `source_finding_id` | UUID (nullable) | Links to suspect_domain / impersonation / mobile_app finding |
| `partner_reference` | String(255) | Ticket ID from external partner API/email |
| `partner_url` | String(500) | Deep link to partner's UI |
| `submitted_by_user_id` | UUID FK (nullable) | User who filed; null = auto-filed by Brand Defender |
| `submitted_at` | DateTime | Immutable |
| `acknowledged_at` | DateTime (nullable) | Set on transition to acknowledged |
| `succeeded_at` | DateTime (nullable) | Set on transition to succeeded |
| `failed_at` | DateTime (nullable) | Set on transition to rejected/failed |
| `needs_review` | Boolean | Auto-set by sync when partner returns unrecognized state |
| `last_partner_state` | String(64) | Raw partner state string (for debugging) |
| `proof_evidence_sha256` | String(64) | SHA256 of removal proof on succeeded |
| `notes` | Text | Accumulated notes; state transitions append `[from→to]` tags |
| `raw` | JSONB | Raw partner response payload |

**Unique constraint**: `(organization_id, target_kind, target_identifier, partner)` — prevents duplicate takedowns for the same target via the same partner.

**State machine** (`_ALLOWED_TRANSITIONS`):

```
submitted    → acknowledged, in_progress, succeeded, rejected, withdrawn, failed
acknowledged → in_progress, succeeded, rejected, failed, withdrawn
in_progress  → succeeded, rejected, failed, withdrawn
succeeded    → (terminal)
rejected     → submitted  (re-open)
failed       → submitted  (re-open)
withdrawn    → submitted  (re-open)
```

---

## 3. Backend API

**Routes** (`src/api/routes/takedown.py`):

| Method | Path | Purpose |
|---|---|---|
| GET | `/takedown/partners` | List adapters + config readiness |
| POST | `/takedown/tickets` | Create/submit new ticket |
| GET | `/takedown/tickets` | List tickets (filtered by org, state, partner, target_kind) |
| GET | `/takedown/tickets/{id}` | Single ticket detail |
| POST | `/takedown/tickets/{id}/transitions` | Advance ticket state |
| POST | `/takedown/tickets/{id}/sync` | Poll partner for live state |
| GET | `/takedown/tickets/{id}/history` | Per-ticket audit timeline |

**Sync state-mapping heuristics** (case-insensitive string matching):

| Partner string | Maps to |
|---|---|
| succeeded, removed, complete, completed, resolved | SUCCEEDED |
| rejected, denied, declined | REJECTED |
| in_progress, investigating, pending, open | IN_PROGRESS |
| acknowledged, received, ack | ACKNOWLEDGED |
| anything else | sets `needs_review=True` |

---

## 4. Adapter Architecture

Five pluggable implementations of `TakedownAdapter` (`src/takedown/adapters.py`):

### ManualAdapter
- Records ticket locally, no external transmission
- `partner_reference` = millisecond timestamp
- Always configured — no env vars required
- Use case: legal team handles off-band, Argus just records

### NetcraftAdapter
- **REST API**: `POST /takedowns` + `GET /takedowns/{id}`
- Requires: `ARGUS_TAKEDOWN_NETCRAFT_API_KEY`
- Circuit breaker: `"takedown:netcraft"`
- **Only adapter with a real status-polling API**
- Timeouts: 30s submit, 15s fetch

### PhishLabsAdapter
- **SMTP only** — no REST API
- Requires: `ARGUS_TAKEDOWN_PHISHLABS_SMTP_RECIPIENT` + SMTP config
- `partner_reference` = email Message-ID
- `fetch_status()` returns error — no polling possible

### GroupIBAdapter
- Identical to PhishLabs (mailbox-based)
- Requires: `ARGUS_TAKEDOWN_GROUPIB_SMTP_RECIPIENT` + SMTP config

### InternalLegalAdapter
- Dual transport: SMTP email + optional Jira issue creation
- Requires at least one of: SMTP recipient or Jira config
- `partner_reference` priority: Jira key > SMTP Message-ID > timestamp
- Jira: creates Task issues with labels `[argus, takedown, target_kind]`

**Submit payload** sent to every adapter:

```python
organization_id: str
target_kind: str        # suspect_domain | impersonation | mobile_app | fraud | other
target_identifier: str  # the domain, URL, handle, app ID, etc.
reason: str
evidence_urls: list[str]
contact_email: str | None
metadata: dict
```

---

## 5. Existing Automation (Brand Defender Agent)

**`_maybe_auto_file_takedown`** (`src/agents/brand_defender_agent.py`, ~line 666):

- Guards: org-level `auto_takedown_high_confidence` setting + global `allow_auto_action()` check
- Triggers when: `recommendation="takedown_now"` + `confidence >= 0.95` + no existing ticket
- Idempotency: checks unique constraint first; if duplicate exists, links action to existing ticket
- Writes directly to DB (bypasses API), `submitted_by_user_id=None` as bot-filed marker
- Notes field: `"AUTO-FILED via Brand Defender HIL bypass. action={id} confidence={conf:.2f}"`

Brand Defender recommendation values:
- `takedown_now` — live phishing verdict + age < 30 days, OR logo similarity > 0.85 + age < 30
- `takedown_after_review` — suspicious but requires analyst confirmation
- `monitor` — suspicious, insufficient evidence
- `insufficient_data` — tools failed

**Gap**: Only Brand Defender auto-files. Investigation Agent and Impersonation Agent produce high-confidence findings but are not wired to auto-file takedowns.

---

## 6. Files Involved

| File | Purpose |
|---|---|
| `src/models/takedown.py` | ORM + state machine |
| `src/api/routes/takedown.py` | REST endpoints |
| `src/takedown/adapters.py` | Pluggable partner adapters |
| `src/agents/brand_defender_agent.py` | Auto-takedown logic (lines ~666–772) |
| `dashboard/src/app/takedowns/page.tsx` | Full UI (Kanban + table, bulk ops, detail drawer) |
| `dashboard/src/lib/api.ts` | API client + TypeScript types |
| `tests/test_takedown.py` | Integration tests |

---

## 7. Automation Roadmap (Ranked by Impact)

### Priority 1 — Background Sync Worker

**The biggest gap.** `syncTicket` is click-only. Every in-flight ticket (submitted, acknowledged, in_progress) should auto-poll on a schedule.

The adapter + state-mapping heuristics already work correctly — there's just no scheduler calling them.

**Implementation sketch:**
- Celery beat task or APScheduler job
- Query all non-terminal tickets grouped by partner
- Call `adapter.fetch_status(partner_reference)` per ticket
- Apply existing state-mapping logic, commit
- Skip PhishLabs + GroupIB (no status API — `fetch_status` returns an error for both)
- Suggested cadence: every 60 minutes for Netcraft; skip SMTP-only partners entirely

---

### Priority 2 — Widen the Auto-File Net

Two gaps in the current auto-file logic:

1. **Investigation Agent + Impersonation Agent** produce high-confidence findings but are never wired to `_maybe_auto_file_takedown`. Fix: call the same auto-file function from those agents under equivalent confidence thresholds.

2. **`takedown_after_review` has no queue path.** Today it just sits in the agent result with no ticket. Fix: create a ticket in state `submitted` with `needs_review=True` so it surfaces in the dashboard Kanban for analyst review without bypassing human approval.

---

### Priority 3 — SLA Escalation / Stale Ticket Alerts

No SLA tracking exists anywhere. Tickets can sit in `submitted` for weeks silently.

**Implementation sketch:**
- Configurable per-partner SLA thresholds (e.g. Netcraft: 48h, InternalLegal: 5 business days)
- Background job checks age of tickets in non-terminal states
- Sets `needs_review=True` + fires notification when SLA is breached
- Both `needs_review` flag and notification pipeline already exist — just needs a trigger

---

### Priority 4 — Netcraft Webhook Receiver

Netcraft supports webhook callbacks on state change. A `POST /takedown/webhooks/netcraft` endpoint could receive push updates and run the same state-mapping logic immediately. Reduces average latency from ~30 minutes (polling) to near-real-time for Netcraft. SMTP-only partners remain polling-only.

---

## 8. External Partner Signups

### What each partner requires and how hard it is to get

| Partner | Signup Type | Env Var Required | Notes |
|---|---|---|---|
| **Manual** | Nothing | — | Always available, works out of the box |
| **Internal Legal** | Internal only | SMTP creds + optional Jira URL/token | Already available |
| **Netcraft** | Sales call required | `ARGUS_TAKEDOWN_NETCRAFT_API_KEY` | Enterprise contract. Most capable (REST API, webhooks, high volume). Worth pursuing. |
| **PhishLabs** | Sales call required | `ARGUS_TAKEDOWN_PHISHLABS_SMTP_RECIPIENT` | Acquired by Fortra. Enterprise-only. SMTP-only so no programmatic status loop possible anyway — just fires an email. |
| **Group-IB** | Sales call required | `ARGUS_TAKEDOWN_GROUPIB_SMTP_RECIPIENT` | Enterprise, relationship-driven. SMTP only. Same story as PhishLabs. |

**Key implication**: The background sync worker is only meaningful for **Netcraft** (the one REST partner with a real polling API). PhishLabs and GroupIB `fetch_status()` both return hardcoded errors — there is nothing to poll. The sync worker can be built and deployed today; it will skip SMTP-only partners and be ready the moment a Netcraft API key arrives.

---

## 9. Open Source / Free Alternatives

### What "takedown" actually means per partner

- **Netcraft**: REST API → they coordinate with registrars and hosting providers using industry relationships. This is the outcome money buys — actual domain suspension.
- **PhishLabs / Group-IB**: Literally a formatted email to their inbox. You're paying for their industry relationships, not their technology. The Argus adapter is a templated email sender.

### Free alternatives by outcome

#### Browser Blocklisting (self-service, all free)

Gets the URL/domain flagged in Chrome, Firefox, Edge, Safari, and hundreds of downstream security tools within hours.

| Service | API | What it does |
|---|---|---|
| **Google Safe Browsing** | Free REST API | Flags in Chrome, Android, Google products |
| **Microsoft SmartScreen** | Free portal (no public API) | Flags in Edge + Windows Defender |
| **Abuse.ch URLhaus** | Free REST API | Distributed to ~500 ISPs, CERTs, AV vendors |
| **PhishTank** | Free API (Cisco/OpenDNS) | Feeds Firefox, OpenDNS, many SIEMs |
| **APWG eCX** | Free for security orgs | Feeds law enforcement + industry partners |

URLhaus and APWG eCX have the cleanest programmatic APIs. Both are self-service.

#### Domain Suspension (the harder problem)

Actually getting a domain killed at the registrar level:

| Path | Cost | How |
|---|---|---|
| **Direct registrar abuse email** | Free | WHOIS the domain → extract `abuse@registrar.tld` → send formatted report. Automatable. No status API. |
| **ICANN Compliance portal** | Free | Escalation path when registrar ignores abuse reports. Manual. |
| **Netcraft** | Paid | Does the above at scale with established relationships and follow-up |

**No open-source service replicates what Netcraft does** in terms of coordinating with registrars to suspend domains. That's relationship-driven. The free path gets you most of the practical outcome — a phishing domain blocked in all major browsers within hours is sufficient for most threats. Paid partners matter when you need actual domain suspension at volume.

### Recommended new adapters to build (zero contracts, zero cost)

1. **URLhausAdapter** — `POST` to `https://urlhaus-api.abuse.ch/v1/` with URL + tags. Gets distributed to ~500 downstream consumers. Free, self-service, instant.
2. **GoogleSafeBrowsingAdapter** — Submit via Google's reporting API. Largest browser reach.
3. **DirectRegistrarAbuseAdapter** — WHOIS lookup → extract registrar abuse contact → send formatted email (same template as existing `_format_email_body`). Creates a `Manual` state ticket (no status API). This is the free version of what Netcraft does without the relationship muscle.

These three adapters give meaningful domain-level coverage without any sales conversation.

---

## 10. Recommended Build Order

1. **Background sync worker** — highest leverage, zero new dependencies, works with existing adapters
2. **URLhaus + Google Safe Browsing adapters** — free, self-service, immediate coverage
3. **Direct Registrar Abuse adapter** — free domain suspension path via WHOIS automation
4. **Widen auto-file net** — wire Investigation Agent + Impersonation Agent to `_maybe_auto_file_takedown`
5. **SLA escalation** — stale ticket alerting with configurable per-partner thresholds
6. **Netcraft webhook receiver** — push updates once contract is signed (eliminates polling)
