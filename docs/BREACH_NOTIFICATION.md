# Breach Notification Workflow

GDPR Art.33 requires data-controller notification to a supervisory
authority **within 72 hours** of becoming aware of a personal data
breach. Several US states + sectoral regulators (NYDFS Part 500,
CCPA/CPRA, RBI 6-hour) layer additional, often shorter, deadlines on
top.

This document is the playbook for the on-call engineer when an Argus
customer becomes the affected data controller. Argus itself is a
**data processor** under GDPR — we notify customers; they notify
authorities and data subjects.

---

## Detection sources

A breach is "discovered" the moment one of these triggers fires:

- A `Case` is transitioned to `CONFIRMED` with `tags ⊇ {"breach"}`
- An `ExposureFinding` lands at severity ≥ HIGH with category
  `data_breach` or `credential_leak`
- A `CardLeakageFinding` is created (these are by definition a breach
  the moment they're confirmed against a real BIN)
- A customer manually invokes `POST /api/v1/cases/{id}/breach-declare`
  (not yet implemented — H-tier follow-up)

The `auto_link_finding` hook (Audit D12+D13) routes all of these to
the customer's notification channels in real time. The clock starts
ticking the moment the dispatch fires.

---

## 72-hour countdown

| T+ | Action |
|----|--------|
| 0h | Detection. `auto_link_finding` opens or aggregates a Case + dispatches every configured notification channel. |
| 0h | Argus on-call ack within 30 minutes (paged via PagerDuty / Opsgenie). |
| 1h | Containment. Revoke the leaked credential / take the exposed asset offline / rotate the affected secret. |
| 4h | Scope assessment. Run an EASM rescan + `audit_log` query for any operation touching the affected `(table, column)` per the PII registry. |
| 12h | Customer briefing. The customer's data-protection officer is notified via the same channel that fired at T+0. |
| 24h | Argus produces an incident-evidence bundle: `GET /api/v1/audit/export/soc2-bundle?since=<T-72h>&until=<T+24h>`. |
| 48h | Customer files supervisory-authority notification (the customer is the controller; we are the processor). |
| 72h | Notification deadline. If the customer hasn't filed by now, escalate to the customer's CEO via the highest-severity channel. |

---

## Argus's role (processor obligations)

- **Notify without undue delay.** GDPR Art.33(2) — Argus emails the
  customer's primary security contact within 24 hours of detection.
  The contact is configured per-org via `Organization.settings.dpo_email`.
- **Provide forensic data.** The SOC2 bundle (G1), audit log (full
  NDJSON), and the case timeline are all customer-accessible at the
  moment of detection.
- **Preserve evidence.** Retention is paused on the affected resources
  for the duration of the incident. (Implementation: G4 legal-hold —
  next item.)

---

## Communication template

Argus ships a default email template at
`src/notifications/templates/breach.html`. It is intentionally
minimal — customers in regulated verticals will customise this per
their legal team's wording. Variables:

- `{{ case_id }}`
- `{{ severity }}`
- `{{ detected_at }}`
- `{{ summary }}`
- `{{ evidence_bundle_url }}`
- `{{ deadline_72h }}`

---

## What we do NOT do

- Notify supervisory authorities **on behalf of** the customer. That
  is the controller's duty.
- Publish breach detail outside the customer's configured notification
  channels until the customer authorises it.
- Pause Argus operations during a breach — the customer's other
  monitoring continues uninterrupted.

---

## Quarterly drill

Once a quarter, run a tabletop:

1. Trigger a synthetic CardLeakageFinding for a test BIN.
2. Time the path from creation → notification fire → SOC2 bundle export.
3. Document the wall-clock — that's your **measured Argus T+0 → T+24h** for this quarter.
4. Adjust runbook if any step exceeded its target.
