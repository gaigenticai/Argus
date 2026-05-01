"""PII registry (Audit E8).

A single source of truth for which `(table, column)` pairs hold
personally identifiable information. Used by:

- **Retention** — tighter cutoff windows for high-PII tables.
- **GDPR forget** — extra fields to scrub on top of the user row.
- **Audit redaction** — hide PII fields when emitting an audit log
  ``details`` blob.

Adding a new model with PII columns? Add it here. The CI test
`tests/test_pii_registry.py` enforces that every entry actually
references a real (table, column) so the registry never goes stale.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PiiField:
    table: str
    column: str
    classification: str  # "direct" (name/email/phone) | "linked" (handle/photo) | "behavioural"
    note: str = ""


# Direct identifiers — the GDPR forget hook scrubs these alongside the
# users row. Tables that hold someone's name/email/phone DIRECTLY.
DIRECT: tuple[PiiField, ...] = (
    PiiField("users", "email", "direct", "primary login identifier"),
    PiiField("users", "username", "direct"),
    PiiField("users", "display_name", "direct"),
    PiiField("vip_targets", "name", "direct", "executive being protected"),
    PiiField("vip_targets", "emails", "direct"),
    PiiField("vip_targets", "phone_numbers", "direct"),
    PiiField("vip_profiles", "full_name", "direct"),
    PiiField("vip_profiles", "title", "direct"),
    PiiField("audit_logs", "user_agent", "direct"),
    PiiField("audit_logs", "ip_address", "direct"),
)

# Linked identifiers — pseudonyms that map to a real person via context.
LINKED: tuple[PiiField, ...] = (
    PiiField("social_accounts", "handle", "linked"),
    PiiField("impersonation_findings", "candidate_handle", "linked"),
    PiiField("impersonation_findings", "candidate_display_name", "linked"),
    PiiField("impersonation_findings", "candidate_bio", "linked"),
    PiiField("impersonation_findings", "candidate_url", "linked"),
    PiiField("impersonation_findings", "candidate_photo_phash", "linked"),
    PiiField("impersonation_findings", "candidate_photo_sha256", "linked"),
    PiiField("fraud_findings", "target_identifier", "linked"),
    PiiField("card_leakage_findings", "pan_first6", "linked"),
    PiiField("card_leakage_findings", "pan_last4", "linked"),
)

# Behavioural — patterns that can re-identify when joined with external data.
BEHAVIOURAL: tuple[PiiField, ...] = (
    PiiField("users", "last_login_ip", "behavioural"),
    PiiField("users", "last_login_at", "behavioural"),
    PiiField("audit_logs", "details", "behavioural", "may embed inputs"),
)


def all_fields() -> tuple[PiiField, ...]:
    return DIRECT + LINKED + BEHAVIOURAL


def by_classification(klass: str) -> tuple[PiiField, ...]:
    return tuple(f for f in all_fields() if f.classification == klass)


__all__ = [
    "PiiField",
    "DIRECT",
    "LINKED",
    "BEHAVIOURAL",
    "all_fields",
    "by_classification",
]
