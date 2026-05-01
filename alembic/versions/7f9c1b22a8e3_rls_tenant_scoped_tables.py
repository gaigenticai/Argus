"""Row-Level Security on tenant-scoped tables (Audit E5).

Defense-in-depth: enables Postgres RLS on every table with an
``organization_id`` column. The policy is *opt-in* via a session GUC
named ``app.current_org``:

- When the GUC is **unset** (its default), the policy allows all rows.
  Existing app code, tests, the worker, and admin queries see no
  behaviour change.
- When the GUC is **set** to a UUID, the policy constrains every query
  on that connection to ``organization_id = current_setting('app.current_org')``.

The application opts in at request boundaries by calling
``set_session_org(db, org_id)`` after authorisation. A SQL-injection
bug that drops the WHERE clause is then still filtered by Postgres
itself.

Once every endpoint sets the GUC, a follow-up migration can flip the
policy to strict (drop the unset-fallback). That's tracked separately;
this migration is the safe, additive first step.

Revision ID: 7f9c1b22a8e3
Revises: 6e1b2d44ab73
Create Date: 2026-04-28
"""

from typing import Sequence, Union

from alembic import op


revision: str = '7f9c1b22a8e3'
down_revision: Union[str, None] = '6e1b2d44ab73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TENANT_TABLES = (
    "actor_playbooks", "advisories", "alerts", "asset_changes", "assets",
    "attack_technique_attachments", "brand_logos", "brand_terms",
    "card_leakage_findings", "cases", "credit_card_bins",
    "discovery_findings", "discovery_jobs", "dlp_findings", "dlp_policies",
    "dmarc_report_records", "dmarc_reports", "evidence_blobs",
    "exposure_findings", "external_ticket_bindings", "fraud_findings",
    "hardening_recommendations", "impersonation_findings", "live_probes",
    "logo_matches", "mobile_app_findings", "news_article_relevance",
    "news_feeds", "notification_channels", "notification_deliveries",
    "notification_rules", "onboarding_sessions", "questionnaire_instances",
    "questionnaire_templates", "reports", "retention_policies",
    "security_ratings", "sla_breach_events", "sla_policies",
    "social_accounts", "suspect_domains", "takedown_tickets",
    "vendor_onboarding_workflows", "vendor_scorecards", "vip_profiles",
    "vip_targets", "vulnerabilities", "vulnerability_scans",
    "webhook_endpoints",
)


def upgrade() -> None:
    for t in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;")
        # FORCE so even table-owning superusers (the connection that
        # ran migrations) are subject to the policy. Without FORCE, RLS
        # is ignored for the table owner.
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;")
        # NULLIF returns NULL when the GUC is empty / unset; the cast
        # then yields NULL; org_id = NULL is unknown → falls through
        # to ``OR <guc-empty>`` which is true. Safer than a bare cast
        # because Postgres won't try to parse '' as a UUID.
        op.execute(
            f"""
            CREATE POLICY {t}_tenant_isolation ON {t}
                USING (
                    NULLIF(current_setting('app.current_org', true), '') IS NULL
                    OR organization_id = NULLIF(current_setting('app.current_org', true), '')::uuid
                )
                WITH CHECK (
                    NULLIF(current_setting('app.current_org', true), '') IS NULL
                    OR organization_id = NULLIF(current_setting('app.current_org', true), '')::uuid
                );
            """
        )


def downgrade() -> None:
    for t in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t};")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY;")
