"""governance: agentic layer — agent_tasks, RUF, in-app inbox, DSAR,
learnings, evidence merkle chain, plus per-table agent_summary columns.

This is the Phase-0 schema for the governance overhaul: every retention/
DMARC/leakage/evidence/notifications upgrade rides on this migration.

Revision ID: fd9e0f1a2b3c
Revises: fc8d9e0f1a2b
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fd9e0f1a2b3c"
down_revision = "fc8d9e0f1a2b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ----------------------------------------------------- agent_tasks
    op.create_table(
        "agent_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("kind", sa.String(80), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("dedup_key", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("priority", sa.Integer, nullable=False, server_default="5"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False, server_default="3"),
        sa.Column("payload", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("result", postgresql.JSONB, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("model_id", sa.String(80), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("cost_usd_estimate", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("kind", "dedup_key", name="uq_agent_tasks_kind_dedup"),
    )
    op.create_index("ix_agent_tasks_status_priority", "agent_tasks",
                    ["status", "priority", "created_at"])
    op.create_index("ix_agent_tasks_kind_status", "agent_tasks", ["kind", "status"])
    op.create_index("ix_agent_tasks_org_kind", "agent_tasks",
                    ["organization_id", "kind"])

    # ----------------------------------------------- dmarc_forensic_reports
    op.create_table(
        "dmarc_forensic_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("feedback_type", sa.String(40)),
        sa.Column("arrival_date", sa.DateTime(timezone=True)),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("reported_domain", sa.String(255)),
        sa.Column("original_envelope_from", sa.String(255)),
        sa.Column("original_envelope_to", sa.String(255)),
        sa.Column("original_mail_from", sa.String(255)),
        sa.Column("original_rcpt_to", sa.String(255)),
        sa.Column("auth_failure", sa.String(255)),
        sa.Column("delivery_result", sa.String(40)),
        sa.Column("raw_headers", sa.Text),
        sa.Column("dkim_domain", sa.String(255)),
        sa.Column("dkim_selector", sa.String(120)),
        sa.Column("spf_domain", sa.String(255)),
        sa.Column("extras", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("agent_summary", postgresql.JSONB),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_dmarc_forensic_org_domain_received",
                    "dmarc_forensic_reports",
                    ["organization_id", "domain", "received_at"])
    op.create_index("ix_dmarc_forensic_source_ip", "dmarc_forensic_reports",
                    ["source_ip"])

    # ----------------------------------------------- dmarc_mailbox_configs
    op.create_table(
        "dmarc_mailbox_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  nullable=False, unique=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer, nullable=False, server_default="993"),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("password_encrypted", sa.Text, nullable=False),
        sa.Column("folder", sa.String(120), nullable=False, server_default="INBOX"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_seen_uid", sa.Integer),
        sa.Column("last_polled_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )

    # ----------------------------------------------- notification_inbox
    op.create_table(
        "notification_inbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("delivery_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_kind", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("link_path", sa.String(500)),
        sa.Column("payload", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_notification_inbox_org_user_created",
                    "notification_inbox",
                    ["organization_id", "user_id", "created_at"])
    op.create_index("ix_notification_inbox_unread", "notification_inbox",
                    ["organization_id", "user_id", "read_at"])

    # ----------------------------------------------- dsar_requests
    op.create_table(
        "dsar_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("subject_email", sa.String(255)),
        sa.Column("subject_name", sa.String(255)),
        sa.Column("subject_phone", sa.String(64)),
        sa.Column("subject_id_other", sa.String(255)),
        sa.Column("request_type", sa.String(40), nullable=False),
        sa.Column("regulation", sa.String(40)),
        sa.Column("status", sa.String(40), nullable=False, server_default="received"),
        sa.Column("deadline_at", sa.DateTime(timezone=True)),
        sa.Column("matched_tables", postgresql.ARRAY(sa.String), nullable=False,
                  server_default=sa.text("'{}'::varchar[]")),
        sa.Column("match_summary", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("matched_row_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("draft_response", sa.Text),
        sa.Column("final_response", sa.Text),
        sa.Column("export_evidence_blob_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("notes", sa.Text),
        sa.Column("closed_reason", sa.String(120)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_dsar_org_status_created", "dsar_requests",
                    ["organization_id", "status", "created_at"])
    op.create_index("ix_dsar_subject_email", "dsar_requests", ["subject_email"])

    # ----------------------------------------------- learnings_log
    op.create_table(
        "learnings_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("source_table", sa.String(80), nullable=False),
        sa.Column("rows_summarised", sa.Integer, nullable=False, server_default="0"),
        sa.Column("window_start", sa.DateTime(timezone=True)),
        sa.Column("window_end", sa.DateTime(timezone=True)),
        sa.Column("summary_md", sa.Text, nullable=False),
        sa.Column("extracted_iocs", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("extracted_actors", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("extracted_techniques", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("model_id", sa.String(80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_learnings_org_table_created", "learnings_log",
                    ["organization_id", "source_table", "created_at"])

    # ----------------------------------------------- evidence_audit_chain
    op.create_table(
        "evidence_audit_chain",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("sequence", sa.BigInteger,
                  sa.Identity(always=False, start=1, cycle=False),
                  unique=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("evidence_blob_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("prev_chain_hash", sa.String(64)),
        sa.Column("chain_hash", sa.String(64), nullable=False),
        sa.Column("anchor_id", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_evidence_audit_org_created", "evidence_audit_chain",
                    ["organization_id", "created_at"])
    op.create_index("ix_evidence_audit_blob", "evidence_audit_chain",
                    ["evidence_blob_id"])

    # ============================================ extend existing tables

    # evidence_blobs ------------------------------------------------
    op.add_column("evidence_blobs", sa.Column("md5", sa.String(32)))
    op.add_column("evidence_blobs", sa.Column("sha1", sa.String(40)))
    op.add_column("evidence_blobs", sa.Column("ssdeep", sa.String(255)))
    op.add_column("evidence_blobs", sa.Column("perceptual_hash", sa.String(64)))
    op.add_column("evidence_blobs", sa.Column("extracted_text", sa.Text))
    op.add_column("evidence_blobs", sa.Column("agent_summary", postgresql.JSONB))
    op.add_column("evidence_blobs", sa.Column("av_scan", postgresql.JSONB))

    # dlp_findings --------------------------------------------------
    op.add_column("dlp_findings", sa.Column("classification", postgresql.JSONB))
    op.add_column("dlp_findings", sa.Column("correlated_findings", postgresql.JSONB))
    op.add_column("dlp_findings", sa.Column("breach_correlations", postgresql.JSONB))
    op.add_column("dlp_findings", sa.Column("agent_summary", postgresql.JSONB))
    op.add_column("dlp_findings", sa.Column("takedown_draft", sa.Text))

    # card_leakage_findings ----------------------------------------
    op.add_column("card_leakage_findings", sa.Column("classification", postgresql.JSONB))
    op.add_column("card_leakage_findings",
                  sa.Column("correlated_findings", postgresql.JSONB))
    op.add_column("card_leakage_findings",
                  sa.Column("breach_correlations", postgresql.JSONB))
    op.add_column("card_leakage_findings", sa.Column("agent_summary", postgresql.JSONB))
    op.add_column("card_leakage_findings", sa.Column("takedown_draft", sa.Text))

    # dmarc_reports -------------------------------------------------
    op.add_column("dmarc_reports", sa.Column("posture_score", postgresql.JSONB))
    op.add_column("dmarc_reports", sa.Column("rca", postgresql.JSONB))
    op.add_column("dmarc_reports", sa.Column("agent_summary", postgresql.JSONB))

    # notification_deliveries --------------------------------------
    op.add_column("notification_deliveries",
                  sa.Column("rendered_payload", postgresql.JSONB))
    op.add_column("notification_deliveries",
                  sa.Column("cluster_count", sa.Integer))
    op.add_column("notification_deliveries",
                  sa.Column("cluster_dedup_key", sa.String(200)))

    # retention_policies -------------------------------------------
    op.add_column(
        "retention_policies",
        sa.Column("deletion_mode", sa.String(20), nullable=False,
                  server_default="hard_delete"),
    )
    op.add_column(
        "retention_policies",
        sa.Column("compliance_mappings", postgresql.ARRAY(sa.String),
                  nullable=False, server_default=sa.text("'{}'::varchar[]")),
    )
    op.add_column("retention_policies", sa.Column("description", sa.Text))


def downgrade() -> None:
    op.drop_column("retention_policies", "description")
    op.drop_column("retention_policies", "compliance_mappings")
    op.drop_column("retention_policies", "deletion_mode")
    op.drop_column("notification_deliveries", "cluster_dedup_key")
    op.drop_column("notification_deliveries", "cluster_count")
    op.drop_column("notification_deliveries", "rendered_payload")
    op.drop_column("dmarc_reports", "agent_summary")
    op.drop_column("dmarc_reports", "rca")
    op.drop_column("dmarc_reports", "posture_score")
    for col in ("takedown_draft", "agent_summary", "breach_correlations",
                "correlated_findings", "classification"):
        op.drop_column("card_leakage_findings", col)
        op.drop_column("dlp_findings", col)
    for col in ("av_scan", "agent_summary", "extracted_text",
                "perceptual_hash", "ssdeep", "sha1", "md5"):
        op.drop_column("evidence_blobs", col)

    op.drop_index("ix_evidence_audit_blob", table_name="evidence_audit_chain")
    op.drop_index("ix_evidence_audit_org_created", table_name="evidence_audit_chain")
    op.drop_table("evidence_audit_chain")

    op.drop_index("ix_learnings_org_table_created", table_name="learnings_log")
    op.drop_table("learnings_log")

    op.drop_index("ix_dsar_subject_email", table_name="dsar_requests")
    op.drop_index("ix_dsar_org_status_created", table_name="dsar_requests")
    op.drop_table("dsar_requests")

    op.drop_index("ix_notification_inbox_unread", table_name="notification_inbox")
    op.drop_index("ix_notification_inbox_org_user_created",
                  table_name="notification_inbox")
    op.drop_table("notification_inbox")

    op.drop_table("dmarc_mailbox_configs")

    op.drop_index("ix_dmarc_forensic_source_ip", table_name="dmarc_forensic_reports")
    op.drop_index("ix_dmarc_forensic_org_domain_received",
                  table_name="dmarc_forensic_reports")
    op.drop_table("dmarc_forensic_reports")

    op.drop_index("ix_agent_tasks_org_kind", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_kind_status", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_status_priority", table_name="agent_tasks")
    op.drop_table("agent_tasks")
