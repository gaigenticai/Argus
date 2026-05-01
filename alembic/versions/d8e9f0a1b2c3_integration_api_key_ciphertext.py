"""integration_configs.api_key — widen for Fernet ciphertext (audit D-8)

Revision ID: d8e9f0a1b2c3
Revises: c9d0e1f2a3b4
Create Date: 2026-04-30

Adversarial audit D-8 — IntegrationConfig.api_key now stores Fernet
ciphertext instead of the raw provider token. Fernet output is base64
text and longer than the original 500-char column allows. Widen to
2048 chars to fit the encrypted payload comfortably.

The model carries a ``set_api_key`` helper that performs the encrypt;
existing rows still hold plaintext until an operator re-saves the key
via PUT /api/v1/integrations/{tool}, and the model's ``api_key_plain``
property degrades gracefully on those rows (returns None and logs a
WARNING so the dashboard can flag "needs re-save").
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "d8e9f0a1b2c3"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "integration_configs",
        "api_key",
        existing_type=sa.String(length=500),
        type_=sa.String(length=2048),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Rolling back will truncate ciphertext — operators must
    # re-key after a downgrade. Documenting that here rather than
    # silently letting Postgres truncate.
    op.alter_column(
        "integration_configs",
        "api_key",
        existing_type=sa.String(length=2048),
        type_=sa.String(length=500),
        existing_nullable=True,
    )
