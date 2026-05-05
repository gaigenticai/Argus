"""Sanitize Decider auto-tag notes corrupted by tuple-comma bug.

A previous corpus had a 1-keyword rule written as ``("foo")`` instead of
``("foo",)``. Python sees that as a parenthesised string, not a tuple,
so the matcher iterated the keyword *character-by-character* and the
audit trail was stamped with notes like
``"Decider auto-tag (corpus=…); matched on: a, a"``.

The corpus is fixed (rule corrected, drift guard added at module load
in ``src/intel/decider.py``), but historical
``attack_technique_attachments`` rows still carry the bogus tail. This
migration strips it so the Navigator hover comments are usable and the
rows can be re-tagged on the next sweep if the analyst chooses.

Idempotent: rerunning this migration on already-cleaned data is a
no-op (the regex only matches the bogus single-character lists).
"""
from __future__ import annotations

from alembic import op


revision = "a8b9c0d1e2f3"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Strip the trailing "; matched on: a, a, a" (single-char list) the
    # bug emitted. Keep the rest of the note so the corpus version
    # marker stays.
    op.execute(
        """
        UPDATE attack_technique_attachments
        SET note = regexp_replace(note, '; matched on: ([a-z])(, [a-z])*$', '')
        WHERE source = 'triage_agent'
          AND note ~ '; matched on: [a-z](, [a-z])*$';
        """
    )


def downgrade() -> None:
    # Lossy data-fix; we don't reconstruct the bogus tail. Downgrade is
    # a no-op and the corrected notes stay.
    pass
