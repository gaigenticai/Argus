"""Executive-briefing playbook execution audit + state-machine model.

A ``PlaybookExecution`` represents one operator-initiated run of a
catalogued playbook (defined in :mod:`src.core.exec_playbooks`). It is
the durable record of:

* what was previewed,
* who approved it (when ``requires_approval=True``),
* which step we're on (multi-step playbooks pause between steps),
* per-item success/failure of every side-effect,

and is the row that powers ``/playbooks/history`` + the admin
``/playbooks/approvals`` queue.

State machine
-------------

::

    (entry)
       │
       ├─ requires_approval=True  ──► pending_approval ──► approved ──► in_progress
       │                                       │
       │                                       └────► denied  (terminal)
       │
       └─ requires_approval=False ─────────────────────► in_progress

    in_progress (running step N)
       │
       ├─ has more steps ──► step_complete  ──► in_progress  (operator advances)
       └─ last step      ──► completed      (terminal)

    Any non-terminal state ──► failed | cancelled  (terminal)

The transitions are enforced in-Python in
:func:`is_playbook_transition_allowed`; we do not encode the state
graph as a check constraint because Postgres ENUM check constraints
aren't expressive enough for "depends on whether more steps remain."
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class PlaybookStatus(str, enum.Enum):
    """End-to-end status of a playbook execution.

    *Non-terminal:* ``pending_approval``, ``approved``, ``in_progress``,
    ``step_complete``.

    *Terminal:* ``completed``, ``failed``, ``denied``, ``cancelled``.
    """

    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    STEP_COMPLETE = "step_complete"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"


class PlaybookTrigger(str, enum.Enum):
    """How the execution was initiated.

    ``EXEC_BRIEFING`` — operator clicked "Open →" on an AI briefing action.
    ``MANUAL``        — operator opened the playbook from /playbooks directly.
    ``CASE_COPILOT``  — Case Copilot's "Apply suggestions" queued an
                        investigation playbook against an open case.
    """

    EXEC_BRIEFING = "exec_briefing"
    MANUAL = "manual"
    CASE_COPILOT = "case_copilot"


class PlaybookExecution(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "playbook_executions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Stable identifier from the in-code Playbook registry — e.g.
    # "bulk_takedown_rogue_apps". A FK is impossible (the catalog lives
    # in code, not the DB) so this is just an indexed string.
    playbook_id: Mapped[str] = mapped_column(String(100), nullable=False)

    status: Mapped[str] = mapped_column(
        Enum(
            PlaybookStatus,
            name="playbook_status",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=PlaybookStatus.PENDING_APPROVAL.value,
        nullable=False,
    )

    # Operator-supplied input frozen at execute() time. Not mutated by
    # step transitions — params describe what they asked for, results
    # describe what happened.
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Snapshot of the preview that was visible to the operator before
    # they clicked Execute. Captured server-side so an auditor can
    # reproduce "what did the operator see when they approved this?"
    preview_snapshot: Mapped[dict | None] = mapped_column(JSONB)

    # Multi-step bookkeeping. Single-step playbooks just have
    # total_steps=1 and current_step_index=0.
    current_step_index: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    total_steps: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )

    # Per-step results, appended as steps complete. Each entry is
    # ``{"step": int, "step_id": str, "ok": bool, "items": [...],
    # "errors": [...], "completed_at": iso}``. Used by the history
    # drill-down and the resume UI.
    step_results: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # Approval workflow.
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    approver_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    approval_note: Mapped[str | None] = mapped_column(Text)
    denial_reason: Mapped[str | None] = mapped_column(Text)

    # Idempotency — frontend mints a UUID per execute click. Same key
    # within an org returns the existing row (409) instead of creating
    # a duplicate. Scoped per-org so two orgs don't collide on a fixed
    # client-side bug.
    idempotency_key: Mapped[str] = mapped_column(String(100), nullable=False)

    error_message: Mapped[str | None] = mapped_column(Text)

    triggered_from: Mapped[str] = mapped_column(
        Enum(
            PlaybookTrigger,
            name="playbook_trigger",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=PlaybookTrigger.MANUAL.value,
        nullable=False,
    )
    # When triggered from an AI briefing, which of the top_actions slots
    # was clicked (0/1/2). Used to attribute briefing-driven actions in
    # analytics; nullable for manual runs.
    briefing_action_index: Mapped[int | None] = mapped_column(Integer)

    # When the run is part of a case investigation (Case Copilot
    # apply_suggestions, or operator-triggered from inside a case), the
    # FK ties it back to the case. Org-scoped runs (briefing actions,
    # manual /playbooks runs) leave this NULL. ON DELETE SET NULL so
    # deleting a case orphans the audit trail rather than nuking it.
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Stable copilot-run pointer for executions queued from a Case
    # Copilot apply. Lets the case detail surface "this execution came
    # from copilot run X" without a join through case_id+timestamp.
    copilot_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("case_copilot_runs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Lifecycle timestamps. ``created_at`` (from TimestampMixin) is when
    # the row first appeared (i.e. when the operator clicked Execute).
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_playbook_exec_org_idem",
        ),
        Index(
            "ix_playbook_exec_org_status_created",
            "organization_id", "status", "created_at",
        ),
        Index(
            "ix_playbook_exec_org_playbook",
            "organization_id", "playbook_id",
        ),
        # Drives the case-detail Copilot tab: "show me every execution
        # we queued for this case in chronological order."
        Index(
            "ix_playbook_exec_case_created",
            "case_id", "created_at",
        ),
    )


# ----------------------------------------------------------------------
# State machine — reject illegal transitions in-Python before they hit
# the audit log. Keep the table close to the model so reviewers can
# match it 1:1 against the docstring graph.
# ----------------------------------------------------------------------


_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "pending_approval": {"approved", "denied", "cancelled"},
    "approved":         {"in_progress", "cancelled"},
    "in_progress":      {"step_complete", "completed", "failed", "cancelled"},
    "step_complete":    {"in_progress", "cancelled"},
    "completed":        set(),  # terminal
    "failed":           set(),  # terminal
    "denied":           set(),  # terminal
    "cancelled":        set(),  # terminal
}


def is_playbook_transition_allowed(from_state: str, to_state: str) -> bool:
    return to_state in _ALLOWED_TRANSITIONS.get(from_state, set())


def is_terminal(state: str) -> bool:
    return state in {"completed", "failed", "denied", "cancelled"}


__all__ = [
    "PlaybookStatus",
    "PlaybookTrigger",
    "PlaybookExecution",
    "is_playbook_transition_allowed",
    "is_terminal",
]
