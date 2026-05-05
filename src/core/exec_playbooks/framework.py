"""Playbook framework — typed contract + registry + module-load validation.

Same drift-fails-at-import discipline as :mod:`src.core.service_inventory`:
adding a malformed playbook (duplicate id, unknown category, empty steps,
non-snake_case ids) blows up the whole import so a CI build catches it
instead of a 500 in production.

Each playbook is a *named* recipe that the AI exec briefing can
reference by ``id``. The LLM never invents action types — it picks a
``playbook_id`` from the catalog the prompt builder hands it. That's
the whole point of this module: turn "what should the operator do?"
from a free-form LLM hallucination into a typed, auditable, executable
contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — type-only imports
    from sqlalchemy.ext.asyncio import AsyncSession
    from src.models.threat import Organization
    from src.models.auth import User


# ----------------------------------------------------------------------
# Categories — closed enum, drift fails at module load.
# ----------------------------------------------------------------------

CANONICAL_CATEGORIES: frozenset[str] = frozenset({
    "brand",         # takedowns, suspect triage, typosquat scans
    "email",         # DMARC, SPF, DKIM
    "asset",         # VIP roster, asset coverage
    "intel",         # IOC enrichment, feed configuration
    "investigation", # WHOIS, live probe, passive DNS, SIEM pivot,
                     # single-domain takedown — queued by Case Copilot
                     # against an open case
})


# Playbook scope decides which prompt surface a playbook can be
# suggested by. ``global`` plays show up in the AI Executive Briefing
# (org-level recommendations). ``investigation`` plays show up in the
# Case Copilot draft (case-level next steps). A playbook is always
# one or the other — never both — so the LLM in each surface only
# sees applicable options.
VALID_SCOPES: frozenset[str] = frozenset({"global", "investigation"})


# ----------------------------------------------------------------------
# Permissions — UserRole values that may execute a playbook. Lower bound
# is enforced by the API layer; "admin" is the strictest.
# ----------------------------------------------------------------------

VALID_PERMISSIONS: frozenset[str] = frozenset({"analyst", "admin"})


# Identifier validator — module-level so __post_init__ can reach it
# regardless of class-definition order below.
_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9_]*$")


# ----------------------------------------------------------------------
# Preview / execute return types
# ----------------------------------------------------------------------


@dataclass
class AffectedItem:
    """One row in the "What will change" preview list.

    The id is opaque to the operator but stable enough that re-running
    a preview will return the same id for the same row (used by the
    drawer to restore selection across re-fetches).
    """

    id: str
    label: str
    sub_label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StepPreview:
    """What the operator sees before clicking Execute on a step."""

    summary: str  # "Will create 34 takedown tickets"
    affected_items: list[AffectedItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    can_execute: bool = True
    blocker_reason: str | None = None
    # Operator-actionable copy block — e.g. DNS records to publish for
    # DMARC playbooks. Rendered in the drawer above the action footer.
    instructions: list[str] = field(default_factory=list)


@dataclass
class StepResult:
    """Outcome of running one step.

    ``ok`` is the per-step verdict; per-item success/failure goes in
    ``items`` (one dict per affected_item).
    """

    ok: bool
    summary: str  # "34 tickets submitted, 0 failed"
    items: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


# Callable signatures. Defined as type aliases so the dataclass below
# stays readable.
PreviewFn = Callable[
    ["AsyncSession", "Organization", dict, list[StepResult]],
    Awaitable[StepPreview],
]
ExecuteFn = Callable[
    ["AsyncSession", "Organization", dict, list[StepResult], "User"],
    Awaitable[StepResult],
]


# ----------------------------------------------------------------------
# Step + Playbook dataclasses
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class PlaybookStep:
    step_id: str
    title: str
    description: str
    preview: PreviewFn
    execute: ExecuteFn

    def __post_init__(self) -> None:
        if not _SNAKE_CASE.match(self.step_id):
            raise ValueError(
                f"PlaybookStep.step_id {self.step_id!r} must be snake_case"
            )


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    category: str
    description: str
    steps: tuple[PlaybookStep, ...]
    applicable_when: Callable[[Any], bool]
    requires_approval: bool = False
    requires_input: bool = False
    permission: str = "analyst"
    input_schema: dict[str, Any] | None = None
    # Optional one-line CTA that overrides the default "Open →" copy on
    # the briefing card (e.g. "Submit takedowns →" reads better than
    # "Open →" for an irreversible action).
    cta_label: str | None = None
    # Where the playbook can be suggested. ``global`` = Exec Briefing
    # (org-scoped recommendations). ``investigation`` = Case Copilot
    # draft (case-scoped next steps). The LLM in each surface only
    # ever sees the playbooks scoped to its surface.
    scope: str = "global"

    # ------------------------------------------------------------------
    # Validation — runs at construction. Catches:
    #   - non-snake_case ids
    #   - unknown category
    #   - unknown permission
    #   - empty steps
    #   - duplicate step ids within the playbook
    #   - requires_input=True with no input_schema
    # ------------------------------------------------------------------
    def __post_init__(self) -> None:
        if not _SNAKE_CASE.match(self.id):
            raise ValueError(f"Playbook.id {self.id!r} must be snake_case")
        if self.category not in CANONICAL_CATEGORIES:
            raise ValueError(
                f"Playbook {self.id}: category {self.category!r} not in "
                f"{sorted(CANONICAL_CATEGORIES)}"
            )
        if self.permission not in VALID_PERMISSIONS:
            raise ValueError(
                f"Playbook {self.id}: permission {self.permission!r} not in "
                f"{sorted(VALID_PERMISSIONS)}"
            )
        if not self.steps:
            raise ValueError(f"Playbook {self.id}: must declare ≥1 step")
        seen: set[str] = set()
        for s in self.steps:
            if s.step_id in seen:
                raise ValueError(
                    f"Playbook {self.id}: duplicate step_id {s.step_id!r}"
                )
            seen.add(s.step_id)
        if self.requires_input and not self.input_schema:
            raise ValueError(
                f"Playbook {self.id}: requires_input=True but input_schema is None"
            )
        if self.scope not in VALID_SCOPES:
            raise ValueError(
                f"Playbook {self.id}: scope {self.scope!r} not in {sorted(VALID_SCOPES)}"
            )

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    def step_at(self, index: int) -> PlaybookStep:
        if not 0 <= index < self.total_steps:
            raise IndexError(
                f"Playbook {self.id}: step index {index} out of range "
                f"(have {self.total_steps})"
            )
        return self.steps[index]


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------


_REGISTRY: dict[str, Playbook] = {}


class PlaybookNotFound(KeyError):
    """Raised when a playbook_id isn't in the registry — the LLM
    hallucinated one, or a stale cached briefing references a removed
    playbook. Callers should render a graceful fallback rather than
    500."""


def register(playbook: Playbook) -> Playbook:
    """Register a playbook in the global catalog.

    Idempotent at module load time (re-imports are no-ops); duplicate
    ids from *different* Playbook instances raise to catch genuine
    drift between two definitions claiming the same id.
    """
    existing = _REGISTRY.get(playbook.id)
    if existing is playbook:
        return playbook
    if existing is not None:
        raise ValueError(
            f"duplicate Playbook registration for id={playbook.id!r}"
        )
    _REGISTRY[playbook.id] = playbook
    return playbook


def get_playbook(playbook_id: str) -> Playbook:
    pb = _REGISTRY.get(playbook_id)
    if pb is None:
        raise PlaybookNotFound(playbook_id)
    return pb


def all_playbooks() -> list[Playbook]:
    return list(_REGISTRY.values())


def applicable_catalog(
    snapshot: Any, *, scope: str = "global"
) -> list[Playbook]:
    """Filter the registry to playbooks whose preconditions match the
    current org snapshot AND whose scope matches.

    Used by:
    - the briefing prompt builder (``scope="global"``) so the LLM
      only sees org-level response actions;
    - the Case Copilot prompt builder (``scope="investigation"``) so
      the LLM only sees per-case investigation actions;
    - the dashboard catalog endpoint that drives the manual
      ``/playbooks`` index (passes whichever scope the surface needs).

    A playbook whose ``applicable_when`` raises is treated as
    inapplicable rather than crashing the whole catalog fetch.
    """
    if scope not in VALID_SCOPES:
        raise ValueError(f"unknown scope {scope!r}")
    out: list[Playbook] = []
    for pb in _REGISTRY.values():
        if pb.scope != scope:
            continue
        try:
            if pb.applicable_when(snapshot):
                out.append(pb)
        except Exception:  # noqa: BLE001 — defensive: predicate bug → skip, not 500
            continue
    return out


__all__ = [
    "AffectedItem",
    "CANONICAL_CATEGORIES",
    "ExecuteFn",
    "Playbook",
    "PlaybookNotFound",
    "PlaybookStep",
    "PreviewFn",
    "StepPreview",
    "StepResult",
    "VALID_PERMISSIONS",
    "VALID_SCOPES",
    "all_playbooks",
    "applicable_catalog",
    "get_playbook",
    "register",
]
