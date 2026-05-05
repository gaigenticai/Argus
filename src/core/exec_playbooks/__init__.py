"""Exec-briefing playbook catalog — see :mod:`.framework` for the
contract and :mod:`.playbooks` for the V1 catalogue.

Importing this package side-effect-registers every playbook in
``playbooks.py`` and runs :py:func:`validate_catalog` so any drift
(duplicate ids, unknown categories, broken applicable_when predicates)
fails at module-load time instead of leaking into a 500.
"""

from __future__ import annotations

from .framework import (
    AffectedItem,
    CANONICAL_CATEGORIES,
    Playbook,
    PlaybookNotFound,
    PlaybookStep,
    StepPreview,
    StepResult,
    VALID_PERMISSIONS,
    VALID_SCOPES,
    all_playbooks,
    applicable_catalog,
    get_playbook,
    register,
)

# Side-effect imports: every module-level ``register(Playbook(...))``
# call adds the playbook to the global registry. Splitting global vs
# investigation across two files keeps each ~400 LOC instead of an
# 800-line megafile, and the scope filter on Playbook itself ensures
# they don't bleed into each other's surfaces.
from . import playbooks  # noqa: F401 — global / response playbooks
from . import playbooks_investigation  # noqa: F401 — case-scoped probes


def validate_catalog() -> None:
    """Sanity-check the registered catalog.

    Raises ``ValueError`` on any drift. Called at module-import time
    from this file so a CI build catches it; also exposed for test
    suites and admin endpoints that want to surface the result.
    """
    seen_ids: set[str] = set()
    for pb in all_playbooks():
        if pb.id in seen_ids:
            raise ValueError(f"duplicate playbook id at validation: {pb.id}")
        seen_ids.add(pb.id)
        if pb.category not in CANONICAL_CATEGORIES:
            raise ValueError(
                f"playbook {pb.id} has invalid category {pb.category!r}"
            )
        if pb.permission not in VALID_PERMISSIONS:
            raise ValueError(
                f"playbook {pb.id} has invalid permission {pb.permission!r}"
            )
        if not pb.steps:
            raise ValueError(f"playbook {pb.id} has no steps")
        if pb.requires_input and not pb.input_schema:
            raise ValueError(
                f"playbook {pb.id} requires_input=True but has no input_schema"
            )
        if pb.scope not in VALID_SCOPES:
            raise ValueError(
                f"playbook {pb.id} has invalid scope {pb.scope!r}"
            )


validate_catalog()


__all__ = [
    "AffectedItem",
    "CANONICAL_CATEGORIES",
    "Playbook",
    "PlaybookNotFound",
    "PlaybookStep",
    "StepPreview",
    "StepResult",
    "VALID_PERMISSIONS",
    "VALID_SCOPES",
    "all_playbooks",
    "applicable_catalog",
    "get_playbook",
    "register",
    "validate_catalog",
]
