"""Umbrella import that registers every governance Bridge-LLM handler.

Imported once by the worker's ``_agent_dispatch_tick_once`` (and at
test boot). Side-effect imports register handlers via
``src.llm.agent_queue.register_handler`` so the dispatcher can pick
them up by ``kind``.
"""
from __future__ import annotations

import logging

_logger = logging.getLogger(__name__)


def _safe_import(modname: str) -> None:
    try:
        __import__(modname)
    except Exception:  # noqa: BLE001 — never let one bad module break the rest
        _logger.exception("[governance] handler module %s failed to import", modname)


# Import every per-page handler module. Each side-effect-registers
# handlers when imported.
for _mod in (
    "src.agents.governance.evidence",
    "src.agents.governance.leakage",
    "src.agents.governance.dmarc",
    "src.agents.governance.notifications",
    "src.agents.governance.retention",
):
    _safe_import(_mod)
