"""Per-page agentic handler modules for the governance section.

Each module registers Bridge-LLM-driven handlers via
``src.llm.agent_queue.register_handler``. The umbrella loader at
``src.agents.governance_handlers`` imports every module here so a
single import in the worker dispatcher wires up the full set.
"""
