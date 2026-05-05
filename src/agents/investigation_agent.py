"""Investigation Agent — the first genuinely *agentic* feature in Argus.

What makes this different from ``TriageAgent`` and ``CorrelationAgent``?
Those are one-shot LLM calls: build a prompt, send it, parse the JSON
that comes back. The model never gets to ask follow-up questions about
the data.

This agent runs a real **observe → reason → act → observe** loop with
typed tools that hit the live database:

    1. start with a seed alert
    2. ask the model: given this alert and what you know so far, which
       tool would you like to call next? (or: should we stop?)
    3. execute the chosen tool (DB query, IOC lookup, related-alerts
       fetch, etc.)
    4. feed the result back into the conversation as a tool-result
       message
    5. loop until the model says ``finalise`` or we hit MAX_ITERATIONS

Output is a structured investigation report with a timeline of every
step the agent took (auditable), the IOCs / actors / assets it
correlated, and concrete recommended actions for the human analyst.

The agent is **transport-agnostic**: it works with the Anthropic-style
tool API (``provider=anthropic`` / ``provider=bridge``) AND with plain
JSON-prompted models (``provider=ollama`` / ``provider=openai``). Each
branch has a small adapter; the loop body is shared.

This file is deliberately self-contained — no API route, no dashboard
tab, no scheduler cron yet. Run it from a script::

    from src.agents.investigation_agent import InvestigationAgent
    async with get_session() as session:
        agent = InvestigationAgent(session)
        report = await agent.investigate(alert_id="...")
        print(report.markdown_summary())

The full integration (POST /investigations endpoint, dashboard tab,
scheduler trigger on HIGH/CRITICAL alerts) is a follow-up.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings


logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
#  Tool registry
# ----------------------------------------------------------------------


@dataclass
class Tool:
    """One callable tool the agent can invoke during a step.

    Tools are pure functions (no instance state) that take an
    ``AsyncSession`` plus typed kwargs and return JSON-serialisable
    output. Schema is published to the model so it knows when to call
    them.
    """

    name: str
    description: str
    schema: dict[str, Any]
    runner: Callable[..., Any]


_TOOLS: dict[str, Tool] = {}


def tool(name: str, description: str, schema: dict[str, Any]):
    """Decorator that registers a coroutine as an investigation tool."""

    def deco(fn):
        _TOOLS[name] = Tool(name=name, description=description, schema=schema, runner=fn)
        return fn

    return deco


# ----------------------------------------------------------------------
#  Tools — every one of these hits the live DB. No mocks.
# ----------------------------------------------------------------------


@tool(
    name="lookup_alert",
    description=(
        "Fetch the full record for a single alert by id. Returns title, "
        "summary, severity, category, matched_entities, and the linked "
        "raw_intel snippet if any."
    ),
    schema={
        "type": "object",
        "properties": {"alert_id": {"type": "string"}},
        "required": ["alert_id"],
    },
)
async def _tool_lookup_alert(session: AsyncSession, alert_id: str) -> dict[str, Any]:
    from src.models.threat import Alert, RawIntel

    res = (
        await session.execute(select(Alert).where(Alert.id == uuid.UUID(alert_id)))
    ).scalar_one_or_none()
    if res is None:
        return {"error": f"alert {alert_id} not found"}
    raw_text = None
    if res.raw_intel_id is not None:
        raw = (
            await session.execute(
                select(RawIntel).where(RawIntel.id == res.raw_intel_id)
            )
        ).scalar_one_or_none()
        raw_text = raw.content[:1500] if raw and raw.content else None
    return {
        "id": str(res.id),
        "title": res.title,
        "summary": res.summary,
        "severity": res.severity,
        "category": res.category,
        "status": res.status,
        "confidence": res.confidence,
        "matched_entities": res.matched_entities,
        "recommended_actions": res.recommended_actions,
        "raw_intel_excerpt": raw_text,
        "created_at": res.created_at.isoformat() if res.created_at else None,
    }


@tool(
    name="search_iocs",
    description=(
        "Find indicators of compromise that match a value or substring. "
        "Returns ioc_type, value, confidence, sighting_count, last_seen, "
        "linked threat actor name (if any), and tags. Use this when the "
        "alert mentions a domain / IP / hash you want context on."
    ),
    schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "ioc value or substring"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["query"],
    },
)
async def _tool_search_iocs(
    session: AsyncSession, query: str, limit: int = 10
) -> list[dict[str, Any]]:
    from src.models.intel import IOC, ThreatActor

    rows = (
        await session.execute(
            select(IOC, ThreatActor)
            .outerjoin(ThreatActor, IOC.threat_actor_id == ThreatActor.id)
            .where(IOC.value.ilike(f"%{query}%"))
            .order_by(IOC.last_seen.desc())
            .limit(limit)
        )
    ).all()
    return [
        {
            "id": str(ioc.id),
            "type": ioc.ioc_type,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "sighting_count": ioc.sighting_count,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "tags": ioc.tags or [],
            "threat_actor": actor.primary_alias if actor else None,
        }
        for ioc, actor in rows
    ]


@tool(
    name="lookup_threat_actor",
    description=(
        "Pull the full profile of a threat actor by alias (case-insensitive). "
        "Returns aliases, description, languages, known MITRE TTPs, risk "
        "score, and how many sightings we've recorded."
    ),
    schema={
        "type": "object",
        "properties": {"alias": {"type": "string"}},
        "required": ["alias"],
    },
)
async def _tool_lookup_threat_actor(
    session: AsyncSession, alias: str
) -> dict[str, Any] | None:
    from src.models.intel import ThreatActor

    res = (
        await session.execute(
            select(ThreatActor).where(ThreatActor.primary_alias.ilike(alias))
        )
    ).scalar_one_or_none()
    if res is None:
        # Fall back to alias-list match.
        all_actors = (await session.execute(select(ThreatActor))).scalars().all()
        for actor in all_actors:
            for a in actor.aliases or []:
                if a.lower() == alias.lower():
                    res = actor
                    break
            if res:
                break
    if res is None:
        return {"error": f"threat actor '{alias}' not found"}
    return {
        "primary_alias": res.primary_alias,
        "aliases": res.aliases,
        "description": res.description,
        "languages": res.languages,
        "known_ttps": res.known_ttps,
        "risk_score": res.risk_score,
        "total_sightings": res.total_sightings,
    }


@tool(
    name="related_alerts",
    description=(
        "Find recent alerts for the same organisation that share a category "
        "or matched entity with the seed alert. Use this to spot campaigns "
        "(several low-sev alerts in the same week may add up to a critical)."
    ),
    schema={
        "type": "object",
        "properties": {
            "organization_id": {"type": "string"},
            "category": {"type": "string"},
            "lookback_days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["organization_id"],
    },
)
async def _tool_related_alerts(
    session: AsyncSession,
    organization_id: str,
    category: str | None = None,
    lookback_days: int = 30,
    limit: int = 10,
) -> list[dict[str, Any]]:
    from src.models.threat import Alert

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    stmt = (
        select(Alert)
        .where(Alert.organization_id == uuid.UUID(organization_id))
        .where(Alert.created_at >= cutoff)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    if category:
        stmt = stmt.where(Alert.category == category)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": str(a.id),
            "title": a.title,
            "severity": a.severity,
            "category": a.category,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows
    ]


@tool(
    name="lookup_asset_exposure",
    description=(
        "For an asset value (subdomain / IP / domain), return whether it's "
        "registered, its criticality, and any open exposure findings on it."
    ),
    schema={
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
    },
)
async def _tool_lookup_asset_exposure(
    session: AsyncSession, value: str
) -> dict[str, Any]:
    from src.models.exposures import ExposureFinding, ExposureState
    from src.models.threat import Asset

    asset = (
        await session.execute(select(Asset).where(Asset.value == value))
    ).scalar_one_or_none()
    if asset is None:
        return {"asset_known": False}
    exposures = (
        await session.execute(
            select(ExposureFinding)
            .where(ExposureFinding.asset_id == asset.id)
            .where(ExposureFinding.state == ExposureState.OPEN.value)
            .order_by(ExposureFinding.matched_at.desc())
            .limit(20)
        )
    ).scalars().all()
    return {
        "asset_known": True,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "open_exposures": [
            {
                "severity": e.severity,
                "category": e.category,
                "title": e.title,
                "target": e.target,
                "matched_at": e.matched_at.isoformat() if e.matched_at else None,
            }
            for e in exposures
        ],
    }


# ----------------------------------------------------------------------
#  Investigation report
# ----------------------------------------------------------------------


@dataclass
class TraceStep:
    iteration: int
    thought: str
    tool: str | None
    tool_args: dict | None
    tool_result: Any
    # Wall-clock start of the iteration + duration for tool-call steps.
    # Both nullable for legacy persistence / forced-finalise paths.
    started_at: datetime | None = None
    duration_ms: int | None = None


@dataclass
class InvestigationReport:
    alert_id: str
    iterations: int
    final_assessment: str
    severity_assessment: str  # critical | high | medium | low | informational
    correlated_iocs: list[str] = field(default_factory=list)
    correlated_actors: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    trace: list[TraceStep] = field(default_factory=list)
    # Why the loop terminated (T48).
    stop_reason: str = "high_confidence"
    # Agent's self-reported confidence in the verdict (0..1). When the
    # model omits it we default to 0.5 — neutral.
    final_confidence: float = 0.5
    # LLM token totals (T50). Null when the provider didn't surface
    # them on any iteration. Provider-agnostic — every backend
    # (Anthropic, OpenAI, Ollama, Bridge) populates these consistently
    # when the upstream API exposes usage data.
    input_tokens: int | None = None
    output_tokens: int | None = None
    # Model id reported by the last provider call. Whichever backend
    # (Anthropic / OpenAI / Ollama / Bridge) — they all stash it under
    # ``provider.last_model_id`` after each ``call``.
    model_id: str | None = None

    def markdown_summary(self) -> str:
        lines = [
            f"# Investigation report — alert `{self.alert_id}`",
            "",
            f"**Severity assessment:** {self.severity_assessment}",
            f"**Iterations:** {self.iterations}",
            "",
            "## Final assessment",
            self.final_assessment,
            "",
        ]
        if self.correlated_iocs:
            lines.append("## Correlated IOCs")
            for i in self.correlated_iocs:
                lines.append(f"- `{i}`")
            lines.append("")
        if self.correlated_actors:
            lines.append("## Suspected threat actors")
            for a in self.correlated_actors:
                lines.append(f"- {a}")
            lines.append("")
        if self.recommended_actions:
            lines.append("## Recommended actions")
            for r in self.recommended_actions:
                lines.append(f"- [ ] {r}")
            lines.append("")
        lines.append("## Trace")
        for s in self.trace:
            tool_str = f"`{s.tool}({json.dumps(s.tool_args)})`" if s.tool else "(thinking only)"
            lines.append(f"### Step {s.iteration} — {tool_str}")
            lines.append(f"> {s.thought}")
            if s.tool_result is not None:
                preview = json.dumps(s.tool_result, default=str)[:600]
                lines.append("")
                lines.append(f"```\n{preview}\n```")
            lines.append("")
        return "\n".join(lines)


# ----------------------------------------------------------------------
#  The agent itself
# ----------------------------------------------------------------------


SYSTEM_PROMPT = """You are an Argus Investigation Agent — a senior SOC \
analyst working as autonomous software. A high-severity alert just \
landed and an analyst will read your report.

You have tools that query the live Argus database. Use them. Do not \
guess about IOCs, threat actors, or related alerts when you can look \
them up.

On each turn you can either:
  (a) call exactly ONE tool, OR
  (b) finalise the investigation.

Stop calling tools as soon as you have a defensible verdict. Default \
to a maximum of 6 tool calls per investigation; quality matters more \
than completeness.

When you finalise, return a JSON object:
{
  "thought": "your reasoning for stopping now",
  "finalise": true,
  "severity_assessment": "critical|high|medium|low|informational",
  "final_assessment": "<2-4 sentences for the analyst>",
  "correlated_iocs": ["..."],
  "correlated_actors": ["..."],
  "recommended_actions": ["short imperative bullets"]
}

When you call a tool, return:
{
  "thought": "why this tool, why now",
  "tool": "<tool name>",
  "args": {...}
}

Only output JSON. No prose around it.
"""


class PlanApprovalRequired(Exception):
    """Raised when the agent has emitted a plan but the org requires
    operator approval before tool calls run. The persistence layer
    catches this, stores the plan + flips status to
    ``awaiting_plan_approval``, and lets the operator review via
    POST /investigations/{id}/approve-plan."""

    def __init__(self, plan: list[dict[str, Any]]):
        self.plan = plan
        super().__init__(f"plan approval required ({len(plan)} steps)")


class InvestigationAgent:
    """Runs a tool-calling loop on top of whatever LLM is configured."""

    MAX_ITERATIONS = 6

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def propose_plan(self, alert_id: str) -> list[dict[str, Any]]:
        """Single LLM call that returns the agent's intended tool
        sequence. No tool execution, no DB writes — just a planning
        sketch for the operator to review.

        Output format::
            [{"tool": "lookup_alert", "rationale": "..."}, ...]
        """
        from src.agents.triage_agent import TriageAgent

        triage = TriageAgent()
        catalogue = ", ".join(t.name for t in _TOOLS.values())
        prompt = (
            f"You are about to investigate alert {alert_id}. "
            f"Available tools: {catalogue}. "
            "Return a JSON list of up to 4 steps you intend to call, "
            'each {"tool": "<name>", "rationale": "<one short line>"}. '
            "Only output JSON."
        )
        try:
            raw = await triage._call_llm(SYSTEM_PROMPT, prompt)
        except Exception:  # noqa: BLE001
            # Failed plan proposal isn't fatal — fall back to a
            # generic plan that doesn't constrain the agent.
            return [{"tool": "lookup_alert", "rationale": "Read the alert first."}]
        try:
            text = raw.strip()
            if text.startswith("```"):
                parts = text.split("```")
                if len(parts) >= 3:
                    text = parts[1]
                    if text.startswith("json"):
                        text = text[4:]
            start = text.find("[")
            end = text.rfind("]")
            if start < 0 or end < 0 or end <= start:
                return [{"tool": "lookup_alert", "rationale": "Read the alert first."}]
            plan = json.loads(text[start : end + 1])
            if not isinstance(plan, list):
                return [{"tool": "lookup_alert", "rationale": "Read the alert first."}]
            cleaned: list[dict[str, Any]] = []
            for step in plan[:4]:
                if not isinstance(step, dict):
                    continue
                tool = step.get("tool")
                if not isinstance(tool, str) or tool not in _TOOLS:
                    continue
                rat = step.get("rationale") or ""
                cleaned.append({"tool": tool, "rationale": str(rat)[:200]})
            return cleaned or [
                {"tool": "lookup_alert", "rationale": "Read the alert first."}
            ]
        except (json.JSONDecodeError, ValueError):
            return [{"tool": "lookup_alert", "rationale": "Read the alert first."}]

    # -- public entrypoint ------------------------------------------

    async def investigate(
        self,
        alert_id: str,
        *,
        investigation_id: uuid.UUID | None = None,
        approved_plan: list[dict[str, Any]] | None = None,
    ) -> InvestigationReport:
        from src.agents.triage_agent import (
            LLMNotConfigured,
            LLMTransportError,
        )
        from src.llm.providers import get_provider

        if not settings.llm.is_configured:
            raise LLMNotConfigured(
                "Investigation agent requires a configured LLM provider."
            )

        # Use the provider directly (rather than going through
        # TriageAgent._call_llm) so we can read per-call token counts
        # off the provider instance after each ``await provider.call(...)``.
        # The provider interface is the same regardless of backend
        # (Anthropic / OpenAI / Ollama / Bridge), so the agent body
        # stays provider-agnostic.
        provider = get_provider(settings.llm)
        call_llm = provider.call
        # Per-run token accumulators. Each ``call_llm`` populates
        # ``provider.last_input_tokens`` / ``last_output_tokens`` if the
        # upstream API surfaces them; we sum into these and stamp the
        # totals onto the report. ``None`` means no provider call ever
        # surfaced a token count — distinguish from zero.
        total_input_tokens: int | None = None
        total_output_tokens: int | None = None

        def _accumulate_tokens() -> None:
            nonlocal total_input_tokens, total_output_tokens
            ti = provider.last_input_tokens
            to = provider.last_output_tokens
            if isinstance(ti, int):
                total_input_tokens = (total_input_tokens or 0) + ti
            if isinstance(to, int):
                total_output_tokens = (total_output_tokens or 0) + to

        # Compose the seed turn. When the operator approved (or
        # supplied) a plan, surface it as an analyst hint — the agent
        # is encouraged to follow it but free to deviate when the
        # evidence calls for it.
        seed = f"Begin the investigation. Seed alert id: {alert_id}."
        if approved_plan:
            # Both shapes are accepted: [{"tool":..,"rationale":..}]
            # (plan-gate proposals) and [{"kind":"extra_context","text":...}]
            # (rerun extra_context). Render whichever is present.
            hint_lines: list[str] = []
            for step in approved_plan:
                if not isinstance(step, dict):
                    continue
                if step.get("kind") == "extra_context" and step.get("text"):
                    hint_lines.append(f"Analyst note: {step['text']}")
                elif step.get("tool"):
                    rat = step.get("rationale") or ""
                    hint_lines.append(
                        f"  - {step['tool']}: {rat}" if rat else f"  - {step['tool']}"
                    )
            if hint_lines:
                seed += "\n\nAnalyst-approved hint (follow when sensible):\n" + "\n".join(hint_lines)
        history: list[dict[str, str]] = [
            {"role": "user", "content": seed}
        ]
        trace: list[TraceStep] = []

        # We hand the model the tool catalogue once via the system prompt
        # so it doesn't have to keep it in working memory across turns.
        catalogue = json.dumps(
            [
                {
                    "name": t.name,
                    "description": t.description,
                    "schema": t.schema,
                }
                for t in _TOOLS.values()
            ],
            indent=2,
        )
        system = SYSTEM_PROMPT + "\n\n## Tools\n" + catalogue

        # Track per-iteration evidence so we can stop early when three
        # iterations in a row return nothing new — saves LLM calls and
        # gives the analyst a meaningful ``no_new_evidence`` stop reason.
        seen_results_hashes: set[str] = set()
        no_new_streak = 0

        # Live event bus — emits each step over SSE so the dashboard
        # can render the trace as it happens. No-op when no subscriber
        # is listening; the persistence layer remains the source of
        # truth for the final view.
        from src.core.investigation_events import bus as _ev_bus
        async def _emit(payload: dict[str, Any]) -> None:
            if investigation_id is None:
                return
            try:
                await _ev_bus.emit(investigation_id, payload)
            except Exception:  # noqa: BLE001
                logger.debug("[investigate] sse emit failed", exc_info=True)

        for i in range(1, self.MAX_ITERATIONS + 1):
            iter_started = datetime.now(timezone.utc)
            user_blob = self._render_history(history)
            try:
                raw = await call_llm(system, user_blob)
            except LLMNotConfigured:
                # Misconfiguration — never retry, the second call would
                # fail identically. Bubble up.
                raise
            except LLMTransportError as exc:
                # Bridge / API transient failure (timeout, connection
                # reset, rate limit). Retry ONCE — the bridge worker
                # may have been mid-rebuild, the upstream API may have
                # rate-limited a single call, etc. A second consecutive
                # failure is a real outage and we surface it.
                logger.warning(
                    "[investigate] iter=%d transport error, retrying once: %s",
                    i, exc,
                )
                try:
                    raw = await call_llm(system, user_blob)
                except LLMTransportError:
                    raise
            _accumulate_tokens()
            decision = self._parse_decision(raw)
            thought = decision.get("thought") or ""

            if decision.get("finalise"):
                step = TraceStep(
                    iteration=i,
                    thought=thought,
                    tool=None,
                    tool_args=None,
                    tool_result=None,
                    started_at=iter_started,
                    duration_ms=int(
                        (datetime.now(timezone.utc) - iter_started).total_seconds() * 1000
                    ),
                )
                trace.append(step)
                await _emit({
                    "kind": "step",
                    "iteration": step.iteration,
                    "tool": step.tool,
                    "thought": step.thought,
                    "args": step.tool_args,
                    "result": step.tool_result,
                    "duration_ms": step.duration_ms,
                })
                # Confidence: prefer the model's self-report when it
                # offers a number in [0,1]; else infer from severity.
                fc = decision.get("final_confidence")
                try:
                    final_confidence = float(fc)
                    if not (0.0 <= final_confidence <= 1.0):
                        raise ValueError
                except (TypeError, ValueError):
                    # Soft inference from severity + presence of evidence.
                    sev = (decision.get("severity_assessment") or "medium").lower()
                    base = {"critical": 0.85, "high": 0.75, "medium": 0.55, "low": 0.4, "informational": 0.3}.get(sev, 0.5)
                    has_evidence = bool(
                        decision.get("correlated_iocs")
                        or decision.get("correlated_actors")
                    )
                    final_confidence = min(1.0, base + (0.05 if has_evidence else 0.0))
                return InvestigationReport(
                    alert_id=alert_id,
                    iterations=i,
                    final_assessment=decision.get("final_assessment", ""),
                    severity_assessment=decision.get("severity_assessment", "medium"),
                    correlated_iocs=list(decision.get("correlated_iocs") or []),
                    correlated_actors=list(decision.get("correlated_actors") or []),
                    recommended_actions=list(
                        decision.get("recommended_actions") or []
                    ),
                    trace=trace,
                    stop_reason="high_confidence",
                    final_confidence=final_confidence,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    model_id=getattr(provider, "last_model_id", None),
                )

            tool_name = decision.get("tool")
            tool_args = decision.get("args") or {}
            if tool_name not in _TOOLS:
                # Model hallucinated a tool — log + nudge it back.
                history.append(
                    {
                        "role": "user",
                        "content": (
                            f"You asked for tool '{tool_name}' which does "
                            "not exist. Pick from the catalogue or finalise."
                        ),
                    }
                )
                step = TraceStep(
                    iteration=i,
                    thought=thought,
                    tool=tool_name,
                    tool_args=tool_args,
                    tool_result={"error": "unknown_tool"},
                    started_at=iter_started,
                    duration_ms=int(
                        (datetime.now(timezone.utc) - iter_started).total_seconds() * 1000
                    ),
                )
                trace.append(step)
                await _emit({
                    "kind": "step",
                    "iteration": step.iteration,
                    "tool": step.tool,
                    "thought": step.thought,
                    "args": step.tool_args,
                    "result": step.tool_result,
                    "duration_ms": step.duration_ms,
                })
                continue

            tool_started = datetime.now(timezone.utc)
            try:
                tool_result = await _TOOLS[tool_name].runner(self.session, **tool_args)
            except TypeError as exc:
                tool_result = {"error": f"bad arguments: {exc}"}
            except Exception as exc:  # noqa: BLE001 — must not crash the loop
                logger.exception("[investigate] tool %s crashed", tool_name)
                tool_result = {"error": f"{type(exc).__name__}: {exc}"}

            # No-new-evidence detection: hash the result and bump a
            # streak when the agent gets a payload it has seen before.
            # Three in a row → break early with stop_reason=no_new_evidence.
            try:
                rh = hashlib.sha256(
                    json.dumps(tool_result, sort_keys=True, default=str).encode()
                ).hexdigest()
            except Exception:  # noqa: BLE001 — hashing must never crash
                rh = ""
            if rh and rh in seen_results_hashes:
                no_new_streak += 1
            else:
                no_new_streak = 0
                if rh:
                    seen_results_hashes.add(rh)

            step = TraceStep(
                iteration=i,
                thought=thought,
                tool=tool_name,
                tool_args=tool_args,
                tool_result=tool_result,
                started_at=tool_started,
                duration_ms=int(
                    (datetime.now(timezone.utc) - tool_started).total_seconds() * 1000
                ),
            )
            trace.append(step)
            await _emit({
                "kind": "step",
                "iteration": step.iteration,
                "tool": step.tool,
                "thought": step.thought,
                "args": step.tool_args,
                "result": step.tool_result,
                "duration_ms": step.duration_ms,
            })
            history.append(
                {
                    "role": "assistant",
                    "content": json.dumps({"tool": tool_name, "args": tool_args}),
                }
            )
            history.append(
                {
                    "role": "user",
                    "content": json.dumps(
                        {"tool_result": tool_result}, default=str
                    )[:6000],
                }
            )

            # Stop early when the agent is spinning on duplicate evidence.
            if no_new_streak >= 3:
                logger.info(
                    "[investigate] alert=%s stopping early: no_new_evidence (streak=%d)",
                    alert_id, no_new_streak,
                )
                return InvestigationReport(
                    alert_id=alert_id,
                    iterations=i,
                    final_assessment=(
                        "Investigation stopped early: three consecutive tool "
                        "calls returned the same evidence the agent had "
                        "already seen. Forwarding the partial trace."
                    ),
                    severity_assessment="medium",
                    recommended_actions=[
                        "Have an analyst review the trace below.",
                    ],
                    trace=trace,
                    stop_reason="no_new_evidence",
                    final_confidence=0.4,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    model_id=getattr(provider, "last_model_id", None),
                )

        # Fell off the end of MAX_ITERATIONS — synthesise a forced finalise.
        return InvestigationReport(
            alert_id=alert_id,
            iterations=self.MAX_ITERATIONS,
            final_assessment=(
                "Investigation exceeded maximum iterations without a "
                "self-reported verdict. Forwarding raw trace to analyst."
            ),
            severity_assessment="medium",
            recommended_actions=["Have an analyst review the trace below."],
            trace=trace,
            stop_reason="max_iterations",
            final_confidence=0.45,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            model_id=getattr(provider, "last_model_id", None),
        )

    # -- helpers ----------------------------------------------------

    @staticmethod
    def _render_history(history: list[dict[str, str]]) -> str:
        """Flatten the conversation into a single prompt body for
        provider transports that don't take a turn list (the existing
        triage transport sends one user prompt at a time).
        """
        return "\n\n".join(f"[{m['role']}] {m['content']}" for m in history)

    @staticmethod
    def _parse_decision(raw: str) -> dict[str, Any]:
        """Parse the model's JSON. Tolerate ```json fences and stray
        prose by extracting the largest balanced JSON object."""
        text = raw.strip()
        if text.startswith("```"):
            # Strip a fenced code block.
            parts = text.split("```")
            if len(parts) >= 3:
                text = parts[1]
                if text.startswith("json"):
                    text = text[4:]
        # Find first '{' and matching closing brace.
        start = text.find("{")
        if start < 0:
            return {"finalise": True, "final_assessment": text, "severity_assessment": "medium"}
        depth = 0
        end = -1
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end < 0:
            return {"finalise": True, "final_assessment": text, "severity_assessment": "medium"}
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            return {"finalise": True, "final_assessment": text[:600], "severity_assessment": "medium"}


# ----------------------------------------------------------------------
#  Persistence — round-trip an investigation through the DB
# ----------------------------------------------------------------------


# Auto-promotion is gated behind two env vars so it cannot be enabled
# accidentally:
#
#   ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED  must be flipped to "false"
#   ARGUS_AGENT_AUTO_PROMOTE            must be set to "true"
#
# Even with both set, only ``critical`` verdicts trigger the bypass.
# See :mod:`src.core.agent_guard` for the audited decision path.
_AUTO_PROMOTE_SEVERITIES = {"critical"}


async def run_and_persist(
    session: AsyncSession,
    *,
    alert_id: uuid.UUID,
    organization_id: uuid.UUID,
    investigation_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Run an investigation and store the trace + verdict.

    If ``investigation_id`` is supplied, the existing row is moved
    through ``running → completed/failed``; otherwise a fresh row is
    created in ``running`` state. Returns the row id either way.

    Designed to be called from a FastAPI BackgroundTask or the worker —
    NEVER from inside an HTTP request handler (the agent loop can take
    many seconds).
    """
    from src.models.investigations import (
        Investigation,
        InvestigationStatus,
        InvestigationStopReason,
    )
    from src.agents.triage_agent import LLMNotConfigured, LLMTransportError
    import time

    # Create or claim the row up front so the API can return its id
    # immediately even though the loop hasn't run yet.
    if investigation_id is None:
        inv = Investigation(
            organization_id=organization_id,
            alert_id=alert_id,
            status=InvestigationStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
        )
        session.add(inv)
        await session.flush()
        investigation_id = inv.id
    else:
        inv = (
            await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
        ).scalar_one()
        inv.status = InvestigationStatus.RUNNING.value
        if not inv.started_at:
            inv.started_at = datetime.now(timezone.utc)
    await session.commit()

    # Plan-then-act gate (T57). Org-opted-in installs pause AFTER the
    # agent emits a plan, so the operator can review tool choices
    # before any tool runs. Skipped on resume — when the row already
    # has a plan we treat that as the approved plan.
    org_settings = await _get_org_agent_settings(session, organization_id)
    plan_gate = bool(
        org_settings is not None
        and getattr(org_settings, "investigation_plan_approval", False)
    )
    if plan_gate and not inv.plan:
        try:
            plan = await InvestigationAgent(session).propose_plan(str(alert_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[investigate] plan proposal failed: %s", exc)
            plan = [{"tool": "lookup_alert", "rationale": "fallback plan"}]
        inv.plan = plan
        inv.status = InvestigationStatus.AWAITING_PLAN_APPROVAL.value
        await session.commit()
        try:
            from src.core.investigation_events import bus as _ev_bus
            await _ev_bus.emit(
                investigation_id,
                {"kind": "plan", "status": inv.status, "plan": plan},
            )
        except Exception:  # noqa: BLE001
            pass
        logger.info(
            "[investigate] paused for plan approval inv=%s plan=%s",
            inv.id, [s.get("tool") for s in plan],
        )
        return investigation_id

    started = time.monotonic()
    agent = InvestigationAgent(session)
    # Lifecycle "started" event so SSE subscribers get a clean
    # marker even if the agent crashes before the first step.
    from src.core.investigation_events import bus as _ev_bus
    try:
        await _ev_bus.emit(investigation_id, {"kind": "started", "status": "running"})
    except Exception:  # noqa: BLE001
        pass
    # Approved plan (post-gate or rerun extra_context) is surfaced to
    # the agent as an analyst hint in the seed turn. Honoured-but-not-
    # enforced — the agent retains discretion to deviate.
    approved_plan = inv.plan if isinstance(inv.plan, list) else None
    try:
        report = await agent.investigate(
            str(alert_id),
            investigation_id=investigation_id,
            approved_plan=approved_plan,
        )
        # Provider-agnostic model id: the agent now records the provider's
        # ``last_model_id`` on the report directly, so we don't need to
        # peek at the BridgeProvider singleton (which only worked for
        # bridge-backed runs and was None for direct Anthropic/OpenAI).
        model_id = report.model_id

        inv.status = InvestigationStatus.COMPLETED.value
        inv.final_assessment = report.final_assessment
        inv.severity_assessment = report.severity_assessment
        inv.correlated_iocs = report.correlated_iocs
        inv.correlated_actors = report.correlated_actors
        inv.recommended_actions = report.recommended_actions
        inv.iterations = report.iterations
        # Persist per-step timing + (later) tokens so the dashboard can
        # render duration / cost without re-running anything. Legacy
        # tools without timing get null fields and degrade gracefully.
        inv.trace = [
            {
                "iteration": s.iteration,
                "thought": s.thought,
                "tool": s.tool,
                "args": s.tool_args,
                "result": s.tool_result,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "duration_ms": s.duration_ms,
            }
            for s in report.trace
        ]
        inv.model_id = model_id
        inv.duration_ms = int((time.monotonic() - started) * 1000)
        inv.finished_at = datetime.now(timezone.utc)
        inv.stop_reason = report.stop_reason
        inv.final_confidence = report.final_confidence
        # Deduped, ordered tool list — first-occurrence order so the
        # dashboard chips read like a timeline ("lookup_alert →
        # search_iocs → lookup_threat_actor"). Filter out None which
        # represents the finalise-only step.
        seen: set[str] = set()
        ordered_tools: list[str] = []
        for s in report.trace:
            if s.tool and s.tool not in seen:
                seen.add(s.tool)
                ordered_tools.append(s.tool)
        inv.tools_used = ordered_tools
        inv.input_tokens = report.input_tokens
        inv.output_tokens = report.output_tokens
    except (LLMNotConfigured, LLMTransportError) as exc:
        inv.status = InvestigationStatus.FAILED.value
        inv.error_message = f"{type(exc).__name__}: {exc}"
        inv.duration_ms = int((time.monotonic() - started) * 1000)
        inv.finished_at = datetime.now(timezone.utc)
        inv.stop_reason = InvestigationStopReason.LLM_ERROR.value
        logger.warning("[investigate] failed for alert=%s: %s", alert_id, exc)
    except Exception as exc:  # noqa: BLE001 — never crash the worker
        inv.status = InvestigationStatus.FAILED.value
        inv.error_message = f"{type(exc).__name__}: {exc}"[:500]
        inv.duration_ms = int((time.monotonic() - started) * 1000)
        inv.finished_at = datetime.now(timezone.utc)
        inv.stop_reason = InvestigationStopReason.LLM_ERROR.value
        logger.exception("[investigate] crashed for alert=%s", alert_id)

    await session.commit()

    try:
        await _ev_bus.emit(
            investigation_id,
            {
                "kind": "stopped",
                "status": inv.status,
                "stop_reason": inv.stop_reason,
                "final_confidence": inv.final_confidence,
                "iterations": inv.iterations,
                "duration_ms": inv.duration_ms,
                "error_message": inv.error_message,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    # Auto-promote — runs through TWO gates layered:
    #   1. Per-org ``auto_promote_critical`` setting (default off). The
    #      operator opts in via Settings → Agents.
    #   2. The global HIL guard (``ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED`` +
    #      ``ARGUS_AGENT_AUTO_PROMOTE``). Even with the per-org flag on,
    #      the master guard wins and the auto-promote is skipped.
    #
    # An additional substantive filter: we only auto-promote when the
    # investigation surfaced at least one correlated actor (otherwise
    # "critical" is just an LLM rating with no anchor — analyst should
    # eyeball before a Case opens).
    if (
        inv.status == InvestigationStatus.COMPLETED.value
        and (inv.severity_assessment or "").lower() in _AUTO_PROMOTE_SEVERITIES
        and inv.correlated_actors
    ):
        org_settings = await _get_org_agent_settings(session, organization_id)
        if org_settings is not None and not org_settings.auto_promote_critical:
            logger.info(
                "[investigate] auto-promote skipped (org %s opt-out) for inv=%s",
                organization_id, inv.id,
            )
        else:
            from src.core.agent_guard import AutoActionKind, allow_auto_action

            decision = await allow_auto_action(
                session,
                kind=AutoActionKind.AUTO_PROMOTE,
                reason=(
                    f"investigation={inv.id} severity={inv.severity_assessment} "
                    f"iterations={inv.iterations} actors={len(inv.correlated_actors)}"
                ),
            )
            if decision.allowed:
                try:
                    case_id = await promote_to_case(
                        session,
                        investigation_id=inv.id,
                        user_id=None,  # bot-promoted
                    )
                    await session.commit()
                    logger.warning(
                        "[investigate] auto-promoted investigation=%s → case=%s "
                        "(org=%s, actors=%s)",
                        inv.id, case_id, organization_id, inv.correlated_actors,
                    )
                except PromoteError as exc:
                    logger.warning(
                        "[investigate] auto-promote skipped for %s: %s", inv.id, exc
                    )

    # Internal routing — chain to a Threat Hunter run when this
    # investigation surfaced a critical actor cluster. This is NOT an
    # external action, so the human-in-loop guard doesn't apply; the
    # per-org settings table can still disable the chain explicitly.
    if (
        inv.status == InvestigationStatus.COMPLETED.value
        and (inv.severity_assessment or "").lower() == "critical"
        and inv.correlated_actors
    ):
        try:
            await _maybe_chain_to_threat_hunter(
                session,
                investigation=inv,
            )
        except Exception:  # noqa: BLE001 — best-effort routing
            logger.exception(
                "[investigate] chain-to-hunter failed for %s", inv.id
            )

    return investigation_id


async def _maybe_chain_to_threat_hunter(session: AsyncSession, *, investigation) -> None:
    """When a critical investigation completes with correlated actors,
    queue a Threat Hunter run anchored on the first one. Internal
    routing only — the hunt itself produces advisory findings that the
    SOC reviews, no external state mutation."""
    from src.models.threat_hunts import HuntStatus, ThreatHuntRun
    from src.models.intel import ThreatActor

    # Per-org agent settings act as the operator's kill-switch.
    settings_row = await _get_org_agent_settings(session, investigation.organization_id)
    if settings_row is not None and not settings_row.chain_investigation_to_hunt:
        return
    if settings_row is not None and not settings_row.threat_hunter_enabled:
        return

    # Only queue if no hunt is already in flight for this org.
    inflight = (
        await session.execute(
            select(ThreatHuntRun.id)
            .where(ThreatHuntRun.organization_id == investigation.organization_id)
            .where(
                ThreatHuntRun.status.in_(
                    [HuntStatus.QUEUED.value, HuntStatus.RUNNING.value]
                )
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if inflight is not None:
        return

    # Look up the actor by alias so we can anchor the hunt.
    primary_alias = investigation.correlated_actors[0]
    actor = (
        await session.execute(
            select(ThreatActor).where(
                ThreatActor.primary_alias.ilike(primary_alias)
            )
        )
    ).scalar_one_or_none()

    run = ThreatHuntRun(
        organization_id=investigation.organization_id,
        primary_actor_id=actor.id if actor is not None else None,
        primary_actor_alias=primary_alias,
        status=HuntStatus.QUEUED.value,
    )
    session.add(run)
    await session.commit()
    logger.info(
        "[investigate] chained → hunt %s anchored on actor '%s' (from investigation %s)",
        run.id, primary_alias, investigation.id,
    )


async def _get_org_agent_settings(session: AsyncSession, org_id):
    """Lazy lookup so the chain helper doesn't need to import the
    settings model at module load (avoids a circular import on the
    first migration cycle)."""
    try:
        from src.models.org_agent_settings import OrganizationAgentSettings
    except ImportError:
        return None
    return (
        await session.execute(
            select(OrganizationAgentSettings).where(
                OrganizationAgentSettings.organization_id == org_id
            )
        )
    ).scalar_one_or_none()


# ----------------------------------------------------------------------
#  Auto-trigger helper — used by alert creation paths
# ----------------------------------------------------------------------


# Severities that trigger an automatic investigation when a new Alert
# lands. Anything below ``high`` would flood the queue without
# meaningful payoff; the analyst can always queue manually via the
# POST endpoint.
_AUTO_INVESTIGATE_SEVERITIES = {"critical", "high"}
_AUTO_INVESTIGATE_MIN_CONFIDENCE = 0.7


async def maybe_queue_investigation(
    session: AsyncSession,
    alert: Any,
) -> uuid.UUID | None:
    """Create a queued Investigation row if the alert is severe enough.

    Returns the row id when one was queued, ``None`` otherwise. The
    caller is responsible for the actual run (the API does it via
    ``BackgroundTasks``; the worker drains queued rows on a tick).

    Idempotent: a second call for the same alert is a no-op while a
    queued/running investigation exists. Once one completes a re-run
    is allowed (analyst may want a refresh after new IOCs land).
    """
    from src.models.investigations import Investigation, InvestigationStatus

    severity = (getattr(alert, "severity", None) or "").lower()
    confidence = float(getattr(alert, "confidence", 0.0) or 0.0)
    if severity not in _AUTO_INVESTIGATE_SEVERITIES:
        return None
    if confidence < _AUTO_INVESTIGATE_MIN_CONFIDENCE:
        return None

    # Per-org veto — operators can disable Investigation per-org from
    # Settings → Agents in the dashboard.
    org_settings = await _get_org_agent_settings(session, alert.organization_id)
    if org_settings is not None and not org_settings.investigation_enabled:
        logger.info(
            "[investigate] queue skipped (org %s disabled investigation_enabled)",
            alert.organization_id,
        )
        return None

    existing = (
        await session.execute(
            select(Investigation.id)
            .where(Investigation.alert_id == alert.id)
            .where(
                Investigation.status.in_(
                    [
                        InvestigationStatus.QUEUED.value,
                        InvestigationStatus.RUNNING.value,
                    ]
                )
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    inv = Investigation(
        organization_id=alert.organization_id,
        alert_id=alert.id,
        status=InvestigationStatus.QUEUED.value,
    )
    session.add(inv)
    await session.flush()
    logger.info(
        "[investigate] queued for alert=%s severity=%s confidence=%.2f",
        alert.id, severity, confidence,
    )
    return inv.id


# ----------------------------------------------------------------------
#  Promote — turn a completed investigation into a Case
# ----------------------------------------------------------------------


# The agent's system prompt allows ``informational``; cases use the
# canonical Severity enum which uses ``info``. Map at the boundary so
# either spelling is accepted at the API and the DB sees the canonical
# value.
_AGENT_TO_CASE_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


class PromoteError(RuntimeError):
    """Caller asked to promote something that isn't promotable yet."""


async def promote_to_case(
    session: AsyncSession,
    *,
    investigation_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Create a Case from a completed investigation and link it back.

    Idempotent: if the investigation already references a case, return
    that case id without creating a second one. Refuses to promote
    non-completed investigations.

    Side effects (one transaction, committed by the caller):
      * insert ``cases`` row populated from the verdict
      * insert ``case_findings`` row tagging the seed alert as primary
        and any DLP/exposure/etc. finding referenced by ``finding_type``
        in the future (alerts only for now — extend when other
        finding-type tools land)
      * set ``investigations.case_id``
    """
    from src.models.cases import Case, CaseFinding, CaseSeverity, CaseState
    from src.models.investigations import Investigation, InvestigationStatus
    from src.models.threat import Alert

    inv = (
        await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
    ).scalar_one_or_none()
    if inv is None:
        raise PromoteError(f"investigation {investigation_id} not found")
    if inv.status != InvestigationStatus.COMPLETED.value:
        raise PromoteError(
            f"only completed investigations can be promoted; current status="
            f"{inv.status}"
        )
    if inv.case_id is not None:
        return inv.case_id

    alert = (
        await session.execute(select(Alert).where(Alert.id == inv.alert_id))
    ).scalar_one_or_none()
    if alert is None:
        # Alert was deleted out from under us — promote anyway with a
        # synthetic title so the case is still useful.
        alert_title = f"alert {inv.alert_id} (deleted)"
        primary_asset_id = None
    else:
        alert_title = alert.title
        primary_asset_id = None  # Alerts don't carry an asset_id directly.

    severity_raw = (inv.severity_assessment or "medium").lower()
    severity = _AGENT_TO_CASE_SEVERITY.get(severity_raw, "medium")

    # Compose the case body — point analysts at the investigation
    # explicitly so they don't mistake the agent's verdict for a
    # human's.
    summary_lines: list[str] = []
    if inv.final_assessment:
        summary_lines.append(inv.final_assessment.strip())
    summary_lines.append("")
    summary_lines.append(
        f"Promoted from agentic investigation `{inv.id}` "
        f"({inv.iterations} step(s), model={inv.model_id or 'n/a'})."
    )
    if inv.correlated_actors:
        summary_lines.append(
            "Suspected actors: " + ", ".join(inv.correlated_actors)
        )
    if inv.correlated_iocs:
        summary_lines.append(
            "Correlated IOCs: " + ", ".join(inv.correlated_iocs[:8])
            + ("…" if len(inv.correlated_iocs) > 8 else "")
        )
    summary = "\n".join(summary_lines).strip()

    tags = ["agent-promoted"]
    if alert is not None and alert.category:
        tags.append(alert.category)
    for actor in inv.correlated_actors[:3]:
        # Slug-ish tag; case schema uses ARRAY(String) so spaces are fine,
        # but lower-case keeps consistency with existing taxonomy.
        tags.append(f"actor:{actor.lower().replace(' ', '-')}")

    case = Case(
        organization_id=inv.organization_id,
        title=alert_title[:500],
        summary=summary,
        severity=severity,
        state=CaseState.OPEN.value,
        tags=tags,
        primary_asset_id=primary_asset_id,
        owner_user_id=user_id,
        extra={
            "promoted_from_investigation_id": str(inv.id),
            "investigation_model_id": inv.model_id,
            "investigation_iterations": inv.iterations,
            "recommended_actions": inv.recommended_actions,
        },
    )
    session.add(case)
    await session.flush()

    # Link the seed alert as the primary finding so the case detail
    # page already has something concrete to render.
    if alert is not None:
        session.add(
            CaseFinding(
                case_id=case.id,
                alert_id=alert.id,
                finding_type="alert",
                finding_id=alert.id,
                is_primary=True,
                linked_by_user_id=user_id,
                link_reason=f"Seed alert for investigation {inv.id}",
            )
        )

    inv.case_id = case.id
    logger.info(
        "[investigate] promoted investigation=%s → case=%s severity=%s",
        inv.id, case.id, severity,
    )
    return case.id


__all__ = [
    "InvestigationAgent",
    "InvestigationReport",
    "TraceStep",
    "run_and_persist",
    "maybe_queue_investigation",
    "promote_to_case",
    "PromoteError",
]
