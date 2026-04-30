"""Threat Hunter Agent — proactive autonomous IOC sweeps.

Fourth tool-calling agent. Different operational shape from the
others:

  * **Scheduler-triggered**, not event-triggered. Runs once a week
    by default (``ARGUS_WORKER_THREAT_HUNT_INTERVAL`` seconds, default
    604800 = 7 days).
  * **No human anchor.** Each run picks its own focus actor cluster
    based on recent activity in the IOC + sighting tables. The
    operator only sees the results.
  * **Output is plural.** Other agents produce one verdict; this one
    produces a list of findings.

Tools (all DB queries — keeps the surface tight):

  * ``pick_active_actor``        — most recently sighted threat actor
  * ``get_actor_ttps``           — known_ttps for the chosen actor
  * ``search_iocs_by_actor``     — IOCs we already have linked to that actor
  * ``find_org_alerts_for_category`` — does the org have alerts in a
                                     category that maps to this actor's TTPs?
  * ``find_org_exposures``       — do we have open exposures in the
                                     entry-vector this actor prefers?
  * ``record_findings``          — finalise with the structured list
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings


logger = logging.getLogger(__name__)


# --- Tool registry ----------------------------------------------------


@dataclass
class _Tool:
    name: str
    description: str
    schema: dict[str, Any]
    runner: Callable[..., Any]


_TOOLS: dict[str, _Tool] = {}


def _tool(name: str, description: str, schema: dict[str, Any]):
    def deco(fn):
        _TOOLS[name] = _Tool(name=name, description=description, schema=schema, runner=fn)
        return fn

    return deco


@_tool(
    name="pick_active_actor",
    description=(
        "Pick the threat-actor cluster worth hunting this week. Picks "
        "by recency of sightings (last_seen) and total_sightings. "
        "Returns alias, aliases, known_ttps, risk_score, total_sightings."
    ),
    schema={"type": "object", "properties": {}},
)
async def _t_pick_actor(session: AsyncSession) -> dict[str, Any] | None:
    from src.models.intel import ThreatActor

    res = (
        await session.execute(
            select(ThreatActor)
            .order_by(ThreatActor.last_seen.desc().nullslast())
            .limit(1)
        )
    ).scalar_one_or_none()
    if res is None:
        return {"error": "no threat actors on file"}
    return {
        "id": str(res.id),
        "primary_alias": res.primary_alias,
        "aliases": res.aliases,
        "known_ttps": res.known_ttps,
        "risk_score": res.risk_score,
        "total_sightings": res.total_sightings,
        "last_seen": res.last_seen.isoformat() if res.last_seen else None,
    }


@_tool(
    name="search_iocs_by_actor",
    description=(
        "IOCs we already track that are linked to this actor. Helpful "
        "for 'do these C2 domains overlap our DNS logs' style hunts."
    ),
    schema={
        "type": "object",
        "properties": {
            "actor_id": {"type": "string"},
            "limit": {"type": "integer", "default": 15},
        },
        "required": ["actor_id"],
    },
)
async def _t_iocs_by_actor(
    session: AsyncSession, actor_id: str, limit: int = 15
) -> list[dict[str, Any]]:
    from src.models.intel import IOC

    rows = (
        await session.execute(
            select(IOC)
            .where(IOC.threat_actor_id == uuid.UUID(actor_id))
            .order_by(IOC.last_seen.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "type": r.ioc_type,
            "value": r.value,
            "confidence": r.confidence,
            "tags": r.tags or [],
        }
        for r in rows
    ]


@_tool(
    name="find_org_alerts_for_category",
    description=(
        "Has the org seen any alerts in the given category in the last "
        "N days? (Map MITRE TTPs onto our category enum loosely.)"
    ),
    schema={
        "type": "object",
        "properties": {
            "organization_id": {"type": "string"},
            "category": {"type": "string"},
            "lookback_days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 8},
        },
        "required": ["organization_id", "category"],
    },
)
async def _t_alerts_for_category(
    session: AsyncSession,
    organization_id: str,
    category: str,
    lookback_days: int = 30,
    limit: int = 8,
) -> list[dict[str, Any]]:
    from src.models.threat import Alert

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    rows = (
        await session.execute(
            select(Alert)
            .where(Alert.organization_id == uuid.UUID(organization_id))
            .where(Alert.category == category)
            .where(Alert.created_at >= cutoff)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "title": r.title,
            "severity": r.severity,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@_tool(
    name="find_org_exposures",
    description=(
        "Open exposure findings on the org's surface. Use this when "
        "the actor's preferred entry vector matches an exposure we're "
        "currently leaking (e.g. T1190 actors + an open RCE exposure)."
    ),
    schema={
        "type": "object",
        "properties": {
            "organization_id": {"type": "string"},
            "min_severity": {"type": "string", "default": "high"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["organization_id"],
    },
)
async def _t_exposures(
    session: AsyncSession,
    organization_id: str,
    min_severity: str = "high",
    limit: int = 10,
) -> list[dict[str, Any]]:
    from src.models.exposures import ExposureFinding, ExposureState

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = sev_order.get(min_severity.lower(), 3)
    allowed = [k for k, v in sev_order.items() if v >= threshold]
    rows = (
        await session.execute(
            select(ExposureFinding)
            .where(ExposureFinding.organization_id == uuid.UUID(organization_id))
            .where(ExposureFinding.state == ExposureState.OPEN.value)
            .where(ExposureFinding.severity.in_(allowed))
            .order_by(ExposureFinding.matched_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "severity": r.severity,
            "category": r.category,
            "title": r.title,
            "target": r.target,
        }
        for r in rows
    ]


@_tool(
    name="get_mitre_techniques_by_ids",
    description=(
        "Look up MITRE technique rows by their external_ids "
        "(e.g. ['T1190', 'T1566']). Returns name, tactics, and "
        "detection guidance for each."
    ),
    schema={
        "type": "object",
        "properties": {
            "external_ids": {
                "type": "array",
                "items": {"type": "string"},
            }
        },
        "required": ["external_ids"],
    },
)
async def _t_mitre_lookup(
    session: AsyncSession, external_ids: list[str]
) -> list[dict[str, Any]]:
    from src.models.mitre import MitreTechnique

    rows = (
        await session.execute(
            select(MitreTechnique).where(
                MitreTechnique.external_id.in_(external_ids)
            )
        )
    ).scalars().all()
    return [
        {
            "external_id": r.external_id,
            "name": r.name,
            "tactics": r.tactics,
            "detection": (r.detection or "")[:300],
        }
        for r in rows
    ]


# --- Report dataclasses ----------------------------------------------


@dataclass
class TraceStep:
    iteration: int
    thought: str
    tool: str | None
    tool_args: dict | None
    tool_result: Any


@dataclass
class HuntReport:
    organization_id: str
    iterations: int
    summary: str
    confidence: float
    primary_actor_id: str | None = None
    primary_actor_alias: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    trace: list[TraceStep] = field(default_factory=list)


# --- Agent loop -------------------------------------------------------


SYSTEM_PROMPT = """You are an Argus Threat Hunter — a proactive senior \
analyst, working as autonomous software, who runs weekly to look for \
gaps between active threat-actor activity and our defensive posture.

Your job:
  1. Pick a threat-actor cluster worth hunting this week.
  2. Pull their known TTPs.
  3. Look for evidence the actor's TTPs are visible in our environment
     (alerts in matching categories, open exposures matching their
     entry vectors, IOCs that overlap our intel).
  4. Surface 1–4 ``hunt findings``. Each one is a short, actionable
     insight the SOC can act on.
  5. If the org's surface is clean against this actor, say so —
     ``findings: []`` plus a confident summary is a valid outcome.

Each turn, emit ONE JSON object.

Tool call:
{
  "thought": "why this tool, why now",
  "tool": "<tool name>",
  "args": {...}
}

Finalise:
{
  "thought": "summary of how you decided",
  "finalise": true,
  "summary": "<2-4 sentences for the SOC>",
  "primary_actor_id": "<uuid or null>",
  "primary_actor_alias": "<alias or null>",
  "confidence": 0.0..1.0,
  "findings": [
    {
      "title": "short headline",
      "description": "1-2 sentences",
      "relevance": 0.0..1.0,
      "mitre_ids": ["T1190"],
      "ioc_ids": ["uuid", ...],
      "recommended_action": "imperative sentence"
    }
  ]
}

Default to a maximum of 6 tool calls. Output only JSON.
"""


class ThreatHunterAgent:
    MAX_ITERATIONS = 6

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def hunt(self, *, organization_id: str) -> HuntReport:
        from src.agents.triage_agent import (
            LLMNotConfigured,
            LLMTransportError,
            TriageAgent,
        )

        if not settings.llm.is_configured:
            raise LLMNotConfigured("Threat Hunter requires a configured LLM provider.")

        triage = TriageAgent()
        call_llm = triage._call_llm

        history: list[dict[str, str]] = [
            {
                "role": "user",
                "content": (
                    f"Begin weekly threat hunt. Organization id: "
                    f"{organization_id}."
                ),
            }
        ]
        trace: list[TraceStep] = []
        catalogue = json.dumps(
            [
                {"name": t.name, "description": t.description, "schema": t.schema}
                for t in _TOOLS.values()
            ],
            indent=2,
        )
        system = SYSTEM_PROMPT + "\n\n## Tools\n" + catalogue

        for i in range(1, self.MAX_ITERATIONS + 1):
            user_blob = "\n\n".join(
                f"[{m['role']}] {m['content']}" for m in history
            )
            try:
                raw = await call_llm(system, user_blob)
            except (LLMNotConfigured, LLMTransportError):
                raise
            decision = _parse_decision(raw)
            thought = decision.get("thought") or ""

            if decision.get("finalise"):
                trace.append(
                    TraceStep(
                        iteration=i,
                        thought=thought,
                        tool=None,
                        tool_args=None,
                        tool_result=None,
                    )
                )
                actor_id = decision.get("primary_actor_id")
                # Validate the actor id parses as UUID before persisting.
                try:
                    actor_uuid_str = (
                        str(uuid.UUID(actor_id)) if actor_id else None
                    )
                except (ValueError, TypeError):
                    actor_uuid_str = None
                return HuntReport(
                    organization_id=organization_id,
                    iterations=i,
                    summary=decision.get("summary") or "",
                    confidence=float(decision.get("confidence") or 0.0),
                    primary_actor_id=actor_uuid_str,
                    primary_actor_alias=decision.get("primary_actor_alias") or None,
                    findings=list(decision.get("findings") or []),
                    trace=trace,
                )

            tool_name = decision.get("tool")
            tool_args = decision.get("args") or {}
            if tool_name not in _TOOLS:
                history.append(
                    {
                        "role": "user",
                        "content": (
                            f"Tool '{tool_name}' is not in the catalogue. "
                            "Pick from the list or finalise."
                        ),
                    }
                )
                trace.append(
                    TraceStep(
                        iteration=i,
                        thought=thought,
                        tool=tool_name,
                        tool_args=tool_args,
                        tool_result={"error": "unknown_tool"},
                    )
                )
                continue

            try:
                tool_result = await _TOOLS[tool_name].runner(self.session, **tool_args)
            except TypeError as exc:
                tool_result = {"error": f"bad arguments: {exc}"}
            except Exception as exc:  # noqa: BLE001
                logger.exception("[threat-hunter] tool %s crashed", tool_name)
                tool_result = {"error": f"{type(exc).__name__}: {exc}"}

            trace.append(
                TraceStep(
                    iteration=i,
                    thought=thought,
                    tool=tool_name,
                    tool_args=tool_args,
                    tool_result=tool_result,
                )
            )
            history.append(
                {"role": "assistant", "content": json.dumps({"tool": tool_name, "args": tool_args})}
            )
            history.append(
                {
                    "role": "user",
                    "content": json.dumps({"tool_result": tool_result}, default=str)[:6000],
                }
            )

        return HuntReport(
            organization_id=organization_id,
            iterations=self.MAX_ITERATIONS,
            summary=(
                "Reached maximum iterations without a self-reported summary. "
                "Forwarding raw trace to the SOC."
            ),
            confidence=0.0,
            trace=trace,
        )


def _parse_decision(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 3:
            text = parts[1]
            if text.startswith("json"):
                text = text[4:]
    start = text.find("{")
    if start < 0:
        return {"finalise": True, "summary": text[:400]}
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
        return {"finalise": True, "summary": text[:400]}
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return {"finalise": True, "summary": text[start:end][:400]}


# --- Persistence ------------------------------------------------------


async def run_and_persist(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID | None = None,
) -> uuid.UUID:
    from src.agents.triage_agent import LLMNotConfigured, LLMTransportError
    from src.llm.providers import BridgeProvider
    from src.models.threat_hunts import HuntStatus, ThreatHuntRun

    if run_id is None:
        run = ThreatHuntRun(
            organization_id=organization_id,
            status=HuntStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
        )
        session.add(run)
        await session.flush()
        run_id = run.id
    else:
        run = (
            await session.execute(
                select(ThreatHuntRun).where(ThreatHuntRun.id == run_id)
            )
        ).scalar_one()
        run.status = HuntStatus.RUNNING.value
        run.started_at = datetime.now(timezone.utc)
    await session.commit()

    started = time.monotonic()
    agent = ThreatHunterAgent(session)
    try:
        report = await agent.hunt(organization_id=str(organization_id))
        try:
            model_id = getattr(BridgeProvider._singleton, "last_model_id", None)
        except Exception:  # noqa: BLE001
            model_id = None

        run.status = HuntStatus.COMPLETED.value
        run.summary = report.summary
        run.confidence = report.confidence
        run.findings = report.findings
        run.iterations = report.iterations
        run.primary_actor_id = (
            uuid.UUID(report.primary_actor_id) if report.primary_actor_id else None
        )
        run.primary_actor_alias = report.primary_actor_alias
        run.trace = [
            {
                "iteration": s.iteration,
                "thought": s.thought,
                "tool": s.tool,
                "args": s.tool_args,
                "result": s.tool_result,
            }
            for s in report.trace
        ]
        run.model_id = model_id
        run.duration_ms = int((time.monotonic() - started) * 1000)
        run.finished_at = datetime.now(timezone.utc)
    except (LLMNotConfigured, LLMTransportError) as exc:
        run.status = HuntStatus.FAILED.value
        run.error_message = f"{type(exc).__name__}: {exc}"
        run.duration_ms = int((time.monotonic() - started) * 1000)
        run.finished_at = datetime.now(timezone.utc)
        logger.warning("[threat-hunter] failed: %s", exc)
    except Exception as exc:  # noqa: BLE001
        run.status = HuntStatus.FAILED.value
        run.error_message = f"{type(exc).__name__}: {exc}"[:500]
        run.duration_ms = int((time.monotonic() - started) * 1000)
        run.finished_at = datetime.now(timezone.utc)
        logger.exception("[threat-hunter] crashed")

    await session.commit()
    return run_id


__all__ = ["ThreatHunterAgent", "HuntReport", "TraceStep", "run_and_persist"]
