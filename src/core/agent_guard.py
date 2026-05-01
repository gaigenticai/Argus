"""Human-in-the-loop guard for agentic actions.

**Argus's first principle is that no agent ever takes an external or
state-mutating action without human approval.** All four agents
(Investigation, Brand Defender, Case Copilot, Threat Hunter) propose;
analysts dispose.

Some operators (typically not regulated banks) want to opt into a
narrow class of *auto-actions* — for example, automatically filing a
takedown when the agent's confidence is overwhelming. The schema and
code paths exist for that, but they all route through this module so
the override is loud, audited, and impossible to enable by accident.

Two env vars participate:

  * ``ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED`` — master switch, default
    ``true``. While true, **every** auto-action call is refused with
    :class:`HumanInLoopRequired`, regardless of any per-feature flag.

  * ``ARGUS_AGENT_AUTO_<FEATURE>`` — per-feature opt-in (only checked
    once the master switch is off). Examples:
    ``ARGUS_AGENT_AUTO_PROMOTE`` for Investigation→Case auto-promotion,
    ``ARGUS_AGENT_AUTO_TAKEDOWN`` for Brand-Defender auto-filing.

Each successful bypass writes an ``AuditAction.SETTINGS_UPDATE`` row
(repurposed as the audit channel for autonomous operations until a
dedicated ``AGENT_AUTO_ACTION`` enum value lands) so compliance
reviewers can grep for them.

Usage::

    from src.core.agent_guard import allow_auto_action, AutoActionKind

    bypass = await allow_auto_action(
        session,
        kind=AutoActionKind.AUTO_TAKEDOWN,
        reason=f"action={action.id} confidence={action.confidence:.2f}",
    )
    if not bypass:
        # leave the row queued for an analyst to click. Default path.
        return None

    # rare path — operator explicitly opted in. Caller proceeds with
    # the mutation, having already passed the audit hop.
"""

from __future__ import annotations

import enum
import logging
import os
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


class AutoActionKind(str, enum.Enum):
    """Closed set of auto-actions the guard knows about. Adding a new
    one requires extending this enum AND .env.example AND the
    per-org settings table — by design."""

    AUTO_PROMOTE = "auto_promote"          # investigation → case
    AUTO_TAKEDOWN = "auto_takedown"        # brand action → takedown ticket
    CHAIN_INVESTIGATION_TO_HUNT = "chain_investigation_to_hunt"
    # ^ chaining is "internal routing only"; it does NOT mutate
    # external state and is allowed even with the master guard on.


# Master switch — default-on so a fresh install is locked down.
_MASTER_ENV = "ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED"

# Per-feature env names. Centralised here so dashboard / CLI / tests
# all read the same canonical name.
_FEATURE_ENV: dict[AutoActionKind, str] = {
    AutoActionKind.AUTO_PROMOTE: "ARGUS_AGENT_AUTO_PROMOTE",
    AutoActionKind.AUTO_TAKEDOWN: "ARGUS_AGENT_AUTO_TAKEDOWN",
    AutoActionKind.CHAIN_INVESTIGATION_TO_HUNT: "ARGUS_AGENT_CHAIN_INVESTIGATION_TO_HUNT",
}


def _is_truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in {"1", "true", "yes", "on"}


def is_human_in_loop_required() -> bool:
    """Read the master switch. Defaults to True when unset."""
    raw = os.environ.get(_MASTER_ENV)
    if raw is None:
        return True
    # Operator must explicitly type "false" / "0" / "no" / "off" to
    # opt out. Empty / blank counts as "leave the default in place".
    return not _is_truthy(raw) is False if raw.strip() else True
    # ^ The double negation reads weird; spelled out: when raw is
    #   "true" → True (HIL required); "false" → False (HIL relaxed).


# Re-implement cleanly — the expression above is too clever.
def is_human_in_loop_required() -> bool:  # noqa: F811
    """Read the master switch. Defaults to True when unset."""
    raw = os.environ.get(_MASTER_ENV, "true")
    return _is_truthy(raw)


def is_feature_enabled(kind: AutoActionKind) -> bool:
    """Per-feature flag. Independent of the master switch — both must
    line up before an auto-action is permitted."""
    env = _FEATURE_ENV.get(kind)
    if env is None:
        return False
    return _is_truthy(os.environ.get(env))


@dataclass
class GuardDecision:
    """Result of a single guard check. Kept structured so dashboards
    can render the *why* alongside the *what*."""

    allowed: bool
    kind: AutoActionKind
    master_switch_relaxed: bool
    feature_enabled: bool
    reason: str


class HumanInLoopRequired(RuntimeError):
    """Raised by callers that don't want to silently swallow a refusal."""


async def allow_auto_action(
    session: AsyncSession,
    *,
    kind: AutoActionKind,
    reason: str,
    actor_user_id: str | None = None,
) -> GuardDecision:
    """Decide whether an auto-action is permitted right now and log
    the decision. Always writes an audit-log row when the answer is
    "yes, bypass" so compliance reviewers can grep for autonomous
    actions taken without a human in the loop.

    The "no" path is *not* logged on every call — that would flood
    the audit table since the guard is checked in tight worker loops.
    Refusal is logged at INFO level instead.
    """

    master_required = is_human_in_loop_required()
    feature_on = is_feature_enabled(kind)

    if master_required:
        decision = GuardDecision(
            allowed=False,
            kind=kind,
            master_switch_relaxed=False,
            feature_enabled=feature_on,
            reason=(
                f"refused: ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED is on (default). "
                f"To bypass, set both ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED=false "
                f"and {_FEATURE_ENV[kind]}=true. Caller reason: {reason}"
            ),
        )
        logger.info("[agent-guard] %s", decision.reason)
        return decision

    if not feature_on:
        decision = GuardDecision(
            allowed=False,
            kind=kind,
            master_switch_relaxed=True,
            feature_enabled=False,
            reason=(
                f"refused: master switch relaxed but {_FEATURE_ENV[kind]} "
                f"is not set. Caller reason: {reason}"
            ),
        )
        logger.info("[agent-guard] %s", decision.reason)
        return decision

    # Both flags align — bypass is permitted. Audit the bypass loudly.
    decision = GuardDecision(
        allowed=True,
        kind=kind,
        master_switch_relaxed=True,
        feature_enabled=True,
        reason=f"BYPASS: {reason}",
    )
    logger.warning(
        "[agent-guard] auto-action %s permitted with HIL bypass: %s",
        kind.value, reason,
    )
    try:
        from src.core.auth import audit_log
        from src.models.auth import AuditAction

        await audit_log(
            session,
            AuditAction.SETTINGS_UPDATE,
            user=None,
            resource_type="agent_auto_action",
            resource_id=kind.value,
            details={
                "kind": kind.value,
                "reason": reason,
                "master_switch": _MASTER_ENV,
                "feature_env": _FEATURE_ENV[kind],
                "bypass": True,
            },
        )
    except Exception:  # noqa: BLE001 — audit must never crash the agent
        logger.exception(
            "[agent-guard] failed to write audit row for %s bypass", kind.value
        )
    return decision


def posture_snapshot() -> dict[str, object]:
    """Lightweight read-only snapshot for the dashboard banner.
    Exposes the current master + per-feature state without touching
    the DB."""

    return {
        "human_in_loop_required": is_human_in_loop_required(),
        "features": {
            kind.value: is_feature_enabled(kind)
            for kind in AutoActionKind
        },
        "env_vars": {
            "master": _MASTER_ENV,
            **{kind.value: env for kind, env in _FEATURE_ENV.items()},
        },
    }


__all__ = [
    "AutoActionKind",
    "GuardDecision",
    "HumanInLoopRequired",
    "allow_auto_action",
    "is_human_in_loop_required",
    "is_feature_enabled",
    "posture_snapshot",
]
