"""Correlation Agent — connects dots across multiple intelligence sources.

This agent takes individual alerts and finds patterns:
- Same threat actor across forums
- CVE + exploit PoC + org uses affected software = escalate
- Multiple credential leaks from same source = possible breach
- VIP mentioned in dark web + credential found = critical
"""

from __future__ import annotations


import json
import logging
from typing import Any

from src.config.settings import settings

logger = logging.getLogger(__name__)

CORRELATION_SYSTEM_PROMPT = """You are Argus Correlation Engine, an expert at connecting threat intelligence signals.

Given a set of recent alerts for an organization, identify patterns and correlations that indicate:
1. Coordinated attacks or campaigns targeting the organization
2. Escalating threats (e.g., discussion → exploit development → active exploitation)
3. Related incidents that should be investigated together
4. Threat actor profiles emerging across multiple sources

Respond ONLY with valid JSON:
{
  "correlations": [
    {
      "alert_ids": ["id1", "id2"],
      "pattern": "description of the correlation",
      "escalation": "none|minor|significant|critical",
      "recommendation": "what should be done"
    }
  ],
  "threat_actors": [
    {
      "identifier": "username/alias",
      "seen_in": ["source1", "source2"],
      "activity_summary": "what they're doing",
      "risk_level": "low|medium|high|critical"
    }
  ],
  "campaign_indicators": [
    {
      "name": "campaign name/identifier",
      "indicators": ["indicator1", "indicator2"],
      "targets": ["what/who is targeted"],
      "stage": "reconnaissance|weaponization|delivery|exploitation|installation|c2|actions"
    }
  ]
}

Be precise. Only report real correlations, not speculative ones."""


class CorrelationAgent:
    """Finds patterns across multiple alerts."""

    def __init__(self):
        self.provider = settings.llm.provider
        self.model = settings.llm.model
        self.base_url = settings.llm.base_url
        self.api_key = settings.llm.api_key

    async def correlate(
        self,
        alerts: list[dict[str, Any]],
        org_profile: dict[str, Any],
        time_window_hours: int = 72,
    ) -> dict[str, Any] | None:
        """Analyze a batch of recent alerts for correlations.

        Returns ``None`` when:
            * fewer than 2 alerts in the batch (nothing to correlate);
            * the LLM provider is not configured;
            * the LLM transport returned non-2xx;
            * the response could not be parsed as JSON.
        Each branch logs structured context so an operator can tell
        "no correlations" apart from "engine never ran".
        """
        if len(alerts) < 2:
            return None

        from src.agents.triage_agent import LLMNotConfigured, LLMTransportError

        prompt = self._build_prompt(alerts, org_profile, time_window_hours)

        try:
            response = await self._call_llm(CORRELATION_SYSTEM_PROMPT, prompt)
        except LLMNotConfigured as e:
            logger.warning(f"[correlation] Skipping — LLM not configured: {e}")
            return None
        except LLMTransportError as e:
            logger.error(f"[correlation] LLM transport failure: {e}")
            return None
        except Exception as e:
            logger.exception(f"[correlation] LLM call crashed: {e}")
            return None

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            logger.error(
                "[correlation] LLM returned invalid JSON: %s",
                response[:200] if response else "<empty>",
            )
            return None

    def _build_prompt(
        self,
        alerts: list[dict],
        org_profile: dict,
        time_window_hours: int,
    ) -> str:
        alerts_text = "\n\n".join(
            f"Alert #{i+1} (ID: {a.get('id', 'N/A')})\n"
            f"  Severity: {a.get('severity')}\n"
            f"  Category: {a.get('category')}\n"
            f"  Title: {a.get('title')}\n"
            f"  Summary: {a.get('summary')}\n"
            f"  Source: {a.get('source_type')} / {a.get('source_name')}\n"
            f"  Matched: {json.dumps(a.get('matched_entities', {}))}\n"
            f"  Time: {a.get('created_at')}"
            for i, a in enumerate(alerts)
        )

        return f"""## Organization
Name: {org_profile.get('name')}
Domains: {', '.join(org_profile.get('domains', []))}
Industry: {org_profile.get('industry', 'Unknown')}

## Recent Alerts (last {time_window_hours}h)
{alerts_text}

Analyze these alerts for correlations, threat actor patterns, and campaign indicators."""

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        from src.llm.providers import get_provider
        from src.config.settings import settings
        provider = get_provider(settings.llm)
        return await provider.call(system_prompt, user_prompt)
