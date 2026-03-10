"""Triage Agent — the brain of Argus.

Takes raw intelligence, matches it against monitored organizations,
classifies threats, and produces actionable alerts.
"""

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.models.threat import Alert, ThreatCategory, ThreatSeverity
from src.models.intel import TriageFeedback

from src.core.activity import ActivityType, emit as activity_emit

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are Argus, an elite threat intelligence analyst AI.
Your job is to analyze raw intelligence data and determine if it represents a threat
to a specific organization, its assets, or its VIP personnel.

You must respond ONLY with valid JSON. No markdown, no explanation outside JSON.

Analyze the provided intelligence against the organization's profile and respond with:
{
  "is_threat": true/false,
  "category": "one of: credential_leak, data_breach, stealer_log, ransomware, ransomware_victim, access_sale, exploit, phishing, impersonation, doxxing, insider_threat, brand_abuse, dark_web_mention, underground_chatter, initial_access",
  "severity": "one of: critical, high, medium, low, info",
  "confidence": 0.0-1.0,
  "title": "concise alert title",
  "summary": "2-3 sentence summary of the threat",
  "matched_entities": {"what matched": "how it matched"},
  "recommended_actions": ["action 1", "action 2"],
  "reasoning": "brief explanation of your analysis"
}

Severity guidelines:
- CRITICAL: Active exploitation, confirmed data breach, stolen credentials actively sold, org named on ransomware leak site, initial access to org being auctioned
- HIGH: Stealer logs containing org domain credentials, VIP credential found, ransomware group targeting org's industry, access broker listing mentioning org
- MEDIUM: Mention on dark web/underground forums, potential phishing infrastructure, unconfirmed leaks, chatter about org's industry on I2P/Lokinet
- LOW: General underground chatter not specific to org, industry threat intelligence, forum discussions about org's tech stack
- INFO: Background noise, general dark web activity, no direct org relevance

Be precise. False positives waste analyst time. Only flag as threat if there's a real connection."""


class TriageAgent:
    """LLM-powered threat triage agent."""

    def __init__(self, db: AsyncSession | None = None):
        self.provider = settings.llm.provider
        self.model = settings.llm.model
        self.base_url = settings.llm.base_url
        self.api_key = settings.llm.api_key
        self._db = db

    async def _build_system_prompt(self) -> str:
        """Build system prompt, enriched with recent analyst feedback when available."""
        if self._db is None:
            return TRIAGE_SYSTEM_PROMPT

        try:
            # Fetch up to 3 true-positive feedback records (most recent first)
            tp_query = (
                select(TriageFeedback, Alert)
                .join(Alert, TriageFeedback.alert_id == Alert.id)
                .where(TriageFeedback.is_true_positive == True)  # noqa: E712
                .order_by(TriageFeedback.created_at.desc())
                .limit(3)
            )
            tp_result = await self._db.execute(tp_query)
            tp_rows = tp_result.all()

            # Fetch up to 3 false-positive feedback records (most recent first)
            fp_query = (
                select(TriageFeedback, Alert)
                .join(Alert, TriageFeedback.alert_id == Alert.id)
                .where(TriageFeedback.is_true_positive == False)  # noqa: E712
                .order_by(TriageFeedback.created_at.desc())
                .limit(3)
            )
            fp_result = await self._db.execute(fp_query)
            fp_rows = fp_result.all()

            if not tp_rows and not fp_rows:
                return TRIAGE_SYSTEM_PROMPT

            # Build the feedback section
            lines = [
                "",
                "---",
                "## Historical Analyst Feedback",
                "Use these real analyst corrections to calibrate your analysis.",
                "",
            ]

            if tp_rows:
                lines.append("### True Positives (correctly flagged threats)")
                for feedback, alert in tp_rows:
                    correction = ""
                    if feedback.corrected_category or feedback.corrected_severity:
                        parts = []
                        if feedback.corrected_category:
                            parts.append(f"category should be {feedback.corrected_category}")
                        if feedback.corrected_severity:
                            parts.append(f"severity should be {feedback.corrected_severity}")
                        correction = f" Analyst correction: {'; '.join(parts)}."
                    notes = f' Notes: "{feedback.feedback_notes}"' if feedback.feedback_notes else ""
                    lines.append(
                        f"- Alert: \"{alert.title}\" | Category: {feedback.original_category} | "
                        f"Severity: {feedback.original_severity} | Confidence: {feedback.original_confidence:.2f} "
                        f"→ TRUE POSITIVE.{correction}{notes}"
                    )
                lines.append("")

            if fp_rows:
                lines.append("### False Positives (incorrectly flagged — should NOT have been alerts)")
                for feedback, alert in fp_rows:
                    notes = f' Notes: "{feedback.feedback_notes}"' if feedback.feedback_notes else ""
                    lines.append(
                        f"- Alert: \"{alert.title}\" | Category: {feedback.original_category} | "
                        f"Severity: {feedback.original_severity} | Confidence: {feedback.original_confidence:.2f} "
                        f"→ FALSE POSITIVE.{notes}"
                    )
                lines.append("")

            lines.append("Learn from these examples to reduce false positives and improve severity/category accuracy.")

            return TRIAGE_SYSTEM_PROMPT + "\n".join(lines)

        except Exception as e:
            logger.warning(f"[triage] Failed to load feedback for prompt enrichment: {e}")
            return TRIAGE_SYSTEM_PROMPT

    async def analyze(
        self,
        raw_content: str,
        source_type: str,
        source_name: str,
        org_profile: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Analyze raw intelligence against an organization's profile.

        Args:
            raw_content: The raw intelligence text
            source_type: Where this came from (tor_forum, i2p, stealer_log, etc.)
            source_name: Specific source name
            org_profile: Organization data including domains, keywords, VIPs, tech stack

        Returns:
            Triage result dict or None if not a threat
        """
        user_prompt = self._build_prompt(raw_content, source_type, source_name, org_profile)
        org_name = org_profile.get("name", "Unknown")

        await activity_emit(
            ActivityType.TRIAGE_START,
            "triage_agent",
            f"Analyzing intel from {source_name} against {org_name}",
            {"source_type": source_type, "source_name": source_name, "org": org_name},
        )

        try:
            system_prompt = await self._build_system_prompt()
            await activity_emit(
                ActivityType.TRIAGE_LLM_CALL,
                "triage_agent",
                f"Calling {self.provider}/{self.model} for threat classification",
                {"provider": self.provider, "model": self.model, "org": org_name},
            )
            response = await self._call_llm(system_prompt, user_prompt)
            result = self._parse_json_response(response)

            if result is None:
                logger.warning(f"[triage] Could not parse LLM response: {response[:200]}")
                return None

            if not result.get("is_threat", False):
                await activity_emit(
                    ActivityType.TRIAGE_NO_THREAT,
                    "triage_agent",
                    f"No threat detected for {org_name} from {source_name}",
                    {"org": org_name, "source": source_name},
                )
                return None

            # Validate enums
            result["category"] = self._validate_enum(
                result.get("category"), ThreatCategory, ThreatCategory.DARK_WEB_MENTION
            )
            result["severity"] = self._validate_enum(
                result.get("severity"), ThreatSeverity, ThreatSeverity.LOW
            )
            result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))

            await activity_emit(
                ActivityType.TRIAGE_RESULT,
                "triage_agent",
                f"Threat detected: [{result['severity'].upper()}] {result.get('title', 'Unknown')}",
                {
                    "severity": result["severity"],
                    "category": result["category"],
                    "confidence": result["confidence"],
                    "org": org_name,
                    "title": result.get("title"),
                },
                severity="warning" if result["severity"] in ("critical", "high") else "info",
            )

            return result
        except Exception as e:
            logger.error(f"[triage] Analysis failed: {e}")
            return None

    def _parse_json_response(self, response: str) -> dict | None:
        """Parse JSON from LLM response, handling markdown wrapping."""
        import re

        # Try direct parse first
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Strip markdown code blocks: ```json ... ``` or ``` ... ```
        cleaned = re.sub(r"^```(?:json)?\s*", "", response.strip())
        cleaned = re.sub(r"\s*```$", "", cleaned.strip())
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Find the first { and last } to extract JSON object
        first_brace = response.find("{")
        last_brace = response.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(response[first_brace : last_brace + 1])
            except json.JSONDecodeError:
                pass

        return None

    def _build_prompt(
        self,
        raw_content: str,
        source_type: str,
        source_name: str,
        org_profile: dict,
    ) -> str:
        return f"""## Intelligence Data
Source Type: {source_type}
Source: {source_name}
Content:
---
{raw_content[:4000]}
---

## Organization Profile
Name: {org_profile.get('name', 'Unknown')}
Domains: {', '.join(org_profile.get('domains', []))}
Keywords: {', '.join(org_profile.get('keywords', []))}
Industry: {org_profile.get('industry', 'Unknown')}
Tech Stack: {json.dumps(org_profile.get('tech_stack', {}), indent=2)}
VIP Names: {', '.join(v.get('name', '') for v in org_profile.get('vips', []))}
VIP Emails: {', '.join(e for v in org_profile.get('vips', []) for e in v.get('emails', []))}

Analyze whether this intelligence represents a threat to this organization."""

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call the configured LLM provider."""
        if self.provider == "ollama":
            return await self._call_ollama(system_prompt, user_prompt)
        elif self.provider == "openai":
            return await self._call_openai(system_prompt, user_prompt)
        elif self.provider == "anthropic":
            return await self._call_anthropic(system_prompt, user_prompt)
        else:
            raise ValueError(f"Unknown LLM provider: {self.provider}")

    async def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "format": "json",
                },
            ) as resp:
                data = await resp.json()
                return data["message"]["content"]

    async def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        import aiohttp

        # z.ai and OpenAI-compatible APIs: base_url may already include path
        base = self.base_url.rstrip("/")
        if base.endswith("/v4") or base.endswith("/v1"):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                },
            ) as resp:
                data = await resp.json()
                logger.debug(f"[triage] LLM response keys: {list(data.keys())}")

                # Handle both OpenAI and z.ai response formats
                if "choices" in data:
                    return data["choices"][0]["message"]["content"]
                elif "data" in data and "choices" in data["data"]:
                    return data["data"]["choices"][0]["message"]["content"]
                elif "result" in data:
                    return data["result"]
                elif "output" in data:
                    return data["output"]
                else:
                    logger.error(f"[triage] Unexpected LLM response format: {list(data.keys())} — {str(data)[:500]}")
                    raise ValueError(f"Unexpected response format: {list(data.keys())}")

    async def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        import aiohttp

        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json={
                    "model": self.model,
                    "max_tokens": 1024,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
            ) as resp:
                data = await resp.json()
                return data["content"][0]["text"]

    def _validate_enum(self, value: str | None, enum_class, default):
        if value is None:
            return default.value
        try:
            return enum_class(value).value
        except ValueError:
            return default.value
