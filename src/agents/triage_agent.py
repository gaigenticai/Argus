"""Triage Agent — the brain of Argus.

Takes raw intelligence, matches it against monitored organizations,
classifies threats, and produces actionable alerts.
"""

from __future__ import annotations


import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.llm.providers import (  # noqa: F401  — re-exported for backward compat
    LLMNotConfigured,
    LLMTransportError,
    get_provider,
)
from src.models.threat import Alert, ThreatCategory, ThreatSeverity
from src.models.intel import TriageFeedback

from src.core.activity import ActivityType, emit as activity_emit
from src.intel.name_permutations import (
    brand_permutations,
    email_permutations,
    split_name,
    username_permutations,
)

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
                await activity_emit(
                    ActivityType.TRIAGE_NO_THREAT,
                    "triage_agent",
                    f"LLM response could not be parsed for {org_name}",
                    {"org": org_name, "response_preview": response[:200]},
                    severity="warning",
                )
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
        except LLMNotConfigured as e:
            logger.warning(f"[triage] Skipping analysis — LLM not configured: {e}")
            await activity_emit(
                ActivityType.TRIAGE_NO_THREAT,
                "triage_agent",
                f"LLM not configured — triage skipped for {org_name}",
                {"org": org_name, "reason": "llm_not_configured"},
                severity="warning",
            )
            return None
        except LLMTransportError as e:
            logger.error(f"[triage] LLM transport failure: {e}")
            await activity_emit(
                ActivityType.TRIAGE_NO_THREAT,
                "triage_agent",
                f"LLM call failed for {org_name}",
                {"org": org_name, "error": str(e)[:300]},
                severity="error",
            )
            return None
        except Exception as e:
            logger.exception(f"[triage] Analysis failed: {e}")
            await activity_emit(
                ActivityType.TRIAGE_NO_THREAT,
                "triage_agent",
                f"Triage agent crashed for {org_name}",
                {"org": org_name, "error": str(e)[:300]},
                severity="error",
            )
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
        # Expand brand keywords + VIP identifiers using name_permutations
        # so the LLM sees impersonation candidates (homoglyphs, leet,
        # acronyms, common email patterns) without bloating org config.
        # The expanded sets are passed as ADDITIONAL match surface — the
        # LLM still applies judgment, we just remove the false-negative
        # path where a typosquatted brand mention or permuted VIP email
        # would otherwise be invisible.
        org_name = org_profile.get("name") or ""
        configured_keywords = list(org_profile.get("keywords") or [])
        domains = list(org_profile.get("domains") or [])
        vips = list(org_profile.get("vips") or [])

        brand_variants: list[str] = []
        seen_brand: set[str] = set()
        for term in [org_name, *configured_keywords]:
            for v in brand_permutations(term, max_variants=20):
                key = v.lower()
                if key in seen_brand:
                    continue
                seen_brand.add(key)
                brand_variants.append(v)

        vip_email_variants: list[str] = []
        vip_username_variants: list[str] = []
        for v in vips:
            name = v.get("name") or ""
            first, last = split_name(name)
            # Literal entries always win — emails/usernames the operator
            # explicitly added are ground truth. Permutations are extra.
            for e in v.get("emails") or []:
                if e and e not in vip_email_variants:
                    vip_email_variants.append(e)
            for u in v.get("usernames") or []:
                if u and u not in vip_username_variants:
                    vip_username_variants.append(u)
            for e in email_permutations(first, last, domains, max_patterns=8):
                if e not in vip_email_variants:
                    vip_email_variants.append(e)
            for u in username_permutations(first, last, max_patterns=6):
                if u not in vip_username_variants:
                    vip_username_variants.append(u)

        # Cap displayed sets so the prompt doesn't balloon. The LLM
        # gets a clear signal of "this is the surface" without becoming
        # token-prohibitive — 40 brand variants + 30 VIP emails is
        # enough headroom for a banking-grade enterprise.
        brand_display = brand_variants[:40]
        email_display = vip_email_variants[:30]
        username_display = vip_username_variants[:20]

        return f"""## Intelligence Data
Source Type: {source_type}
Source: {source_name}
Content:
---
{raw_content[:4000]}
---

## Organization Profile
Name: {org_name or 'Unknown'}
Domains: {', '.join(domains)}
Keywords (configured): {', '.join(configured_keywords)}
Brand impersonation surface (homoglyph/leet/acronym variants — flag any mention):
{', '.join(brand_display) if brand_display else '(none)'}
Industry: {org_profile.get('industry') or 'Unknown'}
Tech Stack: {json.dumps(org_profile.get('tech_stack') or {}, indent=2)}
VIP Names: {', '.join(v.get('name', '') for v in vips)}
VIP Email surface (configured + common enterprise patterns):
{', '.join(email_display) if email_display else '(none)'}
VIP Username surface:
{', '.join(username_display) if username_display else '(none)'}

Analyze whether this intelligence represents a threat to this organization.
A match against any brand-impersonation variant or VIP email/username
permutation should be treated as a probable threat, not a coincidence."""

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Dispatch to the configured LLM provider via ``src.llm.providers``.

        Raises ``LLMNotConfigured`` when credentials are absent so the
        triage path can emit a structured ``triage_skipped`` activity
        rather than silently returning a degraded result.
        """
        provider = get_provider(settings.llm)
        return await provider.call(system_prompt, user_prompt)

    def _validate_enum(self, value: str | None, enum_class, default):
        if value is None:
            return default.value
        try:
            return enum_class(value).value
        except ValueError:
            return default.value
