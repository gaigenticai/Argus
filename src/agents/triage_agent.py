"""Triage Agent — the brain of Argus.

Takes raw intelligence, matches it against monitored organizations,
classifies threats, and produces actionable alerts.
"""

import json
import logging
from typing import Any

from src.config.settings import settings
from src.models.threat import ThreatCategory, ThreatSeverity

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are Argus, an elite threat intelligence analyst AI.
Your job is to analyze raw intelligence data and determine if it represents a threat
to a specific organization, its assets, or its VIP personnel.

You must respond ONLY with valid JSON. No markdown, no explanation outside JSON.

Analyze the provided intelligence against the organization's profile and respond with:
{
  "is_threat": true/false,
  "category": "one of: credential_leak, data_breach, vulnerability, exploit, ransomware, phishing, impersonation, doxxing, insider_threat, brand_abuse, dark_web_mention, paste_leak, code_leak",
  "severity": "one of: critical, high, medium, low, info",
  "confidence": 0.0-1.0,
  "title": "concise alert title",
  "summary": "2-3 sentence summary of the threat",
  "matched_entities": {"what matched": "how it matched"},
  "recommended_actions": ["action 1", "action 2"],
  "reasoning": "brief explanation of your analysis"
}

Severity guidelines:
- CRITICAL: Active exploitation, confirmed data breach, leaked credentials actively sold
- HIGH: PoC exploit for vuln in org's stack, VIP credential found, ransomware targeting org's industry
- MEDIUM: Mention on dark web forums, potential phishing infrastructure, unconfirmed leaks
- LOW: Generic vulnerability not specific to org's stack, general industry threat chatter
- INFO: Background noise, general security news, no direct org relevance

Be precise. False positives waste analyst time. Only flag as threat if there's a real connection."""


class TriageAgent:
    """LLM-powered threat triage agent."""

    def __init__(self):
        self.provider = settings.llm.provider
        self.model = settings.llm.model
        self.base_url = settings.llm.base_url
        self.api_key = settings.llm.api_key

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
            source_type: Where this came from (tor_forum, paste_site, etc.)
            source_name: Specific source name
            org_profile: Organization data including domains, keywords, VIPs, tech stack

        Returns:
            Triage result dict or None if not a threat
        """
        user_prompt = self._build_prompt(raw_content, source_type, source_name, org_profile)

        try:
            response = await self._call_llm(TRIAGE_SYSTEM_PROMPT, user_prompt)
            result = json.loads(response)

            if not result.get("is_threat", False):
                return None

            # Validate enums
            result["category"] = self._validate_enum(
                result.get("category"), ThreatCategory, ThreatCategory.DARK_WEB_MENTION
            )
            result["severity"] = self._validate_enum(
                result.get("severity"), ThreatSeverity, ThreatSeverity.LOW
            )
            result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))

            return result

        except json.JSONDecodeError:
            logger.error(f"[triage] LLM returned invalid JSON")
            return None
        except Exception as e:
            logger.error(f"[triage] Analysis failed: {e}")
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
                    "response_format": {"type": "json_object"},
                },
            ) as resp:
                data = await resp.json()
                return data["choices"][0]["message"]["content"]

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
