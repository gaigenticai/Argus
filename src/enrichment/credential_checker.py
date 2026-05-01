"""Credential leak checker — cross-references intel with monitored emails/usernames.

Uses pattern matching to detect leaked credentials in raw intelligence
without relying on any external paid APIs.
"""

from __future__ import annotations


import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CredentialMatch:
    matched_value: str
    match_type: str  # email, username, domain, phone
    context: str  # surrounding text
    confidence: float


class CredentialChecker:
    """Checks raw intelligence text for mentions of monitored credentials."""

    # Common leak patterns
    EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+", re.IGNORECASE)
    PASSWORD_PATTERN = re.compile(
        r"(?:pass(?:word)?|pwd|passwd)\s*[:=]\s*\S+", re.IGNORECASE
    )
    HASH_PATTERN = re.compile(r"[a-fA-F0-9]{32,64}")  # MD5, SHA1, SHA256
    COMBO_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+\s*[:;|]\s*\S+")  # email:password combos

    def check_text(
        self,
        text: str,
        monitored_emails: list[str],
        monitored_domains: list[str],
        monitored_usernames: list[str],
        monitored_keywords: list[str],
    ) -> list[CredentialMatch]:
        """Check text for credential leaks matching monitored entities."""
        matches = []

        text_lower = text.lower()

        # Check for exact email matches
        found_emails = self.EMAIL_PATTERN.findall(text)
        for email in found_emails:
            email_lower = email.lower()
            if email_lower in [e.lower() for e in monitored_emails]:
                context = self._get_context(text, email, window=200)
                matches.append(CredentialMatch(
                    matched_value=email,
                    match_type="email_exact",
                    context=context,
                    confidence=0.95,
                ))
            else:
                # Check if email domain matches monitored domains
                email_domain = email_lower.split("@")[-1]
                if email_domain in [d.lower() for d in monitored_domains]:
                    context = self._get_context(text, email, window=200)
                    matches.append(CredentialMatch(
                        matched_value=email,
                        match_type="email_domain",
                        context=context,
                        confidence=0.8,
                    ))

        # Check for username mentions
        for username in monitored_usernames:
            if username.lower() in text_lower:
                context = self._get_context(text, username, window=200)
                # Higher confidence if near password-like patterns
                near_password = bool(self.PASSWORD_PATTERN.search(context))
                matches.append(CredentialMatch(
                    matched_value=username,
                    match_type="username",
                    context=context,
                    confidence=0.85 if near_password else 0.6,
                ))

        # Check for combo lists containing monitored domains
        combos = self.COMBO_PATTERN.findall(text)
        for combo in combos:
            for domain in monitored_domains:
                if domain.lower() in combo.lower():
                    matches.append(CredentialMatch(
                        matched_value=combo,
                        match_type="combo_list",
                        context=self._get_context(text, combo, window=200),
                        confidence=0.9,
                    ))

        # Check for keyword mentions (company name, product names, etc.)
        for keyword in monitored_keywords:
            if len(keyword) >= 4 and keyword.lower() in text_lower:
                # Only flag if near sensitive patterns
                context = self._get_context(text, keyword, window=300)
                has_sensitive = any([
                    self.PASSWORD_PATTERN.search(context),
                    self.HASH_PATTERN.search(context),
                    re.search(r"(?:breach|leak|dump|hack|exploit|vuln)", context, re.I),
                ])
                if has_sensitive:
                    matches.append(CredentialMatch(
                        matched_value=keyword,
                        match_type="keyword_sensitive",
                        context=context,
                        confidence=0.7,
                    ))

        return matches

    def _get_context(self, text: str, match: str, window: int = 200) -> str:
        """Get surrounding text around a match."""
        idx = text.lower().find(match.lower())
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(text), idx + len(match) + window)
        return text[start:end]
