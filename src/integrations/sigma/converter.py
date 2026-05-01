"""Sigma rule converter — load, filter, and match Sigma rules against feed data."""

from __future__ import annotations


import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False
    logger.warning(
        "PyYAML is not installed — Sigma rule loading will be unavailable. "
        "Install with: pip install pyyaml"
    )

_VALID_LEVELS = frozenset({"critical", "high", "medium", "low", "informational"})


class SigmaConverter:
    """Load and match Sigma detection rules using native YAML parsing.

    This is a local engine and does NOT inherit from BaseIntegration.
    No pySigma dependency — rules are parsed as plain YAML and matched
    via simple field/keyword comparison.
    """

    def __init__(self, rules_dir: str = "data/sigma_rules"):
        self.rules_dir = Path(rules_dir)
        self._rules: list[dict] = []

    def load_rules(self) -> int:
        """Scan rules_dir for .yml files, parse YAML, and store in memory.

        Returns:
            Number of rules successfully loaded.
        """
        if not _YAML_AVAILABLE:
            logger.warning("PyYAML not installed — cannot load Sigma rules.")
            return 0

        if not self.rules_dir.exists():
            logger.warning("Sigma rules directory does not exist: %s", self.rules_dir)
            return 0

        self._rules = []
        for path in sorted(self.rules_dir.rglob("*.yml")):
            try:
                text = path.read_text(encoding="utf-8")
                docs = list(yaml.safe_load_all(text))
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    # Sigma rules must at minimum have a title and detection block
                    if "title" not in doc:
                        continue
                    doc["_source_file"] = str(path)
                    self._rules.append(doc)
            except yaml.YAMLError as exc:
                logger.warning("Failed to parse %s: %s", path, exc)
            except Exception as exc:
                logger.error("Error reading %s: %s", path, exc)

        logger.info("Loaded %d Sigma rule(s) from %s", len(self._rules), self.rules_dir)
        return len(self._rules)

    def get_rules(self, level: str | None = None) -> list[dict]:
        """Return loaded rules, optionally filtered by severity level.

        Args:
            level: One of critical, high, medium, low, informational.
                   If ``None``, all rules are returned.

        Returns:
            List of Sigma rule dicts.
        """
        if level is not None:
            level_lower = level.lower()
            if level_lower not in _VALID_LEVELS:
                logger.warning(
                    "Unknown Sigma level '%s' — valid: %s",
                    level,
                    ", ".join(sorted(_VALID_LEVELS)),
                )
                return []
            return [
                r for r in self._rules
                if str(r.get("level", "")).lower() == level_lower
            ]
        return list(self._rules)

    def match_against_entry(self, entry_data: dict) -> list[dict]:
        """Match loaded Sigma rules against a feed entry using simple keyword matching.

        For each rule that has a ``detection`` block, the converter flattens
        all detection field values into a set of keywords and checks whether
        they appear in the stringified entry data.  This is intentionally a
        lightweight heuristic — not a full Sigma evaluation engine.

        Args:
            entry_data: Dict representing a threat feed entry (e.g. an
                        indicator, alert, or log line).

        Returns:
            List of matched rule summaries with keys: title, level,
            description, tags, status.
        """
        if not self._rules:
            logger.debug("No Sigma rules loaded — nothing to match.")
            return []

        # Build a single lowercase string representation of the entry for
        # fast substring matching.
        entry_blob = _flatten_to_str(entry_data).lower()

        matched: list[dict] = []
        for rule in self._rules:
            detection = rule.get("detection")
            if not detection or not isinstance(detection, dict):
                continue

            keywords = _extract_detection_keywords(detection)
            if not keywords:
                continue

            if _keywords_match(keywords, entry_blob):
                matched.append({
                    "title": rule.get("title", ""),
                    "level": rule.get("level", "unknown"),
                    "description": rule.get("description", ""),
                    "tags": rule.get("tags", []),
                    "status": rule.get("status", "unknown"),
                })

        return matched


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_to_str(obj: object) -> str:
    """Recursively flatten a dict/list/scalar into a single space-separated string."""
    if isinstance(obj, dict):
        parts = []
        for k, v in obj.items():
            parts.append(str(k))
            parts.append(_flatten_to_str(v))
        return " ".join(parts)
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_to_str(item) for item in obj)
    return str(obj)


def _extract_detection_keywords(detection: dict) -> list[str]:
    """Pull keyword strings out of a Sigma detection block.

    Sigma detection blocks contain named sub-conditions (e.g. ``selection``,
    ``filter``) plus a ``condition`` expression.  We extract all string
    values from the sub-condition dicts/lists and ignore the ``condition``
    and ``timeframe`` meta-keys.
    """
    keywords: list[str] = []
    skip_keys = {"condition", "timeframe"}

    for key, value in detection.items():
        if key in skip_keys:
            continue
        _collect_strings(value, keywords)

    return keywords


def _collect_strings(obj: object, acc: list[str]) -> None:
    """Recursively collect non-empty string leaves from a nested structure."""
    if isinstance(obj, str):
        stripped = obj.strip()
        if stripped:
            acc.append(stripped.lower())
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, acc)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _collect_strings(item, acc)


def _keywords_match(keywords: list[str], blob: str) -> bool:
    """Return True if *any* keyword appears as a substring in the blob.

    Using ``any`` gives an OR-style match which is the safest default for
    a lightweight heuristic — it surfaces potential matches for human review
    rather than silently dropping rules that use complex boolean conditions.
    """
    return any(kw in blob for kw in keywords)
