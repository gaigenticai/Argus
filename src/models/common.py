"""Shared model primitives (Audit D5).

Canonical enums used across multiple phases. Defining them here means
the dashboard, the API serializers, and the rule engines can all
import a single ``Severity`` and trust the value set is identical
across EASM changes, exposures, cases, SLA policies, threats, and
advisories. The phase-specific aliases (`ChangeSeverity`,
`ExposureSeverity`, ...) remain in their original modules as
backwards-compatible re-exports so the alembic-baked enum *names*
(``change_severity``, ``exposure_severity``, ...) stay stable.

Adding a new severity bucket later means changing this file once,
not six.
"""

from __future__ import annotations

import enum


class Severity(str, enum.Enum):
    """Canonical 5-level severity used everywhere a finding has a
    severity. Matches CVSS-derived industry convention.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


__all__ = ["Severity"]
