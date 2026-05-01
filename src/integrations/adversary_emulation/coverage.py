"""ATT&CK detection-coverage scorer (P3 #3.5).

Closes the validation loop:

  executed = {technique_id: count of tests run}
  detected = {technique_id: count of tests that fired a SIEM alert
                              within the correlation window}

  coverage[t] = detected[t] / executed[t]

The aggregate report is consumed by the dashboard (per-technique
heatmap) and by ``threat_hunter_agent`` (recommends Sigma rules for the
techniques with low coverage).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CoverageEntry:
    technique_id: str
    executed: int
    detected: int

    @property
    def coverage(self) -> float:
        if self.executed <= 0:
            return 0.0
        return min(self.detected / self.executed, 1.0)

    @property
    def status(self) -> str:
        c = self.coverage
        if c >= 0.9:
            return "covered"
        if c >= 0.5:
            return "partial"
        if self.executed == 0:
            return "untested"
        return "gap"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "executed": self.executed,
            "detected": self.detected,
            "coverage": round(self.coverage, 4),
            "status": self.status,
        }


@dataclass
class CoverageReport:
    entries: list[CoverageEntry] = field(default_factory=list)

    @property
    def overall(self) -> float:
        total_exec = sum(e.executed for e in self.entries)
        total_det = sum(e.detected for e in self.entries)
        if total_exec <= 0:
            return 0.0
        return min(total_det / total_exec, 1.0)

    @property
    def gaps(self) -> list[str]:
        return [e.technique_id for e in self.entries if e.status == "gap"]

    @property
    def covered(self) -> list[str]:
        return [e.technique_id for e in self.entries if e.status == "covered"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": round(self.overall, 4),
            "techniques_total": len(self.entries),
            "techniques_covered": len(self.covered),
            "gaps": self.gaps,
            "entries": [e.to_dict() for e in self.entries],
        }


def score(
    executed: dict[str, int],
    detected: dict[str, int],
) -> CoverageReport:
    """Build a CoverageReport from executed / detected technique tallies.

    Any technique that appears in either map is included. Unknown
    techniques in ``detected`` (i.e. detection without a corresponding
    execution) are recorded with executed=0 — those are "free" detections,
    flagged in the report so reviewers can audit unexpected SIEM noise.
    """
    keys = set(executed.keys()) | set(detected.keys())
    entries: list[CoverageEntry] = []
    for tid in sorted(keys):
        entries.append(CoverageEntry(
            technique_id=tid,
            executed=int(executed.get(tid, 0)),
            detected=int(detected.get(tid, 0)),
        ))
    return CoverageReport(entries=entries)
