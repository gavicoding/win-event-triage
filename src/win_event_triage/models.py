"""Core data structures for win-event-triage events, rules, findings, and triage reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Normalized severity levels matching PowerShell and browser engines."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 14,
            Severity.MEDIUM: 6,
            Severity.LOW: 2,
        }[self]


@dataclass(frozen=True)
class TriageRule:
    """Detection rule metadata mapped to MITRE ATT&CK."""

    rule_id: str
    severity: Severity
    tactic: str
    technique: str
    event_ids: tuple[int, ...]


@dataclass
class NormalizedEvent:
    """Normalized Windows Event record independent of JSON or Event Viewer XML origin."""

    event_id: int
    time_created: str
    computer: str
    provider: str = ""
    log_name: str = ""
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Single DFIR alert emitted by win-event-triage."""

    rule_id: str
    severity: Severity
    tactic: str
    technique: str
    timestamp: str
    computer: str
    account: str
    source_ip: str
    evidence: str

    def sort_key(self) -> tuple[int, str, str]:
        return (-self.severity.rank, self.timestamp, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "tactic": self.tactic,
            "technique": self.technique,
            "timestamp": self.timestamp,
            "computer": self.computer,
            "account": self.account,
            "source_ip": self.source_ip,
            "evidence": self.evidence,
        }


@dataclass
class TriageReport:
    """Complete read-only triage report."""

    source: str
    events_analyzed: int
    findings: list[Finding]
    version: str = "1.0.0"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def risk_score(self) -> int:
        return min(100, sum(f.severity.weight for f in self.findings))

    def exceeds_threshold(self, fail_on: str) -> bool:
        if fail_on == "none":
            return False
        threshold = Severity(fail_on)
        return any(f.severity.rank >= threshold.rank for f in self.findings)
