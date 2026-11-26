"""Rule catalog for win-event-triage (WET001..WET023) mapped to MITRE ATT&CK."""

from __future__ import annotations

from .models import Severity, TriageRule

RULES: dict[str, TriageRule] = {
    "WET001": TriageRule("WET001", Severity.HIGH, "Credential Access", "T1110.001", (4625,)),
    "WET002": TriageRule("WET002", Severity.CRITICAL, "Credential Access", "T1110", (4625, 4624)),
    "WET003": TriageRule("WET003", Severity.CRITICAL, "Credential Access", "T1558.003", (4769,)),
    "WET004": TriageRule("WET004", Severity.HIGH, "Credential Access", "T1110", (4740,)),
    "WET005": TriageRule("WET005", Severity.CRITICAL, "Credential Access", "T1003.001", (4656, 4663, 4688, 4104)),
    "WET006": TriageRule("WET006", Severity.CRITICAL, "Persistence", "T1098", (4728, 4732, 4756)),
    "WET007": TriageRule("WET007", Severity.HIGH, "Persistence", "T1136", (4720, 4728, 4732)),
    "WET008": TriageRule("WET008", Severity.HIGH, "Persistence", "T1543.003", (7045, 4697)),
    "WET009": TriageRule("WET009", Severity.HIGH, "Persistence", "T1053.005", (4698, 4702, 106)),
    "WET010": TriageRule("WET010", Severity.CRITICAL, "Defense Evasion", "T1070.001", (1102, 104)),
    "WET011": TriageRule("WET011", Severity.CRITICAL, "Impact", "T1490", (4688, 4104)),
    "WET012": TriageRule("WET012", Severity.CRITICAL, "Defense Evasion", "T1562.001", (5001, 5007, 5010, 5012)),
    "WET013": TriageRule("WET013", Severity.HIGH, "Defense Evasion", "T1562.002", (4719,)),
    "WET014": TriageRule("WET014", Severity.CRITICAL, "Execution", "T1059.001", (4104, 4688)),
    "WET015": TriageRule("WET015", Severity.HIGH, "Lateral Movement", "T1021.001", (4624, 4648)),
    "WET016": TriageRule("WET016", Severity.HIGH, "Defense Evasion", "T1218", (4688,)),
    "WET017": TriageRule("WET017", Severity.MEDIUM, "Initial Access", "T1078", (4672, 4624)),
    "WET018": TriageRule("WET018", Severity.CRITICAL, "Credential Access", "T1003.006", (4662,)),
    "WET019": TriageRule("WET019", Severity.HIGH, "Lateral Movement", "T1021.001", (1149, 4778)),
    "WET020": TriageRule("WET020", Severity.HIGH, "Persistence", "T1547.001", (13, 4657)),
    "WET021": TriageRule("WET021", Severity.CRITICAL, "Impact", "T1486", (11,)),
    "WET022": TriageRule("WET022", Severity.HIGH, "Execution", "T1204.002", (1116, 1117)),
    "WET023": TriageRule("WET023", Severity.HIGH, "Defense Evasion", "T1562.001", (7040, 7036)),
}


def list_rules() -> list[TriageRule]:
    """Return all rules ordered by RuleId."""
    return [RULES[k] for k in sorted(RULES)]
