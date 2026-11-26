"""Python detection engine tests covering WET001..WET018 and clean baselines."""

import unittest
from pathlib import Path

from win_event_triage.engine import analyze_events
from win_event_triage.models import NormalizedEvent
from win_event_triage.parsers import parse_events_file

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


class TestWinEventRules(unittest.TestCase):
    def test_ransomware_chain_triggers_core_rules(self):
        events = parse_events_file(SAMPLES / "ransomware-intrusion.json")
        rep = analyze_events(events, source_label="ransomware-intrusion.json")
        ids = {f.rule_id for f in rep.findings}
        for expected in ("WET001", "WET002", "WET003", "WET005", "WET008", "WET010", "WET011", "WET012", "WET014", "WET015", "WET017"):
            self.assertIn(expected, ids, f"Missing expected rule {expected}")
        self.assertEqual(rep.risk_score(), 100)

    def test_insider_escalation_and_dcsync(self):
        events = parse_events_file(SAMPLES / "insider-lateral-movement.json")
        rep = analyze_events(events, source_label="insider-lateral-movement.json")
        ids = {f.rule_id for f in rep.findings}
        for expected in ("WET004", "WET006", "WET007", "WET009", "WET013", "WET015", "WET016", "WET018"):
            self.assertIn(expected, ids, f"Missing expected rule {expected}")

    def test_clean_baseline_zero_findings(self):
        events = parse_events_file(SAMPLES / "clean-baseline.json")
        rep = analyze_events(events, source_label="clean-baseline.json")
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.risk_score(), 0)

    def test_anonymize_hashes_hosts_and_accounts(self):
        ev = [
            NormalizedEvent(
                event_id=1102,
                time_created="2026-11-25T10:00:00Z",
                computer="DC01.contoso.lab",
                data={"SubjectUserName": "sec-operator"},
            )
        ]
        rep = analyze_events(ev, anonymize=True)
        self.assertEqual(len(rep.findings), 1)
        self.assertTrue(rep.findings[0].computer.startswith("ANON-"))
        self.assertTrue(rep.findings[0].account.startswith("ANON-"))


if __name__ == "__main__":
    unittest.main()
