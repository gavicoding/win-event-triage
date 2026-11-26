"""Parser tests for JSON snapshots and native Windows Event Viewer XML."""

import unittest
from pathlib import Path

from win_event_triage.engine import analyze_events
from win_event_triage.parsers import parse_events_file

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


class TestParsers(unittest.TestCase):
    def test_xml_eventviewer_parser_extracts_events_and_fields(self):
        events = parse_events_file(SAMPLES / "sample-eventviewer.xml")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_id, 4769)
        self.assertEqual(events[0].data["TicketEncryptionType"], "0x17")
        rep = analyze_events(events, source_label="sample-eventviewer.xml")
        ids = {f.rule_id for f in rep.findings}
        self.assertEqual(ids, {"WET003", "WET010"})


if __name__ == "__main__":
    unittest.main()
