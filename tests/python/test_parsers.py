"""Parser tests for JSON snapshots and native Windows Event Viewer XML."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from win_event_triage.cli import main
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

    def test_malformed_xml_is_a_value_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "quebrado.xml"
            broken.write_text("<Events><Event><System>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed XML"):
                parse_events_file(broken)

    def test_cli_malformed_xml_exits_2_not_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "quebrado.xml"
            broken.write_text("<Events><Event><System>", encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = main(["triage", str(broken), "--no-color"])
            self.assertEqual(rc, 2)
            self.assertIn("malformed XML", err.getvalue())


if __name__ == "__main__":
    unittest.main()
