"""Reporter, CLI, and quality-gate tests for win-event-triage."""

import csv
import io
import json
import unittest
from pathlib import Path

from win_event_triage.cli import main
from win_event_triage.engine import analyze_events
from win_event_triage.i18n import load_locale
from win_event_triage.parsers import parse_events_file
from win_event_triage.reporters import render_csv, render_html, render_json, render_markdown, render_terminal
from win_event_triage.rules import RULES

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_TERMS = [
    "ret" + "iro",
    "proc" + "fit",
    "farma" + "one",
    "nex" + "us",
    "ekle" + "sia",
    "ed" + "oc",
    "port" + "aria",
    "671/" + "2021",
]


class TestReportersCLIAndQuality(unittest.TestCase):
    def test_all_reporters_and_cli_exit_codes(self):
        events = parse_events_file(ROOT / "samples" / "ransomware-intrusion.json")
        rep = analyze_events(events, source_label="ransomware-intrusion.json")

        j = json.loads(render_json(rep, lang="pt"))
        self.assertEqual(j["language"], "pt")
        self.assertGreater(len(j["findings"]), 8)

        rows = list(csv.reader(io.StringIO(render_csv(rep, lang="en"))))
        self.assertEqual(rows[0][0], "RuleId")
        self.assertEqual(len(rows), 1 + len(rep.findings))

        self.assertIn("T1490", render_markdown(rep, lang="pt"))
        self.assertIn("T1490", render_html(rep, lang="en"))
        self.assertIn("WET011", render_terminal(rep, lang="en", no_color=True))

        self.assertEqual(main(["rules", "--lang", "pt"]), 0)
        self.assertEqual(main(["triage", str(ROOT / "samples" / "clean-baseline.json"), "--fail-on", "low", "--no-color"]), 0)
        self.assertEqual(main(["triage", str(ROOT / "samples" / "ransomware-intrusion.json"), "--fail-on", "critical", "--no-color"]), 1)

    def test_locale_parity_zero_em_dashes_zero_confidential(self):
        en = load_locale("en")
        pt = load_locale("pt")
        self.assertEqual(set(en["ui"].keys()), set(pt["ui"].keys()))
        self.assertEqual(set(RULES.keys()), set(en["rules"].keys()))
        self.assertEqual(set(en["rules"].keys()), set(pt["rules"].keys()))

        exts = {".py", ".ps1", ".psm1", ".psd1", ".json", ".md", ".html", ".css", ".js", ".mjs", ".yml", ".yaml", ".xml", ".toml"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
                continue
            if path.suffix.lower() not in exts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("\u2014", text, f"Em-dash found in {path}")
            low = text.lower()
            for term in FORBIDDEN_TERMS:
                self.assertNotIn(term, low, f"Forbidden term '{term}' in {path}")


if __name__ == "__main__":
    unittest.main()
