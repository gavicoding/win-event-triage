"""Command-line interface for win-event-triage."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import analyze_events
from .i18n import t_rule
from .parsers import parse_events_file
from .reporters import render_report
from .rules import list_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="win-event-triage",
        description="Read-only Windows Security/System/PowerShell/Defender event triage mapped to MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    tr_p = sub.add_parser("triage", help="Analyze a JSON event snapshot or Event Viewer XML export.")
    tr_p.add_argument("input_file", help="Path to .json snapshot or Event Viewer .xml file.")
    tr_p.add_argument("--format", choices=["terminal", "json", "csv", "markdown", "html"], default="terminal")
    tr_p.add_argument("--output", "-o", help="Write report to a file.")
    tr_p.add_argument("--lang", choices=["en", "pt"], default="en")
    tr_p.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="high")
    tr_p.add_argument("--bh-start", type=int, default=7, help="Business hours start UTC (0-23).")
    tr_p.add_argument("--bh-end", type=int, default=20, help="Business hours end UTC (0-23).")
    tr_p.add_argument("--brute-threshold", type=int, default=5, help="Failed 4625 threshold within 15m.")
    tr_p.add_argument("--anonymize", action="store_true", help="Hash computer and account names using SHA-256.")
    tr_p.add_argument("--no-color", action="store_true")

    rules_p = sub.add_parser("rules", help="List all 18 MITRE ATT&CK detection rules.")
    rules_p.add_argument("--lang", choices=["en", "pt"], default="en")

    demo_p = sub.add_parser("demo", help="Run triage over bundled synthetic ransomware and clean baselines.")
    demo_p.add_argument("--lang", choices=["en", "pt"], default="en")
    demo_p.add_argument("--no-color", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        for rule in list_rules():
            copy = t_rule(args.lang, rule.rule_id)
            print(f"{rule.rule_id} [{rule.severity.value.upper():8}] {rule.tactic} / {rule.technique} - {copy['title']}")
        return 0

    if args.command == "demo":
        samples_dir = _find_samples_dir()
        if samples_dir is None:
            print("Error: bundled samples/ directory not found.", file=sys.stderr)
            return 2
        for sample_name in ("ransomware-intrusion.json", "clean-baseline.json"):
            p = samples_dir / sample_name
            events = parse_events_file(p)
            rep = analyze_events(events, source_label=sample_name)
            print(f"=== {sample_name.upper()} ===")
            print(render_report(rep, "terminal", lang=args.lang, no_color=args.no_color))
            print()
        return 0

    path = Path(args.input_file)
    if not path.is_file():
        print(f"Error: input file not found: {path}", file=sys.stderr)
        return 2

    events = parse_events_file(path)
    report = analyze_events(
        events,
        source_label=path.name,
        business_hours_start=args.bh_start,
        business_hours_end=args.bh_end,
        brute_force_threshold=args.brute_threshold,
        anonymize=args.anonymize,
    )
    rendered = render_report(report, args.format, lang=args.lang, no_color=args.no_color)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 1 if report.exceeds_threshold(args.fail_on) else 0


def _find_samples_dir() -> Path | None:
    candidates = [
        Path.cwd() / "samples",
        Path(__file__).resolve().parents[2] / "samples",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None
