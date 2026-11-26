"""Terminal, JSON, CSV, Markdown, and self-contained HTML reporters for win-event-triage."""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

from .i18n import t_rule, t_ui
from .models import Severity, TriageReport


def render_report(report: TriageReport, fmt: str, lang: str = "en", no_color: bool = False) -> str:
    if fmt == "json":
        return render_json(report, lang)
    if fmt == "csv":
        return render_csv(report, lang)
    if fmt == "markdown":
        return render_markdown(report, lang)
    if fmt == "html":
        return render_html(report, lang)
    return render_terminal(report, lang, no_color=no_color)


def render_terminal(report: TriageReport, lang: str = "en", no_color: bool = False) -> str:
    use_color = not no_color
    colors = {
        Severity.CRITICAL: "\033[91m" if use_color else "",
        Severity.HIGH: "\033[31m" if use_color else "",
        Severity.MEDIUM: "\033[33m" if use_color else "",
        Severity.LOW: "\033[36m" if use_color else "",
    }
    reset = "\033[0m" if use_color else ""
    bold = "\033[1m" if use_color else ""

    counts = report.counts_by_severity()
    lines = [
        f"{bold}{t_ui(lang, 'report_title')} v{report.version}{reset}",
        f"{t_ui(lang, 'host_label')}: {report.source} | {t_ui(lang, 'events_analyzed')}: {report.events_analyzed} | {t_ui(lang, 'risk_score')}: {report.risk_score()}/100",
        f"Summary: Critical={counts['critical']} High={counts['high']} Medium={counts['medium']} Low={counts['low']}",
        "-" * 74,
    ]
    ordered = report.sorted_findings()
    if not ordered:
        lines.append(t_ui(lang, "clean_status"))
        return "\n".join(lines)

    for f in ordered:
        copy = t_rule(lang, f.rule_id)
        badge = f"{colors[f.severity]}[{f.severity.value.upper()}]{reset}"
        lines.append(f"{badge} {bold}{f.rule_id}{reset} ({f.tactic} / {f.technique}) {copy['title']}")
        lines.append(f"  {t_ui(lang, 'timestamp')}: {f.timestamp} | Host: {f.computer} | Account: {f.account} | IP: {f.source_ip}")
        lines.append(f"  {t_ui(lang, 'evidence')}: {f.evidence}")
        lines.append(f"  {t_ui(lang, 'containment')}: {copy['remediation']}")
    return "\n".join(lines)


def render_json(report: TriageReport, lang: str = "en") -> str:
    payload: dict[str, Any] = {
        "tool": "win-event-triage",
        "version": report.version,
        "language": lang,
        "source": report.source,
        "events_analyzed": report.events_analyzed,
        "risk_score": report.risk_score(),
        "counts": report.counts_by_severity(),
        "findings": [],
    }
    for f in report.sorted_findings():
        copy = t_rule(lang, f.rule_id)
        item = f.to_dict()
        item["title"] = copy["title"]
        item["remediation"] = copy["remediation"]
        payload["findings"].append(item)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_csv(report: TriageReport, lang: str = "en") -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["RuleId", "Severity", "Tactic", "Technique", "Timestamp", "Computer", "Account", "SourceIp", "Title", "Evidence", "Remediation"])
    for f in report.sorted_findings():
        copy = t_rule(lang, f.rule_id)
        writer.writerow([f.rule_id, f.severity.value, f.tactic, f.technique, f.timestamp, f.computer, f.account, f.source_ip, copy["title"], f.evidence, copy["remediation"]])
    return buf.getvalue()


def render_markdown(report: TriageReport, lang: str = "en") -> str:
    counts = report.counts_by_severity()
    lines = [
        f"# {t_ui(lang, 'report_title')}",
        "",
        f"- **{t_ui(lang, 'host_label')}:** `{report.source}`",
        f"- **{t_ui(lang, 'events_analyzed')}:** {report.events_analyzed}",
        f"- **{t_ui(lang, 'risk_score')}:** `{report.risk_score()}/100`",
        "",
        f"| {t_ui(lang, 'critical')} | {t_ui(lang, 'high')} | {t_ui(lang, 'medium')} | {t_ui(lang, 'low')} |",
        "|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
        "",
    ]
    ordered = report.sorted_findings()
    if not ordered:
        lines.append(f"> {t_ui(lang, 'clean_status')}")
        return "\n".join(lines) + "\n"

    for f in ordered:
        copy = t_rule(lang, f.rule_id)
        lines.append(f"- **[{f.severity.value.upper()}] `{f.rule_id}` ({f.tactic} / {f.technique})** {copy['title']} (`{f.timestamp}`) - `{f.evidence}`")
    return "\n".join(lines) + "\n"


def render_html(report: TriageReport, lang: str = "en") -> str:
    counts = report.counts_by_severity()
    ordered = report.sorted_findings()
    rows = []
    for f in ordered:
        copy = t_rule(lang, f.rule_id)
        sev = f.severity.value
        rows.append(
            f"""
            <tr data-severity="{html.escape(sev)}">
              <td><span class="pill pill-{html.escape(sev)}">{html.escape(sev.upper())}</span></td>
              <td><strong>{html.escape(f.rule_id)}</strong><div class="sub">{html.escape(copy['title'])}</div></td>
              <td><span class="badge">{html.escape(f.tactic)}</span><div class="sub">{html.escape(f.technique)}</div></td>
              <td class="mono">{html.escape(f.timestamp)}<div class="sub">{html.escape(f.computer)} | {html.escape(f.account)}</div></td>
              <td><code>{html.escape(f.evidence)}</code><div class="rem">{html.escape(copy['remediation'])}</div></td>
            </tr>
            """
        )

    tbody = "\n".join(rows) if rows else f'<tr><td colspan="5" class="clean">{html.escape(t_ui(lang, "clean_status"))}</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="{html.escape(lang)}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(t_ui(lang, 'report_title'))}</title>
  <style>
    :root {{ --bg: #080d17; --card: #11192a; --border: #23304d; --text: #e8effc; --muted: #93a6c8; --crit: #ef4444; --high: #f97316; --med: #eab308; --ok: #22c55e; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 28px; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--text); }}
    .wrap {{ max-width: 1240px; margin: 0 auto; }}
    .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin: 18px 0; }}
    .kpi {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }}
    .kpi b {{ font-size: 1.6rem; display: block; }}
    .muted {{ color: var(--muted); font-size: 0.9rem; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; }}
    .pill {{ padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }}
    .pill-critical {{ background: rgba(239,68,68,.18); color: #fca5a5; border: 1px solid var(--crit); }}
    .pill-high {{ background: rgba(249,115,22,.18); color: #fdba74; border: 1px solid var(--high); }}
    .pill-medium {{ background: rgba(234,179,8,.16); color: #fde047; border: 1px solid var(--med); }}
    .badge {{ background: #1c2740; border: 1px solid var(--border); border-radius: 6px; padding: 2px 6px; font-size: 0.78rem; display: inline-block; }}
    .sub {{ color: var(--muted); font-size: 0.8rem; margin-top: 3px; }}
    .rem {{ color: #86efac; font-size: 0.82rem; margin-top: 6px; }}
    code {{ background: #070b14; padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; word-break: break-word; display: inline-block; }}
    .clean {{ text-align: center; color: var(--ok); font-weight: 600; padding: 24px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{html.escape(t_ui(lang, 'report_title'))}</h1>
    <div class="muted">{html.escape(t_ui(lang, 'report_subtitle'))} | {html.escape(t_ui(lang, 'host_label'))}: <code>{html.escape(report.source)}</code></div>
    <div class="kpis">
      <div class="kpi"><span class="muted">{html.escape(t_ui(lang, 'risk_score'))}</span><b>{report.risk_score()}/100</b></div>
      <div class="kpi"><span class="muted">{html.escape(t_ui(lang, 'events_analyzed'))}</span><b>{report.events_analyzed}</b></div>
      <div class="kpi"><span class="muted">{html.escape(t_ui(lang, 'critical'))}</span><b style="color:var(--crit)">{counts['critical']}</b></div>
      <div class="kpi"><span class="muted">{html.escape(t_ui(lang, 'high'))}</span><b style="color:var(--high)">{counts['high']}</b></div>
      <div class="kpi"><span class="muted">{html.escape(t_ui(lang, 'medium'))}</span><b style="color:var(--med)">{counts['medium']}</b></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>{html.escape(t_ui(lang, 'severity'))}</th>
          <th>{html.escape(t_ui(lang, 'rule'))}</th>
          <th>{html.escape(t_ui(lang, 'mitre'))}</th>
          <th>{html.escape(t_ui(lang, 'timestamp'))}</th>
          <th>{html.escape(t_ui(lang, 'evidence'))} &amp; {html.escape(t_ui(lang, 'containment'))}</th>
        </tr>
      </thead>
      <tbody>{tbody}</tbody>
    </table>
    <p class="muted" style="margin-top:14px;">{html.escape(t_ui(lang, 'generated_by'))} v{html.escape(report.version)}</p>
  </div>
</body>
</html>
"""
