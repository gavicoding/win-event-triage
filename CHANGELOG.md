# Changelog

## v1.1.0 (2026-11-26)

- **Reads `.evtx` files directly, with no dependencies, in Python and in the browser.** The new readers decode chunks, records and BinXML templates; checked against `Get-WinEvent` on 83,950 real events (System, Application and PowerShell logs) with 100% identical fields. Drag `.evtx` files into the web page: they are read inside the tab and never uploaded.
- `triage` accepts several files and whole folders (`win-event-triage triage C:\Logs\`), mixing `.evtx`, JSON and XML.
- New rules: `WET019` RDP from an internet IP (1149/4778), `WET020` Run-key persistence (Sysmon 13/4657), `WET021` ransom note or encrypted file (Sysmon 11), `WET022` malware detected by Defender (1116/1117), `WET023` security service stopped or disabled (7040/7036). Sysmon 1 is read like 4688 and Sysmon 10 on LSASS feeds `WET005`.
- Fewer false alarms: event IDs reused by many providers (104, 106, 1/3/10/11/13, 5001, 7045...) only count when the right provider wrote them. `WET012` now means "Defender protection turned off" (5001/5007/5010/5012); detections moved to `WET022`.
- PowerShell module: `-EvtxPath` crashed on any file under StrictMode and unnamed `<Data>` values were dropped; both fixed, plus the same new rules and provider checks.
- `tools/make_sample_evtx.py` writes valid `.evtx` files (Windows opens them) from JSON snapshots; the bundled samples now also ship as `.evtx`.
- Timestamps with 7 fractional digits parse on Python 3.10; translations ship inside the Python package (works with `pip`/`pipx`); Portuguese texts with proper accents.

## v1.0.0 (2026-11-25)

- Initial release of `win-event-triage`.
- Added 18 MITRE ATT&CK correlated detection rules (`WET001` - `WET018`) across PowerShell 5.1/7+, zero-dependency Python CLI, and offline browser workbench.
- Added native Windows Event Viewer XML + JSON snapshot + `.evtx` support, SHA-256 anonymization, and HTML/CSV/JSON/Markdown reports in English and Portuguese.
