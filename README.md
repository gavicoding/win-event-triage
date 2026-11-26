# win-event-triage

[Português](README.pt-BR.md) | **English**

[![CI](https://github.com/gavicoding/win-event-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/gavicoding/win-event-triage/actions/workflows/ci.yml)
![PowerShell 5.1 | 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-dc2626)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

**Read-only Windows Security, System, PowerShell, and Defender Event Log triage engine mapped to MITRE ATT&CK. Runs via PowerShell 5.1/7+, zero-dependency Python CLI, or offline in your browser.**

🌐 **[Open Interactive Browser Triage Workbench (Zero upload)](https://gavicoding.github.io/win-event-triage/)**

![win-event-triage browser workbench](docs/screenshot.png)

## Why this exists

During a suspected Windows or Active Directory incident, responders need immediate answers without modifying host state or shipping sensitive `.evtx` logs to external cloud SaaS tools:

- Did brute force (`4625`) succeed (`4624`) within the attack window?
- Was a service account Kerberoasted using weak RC4 (`4769` `0x17`)?
- Did an attacker dump LSASS/NTDS, add someone to `Domain Admins` (`4728`/`4732`), plant a service (`7045`) or scheduled task (`4698`), run obfuscated PowerShell (`4104`), wipe Volume Shadow Copies (`vssadmin`), turn off Defender (`5001`), clear logs (`1102`), or attempt DCSync (`4662`)?

`win-event-triage` runs **100% read-only**, correlates 18 MITRE ATT&CK detections (`WET001` - `WET018`), optionally hashes hostnames and usernames with SHA-256 (`-Anonymize` / `--anonymize`), and exports executive + technical HTML, CSV, JSON, and Markdown incident reports.

## 18 Detection Rules (MITRE ATT&CK)

| Rule | Severity | Event IDs | MITRE Tactic / Technique | Signal |
|---|---|---|---|---|
| `WET001` | High | `4625` | Credential Access / `T1110.001` | Brute-force or password spray burst |
| `WET002` | Critical | `4625` -> `4624` | Credential Access / `T1110` | Brute-force burst followed by logon success |
| `WET003` | Critical | `4769` | Credential Access / `T1558.003` | Kerberoasting RC4 (`0x17`) on non-machine SPN |
| `WET004` | High | `4740` | Credential Access / `T1110` | Account lockout storm |
| `WET005` | Critical | `4656, 4663, 4688, 4104` | Credential Access / `T1003.001` | LSASS / NTDS.dit credential dumping indicators |
| `WET006` | Critical | `4728, 4732, 4756` | Persistence / `T1098` | Privileged security group modification |
| `WET007` | High | `4720` + `4728/4732` | Persistence / `T1136` | Off-hours user creation or rapid admin elevation |
| `WET008` | High | `7045, 4697` | Persistence / `T1543.003` | Suspicious service pointing to writable staging paths |
| `WET009` | High | `4698, 4702, 106` | Persistence / `T1053.005` | Suspicious scheduled task persistence |
| `WET010` | Critical | `1102, 104` | Defense Evasion / `T1070.001` | Security or System event log cleared |
| `WET011` | Critical | `4688, 4104` | Impact / `T1490` | Shadow copy deletion / recovery sabotage |
| `WET012` | Critical | `5001, 5007, 1116, 1117` | Defense Evasion / `T1562.001` | Microsoft Defender tampered or malware detected |
| `WET013` | High | `4719` | Defense Evasion / `T1562.002` | System audit policy altered |
| `WET014` | Critical | `4104, 4688` | Execution / `T1059.001` | Obfuscated `-enc` or download-cradle PowerShell |
| `WET015` | High | `4624, 4648` | Lateral Movement / `T1021.001` | External RDP (Type 10) or explicit credentials (`4648`) |
| `WET016` | High | `4688` | Defense Evasion / `T1218` | LOLBin abuse (`certutil`, `mshta`, `bitsadmin`, `wmic`) |
| `WET017` | Medium | `4672` | Initial Access / `T1078` | Off-hours privileged logon |
| `WET018` | Critical | `4662` | Credential Access / `T1003.006` | Non-DC DCSync replication attempt |

## Quick Start

### PowerShell (Windows Server / Workstation, PS 5.1 & 7+)

```powershell
Import-Module .\WinEventTriage\WinEventTriage.psd1 -Force

# Triage an offline JSON snapshot or Event Viewer XML export
Invoke-WinEventTriage -SnapshotPath .\samples\ransomware-intrusion.json -OutputDir .\reports -Language en

# Export live read-only Windows Event snapshot safely for offline triage
Export-WinEventSnapshot -Hours 24 -OutputPath .\host-snapshot.json

# Triage an exported .evtx file directly on Windows (anonymized HTML/CSV/JSON/MD reports)
Invoke-WinEventTriage -EvtxPath C:\Logs\Security.evtx -OutputDir .\reports -Language pt -Anonymize
```

### Cross-Platform Python CLI (Zero Dependencies)

```bash
# Run built-in synthetic ransomware and clean baseline demo
PYTHONPATH=src python -m win_event_triage demo

# Triage a JSON snapshot or native Windows Event Viewer XML export
PYTHONPATH=src python -m win_event_triage triage samples/sample-eventviewer.xml --format html --output report.html --lang en
```

## Development & Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests/python -v
node tests/test_web_engine.mjs
```

MIT License. Built by [Gabriel Souza (@gavicoding)](https://gavicoding.github.io/).
