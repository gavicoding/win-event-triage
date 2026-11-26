"""Core read-only MITRE ATT&CK event correlation engine (WET001..WET023)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .models import Finding, NormalizedEvent, TriageReport
from .rules import RULES

PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "backup operators",
    "remote desktop users",
}

LSASS_NTDS_RX = re.compile(r"(?i)(?:sekurlsa|comsvcs\.dll.*minidump|procdump.*lsass|ntdsutil.*ifm|vssadmin.*ntds)")
SVC_SUSP_RX = re.compile(r"(?i)(?:\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\|cmd\.exe\s+/c|powershell.*-enc|PSEXESVC)")
TASK_SUSP_RX = re.compile(r"(?i)(?:\\Temp\\|\\AppData\\|\\ProgramData\\|-enc|EncodedCommand|powershell|mshta|certutil|rundll32)")
SHADOW_WIPE_RX = re.compile(
    r"(?i)(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|bcdedit.*recoveryenabled\s+no)"
)
PS_SUSP_RX = re.compile(r"(?i)(?:-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}|FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|Net\.WebClient|AmsiUtils)")
LOLBIN_RX = re.compile(r"(?i)(?:certutil.*-urlcache|mshta(?:\.exe)?\s+https?://|bitsadmin.*/transfer|regsvr32.*/i:https?://|wmic\s+/node:)")
DCSYNC_GUIDS = ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
RUN_KEY_RX = re.compile(
    r"(?i)\\(?:Software\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunServices|Policies\\Explorer\\Run)|"
    r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\(?:Userinit|Shell))\b"
)
RANSOM_NOTE_RX = re.compile(
    r"(?i)(?:\\|/)(?:[^\\/]*(?:decrypt|restore|recover|ransom|how[_ -]?to|readme[_ -]?(?:now|warning|for[_ -]?decrypt))[^\\/]*\.(?:txt|html?|hta|url)|"
    r"[^\\/]+\.(?:locked|encrypted|crypt|crypted|enc[0-9]*|lockbit|ryk|conti|akira|blackcat|phobos|8base))$"
)
SECURITY_SERVICES_RX = re.compile(r"(?i)\b(?:windefend|microsoft defender|windows defender|eventlog|windows event log|sense|wscsvc|security center|mpssvc|windows firewall|wdnissvc|sysmon64?)\b")
DISABLED_RX = re.compile(r"(?i)\b(?:disabled|desativad[oa]|stopped|parad[oa]|interrompid[oa])\b")

# Event IDs reused by many providers: only trust them from the right source (empty provider = JSON snapshot)
PROVIDERS = {
    "eventlog": ("microsoft-windows-eventlog", "eventlog"),
    "tasks": ("microsoft-windows-taskscheduler",),
    "defender": ("microsoft-windows-windows defender", "windows defender"),
    "sysmon": ("microsoft-windows-sysmon",),
    "scm": ("service control manager",),
    "rdp": ("microsoft-windows-terminalservices-remoteconnectionmanager", "microsoft-windows-terminalservices-localsessionmanager"),
}


def _from(ev: NormalizedEvent, source: str) -> bool:
    prov = (ev.provider or "").strip().lower()
    return not prov or prov in PROVIDERS[source]


def _process_line(ev: NormalizedEvent) -> str:
    """Command line of a process creation (4688 or Sysmon 1)."""
    return f"{_dget(ev, 'CommandLine', '')} {_dget(ev, 'Image', '') if not _dget(ev, 'CommandLine', '') else ''}".strip()


def _parse_ts(ts: str) -> datetime:
    if not ts:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    # Windows writes 7 fractional digits; Python 3.10 only accepts up to 6
    cleaned = re.sub(r"(\.\d{6})\d+", r"\1", cleaned)
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_private_or_local_ip(ip_text: str) -> bool:
    s = (ip_text or "").strip()
    if s in ("", "-", "localhost", "::1", "127.0.0.1"):
        return True
    try:
        ip_obj = ipaddress.ip_address(s)
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
            return True
        return any(ip_obj in net for net in RFC1918_NETS)
    except ValueError:
        return True


def _protect(value: str, anonymize: bool) -> str:
    if not anonymize or not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"ANON-{digest}"


def _dget(ev: NormalizedEvent, key: str, default: str = "") -> str:
    val = ev.data.get(key)
    return default if val is None else str(val)


def analyze_events(
    events: list[NormalizedEvent],
    source_label: str = "snapshot",
    business_hours_start: int = 7,
    business_hours_end: int = 20,
    brute_force_threshold: int = 5,
    anonymize: bool = False,
) -> TriageReport:
    """Analyze normalized Windows events across all MITRE-mapped triage rules."""
    ordered = sorted(events, key=lambda e: _parse_ts(e.time_created))
    findings: list[Finding] = []

    def add(rule_id: str, ts: str, host: str, account: str, src_ip: str, evidence: str) -> None:
        meta = RULES[rule_id]
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=meta.severity,
                tactic=meta.tactic,
                technique=meta.technique,
                timestamp=ts,
                computer=_protect(host, anonymize),
                account=_protect(account, anonymize),
                source_ip=src_ip,
                evidence=evidence,
            )
        )

    # WET001 & WET002: failed logon 4625 clusters + subsequent 4624
    failed_by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for ev in ordered:
        if ev.event_id == 4625:
            ip = _dget(ev, "IpAddress", "-")
            failed_by_ip[ip].append(ev)

    for ip, grp in failed_by_ip.items():
        if len(grp) >= brute_force_threshold:
            delta_min = (_parse_ts(grp[-1].time_created) - _parse_ts(grp[0].time_created)).total_seconds() / 60.0
            if delta_min <= 15.0:
                targets = sorted({_dget(item, "TargetUserName", "unknown") for item in grp})
                add(
                    "WET001",
                    grp[-1].time_created,
                    grp[0].computer,
                    ",".join(targets),
                    ip,
                    f"{len(grp)} failed logons (4625) from {ip} within 15m targeting: {', '.join(targets)}",
                )

    for ev in ordered:
        if ev.event_id == 4624:
            ok_ip = _dget(ev, "IpAddress", "-")
            ok_user = _dget(ev, "TargetUserName", "")
            ok_ts = _parse_ts(ev.time_created)
            if ok_ip != "-" and ok_ip in failed_by_ip:
                prior = [
                    f
                    for f in failed_by_ip[ok_ip]
                    if 0.0 <= (ok_ts - _parse_ts(f.time_created)).total_seconds() / 60.0 <= 15.0
                ]
                if len(prior) >= min(3, brute_force_threshold):
                    add(
                        "WET002",
                        ev.time_created,
                        ev.computer,
                        ok_user,
                        ok_ip,
                        f"Successful logon (4624) for '{ok_user}' from {ok_ip} after {len(prior)} failed attempts within 15m.",
                    )

    # Track newly created accounts for WET007
    created_users: dict[str, NormalizedEvent] = {}
    for ev in ordered:
        if ev.event_id == 4720:
            uname = _dget(ev, "TargetUserName", "")
            if uname:
                created_users[uname.lower()] = ev
            dt = _parse_ts(ev.time_created)
            if dt.hour < business_hours_start or dt.hour >= business_hours_end:
                actor = _dget(ev, "SubjectUserName", "unknown")
                add(
                    "WET007",
                    ev.time_created,
                    ev.computer,
                    uname,
                    "-",
                    f"New user '{uname}' created off-hours by '{actor}'.",
                )

    # WET004: account lockouts 4740
    lockouts = [e for e in ordered if e.event_id == 4740]
    if len(lockouts) >= 3:
        locked = sorted({_dget(e, "TargetUserName", "user") for e in lockouts})
        add(
            "WET004",
            lockouts[-1].time_created,
            lockouts[0].computer,
            ",".join(locked),
            "-",
            f"{len(lockouts)} account lockouts (4740) detected: {', '.join(locked)}",
        )

    for ev in ordered:
        eid = ev.event_id
        sysmon = (ev.provider or "").lower() == "microsoft-windows-sysmon"
        # Sysmon 1 (process creation) is read like 4688; IDs 1/10/11/13 only count when Sysmon wrote them
        if sysmon and eid == 1:
            eid = 4688
        elif eid in (1, 3, 10, 11, 13) and not sysmon:
            eid = -eid
        cmd_line = _process_line(ev)
        script_block = _dget(ev, "ScriptBlockText", "")
        combined = f"{cmd_line} {script_block} {ev.message}".strip()
        user = _dget(ev, "SubjectUserName", "") or _dget(ev, "User", "unknown")

        if sysmon and eid == 10:
            target = _dget(ev, "TargetImage", "").lower()
            source_img = _dget(ev, "SourceImage", "")
            access = _dget(ev, "GrantedAccess", "").lower()
            benign = re.search(r"(?i)\\(?:MsMpEng|csrss|wininit|lsm|svchost|services|wmiprvse|taskmgr|procexp64?)\.exe$", source_img)
            if target.endswith("\\lsass.exe") and not benign and access in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x40"):
                add("WET005", ev.time_created, ev.computer, user, "-", f"Process '{source_img}' opened LSASS memory (access {access}).")

        if (sysmon and eid == 13) or eid == 4657:
            key = _dget(ev, "TargetObject", "") or _dget(ev, "ObjectName", "")
            details = _dget(ev, "Details", "") or _dget(ev, "NewValue", "")
            if RUN_KEY_RX.search(key):
                add("WET020", ev.time_created, ev.computer, user, "-", f"Autostart registry value set: {key} = {details[:100]}")

        if sysmon and eid == 11:
            fname = _dget(ev, "TargetFilename", "")
            if RANSOM_NOTE_RX.search(fname):
                add("WET021", ev.time_created, ev.computer, user, "-", f"Ransom note or encrypted file written: {fname}")

        if eid in (1116, 1117) and _from(ev, "defender"):
            threat = _dget(ev, "Threat Name", "") or _dget(ev, "ThreatName", "") or ev.message[:80]
            path_ = _dget(ev, "Path", "")
            action = "blocked/removed" if eid == 1117 else "detected"
            add("WET022", ev.time_created, ev.computer, _dget(ev, "Detection User", "") or "-", "-", f"Defender {action} '{threat}' {path_[:100]}".strip())

        if eid in (7040, 7036) and _from(ev, "scm"):
            svc = _dget(ev, "param1", "") or _dget(ev, "Data_0", "") or ev.message
            state = f"{_dget(ev, 'param2', '')} {_dget(ev, 'param3', '')} {_dget(ev, 'Data_1', '')} {ev.message}"
            if SECURITY_SERVICES_RX.search(svc) and DISABLED_RX.search(state):
                add("WET023", ev.time_created, ev.computer, "-", "-", f"Security service '{svc[:60]}' changed to: {state.strip()[:80]}")

        if (eid == 1149 and _from(ev, "rdp")) or eid == 4778:
            ip = _dget(ev, "Param3", "") or _dget(ev, "ClientAddress", "") or _dget(ev, "Address", "")
            u = _dget(ev, "Param1", "") or _dget(ev, "AccountName", "") or _dget(ev, "User", "")
            if ip and not _is_private_or_local_ip(ip):
                what = "RDP authentication (1149)" if eid == 1149 else "RDP session reconnected (4778)"
                add("WET019", ev.time_created, ev.computer, u, ip, f"{what} for '{u}' from internet IP {ip}.")

        if eid == 4769:
            enc = _dget(ev, "TicketEncryptionType", "")
            spn = _dget(ev, "ServiceName", "")
            acct = _dget(ev, "TargetUserName", "")
            ip = _dget(ev, "IpAddress", "-")
            if enc == "0x17" and spn and not spn.endswith("$") and not spn.lower().startswith("krbtgt"):
                add("WET003", ev.time_created, ev.computer, acct, ip, f"Kerberos TGS 4769 with RC4 (0x17) requested for SPN '{spn}'.")

        if eid in (4656, 4663, 4688, 4104):
            obj_name = _dget(ev, "ObjectName", "")
            if "lsass.exe" in obj_name.lower() or LSASS_NTDS_RX.search(combined):
                subj = _dget(ev, "SubjectUserName", "unknown")
                add("WET005", ev.time_created, ev.computer, subj, "-", f"LSASS/NTDS credential access pattern: {combined[:110]}")

        if eid in (4728, 4732, 4756):
            grp = _dget(ev, "TargetUserName", "")
            member = _dget(ev, "MemberName", "unknown")
            actor = _dget(ev, "SubjectUserName", "unknown")
            if grp.lower() in PRIVILEGED_GROUPS:
                add("WET006", ev.time_created, ev.computer, member, "-", f"'{member}' added to privileged group '{grp}' by '{actor}'.")
            cn_clean = re.sub(r"^CN=([^,]+),.*$", r"\1", member, flags=re.I).lower()
            if cn_clean in created_users:
                add("WET007", ev.time_created, ev.computer, member, "-", f"Newly created account '{member}' was elevated into '{grp}'.")

        if eid == 4697 or (eid == 7045 and _from(ev, "scm")):
            srv = _dget(ev, "ServiceName", "unknown")
            img = _dget(ev, "ImagePath", "")
            if SVC_SUSP_RX.search(img):
                add("WET008", ev.time_created, ev.computer, "SYSTEM", "-", f"Suspicious service '{srv}' installed with path '{img}'.")

        if eid in (4698, 4702) or (eid == 106 and _from(ev, "tasks")):
            tname = _dget(ev, "TaskName", "unknown")
            tcontent = _dget(ev, "TaskContent", "")
            if TASK_SUSP_RX.search(f"{tcontent} {ev.message}"):
                subj = _dget(ev, "SubjectUserName", "unknown")
                add("WET009", ev.time_created, ev.computer, subj, "-", f"Suspicious scheduled task '{tname}' registered.")

        if eid in (1102, 104) and _from(ev, "eventlog"):
            subj = _dget(ev, "SubjectUserName", "unknown")
            add("WET010", ev.time_created, ev.computer, subj, "-", f"Event log cleared (EventID {eid}) by '{subj}'.")

        if eid in (4688, 4104) and SHADOW_WIPE_RX.search(combined):
            subj = _dget(ev, "SubjectUserName", "unknown")
            add("WET011", ev.time_created, ev.computer, subj, "-", f"Shadow copy/recovery sabotage command: {combined[:110]}")

        if eid in (5001, 5007, 5010, 5012) and _from(ev, "defender"):
            add("WET012", ev.time_created, ev.computer, "Defender", "-", f"Microsoft Defender telemetry EventID {eid}: {ev.message}")

        if eid == 4719:
            subj = _dget(ev, "SubjectUserName", "unknown")
            add("WET013", ev.time_created, ev.computer, subj, "-", f"System audit policy changed by '{subj}'.")

        if eid in (4104, 4688) and PS_SUSP_RX.search(combined):
            subj = _dget(ev, "SubjectUserName", "unknown")
            add("WET014", ev.time_created, ev.computer, subj, "-", f"Suspicious PowerShell execution: {combined[:110]}")

        if eid == 4624:
            ltype = _dget(ev, "LogonType", "")
            ip = _dget(ev, "IpAddress", "-")
            u = _dget(ev, "TargetUserName", "")
            if ltype == "10" and not _is_private_or_local_ip(ip):
                add("WET015", ev.time_created, ev.computer, u, ip, f"External RDP logon (Type 10) for '{u}' from IP {ip}.")

        if eid == 4648:
            subj = _dget(ev, "SubjectUserName", "unknown")
            targ = _dget(ev, "TargetUserName", "unknown")
            srv = _dget(ev, "TargetServerName", "unknown")
            if not subj.endswith("$"):
                add("WET015", ev.time_created, ev.computer, subj, "-", f"Explicit credentials used (4648): '{subj}' -> '{targ}' on '{srv}'.")

        if eid == 4688 and LOLBIN_RX.search(combined):
            subj = _dget(ev, "SubjectUserName", "unknown")
            add("WET016", ev.time_created, ev.computer, subj, "-", f"LOLBin remote/lateral abuse: {combined[:110]}")

        if eid == 4672:
            acct = _dget(ev, "SubjectUserName", "")
            if acct and not acct.endswith("$") and acct.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                dt = _parse_ts(ev.time_created)
                if dt.hour < business_hours_start or dt.hour >= business_hours_end:
                    add("WET017", ev.time_created, ev.computer, acct, "-", f"Privileged logon (4672) outside business hours for '{acct}' at {dt:%H:%M} UTC.")

        if eid == 4662:
            props = _dget(ev, "Properties", "").lower()
            subj = _dget(ev, "SubjectUserName", "unknown")
            if any(guid in props for guid in DCSYNC_GUIDS) and not subj.endswith("$"):
                add("WET018", ev.time_created, ev.computer, subj, "-", f"DS-Replication-Get-Changes requested by non-DC account '{subj}'.")

    return TriageReport(source=source_label, events_analyzed=len(ordered), findings=findings)
