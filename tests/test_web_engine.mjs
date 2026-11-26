import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const web = require("../docs/app.js");

assert.equal(Object.keys(web.RULES).length, 23, "Must expose 23 MITRE-mapped rules");

const ransom = web.analyzeEvents(web.PRESETS.ransomware.events, "ransomware");
const rIds = new Set(ransom.findings.map((f) => f.rule_id));
for (const expected of ["WET001", "WET002", "WET003", "WET005", "WET008", "WET010", "WET011", "WET012", "WET014"]) {
  assert.ok(rIds.has(expected), `Missing rule ${expected} in ransomware scenario`);
}
assert.equal(ransom.risk_score, 100);

const insider = web.analyzeEvents(web.PRESETS.insider.events, "insider");
const iIds = new Set(insider.findings.map((f) => f.rule_id));
assert.ok(iIds.has("WET006") && iIds.has("WET018"), "Insider scenario must detect group add and DCSync");

const clean = web.analyzeEvents(web.PRESETS.clean.events, "clean");
assert.equal(clean.findings.length, 0, "Clean baseline must have 0 findings");

const xmlSample = fs.readFileSync(path.resolve("samples/sample-eventviewer.xml"), "utf8");
const parsedXml = web.parseXmlEventsString(xmlSample);
assert.equal(parsedXml.length, 2, "Must parse 2 events from sample Event Viewer XML");
const xmlReport = web.analyzeEvents(parsedXml, "xml");
assert.deepEqual(xmlReport.findings.map((f) => f.rule_id), ["WET003", "WET010"]);

// .evtx read in the browser engine gives the same findings as the JSON snapshot
for (const name of ["ransomware-intrusion", "insider-lateral-movement", "clean-baseline"]) {
  const fromEvtx = web.analyzeEvents(web.readEvtx(fs.readFileSync(path.resolve(`samples/${name}.evtx`))), name);
  const snap = JSON.parse(fs.readFileSync(path.resolve(`samples/${name}.json`), "utf8"));
  const fromJson = web.analyzeEvents(snap.events || snap, name);
  assert.deepEqual(fromEvtx.findings.map((f) => f.rule_id).sort(), fromJson.findings.map((f) => f.rule_id).sort(), `evtx/json parity for ${name}`);
}
assert.ok(fs.readFileSync(path.resolve("docs/samples/ransomware-intrusion.evtx")).equals(fs.readFileSync(path.resolve("samples/ransomware-intrusion.evtx"))), "docs sample must match samples/");

// new rules: Sysmon, RDP, Defender detection, service tampering; provider guard on reused IDs
const extra = web.analyzeEvents([
  { EventId: 13, Provider: "Microsoft-Windows-Sysmon", TimeCreated: "2026-11-25T10:00:00Z", Computer: "WS1", Data: { TargetObject: String.raw`HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\updater`, Details: String.raw`C:\Users\Public\u.exe` } },
  { EventId: 11, Provider: "Microsoft-Windows-Sysmon", TimeCreated: "2026-11-25T10:01:00Z", Computer: "WS1", Data: { TargetFilename: String.raw`C:\Users\ana\Desktop\HOW_TO_DECRYPT.txt` } },
  { EventId: 1149, Provider: "Microsoft-Windows-TerminalServices-RemoteConnectionManager", TimeCreated: "2026-11-25T10:02:00Z", Computer: "WS1", Data: { Param1: "adm", Param3: "203.0.113.9" } },
  { EventId: 1116, Provider: "Microsoft-Windows-Windows Defender", TimeCreated: "2026-11-25T10:03:00Z", Computer: "WS1", Data: { "Threat Name": "Trojan:Win32/Test", Path: String.raw`C:\tmp\x.exe` } },
  { EventId: 7040, Provider: "Service Control Manager", TimeCreated: "2026-11-25T10:04:00Z", Computer: "WS1", Data: { param1: "Microsoft Defender Antivirus Service", param2: "auto start", param3: "disabled" } },
  { EventId: 104, Provider: "Some-Other-Provider", TimeCreated: "2026-11-25T10:05:00Z", Computer: "WS1", Data: {} },
  { EventId: 11, Provider: "Some-Other-Provider", TimeCreated: "2026-11-25T10:06:00Z", Computer: "WS1", Data: { TargetFilename: String.raw`C:\x\HOW_TO_DECRYPT.txt` } }
], "extra");
const extraIds = extra.findings.map((f) => f.rule_id).sort();
assert.deepEqual(extraIds, ["WET019", "WET020", "WET021", "WET022", "WET023"], `got ${extraIds}`);

console.log("win-event-triage web engine tests passed.");
