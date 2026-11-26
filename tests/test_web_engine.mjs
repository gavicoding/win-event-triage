import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const web = require("../docs/app.js");

assert.equal(Object.keys(web.RULES).length, 18, "Must expose 18 MITRE-mapped rules");

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

console.log("win-event-triage web engine tests passed.");
