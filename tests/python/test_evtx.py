"""EVTX reader, multi-file input, new rules (WET019-WET023) and provider guards."""

import io
import json
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from make_sample_evtx import write_evtx  # noqa: E402

from win_event_triage.cli import main  # noqa: E402
from win_event_triage.engine import _parse_ts, analyze_events  # noqa: E402
from win_event_triage.evtx import EvtxError, read_evtx  # noqa: E402
from win_event_triage.models import NormalizedEvent  # noqa: E402
from win_event_triage.parsers import collect_inputs, parse_events_file  # noqa: E402

SAMPLES = ROOT / "samples"


def ev(eid, provider, data, ts="2026-11-25T10:00:00Z"):
    return NormalizedEvent(event_id=eid, time_created=ts, computer="WS1", provider=provider, data=data)


class TestEvtxReader(unittest.TestCase):
    def test_samples_match_json_snapshots(self):
        for name in ("ransomware-intrusion", "insider-lateral-movement", "clean-baseline"):
            a = sorted(f.rule_id for f in analyze_events(parse_events_file(SAMPLES / f"{name}.json")).findings)
            b = sorted(f.rule_id for f in analyze_events(parse_events_file(SAMPLES / f"{name}.evtx")).findings)
            self.assertEqual(a, b, name)

    def test_fields_are_decoded(self):
        events = read_evtx(SAMPLES / "ransomware-intrusion.evtx")
        first = events[0]
        self.assertEqual(first["EventId"], 4625)
        self.assertEqual(first["Provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(first["LogName"], "Security")
        self.assertEqual(first["Computer"], "SRV-APP01.contoso.lab")
        self.assertEqual(first["Data"]["TargetUserName"], "svc-backup")
        self.assertTrue(first["TimeCreated"].endswith("Z"))
        self.assertEqual(len(first["TimeCreated"].split(".")[1]), 8, "7 fractional digits + Z, like Windows")

    def test_writer_round_trip_with_special_characters(self):
        events = [
            {"EventId": 4688, "TimeCreated": "2026-11-25T10:00:00.1234567Z", "Computer": "PC-Ação", "Data": {"CommandLine": 'cmd /c "echo <ok> & exit"', "Empty": ""}},
            {"EventId": 4624, "TimeCreated": "2026-11-25T10:00:01Z", "Computer": "PC-2", "Data": {"TargetUserName": "joão", "LogonType": "10"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "x.evtx"
            write_evtx(events, out)
            got = read_evtx(out)
        self.assertEqual(got[0]["Computer"], "PC-Ação")
        self.assertEqual(got[0]["Data"]["CommandLine"], 'cmd /c "echo <ok> & exit"')
        self.assertEqual(got[0]["Data"]["Empty"], "")
        self.assertEqual(got[0]["TimeCreated"], "2026-11-25T10:00:00.1234560Z")
        self.assertEqual(got[1]["Data"]["TargetUserName"], "joão")

    def test_many_events_span_several_chunks(self):
        events = [{"EventId": 4625, "TimeCreated": f"2026-11-25T10:{i // 60:02d}:{i % 60:02d}Z", "Computer": "DC1", "Data": {"TargetUserName": f"user{i}", "IpAddress": "203.0.113.7"}} for i in range(1500)]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "big.evtx"
            write_evtx(events, out)
            self.assertGreater(out.stat().st_size, 0x1000 + 0x10000, "must use more than one chunk")
            got = read_evtx(out)
        self.assertEqual(len(got), 1500)
        self.assertEqual([g["EventRecordID"] for g in got[:3]], [1, 2, 3])

    def test_not_an_evtx_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.evtx"
            bad.write_bytes(b"MZ" + b"\x00" * 5000)
            with self.assertRaises(EvtxError):
                read_evtx(bad)

    def test_damaged_chunk_is_skipped_not_fatal(self):
        data = bytearray((SAMPLES / "ransomware-intrusion.evtx").read_bytes())
        struct.pack_into("<I", data, 0x1000 + 0x200 + 4, 0xFFFFFF)  # absurd record size in the first record
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "damaged.evtx"
            p.write_bytes(bytes(data))
            self.assertEqual(read_evtx(p), [])

    def test_seven_digit_timestamps_parse_on_every_python(self):
        self.assertEqual(_parse_ts("2026-05-28T14:59:57.8629900Z").microsecond, 862990)


class TestNewRules(unittest.TestCase):
    def test_sysmon_rdp_defender_services(self):
        events = [
            ev(13, "Microsoft-Windows-Sysmon", {"TargetObject": r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\updater", "Details": r"C:\Users\Public\u.exe"}),
            ev(11, "Microsoft-Windows-Sysmon", {"TargetFilename": r"C:\Users\ana\Desktop\HOW_TO_DECRYPT.txt"}),
            ev(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", {"Param1": "adm", "Param3": "203.0.113.9"}),
            ev(1116, "Microsoft-Windows-Windows Defender", {"Threat Name": "Trojan:Win32/Test", "Path": r"C:\tmp\x.exe"}),
            ev(7040, "Service Control Manager", {"param1": "Microsoft Defender Antivirus Service", "param2": "auto start", "param3": "disabled"}),
            ev(10, "Microsoft-Windows-Sysmon", {"TargetImage": r"C:\Windows\system32\lsass.exe", "SourceImage": r"C:\Users\x\m.exe", "GrantedAccess": "0x1010"}),
            ev(1, "Microsoft-Windows-Sysmon", {"CommandLine": "vssadmin delete shadows /all /quiet", "Image": r"C:\Windows\System32\vssadmin.exe"}),
        ]
        ids = sorted(f.rule_id for f in analyze_events(events).findings)
        self.assertEqual(ids, ["WET005", "WET011", "WET019", "WET020", "WET021", "WET022", "WET023"])

    def test_reused_event_ids_from_other_providers_are_ignored(self):
        events = [
            ev(104, "Some-Other-Provider", {}),
            ev(11, "Some-Other-Provider", {"TargetFilename": r"C:\x\HOW_TO_DECRYPT.txt"}),
            ev(1, "Some-Other-Provider", {"CommandLine": "vssadmin delete shadows /all"}),
            ev(5001, "Some-Other-Provider", {}),
            ev(7045, "Some-Other-Provider", {"ServiceName": "x", "ImagePath": r"C:\Temp\x.exe"}),
            ev(10, "Microsoft-Windows-Sysmon", {"TargetImage": r"C:\Windows\system32\lsass.exe", "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe", "GrantedAccess": "0x1010"}),
            ev(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", {"Param1": "adm", "Param3": "10.0.0.5"}),
        ]
        self.assertEqual(analyze_events(events).findings, [])


class TestInputs(unittest.TestCase):
    def test_folder_and_many_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "a.evtx").write_bytes((SAMPLES / "ransomware-intrusion.evtx").read_bytes())
            (d / "b.json").write_text((SAMPLES / "clean-baseline.json").read_text(encoding="utf-8"), encoding="utf-8")
            (d / "notes.txt").write_text("ignore me", encoding="utf-8")
            files = collect_inputs([d, d / "a.evtx"])
            self.assertEqual([f.name for f in files], ["a.evtx", "b.json"])
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["triage", str(d), "--format", "json", "--fail-on", "none"])
            self.assertEqual(code, 0)
            rep = json.loads(out.getvalue())
            self.assertEqual(rep["events_analyzed"], 14 + 6)

    def test_locales_are_packaged_and_in_sync(self):
        pkg = ROOT / "src" / "win_event_triage" / "locales"
        src = ROOT / "WinEventTriage" / "locales"
        for name in ("en.json", "pt-BR.json"):
            self.assertEqual(json.loads((pkg / name).read_text(encoding="utf-8")), json.loads((src / name).read_text(encoding="utf-8")), name)


if __name__ == "__main__":
    unittest.main()
