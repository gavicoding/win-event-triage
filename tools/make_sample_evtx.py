"""Write a small, valid .evtx file from a JSON snapshot (fictitious data for demos and tests).

Usage: python tools/make_sample_evtx.py samples/ransomware-intrusion.json samples/ransomware-intrusion.evtx
The output opens in Windows Event Viewer / Get-WinEvent and in the zero-dependency readers of this repo.
"""

from __future__ import annotations

import json
import struct
import sys
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path

CHUNK_SIZE = 0x10000
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(iso: str) -> int:
    s = iso.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dot = s.find(".")
    if dot != -1:  # keep at most 6 fractional digits for fromisoformat
        end = dot + 1
        while end < len(s) and s[end].isdigit():
            end += 1
        s = s[: min(end, dot + 7)] + s[end:]
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


DEFAULT_SOURCE = {
    104: ("Microsoft-Windows-Eventlog", "System"),
    1102: ("Microsoft-Windows-Eventlog", "Security"),
    7045: ("Service Control Manager", "System"),
    7040: ("Service Control Manager", "System"),
    4104: ("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational"),
    106: ("Microsoft-Windows-TaskScheduler", "Microsoft-Windows-TaskScheduler/Operational"),
    1149: ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
}
for _id in (5001, 5007, 1116, 1117):
    DEFAULT_SOURCE[_id] = ("Microsoft-Windows-Windows Defender", "Microsoft-Windows-Windows Defender/Operational")


def source_of(ev: dict) -> tuple[str, str]:
    """Provider and channel: from the snapshot, or the usual ones for that event ID."""
    eid = int(ev.get("EventId") or 0)
    prov, chan = DEFAULT_SOURCE.get(eid, ("Microsoft-Windows-Security-Auditing", "Security"))
    return str(ev.get("Provider") or prov), str(ev.get("LogName") or chan)


def name_hash(name: str) -> int:
    h = 0
    for ch in name:
        h = (h * 65599 + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


class ChunkWriter:
    def __init__(self) -> None:
        self.buf = bytearray(CHUNK_SIZE)
        self.pos = 0x200
        self.names: dict[str, int] = {}
        self.templates: dict[tuple, tuple[int, int]] = {}  # key -> (definition offset, template id)
        self.records: list[tuple[int, int]] = []  # (offset, size)

    # name reference: inline the first time, then point to the stored copy
    def name(self, out: bytearray, base: int, name: str) -> None:
        here = base + len(out)
        if name in self.names:
            out += struct.pack("<I", self.names[name])
            return
        off = here + 4
        self.names[name] = off
        out += struct.pack("<I", off)
        out += struct.pack("<IHH", 0, name_hash(name), len(name)) + name.encode("utf-16-le") + b"\x00\x00"

    def element(self, out: bytearray, base: int, name: str, attrs: list[tuple[str, object]], children) -> None:
        out.append(0x41 if attrs else 0x01)
        out += struct.pack("<H", 0xFFFF)
        size_at = len(out)
        out += b"\x00\x00\x00\x00"
        self.name(out, base, name)
        if attrs:
            list_at = len(out)
            out += b"\x00\x00\x00\x00"
            for i, (aname, aval) in enumerate(attrs):
                out.append(0x46 if i < len(attrs) - 1 else 0x06)
                self.name(out, base, aname)
                self.value(out, aval)
            struct.pack_into("<I", out, list_at, len(out) - list_at - 4)
        if children is None:
            out.append(0x03)  # close empty element
        else:
            out.append(0x02)
            for c in children:
                if isinstance(c, tuple) and c[0] == "el":
                    self.element(out, base, c[1], c[2], c[3])
                else:
                    self.value(out, c)
            out.append(0x04)
        struct.pack_into("<I", out, size_at, len(out) - size_at - 4)

    @staticmethod
    def value(out: bytearray, v) -> None:
        if isinstance(v, tuple) and v[0] == "sub":
            out += bytes([0x0E, v[1] & 0xFF, v[1] >> 8, v[2]])  # optional substitution
        else:
            text = str(v)
            out += bytes([0x05, 0x01]) + struct.pack("<H", len(text)) + text.encode("utf-16-le")

    def template_body(self, base: int, data_names: tuple[str, ...]) -> bytearray:
        body = bytearray(b"\x0f\x01\x01\x00")
        sub = lambda i, t: ("sub", i, t)  # noqa: E731
        system = [
            ("el", "Provider", [("Name", sub(0, 0x01))], None),
            ("el", "EventID", [], [sub(1, 0x06)]),
            ("el", "TimeCreated", [("SystemTime", sub(2, 0x11))], None),
            ("el", "EventRecordID", [], [sub(3, 0x0A)]),
            ("el", "Channel", [], [sub(4, 0x01)]),
            ("el", "Computer", [], [sub(5, 0x01)]),
        ]
        data = [("el", "Data", [("Name", n)], [sub(6 + i, 0x01)]) for i, n in enumerate(data_names)]
        self.element(
            body,
            base,
            "Event",
            [("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")],
            [("el", "System", [], system), ("el", "EventData", [], data)],
        )
        body.append(0x00)
        return body

    def add_record(self, record_id: int, ev: dict) -> bool:
        data = {str(k): "" if v is None else str(v) for k, v in (ev.get("Data") or {}).items()}
        names = tuple(data)
        key = names
        out = bytearray()
        start = self.pos + 24  # BinXML starts after the record header
        out += b"\x0f\x01\x01\x00"
        out.append(0x0C)
        out.append(0x01)
        if key in self.templates:
            def_off, tid = self.templates[key]
            out += struct.pack("<II", tid, def_off)
        else:
            guid = uuid.uuid5(uuid.NAMESPACE_URL, "win-event-triage/" + "|".join(names)).bytes_le
            tid = struct.unpack_from("<I", guid)[0]
            def_off = start + len(out) + 8
            out += struct.pack("<II", tid, def_off)
            body_base = def_off + 24
            body = self.template_body(body_base, names)
            out += struct.pack("<I", 0) + guid + struct.pack("<I", len(body))
            out += body
            self.templates[key] = (def_off, tid)
        provider, channel = source_of(ev)
        values = [
            ("s", provider),
            ("u16", int(ev.get("EventId") or 0)),
            ("ft", filetime(str(ev.get("TimeCreated")))),
            ("u64", record_id),
            ("s", channel),
            ("s", str(ev.get("Computer") or "")),
        ] + [("s", data[n]) for n in names]
        descs = bytearray()
        payload = bytearray()
        for kind, v in values:
            if kind == "s":
                raw = v.encode("utf-16-le")
                descs += struct.pack("<HBB", len(raw), 0x01 if raw else 0x00, 0)
            elif kind == "u16":
                raw = struct.pack("<H", v)
                descs += struct.pack("<HBB", 2, 0x06, 0)
            elif kind == "u64":
                raw = struct.pack("<Q", v)
                descs += struct.pack("<HBB", 8, 0x0A, 0)
            else:
                raw = struct.pack("<Q", v)
                descs += struct.pack("<HBB", 8, 0x11, 0)
            payload += raw
        out += struct.pack("<I", len(values)) + descs + payload
        out += b"\x00" * ((-(24 + len(out) + 4)) % 8)  # records are 8-byte aligned
        size = 24 + len(out) + 4
        if self.pos + size > CHUNK_SIZE:
            return False
        rec = struct.pack("<IIQQ", 0x2A2A, size, record_id, filetime(str(ev.get("TimeCreated")))) + out + struct.pack("<I", size)
        self.buf[self.pos : self.pos + size] = rec
        self.records.append((self.pos, size))
        self.pos += size
        return True

    def finish(self, first_id: int, last_id: int) -> bytes:
        b = self.buf
        b[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQ", b, 8, first_id, last_id, first_id, last_id)
        struct.pack_into("<III", b, 40, 128, self.records[-1][0], self.pos)
        # string offsets (64) and template pointers (32) tables
        for i in range(64):
            struct.pack_into("<I", b, 128 + 4 * i, 0)
        for name, off in self.names.items():
            slot = name_hash(name) % 64
            previous = struct.unpack_from("<I", b, 128 + 4 * slot)[0]
            struct.pack_into("<I", b, off, previous)
            struct.pack_into("<I", b, 128 + 4 * slot, off)
        for def_off, tid in self.templates.values():
            slot = tid % 32
            previous = struct.unpack_from("<I", b, 384 + 4 * slot)[0]
            struct.pack_into("<I", b, def_off, previous)
            struct.pack_into("<I", b, 384 + 4 * slot, def_off)
        struct.pack_into("<I", b, 52, zlib.crc32(bytes(b[0x200 : self.pos])) & 0xFFFFFFFF)
        struct.pack_into("<I", b, 124, zlib.crc32(bytes(b[0:120]) + bytes(b[128:0x200])) & 0xFFFFFFFF)
        return bytes(b)


def write_evtx(events: list[dict], out: Path) -> None:
    chunks: list[bytes] = []
    cw = ChunkWriter()
    first = 1
    rid = 1
    for ev in events:
        if not cw.add_record(rid, ev):
            chunks.append(cw.finish(first, rid - 1))
            cw = ChunkWriter()
            first = rid
            assert cw.add_record(rid, ev), "event too large for one chunk"
        rid += 1
    chunks.append(cw.finish(first, rid - 1))
    header = bytearray(0x1000)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", header, 8, 0, len(chunks) - 1, rid, 128, 2, 3, 0x1000, len(chunks))
    struct.pack_into("<I", header, 120, 0)  # flags: clean
    struct.pack_into("<I", header, 124, zlib.crc32(bytes(header[0:120])) & 0xFFFFFFFF)
    out.write_bytes(bytes(header) + b"".join(chunks))


def main(argv: list[str]) -> int:
    src, dst = Path(argv[1]), Path(argv[2])
    payload = json.loads(src.read_text(encoding="utf-8"))
    events = payload["events"] if isinstance(payload, dict) else payload
    events = sorted(events, key=lambda e: str(e.get("TimeCreated")))
    write_evtx(events, dst)
    print(f"{dst}: {len(events)} events")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
