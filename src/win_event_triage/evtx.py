"""Zero-dependency reader for Windows .evtx files (EVTX: chunks, records, BinXML templates).

Only what triage needs is decoded: System fields and EventData/UserData values. Works on any OS,
reads the file without changing it and skips damaged chunks/records instead of failing.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterator

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class EvtxError(ValueError):
    """The file is not a readable EVTX log."""


@dataclass
class Node:
    """Tiny element tree: enough to read System and EventData."""

    name: str
    attrs: dict[str, Any] = field(default_factory=dict)
    children: list["Node | Any"] = field(default_factory=list)

    def text(self) -> str:
        return "".join(_as_text(c) for c in self.children if not isinstance(c, Node))

    def find(self, name: str) -> "Node | None":
        for c in self.children:
            if isinstance(c, Node) and c.name == name:
                return c
        return None

    def iter_nodes(self) -> Iterator["Node"]:
        for c in self.children:
            if isinstance(c, Node):
                yield c


class _Sub:
    """Placeholder for a template substitution."""

    __slots__ = ("index", "vtype", "optional")

    def __init__(self, index: int, vtype: int, optional: bool) -> None:
        self.index, self.vtype, self.optional = index, vtype, optional


def filetime_to_iso(ft: int) -> str:
    if ft < 0:
        return ""
    try:
        dt = EPOCH + timedelta(seconds=ft // 10_000_000)
    except OverflowError:
        return ""
    # same 100-nanosecond precision Windows shows in the event XML
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ft % 10_000_000:07d}Z"


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return ", ".join(_as_text(x) for x in v)
    if isinstance(v, Node):
        return v.text()
    return str(v)


def _sid(b: bytes) -> str:
    if len(b) < 8:
        return b.hex()
    rev, count = b[0], b[1]
    auth = int.from_bytes(b[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", b, 8) if len(b) >= 8 + 4 * count else ()
    return "S-{}-{}".format(rev, auth) + "".join(f"-{s}" for s in subs)


class _Chunk:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.templates: dict[int, list[Any]] = {}

    # ---------- primitives ----------
    def u8(self, o: int) -> int:
        return self.data[o]

    def u16(self, o: int) -> int:
        return struct.unpack_from("<H", self.data, o)[0]

    def u32(self, o: int) -> int:
        return struct.unpack_from("<I", self.data, o)[0]

    def name_at(self, off: int) -> str:
        # name string: next offset (4), hash (2), char count (2), UTF-16 chars, NUL (2)
        n = self.u16(off + 6)
        return self.data[off + 8 : off + 8 + 2 * n].decode("utf-16-le", errors="replace")

    def read_name(self, pos: int) -> tuple[str, int]:
        """Name reference at pos; when the string is stored inline right here, skip over it."""
        off = self.u32(pos)
        pos += 4
        if off == pos:
            n = self.u16(off + 6)
            return self.name_at(off), off + 8 + 2 * n + 2
        return self.name_at(off), pos

    # ---------- values ----------
    def value(self, vtype: int, o: int, size: int) -> Any:
        d = self.data
        if size == 0 and vtype not in (0x01,):
            return None
        base = vtype & 0x7F
        if vtype & 0x80:
            if base == 0x01:
                s = d[o : o + size].decode("utf-16-le", errors="replace")
                items = s.split("\x00")
                if items and items[-1] == "":
                    items.pop()  # final terminator, not an empty item
                return items
            width = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0F: 16, 0x11: 8, 0x14: 4, 0x15: 8}.get(base)
            if width:
                return [self.value(base, o + i, width) for i in range(0, size - size % width, width)]
            return d[o : o + size].hex().upper()
        if base == 0x00:
            return None
        if base == 0x01:
            return d[o : o + size].decode("utf-16-le", errors="replace").rstrip("\x00")
        if base == 0x02:
            return d[o : o + size].decode("latin-1").rstrip("\x00")
        fmt = {0x03: "<b", 0x04: "<B", 0x05: "<h", 0x06: "<H", 0x07: "<i", 0x08: "<I", 0x09: "<q", 0x0A: "<Q", 0x0B: "<f", 0x0C: "<d"}.get(base)
        if fmt:
            return struct.unpack_from(fmt, d, o)[0]
        if base == 0x0D:
            return struct.unpack_from("<I", d, o)[0] != 0
        if base == 0x0E:
            return d[o : o + size].hex().upper()
        if base == 0x0F:
            return "{" + str(uuid.UUID(bytes_le=bytes(d[o : o + 16]))) + "}"
        if base == 0x10:
            return hex(struct.unpack_from("<Q" if size == 8 else "<I", d, o)[0])
        if base == 0x11:
            return filetime_to_iso(struct.unpack_from("<Q", d, o)[0])
        if base == 0x12:
            y, mo, _wd, day, h, mi, s, ms = struct.unpack_from("<8H", d, o)
            return f"{y:04d}-{mo:02d}-{day:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"
        if base == 0x13:
            return _sid(bytes(d[o : o + size]))
        if base == 0x14:
            return hex(struct.unpack_from("<I", d, o)[0])
        if base == 0x15:
            return hex(struct.unpack_from("<Q", d, o)[0])
        if base == 0x21:  # embedded BinXML (e.g. UserData)
            nodes, _ = self.fragment(o, o + size)
            return nodes
        return d[o : o + size].hex().upper()

    # ---------- BinXML ----------
    def fragment(self, pos: int, end: int, in_template: bool = False) -> tuple[list[Any], int]:
        """Parse a BinXML stream into a list of top-level items."""
        stack: list[Node] = [Node("#root")]
        while pos < end:
            tok = self.u8(pos)
            t = tok & 0x0F if tok not in (0x0C, 0x0D, 0x0E, 0x0F) else tok
            if tok == 0x00:  # end of fragment
                pos += 1
                break
            if tok == 0x0F:  # fragment header
                pos += 4
                continue
            if t == 0x01:  # open start element
                pos += 1
                pos += 2  # dependency identifier
                pos += 4  # data size
                name, pos = self.read_name(pos)
                el = Node(name)
                if tok & 0x40:
                    pos += 4  # attribute list size
                    while pos < end and (self.u8(pos) & 0x0F) == 0x06:
                        pos += 1
                        aname, pos = self.read_name(pos)
                        val, pos = self._attr_value(pos, end)
                        el.attrs[aname] = val
                stack[-1].children.append(el)
                stack.append(el)
                continue
            if t == 0x02:  # close start element
                pos += 1
                continue
            if t in (0x03, 0x04):  # close empty / end element
                pos += 1
                if len(stack) > 1:
                    stack.pop()
                continue
            if t == 0x05:  # value text
                vtype = self.u8(pos + 1)
                if vtype == 0x01:
                    n = self.u16(pos + 2)
                    stack[-1].children.append(self.data[pos + 4 : pos + 4 + 2 * n].decode("utf-16-le", errors="replace"))
                    pos += 4 + 2 * n
                else:
                    raise EvtxError(f"unsupported inline value type {vtype:#x}")
                continue
            if t in (0x07, 0x08, 0x09):  # CDATA / char ref / entity ref
                if t == 0x07:
                    n = self.u16(pos + 1)
                    stack[-1].children.append(self.data[pos + 3 : pos + 3 + 2 * n].decode("utf-16-le", errors="replace"))
                    pos += 3 + 2 * n
                elif t == 0x08:
                    stack[-1].children.append(chr(self.u16(pos + 1)))
                    pos += 3
                else:
                    name, pos = self.read_name(pos + 1)
                    stack[-1].children.append({"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}.get(name, ""))
                continue
            if t in (0x0A, 0x0B):  # processing instructions: skip
                if t == 0x0A:
                    _, pos = self.read_name(pos + 1)
                else:
                    n = self.u16(pos + 1)
                    pos += 3 + 2 * n
                continue
            if tok == 0x0C:  # template instance
                item, pos = self._template_instance(pos)
                stack[-1].children.extend(item)
                continue
            if tok in (0x0D, 0x0E):  # substitution placeholder (only inside template definitions)
                stack[-1].children.append(_Sub(self.u16(pos + 1), self.u8(pos + 3), tok == 0x0E))
                pos += 4
                continue
            raise EvtxError(f"unknown BinXML token {tok:#x} at {pos:#x}")
        return stack[0].children, pos

    def _attr_value(self, pos: int, end: int) -> tuple[Any, int]:
        tok = self.u8(pos)
        if tok in (0x0D, 0x0E):
            return _Sub(self.u16(pos + 1), self.u8(pos + 3), tok == 0x0E), pos + 4
        if (tok & 0x0F) == 0x05:
            vtype = self.u8(pos + 1)
            n = self.u16(pos + 2)
            return self.data[pos + 4 : pos + 4 + 2 * n].decode("utf-16-le", errors="replace") if vtype == 0x01 else None, pos + 4 + 2 * n
        if (tok & 0x0F) == 0x08:
            return chr(self.u16(pos + 1)), pos + 3
        if (tok & 0x0F) == 0x09:
            name, p = self.read_name(pos + 1)
            return {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}.get(name, ""), p
        return None, pos

    def _template_instance(self, pos: int) -> tuple[list[Any], int]:
        pos += 1 + 1  # token + unknown
        pos += 4  # template id
        def_off = self.u32(pos)
        pos += 4
        if def_off == pos:  # definition stored inline right here
            size = self.u32(def_off + 20)
            body_start = def_off + 24
            if def_off not in self.templates:
                self.templates[def_off], _ = self.fragment(body_start, body_start + size, in_template=True)
            pos = body_start + size
        elif def_off not in self.templates:
            size = self.u32(def_off + 20)
            body_start = def_off + 24
            self.templates[def_off], _ = self.fragment(body_start, body_start + size, in_template=True)
        template = self.templates[def_off]

        count = self.u32(pos)
        pos += 4
        descs = []
        for _ in range(count):
            descs.append((self.u16(pos), self.u8(pos + 2)))
            pos += 4
        values = []
        for size, vtype in descs:
            values.append(self.value(vtype, pos, size) if size else None)
            pos += size
        out: list[Any] = []
        for n in template:
            r = _instantiate(n, values)
            if isinstance(r, list) and r and all(isinstance(x, Node) for x in r):
                out.extend(r)
            elif r is not None:
                out.append(r)
        return out, pos


def _instantiate(item: Any, values: list[Any]) -> Any:
    if isinstance(item, _Sub):
        v = values[item.index] if item.index < len(values) else None
        return v
    if isinstance(item, Node):
        # an element whose only content is an array substitution is repeated once per item
        if len(item.children) == 1 and isinstance(item.children[0], _Sub):
            sub = item.children[0]
            v = values[sub.index] if sub.index < len(values) else None
            if isinstance(v, list) and v and not all(isinstance(x, Node) for x in v) and sub.vtype & 0x80:
                copies = []
                for x in v:
                    n = Node(item.name, {k: (_as_text(_instantiate(a, values)) if isinstance(a, _Sub) else a) for k, a in item.attrs.items()})
                    n.children.append(x)
                    copies.append(n)
                return copies
        n = Node(item.name, {})
        for k, v in item.attrs.items():
            n.attrs[k] = _as_text(_instantiate(v, values)) if isinstance(v, _Sub) else v
        for c in item.children:
            r = _instantiate(c, values)
            if r is None:
                continue
            if isinstance(r, list) and r and all(isinstance(x, Node) for x in r):
                n.children.extend(r)  # embedded BinXML or repeated array elements
            else:
                n.children.append(r)
        return n
    return item


@dataclass
class EvtxRecord:
    record_id: int
    timestamp: str
    root: Node | None

    def to_event(self) -> dict[str, Any]:
        """Flatten into the fields triage uses."""
        ev = self.root
        out: dict[str, Any] = {"EventRecordID": self.record_id, "TimeCreated": self.timestamp, "Data": {}}
        if ev is None:
            return out
        system = ev.find("System")
        if system is not None:
            for el in system.iter_nodes():
                if el.name == "EventID":
                    try:
                        out["EventId"] = int(el.text() or 0)
                    except ValueError:
                        out["EventId"] = 0
                elif el.name == "Provider":
                    out["Provider"] = _as_text(el.attrs.get("Name", ""))
                elif el.name == "Computer":
                    out["Computer"] = el.text()
                elif el.name == "Channel":
                    out["LogName"] = el.text()
                elif el.name == "TimeCreated" and el.attrs.get("SystemTime"):
                    out["TimeCreated"] = _as_text(el.attrs["SystemTime"])
                elif el.name == "Security" and el.attrs.get("UserID"):
                    out["UserSid"] = _as_text(el.attrs["UserID"])
                elif el.name == "Level":
                    out["Level"] = el.text()
                elif el.name == "EventRecordID":
                    try:
                        out["EventRecordID"] = int(el.text() or out["EventRecordID"])
                    except ValueError:
                        pass
        data: dict[str, Any] = {}
        payload = ev.find("EventData") or ev.find("UserData")
        if payload is not None:
            _flatten(payload, data)
        out["Data"] = data
        return out


def _flatten(node: Node, data: dict[str, Any], prefix: str = "") -> None:
    unnamed = 0
    for c in node.children:
        if isinstance(c, Node):
            if c.name == "Data":
                key = _as_text(c.attrs.get("Name")) or f"Data_{unnamed}"
                if not c.attrs.get("Name"):
                    unnamed += 1
                data[key] = c.text()
            elif any(isinstance(x, Node) for x in c.children):
                _flatten(c, data, c.name + ".")
            else:
                data[prefix + c.name] = c.text()


def iter_records(fh: BinaryIO, max_records: int | None = None) -> Iterator[EvtxRecord]:
    header = fh.read(FILE_HEADER_SIZE)
    if len(header) < 128 or header[:8] != FILE_MAGIC:
        raise EvtxError("not an EVTX file (missing ElfFile signature)")
    header_block = struct.unpack_from("<H", header, 40)[0] or FILE_HEADER_SIZE
    fh.seek(header_block)
    seen = 0
    while True:
        raw = fh.read(CHUNK_SIZE)
        if len(raw) < CHUNK_SIZE:
            break
        if raw[:8] != CHUNK_MAGIC:
            continue  # empty or damaged chunk
        chunk = _Chunk(raw)
        free_off = struct.unpack_from("<I", raw, 48)[0]
        end = min(free_off or CHUNK_SIZE, CHUNK_SIZE)
        pos = 0x200
        while pos + 24 <= end:
            if raw[pos : pos + 4] != RECORD_MAGIC:
                break
            size = struct.unpack_from("<I", raw, pos + 4)[0]
            if size < 28 or pos + size > CHUNK_SIZE:
                break
            rec_id = struct.unpack_from("<Q", raw, pos + 8)[0]
            ts = filetime_to_iso(struct.unpack_from("<Q", raw, pos + 16)[0])
            try:
                items, _ = chunk.fragment(pos + 24, pos + size - 4)
                root = next((x for x in items if isinstance(x, Node)), None)
            except (EvtxError, struct.error, IndexError, UnicodeDecodeError):
                root = None
            yield EvtxRecord(rec_id, ts, root)
            seen += 1
            if max_records is not None and seen >= max_records:
                return
            pos += size


def read_evtx(path: Path | str, max_records: int | None = None) -> list[dict[str, Any]]:
    """All records of an .evtx file as flat dicts (EventId, TimeCreated, Computer, Provider, LogName, Data...)."""
    with open(path, "rb") as fh:
        return [r.to_event() for r in iter_records(fh, max_records)]
