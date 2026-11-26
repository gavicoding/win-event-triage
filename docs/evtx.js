/* Zero-dependency .evtx reader for the browser and Node.js (same logic as src/win_event_triage/evtx.py).
 * Decodes chunks, records and BinXML templates into flat events: EventId, TimeCreated, Computer,
 * Provider, LogName, EventRecordID and Data. The file never leaves the browser tab. */

(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.WinEvtx = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const CHUNK_SIZE = 0x10000;
  const utf16 = new TextDecoder("utf-16le");
  const latin1 = new TextDecoder("latin1");
  const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };

  function isNode(x) {
    return x !== null && typeof x === "object" && x.kind === "node";
  }
  function isSub(x) {
    return x !== null && typeof x === "object" && x.kind === "sub";
  }
  function node(name) {
    return { kind: "node", name, attrs: {}, children: [] };
  }

  function asText(v) {
    if (v === null || v === undefined) return "";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (Array.isArray(v)) return v.map(asText).join(", ");
    if (isNode(v)) return v.children.filter((c) => !isNode(c)).map(asText).join("");
    return String(v);
  }

  function hex(bytes, upper) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return upper ? s.toUpperCase() : s;
  }

  function filetimeToIso(lo, hi) {
    // 64-bit FILETIME without BigInt precision loss: split into seconds and 100 ns ticks
    const big = BigInt(hi) * 4294967296n + BigInt(lo);
    const secs = big / 10000000n;
    const ticks = Number(big % 10000000n);
    const ms = Number(secs - 11644473600n) * 1000;
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return "";
    return d.toISOString().slice(0, 19) + "." + String(ticks).padStart(7, "0") + "Z";
  }

  class Chunk {
    constructor(bytes) {
      this.b = bytes;
      this.v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      this.templates = new Map();
    }
    u8(o) { return this.b[o]; }
    u16(o) { return this.v.getUint16(o, true); }
    u32(o) { return this.v.getUint32(o, true); }
    str16(o, chars) { return utf16.decode(this.b.subarray(o, o + 2 * chars)); }

    nameAt(off) {
      return this.str16(off + 8, this.u16(off + 6));
    }
    readName(pos) {
      const off = this.u32(pos);
      pos += 4;
      if (off === pos) {
        const n = this.u16(off + 6);
        return [this.nameAt(off), off + 8 + 2 * n + 2];
      }
      return [this.nameAt(off), pos];
    }

    value(vtype, o, size) {
      const base = vtype & 0x7f;
      if (size === 0 && vtype !== 0x01) return null;
      const v = this.v;
      if (vtype & 0x80) {
        if (base === 0x01) {
          const items = utf16.decode(this.b.subarray(o, o + size)).split("\u0000");
          if (items.length && items[items.length - 1] === "") items.pop();
          return items;
        }
        const width = { 3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 15: 16, 17: 8, 20: 4, 21: 8 }[base];
        if (width) {
          const out = [];
          for (let i = 0; i + width <= size; i += width) out.push(this.value(base, o + i, width));
          return out;
        }
        return hex(this.b.subarray(o, o + size), true);
      }
      switch (base) {
        case 0x00: return null;
        case 0x01: return utf16.decode(this.b.subarray(o, o + size)).replace(/\u0000+$/, "");
        case 0x02: return latin1.decode(this.b.subarray(o, o + size)).replace(/\u0000+$/, "");
        case 0x03: return v.getInt8(o);
        case 0x04: return v.getUint8(o);
        case 0x05: return v.getInt16(o, true);
        case 0x06: return v.getUint16(o, true);
        case 0x07: return v.getInt32(o, true);
        case 0x08: return v.getUint32(o, true);
        case 0x09: return v.getBigInt64(o, true).toString();
        case 0x0a: return v.getBigUint64(o, true).toString();
        case 0x0b: return v.getFloat32(o, true);
        case 0x0c: return v.getFloat64(o, true);
        case 0x0d: return v.getUint32(o, true) !== 0;
        case 0x0e: return hex(this.b.subarray(o, o + size), true);
        case 0x0f: {
          const b = this.b.subarray(o, o + 16);
          const p = (arr) => hex(arr, false);
          const d1 = p([b[3], b[2], b[1], b[0]]);
          const d2 = p([b[5], b[4]]);
          const d3 = p([b[7], b[6]]);
          return `{${d1}-${d2}-${d3}-${p(b.subarray(8, 10))}-${p(b.subarray(10, 16))}}`;
        }
        case 0x10: return "0x" + (size === 8 ? v.getBigUint64(o, true).toString(16) : v.getUint32(o, true).toString(16));
        case 0x11: return filetimeToIso(v.getUint32(o, true), v.getUint32(o + 4, true));
        case 0x12: {
          const f = (i) => v.getUint16(o + 2 * i, true);
          const pad = (n, w) => String(n).padStart(w, "0");
          return `${pad(f(0), 4)}-${pad(f(1), 2)}-${pad(f(3), 2)}T${pad(f(4), 2)}:${pad(f(5), 2)}:${pad(f(6), 2)}.${pad(f(7), 3)}Z`;
        }
        case 0x13: {
          const rev = this.b[o];
          const count = this.b[o + 1];
          let auth = 0;
          for (let i = 2; i < 8; i++) auth = auth * 256 + this.b[o + i];
          let s = `S-${rev}-${auth}`;
          for (let i = 0; i < count && 8 + 4 * i + 4 <= size; i++) s += "-" + v.getUint32(o + 8 + 4 * i, true);
          return s;
        }
        case 0x14: return "0x" + v.getUint32(o, true).toString(16);
        case 0x15: return "0x" + v.getBigUint64(o, true).toString(16);
        case 0x21: return this.fragment(o, o + size)[0];
        default: return hex(this.b.subarray(o, o + size), true);
      }
    }

    fragment(pos, end) {
      const stack = [node("#root")];
      while (pos < end) {
        const tok = this.u8(pos);
        const t = [0x0c, 0x0d, 0x0e, 0x0f].includes(tok) ? tok : tok & 0x0f;
        if (tok === 0x00) { pos += 1; break; }
        if (tok === 0x0f) { pos += 4; continue; }
        const top = stack[stack.length - 1];
        if (t === 0x01) {
          pos += 1 + 2 + 4;
          let name;
          [name, pos] = this.readName(pos);
          const el = node(name);
          if (tok & 0x40) {
            pos += 4;
            while (pos < end && (this.u8(pos) & 0x0f) === 0x06) {
              let aname;
              [aname, pos] = this.readName(pos + 1);
              let val;
              [val, pos] = this.attrValue(pos);
              el.attrs[aname] = val;
            }
          }
          top.children.push(el);
          stack.push(el);
          continue;
        }
        if (t === 0x02) { pos += 1; continue; }
        if (t === 0x03 || t === 0x04) { pos += 1; if (stack.length > 1) stack.pop(); continue; }
        if (t === 0x05) {
          const vtype = this.u8(pos + 1);
          if (vtype !== 0x01) throw new Error("unsupported inline value type " + vtype);
          const n = this.u16(pos + 2);
          top.children.push(this.str16(pos + 4, n));
          pos += 4 + 2 * n;
          continue;
        }
        if (t === 0x07) { const n = this.u16(pos + 1); top.children.push(this.str16(pos + 3, n)); pos += 3 + 2 * n; continue; }
        if (t === 0x08) { top.children.push(String.fromCharCode(this.u16(pos + 1))); pos += 3; continue; }
        if (t === 0x09) { let nm; [nm, pos] = this.readName(pos + 1); top.children.push(ENTITIES[nm] || ""); continue; }
        if (t === 0x0a) { [, pos] = this.readName(pos + 1); continue; }
        if (t === 0x0b) { const n = this.u16(pos + 1); pos += 3 + 2 * n; continue; }
        if (tok === 0x0c) { let items; [items, pos] = this.templateInstance(pos); top.children.push(...items); continue; }
        if (tok === 0x0d || tok === 0x0e) {
          top.children.push({ kind: "sub", index: this.u16(pos + 1), vtype: this.u8(pos + 3) });
          pos += 4;
          continue;
        }
        throw new Error("unknown BinXML token 0x" + tok.toString(16));
      }
      return [stack[0].children, pos];
    }

    attrValue(pos) {
      const tok = this.u8(pos);
      if (tok === 0x0d || tok === 0x0e) return [{ kind: "sub", index: this.u16(pos + 1), vtype: this.u8(pos + 3) }, pos + 4];
      if ((tok & 0x0f) === 0x05) {
        const vtype = this.u8(pos + 1);
        const n = this.u16(pos + 2);
        return [vtype === 0x01 ? this.str16(pos + 4, n) : null, pos + 4 + 2 * n];
      }
      if ((tok & 0x0f) === 0x08) return [String.fromCharCode(this.u16(pos + 1)), pos + 3];
      if ((tok & 0x0f) === 0x09) { const [nm, p] = this.readName(pos + 1); return [ENTITIES[nm] || "", p]; }
      return [null, pos];
    }

    templateInstance(pos) {
      pos += 2 + 4;
      const defOff = this.u32(pos);
      pos += 4;
      if (!this.templates.has(defOff)) {
        const size = this.u32(defOff + 20);
        this.templates.set(defOff, this.fragment(defOff + 24, defOff + 24 + size)[0]);
        if (defOff === pos) pos = defOff + 24 + size;
      } else if (defOff === pos) {
        pos = defOff + 24 + this.u32(defOff + 20);
      }
      const template = this.templates.get(defOff);
      const count = this.u32(pos);
      pos += 4;
      const descs = [];
      for (let i = 0; i < count; i++) { descs.push([this.u16(pos), this.u8(pos + 2)]); pos += 4; }
      const values = [];
      for (const [size, vtype] of descs) { values.push(size ? this.value(vtype, pos, size) : null); pos += size; }
      const out = [];
      for (const n of template) {
        const r = instantiate(n, values);
        if (Array.isArray(r) && r.length && r.every(isNode)) out.push(...r);
        else if (r !== null && r !== undefined) out.push(r);
      }
      return [out, pos];
    }
  }

  function instantiate(item, values) {
    if (isSub(item)) return item.index < values.length ? values[item.index] : null;
    if (!isNode(item)) return item;
    if (item.children.length === 1 && isSub(item.children[0])) {
      const sub = item.children[0];
      const v = sub.index < values.length ? values[sub.index] : null;
      if (Array.isArray(v) && v.length && !v.every(isNode) && (sub.vtype & 0x80)) {
        return v.map((x) => {
          const n = node(item.name);
          for (const [k, a] of Object.entries(item.attrs)) n.attrs[k] = isSub(a) ? asText(instantiate(a, values)) : a;
          n.children.push(x);
          return n;
        });
      }
    }
    const n = node(item.name);
    for (const [k, a] of Object.entries(item.attrs)) n.attrs[k] = isSub(a) ? asText(instantiate(a, values)) : a;
    for (const c of item.children) {
      const r = instantiate(c, values);
      if (r === null || r === undefined) continue;
      if (Array.isArray(r) && r.length && r.every(isNode)) n.children.push(...r);
      else n.children.push(r);
    }
    return n;
  }

  function find(n, name) {
    return n.children.find((c) => isNode(c) && c.name === name) || null;
  }

  function flatten(n, data, prefix) {
    let unnamed = 0;
    for (const c of n.children) {
      if (!isNode(c)) continue;
      if (c.name === "Data") {
        const nm = asText(c.attrs.Name);
        const key = nm || `Data_${unnamed++}`;
        data[key] = asText(c);
      } else if (c.children.some(isNode)) {
        flatten(c, data, c.name + ".");
      } else {
        data[prefix + c.name] = asText(c);
      }
    }
  }

  function toEvent(recordId, ts, ev) {
    const out = { EventRecordID: recordId, TimeCreated: ts, Data: {} };
    if (!ev) return out;
    const system = find(ev, "System");
    if (system) {
      for (const el of system.children.filter(isNode)) {
        if (el.name === "EventID") out.EventId = parseInt(asText(el), 10) || 0;
        else if (el.name === "Provider") out.Provider = asText(el.attrs.Name || "");
        else if (el.name === "Computer") out.Computer = asText(el);
        else if (el.name === "Channel") out.LogName = asText(el);
        else if (el.name === "TimeCreated" && el.attrs.SystemTime) out.TimeCreated = asText(el.attrs.SystemTime);
        else if (el.name === "EventRecordID") out.EventRecordID = parseInt(asText(el), 10) || recordId;
      }
    }
    const payload = find(ev, "EventData") || find(ev, "UserData");
    if (payload) flatten(payload, out.Data, "");
    return out;
  }

  /** Read every record of an .evtx file. `input` is an ArrayBuffer or Uint8Array. */
  function readEvtx(input, options) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    const max = (options && options.maxRecords) || Infinity;
    const magic = latin1.decode(bytes.subarray(0, 8));
    if (magic !== "ElfFile\u0000") throw new Error("Not an EVTX file (missing ElfFile signature).");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const headerBlock = view.getUint16(40, true) || 0x1000;
    const events = [];
    for (let off = headerBlock; off + CHUNK_SIZE <= bytes.length && events.length < max; off += CHUNK_SIZE) {
      const raw = bytes.subarray(off, off + CHUNK_SIZE);
      if (latin1.decode(raw.subarray(0, 8)) !== "ElfChnk\u0000") continue;
      const chunk = new Chunk(raw);
      const end = Math.min(chunk.u32(48) || CHUNK_SIZE, CHUNK_SIZE);
      let pos = 0x200;
      while (pos + 24 <= end && events.length < max) {
        if (chunk.u32(pos) !== 0x2a2a) break;
        const size = chunk.u32(pos + 4);
        if (size < 28 || pos + size > CHUNK_SIZE) break;
        const recId = Number(chunk.v.getBigUint64(pos + 8, true));
        const ts = filetimeToIso(chunk.u32(pos + 16), chunk.u32(pos + 20));
        let rootNode = null;
        try {
          const [items] = chunk.fragment(pos + 24, pos + size - 4);
          rootNode = items.find(isNode) || null;
        } catch (_err) {
          rootNode = null;
        }
        events.push(toEvent(recId, ts, rootNode));
        pos += size;
      }
    }
    return events;
  }

  return { readEvtx, filetimeToIso };
});
