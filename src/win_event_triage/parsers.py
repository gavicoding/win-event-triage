"""Parsers for JSON snapshots and native Windows Event Viewer XML exports."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .models import NormalizedEvent


def parse_events_file(path: Path) -> list[NormalizedEvent]:
    """Load events from a JSON snapshot or native Windows Event Viewer XML file."""
    raw = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    if path.suffix.lower() == ".xml" or raw.lstrip().startswith("<"):
        return parse_eventviewer_xml(raw)
    return parse_json_snapshot(raw)


def parse_json_snapshot(raw: str) -> list[NormalizedEvent]:
    """Parse JSON array or Export-WinEventSnapshot object."""
    payload = json.loads(raw)
    items: list[dict[str, Any]]
    if isinstance(payload, list):
        items = [x for x in payload if isinstance(x, dict)]
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        items = [x for x in payload["events"] if isinstance(x, dict)]
    else:
        items = []

    result: list[NormalizedEvent] = []
    for item in items:
        ev_id = int(item.get("EventId") or item.get("event_id") or 0)
        ts = str(item.get("TimeCreated") or item.get("time_created") or "")
        comp = str(item.get("Computer") or item.get("computer") or "unknown-host")
        prov = str(item.get("Provider") or item.get("provider") or "")
        log_name = str(item.get("LogName") or item.get("log_name") or "")
        msg = str(item.get("Message") or item.get("message") or "")
        data = item.get("Data") if isinstance(item.get("Data"), dict) else {}
        result.append(
            NormalizedEvent(
                event_id=ev_id,
                time_created=ts,
                computer=comp,
                provider=prov,
                log_name=log_name,
                message=msg,
                data={str(k): v for k, v in data.items()},
            )
        )
    return result


def parse_eventviewer_xml(raw: str) -> list[NormalizedEvent]:
    """Parse native Windows Event Viewer XML (<Events><Event>...</Event></Events>)."""
    root = ET.fromstring(raw)
    events: list[NormalizedEvent] = []

    def _strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    event_elems = [elem for elem in root.iter() if _strip_ns(elem.tag) == "Event"]
    for ev_el in event_elems:
        sys_el = next((c for c in ev_el if _strip_ns(c.tag) == "System"), None)
        if sys_el is None:
            continue

        ev_id = 0
        ts = ""
        computer = "unknown-host"
        provider = ""
        log_name = ""

        for child in sys_el:
            cname = _strip_ns(child.tag)
            if cname == "EventID" and (child.text or "").strip().isdigit():
                ev_id = int(child.text.strip())
            elif cname == "TimeCreated":
                ts = child.attrib.get("SystemTime", "")
            elif cname == "Computer":
                computer = (child.text or "").strip() or "unknown-host"
            elif cname == "Provider":
                provider = child.attrib.get("Name", "")
            elif cname == "Channel":
                log_name = (child.text or "").strip()

        data_map: dict[str, Any] = {}
        ev_data = next((c for c in ev_el if _strip_ns(c.tag) == "EventData"), None)
        if ev_data is not None:
            for idx, d in enumerate(ev_data):
                if _strip_ns(d.tag) == "Data":
                    key = d.attrib.get("Name") or f"Data_{idx}"
                    data_map[key] = d.text or ""

        msg = ""
        rendering = next((c for c in ev_el if _strip_ns(c.tag) == "RenderingInfo"), None)
        if rendering is not None:
            msg_el = next((c for c in rendering if _strip_ns(c.tag) == "Message"), None)
            if msg_el is not None and msg_el.text:
                msg = msg_el.text.strip()

        events.append(
            NormalizedEvent(
                event_id=ev_id,
                time_created=ts,
                computer=computer,
                provider=provider,
                log_name=log_name,
                message=msg,
                data=data_map,
            )
        )
    return events
