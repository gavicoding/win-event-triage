"""Shared EN / PT-BR localization loader backed by WinEventTriage/locales JSON files."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


def _find_locales_dir() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "WinEventTriage" / "locales",
        Path.cwd() / "WinEventTriage" / "locales",
    ]
    for cand in candidates:
        if cand.is_dir():
            return cand
    raise FileNotFoundError("Could not locate WinEventTriage/locales directory")


@lru_cache(maxsize=4)
def load_locale(lang: str) -> dict[str, Any]:
    """Load locale dictionary cleanly from single source of truth JSON."""
    filename = "pt-BR.json" if lang == "pt" else "en.json"
    path = _find_locales_dir() / filename
    return json.loads(path.read_text(encoding="utf-8"))


def t_ui(lang: str, key: str) -> str:
    data = load_locale(lang)
    return str(data.get("ui", {}).get(key, key))


def t_rule(lang: str, rule_id: str) -> dict[str, str]:
    data = load_locale(lang)
    entry = data.get("rules", {}).get(rule_id)
    if entry:
        return {k: str(v) for k, v in entry.items()}
    return {"title": rule_id, "description": "", "remediation": ""}
