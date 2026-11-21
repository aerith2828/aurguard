"""Small JSON state: what was seen per package base on the last run."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "aurguard"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "aurguard"


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(path)


def remember(state: dict, reports) -> None:
    now = int(time.time())
    for r in reports:
        if r.error or r.aur_version is None:
            continue
        entry = state.setdefault(r.base, {})
        entry.update(aur_version=r.aur_version, maintainer=r.maintainer, last_modified=r.last_modified, checked_at=now)
        if r.new_rev:
            entry["rev"] = r.new_rev
        if r.findings:
            entry["last_findings"] = [f.as_dict() for f in r.findings]
        elif r.new_rev:
            entry.pop("last_findings", None)
