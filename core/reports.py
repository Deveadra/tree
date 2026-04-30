from __future__ import annotations

from pathlib import Path
from typing import Any

from dupe_core import append_prune_event, safe_mkdir, write_json_atomic, write_live_reports, write_path_suggestions, write_scan_reports

SCHEMA_VERSION = "1.0"


def write_versioned_meta(path: Path, data: dict[str, Any]) -> None:
    payload = dict(data)
    payload.setdefault("schema_version", SCHEMA_VERSION)
    write_json_atomic(path, payload)
