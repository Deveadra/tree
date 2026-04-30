from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dupe_core import safe_mkdir, write_json_atomic

from core.ai.evidence_schema import EVIDENCE_SCHEMA_VERSION, validate_evidence_schema
from core.ai.prompt_security import sanitize_untrusted_text


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _feature(value: dict[str, Any], *, source_file: str, run_id: str, event_id: str, timestamp: str | None = None) -> dict[str, Any]:
    return {
        **value,
        "provenance": {
            "source_file": source_file,
            "run_id": run_id,
            "event_id": event_id,
            "timestamp": timestamp or _utc_now_iso(),
        },
    }


def build_normalized_evidence(
    *,
    run_id: str,
    event_id: str,
    disk_metrics_payload: dict[str, Any],
    top_dir_payload: dict[str, Any],
    top_ext_payload: dict[str, Any],
    process_io_payload: dict[str, Any],
    process_handles_payload: dict[str, Any],
    plugin_payload: dict[str, Any],
    policy_context_payload: dict[str, Any],
    user_notes: str | None = None,
    user_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ts = str(disk_metrics_payload.get("timestamp") or _utc_now_iso())
    evidence: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "run_id": run_id,
        "event_id": event_id,
        "generated_at": _utc_now_iso(),
        "space_audit_snapshot_features": [
            _feature({"metrics": disk_metrics_payload}, source_file="disk_metrics.json", run_id=run_id, event_id=event_id, timestamp=ts),
            _feature({"top_dir_deltas": top_dir_payload.get("rows", [])}, source_file="top_dir_deltas.json", run_id=run_id, event_id=event_id, timestamp=ts),
            _feature({"top_extension_deltas": top_ext_payload.get("rows", [])}, source_file="top_extension_deltas.json", run_id=run_id, event_id=event_id, timestamp=ts),
        ],
        "monitor_timeline_features": [
            _feature({"free_delta_bytes": int(disk_metrics_payload.get("free_delta_bytes", 0)), "free_bytes": int(disk_metrics_payload.get("free_bytes", 0)), "used_bytes": int(disk_metrics_payload.get("used_bytes", 0))}, source_file="disk_metrics.json", run_id=run_id, event_id=event_id, timestamp=ts),
            _feature({"process_io": process_io_payload}, source_file="process_io_snapshot.json", run_id=run_id, event_id=event_id, timestamp=ts),
            _feature({"process_file_handles": process_handles_payload}, source_file="process_file_handles.json", run_id=run_id, event_id=event_id, timestamp=ts),
            _feature({"collector_plugins": plugin_payload}, source_file="plugin_collectors.json", run_id=run_id, event_id=event_id, timestamp=ts),
        ],
        "protection_policy_state": [
            _feature({"policy": policy_context_payload}, source_file="policy_context.json", run_id=run_id, event_id=event_id, timestamp=ts),
        ],
        "user_notes_context": [
            _feature({"notes": sanitize_untrusted_text(user_notes), "context": user_context or {}}, source_file="user_context", run_id=run_id, event_id=event_id, timestamp=ts),
        ],
    }
    validate_evidence_schema(evidence)
    return evidence


def persist_normalized_evidence(case_or_run_dir: str | Path, evidence: dict[str, Any]) -> Path:
    validate_evidence_schema(evidence)
    out_dir = Path(case_or_run_dir)
    safe_mkdir(out_dir)
    out_path = out_dir / "ai_evidence.json"
    write_json_atomic(out_path, evidence)
    return out_path
