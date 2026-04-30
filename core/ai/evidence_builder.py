from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
from pathlib import Path
from typing import Any

from dupe_core import safe_mkdir, write_json_atomic

from core.ai.evidence_schema import EVIDENCE_SCHEMA_VERSION, validate_evidence_schema
from core.ai.prompt_security import sanitize_untrusted_text


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()




DEFAULT_REDACTION_POLICY = {
    "usernames": "hash",
    "hostnames": "hash",
    "process_args": "mask",
    "path_segments": "partial",
}


def _redaction_policy(overrides: dict[str, str] | None = None) -> dict[str, str]:
    policy = dict(DEFAULT_REDACTION_POLICY)
    if isinstance(overrides, dict):
        for key in DEFAULT_REDACTION_POLICY:
            if key in overrides and overrides[key]:
                policy[key] = str(overrides[key])
    return policy


def _build_export_tiers(evidence: dict[str, Any], policy: dict[str, str]) -> dict[str, Any]:
    full_payload = deepcopy(evidence)
    share_safe = deepcopy(evidence)
    share_safe["export_tier"] = "share_safe_redacted"
    share_safe["report_redaction_level"] = "share_safe"
    share_safe["redaction_policy"] = policy
    full_payload["report_redaction_level"] = "full"
    return {
        "full_forensic_report": {"export_tier": "full_forensic_report", "payload": full_payload},
        "share_safe_redacted_report": {"export_tier": "share_safe_redacted", "payload": share_safe},
    }

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
    redaction_policy: dict[str, str] | None = None,
    consent_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ts = str(disk_metrics_payload.get("timestamp") or _utc_now_iso())
    policy = _redaction_policy(redaction_policy)
    evidence: dict[str, Any] = {
        "report_redaction_level": "full",
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "run_id": run_id,
        "event_id": event_id,
        "generated_at": _utc_now_iso(),
        "redaction_policy": policy,
        "export_tiers": {},
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
        "external_model_provider_usage": [
            _feature({"consent_state": consent_state or {"provider_enabled": False, "consent_captured": False}}, source_file="model_provider_state.json", run_id=run_id, event_id=event_id, timestamp=ts),
        ],
    }
    evidence["export_tiers"] = _build_export_tiers(evidence, policy)
    evidence["report_redaction_level"] = "full"
    validate_evidence_schema(evidence)
    return evidence


def build_evidence_from_space_outputs(
    *,
    run_id: str,
    event_id: str,
    space_audit_output: dict[str, Any],
    space_watch_output: dict[str, Any],
    policy_context_payload: dict[str, Any],
) -> dict[str, Any]:
    disk_metrics = dict(space_watch_output.get("disk_metrics", {}))
    if not disk_metrics:
        volume = space_audit_output.get("volume", {}) if isinstance(space_audit_output, dict) else {}
        disk_metrics = {
            "timestamp": _utc_now_iso(),
            "free_bytes": int(volume.get("free_bytes", 0)),
            "used_bytes": int(volume.get("used_bytes", 0)),
            "free_delta_bytes": int(space_watch_output.get("free_delta_bytes", 0)),
        }
    return build_normalized_evidence(
        run_id=run_id,
        event_id=event_id,
        disk_metrics_payload=disk_metrics,
        top_dir_payload={"rows": list(space_audit_output.get("top_dirs", []))},
        top_ext_payload={"rows": list(space_audit_output.get("top_extensions", []))},
        process_io_payload=dict(space_watch_output.get("process_io", {})),
        process_handles_payload=dict(space_watch_output.get("process_handles", {})),
        plugin_payload=dict(space_watch_output.get("plugins", {})),
        policy_context_payload=policy_context_payload,
        user_notes=str(space_watch_output.get("operator_notes", "")),
        user_context={"space_watch_event": event_id},
        consent_state=dict(space_watch_output.get("consent_state", {})),
    )


def persist_normalized_evidence(case_or_run_dir: str | Path, evidence: dict[str, Any]) -> Path:
    validate_evidence_schema(evidence)
    out_dir = Path(case_or_run_dir)
    safe_mkdir(out_dir)
    out_path = out_dir / "ai_evidence.json"
    write_json_atomic(out_path, evidence)
    return out_path


def export_ai_case_outputs(case_or_run_dir: str | Path, report_payload: dict[str, Any], findings_lines: list[str]) -> tuple[Path, Path]:
    out_dir = Path(case_or_run_dir)
    safe_mkdir(out_dir)
    case_report = out_dir / "ai_case_report.json"
    findings_txt = out_dir / "ai_findings.txt"
    write_json_atomic(case_report, report_payload)
    findings_txt.write_text("\n".join(findings_lines).strip() + "\n", encoding="utf-8")
    return case_report, findings_txt
