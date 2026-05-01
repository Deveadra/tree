from __future__ import annotations

import hashlib
import json
import os
import platform
import zipfile
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from core.actions import build_prune_plan, execute_prune_plan
from core.hash_index import find_duplicates as hash_find_duplicates
from core.models import DuplicateResultGroup, ScanRequest
from core.ai.policy_firewall import enforce_plan_compliance
from core.protection_policy import evaluate_delete_permission
from core.space_audit import sample_correlated_space_timeline, sample_free_space_timeline
from config.protection_loader import DEFAULT_TOML, resolve_protection_config
from dupe_core import (
    DupeGroup,
    analyze_path_prefixes,
    append_prune_event,
    find_dupes_from_db,
    format_bytes,
    safe_mkdir,
    scan_root_to_db,
    scan_roots_to_db,
    windows_recycle,
    write_live_reports,
    write_path_suggestions,
    write_scan_reports,
)

PRUNE_PLAN_SCHEMA_VERSION = "1.0"

ERROR_CODE_MAP = {
    "PLAN_MISSING_FIELD": "Prune plan is missing required fields.",
    "PLAN_SCHEMA_UNSUPPORTED": "Prune plan schema is not supported.",
    "PLAN_VERSION_UNSUPPORTED": "Prune plan version is not supported.",
    "PLAN_CHECKSUM_FAILED": "Prune plan integrity checksum failed verification.",
    "POLICY_BLOCKED": "Action was blocked by protection policy.",
    "CONFIRMATION_REQUIRED": "Destructive apply requires --no-dry-run and --yes.",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_json(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _file_snapshot(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "exists": True,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "hash": None,
    }


def _validate_plan_structure(plan: dict[str, Any]) -> None:
    for key in ("schema", "metadata", "actions", "plan_checksum"):
        if key not in plan:
            raise ValueError(f"PLAN_MISSING_FIELD: Missing required plan field: {key}")
    if plan["schema"] != "plan-prune":
        raise ValueError(f"PLAN_SCHEMA_UNSUPPORTED: Unsupported plan schema: {plan['schema']}")
    meta = plan.get("metadata", {})
    if meta.get("plan_version") != PRUNE_PLAN_SCHEMA_VERSION:
        raise ValueError(f"PLAN_VERSION_UNSUPPORTED: Unsupported plan version: {meta.get('plan_version')}")
    for required_meta in ("generated_at", "source_id", "policy_firewall"):
        if required_meta not in meta:
            raise ValueError(f"Missing required plan metadata field: {required_meta}")
    firewall = meta.get("policy_firewall")
    if not isinstance(firewall, dict):
        raise ValueError("Invalid policy firewall metadata")
    for firewall_key in ("violations", "rewritten"):
        if firewall_key not in firewall:
            raise ValueError(f"Missing required policy firewall field: {firewall_key}")


def _verify_plan_checksum(plan: dict[str, Any]) -> None:
    expected = plan.get("plan_checksum")
    unsigned = dict(plan)
    unsigned.pop("plan_checksum", None)
    actual = _sha256_json(unsigned)
    if not isinstance(expected, str) or expected != actual:
        raise ValueError("PLAN_CHECKSUM_FAILED: Plan checksum verification failed")


def _run_pre_execution_guards(
    *,
    plan: dict[str, Any],
    dry_run: bool,
    yes: bool,
    policy_cfg: Any,
    enforce_safe_delete_roots: bool,
    safe_delete_roots: list[Path] | None,
) -> None:
    # 1) policy check
    for action in plan.get("actions", []):
        path = action.get("path")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Missing action path metadata")
        action_mode = str(action.get("action", "delete"))
        if action_mode in {"recycle", "delete", "move"}:
            perm = evaluate_delete_permission(
                path,
                mode=action_mode,
                action_type="delete",
                safe_roots=safe_delete_roots if enforce_safe_delete_roots else None,
                policy=policy_cfg,
            )
            # Fail closed on uncertain policy decisions.
            if "allow" not in perm or not isinstance(perm.get("allow"), bool):
                raise ValueError(f"Uncertain policy decision for {path}")

    # 2) plan integrity check
    _validate_plan_structure(plan)
    _verify_plan_checksum(plan)

    # 3) confirmation check
    if not dry_run and not yes:
        raise ValueError("CONFIRMATION_REQUIRED: Refusing destructive action without --yes")


def generate_diagnostic_bundle(
    report_dir: Path,
    output_zip: Path,
    include_patterns: list[str] | None = None,
    telemetry_opt_in: bool = False,
) -> dict[str, Any]:
    report_dir.mkdir(parents=True, exist_ok=True)
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    patterns = include_patterns or ["*.json", "*.jsonl", "*.txt", "*.csv", "*.log"]
    included: list[str] = []

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for pattern in patterns:
            for p in sorted(report_dir.glob(pattern)):
                if p.is_file():
                    arcname = p.relative_to(report_dir)
                    zf.write(p, arcname=str(arcname))
                    included.append(str(arcname))

        manifest = {
            "generated_at": _utc_now_iso(),
            "report_dir": str(report_dir),
            "telemetry_opt_in": telemetry_opt_in,
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "error_codes": ERROR_CODE_MAP,
            "included_files": included,
        }
        if telemetry_opt_in:
            manifest["telemetry"] = {
                "session_id": os.environ.get("TREE_SESSION_ID", "unset"),
                "debug_mode": os.environ.get("TREE_DEBUG_MODE", "0"),
            }
        zf.writestr("diagnostic_manifest.json", json.dumps(manifest, indent=2))

    return {
        "bundle": str(output_zip),
        "file_count": len(included),
        "telemetry_opt_in": telemetry_opt_in,
    }


def scan_to_db(
    roots: list[Path],
    db_path: Path,
    excludes: set[str],
    follow_symlinks: bool = False,
    min_size: int = 1,
    compare_mode: bool = False,
    scan_error_log_path: Path | None = None,
    checkpoint_path: Path | None = None,
) -> dict[str, Any]:
    def _never_cancel() -> bool:
        return False

    def _ignore_metrics(_: dict) -> None:
        return None

    if compare_mode and len(roots) >= 2:
        return scan_roots_to_db(
            db_path=db_path,
            roots=roots,
            excludes=excludes,
            follow_symlinks=follow_symlinks,
            min_size=min_size,
            cancel_flag=lambda: False,
            metrics_cb=lambda _m: None,
            scan_error_log_path=scan_error_log_path,
            checkpoint_path=checkpoint_path,
        )
    return scan_root_to_db(
        db_path=db_path,
        root=roots[0],
        excludes=excludes,
        follow_symlinks=follow_symlinks,
        min_size=min_size,
        cancel_flag=lambda: False,
        metrics_cb=lambda _m: None,
        scan_error_log_path=scan_error_log_path,
        checkpoint_path=checkpoint_path,
    )


def load_dupes(db_path: Path, compare_mode: bool = False) -> list[DupeGroup]:
    required_roots = (0, 1) if compare_mode else None
    return find_dupes_from_db(
        db_path=db_path,
        cancel_flag=lambda: False,
        metrics_cb=lambda _m: None,
        required_roots=required_roots,
    )


def run_free_space_watchdog(
    root: Path,
    report_dir: Path,
    interval_seconds: float,
    duration_seconds: float | None,
    max_rows: int | None,
    spike_threshold_bytes: int | None,
    enable_local_notifications: bool = False,
    alerts_feed_path: Path | None = None,
    hash_usernames: bool = False,
    hash_filenames: bool = False,
    hash_process_arguments: bool = False,
    local_only_mode: bool = False,
    cancel_flag: Any | None = None,
) -> dict[str, Any]:
    report_dir.mkdir(parents=True, exist_ok=True)
    return sample_free_space_timeline(
        root=root,
        output_csv=report_dir / "free_space_timeline.csv",
        interval_seconds=interval_seconds,
        duration_seconds=duration_seconds,
        max_rows=max_rows,
        free_space_drop_spike_threshold_bytes=spike_threshold_bytes,
        enable_local_notifications=enable_local_notifications,
        alerts_feed_path=alerts_feed_path,
        hash_usernames=hash_usernames,
        hash_filenames=hash_filenames,
        hash_process_arguments=hash_process_arguments,
        local_only_mode=local_only_mode,
        cancel_flag=cancel_flag,
    )


def run_correlated_space_watchdog(
    root: Path,
    report_dir: Path,
    fast_interval_seconds: float,
    growth_interval_seconds: float,
    duration_seconds: float | None,
    max_fast_rows: int | None,
    max_growth_rows: int | None,
    cancel_flag: Any | None = None,
) -> dict[str, Any]:
    report_dir.mkdir(parents=True, exist_ok=True)
    return sample_correlated_space_timeline(
        root=root,
        output_fast_csv=report_dir / "free_space_timeline_fast.csv",
        output_growth_csv=report_dir / "space_growth_timeline.csv",
        fast_interval_seconds=fast_interval_seconds,
        growth_interval_seconds=growth_interval_seconds,
        duration_seconds=duration_seconds,
        max_fast_rows=max_fast_rows,
        max_growth_rows=max_growth_rows,
        cancel_flag=cancel_flag,
    )


def serialize_dupes(groups: list[DupeGroup]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for g in groups:
        out.append(
            {
                "sha256": g.sha256,
                "size": g.size,
                "size_human": format_bytes(g.size),
                "count": len(g.files),
                "files": [asdict(f) for f in g.files],
            }
        )
    return out


def plan_prune(
    groups: list[DupeGroup],
    source_id: str = "unknown",
    enforce_safe_delete_roots: bool = False,
    safe_delete_roots: list[Path] | None = None,
    policy_path: Path | None = None,
) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    bytes_reclaimable = 0
    for g in groups:
        if len(g.files) < 2:
            continue
        keep = sorted(g.files, key=lambda f: (f.mtime, f.path), reverse=True)[0]
        for f in g.files:
            if f.path == keep.path:
                continue
            snapshot = _file_snapshot(Path(f.path)) if Path(f.path).exists() else {"exists": False, "size": None, "mtime": None, "hash": None}
            actions.append({
                "action": "recycle",
                "path": f.path,
                "keep": keep.path,
                "size": f.size,
                "snapshot": snapshot,
            })
            bytes_reclaimable += f.size

    policy_cfg = resolve_protection_config(policy_path or DEFAULT_TOML)
    policy_cfg = replace(policy_cfg, enforce_safe_delete_roots=enforce_safe_delete_roots)

    compliance = enforce_plan_compliance(
        actions,
        policy=policy_cfg,
        enforce_safe_delete_roots=enforce_safe_delete_roots,
        safe_delete_roots=safe_delete_roots,
    )

    planned_actions = compliance["safe_actions"] if enforce_safe_delete_roots else actions
    plan_actions = [*compliance["safe_actions"], *compliance["rewritten_actions"]]

    plan = {
        "schema": "plan-prune",
        "metadata": {
            "plan_version": PRUNE_PLAN_SCHEMA_VERSION,
            "generated_at": _utc_now_iso(),
            "source_id": source_id,
            "policy_firewall": {
                "violations": compliance["violations"],
                "rewritten": compliance["rewritten_actions"],
            },
        },
        "groups": len(groups),
        "actions": planned_actions,
        "files_to_prune": len(planned_actions),
        "bytes_reclaimable": sum(int(a.get("size", 0)) for a in planned_actions),
        "actions": plan_actions,
        "files_to_prune": len(compliance["safe_actions"]),
        "bytes_reclaimable": sum(int(a.get("size", 0)) for a in compliance["safe_actions"]),
        "dry_run_default": True,
    }
    plan["plan_checksum"] = _sha256_json(plan)
    return plan


def apply_prune(
    plan: dict[str, Any],
    dry_run: bool = True,
    yes: bool = False,
    audit_log: Path | None = None,
    enforce_safe_delete_roots: bool = False,
    safe_delete_roots: list[Path] | None = None,
    policy_path: Path | None = None,
) -> dict[str, Any]:
    policy_cfg = resolve_protection_config(policy_path or DEFAULT_TOML)
    policy_cfg = replace(policy_cfg, enforce_safe_delete_roots=enforce_safe_delete_roots)
    _run_pre_execution_guards(
        plan=plan,
        dry_run=dry_run,
        yes=yes,
        policy_cfg=policy_cfg,
        enforce_safe_delete_roots=enforce_safe_delete_roots,
        safe_delete_roots=safe_delete_roots,
    )

    results = {
        "applied": 0,
        "skipped": 0,
        "errors": 0,
        "blocked": 0,
        "blocked_reasons": {},
        "dry_run": dry_run,
    }
    blocked_paths_by_reason: dict[str, list[str]] = {}
    policy_rule_map = {
        "outside_safe_roots": "safe_delete_roots",
        "protected_prefix": "protected_prefixes",
        "protected_dir_name": "protected_dir_names",
        "unsafe_quarantine_config": "quarantine_requires_safe_roots",
        "invalid_path": "valid_path_required",
        "allowed": "allow_default",
    }

    def _audit_payload(base: dict[str, Any], *, decision: str, reason_code: str, matched_rule: str) -> dict[str, Any]:
        payload = dict(base)
        payload["policy_decision"] = decision
        payload["policy_reason_code"] = reason_code
        payload["matched_rule"] = matched_rule
        return payload

    for a in plan.get("actions", []):
        p = Path(a["path"])
        snapshot = a.get("snapshot", {})
        reason = None

        action_mode = str(a.get("action", "delete"))

        if action_mode == "skip":
            violations = a.get("violations") if isinstance(a.get("violations"), list) else []
            violation = violations[0] if violations and isinstance(violations[0], dict) else {}
            reason_code = str(violation.get("reason_code") or a.get("reason") or "policy_deny")
            results["skipped"] += 1
            results["blocked"] += 1
            blocked_reasons = results["blocked_reasons"]
            blocked_reasons[reason_code] = int(blocked_reasons.get(reason_code, 0)) + 1
            blocked_paths_by_reason.setdefault(reason_code, []).append(str(p))
            if audit_log:
                append_prune_event(
                    audit_log,
                    _audit_payload(
                        {
                            "action": a.get("action"),
                            "path": str(p),
                            "status": "skip",
                            "reason_code": reason_code,
                            "reason": str(violation.get("message") or "Blocked by policy firewall"),
                        },
                        decision="blocked",
                        reason_code=reason_code,
                        matched_rule=policy_rule_map.get(reason_code, "policy_default_deny"),
                    ),
                )
            continue

        if not p.exists():
            reason = "file_missing"
        elif snapshot.get("size") is not None and p.stat().st_size != snapshot.get("size"):
            reason = "size_changed"
        elif snapshot.get("mtime") is not None and int(p.stat().st_mtime) != snapshot.get("mtime"):
            reason = "mtime_changed"

        if reason:
            results["skipped"] += 1
            if audit_log:
                append_prune_event(
                    audit_log,
                    _audit_payload(
                        {"action": a.get("action"), "path": str(p), "status": "skip", "reason_code": reason},
                        decision="allowed",
                        reason_code="allowed",
                        matched_rule="allow_default",
                    ),
                )
            continue

        if dry_run:
            results["skipped"] += 1
            if audit_log:
                append_prune_event(
                    audit_log,
                    _audit_payload(
                        {"action": a.get("action"), "path": str(p), "status": "skip", "reason_code": "dry_run"},
                        decision="allowed",
                        reason_code="allowed",
                        matched_rule="allow_default",
                    ),
                )
            continue
        if action_mode in {"recycle", "delete", "move"}:
            perm = evaluate_delete_permission(
                str(p),
                mode=action_mode,
                action_type="delete",
                safe_roots=safe_delete_roots if enforce_safe_delete_roots else None,
                policy=policy_cfg,
            )
            if not bool(perm.get("allow")):
                reason_code = str(perm.get("reason_code", "policy_deny"))
                reason = str(perm.get("reason", "Blocked by protection policy"))
                results["skipped"] += 1
                results["blocked"] += 1
                blocked_reasons = results["blocked_reasons"]
                blocked_reasons[reason_code] = int(blocked_reasons.get(reason_code, 0)) + 1
                blocked_paths_by_reason.setdefault(reason_code, []).append(str(p))
                if audit_log:
                    append_prune_event(
                        audit_log,
                        _audit_payload(
                            {
                                "action": a.get("action"),
                                "path": str(p),
                                "status": "skip",
                                "reason_code": reason_code,
                                "reason": reason,
                            },
                            decision="blocked",
                            reason_code=reason_code,
                            matched_rule=policy_rule_map.get(reason_code, "policy_default_deny"),
                        ),
                    )
                continue

        ok = windows_recycle(p)
        if ok:
            results["applied"] += 1
            if audit_log:
                append_prune_event(
                    audit_log,
                    _audit_payload(
                        {"action": "recycle", "path": str(p), "status": "success", "reason_code": "recycled"},
                        decision="allowed",
                        reason_code="allowed",
                        matched_rule="allow_default",
                    ),
                )
        else:
            results["errors"] += 1
            if audit_log:
                append_prune_event(
                    audit_log,
                    _audit_payload(
                        {"action": "recycle", "path": str(p), "status": "error", "reason_code": "recycle_failed"},
                        decision="allowed",
                        reason_code="allowed",
                        matched_rule="allow_default",
                    ),
                )

    if audit_log:
        safe_mkdir(audit_log)
        report_payload = {
            "blocked_total": results["blocked"],
            "blocked_by_reason": results["blocked_reasons"],
            "blocked_paths_by_reason": blocked_paths_by_reason,
            "generated_at": _utc_now_iso(),
        }
        (audit_log / "policy_block_report.json").write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        summary_lines = [
            "Policy summary",
            f"- blocked_total: {results['blocked']}",
        ]
        for reason_code, count in sorted(results["blocked_reasons"].items()):
            summary_lines.append(f"- {reason_code}: {count}")
        (audit_log / "prune_summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return results

# rest unchanged

def write_reports(report_dir: Path, groups: list[DupeGroup], scan_stats: dict[str, Any], excludes: set[str]) -> None:
    safe_mkdir(report_dir)
    write_scan_reports(report_dir=report_dir, dupes=groups)
    write_live_reports(report_dir=report_dir, dupes=groups)
    suggestions = analyze_path_prefixes(groups)
    write_path_suggestions(report_dir, suggestions)


def scan(request: ScanRequest) -> dict[str, Any]:
    return scan_to_db(
        roots=request.roots,
        db_path=request.db_path,
        excludes=request.excludes,
        follow_symlinks=request.follow_symlinks,
        min_size=request.min_size,
        scan_error_log_path=request.scan_error_log_path,
    )


def find_duplicates(
    db_path: Path,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    compare_mode: bool = False,
    error_log_path: Optional[Path] = None,
    required_roots: Optional[tuple[int, int]] = None,
) -> list[DuplicateResultGroup]:
    # compare_mode is kept for backward-compatible facade calls, but
    # duplicate filtering is handled via required_roots.
    _ = compare_mode
    return hash_find_duplicates(
        db_path=db_path,
        cancel_flag=cancel_flag,
        metrics_cb=metrics_cb,
        error_log_path=error_log_path,
        required_roots=required_roots,
    )


__all__ = [
    "scan_to_db",
    "load_dupes",
    "serialize_dupes",
    "plan_prune",
    "apply_prune",
    "write_reports",
    "scan",
    "find_duplicates",
    "build_prune_plan",
    "execute_prune_plan",
]
