from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from dupe_core import (
    DupeGroup,
    FileRec,
    analyze_path_prefixes,
    append_prune_event,
    compile_excludes,
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


def scan_to_db(
    roots: list[Path],
    db_path: Path,
    excludes: set[str],
    follow_symlinks: bool = False,
    min_size: int = 1,
    compare_mode: bool = False,
    scan_error_log_path: Path | None = None,
) -> dict[str, Any]:
    if compare_mode and len(roots) >= 2:
        return scan_roots_to_db(
            db_path=db_path,
            roots=roots,
            excludes=excludes,
            follow_symlinks=follow_symlinks,
            min_size=min_size,
            scan_error_log_path=scan_error_log_path,
        )
    return scan_root_to_db(
        db_path=db_path,
        root=roots[0],
        excludes=excludes,
        follow_symlinks=follow_symlinks,
        min_size=min_size,
        scan_error_log_path=scan_error_log_path,
    )


def load_dupes(db_path: Path, compare_mode: bool = False) -> list[DupeGroup]:
    return find_dupes_from_db(db_path, compare_mode=compare_mode)


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


def plan_prune(groups: list[DupeGroup]) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    bytes_reclaimable = 0
    for g in groups:
        if len(g.files) < 2:
            continue
        keep = sorted(g.files, key=lambda f: (f.mtime, f.path), reverse=True)[0]
        for f in g.files:
            if f.path == keep.path:
                continue
            actions.append({"action": "recycle", "path": f.path, "keep": keep.path, "size": f.size})
            bytes_reclaimable += f.size
    return {
        "groups": len(groups),
        "actions": actions,
        "files_to_prune": len(actions),
        "bytes_reclaimable": bytes_reclaimable,
        "dry_run_default": True,
    }


def apply_prune(plan: dict[str, Any], dry_run: bool = True, yes: bool = False, audit_log: Path | None = None) -> dict[str, Any]:
    if not dry_run and not yes:
        raise ValueError("Refusing destructive action without --yes")

    results = {"applied": 0, "skipped": 0, "errors": 0, "dry_run": dry_run}
    for a in plan.get("actions", []):
        p = Path(a["path"])
        if dry_run:
            results["skipped"] += 1
            continue
        ok = windows_recycle(p)
        if ok:
            results["applied"] += 1
            if audit_log:
                append_prune_event(audit_log, {"action": "recycle", "path": str(p), "status": "ok"})
        else:
            results["errors"] += 1
            if audit_log:
                append_prune_event(audit_log, {"action": "recycle", "path": str(p), "status": "error"})
    return results


def write_reports(report_dir: Path, groups: list[DupeGroup], scan_stats: dict[str, Any], excludes: set[str]) -> None:
    safe_mkdir(report_dir)
    write_scan_reports(report_dir=report_dir, dupes=groups, scan_stats=scan_stats, excludes=excludes)
    write_live_reports(report_dir=report_dir, dupes=groups, scan_stats=scan_stats)
    suggestions = analyze_path_prefixes(groups)
    write_path_suggestions(report_dir, suggestions)


def scan(request: ScanRequest) -> dict:
    return _scan(request)


def find_duplicates(
    db_path: Path,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    compare_mode: bool = False,
    error_log_path: Optional[Path] = None,
    required_roots: Optional[tuple[int, int]] = None,
) -> list[DuplicateResultGroup]:
    return _find_duplicates(
        db_path=db_path,
        cancel_flag=cancel_flag,
        metrics_cb=metrics_cb,
        compare_mode=compare_mode,
        error_log_path=error_log_path,
        required_roots=required_roots,
    )


__all__ = ["scan", "find_duplicates", "build_prune_plan", "execute_prune_plan"]
