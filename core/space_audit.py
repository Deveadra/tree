from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import json
import errno
import os
import time
import tempfile

from config.protection_loader import DEFAULT_TOML, ProtectionConfig, resolve_protection_config
from core.protection_policy import contains_protected_dir_name, is_under_protected_prefix

from dupe_core import safe_mkdir, write_json_atomic
from core.space_categories import classify_path

SCHEMA_VERSION = "1.1"

ErrorCallback = Callable[[dict[str, Any]], None]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_excluded(path: Path, root: Path, excludes: set[str]) -> bool:
    if not excludes:
        return False
    rel = str(path.relative_to(root)).replace("\\", "/").lower()
    name = path.name.lower()
    for item in excludes:
        rule = item.strip().replace("\\", "/").strip("/").lower()
        if not rule:
            continue
        if name == rule or rel == rule or rel.startswith(rule + "/"):
            return True
    return False


def _extension_for(path: Path) -> str:
    ext = path.suffix.lower()
    return ext if ext else "[no_ext]"


def _is_protected(path: Path, policy: ProtectionConfig) -> tuple[bool, str | None, str | None]:
    pref = is_under_protected_prefix(str(path), protected_prefixes=policy.protected_prefixes)
    if pref:
        return True, "protected_prefix", pref
    name = contains_protected_dir_name(str(path), protected_dir_names=policy.protected_dir_names)
    if name:
        return True, "protected_dir_name", str(name)
    return False, None, None


def scan_space_usage(
    root: str | Path,
    excludes: list[str] | set[str],
    depth: int = 4,
    policy: Callable[[Path, os.stat_result], bool] | None = None,
    cancel_flag: Any | None = None,
    metrics_cb: Callable[[dict[str, Any]], None] | None = None,
    policy_path: str | Path | None = None,
    audit_mode: bool = True,
) -> dict[str, Any]:
    """Read-only filesystem scan that records file usage by tree node and extension."""
    root_path = Path(root).expanduser().resolve()
    exclude_set = {str(item) for item in excludes}
    start = _utc_now_iso()
    protection_cfg = resolve_protection_config(Path(policy_path) if policy_path else DEFAULT_TOML)

    volume_total = 0
    volume_free = 0
    volume_used = 0
    volume_info_confidence = "none"
    volume_info_caveats: list[str] = []
    size_modes = {
        "apparent": {
            "enabled": True,
            "description": "Logical file size from st_size.",
            "fallback_behavior": "Always available when file metadata can be read.",
            "confidence": "high",
        },
        "allocated": {
            "enabled": True,
            "description": "Allocated size from st_blocks*512 when the platform exposes st_blocks.",
            "fallback_behavior": "Falls back to apparent size when st_blocks is unavailable.",
            "confidence": "partial",
        },
    }

    try:
        statvfs = os.statvfs(root_path)
        volume_total = int(statvfs.f_blocks * statvfs.f_frsize)
        volume_free = int(statvfs.f_bavail * statvfs.f_frsize)
        volume_used = max(0, int(volume_total - volume_free))
        volume_info_confidence = "high"
    except OSError as exc:
        volume_info_caveats.append(f"volume stats unavailable: {exc}")
    except AttributeError:
        volume_info_caveats.append("volume stats unavailable on this platform")

    dir_totals: Counter[str] = Counter()
    dir_totals_allocated: Counter[str] = Counter()
    ext_totals: Counter[str] = Counter()
    ext_totals_allocated: Counter[str] = Counter()
    category_totals: Counter[str] = Counter()
    categorized_items: list[dict[str, Any]] = []
    file_count = 0
    skipped_count = 0
    skipped_protected: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []

    def record_error(path: str, exc: BaseException) -> None:
        code = getattr(exc, "errno", None)
        errors.append(
            {
                "path": path,
                "error": type(exc).__name__,
                "errno": code,
                "message": str(exc),
            }
        )

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break

        current_dir = Path(dirpath)
        pruned_dirnames: list[str] = []
        for d in dirnames:
            candidate = current_dir / d
            if _is_excluded(candidate, root_path, exclude_set):
                continue
            is_protected, reason_code, reason_detail = _is_protected(candidate, protection_cfg)
            if is_protected:
                skipped_count += 1
                skipped_protected.append(
                    {"path": str(candidate), "reason_code": str(reason_code), "reason": str(reason_detail)}
                )
                continue
            pruned_dirnames.append(d)
        dirnames[:] = pruned_dirnames
        if _is_excluded(current_dir, root_path, exclude_set):
            continue

        current_is_protected, reason_code, reason_detail = _is_protected(current_dir, protection_cfg)
        if current_is_protected:
            skipped_count += 1
            skipped_protected.append(
                {"path": str(current_dir), "reason_code": str(reason_code), "reason": str(reason_detail)}
            )
            continue

        for filename in filenames:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break

            file_path = current_dir / filename
            if _is_excluded(file_path, root_path, exclude_set):
                skipped_count += 1
                continue
            file_is_protected, reason_code, reason_detail = _is_protected(file_path, protection_cfg)
            if file_is_protected:
                skipped_count += 1
                skipped_protected.append(
                    {"path": str(file_path), "reason_code": str(reason_code), "reason": str(reason_detail)}
                )
                continue

            try:
                st = file_path.stat(follow_symlinks=False)
                if not os.path.isfile(file_path):
                    continue
                if policy and not policy(file_path, st):
                    skipped_count += 1
                    continue
                size = int(st.st_size)
                allocated = size
                if hasattr(st, "st_blocks"):
                    allocated = int(st.st_blocks) * 512
                else:
                    size_modes["allocated"]["confidence"] = "low"
                    size_modes["allocated"]["fallback_behavior"] = "Platform does not expose st_blocks; allocated size equals apparent size."
            except OSError as exc:
                if getattr(exc, "errno", None) in {errno.EACCES, errno.EPERM, errno.ENOENT, errno.EBUSY, errno.EIO}:
                    record_error(str(file_path), exc)
                    continue
                record_error(str(file_path), exc)
                continue

            file_count += 1
            rel_parts = file_path.relative_to(root_path).parts
            max_depth = min(depth, len(rel_parts) - 1)
            dir_totals["."] += size
            dir_totals_allocated["."] += allocated
            for d in range(1, max_depth + 1):
                key = "/".join(rel_parts[:d])
                dir_totals[key] += size
                dir_totals_allocated[key] += allocated
            ext = _extension_for(file_path)
            ext_totals[ext] += size
            ext_totals_allocated[ext] += allocated

            rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
            category_meta = classify_path(rel_path)
            category = str(category_meta["category"])
            category_totals[category] += size
            categorized_items.append({
                "path": rel_path,
                "bytes": size,
                "allocated_bytes": allocated,
                "category": category,
                "matched_rule": category_meta["matched_rule"],
                "confidence": float(category_meta["confidence"]),
            })

            if metrics_cb is not None and file_count % 500 == 0:
                metrics_cb(
                    {
                        "files_seen": file_count,
                        "dirs_tracked": len(dir_totals),
                        "extensions_tracked": len(ext_totals),
                        "errors": len(errors),
                    }
                )

    tree_total = int(dir_totals.get(".", 0))
    tree_total_allocated = int(dir_totals_allocated.get(".", 0))
    unattributed = int(volume_used - tree_total) if volume_total else 0
    reserved_or_system_managed_estimate = int(volume_used - tree_total_allocated) if volume_total else None

    categorized_total = int(sum(category_totals.values()))
    unknown_unattributed_bytes = max(0, tree_total - categorized_total)
    if unknown_unattributed_bytes:
        category_totals["system-managed / unattributed"] += unknown_unattributed_bytes
    if unattributed > 0:
        category_totals["system-managed / unattributed"] += int(unattributed)

    denominator = (tree_total + max(0, unattributed)) if (tree_total + max(0, unattributed)) > 0 else 1
    category_breakdown = [
        {
            "category": category,
            "bytes": int(total),
            "percent_of_tree": (float(total) / float(denominator)) * 100.0,
        }
        for category, total in sorted(category_totals.items(), key=lambda pair: pair[1], reverse=True)
    ]

    if not volume_total:
        volume_info_confidence = "none"
    elif not volume_info_caveats and size_modes["allocated"]["confidence"] == "partial":
        size_modes["allocated"]["confidence"] = "high"

    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "started_at": start,
            "finished_at": _utc_now_iso(),
            "root": str(root_path),
            "depth": depth,
            "cancelled": bool(cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)()),
            "audit_mode": bool(audit_mode),
        },
        "totals": {
            "volume_total_bytes": int(volume_total),
            "volume_free_bytes": int(volume_free),
            "volume_used_bytes": int(volume_used),
            "volume_bytes": int(volume_total),
            "tree_sum_bytes": tree_total,
            "tree_sum_allocated_bytes": tree_total_allocated,
            "tree_bytes": tree_total,
            "unattributed_bytes": unattributed,
            "reserved_or_system_managed_estimate": reserved_or_system_managed_estimate,
            "file_count": file_count,
            "skipped_count": skipped_count,
            "error_count": len(errors),
        },
        "size_modes": size_modes,
        "confidence": {
            "volume_metrics": volume_info_confidence,
            "unattributed_bytes": "high" if volume_total else "none",
            "reserved_or_system_managed_estimate": "partial" if reserved_or_system_managed_estimate is not None else "none",
        },
        "caveats": volume_info_caveats,
        "tree": {"dir_bytes": dict(dir_totals), "dir_allocated_bytes": dict(dir_totals_allocated)},
        "extensions": {"ext_bytes": dict(ext_totals), "ext_allocated_bytes": dict(ext_totals_allocated)},
        "categories": {"rows": category_breakdown, "items": categorized_items},
        "errors": errors,
        "protection": {
            "policy_path": str(Path(policy_path).resolve()) if policy_path else str(DEFAULT_TOML),
            "invariant": {
                "traversal": "strict",
                "recommendations": "advisory",
                "note": "Policy checks are advisory for recommendations, strict for traversal skip behavior as configured.",
            },
            "skipped_regions": skipped_protected,
        },
    }


def _sort_keys_stable(keys: set[str]) -> list[str]:
    return sorted(keys, key=lambda item: (item != ".", item))


def _safe_percent(delta: int, baseline: int) -> float | None:
    if baseline <= 0:
        return None
    return (float(delta) / float(baseline)) * 100.0


def _parse_iso_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_previous_snapshot(report_root: str | Path, current_report_dir: str | Path, scan_root: str | Path) -> dict[str, Any] | None:
    root = Path(report_root).resolve()
    current = Path(current_report_dir).resolve()
    scan_root_resolved = str(Path(scan_root).expanduser().resolve())

    candidates: list[tuple[datetime, Path, dict[str, Any]]] = []
    for snapshot_path in root.glob("**/space_snapshot.json"):
        snapshot_dir = snapshot_path.parent.resolve()
        if snapshot_dir == current:
            continue
        try:
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(data.get("run", {}).get("root", "")) != scan_root_resolved:
            continue
        finished_at = _parse_iso_datetime(data.get("run", {}).get("finished_at"))
        candidates.append((finished_at, snapshot_path, data))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (item[0], str(item[1])))
    return candidates[-1][2]


def summarize_top_dirs(snapshot: dict[str, Any], top_n: int = 100) -> list[dict[str, Any]]:
    dir_bytes = snapshot.get("tree", {}).get("dir_bytes", {})
    rows = sorted(dir_bytes.items(), key=lambda pair: pair[1], reverse=True)
    protected_paths = {item.get("path") for item in snapshot.get("protection", {}).get("skipped_regions", [])}
    out: list[dict[str, Any]] = []
    for path, total in rows[:top_n]:
        row = {"path": path, "bytes": int(total)}
        if path in protected_paths:
            row["warning"] = "Protected region: do not perform direct action without explicit override and validation."
        out.append(row)
    return out


def summarize_by_extension(snapshot: dict[str, Any], top_n: int = 100) -> list[dict[str, Any]]:
    ext_bytes = snapshot.get("extensions", {}).get("ext_bytes", {})
    rows = sorted(ext_bytes.items(), key=lambda pair: pair[1], reverse=True)
    return [{"extension": ext, "bytes": int(total)} for ext, total in rows[:top_n]]


def diff_space_snapshots(
    current_snapshot: dict[str, Any],
    previous_snapshot: dict[str, Any],
    noise_threshold_bytes: int = 0,
) -> dict[str, Any]:
    current_dirs = current_snapshot.get("tree", {}).get("dir_bytes", {})
    previous_dirs = previous_snapshot.get("tree", {}).get("dir_bytes", {})
    current_ext = current_snapshot.get("extensions", {}).get("ext_bytes", {})
    previous_ext = previous_snapshot.get("extensions", {}).get("ext_bytes", {})

    dir_keys = _sort_keys_stable(set(current_dirs) | set(previous_dirs))
    ext_keys = _sort_keys_stable(set(current_ext) | set(previous_ext))

    threshold = max(0, int(noise_threshold_bytes))
    dir_rows: list[dict[str, Any]] = []
    growth_rows: list[dict[str, Any]] = []
    shrink_rows: list[dict[str, Any]] = []

    for key in dir_keys:
        current = int(current_dirs.get(key, 0))
        previous = int(previous_dirs.get(key, 0))
        delta = current - previous
        if abs(delta) < threshold:
            continue
        state = "unchanged"
        if previous == 0 and current > 0:
            state = "new"
        elif current == 0 and previous > 0:
            state = "deleted"
        elif delta > 0:
            state = "grown"
        elif delta < 0:
            state = "shrunk"

        row = {
            "path": key,
            "status": state,
            "previous_bytes": previous,
            "current_bytes": current,
            "delta_bytes": delta,
            "delta_percent": _safe_percent(delta, previous),
            "impact_bytes": abs(delta),
        }
        dir_rows.append(row)
        if delta > 0:
            growth_rows.append(row)
        elif delta < 0:
            shrink_rows.append(row)

    growth_rows.sort(key=lambda item: (-item["impact_bytes"], item["path"]))
    shrink_rows.sort(key=lambda item: (-item["impact_bytes"], item["path"]))
    dir_rows.sort(key=lambda item: (-item["impact_bytes"], item["path"]))

    total_growth = sum(item["delta_bytes"] for item in growth_rows)
    total_shrink_abs = sum(abs(item["delta_bytes"]) for item in shrink_rows)
    net_change = total_growth - total_shrink_abs

    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "generated_at": _utc_now_iso(),
            "current_finished_at": current_snapshot.get("run", {}).get("finished_at"),
            "previous_finished_at": previous_snapshot.get("run", {}).get("finished_at"),
        },
        "config": {"noise_threshold_bytes": threshold},
        "totals": {
            "tree_bytes_delta": int(current_snapshot.get("totals", {}).get("tree_bytes", 0)) - int(previous_snapshot.get("totals", {}).get("tree_bytes", 0)),
            "file_count_delta": int(current_snapshot.get("totals", {}).get("file_count", 0)) - int(previous_snapshot.get("totals", {}).get("file_count", 0)),
            "total_growth_bytes": int(total_growth),
            "total_shrink_bytes": int(total_shrink_abs),
            "net_change_bytes": int(net_change),
        },
        "summary": {
            "total_growth_bytes": int(total_growth),
            "total_shrink_bytes": int(total_shrink_abs),
            "net_change_bytes": int(net_change),
            "top_growth_contributors": growth_rows[:10],
        },
        "tree": {
            "dir_bytes_delta": {k: int(current_dirs.get(k, 0)) - int(previous_dirs.get(k, 0)) for k in dir_keys},
            "dir_delta_rows": dir_rows,
            "ranked_growth": growth_rows,
            "ranked_shrink": shrink_rows,
        },
        "extensions": {"ext_bytes_delta": {k: int(current_ext.get(k, 0)) - int(previous_ext.get(k, 0)) for k in ext_keys}},
    }


def write_space_reports(
    report_dir: str | Path,
    snapshot: dict[str, Any],
    top_dirs: list[dict[str, Any]],
    by_ext: list[dict[str, Any]],
    diff: dict[str, Any] | None = None,
    timeline_row: dict[str, Any] | None = None,
) -> dict[str, str]:
    out_dir = Path(report_dir)
    safe_mkdir(out_dir)

    generated_at = _utc_now_iso()
    paths = {
        "snapshot": str(out_dir / "space_snapshot.json"),
        "top_dirs": str(out_dir / "space_top_dirs.json"),
        "by_extension": str(out_dir / "space_by_extension.json"),
        "usage_by_dir": str(out_dir / "space_usage_by_dir.json"),
        "usage_topn": str(out_dir / "space_usage_topN.txt"),
        "usage_by_ext": str(out_dir / "space_usage_by_ext.json"),
        "audit_summary": str(out_dir / "space_audit_summary.json"),
        "audit_meta": str(out_dir / "space_audit_meta.json"),
        "audit_warnings": str(out_dir / "space_audit_warnings.txt"),
    }
    write_json_atomic(Path(paths["snapshot"]), snapshot)
    top_dirs_payload = {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, "rows": top_dirs}
    by_ext_payload = {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, "rows": by_ext}
    write_json_atomic(Path(paths["top_dirs"]), top_dirs_payload)
    write_json_atomic(Path(paths["by_extension"]), by_ext_payload)
    write_json_atomic(Path(paths["usage_by_dir"]), {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "rows": [{"path": k, "bytes": int(v)} for k, v in snapshot.get("tree", {}).get("dir_bytes", {}).items()],
    })
    write_json_atomic(Path(paths["usage_by_ext"]), by_ext_payload)

    top_lines = [f"{row.get('bytes', 0)}\t{row.get('path', '')}" for row in top_dirs]
    _write_text_atomic(Path(paths["usage_topn"]), "\n".join(top_lines) + ("\n" if top_lines else ""))

    if diff is not None:
        paths["diff"] = str(out_dir / "space_diff.json")
        paths["diff_vs_previous"] = str(out_dir / "space_diff_vs_previous.json")
        write_json_atomic(Path(paths["diff"]), diff)
        write_json_atomic(Path(paths["diff_vs_previous"]), diff)

    if timeline_row is not None:
        paths["timeline_row"] = str(out_dir / "space_timeline_row.json")
        write_json_atomic(Path(paths["timeline_row"]), {"schema_version": SCHEMA_VERSION, "row": timeline_row})

    warning_lines: list[str] = []
    for warning in snapshot.get("caveats", []):
        warning_lines.append(str(warning))
    for row in top_dirs:
        if "warning" in row:
            warning_lines.append(str(row["warning"]))

    _write_text_atomic(
        Path(paths["audit_warnings"]),
        "\n".join(warning_lines) + ("\n" if warning_lines else ""),
    )
    write_json_atomic(Path(paths["audit_summary"]), {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "summary": {
            "tree_bytes": int(snapshot.get("totals", {}).get("tree_bytes", 0)),
            "file_count": int(snapshot.get("totals", {}).get("file_count", 0)),
            "warnings_count": len(warning_lines),
        },
    })
    write_json_atomic(Path(paths["audit_meta"]), {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "run": snapshot.get("run", {}),
        "artifacts": {k: str(v) for k, v in paths.items()},
    })

    return paths


def _write_text_atomic(path: Path, text: str) -> None:
    safe_mkdir(path.parent)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def calibrate_baseline(volume: str, duration_minutes: float) -> dict[str, Any]:
    """Learn normal free-space oscillation for a volume and return threshold profile."""
    samples = max(2, int(duration_minutes * 60))
    previous_free: int | None = None
    deltas: list[int] = []
    for _ in range(samples):
        statvfs = os.statvfs(Path(volume))
        free = int(statvfs.f_bavail * statvfs.f_frsize)
        if previous_free is not None:
            deltas.append(abs(int(free - previous_free)))
        previous_free = free
        time.sleep(0.0)

    if deltas:
        sorted_deltas = sorted(deltas)
        median_noise = sorted_deltas[len(sorted_deltas) // 2]
        p90_noise = sorted_deltas[int((len(sorted_deltas) - 1) * 0.9)]
        max_noise = sorted_deltas[-1]
    else:
        median_noise = p90_noise = max_noise = 0

    minor_band = int(max(1, p90_noise))
    significant_drop = int(max(minor_band + 1, max(minor_band * 2, median_noise * 3)))
    critical_drop = int(max(significant_drop + 1, max(significant_drop * 2, max_noise * 4)))

    return {
        "calibrated_at": _utc_now_iso(),
        "duration_minutes": float(duration_minutes),
        "sample_count": len(deltas),
        "minor_fluctuation_band_bytes": minor_band,
        "significant_drop_threshold_bytes": significant_drop,
        "critical_drop_threshold_bytes": critical_drop,
    }


__all__ = [
    "SCHEMA_VERSION",
    "scan_space_usage",
    "summarize_top_dirs",
    "summarize_by_extension",
    "resolve_previous_snapshot",
    "diff_space_snapshots",
    "write_space_reports",
    "sample_free_space_timeline",
]


def sample_free_space_timeline(
    root: str | Path,
    output_csv: str | Path,
    interval_seconds: float = 1.0,
    duration_seconds: float | None = None,
    max_rows: int | None = None,
    free_space_drop_spike_threshold_bytes: int | None = None,
    capture_active_process_io: bool = False,
    policy_path: str | Path | None = None,
    retention_max_bundles: int | None = None,
    retention_max_disk_bytes: int | None = None,
    top_n_deltas: int = 20,
    cancel_flag: Any | None = None,
) -> dict[str, Any]:
    """Periodically capture free-space metrics into CSV.

    This sampler is read-only and only relies on os.statvfs for volume stats.
    """
    root_path = Path(root).expanduser().resolve()
    out_path = Path(output_csv)
    safe_mkdir(out_path.parent)
    baseline_path = out_path.parent / "space_watch_baseline.json"
    volume_key = str(root_path)

    if baseline_path.exists():
        baseline_profiles = json.loads(baseline_path.read_text(encoding="utf-8"))
    else:
        baseline_profiles = {}
    if volume_key not in baseline_profiles:
        baseline_profiles[volume_key] = calibrate_baseline(volume=volume_key, duration_minutes=0.05)
        write_json_atomic(baseline_path, baseline_profiles)

    profile = baseline_profiles[volume_key]
    minor_band = int(profile["minor_fluctuation_band_bytes"])
    significant_drop = int(profile["significant_drop_threshold_bytes"])
    critical_drop = int(profile["critical_drop_threshold_bytes"])

    started_at = time.time()
    rows_written = 0
    previous_free: int | None = None
    spikes: list[dict[str, Any]] = []
    evidence_bundles: list[dict[str, Any]] = []
    baseline_snapshot: dict[str, Any] | None = None
    protection_cfg = resolve_protection_config(Path(policy_path) if policy_path else DEFAULT_TOML)
    cancelled = False

    def _collect_io_snapshot() -> dict[str, Any]:
        if not capture_active_process_io:
            return {"enabled": False}
        pid = os.getpid()
        io_path = Path(f"/proc/{pid}/io")
        payload: dict[str, Any] = {"enabled": True, "pid": pid}
        if io_path.exists():
            try:
                rows = io_path.read_text(encoding="utf-8").splitlines()
                for row in rows:
                    if ":" in row:
                        key, value = row.split(":", 1)
                        payload[key.strip()] = int(value.strip())
            except OSError as exc:
                payload["error"] = str(exc)
        else:
            payload["error"] = "process io counters unavailable on this platform"
        return payload

    def _bundle_size_bytes(bundle_dir: Path) -> int:
        total = 0
        for p in bundle_dir.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
        return total

    def _prune_bundles() -> None:
        bundles = sorted(
            [p for p in out_path.parent.glob("evidence_bundle_*") if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
        )
        if retention_max_bundles is not None and retention_max_bundles >= 0:
            while len(bundles) > retention_max_bundles:
                doomed = bundles.pop(0)
                for item in sorted(doomed.rglob("*"), reverse=True):
                    if item.is_file():
                        item.unlink(missing_ok=True)
                    else:
                        item.rmdir()
                doomed.rmdir()
        if retention_max_disk_bytes is not None and retention_max_disk_bytes >= 0:
            while True:
                usage = sum(_bundle_size_bytes(p) for p in bundles)
                if usage <= retention_max_disk_bytes or not bundles:
                    break
                doomed = bundles.pop(0)
                for item in sorted(doomed.rglob("*"), reverse=True):
                    if item.is_file():
                        item.unlink(missing_ok=True)
                    else:
                        item.rmdir()
                doomed.rmdir()

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "timestamp",
            "total_bytes",
            "free_bytes",
            "used_bytes",
            "free_delta_bytes",
            "spike",
        ])
        handle.flush()
        os.fsync(handle.fileno())

        while True:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                cancelled = True
                break
            if duration_seconds is not None and (time.time() - started_at) >= duration_seconds:
                break
            if max_rows is not None and rows_written >= max_rows:
                break
            if baseline_snapshot is None:
                baseline_snapshot = scan_space_usage(root_path, excludes=[], policy_path=policy_path)

            statvfs = os.statvfs(root_path)
            total = int(statvfs.f_blocks * statvfs.f_frsize)
            free = int(statvfs.f_bavail * statvfs.f_frsize)
            used = max(0, total - free)
            delta = 0 if previous_free is None else int(free - previous_free)
            spike = False
            threshold = int(free_space_drop_spike_threshold_bytes) if free_space_drop_spike_threshold_bytes is not None else significant_drop
            if previous_free is not None and delta < 0 and abs(delta) > minor_band and abs(delta) >= threshold:
                spike = True
                event_id = f"{int(time.time())}_{rows_written}"
                bundle_dir = out_path.parent / f"evidence_bundle_{event_id}"
                safe_mkdir(bundle_dir)
                current_snapshot = scan_space_usage(root_path, excludes=[], policy_path=policy_path)
                diff = diff_space_snapshots(current_snapshot, baseline_snapshot)
                top_dir_deltas = sorted(
                    diff.get("tree", {}).get("dir_bytes_delta", {}).items(),
                    key=lambda item: abs(int(item[1])),
                    reverse=True,
                )[: max(1, int(top_n_deltas))]
                top_ext_deltas = sorted(
                    diff.get("extensions", {}).get("ext_bytes_delta", {}).items(),
                    key=lambda item: abs(int(item[1])),
                    reverse=True,
                )[: max(1, int(top_n_deltas))]
                write_json_atomic(bundle_dir / "disk_metrics.json", {
                    "timestamp": _utc_now_iso(),
                    "total_bytes": total,
                    "free_bytes": free,
                    "used_bytes": used,
                    "free_delta_bytes": delta,
                    "threshold_bytes": int(free_space_drop_spike_threshold_bytes),
                })
                write_json_atomic(bundle_dir / "top_dir_deltas.json", {"rows": [{"dir": k, "delta_bytes": int(v)} for k, v in top_dir_deltas]})
                write_json_atomic(bundle_dir / "top_extension_deltas.json", {"rows": [{"extension": k, "delta_bytes": int(v)} for k, v in top_ext_deltas]})
                write_json_atomic(bundle_dir / "process_io_snapshot.json", _collect_io_snapshot())
                write_json_atomic(bundle_dir / "policy_context.json", {
                    "policy_path": str(Path(policy_path).resolve()) if policy_path else str(DEFAULT_TOML),
                    "enforce_safe_delete_roots": bool(protection_cfg.enforce_safe_delete_roots),
                    "safe_delete_roots": list(protection_cfg.safe_delete_roots),
                    "protected_prefixes": list(protection_cfg.protected_prefixes),
                    "protected_dir_names": list(protection_cfg.protected_dir_names),
                })
                manifest = {
                    "event_id": event_id,
                    "bundle_dir": str(bundle_dir),
                    "generated_at": _utc_now_iso(),
                    "artifacts": {
                        "disk_metrics": str(bundle_dir / "disk_metrics.json"),
                        "top_dir_deltas": str(bundle_dir / "top_dir_deltas.json"),
                        "top_extension_deltas": str(bundle_dir / "top_extension_deltas.json"),
                        "process_io_snapshot": str(bundle_dir / "process_io_snapshot.json"),
                        "policy_context": str(bundle_dir / "policy_context.json"),
                    },
                }
                write_json_atomic(bundle_dir / "bundle_manifest.json", manifest)
                evidence_bundles.append(manifest)
                _prune_bundles()
                severity = "critical" if abs(delta) >= critical_drop else "significant"
                spikes.append(
                    {
                        "timestamp": _utc_now_iso(),
                        "free_delta_bytes": delta,
                        "free_bytes": free,
                        "threshold_bytes": threshold,
                        "severity": severity,
                    }
                )

            writer.writerow([_utc_now_iso(), total, free, used, delta, int(spike)])
            handle.flush()
            os.fsync(handle.fileno())

            previous_free = free
            rows_written += 1
            time.sleep(max(0.0, float(interval_seconds)))

    return {
        "root": str(root_path),
        "output_csv": str(out_path),
        "rows_written": rows_written,
        "cancelled": cancelled,
        "duration_seconds": float(time.time() - started_at),
        "spike_count": len(spikes),
        "spikes": spikes,
        "baseline_profile": profile,
        "baseline_profile_path": str(baseline_path),
        "mode": "watchdog_read_only",
        "evidence_bundle_count": len(evidence_bundles),
        "evidence_bundles": evidence_bundles,
    }
