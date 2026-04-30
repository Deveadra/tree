from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import errno
import os

from dupe_core import safe_mkdir, write_json_atomic

SCHEMA_VERSION = "1.0"

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


def scan_space_usage(
    root: str | Path,
    excludes: list[str] | set[str],
    depth: int = 4,
    policy: Callable[[Path, os.stat_result], bool] | None = None,
    cancel_flag: Any | None = None,
    metrics_cb: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Read-only filesystem scan that records file usage by tree node and extension."""
    root_path = Path(root).expanduser().resolve()
    exclude_set = {str(item) for item in excludes}
    start = _utc_now_iso()

    volume_total = 0
    try:
        volume_total = os.statvfs(root_path).f_blocks * os.statvfs(root_path).f_frsize
    except OSError:
        pass

    dir_totals: Counter[str] = Counter()
    ext_totals: Counter[str] = Counter()
    file_count = 0
    skipped_count = 0
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
        dirnames[:] = [d for d in dirnames if not _is_excluded(current_dir / d, root_path, exclude_set)]
        if _is_excluded(current_dir, root_path, exclude_set):
            continue

        for filename in filenames:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break

            file_path = current_dir / filename
            if _is_excluded(file_path, root_path, exclude_set):
                skipped_count += 1
                continue

            try:
                st = file_path.stat(follow_symlinks=False)
                if not os.path.isfile(file_path):
                    continue
                if policy and not policy(file_path, st):
                    skipped_count += 1
                    continue
                size = st.st_size
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
            for d in range(1, max_depth + 1):
                key = "/".join(rel_parts[:d])
                dir_totals[key] += size
            ext_totals[_extension_for(file_path)] += size

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
    unattributed = max(0, int(volume_total - tree_total)) if volume_total else 0

    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "started_at": start,
            "finished_at": _utc_now_iso(),
            "root": str(root_path),
            "depth": depth,
            "cancelled": bool(cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)()),
        },
        "totals": {
            "volume_bytes": int(volume_total),
            "tree_bytes": tree_total,
            "unattributed_bytes": unattributed,
            "file_count": file_count,
            "skipped_count": skipped_count,
            "error_count": len(errors),
        },
        "tree": {"dir_bytes": dict(dir_totals)},
        "extensions": {"ext_bytes": dict(ext_totals)},
        "errors": errors,
    }


def summarize_top_dirs(snapshot: dict[str, Any], top_n: int = 100) -> list[dict[str, Any]]:
    dir_bytes = snapshot.get("tree", {}).get("dir_bytes", {})
    rows = sorted(dir_bytes.items(), key=lambda pair: pair[1], reverse=True)
    return [{"path": path, "bytes": int(total)} for path, total in rows[:top_n]]


def summarize_by_extension(snapshot: dict[str, Any], top_n: int = 100) -> list[dict[str, Any]]:
    ext_bytes = snapshot.get("extensions", {}).get("ext_bytes", {})
    rows = sorted(ext_bytes.items(), key=lambda pair: pair[1], reverse=True)
    return [{"extension": ext, "bytes": int(total)} for ext, total in rows[:top_n]]


def diff_space_snapshots(current_snapshot: dict[str, Any], previous_snapshot: dict[str, Any]) -> dict[str, Any]:
    current_dirs = current_snapshot.get("tree", {}).get("dir_bytes", {})
    previous_dirs = previous_snapshot.get("tree", {}).get("dir_bytes", {})
    current_ext = current_snapshot.get("extensions", {}).get("ext_bytes", {})
    previous_ext = previous_snapshot.get("extensions", {}).get("ext_bytes", {})

    dir_keys = set(current_dirs) | set(previous_dirs)
    ext_keys = set(current_ext) | set(previous_ext)

    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "generated_at": _utc_now_iso(),
            "current_finished_at": current_snapshot.get("run", {}).get("finished_at"),
            "previous_finished_at": previous_snapshot.get("run", {}).get("finished_at"),
        },
        "totals": {
            "tree_bytes_delta": int(current_snapshot.get("totals", {}).get("tree_bytes", 0)) - int(previous_snapshot.get("totals", {}).get("tree_bytes", 0)),
            "file_count_delta": int(current_snapshot.get("totals", {}).get("file_count", 0)) - int(previous_snapshot.get("totals", {}).get("file_count", 0)),
        },
        "tree": {"dir_bytes_delta": {k: int(current_dirs.get(k, 0)) - int(previous_dirs.get(k, 0)) for k in dir_keys}},
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

    paths = {
        "snapshot": str(out_dir / "space_snapshot.json"),
        "top_dirs": str(out_dir / "space_top_dirs.json"),
        "by_extension": str(out_dir / "space_by_extension.json"),
    }
    write_json_atomic(Path(paths["snapshot"]), snapshot)
    write_json_atomic(Path(paths["top_dirs"]), {"schema_version": SCHEMA_VERSION, "rows": top_dirs})
    write_json_atomic(Path(paths["by_extension"]), {"schema_version": SCHEMA_VERSION, "rows": by_ext})

    if diff is not None:
        paths["diff"] = str(out_dir / "space_diff.json")
        write_json_atomic(Path(paths["diff"]), diff)

    if timeline_row is not None:
        paths["timeline_row"] = str(out_dir / "space_timeline_row.json")
        write_json_atomic(Path(paths["timeline_row"]), {"schema_version": SCHEMA_VERSION, "row": timeline_row})

    return paths


__all__ = [
    "SCHEMA_VERSION",
    "scan_space_usage",
    "summarize_top_dirs",
    "summarize_by_extension",
    "diff_space_snapshots",
    "write_space_reports",
]
