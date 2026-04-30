from __future__ import annotations

from dupe_core import compile_excludes, scan_root_to_db, scan_roots_to_db
from .models import ScanRequest


def scan(request: ScanRequest) -> dict:
    if len(request.roots) >= 2:
        return scan_roots_to_db(
            db_path=request.db_path,
            roots=request.roots,
            excludes=request.excludes,
            follow_symlinks=request.follow_symlinks,
            min_size=request.min_size,
            cancel_flag=request.cancel_flag,
            metrics_cb=request.metrics_cb,
            scan_error_log_path=request.scan_error_log_path,
        )
    return scan_root_to_db(
        db_path=request.db_path,
        root=request.roots[0],
        excludes=request.excludes,
        follow_symlinks=request.follow_symlinks,
        min_size=request.min_size,
        cancel_flag=request.cancel_flag,
        metrics_cb=request.metrics_cb,
        scan_error_log_path=request.scan_error_log_path,
    )


__all__ = ["scan", "compile_excludes"]
