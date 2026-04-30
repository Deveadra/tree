from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from .actions import build_prune_plan, execute_prune_plan
from .hash_index import find_duplicates as _find_duplicates
from .models import DuplicateResultGroup, ScanRequest
from .scanner import scan as _scan


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
