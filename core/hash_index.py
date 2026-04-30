from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from dupe_core import find_dupes_from_db
from .models import DuplicateResultGroup


def find_duplicates(
    db_path: Path,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    error_log_path: Optional[Path] = None,
    required_roots: Optional[tuple[int, int]] = None,
) -> list[DuplicateResultGroup]:
    return find_dupes_from_db(
        db_path=db_path,
        cancel_flag=cancel_flag,
        metrics_cb=metrics_cb,
        error_log_path=error_log_path,
        required_roots=required_roots,
    )
