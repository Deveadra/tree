from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass(frozen=True)
class FileRec:
    path: str
    name: str
    size: int
    mtime: float
    root_id: int = 0


@dataclass
class DuplicateResultGroup:
    sha256: str
    size: int
    files: list[FileRec]


@dataclass
class ScanRequest:
    db_path: Path
    roots: list[Path]
    excludes: set[str] = field(default_factory=set)
    follow_symlinks: bool = False
    min_size: int = 1
    cancel_flag: Callable[[], bool] = lambda: False
    metrics_cb: Callable[[dict], None] = lambda _m: None
    scan_error_log_path: Optional[Path] = None


@dataclass
class PrunePlan:
    total_candidates: int
    paths_to_remove: list[str]
    mode: str = "recycle"


@dataclass
class PruneExecutionResult:
    removed: int
    failed: int
    errors: list[str] = field(default_factory=list)
