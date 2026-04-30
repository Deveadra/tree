from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from dupe_core import PROTECTED_PATH_DENYLIST, canonicalize_path

SAFE_DELETE_ROOTS: tuple[str, ...] = tuple()


def _normalize_path(path: str) -> str:
    return canonicalize_path(path).canonical


def _is_same_or_child(path: str, prefix: str) -> bool:
    if prefix.endswith(os.sep):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + os.sep)


def is_under_protected_prefix(path: str) -> Optional[str]:
    np = _normalize_path(path)
    for pref in PROTECTED_PATH_DENYLIST:
        n_pref = _normalize_path(pref)
        if _is_same_or_child(np, n_pref):
            return n_pref
    return None


def contains_protected_dir_name(path: str) -> Optional[str]:
    np = _normalize_path(path)
    try:
        parts = Path(np).parts
    except Exception:
        parts = re.split(r"[\\/]+", np)

    protected_names = {"windows", "program files", "program files (x86)", "programdata", "$recycle.bin", "system volume information"}
    for part in parts:
        if part and part.lower() in protected_names:
            return part
    return None


def is_within_safe_delete_roots(path: str, safe_roots: Optional[list[Path]] = None) -> bool:
    roots = safe_roots if safe_roots is not None else [Path(r) for r in SAFE_DELETE_ROOTS]
    np = _normalize_path(path)
    for root in roots:
        nr = _normalize_path(str(root))
        if _is_same_or_child(np, nr):
            return True
    return False


def evaluate_delete_permission(path: str, mode: str, action_type: str, safe_roots: Optional[list[Path]] = None) -> dict[str, str | bool]:
    if not path:
        return {"allow": False, "reason_code": "invalid_path", "reason": "Path is empty."}

    if not is_within_safe_delete_roots(path, safe_roots=safe_roots):
        return {"allow": False, "reason_code": "outside_safe_roots", "reason": "Path is outside selected scan roots."}

    pref = is_under_protected_prefix(path)
    if pref:
        return {"allow": False, "reason_code": "protected_prefix", "reason": f"Path is under protected prefix: {pref}"}

    dname = contains_protected_dir_name(path)
    if dname:
        return {"allow": False, "reason_code": "protected_dir_name", "reason": f"Path contains protected directory name: {dname}"}

    if action_type == "delete" and "quarantine" in (mode or "").lower() and not safe_roots:
        return {"allow": False, "reason_code": "unsafe_quarantine_config", "reason": "Quarantine requires configured safe roots."}

    return {"allow": True, "reason_code": "allowed", "reason": "Allowed by protection policy."}
