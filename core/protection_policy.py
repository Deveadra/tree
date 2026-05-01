from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from config.protection_loader import ProtectionConfig

from dupe_core import PROTECTED_PATH_DENYLIST, canonicalize_path

SAFE_DELETE_ROOTS: tuple[str, ...] = tuple()


def _normalize_path(path: str) -> str:
    return canonicalize_path(path).canonical


def _is_same_or_child(path: str, prefix: str) -> bool:
    path = path.replace("/", "\\")
    prefix = prefix.replace("/", "\\")
    sep = "\\"
    if prefix.endswith(sep):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + sep)


def is_under_protected_prefix(path: str, protected_prefixes: Optional[list[str]] = None) -> Optional[str]:
    np = _normalize_path(path)
    prefixes = protected_prefixes if protected_prefixes is not None else list(PROTECTED_PATH_DENYLIST)
    for pref in prefixes:
        n_pref = _normalize_path(pref)
        if _is_same_or_child(np, n_pref):
            return n_pref
    return None


def contains_protected_dir_name(path: str, protected_dir_names: Optional[list[str]] = None) -> Optional[str]:
    np = _normalize_path(path)
    parts = re.split(r"[\\/]+", np)

    protected_names = set(protected_dir_names) if protected_dir_names is not None else {"windows", "program files", "program files (x86)", "programdata", "$recycle.bin", "system volume information"}
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


def evaluate_delete_permission(path: str, mode: str, action_type: str, safe_roots: Optional[list[Path]] = None, policy: Optional[ProtectionConfig] = None) -> dict[str, str | bool]:
    if not path:
        return {"allow": False, "reason_code": "invalid_path", "reason": "Path is empty."}

    effective_roots = safe_roots
    if effective_roots is None and policy is not None:
        effective_roots = [Path(r) for r in policy.safe_delete_roots]

    pref = is_under_protected_prefix(path, protected_prefixes=(policy.protected_prefixes if policy else None))
    if pref:
        return {"allow": False, "reason_code": "protected_prefix", "reason": f"Path is under protected prefix: {pref}"}

    dname = contains_protected_dir_name(path, protected_dir_names=(policy.protected_dir_names if policy else None))
    if dname:
        return {"allow": False, "reason_code": "protected_dir_name", "reason": f"Path contains protected directory name: {dname}"}

    if policy is not None and not policy.enforce_safe_delete_roots:
        safe_roots_ok = True
    else:
        safe_roots_ok = is_within_safe_delete_roots(path, safe_roots=effective_roots)

    if not safe_roots_ok:
        return {"allow": False, "reason_code": "outside_safe_roots", "reason": "Path is outside selected scan roots."}

    if action_type == "delete" and "quarantine" in (mode or "").lower() and not effective_roots:
        return {"allow": False, "reason_code": "unsafe_quarantine_config", "reason": "Quarantine requires configured safe roots."}

    return {"allow": True, "reason_code": "allowed", "reason": "Allowed by protection policy."}
