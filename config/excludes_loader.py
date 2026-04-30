# dupes/config/excludes_loader.py

from __future__ import annotations

import os
from pathlib import Path
from config.path_rules import canonicalize_path, validate_rule_inputs

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # pip install tomli


REPO_ROOT = Path(__file__).resolve().parents[1]  # config/.. -> repo root
DEFAULT_TOML = REPO_ROOT / "config" / "excludes.toml"


def _norm(p: str) -> str:
    return canonicalize_path(p).canonical


def _csv_env(name: str) -> list[str] | None:
    v = os.environ.get(name)
    if not v:
        return None
    return [x.strip() for x in v.split(",") if x.strip()]


def _pathlist_env(name: str) -> list[str] | None:
    # Uses os.pathsep so Windows can do:
    #   set DUPES_EXCLUDE_ADD=C:\Foo;D:\Bar
    v = os.environ.get(name)
    if not v:
        return None
    return [x.strip() for x in v.split(os.pathsep) if x.strip()]


def load_exclude_prefixes(toml_path: Path = DEFAULT_TOML) -> list[str]:
    """
    Loads exclude directories as normalized path prefixes.

    Env overrides (optional):
      DUPES_EXCLUDE_GROUPS  = "windows_protected,app_caches"
      DUPES_EXCLUDE_ADD     = "C:\\Extra1;D:\\Extra2"
      DUPES_EXCLUDE_REMOVE  = "C:\\Recovery"
    """
    data = tomllib.loads(toml_path.read_text(encoding="utf-8"))

    excludes = data.get("excludes", {})
    groups = excludes.get("groups", {}) or {}
    enabled = excludes.get("enabled_groups", []) or []

    env_groups = _csv_env("DUPES_EXCLUDE_GROUPS")
    if env_groups is not None:
        enabled = env_groups

    prefixes: list[str] = []
    for g in enabled:
        gdata = groups.get(g, {}) or {}
        for p in gdata.get("paths", []) or []:
            prefixes.append(_norm(p))

    add = _pathlist_env("DUPES_EXCLUDE_ADD") or []
    for w in validate_rule_inputs(add):
        print(f"[exclude-warning] {w}")
    rem = set(_norm(p) for p in (_pathlist_env("DUPES_EXCLUDE_REMOVE") or []))

    prefixes = [_norm(p) for p in prefixes] + [_norm(p) for p in add]
    prefixes = [p for p in prefixes if p and p not in rem]

    # Dedupe while preserving order
    seen = set()
    out: list[str] = []
    for p in prefixes:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def is_excluded(path: str, exclude_prefixes: list[str]) -> bool:
    """
    Prefix match: exclude if path == prefix or path is under prefix.
    """
    p = _norm(path)
    for pref in exclude_prefixes:
        if p == pref or p.startswith(pref + os.sep):
            return True
    return False
