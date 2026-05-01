from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from config.path_rules import canonicalize_path, validate_rule_inputs

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOML = REPO_ROOT / "config" / "protection.toml"

BUILTIN_PROTECTED_PREFIXES = [
    r"C:\\Windows",
    r"C:\\Program Files",
    r"C:\\Program Files (x86)",
    r"C:\\ProgramData",
]
BUILTIN_PROTECTED_DIR_NAMES = [
    "$Recycle.Bin",
    "System Volume Information",
    "Windows",
]


@dataclass(frozen=True)
class ProtectionConfig:
    enforce_safe_delete_roots: bool
    protected_prefixes: list[str]
    protected_dir_names: list[str]
    safe_delete_roots: list[str]
    warnings: list[str]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _load_file_config(toml_path: Path) -> dict:
    if not toml_path.exists():
        return {}
    return tomllib.loads(toml_path.read_text(encoding="utf-8"))


def _env_list(name: str) -> list[str] | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    if ";" in raw:
        return [x.strip() for x in raw.split(";") if x.strip()]
    if os.pathsep == ":" and len(raw) >= 2 and raw[1] == ":":
        return [raw.strip()]
    return [x.strip() for x in raw.split(os.pathsep) if x.strip()]


def resolve_protection_config(toml_path: Path = DEFAULT_TOML) -> ProtectionConfig:
    """Precedence: built-in defaults -> file config -> env/runtime overrides."""
    data = _load_file_config(toml_path)

    enforce = True
    if "enforce_safe_delete_roots" in data:
        enforce = bool(data.get("enforce_safe_delete_roots"))

    protected_prefixes = BUILTIN_PROTECTED_PREFIXES + list(data.get("protected_prefixes", []) or [])
    protected_dir_names = BUILTIN_PROTECTED_DIR_NAMES + list(data.get("protected_dir_names", []) or [])
    safe_delete_roots = list(data.get("safe_delete_roots", []) or [])

    env_protected_prefixes = _env_list("DUPES_PROTECTED_PREFIXES")
    if env_protected_prefixes is not None:
        protected_prefixes.extend(env_protected_prefixes)

    env_protected_dir_names = _env_list("DUPES_PROTECTED_DIR_NAMES")
    if env_protected_dir_names is not None:
        protected_dir_names.extend(env_protected_dir_names)

    env_safe_delete_roots = _env_list("DUPES_SAFE_DELETE_ROOTS")
    if env_safe_delete_roots is not None:
        safe_delete_roots = env_safe_delete_roots

    env_enforce = os.environ.get("DUPES_ENFORCE_SAFE_DELETE_ROOTS")
    if env_enforce is not None:
        enforce = env_enforce.strip().lower() not in {"0", "false", "no", "off"}

    warnings = validate_rule_inputs(protected_prefixes + safe_delete_roots)

    normalized_prefixes = _dedupe([canonicalize_path(p).canonical for p in protected_prefixes if p])
    normalized_roots = _dedupe([canonicalize_path(p).canonical for p in safe_delete_roots if p])
    normalized_dir_names = _dedupe([x.strip().lower() for x in protected_dir_names if x and x.strip()])

    if enforce and not normalized_roots:
        warnings.append("safe_delete_roots missing while enforcement is enabled")

    return ProtectionConfig(
        enforce_safe_delete_roots=enforce,
        protected_prefixes=normalized_prefixes,
        protected_dir_names=normalized_dir_names,
        safe_delete_roots=normalized_roots,
        warnings=warnings,
    )
