from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Iterable

_ENV_VAR_PATTERN = re.compile(r"%([^%]+)%")
_MALFORMED_PREFIX = re.compile(r"^[A-Za-z]:(?![\\/]|$)")


@dataclass(frozen=True)
class CanonicalPath:
    raw: str
    canonical: str


def canonicalize_path(raw: str) -> CanonicalPath:
    expanded = os.path.expandvars(raw or "")
    win = str(PureWindowsPath(expanded))
    canonical = win.replace("/", "\\").rstrip()
    canonical = os.path.normpath(canonical).lower()
    if re.match(r"^[a-z]:$", canonical):
        canonical += "\\"
    return CanonicalPath(raw=raw, canonical=canonical)


def validate_rule_inputs(values: Iterable[str]) -> list[str]:
    warnings: list[str] = []
    for raw in values:
        if not raw:
            continue
        unresolved = _ENV_VAR_PATTERN.findall(raw)
        for var in unresolved:
            if os.environ.get(var) is None:
                warnings.append(f"Unresolved environment variable %{var}% in rule '{raw}'")
        if _MALFORMED_PREFIX.search(raw):
            warnings.append(f"Malformed path prefix '{raw}'")
    return warnings


def match_pattern(path: str, pattern: str) -> bool:
    p = canonicalize_path(path).canonical
    pat = canonicalize_path(pattern).canonical
    if any(ch in pat for ch in "*?[]"):
        return fnmatch.fnmatch(p, pat)
    if pat.endswith("\\"):
        return p.startswith(pat)
    return p == pat or p.startswith(pat + "\\")


def evaluate_rules(path: str, includes: list[str], excludes: list[str]) -> tuple[bool, str]:
    """Return (allowed, reason). Precedence: excludes always win over includes."""
    for patt in excludes:
        if match_pattern(path, patt):
            return False, f"excluded by '{patt}'"
    if includes:
        for patt in includes:
            if match_pattern(path, patt):
                return True, f"included by '{patt}'"
        return False, "not matched by include rules"
    return True, "allowed by default"
