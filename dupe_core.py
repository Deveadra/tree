# C://~Projects/dupes/dupe_core.py

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import sqlite3
import time

from collections import Counter, defaultdict
from config.excludes_loader import load_exclude_prefixes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Optional


# ----------------------------
# Data
# ----------------------------


@dataclass(frozen=True)
class FileRec:
    path: str
    name: str
    size: int
    mtime: float
    root_id: int = 0  # 0=Root A, 1=Root B (compare mode)
    inode: Optional[int] = None
    device_id: Optional[int] = None
    ctime: Optional[float] = None
    nlink: Optional[int] = None
    ext_hint: str = ""
    mime_hint: str = ""


@dataclass
class DupeGroup:
    sha256: str
    size: int
    files: list[FileRec]


@dataclass(frozen=True)
class PruneCandidate:
    path: str
    size: int
    mtime: float
    reason_codes: list[str]
    risk_flags: list[str]


@dataclass(frozen=True)
class ApplyResult:
    path: str
    action: str
    status: str
    detail: str
    ts_utc: str


# Normalized (case-insensitive on Windows) path prefixes loaded from config/excludes.toml
DEFAULT_EXCLUDES: list[str] = load_exclude_prefixes()


# ----------------------------
# Exclude compilation / normalization
# ----------------------------


def _norm_path_str(p: str) -> str:
    """
    Normalize a path string for reliable Windows comparisons:
      - expand %VARS%
      - normpath
      - normcase (case-insensitive on Windows)
    """
    expanded = os.path.expandvars(p)
    return os.path.normcase(os.path.normpath(expanded))


def _looks_like_path_prefix(s: str) -> bool:
    """
    Heuristic: treat token as a full path/prefix if it contains drive, slashes, or env-vars.
    """
    s = (s or "").strip()
    return (":" in s) or ("\\" in s) or ("/" in s) or s.startswith("%")


def _norm_prefix(p: str) -> str:
    """
    Normalize a prefix for prefix-matching:
      - normalize
      - strip trailing separators (except for "E:\\" style drive roots, which may end with os.sep)
    """
    p2 = _norm_path_str(p)

    # Handle "E:" -> treat as "E:\"
    if re.match(r"^[A-Za-z]:$", p2):
        return p2 + os.sep

    # Trim trailing slashes for consistent "pref + os.sep" matching
    return p2.rstrip("\\/")

def compile_excludes(excludes: set[str]) -> tuple[set[str], list[str]]:
    """
    Split the user-provided excludes into:
      - dir_names: set of directory NAMES to skip (case-insensitive), e.g. {"windowsapps", ".git"}
      - prefixes: list of FULL PATH prefixes to skip, normalized, e.g. ["c:\\windows", "e:\\system volume information"]
    Also ALWAYS includes DEFAULT_EXCLUDES (prefixes from TOML).

    Why this exists:
      - Users want to exclude both "folder names anywhere" AND "specific folders by full path".
      - We do the heavy normalization once per scan, not during every scandir loop.
    """
    dir_names: set[str] = set()
    prefixes: list[str] = []

    # 1) User-provided excludes
    for raw in excludes:
        s = (raw or "").strip()
        if not s:
            continue

        if _looks_like_path_prefix(s):
            prefixes.append(_norm_prefix(s))
        else:
            dir_names.add(s.lower())

    # 2) TOML defaults (always path prefixes)
    for p in DEFAULT_EXCLUDES:
        if p:
            prefixes.append(_norm_prefix(p))

    # 3) Dedupe prefixes, preserve order
    seen: set[str] = set()
    out_prefixes: list[str] = []
    for p in prefixes:
        if not p:
            continue
        if p not in seen:
            seen.add(p)
            out_prefixes.append(p)

    return dir_names, out_prefixes


def is_under_any_prefix(p: Path, prefixes: list[str]) -> bool:
    """
    True if p is equal to or under any prefix in prefixes (normalized compare).
    Supports drive-root prefixes like "E:\\".
    """
    ps = _norm_path_str(str(p))
    for pref in prefixes:
        if not pref:
            continue

        # Drive-root prefix like "E:\"
        if pref.endswith(os.sep):
            if ps.startswith(pref):
                return True
            continue

        if ps == pref or ps.startswith(pref + os.sep):
            return True

    return False


# ----------------------------
# Utils
# ----------------------------


def is_reparse_point(path: Path) -> bool:
    try:
        st = path.stat(follow_symlinks=False)
        attrs = getattr(st, "st_file_attributes", 0)
        return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (PermissionError, FileNotFoundError, OSError):
        return False


def safe_walk(root: Path):
    """
    Simple, safe file walk that:
      - skips DEFAULT_EXCLUDES
      - skips reparse points
      - yields file Paths
    """
    stack = [root]
    while stack:
        d = stack.pop()
        if is_under_any_prefix(d, DEFAULT_EXCLUDES):
            continue
        if is_reparse_point(d):
            continue

        try:
            with os.scandir(d) as it:
                for entry in it:
                    p = Path(entry.path)

                    if is_under_any_prefix(p, DEFAULT_EXCLUDES):
                        continue

                    if entry.is_dir(follow_symlinks=False):
                        if is_reparse_point(p):
                            continue
                        stack.append(p)
                    elif entry.is_file(follow_symlinks=False):
                        yield p
        except (PermissionError, FileNotFoundError):
            continue


def safe_hash_file(path: Path, hasher_factory, bufsize=1024 * 1024):
    try:
        h = hasher_factory()
        with open(path, "rb", buffering=0) as f:
            while True:
                chunk = f.read(bufsize)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}h{m:02d}m{s:02d}s"


def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    units = ["KB", "MB", "GB", "TB", "PB"]
    f = float(n)
    for u in units:
        f /= 1024.0
        if f < 1024:
            return f"{f:.2f} {u}"
    return f"{f:.2f} EB"


def fmt_time(epoch: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except Exception:
        return str(epoch)


def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _normalized_plan_payload(plan: dict[str, Any]) -> bytes:
    # Signature always excludes itself.
    to_sign = dict(plan)
    to_sign.pop("plan_signature", None)
    return json.dumps(to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_plan_signature(plan: dict[str, Any]) -> str:
    return hashlib.sha256(_normalized_plan_payload(plan)).hexdigest()


def validate_plan_signature(plan: dict[str, Any]) -> bool:
    sig = str(plan.get("plan_signature", ""))
    return bool(sig) and sig == compute_plan_signature(plan)


def write_prune_plan(
    artifact_path: Path,
    *,
    roots: list[str],
    excludes: list[str],
    compare_mode: bool,
    candidates: list[PruneCandidate],
    dry_run: bool,
    plan_id: Optional[str] = None,
) -> dict[str, Any]:
    if not plan_id:
        plan_id = hashlib.sha256(f"{utc_now_iso()}|{'|'.join(sorted(roots))}".encode("utf-8")).hexdigest()[:12]

    plan: dict[str, Any] = {
        "plan_id": plan_id,
        "metadata": {
            "roots": roots,
            "excludes": excludes,
            "compare_mode": compare_mode,
            "generated_at_utc": utc_now_iso(),
            "dry_run": dry_run,
        },
        "candidates": [
            {
                "path": c.path,
                "size": int(c.size),
                "mtime": float(c.mtime),
                "reason_codes": c.reason_codes,
                "risk_flags": c.risk_flags,
            }
            for c in candidates
        ],
        "aggregate": {
            "candidate_count": len(candidates),
            "bytes_to_reclaim": sum(int(c.size) for c in candidates),
        },
    }
    plan["plan_signature"] = compute_plan_signature(plan)
    artifact_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return plan


def _is_writable_dir(path: Path) -> bool:
    try:
        safe_mkdir(path)
        probe = path / f".write_test_{time.time_ns()}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def apply_prune_plan(
    plan: dict[str, Any],
    *,
    confirmation_token: Optional[str],
    require_confirmation: bool,
    dry_run: bool,
    destination_dir: Optional[Path],
    events_path: Path,
    apply_fn: Callable[[str], None],
) -> list[ApplyResult]:
    if not validate_plan_signature(plan):
        raise ValueError("Invalid plan signature; refusing apply.")

    expected = f"APPLY PLAN {plan.get('plan_id', '')}"
    if require_confirmation and confirmation_token != expected:
        raise ValueError(f"Confirmation token required: '{expected}'")

    if destination_dir is not None and not _is_writable_dir(destination_dir):
        raise RuntimeError(f"Destination is not writable: {destination_dir}")

    results: list[ApplyResult] = []
    for c in plan.get("candidates", []):
        p = Path(str(c.get("path", "")))
        rec_size = int(c.get("size", -1))
        rec_mtime = float(c.get("mtime", -1.0))
        ts = utc_now_iso()

        if not p.exists():
            results.append(ApplyResult(str(p), "skip", "preflight_failed", "missing", ts))
            continue

        st = p.stat()
        if st.st_size != rec_size or float(st.st_mtime) != rec_mtime:
            results.append(ApplyResult(str(p), "skip", "preflight_failed", "changed_since_scan", ts))
            continue

        if dry_run:
            results.append(ApplyResult(str(p), "dry_run", "ok", "no filesystem changes", ts))
            continue

        try:
            apply_fn(str(p))
            results.append(ApplyResult(str(p), "apply", "ok", "deleted_or_moved", ts))
        except Exception as e:
            results.append(ApplyResult(str(p), "apply", "error", f"{type(e).__name__}: {e}", ts))

    with events_path.open("a", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r.__dict__, sort_keys=True) + "\n")

    return results


# ----------------------------
# Windows placeholder / offline detection (Cloud Files / Files-on-Demand)
# ----------------------------

_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
_FILE_ATTRIBUTE_OFFLINE = 0x00001000
_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000


def windows_get_file_attributes(path: str) -> Optional[int]:
    """
    Returns Windows file attributes bitmask, or None if unavailable.
    """
    if os.name != "nt":
        return None

    try:
        GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
        GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        GetFileAttributesW.restype = ctypes.c_uint32

        attrs = int(GetFileAttributesW(path))
        if attrs == _INVALID_FILE_ATTRIBUTES:
            return None
        return attrs
    except Exception:
        return None


def is_windows_placeholder_or_offline(path: str) -> tuple[bool, Optional[int]]:
    """
    Returns (is_placeholder_or_offline, attrs).
    We treat OFFLINE / RECALL flags as 'would trigger hydration/transfer on read'.
    """
    attrs = windows_get_file_attributes(path)
    if attrs is None:
        return (False, None)

    mask = (
        _FILE_ATTRIBUTE_OFFLINE
        | _FILE_ATTRIBUTE_RECALL_ON_OPEN
        | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    )
    return ((attrs & mask) != 0, attrs)


def sha256_file(
    path: str,
    chunk_size: int = 8 * 1024 * 1024,
    cancel_flag: Optional[Callable[[], bool]] = None,
) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            if cancel_flag and cancel_flag():
                raise RuntimeError("Cancelled during hashing.")
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_json_atomic(path: Path, data: dict) -> None:
    """
    Writes JSON atomically (temp file + replace) so we don't end up with a half-written meta file.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _db_create_schema(con: sqlite3.Connection) -> None:
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute(
        """
        CREATE TABLE files (
            path      TEXT PRIMARY KEY,
            name      TEXT NOT NULL,
            size      INTEGER NOT NULL,
            mtime     REAL NOT NULL,
            root_id   INTEGER NOT NULL,
            inode     INTEGER,
            device_id INTEGER,
            ctime     REAL,
            nlink     INTEGER,
            ext_hint  TEXT,
            mime_hint TEXT
        );
        """
    )
    con.execute("CREATE INDEX idx_files_size ON files(size);")
    con.execute("CREATE INDEX idx_files_name ON files(name);")
    con.execute("CREATE INDEX idx_files_root ON files(root_id);")
    con.execute("CREATE INDEX idx_files_dev_inode ON files(device_id, inode);")


def _scan_root_append_to_con(
    con: sqlite3.Connection,
    root: Path,
    root_id: int,
    exclude_names: set[str],
    exclude_prefixes: list[str],
    follow_symlinks: bool,
    min_size: int,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    scan_error_log_path: Optional[Path] = None,
) -> dict:
    """
    Walk root and insert file rows into SQLite.

    exclude_names:
      - directory NAMES to skip anywhere (case-insensitive)
    exclude_prefixes:
      - normalized full PATH prefixes to skip
    """
    err_f = None
    if scan_error_log_path:
        try:
            scan_error_log_path.parent.mkdir(parents=True, exist_ok=True)
            err_f = open(scan_error_log_path, "a", encoding="utf-8")
            if scan_error_log_path.stat().st_size == 0:
                err_f.write("kind\tpath\terror\n")
        except Exception:
            err_f = None

    def log_err(kind: str, path: str, e: Exception) -> None:
        if not err_f:
            return
        try:
            err_f.write(f"{kind}\t{path}\t{type(e).__name__}: {e}\n")
        except Exception:
            pass

    listed = 0
    indexed = 0
    skipped = 0
    errors = 0

    batch: list[tuple[str, str, int, float, int, Optional[int], Optional[int], Optional[float], Optional[int], str, str]] = []
    last_emit = 0.0
    t0 = time.time()

    def emit(force: bool = False) -> None:
        nonlocal last_emit
        now = time.time()
        if force or (now - last_emit) >= 0.5:
            elapsed = now - t0
            rate = (listed / elapsed) if elapsed > 0 else 0.0
            metrics_cb(
                {
                    "phase": "Scanning",
                    "listed": listed,
                    "indexed": indexed,
                    "skipped": skipped,
                    "errors": errors,
                    "rate_files_per_s": rate,
                    "elapsed_s": elapsed,
                    "eta_s": None,
                    "hash_done": None,
                    "hash_total": None,
                    "dupe_groups": None,
                    "scan_root_id": root_id,
                    "scan_root": str(root),
                }
            )
            last_emit = now

    stack: list[Path] = [root]
    emit(force=True)

    while stack and not cancel_flag():
        d = stack.pop()

        # Skip excluded directory prefix
        if is_under_any_prefix(d, exclude_prefixes):
            continue

        # Skip reparse points if not following symlinks/junctions
        if not follow_symlinks and is_reparse_point(d):
            continue

        try:
            with os.scandir(d) as it:
                for entry in it:
                    if cancel_flag():
                        break

                    name = entry.name
                    p = Path(entry.path)

                    # Skip by name
                    if name.lower() in exclude_names:
                        continue

                    # Skip by full path prefix
                    if is_under_any_prefix(p, exclude_prefixes):
                        continue

                    try:
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            # Avoid following reparse points unless explicitly allowed
                            if not follow_symlinks and is_reparse_point(p):
                                continue
                            stack.append(p)
                            continue

                        if entry.is_file(follow_symlinks=follow_symlinks):
                            listed += 1
                            try:
                                st = entry.stat(follow_symlinks=follow_symlinks)
                                size = int(st.st_size)
                                if size < min_size:
                                    skipped += 1
                                else:
                                    suffix = Path(name).suffix.lower()
                                    batch.append(
                                        (
                                            entry.path,
                                            name,
                                            size,
                                            float(st.st_mtime),
                                            int(root_id),
                                            int(st.st_ino) if hasattr(st, "st_ino") else None,
                                            int(st.st_dev) if hasattr(st, "st_dev") else None,
                                            float(st.st_ctime) if hasattr(st, "st_ctime") else None,
                                            int(st.st_nlink) if hasattr(st, "st_nlink") else None,
                                            suffix,
                                            "",
                                        )
                                    )
                                    indexed += 1
                            except (PermissionError, FileNotFoundError, OSError) as e:
                                errors += 1
                                log_err("FILE_STAT", entry.path, e)

                            if len(batch) >= 5000:
                                con.executemany(
                                    "INSERT OR REPLACE INTO files(path,name,size,mtime,root_id,inode,device_id,ctime,nlink,ext_hint,mime_hint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                    batch,
                                )
                                con.commit()
                                batch.clear()

                            emit()

                    except (PermissionError, FileNotFoundError, OSError) as e:
                        errors += 1
                        log_err("ENTRY", entry.path, e)
                        continue

        except (PermissionError, FileNotFoundError, OSError) as e:
            errors += 1
            log_err("DIR", str(d), e)
            continue

    if batch:
        con.executemany(
            "INSERT OR REPLACE INTO files(path,name,size,mtime,root_id,inode,device_id,ctime,nlink,ext_hint,mime_hint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            batch,
        )
        con.commit()
        batch.clear()

    emit(force=True)

    try:
        if err_f:
            err_f.close()
    except Exception:
        pass

    return {"listed": listed, "indexed": indexed, "skipped": skipped, "errors": errors}


def scan_roots_to_db(
    db_path: Path,
    roots: list[Path],
    excludes: set[str],
    follow_symlinks: bool,
    min_size: int,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    scan_error_log_path: Optional[Path] = None,
) -> dict:
    """
    Scan multiple roots into one DB. root_id is assigned by index in `roots`.
    Returns combined stats + per-root stats.
    """
    exclude_names, exclude_prefixes = compile_excludes(excludes)

    if db_path.exists():
        db_path.unlink()

    con = sqlite3.connect(str(db_path))
    try:
        _db_create_schema(con)

        per_root: list[dict] = []
        combined = {"listed": 0, "indexed": 0, "skipped": 0, "errors": 0}

        for rid, r in enumerate(roots):
            if cancel_flag():
                break

            st = _scan_root_append_to_con(
                con=con,
                root=r,
                root_id=rid,
                exclude_names=exclude_names,
                exclude_prefixes=exclude_prefixes,
                follow_symlinks=follow_symlinks,
                min_size=min_size,
                cancel_flag=cancel_flag,
                metrics_cb=metrics_cb,
                scan_error_log_path=scan_error_log_path,
            )
            per_root.append({"root_id": rid, "root": str(r), **st})
            for k in combined.keys():
                combined[k] += int(st.get(k, 0))

        return {"combined": combined, "per_root": per_root}

    finally:
        con.close()


def scan_root_to_db(
    db_path: Path,
    root: Path,
    excludes: set[str],
    follow_symlinks: bool,
    min_size: int,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    scan_error_log_path: Optional[Path] = None,
) -> dict:
    """
    Backward compatible single-root scan. Uses the new schema (includes root_id).
    """
    r = scan_roots_to_db(
        db_path=db_path,
        roots=[root],
        excludes=excludes,
        follow_symlinks=follow_symlinks,
        min_size=min_size,
        cancel_flag=cancel_flag,
        metrics_cb=metrics_cb,
        scan_error_log_path=scan_error_log_path,
    )
    return r.get("combined") or {"listed": 0, "indexed": 0, "skipped": 0, "errors": 0}


def find_dupes_from_db(
    db_path: Path,
    cancel_flag: Callable[[], bool],
    metrics_cb: Callable[[dict], None],
    error_log_path: Optional[Path] = None,
    required_roots: Optional[tuple[int, int]] = None,
) -> list[DupeGroup]:
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    dupes: list[DupeGroup] = []

    # For diagnostics / UI
    current_file: Optional[str] = None
    current_size_group: Optional[int] = None
    current_in_group: int = 0
    total_in_group: int = 0
    skipped_placeholders = 0
    placeholder_list: list[str] = []

    err_f = None
    if error_log_path:
        try:
            error_log_path.parent.mkdir(parents=True, exist_ok=True)
            err_f = open(error_log_path, "w", encoding="utf-8", newline="\n")
            err_f.write("kind\tpath\terror\n")
        except Exception:
            err_f = None

    def log_hash_err(kind: str, path: str, e: Exception) -> None:
        if not err_f:
            return
        try:
            err_f.write(f"{kind}\t{path}\t{type(e).__name__}: {e}\n")
        except Exception:
            pass

    try:
        if required_roots is not None:
            r0, r1 = required_roots
            size_rows = con.execute(
                """
                SELECT size
                FROM files
                GROUP BY size
                HAVING COUNT(*) > 1
                AND SUM(CASE WHEN root_id = ? THEN 1 ELSE 0 END) > 0
                AND SUM(CASE WHEN root_id = ? THEN 1 ELSE 0 END) > 0
                """,
                (r0, r1),
            ).fetchall()
        else:
            size_rows = con.execute(
                "SELECT size FROM files GROUP BY size HAVING COUNT(*) > 1"
            ).fetchall()

        sizes = [int(r["size"]) for r in size_rows]
        total_groups = len(sizes)

        t0 = time.time()
        last_emit = 0.0
        done_groups = 0
        errors = 0

        def emit(force: bool = False) -> None:
            nonlocal last_emit
            now = time.time()
            if force or (now - last_emit) >= 0.5:
                elapsed = now - t0
                eta = None
                if done_groups > 0 and total_groups > 0:
                    eta = elapsed * (total_groups - done_groups) / done_groups

                metrics_cb(
                    {
                        "phase": "Hashing",
                        "listed": None,
                        "indexed": None,
                        "skipped": None,
                        "errors": errors,
                        "skipped_placeholders": skipped_placeholders,
                        "rate_files_per_s": None,
                        "elapsed_s": elapsed,
                        "eta_s": eta,
                        "hash_done": done_groups,
                        "hash_total": total_groups,
                        "dupe_groups": len(dupes),
                        "current_file": current_file,
                        "current_size_group": current_size_group,
                        "current_in_group": current_in_group,
                        "total_in_group": total_in_group,
                    }
                )
                last_emit = now

        emit(force=True)

        for i, size in enumerate(sizes, start=1):
            if cancel_flag():
                break

            current_size_group = size
            current_file = None
            current_in_group = 0

            rows = con.execute(
                """
                SELECT path, name, size, mtime, root_id, inode, device_id, ctime, nlink, ext_hint, mime_hint
                FROM files
                WHERE size= ?
                """,
                (size,),
            ).fetchall()

            total_in_group = len(rows)

            recs = [
                FileRec(
                    path=r["path"],
                    name=r["name"],
                    size=int(r["size"]),
                    mtime=float(r["mtime"]),
                    root_id=int(r["root_id"]),
                    inode=int(r["inode"]) if r["inode"] is not None else None,
                    device_id=int(r["device_id"]) if r["device_id"] is not None else None,
                    ctime=float(r["ctime"]) if r["ctime"] is not None else None,
                    nlink=int(r["nlink"]) if r["nlink"] is not None else None,
                    ext_hint=(r["ext_hint"] or ""),
                    mime_hint=(r["mime_hint"] or ""),
                )
                for r in rows
            ]

            by_hash: dict[str, list[FileRec]] = defaultdict(list)

            for rec in recs:
                if cancel_flag():
                    break

                current_file = rec.path
                current_in_group += 1

                emit()

                is_ph, attrs = is_windows_placeholder_or_offline(rec.path)
                if is_ph:
                    skipped_placeholders += 1
                    a = f"0x{attrs:08X}" if isinstance(attrs, int) else "unknown"
                    placeholder_list.append(f"PLACEHOLDER\t{rec.path}\tattrs={a}")
                    continue

                try:
                    digest = sha256_file(rec.path, cancel_flag=cancel_flag)
                    by_hash[digest].append(rec)

                except RuntimeError as e:
                    if cancel_flag():
                        break
                    errors += 1
                    log_hash_err("HASH", rec.path, e)
                    continue

                except (PermissionError, FileNotFoundError, OSError) as e:
                    errors += 1
                    log_hash_err("HASH", rec.path, e)
                    continue

            if cancel_flag():
                break

            for digest, items in by_hash.items():
                unique_items: list[FileRec] = []
                for cand in items:
                    if any(_same_file_identity(cand, ex) for ex in unique_items):
                        continue
                    unique_items.append(cand)
                if len(unique_items) > 1:
                    dupes.append(
                        DupeGroup(
                            sha256=digest,
                            size=size,
                            files=sorted(unique_items, key=lambda x: x.path.lower()),
                        )
                    )

            done_groups = i
            emit()

        emit(force=True)

        if error_log_path and placeholder_list:
            try:
                p = error_log_path.parent / "placeholder_skips.txt"
                p.write_text("\n".join(placeholder_list) + "\n", encoding="utf-8")
            except Exception:
                pass

        return dupes

    finally:
        try:
            if err_f:
                err_f.close()
        except Exception:
            pass
        con.close()


def _same_file_identity(a: FileRec, b: FileRec) -> bool:
    return (
        a.device_id is not None
        and a.inode is not None
        and a.device_id == b.device_id
        and a.inode == b.inode
    )


def classify_confidence_tier(group: DupeGroup) -> str:
    return "Tier 1: size+hash exact duplicates"


def score_retention_candidate(rec: FileRec, keep_roots: list[str], root_priority: dict[str, int], mode: str = "newest") -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    rec_path_norm = os.path.normcase(os.path.normpath(rec.path))
    for kr in keep_roots:
        nkr = os.path.normcase(os.path.normpath(kr))
        if rec_path_norm == nkr or rec_path_norm.startswith(nkr + os.sep):
            score += 1_000_000
            reasons.append(f"protected_keep_root:{kr}")
            break
    if mode == "newest":
        score += rec.mtime
        reasons.append("newest")
    elif mode == "oldest":
        score -= rec.mtime
        reasons.append("oldest")
    elif mode == "largest":
        score += rec.size
        reasons.append("largest")
    depth = len(Path(rec.path).parts)
    score += depth * 0.01
    reasons.append(f"path_depth={depth}")
    for root, prio in root_priority.items():
        nr = os.path.normcase(os.path.normpath(root))
        if rec_path_norm == nr or rec_path_norm.startswith(nr + os.sep):
            score += prio * 1000.0
            reasons.append(f"root_priority:{root}={prio}")
            break
    return score, reasons


def build_reports(dupes: list[DupeGroup]) -> tuple[list[dict], dict[str, list[dict]]]:
    by_hash: list[dict] = []
    by_name: dict[str, list[dict]] = defaultdict(list)

    for g in dupes:
        scored = [
            (
                f,
                *score_retention_candidate(
                    f, keep_roots=[], root_priority={}, mode="newest"
                ),
            )
            for f in g.files
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        keep_path = scored[0][0].path if scored else None
        reason_by_path = {it[0].path: it[2] for it in scored}
        files = [
            {
                "path": f.path,
                "name": f.name,
                "size": f.size,
                "mtime": f.mtime,
                "root_id": int(getattr(f, "root_id", 0)),
                "inode": getattr(f, "inode", None),
                "device_id": getattr(f, "device_id", None),
                "ctime": getattr(f, "ctime", None),
                "nlink": getattr(f, "nlink", None),
                "ext_hint": getattr(f, "ext_hint", ""),
                "mime_hint": getattr(f, "mime_hint", ""),
                "decision": "keep" if f.path == keep_path else "delete_candidate",
                "decision_reasons": reason_by_path.get(f.path, []),
            }
            for f in g.files
        ]

        group = {
            "confidence_tier": classify_confidence_tier(g),
            "sha256": g.sha256,
            "size": g.size,
            "count": len(g.files),
            "names": sorted(set(f.name for f in g.files)),
            "files": files,
        }
        by_hash.append(group)

        counts_by_name = Counter([f.name for f in g.files])
        for name, c in counts_by_name.items():
            if c >= 2:
                by_name[name].append(
                    {
                        "sha256": g.sha256,
                        "size": g.size,
                        "count_in_this_name": c,
                        "total_in_hash_group": len(g.files),
                        "files_in_hash_group": files,
                    }
                )

    by_hash.sort(key=lambda x: (-x["size"], -x["count"], x["sha256"]))
    for n in list(by_name.keys()):
        by_name[n].sort(
            key=lambda x: (-x["size"], -x["total_in_hash_group"], x["sha256"])
        )

    return by_hash, dict(by_name)


def _preserve_existing(path: Path) -> None:
    """
    If `path` already exists, rename it to *.preserved_<timestamp>* before writing a new one.
    This keeps history BUT ensures the canonical filename always contains the latest scan.
    """
    if not path.exists():
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(f"{path.stem}.preserved_{ts}{path.suffix}")
    try:
        path.replace(backup)
    except Exception:
        try:
            shutil.copy2(path, backup)
        finally:
            try:
                path.unlink()
            except Exception:
                pass


def _write_json_no_clobber(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _preserve_existing(path)
    write_json_atomic(path, obj)


def _write_text_no_clobber(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text += "\n"
    _preserve_existing(path)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_jsonl_no_clobber(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _preserve_existing(path)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for obj in rows:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _write_jsonl_overwrite(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for obj in rows:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def append_jsonl_line(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(obj, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(line)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass


def append_prune_event(report_dir: Path, event: dict) -> None:
    append_jsonl_line(report_dir / "prune_events.jsonl", event)


def write_scan_reports(
    report_dir: Path, dupes: list[DupeGroup]
) -> tuple[list[dict], dict[str, list[dict]]]:
    """
    Final scan artifacts (duplicates_*) are written to canonical names, but previous versions
    are preserved as *.preserved_<timestamp>*.
    """
    safe_mkdir(report_dir)
    by_hash, by_name = build_reports(dupes)

    _write_json_no_clobber(report_dir / "duplicates_by_hash.json", by_hash)
    _write_json_no_clobber(report_dir / "duplicates_by_name.json", by_name)
    _write_jsonl_no_clobber(report_dir / "duplicates_by_hash.jsonl", by_hash)

    lines: list[str] = []
    lines.append(f"Duplicate groups (by content hash): {len(by_hash)}")
    lines.append("")
    for g in by_hash:
        lines.append(
            f"SHA256={g['sha256']}  size={format_bytes(g['size'])}  count={g['count']}  names={g['names']}"
        )
        for f in g["files"]:
            lines.append(f"    {f['path']}")
        lines.append("")

    _write_text_no_clobber(report_dir / "duplicates_summary.txt", "\n".join(lines))
    return by_hash, by_name


def write_live_reports(report_dir: Path, dupes: list[DupeGroup]) -> None:
    """
    Live artifacts (live_duplicates_*) may be overwritten freely.
    Used for crash-survival + post-prune current state.
    """
    safe_mkdir(report_dir)
    by_hash, by_name = build_reports(dupes)

    (report_dir / "live_duplicates_by_hash.json").write_text(
        json.dumps(by_hash, indent=2), encoding="utf-8"
    )
    (report_dir / "live_duplicates_by_name.json").write_text(
        json.dumps(by_name, indent=2), encoding="utf-8"
    )
    _write_jsonl_overwrite(report_dir / "live_duplicates_by_hash.jsonl", by_hash)

    lines: list[str] = []
    lines.append(f"Live duplicate groups (by content hash): {len(by_hash)}")
    lines.append("")
    for g in by_hash:
        lines.append(
            f"SHA256={g['sha256']}  size={format_bytes(g['size'])}  count={g['count']}  names={g['names']}"
        )
        for f in g["files"]:
            lines.append(f"    {f['path']}")
        lines.append("")

    (report_dir / "live_duplicates_summary.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _norm_dir_prefix(p: str) -> str:
    p2 = os.path.normcase(os.path.normpath(p))
    if re.match(r"^[A-Za-z]:$", p2):
        p2 = p2 + os.sep
    if not p2.endswith(os.sep):
        p2 += os.sep
    return p2


def _prefixes_for_file(path_str: str, max_depth: int = 6) -> list[str]:
    p = PureWindowsPath(path_str)
    dir_parts = p.parent.parts
    if not dir_parts:
        return []

    out: list[str] = []
    for depth in range(1, max_depth + 1):
        n = 1 + depth
        if n > len(dir_parts):
            break
        pref = str(PureWindowsPath(*dir_parts[:n]))
        out.append(_norm_dir_prefix(pref))

    return out


def analyze_path_prefixes(
    dupes: list[DupeGroup],
    max_depth: int = 6,
    min_group_hits: int = 25,
) -> list[dict]:
    file_hits: Counter[str] = Counter()
    group_hits: Counter[str] = Counter()
    groups_exactly_one: Counter[str] = Counter()
    groups_ambiguous: Counter[str] = Counter()

    for g in dupes:
        per_group_counts: Counter[str] = Counter()

        for f in g.files:
            prefs = _prefixes_for_file(f.path, max_depth=max_depth)
            for pref in prefs:
                file_hits[pref] += 1
                per_group_counts[pref] += 1

        for pref, c in per_group_counts.items():
            group_hits[pref] += 1
            if c == 1:
                groups_exactly_one[pref] += 1
            else:
                groups_ambiguous[pref] += 1

    rows: list[dict] = []
    for pref, gh in group_hits.items():
        if gh < min_group_hits:
            continue
        one = int(groups_exactly_one.get(pref, 0))
        amb = int(groups_ambiguous.get(pref, 0))
        fh = int(file_hits.get(pref, 0))
        rate = (one / gh) if gh else 0.0
        rows.append(
            {
                "prefix": pref,
                "file_hits": fh,
                "group_hits": int(gh),
                "groups_exactly_one": one,
                "groups_ambiguous": amb,
                "solvable_rate": rate,
            }
        )

    rows.sort(
        key=lambda r: (
            -r["groups_exactly_one"],
            -r["group_hits"],
            -r["solvable_rate"],
            r["prefix"],
        )
    )
    return rows


def write_path_suggestions(
    report_dir: Path,
    dupes: list[DupeGroup],
    max_depth: int = 6,
    min_group_hits: int = 25,
    top_n: int = 60,
) -> tuple[Path, Path]:
    safe_mkdir(report_dir)

    rows = analyze_path_prefixes(
        dupes, max_depth=max_depth, min_group_hits=min_group_hits
    )
    rows_top = rows[:top_n]

    json_path = report_dir / "path_suggestions.json"
    txt_path = report_dir / "path_suggestions.txt"

    try:
        json_path.write_text(json.dumps(rows_top, indent=2), encoding="utf-8")
    except Exception:
        pass

    lines: list[str] = []
    lines.append("Path prefix suggestions (from CURRENT remaining duplicates)")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Groups analyzed: {len(dupes):,}")
    lines.append(
        f"max_depth={max_depth}  min_group_hits={min_group_hits}  top_n={top_n}"
    )
    lines.append("")
    lines.append("Legend:")
    lines.append(
        "  group_hits         = how many dupe groups contain files under this prefix"
    )
    lines.append(
        "  exactly_one        = groups where exactly 1 file is under this prefix (auto-prune-friendly)"
    )
    lines.append(
        "  ambiguous          = groups where 2+ files are under this prefix (prefix alone can't decide)"
    )
    lines.append("  solvable_rate      = exactly_one / group_hits")
    lines.append("  file_hits          = total duplicate-file occurrences under prefix")
    lines.append("")
    lines.append("Top candidates (ranked by auto-prune potential):")
    lines.append("")

    for r in rows_top:
        lines.append(
            f"{r['prefix']}\n"
            f"  group_hits={r['group_hits']:,}  exactly_one={r['groups_exactly_one']:,}  "
            f"ambiguous={r['groups_ambiguous']:,}  solvable_rate={r['solvable_rate']:.3f}  "
            f"file_hits={r['file_hits']:,}\n"
        )

    try:
        txt_path.write_text("\n".join(lines), encoding="utf-8")
    except Exception:
        pass

    return txt_path, json_path


# ----------------------------
# Recycle Bin deletion
# ----------------------------


def windows_recycle(paths: list[str]) -> None:
    """
    Try send2trash first (if installed). Fall back to SHFileOperationW.
    """
    if not paths:
        return

    try:
        from send2trash import send2trash  # type: ignore

        for p in paths:
            send2trash(p)
        return
    except Exception:
        pass

    if os.name != "nt":
        raise RuntimeError("Recycle Bin deletion is only supported on Windows.")

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_SILENT = 0x0004

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", ctypes.c_void_p),
            ("wFunc", ctypes.c_uint),
            ("pFrom", ctypes.c_wchar_p),
            ("pTo", ctypes.c_wchar_p),
            ("fFlags", ctypes.c_ushort),
            ("fAnyOperationsAborted", ctypes.c_int),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", ctypes.c_wchar_p),
        ]

    for p in paths:
        pfrom = p + "\0\0"
        op = SHFILEOPSTRUCTW()
        op.hwnd = None
        op.wFunc = FO_DELETE
        op.pFrom = pfrom
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
        op.fAnyOperationsAborted = 0
        op.hNameMappings = None
        op.lpszProgressTitle = None

        res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if res != 0:
            raise RuntimeError(f"SHFileOperationW failed for {p} (code {res})")
        if op.fAnyOperationsAborted:
            raise RuntimeError("Recycle operation aborted.")
