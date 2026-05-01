#!/usr/bin/env python3
"""Deterministic artifact builder for Linux/macOS/Windows.

Creates platform-specific tar/zip archives from tracked repository files with
stable timestamps, permissions, and ordering.
"""

from __future__ import annotations

import argparse
import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable

EPOCH = 946684800  # 2000-01-01T00:00:00Z


def tracked_files(repo_root: Path) -> list[Path]:
    output = os.popen("git -C '{}' ls-files".format(repo_root)).read().splitlines()
    return [repo_root / p for p in sorted(output)]


def normalize_mode(path: Path) -> int:
    mode = path.stat().st_mode
    if mode & stat.S_IXUSR:
        return 0o755
    return 0o644


def iter_payload(paths: Iterable[Path], repo_root: Path) -> Iterable[tuple[Path, str]]:
    for p in paths:
        if not p.is_file():
            continue
        rel = p.relative_to(repo_root).as_posix()
        yield p, f"tree/{rel}"


def build_tar(out_file: Path, paths: list[Path], repo_root: Path) -> None:
    with tarfile.open(out_file, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for src, arcname in iter_payload(paths, repo_root):
            data = src.read_bytes()
            ti = tarfile.TarInfo(name=arcname)
            ti.size = len(data)
            ti.mtime = EPOCH
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            ti.mode = normalize_mode(src)
            tf.addfile(ti, io.BytesIO(data))


def build_zip(out_file: Path, paths: list[Path], repo_root: Path) -> None:
    with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for src, arcname in iter_payload(paths, repo_root):
            info = zipfile.ZipInfo(filename=arcname, date_time=(2000, 1, 1, 0, 0, 0))
            info.external_attr = normalize_mode(src) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, src.read_bytes())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", choices=["linux", "macos", "windows"], required=True)
    ap.add_argument("--output-dir", default="dist")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[2]
    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    files = tracked_files(root)

    if args.platform in {"linux", "macos"}:
        out = out_dir / f"tree-{args.platform}.tar.gz"
        build_tar(out, files, root)
    else:
        out = out_dir / "tree-windows.zip"
        build_zip(out, files, root)
    print(out)


if __name__ == "__main__":
    main()
