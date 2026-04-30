from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dupe_core import _db_create_schema, _scan_root_append_to_con


def build_tree(root: Path, dirs: int, files_per_dir: int, file_size: int) -> None:
    payload = (b"x" * file_size) if file_size > 0 else b""
    for d in range(dirs):
        cur = root / f"d{d:04d}"
        cur.mkdir(parents=True, exist_ok=True)
        for f in range(files_per_dir):
            (cur / f"f{f:04d}.bin").write_bytes(payload)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", type=int, default=200)
    ap.add_argument("--files-per-dir", type=int, default=200)
    ap.add_argument("--file-size", type=int, default=256)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "tree"
        root.mkdir()
        build_tree(root, args.dirs, args.files_per_dir, args.file_size)
        con = sqlite3.connect(":memory:")
        _db_create_schema(con)
        t0 = time.time()
        stats = _scan_root_append_to_con(
            con=con,
            root=root,
            root_id=0,
            exclude_names=set(),
            exclude_prefixes=[],
            follow_symlinks=False,
            min_size=0,
            cancel_flag=lambda: False,
            metrics_cb=lambda _: None,
        )
        elapsed = time.time() - t0
        print({"elapsed_s": elapsed, **stats})


if __name__ == "__main__":
    main()
