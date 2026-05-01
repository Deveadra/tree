#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="dist")
    args = ap.parse_args()

    dist = Path(args.dist)
    manifest = json.loads((dist / "checksums.sha256.json").read_text(encoding="utf-8"))
    failures = []
    for name, expected in manifest.items():
        got = sha256(dist / name)
        if got != expected:
            failures.append((name, expected, got))

    if failures:
        for name, exp, got in failures:
            print(f"mismatch: {name} expected={exp} got={got}")
        raise SystemExit(1)
    print("checksum verification passed")


if __name__ == "__main__":
    main()
