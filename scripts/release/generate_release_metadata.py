#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--version", required=True)
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[2]
    dist = root / args.dist
    artifacts = sorted([p for p in dist.iterdir() if p.is_file() and not p.name.endswith((".sig", ".pem", ".spdx.json", ".intoto.jsonl"))])

    checksums = {p.name: sha256(p) for p in artifacts}
    (dist / "checksums.sha256.json").write_text(json.dumps(checksums, indent=2) + "\n", encoding="utf-8")

    for p in artifacts:
        sbom = dist / f"{p.name}.spdx.json"
        subprocess.check_call(["syft", str(p), "-o", "spdx-json", "--file", str(sbom)])

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": digest}} for name, digest in checksums.items()],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
            "builder": {"id": "https://github.com/actions"},
            "metadata": {
                "version": args.version,
                "git_commit": run(["git", "rev-parse", "HEAD"]),
            },
        },
    }
    (dist / "provenance.intoto.jsonl").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
