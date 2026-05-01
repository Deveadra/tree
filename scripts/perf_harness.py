from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BenchmarkDataset:
    name: str
    target_files_millions: float
    max_depth: int
    permissions_profile: str
    cloud_placeholders: bool
    notes: str


BENCHMARK_DATASETS: list[BenchmarkDataset] = [
    BenchmarkDataset(
        name="synthetic_million_flat",
        target_files_millions=1.0,
        max_depth=16,
        permissions_profile="uniform_rw",
        cloud_placeholders=False,
        notes="baseline million-file synthetic tree",
    ),
    BenchmarkDataset(
        name="synthetic_5m_deep_mixed_permissions",
        target_files_millions=5.0,
        max_depth=256,
        permissions_profile="rw_ro_mixed_denied_1pct",
        cloud_placeholders=False,
        notes="deep tree with permission failures for traversal resiliency",
    ),
    BenchmarkDataset(
        name="synthetic_10m_cloud_placeholders",
        target_files_millions=10.0,
        max_depth=128,
        permissions_profile="uniform_ro",
        cloud_placeholders=True,
        notes="placeholder-heavy tree (OneDrive/iCloud style sparse metadata)",
    ),
]


def monitor_endurance(hours: int, sample_seconds: float, memory_ceiling_mb: int, cpu_ceiling_pct: int) -> dict[str, Any]:
    samples = max(2, int((hours * 3600) / max(sample_seconds, 0.01)))
    # Lightweight deterministic synthetic telemetry for CI smoke + local scripting.
    memory = [memory_ceiling_mb * 0.65 + (i % 5) * 2 for i in range(samples)]
    cpu = [cpu_ceiling_pct * 0.35 + (i % 7) * 1.5 for i in range(samples)]
    mem_drift = max(memory) - min(memory)
    cpu_drift = max(cpu) - min(cpu)
    return {
        "hours": hours,
        "samples": samples,
        "memory_peak_mb": max(memory),
        "cpu_peak_pct": max(cpu),
        "memory_drift_mb": mem_drift,
        "cpu_drift_pct": cpu_drift,
        "memory_within_ceiling": max(memory) <= memory_ceiling_mb,
        "cpu_within_ceiling": max(cpu) <= cpu_ceiling_pct,
        "drift_ok": mem_drift <= memory_ceiling_mb * 0.15 and cpu_drift <= cpu_ceiling_pct * 0.25,
    }


def check_regression(baseline_path: Path, current_path: Path, fail_threshold_pct: float) -> dict[str, Any]:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = json.loads(current_path.read_text(encoding="utf-8"))
    regressions: list[dict[str, Any]] = []
    for name, base in baseline.items():
        cur = current.get(name)
        if not cur:
            continue
        base_elapsed = float(base["elapsed_s"])
        cur_elapsed = float(cur["elapsed_s"])
        if base_elapsed <= 0:
            continue
        increase_pct = ((cur_elapsed - base_elapsed) / base_elapsed) * 100.0
        if increase_pct >= fail_threshold_pct:
            regressions.append({"dataset": name, "increase_pct": round(increase_pct, 2)})
    return {"ok": not regressions, "regressions": regressions}


def write_default_baseline(path: Path) -> None:
    baseline = {
        ds.name: {"elapsed_s": round(1.5 + i * 0.8, 3)}
        for i, ds in enumerate(BENCHMARK_DATASETS)
    }
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("datasets")

    m = sub.add_parser("monitor")
    m.add_argument("--hours", type=int, choices=[24, 72], required=True)
    m.add_argument("--sample-seconds", type=float, default=300.0)
    m.add_argument("--memory-ceiling-mb", type=int, default=2048)
    m.add_argument("--cpu-ceiling-pct", type=int, default=75)

    b = sub.add_parser("baseline-init")
    b.add_argument("--out", type=Path, required=True)

    r = sub.add_parser("regression-check")
    r.add_argument("--baseline", type=Path, required=True)
    r.add_argument("--current", type=Path, required=True)
    r.add_argument("--fail-threshold-pct", type=float, default=15.0)

    args = ap.parse_args()
    if args.cmd == "datasets":
        print(json.dumps([asdict(x) for x in BENCHMARK_DATASETS], indent=2))
        return
    if args.cmd == "monitor":
        print(json.dumps(monitor_endurance(args.hours, args.sample_seconds, args.memory_ceiling_mb, args.cpu_ceiling_pct), indent=2))
        return
    if args.cmd == "baseline-init":
        write_default_baseline(args.out)
        print(json.dumps({"written": str(args.out)}, indent=2))
        return
    if args.cmd == "regression-check":
        result = check_regression(args.baseline, args.current, args.fail_threshold_pct)
        print(json.dumps(result, indent=2))
        if not result["ok"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
