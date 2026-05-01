from __future__ import annotations

import json
from pathlib import Path

from scripts.perf_harness import BENCHMARK_DATASETS, check_regression, monitor_endurance


def test_benchmark_datasets_cover_scale_and_complexity():
    assert any(ds.target_files_millions >= 1.0 for ds in BENCHMARK_DATASETS)
    assert any(ds.max_depth >= 128 for ds in BENCHMARK_DATASETS)
    assert any(ds.cloud_placeholders for ds in BENCHMARK_DATASETS)
    assert any("mixed" in ds.permissions_profile for ds in BENCHMARK_DATASETS)


def test_endurance_monitor_24h_72h_and_drift():
    r24 = monitor_endurance(24, 3600, 2048, 80)
    r72 = monitor_endurance(72, 3600, 2048, 80)
    assert r24["hours"] == 24
    assert r72["hours"] == 72
    assert r24["memory_within_ceiling"] is True
    assert r72["cpu_within_ceiling"] is True
    assert r24["drift_ok"] is True


def test_regression_checker_flags_degradation(tmp_path: Path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps({"a": {"elapsed_s": 10.0}}), encoding="utf-8")
    current.write_text(json.dumps({"a": {"elapsed_s": 13.0}}), encoding="utf-8")
    ok = check_regression(baseline, current, 40.0)
    fail = check_regression(baseline, current, 20.0)
    assert ok["ok"] is True
    assert fail["ok"] is False
    assert fail["regressions"][0]["dataset"] == "a"
