from pathlib import Path
from threading import Event

from core.space_audit import sample_correlated_space_timeline, sample_free_space_timeline


def test_long_run_watchdog_soak_generates_stable_rows(tmp_path: Path):
    out_csv = tmp_path / "free_space_timeline.csv"
    result = sample_free_space_timeline(
        root=tmp_path,
        output_csv=out_csv,
        interval_seconds=0.0,
        max_rows=50,
        free_space_drop_spike_threshold_bytes=1,
    )
    lines = out_csv.read_text(encoding="utf-8").strip().splitlines()
    assert result["rows_written"] == 50
    assert len(lines) == 51
    assert result["mode"] == "watchdog_read_only"


def test_watchdog_cancel_then_restart_recovers_cleanly(tmp_path: Path):
    out_csv = tmp_path / "free_space_timeline.csv"
    cancel = Event()
    cancel.set()
    cancelled = sample_free_space_timeline(
        root=tmp_path,
        output_csv=out_csv,
        interval_seconds=0.0,
        max_rows=10,
        cancel_flag=cancel,
    )
    assert cancelled["cancelled"] is True
    assert cancelled["rows_written"] == 0

    restarted = sample_free_space_timeline(
        root=tmp_path,
        output_csv=out_csv,
        interval_seconds=0.0,
        max_rows=5,
    )
    assert restarted["cancelled"] is False
    assert restarted["rows_written"] == 5


def test_correlated_watchdog_restart_after_cancel(tmp_path: Path):
    fast_csv = tmp_path / "free_space_timeline_fast.csv"
    growth_csv = tmp_path / "space_growth_timeline.csv"
    cancel = Event()
    cancel.set()

    cancelled = sample_correlated_space_timeline(
        root=tmp_path,
        output_fast_csv=fast_csv,
        output_growth_csv=growth_csv,
        fast_interval_seconds=0.0,
        growth_interval_seconds=0.0,
        max_fast_rows=10,
        max_growth_rows=10,
        cancel_flag=cancel,
    )
    assert cancelled["cancelled"] is True

    recovered = sample_correlated_space_timeline(
        root=tmp_path,
        output_fast_csv=fast_csv,
        output_growth_csv=growth_csv,
        fast_interval_seconds=0.0,
        growth_interval_seconds=0.0,
        max_fast_rows=3,
        max_growth_rows=3,
    )
    assert recovered["cancelled"] is False
    assert recovered["fast_rows_written"] == 3
    assert recovered["growth_rows_written"] == 3
