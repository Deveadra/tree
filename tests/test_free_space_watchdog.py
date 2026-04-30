from pathlib import Path
from tempfile import TemporaryDirectory

from core.space_audit import sample_free_space_timeline


def test_free_space_timeline_writes_csv_and_respects_max_rows():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        result = sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=3,
        )
        lines = out_csv.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 4
        assert lines[0].startswith("timestamp,total_bytes,free_bytes,used_bytes,free_delta_bytes,spike")
        assert result["rows_written"] == 3
        assert result["mode"] == "watchdog_read_only"


def test_spike_detection_records_events():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        blocker = root / "grow.bin"
        blocker.write_bytes(b"x" * 4096)
        result = sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=2,
            free_space_drop_spike_threshold_bytes=1,
        )
        assert "spikes" in result
        assert result["spike_count"] >= 0

