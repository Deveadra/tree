from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

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


def test_spike_creates_evidence_bundle_and_manifest():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        result = sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=2,
            free_space_drop_spike_threshold_bytes=1,
            capture_active_process_io=True,
            retention_max_bundles=5,
            retention_max_disk_bytes=10_000_000,
        )
        if result["evidence_bundle_count"] > 0:
            bundle = Path(result["evidence_bundles"][0]["bundle_dir"])
            assert (bundle / "bundle_manifest.json").exists()
            assert (bundle / "disk_metrics.json").exists()
            assert (bundle / "top_dir_deltas.json").exists()
            assert (bundle / "top_extension_deltas.json").exists()
            assert (bundle / "process_io_snapshot.json").exists()
            assert (bundle / "policy_context.json").exists()


def test_bundle_retention_max_bundles_prunes_oldest():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=4,
            free_space_drop_spike_threshold_bytes=1,
            retention_max_bundles=1,
        )
        bundles = [p for p in root.glob("evidence_bundle_*") if p.is_dir()]
        assert len(bundles) <= 1


def test_watchdog_respects_cancellation_and_schema_shape():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        cancel = Event()
        cancel.set()
        result = sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=10,
            cancel_flag=cancel,
        )
        assert result["cancelled"] is True
        assert result["rows_written"] == 0
        lines = out_csv.read_text(encoding="utf-8").strip().splitlines()
        assert lines == ["timestamp,total_bytes,free_bytes,used_bytes,free_delta_bytes,spike"]
        assert result["mode"] == "watchdog_read_only"


def test_watchdog_cancellation_skips_snapshot_scan(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        cancel = Event()
        cancel.set()

        def _raise_if_called(*args, **kwargs):
            raise AssertionError("scan_space_usage should not run for pre-cancelled watchdog runs")

        monkeypatch.setattr("core.space_audit.scan_space_usage", _raise_if_called)
        result = sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=10,
            cancel_flag=cancel,
        )
        assert result["cancelled"] is True
        assert result["rows_written"] == 0
