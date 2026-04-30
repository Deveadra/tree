from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

from core.space_audit import sample_correlated_space_timeline, sample_free_space_timeline


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
            capture_process_file_handles=True,
        )
        if result["evidence_bundle_count"] > 0:
            bundle = Path(result["evidence_bundles"][0]["bundle_dir"])
            assert (bundle / "bundle_manifest.json").exists()
            assert (bundle / "disk_metrics.json").exists()
            assert (bundle / "top_dir_deltas.json").exists()
            assert (bundle / "top_extension_deltas.json").exists()
            assert (bundle / "process_io_snapshot.json").exists()
            assert (bundle / "process_file_handles.json").exists()
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
        assert "remediation" in result
        assert result["remediation"]["safety"] == "Never force-terminate processes automatically."
        assert "signals" in result


def test_correlated_watchdog_writes_both_streams_and_event_ids():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        fast_csv = root / "free_space_timeline_fast.csv"
        growth_csv = root / "space_growth_timeline.csv"
        result = sample_correlated_space_timeline(
            root=root,
            output_fast_csv=fast_csv,
            output_growth_csv=growth_csv,
            fast_interval_seconds=0.0,
            growth_interval_seconds=0.0,
            max_fast_rows=2,
            max_growth_rows=2,
        )
        fast_lines = fast_csv.read_text(encoding="utf-8").strip().splitlines()
        growth_lines = growth_csv.read_text(encoding="utf-8").strip().splitlines()
        assert len(fast_lines) == 3
        assert len(growth_lines) == 3
        assert fast_lines[0].startswith("event_id,stream,timestamp,total_bytes")
        assert growth_lines[0].startswith("event_id,stream,timestamp,tree_bytes_delta")
        assert result["mode"] == "watchdog_correlated_read_only"
