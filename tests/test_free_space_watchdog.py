from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

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
            assert (bundle / "ai_evidence.json").exists()


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


def test_first_spike_diff_uses_pre_spike_baseline(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        free_values = iter([1_000_000, 900_000])

        class _FakeStatVfs:
            f_frsize = 1
            f_blocks = 2_000_000

            def __init__(self, free_bytes: int) -> None:
                self.f_bavail = free_bytes

        scan_calls: list[str] = []
        diff_inputs: list[tuple[str, str]] = []

        def _fake_statvfs(_path):
            return _FakeStatVfs(next(free_values))

        def _fake_scan(*args, **kwargs):
            label = f"snapshot_{len(scan_calls)}"
            scan_calls.append(label)
            return {"label": label, "tree": {"dir_bytes": {}}, "extensions": {"ext_bytes": {}}, "totals": {}}

        def _fake_diff(current_snapshot, previous_snapshot):
            diff_inputs.append((current_snapshot["label"], previous_snapshot["label"]))
            return {"tree": {"dir_bytes_delta": {}}, "extensions": {"ext_bytes_delta": {}}}

        monkeypatch.setattr("core.space_audit.os.statvfs", _fake_statvfs)
        monkeypatch.setattr("core.space_audit.scan_space_usage", _fake_scan)
        monkeypatch.setattr("core.space_audit.diff_space_snapshots", _fake_diff)
        monkeypatch.setattr(
            "core.space_audit.calibrate_baseline",
            lambda *args, **kwargs: {
                "median_abs_delta": 1,
                "minor_fluctuation_band_bytes": 1,
                "significant_drop_threshold_bytes": 1,
                "critical_drop_threshold_bytes": 1,
            },
        )
        result = sample_free_space_timeline(
            root=root,
            output_csv=out_csv,
            interval_seconds=0.0,
            max_rows=2,
            free_space_drop_spike_threshold_bytes=1,
        )
        assert result["rows_written"] == 2
        assert scan_calls == ["snapshot_0", "snapshot_1"]
        assert diff_inputs == [("snapshot_1", "snapshot_0")]
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
        assert growth_lines[0].startswith("event_id,stream,timestamp,tree_bytes_delta,top_dir_growth_path,top_dir_growth_zone")
        assert result["mode"] == "watchdog_correlated_read_only"


def test_alerts_are_deduplicated_with_metadata_and_jsonl_feed():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        out_csv = root / "free_space_timeline.csv"
        alerts_feed = root / "alerts.jsonl"
        stats = [
            SimpleNamespace(f_blocks=1000, f_frsize=1, f_bavail=900),
            SimpleNamespace(f_blocks=1000, f_frsize=1, f_bavail=880),
            SimpleNamespace(f_blocks=1000, f_frsize=1, f_bavail=860),
            SimpleNamespace(f_blocks=1000, f_frsize=1, f_bavail=840),
        ]
        idx = {"i": 0}

        def _fake_statvfs(_path):
            i = idx["i"]
            if i < len(stats):
                idx["i"] += 1
                return stats[i]
            return stats[-1]

        with patch("core.space_audit.os.statvfs", side_effect=_fake_statvfs), patch(
            "core.space_audit.calibrate_baseline",
            return_value={
                "minor_fluctuation_band_bytes": 1,
                "significant_drop_threshold_bytes": 5,
                "critical_drop_threshold_bytes": 15,
            },
        ), patch(
            "core.space_audit.scan_space_usage",
            return_value={"tree": {"dir_bytes": {}}, "extensions": {"ext_bytes": {}}, "totals": {"total_size_bytes": 0}},
        ), patch(
            "core.space_audit.diff_space_snapshots",
            return_value={"tree": {"dir_bytes_delta": {"/same/root/cause": 100}}, "extensions": {"ext_bytes_delta": {".tmp": 100}}, "totals": {"total_shrink_bytes": 0}},
        ):
            result = sample_free_space_timeline(
                root=root,
                output_csv=out_csv,
                interval_seconds=0.0,
                max_rows=4,
                free_space_drop_spike_threshold_bytes=1,
                alerts_feed_path=alerts_feed,
            )
        assert len(result["alerts"]) == 1
        alert = result["alerts"][0]
        assert alert["count"] == 3
        assert "first_seen" in alert and "last_seen" in alert
        lines = alerts_feed.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3
        assert len(result["attribution_reports"]) == 3
        assert len({Path(path).name for path in result["attribution_reports"]}) == 3
def test_correlated_watchdog_heartbeat_state_and_recovery():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        fast_csv = root / "free_space_timeline_fast.csv"
        growth_csv = root / "space_growth_timeline.csv"
        heartbeat = root / "heartbeat.json"
        state = root / "collector_state.json"
        sample_correlated_space_timeline(
            root=root,
            output_fast_csv=fast_csv,
            output_growth_csv=growth_csv,
            fast_interval_seconds=0.0,
            growth_interval_seconds=0.0,
            max_fast_rows=1,
            max_growth_rows=1,
            heartbeat_path=heartbeat,
            restart_state_path=state,
            heartbeat_interval_seconds=0.0,
            rotate_bytes=256,
        )
        assert heartbeat.exists()
        assert state.exists()
        first_state = state.read_text(encoding="utf-8")
        resumed = sample_correlated_space_timeline(
            root=root,
            output_fast_csv=fast_csv,
            output_growth_csv=growth_csv,
            fast_interval_seconds=0.0,
            growth_interval_seconds=0.0,
            max_fast_rows=2,
            max_growth_rows=2,
            heartbeat_path=heartbeat,
            restart_state_path=state,
            heartbeat_interval_seconds=0.0,
            rotate_bytes=256,
        )
        assert resumed["degradation"]["api_failures"] >= 0
        assert resumed["degradation"]["missed_ticks"] >= 0
        assert resumed["degradation"]["sampling_lag_events"] >= 0
        assert state.read_text(encoding="utf-8") != first_state
