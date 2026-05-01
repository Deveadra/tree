from core.space_audit import attribute_growth


def test_attribute_growth_ranks_direct_writer_first():
    event = {
        "event_id": "spike-1",
        "window_start": "2026-01-01T00:00:00Z",
        "window_end": "2026-01-01T00:01:00Z",
        "directory_growth_windows": [
            {"path": "/Users/me/OneDrive/cache", "delta_bytes": 30 * 1024 * 1024, "writer": "OneDrive.exe"}
        ],
        "extension_surges": [
            {"extension": ".tmp", "delta_bytes": 5 * 1024 * 1024}
        ],
        "process_io_deltas": [
            {"process": "OneDrive.exe", "write_bytes_delta": 50 * 1024 * 1024, "direct_writer": True}
        ],
    }

    report = attribute_growth(event)
    assert report["event_id"] == "spike-1"
    assert report["suspects"][0]["name"] == "OneDrive.exe"
    assert report["suspects"][0]["observation"] == "directly_observed_writer"
    assert report["suspects"][0]["confidence_tier"] in {"high", "medium"}


def test_attribute_growth_marks_inferred_suspects():
    event = {
        "event_id": "spike-2",
        "window_start": "2026-01-01T00:00:00Z",
        "window_end": "2026-01-01T00:01:00Z",
        "directory_growth_windows": [
            {"path": "/var/cache/browser", "delta_bytes": 2 * 1024 * 1024}
        ],
        "extension_surges": [
            {"extension": ".cache", "delta_bytes": 2 * 1024 * 1024}
        ],
        "process_io_deltas": [],
    }

    report = attribute_growth(event)
    observations = {item["observation"] for item in report["suspects"]}
    assert "inferred_suspect" in observations
    assert "confidence" in report
    assert "ambiguity" in report
    assert report["ambiguity"]["what_evidence_would_disambiguate_this"]


def test_attribute_growth_adds_alternate_hypothesis_for_non_high_confidence():
    event = {
        "event_id": "spike-3",
        "window_start": "2026-01-01T00:00:00Z",
        "window_end": "2026-01-01T00:01:00Z",
        "directory_growth_windows": [
            {"path": "/tmp/cache", "delta_bytes": 2 * 1024 * 1024}
        ],
        "extension_surges": [],
        "process_io_deltas": [],
    }
    report = attribute_growth(event)
    assert any("alternate_hypotheses" in suspect for suspect in report["suspects"])


def test_attribute_growth_marks_open_handle_probable_cause_and_label():
    event = {
        "event_id": "spike-4",
        "window_start": "2026-01-01T00:00:00Z",
        "window_end": "2026-01-01T00:01:00Z",
        "directory_growth_windows": [{"path": "/var/tmp", "delta_bytes": 1024}],
        "extension_surges": [],
        "process_io_deltas": [],
        "open_handle_deltas": [{"process": "backupd", "deleted_open_handles": 4}],
    }
    report = attribute_growth(event)
    backup = next(s for s in report["suspects"] if s["name"] == "backupd")
    assert backup["observation"] == "probable_open_handle_not_released"
    assert backup["attribution"] == "inferred"
    assert backup["confidence_tier"] in {"medium", "high"}
    assert report["remediation"]["safe_steps"][-1].lower().startswith("reboot")
