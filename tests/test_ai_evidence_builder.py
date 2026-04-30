from pathlib import Path

import pytest

from core.ai.evidence_builder import build_normalized_evidence, persist_normalized_evidence
from core.ai.evidence_schema import validate_evidence_schema


def test_build_and_persist_evidence(tmp_path: Path):
    evidence = build_normalized_evidence(
        run_id="run-1",
        event_id="event-1",
        disk_metrics_payload={"timestamp": "2026-01-01T00:00:00+00:00", "free_delta_bytes": -1, "free_bytes": 10, "used_bytes": 20},
        top_dir_payload={"rows": [{"dir": "/tmp", "delta_bytes": 10}]},
        top_ext_payload={"rows": [{"extension": ".log", "delta_bytes": 10}]},
        process_io_payload={"enabled": False},
        process_handles_payload={"enabled": False},
        plugin_payload={"disabled": True},
        policy_context_payload={"protected_prefixes": []},
        user_notes="note",
        user_context={"case_id": "case-1"},
    )
    out = persist_normalized_evidence(tmp_path, evidence)
    assert out.name == "ai_evidence.json"
    assert out.exists()


def test_schema_rejects_missing_provenance():
    with pytest.raises(ValueError):
        validate_evidence_schema(
            {
                "schema_version": "1.0",
                "space_audit_snapshot_features": [{}],
                "monitor_timeline_features": [],
                "protection_policy_state": [],
                "user_notes_context": [],
            }
        )
