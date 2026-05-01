import json
from pathlib import Path

from core.ai.evidence_builder import build_normalized_evidence
from core.space_audit import diff_space_snapshots, scan_space_usage, summarize_by_extension, summarize_top_dirs, write_space_reports


def test_space_audit_outputs_match_golden_schema_fixture(tmp_path: Path):
    root = tmp_path / "root"
    out = tmp_path / "out"
    root.mkdir()
    (root / "sample.txt").write_text("abc", encoding="utf-8")

    golden = json.loads((Path(__file__).parent / "fixtures" / "golden_space_audit_schema.json").read_text(encoding="utf-8"))
    snapshot = scan_space_usage(root, excludes=[])
    top_dirs = summarize_top_dirs(snapshot)
    by_ext = summarize_by_extension(snapshot)
    diff = diff_space_snapshots(snapshot, snapshot)
    paths = write_space_reports(out, snapshot, top_dirs, by_ext, diff=diff, timeline_row={"ts": "now"})

    for artifact, expected_fields in golden["required_keys"].items():
        payload = json.loads(Path(paths[artifact]).read_text(encoding="utf-8"))
        for field in expected_fields:
            assert field in payload


def test_ai_findings_evidence_matches_golden_schema_fixture():
    golden = json.loads((Path(__file__).parent / "fixtures" / "golden_ai_findings_schema.json").read_text(encoding="utf-8"))
    evidence = build_normalized_evidence(
        run_id="run-golden",
        event_id="event-golden",
        disk_metrics_payload={"timestamp": "2026-01-01T00:00:00+00:00"},
        top_dir_payload={"rows": []},
        top_ext_payload={"rows": []},
        process_io_payload={},
        process_handles_payload={},
        plugin_payload={},
        policy_context_payload={},
    )

    for key in golden["required_top_level_keys"]:
        assert key in evidence
    for tier in golden["required_export_tiers"]:
        assert tier in evidence["export_tiers"]
