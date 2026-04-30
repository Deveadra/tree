from pathlib import Path
from tempfile import TemporaryDirectory

from core.space_audit import (
    build_replay_diff_view,
    create_replay_bookmark,
    export_incident_summary,
)


def _snapshot(tree_bytes: int, dir_rows: dict[str, int]) -> dict:
    return {
        "run": {"finished_at": "2026-01-01T00:00:00Z", "root": "/tmp"},
        "totals": {"tree_bytes": tree_bytes, "file_count": 1},
        "tree": {"dir_bytes": dir_rows},
        "extensions": {"ext_bytes": {".tmp": tree_bytes}},
    }


def test_create_bookmarks_and_replay_diff_and_export_incident():
    before = _snapshot(100, {".": 100, "cache": 40})
    after = _snapshot(260, {".": 260, "cache": 180})
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = {"event_id": "spike-1", "bundle_dir": str(root / "evidence_bundle_spike-1")}
        suspects = {
            "suspects": [{"name": "OneDrive.exe", "confidence_tier": "high"}],
            "confidence": {"tier_criteria": {"high": "x"}},
            "ambiguity": {"contradictions": [], "what_evidence_would_disambiguate_this": ["y"]},
        }
        pre = create_replay_bookmark(root, "pre-cleanup", before)
        relapse = create_replay_bookmark(root, "relapse detected", after, evidence_bundle=evidence, suspect_report=suspects)
        view = build_replay_diff_view(pre, relapse, top_n_regrowth_sources=5)
        assert view["from_bookmark"] == "pre-cleanup"
        assert view["to_bookmark"] == "relapse detected"
        assert view["top_regrowth_sources"]
        first = view["top_regrowth_sources"][0]
        assert "evidence_bundle" in first
        assert "suspect_attribution" in first

        report_path = export_incident_summary(root, view)
        assert report_path.exists()
        text = report_path.read_text(encoding="utf-8")
        assert "top_regrowth_sources" in text
        assert "\"confidence\"" in text
        assert "\"ambiguity\"" in text


def test_rejects_invalid_bookmark_label():
    with TemporaryDirectory() as tmp:
        try:
            create_replay_bookmark(Path(tmp), "random", _snapshot(1, {".": 1}))
            assert False, "expected ValueError"
        except ValueError:
            pass
