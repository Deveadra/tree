from pathlib import Path

from core.ai.outcomes_tracker import (
    OutcomeLearningConfig,
    append_outcomes_history,
    build_action_outcome_record,
    summarize_case_outcomes,
    update_heuristic_weights,
    purge_expired_case_reports,
    EvidenceRetentionConfig,
)


def test_build_action_outcome_record_includes_reclaim_delta() -> None:
    row = build_action_outcome_record(
        case_id="case-1",
        action_id="a-1",
        action="recycle",
        pre_free_bytes=100,
        post_free_bytes=160,
        predicted_reclaim_bytes=40,
        recommendation_label="helpful",
        executed_at="2026-04-30T00:00:00Z",
    )
    assert row["disk_metrics"]["realized_reclaim_bytes"] == 60
    assert row["disk_metrics"]["reclaim_delta_bytes"] == 20


def test_summarize_case_outcomes_precision_and_case_delta() -> None:
    rows = [
        build_action_outcome_record(case_id="case-1", action_id="1", action="recycle", pre_free_bytes=0, post_free_bytes=20, predicted_reclaim_bytes=10, recommendation_label="helpful"),
        build_action_outcome_record(case_id="case-1", action_id="2", action="recycle", pre_free_bytes=20, post_free_bytes=30, predicted_reclaim_bytes=15, recommendation_label="neutral"),
        build_action_outcome_record(case_id="case-1", action_id="3", action="recycle", pre_free_bytes=30, post_free_bytes=20, predicted_reclaim_bytes=5, recommendation_label="misleading"),
        build_action_outcome_record(case_id="other", action_id="x", action="recycle", pre_free_bytes=0, post_free_bytes=999, predicted_reclaim_bytes=1),
    ]
    summary = summarize_case_outcomes(rows, case_id="case-1")
    assert summary["actions"] == 3
    assert summary["reclaim_delta_bytes"] == -10
    assert summary["precision"]["helpful"] == 1 / 3
    assert summary["precision"]["neutral"] == 1 / 3
    assert summary["precision"]["misleading"] == 1 / 3


def test_update_heuristic_weights_adapts_on_outcomes() -> None:
    weights = {"a": 0.5, "b": 0.2}
    rows = [
        {"recommendation_label": "helpful"},
        {"recommendation_label": "helpful"},
        {"recommendation_label": "misleading"},
    ]
    updated = update_heuristic_weights(weights, outcomes=rows, config=OutcomeLearningConfig(adaptation_rate=0.1))
    assert updated["a"] > weights["a"]
    assert updated["b"] > weights["b"]


def test_append_outcomes_history_jsonl(tmp_path: Path) -> None:
    target = tmp_path / "ai_outcomes_history.jsonl"
    append_outcomes_history(target, {"case_id": "x", "actions": 1})
    append_outcomes_history(target, {"case_id": "y", "actions": 2})
    lines = target.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert '"case_id": "x"' in lines[0]


def test_purge_expired_case_reports(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    keep = tmp_path / "keep.json"
    old.write_text("{}", encoding="utf-8")
    keep.write_text("{}", encoding="utf-8")

    import os, time
    old_ts = time.time() - (40 * 86400)
    os.utime(old, (old_ts, old_ts))

    result = purge_expired_case_reports(tmp_path, config=EvidenceRetentionConfig(keep_days=30))
    assert result["purged"] == 1
    assert not old.exists()
    assert keep.exists()
