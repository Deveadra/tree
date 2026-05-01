from pathlib import Path

from core.ai.eval_harness import (
    detect_workload_drift,
    evaluate_incident_corpus,
    load_eval_corpus,
    validate_eval_thresholds,
)


def test_eval_harness_metrics_and_thresholds() -> None:
    corpus = load_eval_corpus(Path("tests/fixtures/incident_eval_corpus.json"))
    metrics = evaluate_incident_corpus(corpus)
    assert metrics["root_cause_precision"] == 2 / 3
    assert metrics["recommendation_usefulness"] == 2 / 3
    assert metrics["false_danger_rate"] == 1 / 3
    report = validate_eval_thresholds(metrics)
    assert report["passed"] is False
    assert report["checks"]["false_danger_rate"] is False


def test_workload_drift_detection_trigger() -> None:
    baseline = {"io_ratio": 0.3, "growth_ratio": 0.2}
    current = {"io_ratio": 0.61, "growth_ratio": 0.19}
    drift = detect_workload_drift(baseline, current, threshold=0.2)
    assert drift["drift_detected"] is True
    assert drift["recommended_action"] == "retrain_or_reweight"
    assert "io_ratio" in drift["drifted_features"]
