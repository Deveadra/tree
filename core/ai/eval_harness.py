from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class EvalThresholds:
    min_root_cause_precision: float = 0.70
    min_recommendation_usefulness: float = 0.70
    max_false_danger_rate: float = 0.10
    max_confidence_calibration_error: float = 0.20


def evaluate_incident_corpus(cases: list[dict[str, Any]]) -> dict[str, float]:
    total = len(cases)
    if total == 0:
        return {
            "root_cause_precision": 0.0,
            "recommendation_usefulness": 0.0,
            "false_danger_rate": 0.0,
            "confidence_calibration_error": 0.0,
            "coverage": 0.0,
        }

    correct_root = useful = false_danger = 0
    calibration_errors: list[float] = []
    for case in cases:
        expected = case.get("expected", {}) if isinstance(case.get("expected"), dict) else {}
        predicted = case.get("predicted", {}) if isinstance(case.get("predicted"), dict) else {}

        if str(expected.get("root_cause_id", "")) == str(predicted.get("root_cause_id", "")):
            correct_root += 1

        if bool(predicted.get("useful", False)):
            useful += 1

        if str(expected.get("risk_tier", "")) != "Dangerous" and str(predicted.get("risk_tier", "")) == "Dangerous":
            false_danger += 1

        confidence = _safe_float(predicted.get("confidence", 0.0))
        correctness = 1.0 if str(expected.get("root_cause_id", "")) == str(predicted.get("root_cause_id", "")) else 0.0
        calibration_errors.append(abs(confidence - correctness))

    return {
        "root_cause_precision": correct_root / total,
        "recommendation_usefulness": useful / total,
        "false_danger_rate": false_danger / total,
        "confidence_calibration_error": sum(calibration_errors) / len(calibration_errors),
        "coverage": 1.0,
    }


def validate_eval_thresholds(metrics: dict[str, float], thresholds: EvalThresholds = EvalThresholds()) -> dict[str, Any]:
    checks = {
        "root_cause_precision": metrics.get("root_cause_precision", 0.0) >= thresholds.min_root_cause_precision,
        "recommendation_usefulness": metrics.get("recommendation_usefulness", 0.0) >= thresholds.min_recommendation_usefulness,
        "false_danger_rate": metrics.get("false_danger_rate", 1.0) <= thresholds.max_false_danger_rate,
        "confidence_calibration_error": metrics.get("confidence_calibration_error", 1.0) <= thresholds.max_confidence_calibration_error,
    }
    return {"passed": all(checks.values()), "checks": checks, "metrics": metrics}


def load_eval_corpus(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def detect_workload_drift(baseline: dict[str, float], current: dict[str, float], *, threshold: float = 0.20) -> dict[str, Any]:
    deltas: dict[str, float] = {}
    drifted: list[str] = []
    for key, base in baseline.items():
        b = _safe_float(base)
        c = _safe_float(current.get(key, base))
        delta = abs(c - b)
        deltas[key] = delta
        if delta > threshold:
            drifted.append(key)
    return {
        "drift_detected": bool(drifted),
        "drifted_features": sorted(drifted),
        "deltas": deltas,
        "recommended_action": "retrain_or_reweight" if drifted else "none",
    }
