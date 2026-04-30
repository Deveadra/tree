from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class OutcomeLearningConfig:
    adaptation_rate: float = 0.05
    enable_local_ranker: bool = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_action_outcome_record(
    *,
    case_id: str,
    action_id: str,
    action: str,
    pre_free_bytes: int,
    post_free_bytes: int,
    predicted_reclaim_bytes: int,
    recommendation_label: str | None = None,
    executed_at: str | None = None,
) -> dict[str, Any]:
    realized_reclaim = int(post_free_bytes) - int(pre_free_bytes)
    predicted = int(predicted_reclaim_bytes)
    delta = realized_reclaim - predicted
    return {
        "timestamp": executed_at or _utc_now_iso(),
        "case_id": case_id,
        "action_id": action_id,
        "action": action,
        "disk_metrics": {
            "pre_free_bytes": int(pre_free_bytes),
            "post_free_bytes": int(post_free_bytes),
            "realized_reclaim_bytes": realized_reclaim,
            "predicted_reclaim_bytes": predicted,
            "reclaim_delta_bytes": delta,
        },
        "recommendation_label": recommendation_label or "neutral",
    }


def summarize_case_outcomes(records: list[dict[str, Any]], *, case_id: str) -> dict[str, Any]:
    case_records = [r for r in records if str(r.get("case_id")) == case_id]
    action_count = len(case_records)
    realized = 0
    predicted = 0
    helpful = neutral = misleading = 0

    for row in case_records:
        dm = row.get("disk_metrics", {}) if isinstance(row.get("disk_metrics"), dict) else {}
        realized += _safe_int(dm.get("realized_reclaim_bytes", 0))
        predicted += _safe_int(dm.get("predicted_reclaim_bytes", 0))
        label = str(row.get("recommendation_label", "neutral")).lower()
        if label == "helpful":
            helpful += 1
        elif label == "misleading":
            misleading += 1
        else:
            neutral += 1

    precision = {
        "helpful": (helpful / action_count) if action_count else 0.0,
        "neutral": (neutral / action_count) if action_count else 0.0,
        "misleading": (misleading / action_count) if action_count else 0.0,
    }

    return {
        "case_id": case_id,
        "actions": action_count,
        "realized_reclaim_bytes": realized,
        "predicted_reclaim_bytes": predicted,
        "reclaim_delta_bytes": realized - predicted,
        "precision": precision,
    }


def update_heuristic_weights(
    current_weights: dict[str, float],
    *,
    outcomes: list[dict[str, Any]],
    config: OutcomeLearningConfig | None = None,
) -> dict[str, float]:
    cfg = config or OutcomeLearningConfig()
    if cfg.enable_local_ranker:
        # Placeholder path for future pluggable local model; keep deterministic fallback.
        pass

    helpful = sum(1 for row in outcomes if str(row.get("recommendation_label", "")).lower() == "helpful")
    misleading = sum(1 for row in outcomes if str(row.get("recommendation_label", "")).lower() == "misleading")
    total = max(1, len(outcomes))
    signal = (helpful - misleading) / total

    updated: dict[str, float] = {}
    for key, value in current_weights.items():
        base = max(0.0, _safe_float(value, 0.0))
        updated[key] = max(0.0, min(1.0, base + cfg.adaptation_rate * signal))

    return updated


def append_outcomes_history(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
