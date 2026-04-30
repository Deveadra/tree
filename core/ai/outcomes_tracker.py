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
    min_samples_for_tuning: int = 3


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
    free_bytes_windows: dict[str, int] | None = None,
) -> dict[str, Any]:
    realized_reclaim = int(post_free_bytes) - int(pre_free_bytes)
    predicted = int(predicted_reclaim_bytes)
    delta = realized_reclaim - predicted
    windows = free_bytes_windows if isinstance(free_bytes_windows, dict) else {}
    persistence = {
        name: int(v) - int(post_free_bytes)
        for name, v in windows.items()
        if isinstance(name, str)
    }
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
            "reclaim_ratio": (realized_reclaim / predicted) if predicted > 0 else 0.0,
            "persistence_deltas_bytes": persistence,
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
    total = len(outcomes)
    if total < max(1, cfg.min_samples_for_tuning):
        return dict(current_weights)
    signal = (helpful - misleading) / total

    updated: dict[str, float] = {}
    for key, value in current_weights.items():
        base = max(0.0, _safe_float(value, 0.0))
        updated[key] = max(0.0, min(1.0, base + cfg.adaptation_rate * signal))

    return updated


def tune_rule_weights_from_history(
    current_weights: dict[str, float],
    *,
    outcomes: list[dict[str, Any]],
    config: OutcomeLearningConfig | None = None,
) -> dict[str, float]:
    cfg = config or OutcomeLearningConfig()
    by_rule: dict[str, dict[str, int]] = {}
    for row in outcomes:
        rule_id = str(row.get("rule_id", "")).strip()
        if not rule_id:
            continue
        label = str(row.get("recommendation_label", "neutral")).lower()
        stats = by_rule.setdefault(rule_id, {"total": 0, "helpful": 0, "misleading": 0})
        stats["total"] += 1
        if label == "helpful":
            stats["helpful"] += 1
        elif label == "misleading":
            stats["misleading"] += 1

    tuned = dict(current_weights)
    for rule_id, stats in by_rule.items():
        if stats["total"] < max(1, cfg.min_samples_for_tuning):
            continue
        precision = stats["helpful"] / stats["total"]
        false_lead_rate = stats["misleading"] / stats["total"]
        signal = precision - false_lead_rate
        base = max(0.0, _safe_float(tuned.get(rule_id, 0.5), 0.5))
        tuned[rule_id] = max(0.0, min(1.0, base + (cfg.adaptation_rate * signal)))
    return tuned


def build_outcome_quality_dashboard(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    if total == 0:
        return {"actions": 0, "precision": 0.0, "false_lead_rate": 0.0, "avg_reclaim_ratio": 0.0}
    helpful = misleading = 0
    reclaim_ratios: list[float] = []
    persistence_values: list[int] = []
    for row in records:
        label = str(row.get("recommendation_label", "neutral")).lower()
        if label == "helpful":
            helpful += 1
        elif label == "misleading":
            misleading += 1
        dm = row.get("disk_metrics", {}) if isinstance(row.get("disk_metrics"), dict) else {}
        reclaim_ratios.append(_safe_float(dm.get("reclaim_ratio", 0.0)))
        for v in (dm.get("persistence_deltas_bytes") or {}).values():
            persistence_values.append(_safe_int(v, 0))
    return {
        "actions": total,
        "precision": helpful / total,
        "false_lead_rate": misleading / total,
        "avg_reclaim_ratio": sum(reclaim_ratios) / max(1, len(reclaim_ratios)),
        "avg_persistence_delta_bytes": (sum(persistence_values) / len(persistence_values)) if persistence_values else 0.0,
    }


def append_outcomes_history(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


@dataclass
class EvidenceRetentionConfig:
    keep_days: int = 30
    enabled: bool = True


def purge_expired_case_reports(base_dir: Path, *, now: datetime | None = None, config: EvidenceRetentionConfig | None = None) -> dict[str, Any]:
    cfg = config or EvidenceRetentionConfig()
    ref = now or datetime.now(timezone.utc)
    purged = 0
    skipped = 0
    if not cfg.enabled:
        return {"purged": 0, "skipped": 0, "enabled": False}
    for path in base_dir.rglob("*.json"):
        age_days = (ref - datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)).days
        if age_days > cfg.keep_days:
            path.unlink(missing_ok=True)
            purged += 1
        else:
            skipped += 1
    return {"purged": purged, "skipped": skipped, "enabled": True, "keep_days": cfg.keep_days}
