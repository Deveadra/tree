from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from core.ai.action_catalog import build_action_step, order_steps
from core.ai.prompt_security import build_strict_prompt_template, validate_allowlisted_schema


@dataclass(frozen=True)
class RecommendationConfig:
    """Configuration for deterministic recommendation scoring."""

    root_cause_weights: dict[str, float]
    reclaim_weights: dict[str, float]
    risk_thresholds: dict[str, float]
    top_n: int = 5


DEFAULT_CONFIG = RecommendationConfig(
    root_cause_weights={
        "free_delta_severity": 0.45,
        "top_dir_impact": 0.35,
        "process_io_impact": 0.20,
    },
    reclaim_weights={
        "duplicate_reclaim_ratio": 0.5,
        "cold_data_ratio": 0.25,
        "growth_reclaim_ratio": 0.25,
    },
    risk_thresholds={"safe_max": 0.33, "caution_max": 0.66},
)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _score_weighted(components: dict[str, float], weights: dict[str, float]) -> float:
    weighted_sum = 0.0
    weight_sum = 0.0
    for key in sorted(weights):
        w = max(0.0, float(weights[key]))
        c = _clamp01(_safe_float(components.get(key, 0.0)))
        weighted_sum += c * w
        weight_sum += w
    if weight_sum == 0:
        return 0.0
    return weighted_sum / weight_sum


def _risk_tier(risk_score: float, thresholds: dict[str, float]) -> str:
    safe_max = _safe_float(thresholds.get("safe_max"), 0.33)
    caution_max = _safe_float(thresholds.get("caution_max"), 0.66)
    score = _clamp01(risk_score)
    if score <= safe_max:
        return "Safe"
    if score <= caution_max:
        return "Caution"
    return "Dangerous"


def _extract_candidates(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    # Accept explicit candidates, or build a default candidate from global evidence.
    raw = evidence.get("recommendation_candidates")
    if isinstance(raw, list) and raw:
        return [c for c in raw if isinstance(c, dict)]
    return [{"id": "global", "title": "General cleanup plan", "metrics": evidence.get("metrics", {})}]


def _default_summary(rec: dict[str, Any]) -> str:
    return (
        f"{rec.get('title', 'Recommendation')} | "
        f"root-cause {rec['root_cause_score']:.2f}, "
        f"reclaim {rec['reclaim_opportunity_score']:.2f}, "
        f"risk {rec['risk_tier']}"
    )


def build_recommendations(
    evidence: dict[str, Any],
    *,
    config: RecommendationConfig = DEFAULT_CONFIG,
    rationale_generator: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    """Build deterministic recommendation scores and optional rationale text.

    If rationale_generator is unavailable or fails, falls back to a deterministic
    non-LLM summary.
    """

    candidates = _extract_candidates(evidence)
    user_notes = ""
    try:
        notes_features = evidence.get("user_notes_context", [])
        if isinstance(notes_features, list) and notes_features:
            user_notes = str(notes_features[0].get("notes") or notes_features[0].get("context", {}).get("notes", ""))
    except Exception:
        user_notes = ""
    recommendations: list[dict[str, Any]] = []

    for idx, candidate in enumerate(candidates):
        metrics = candidate.get("metrics", {}) if isinstance(candidate.get("metrics"), dict) else {}

        root_components = {
            "free_delta_severity": _clamp01(abs(_safe_float(metrics.get("free_delta_ratio", 0.0)))),
            "top_dir_impact": _clamp01(_safe_float(metrics.get("top_dir_growth_ratio", 0.0))),
            "process_io_impact": _clamp01(_safe_float(metrics.get("process_io_ratio", 0.0))),
        }
        reclaim_components = {
            "duplicate_reclaim_ratio": _clamp01(_safe_float(metrics.get("duplicate_reclaim_ratio", 0.0))),
            "cold_data_ratio": _clamp01(_safe_float(metrics.get("cold_data_ratio", 0.0))),
            "growth_reclaim_ratio": _clamp01(_safe_float(metrics.get("growth_reclaim_ratio", 0.0))),
        }

        root_cause_score = _score_weighted(root_components, config.root_cause_weights)
        reclaim_score = _score_weighted(reclaim_components, config.reclaim_weights)
        risk_score = _clamp01(root_cause_score * 0.7 + (1.0 - reclaim_score) * 0.3)
        tier = _risk_tier(risk_score, config.risk_thresholds)

        action_step = build_action_step(str(candidate.get("id", "")))

        rec = {
            "id": candidate.get("id", f"candidate-{idx}"),
            "title": candidate.get("title", "Recommendation"),
            "root_cause_score": root_cause_score,
            "reclaim_opportunity_score": reclaim_score,
            "risk_score": risk_score,
            "risk_tier": tier,
            "score_components": {
                "root_cause": root_components,
                "reclaim_opportunity": reclaim_components,
            },
            "weights": {
                "root_cause": dict(config.root_cause_weights),
                "reclaim_opportunity": dict(config.reclaim_weights),
                "risk_blend": {"root_cause": 0.7, "inverse_reclaim": 0.3},
            },
            "thresholds": {"risk_tier": dict(config.risk_thresholds)},
            "action_steps": order_steps([action_step]) if action_step else [],
            "contains_irreversible_steps": bool(action_step and action_step.get("reversibility") == "irreversible"),
        }

        try:
            rec["strict_prompt_template"] = build_strict_prompt_template(
                evidence={"candidate": candidate, "metrics": metrics},
                user_notes=user_notes,
            )
            rec["rationale"] = rationale_generator(rec) if rationale_generator else _default_summary(rec)
            rec["rationale_mode"] = "llm" if rationale_generator else "deterministic"
        except Exception:
            rec["rationale"] = _default_summary(rec)
            rec["rationale_mode"] = "fallback_non_llm"

        recommendations.append(rec)

    ordered = sorted(
        recommendations,
        key=lambda r: (
            -r["risk_score"],
            -r["root_cause_score"],
            -r["reclaim_opportunity_score"],
            str(r["id"]),
        ),
    )

    top = ordered[: max(1, config.top_n)]

    response = {
        "recommendations": top,
        "rankings": {
            "root_cause": [r["id"] for r in sorted(ordered, key=lambda x: (-x["root_cause_score"], str(x["id"])))],
            "reclaim_opportunity": [
                r["id"] for r in sorted(ordered, key=lambda x: (-x["reclaim_opportunity_score"], str(x["id"])))
            ],
        },
        "deterministic": True,
    }
    validate_allowlisted_schema(response, allowlisted_keys={"recommendations", "rankings", "deterministic"})
    return response
