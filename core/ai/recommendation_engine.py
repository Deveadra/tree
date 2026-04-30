from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from core.ai.action_catalog import build_action_step, order_steps
from core.ai.prompt_security import build_strict_prompt_template, sanitize_untrusted_text, validate_allowlisted_schema
from core.ai.policy_firewall import validate_action_candidate
from config.protection_loader import resolve_protection_config


@dataclass(frozen=True)
class RecommendationConfig:
    """Configuration for deterministic recommendation scoring."""

    root_cause_weights: dict[str, float]
    reclaim_weights: dict[str, float]
    risk_thresholds: dict[str, float]
    top_n: int = 5


@dataclass(frozen=True)
class AIExecutionConfig:
    model_routing: dict[str, str]
    token_budget_per_run: int = 4000
    time_budget_ms: int = 3000
    max_analysis_window: int = 3


@dataclass
class _RunTelemetry:
    tokens_used: int = 0
    estimated_cost_usd: float = 0.0
    llm_calls: int = 0
    cache_hits: int = 0
    fallback_count: int = 0


DEFAULT_CONFIG = RecommendationConfig(
    root_cause_weights={
        "free_delta_severity": 0.45,
        "top_dir_impact": 0.35,
        "process_io_impact": 0.15,
        "io_growth_correlation": 0.05,
    },
    reclaim_weights={
        "duplicate_reclaim_ratio": 0.5,
        "cold_data_ratio": 0.25,
        "growth_reclaim_ratio": 0.25,
    },
    risk_thresholds={"safe_max": 0.33, "caution_max": 0.66},
)

DEFAULT_EXECUTION_CONFIG = AIExecutionConfig(
    model_routing={
        "root_cause": "local",
        "reclaim_opportunity": "hybrid",
        "risk_assessment": "cloud",
    }
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


def _correlated_io_growth_score(metrics: dict[str, Any]) -> float:
    io_ratio = _clamp01(_safe_float(metrics.get("process_io_ratio", 0.0)))
    growth_ratio = _clamp01(_safe_float(metrics.get("top_dir_growth_ratio", 0.0)))
    windows = metrics.get("growth_windows", {}) if isinstance(metrics.get("growth_windows"), dict) else {}
    window_strength = 0.0
    if windows:
        values = [_clamp01(_safe_float(v, 0.0)) for v in windows.values()]
        window_strength = sum(values) / len(values)
    return _clamp01((io_ratio * 0.45) + (growth_ratio * 0.45) + (window_strength * 0.10))


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


def _confidence_from_scores(root_cause_score: float, reclaim_score: float, risk_score: float) -> float:
    spread = abs(root_cause_score - reclaim_score)
    return _clamp01((root_cause_score * 0.5) + (reclaim_score * 0.3) + ((1.0 - spread) * 0.2) + (risk_score * 0.1))


def _evidence_hash(evidence: dict[str, Any]) -> str:
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _offline_summary(rec: dict[str, Any], route: str) -> str:
    return (
        f"[{route}] {rec.get('title', 'Recommendation')} | "
        f"risk={rec['risk_tier']} ({rec['risk_score']:.2f}) | "
        f"reclaim={rec['reclaim_opportunity_score']:.2f}"
    )


def _sanitize_evidence_link(value: Any) -> str | None:
    text = sanitize_untrusted_text(str(value) if value is not None else "").strip()
    if not text:
        return None
    if not (text.startswith("http://") or text.startswith("https://")):
        return None
    return text[:500]


def _build_explanation_payload(candidate: dict[str, Any], rec: dict[str, Any]) -> dict[str, Any]:
    raw_links = candidate.get("evidence_links")
    links: list[str] = []
    if isinstance(raw_links, list):
        for link in raw_links:
            sanitized = _sanitize_evidence_link(link)
            if sanitized:
                links.append(sanitized)

    alternate = candidate.get("alternate_hypotheses")
    alt_list = [sanitize_untrusted_text(str(h))[:300] for h in alternate] if isinstance(alternate, list) else []

    return {
        "summary": _default_summary(rec),
        "feature_evidence_links": links,
        "alternate_hypotheses": alt_list,
    }


def _build_approval_workflow(action_steps: list[dict[str, Any]]) -> dict[str, Any]:
    irreversible_tokens = [s.get("confirmation_token") for s in action_steps if s.get("requires_confirmation_token")]
    return {
        "state": "draft",
        "allowed_states": ["draft", "pending_approval", "approved", "handoff_blocked", "handoff_ready", "completed"],
        "requires_explicit_confirmation_before_handoff": True,
        "required_confirmation_tokens": [t for t in irreversible_tokens if isinstance(t, str) and t],
    }


def build_recommendations(
    evidence: dict[str, Any],
    *,
    config: RecommendationConfig = DEFAULT_CONFIG,
    execution_config: AIExecutionConfig = DEFAULT_EXECUTION_CONFIG,
    artifact_cache: dict[str, dict[str, Any]] | None = None,
    rationale_generator: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    """Build deterministic recommendation scores and optional rationale text.

    If rationale_generator is unavailable or fails, falls back to a deterministic
    non-LLM summary.
    """

    run_started = time.perf_counter()
    candidates = _extract_candidates(evidence)[: max(1, execution_config.max_analysis_window)]
    recommendations: list[dict[str, Any]] = []
    cache = artifact_cache if artifact_cache is not None else {}
    telemetry = _RunTelemetry()
    policy_cfg = resolve_protection_config()
    safe_roots = [Path(p) for p in policy_cfg.safe_delete_roots]

    for idx, candidate in enumerate(candidates):
        metrics = candidate.get("metrics", {}) if isinstance(candidate.get("metrics"), dict) else {}

        root_components = {
            "free_delta_severity": _clamp01(abs(_safe_float(metrics.get("free_delta_ratio", 0.0)))),
            "top_dir_impact": _clamp01(_safe_float(metrics.get("top_dir_growth_ratio", 0.0))),
            "process_io_impact": _clamp01(_safe_float(metrics.get("process_io_ratio", 0.0))),
            "io_growth_correlation": _correlated_io_growth_score(metrics),
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

        redaction_policy = evidence.get("redaction_policy", {}) if isinstance(evidence.get("redaction_policy"), dict) else {}
        rec = {
            "id": candidate.get("id", f"candidate-{idx}"),
            "title": candidate.get("title", "Recommendation"),
            "root_cause_score": root_cause_score,
            "reclaim_opportunity_score": reclaim_score,
            "risk_score": risk_score,
            "risk_tier": tier,
            "confidence_score": _confidence_from_scores(root_cause_score, reclaim_score, risk_score),
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
            "redaction_impact": {
                "summary": "Sensitive identifiers may be hidden in share-safe export.",
                "hidden_fields": [k for k in ("usernames", "hostnames", "process_args", "path_segments") if k in redaction_policy],
                "policy": dict(redaction_policy),
            },
        }

        rec["explanation_payload"] = _build_explanation_payload(candidate, rec)
        rec["action_plan"] = {
            "schema_version": "1.0",
            "guardrails": {
                "requires_precheck": True,
                "rollback_steps_required": True,
                "expected_gain_range_required": True,
            },
            "steps": rec["action_steps"],
        }
        rec["approval_workflow"] = _build_approval_workflow(rec["action_steps"])
        rec["handoff_ready"] = rec["approval_workflow"]["state"] == "handoff_ready"

        route = execution_config.model_routing.get(str(candidate.get("task_type", "risk_assessment")), "local")
        rec["model_route"] = route

        proposed_action = candidate.get("proposed_action") if isinstance(candidate.get("proposed_action"), dict) else None
        if proposed_action:
            violations = validate_action_candidate(
                proposed_action,
                policy=policy_cfg,
                enforce_safe_delete_roots=policy_cfg.enforce_safe_delete_roots,
                safe_delete_roots=safe_roots,
            )
            rec["protection_policy_validation"] = {
                "ok": len(violations) == 0,
                "violations": [v.to_dict() for v in violations],
            }
            if violations:
                rec["action_steps"] = []
                rec["contains_irreversible_steps"] = False
                rec["risk_tier"] = "Dangerous"
        else:
            rec["protection_policy_validation"] = {
                "ok": True,
                "violations": [],
            }

        evidence_key = _evidence_hash(
            {
                "candidate": candidate,
                "route": route,
                "weights": rec["weights"],
                "thresholds": rec["thresholds"],
            }
        )
        rec["analysis_evidence_hash"] = evidence_key
        if evidence_key in cache:
            cached = cache[evidence_key]
            rec["rationale"] = cached["rationale"]
            rec["rationale_mode"] = cached["rationale_mode"]
            telemetry.cache_hits += 1
            recommendations.append(rec)
            continue

        elapsed_ms = int((time.perf_counter() - run_started) * 1000)
        budget_exceeded = telemetry.tokens_used >= execution_config.token_budget_per_run or elapsed_ms >= execution_config.time_budget_ms

        try:
            if rationale_generator and not budget_exceeded:
                rec["rationale"] = rationale_generator(rec)
                rec["rationale_mode"] = "llm"
                telemetry.llm_calls += 1
                token_estimate = max(1, len(rec["rationale"].split()))
                telemetry.tokens_used += token_estimate
                telemetry.estimated_cost_usd += token_estimate * 0.000002
            else:
                rec["rationale"] = _default_summary(rec)
                rec["rationale_mode"] = "deterministic"
        except Exception:
            rec["rationale"] = _offline_summary(rec, route)
            rec["rationale_mode"] = "fallback_non_llm"
            telemetry.fallback_count += 1

        if budget_exceeded and rec["rationale_mode"] != "fallback_non_llm":
            rec["rationale"] = _offline_summary(rec, route)
            rec["rationale_mode"] = "budget_offline_fallback"
            telemetry.fallback_count += 1

        cache[evidence_key] = {
            "rationale": rec["rationale"],
            "rationale_mode": rec["rationale_mode"],
        }

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
        "metadata": {
            "analysis_window_applied": len(candidates),
            "execution": {
                "token_budget_per_run": execution_config.token_budget_per_run,
                "time_budget_ms": execution_config.time_budget_ms,
                "max_analysis_window": execution_config.max_analysis_window,
                "model_routing": dict(execution_config.model_routing),
            },
            "telemetry": {
                "tokens_used": telemetry.tokens_used,
                "estimated_cost_usd": round(telemetry.estimated_cost_usd, 8),
                "llm_calls": telemetry.llm_calls,
                "cache_hits": telemetry.cache_hits,
                "fallback_count": telemetry.fallback_count,
                "elapsed_ms": int((time.perf_counter() - run_started) * 1000),
            },
        },
    }
    validate_allowlisted_schema(response, allowlisted_keys={"recommendations", "rankings", "deterministic", "metadata"})
    return response
