from core.ai.recommendation_engine import AIExecutionConfig, build_recommendations


def _sample_evidence():
    return {
        "recommendation_candidates": [
            {
                "id": "cache-cleanup",
                "title": "Clean package cache",
                "metrics": {
                    "free_delta_ratio": 0.8,
                    "top_dir_growth_ratio": 0.7,
                    "process_io_ratio": 0.1,
                    "duplicate_reclaim_ratio": 0.4,
                    "cold_data_ratio": 0.2,
                    "growth_reclaim_ratio": 0.6,
                },
            },
            {
                "id": "archive-old-media",
                "title": "Archive old media",
                "metrics": {
                    "free_delta_ratio": 0.3,
                    "top_dir_growth_ratio": 0.4,
                    "process_io_ratio": 0.3,
                    "duplicate_reclaim_ratio": 0.8,
                    "cold_data_ratio": 0.7,
                    "growth_reclaim_ratio": 0.5,
                },
            },
        ]
    }


def test_recommendations_are_deterministic_and_ranked():
    a = build_recommendations(_sample_evidence())
    b = build_recommendations(_sample_evidence())

    assert a == b
    assert a["recommendations"][0]["id"] == "cache-cleanup"
    assert a["rankings"]["root_cause"][0] == "cache-cleanup"
    assert a["rankings"]["reclaim_opportunity"][0] == "archive-old-media"


def test_recommendation_artifacts_and_fallback_mode():
    def _boom(_):
        raise RuntimeError("llm unavailable")

    out = build_recommendations(_sample_evidence(), rationale_generator=_boom)
    rec = out["recommendations"][0]

    assert "score_components" in rec
    assert "weights" in rec
    assert "thresholds" in rec
    assert rec["rationale_mode"] == "fallback_non_llm"
    assert isinstance(rec["rationale"], str) and rec["rationale"]
    assert isinstance(rec["action_steps"], list)
    assert rec["action_steps"][0]["expected_space_recovery_range_gb"]["min"] >= 0
    assert "verification_checkpoint" in rec["action_steps"][0]
    assert "rollback_path" in rec["action_steps"][0]


def test_routing_budgets_cache_and_telemetry():
    calls = {"count": 0}

    def _rationale(rec):
        calls["count"] += 1
        return f"explain {rec['id']}"

    evidence = _sample_evidence()
    evidence["recommendation_candidates"][0]["task_type"] = "root_cause"
    evidence["recommendation_candidates"][1]["task_type"] = "reclaim_opportunity"

    execution = AIExecutionConfig(
        model_routing={"root_cause": "local", "reclaim_opportunity": "cloud"},
        token_budget_per_run=2,
        time_budget_ms=10000,
        max_analysis_window=2,
    )
    cache = {}

    first = build_recommendations(evidence, execution_config=execution, rationale_generator=_rationale, artifact_cache=cache)
    second = build_recommendations(evidence, execution_config=execution, rationale_generator=_rationale, artifact_cache=cache)

    assert first["metadata"]["execution"]["model_routing"]["root_cause"] == "local"
    assert first["metadata"]["analysis_window_applied"] == 2
    assert first["metadata"]["telemetry"]["llm_calls"] >= 1
    assert first["recommendations"][0]["analysis_evidence_hash"]
    assert first["recommendations"][0]["model_route"] in {"local", "cloud"}
    assert second["metadata"]["telemetry"]["cache_hits"] >= 1
    assert calls["count"] <= 2
