from core.ai.recommendation_engine import build_recommendations


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
