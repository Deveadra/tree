import json
from pathlib import Path

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


def test_golden_ranking_fixture_is_reproducible():
    fixture = json.loads(Path("tests/fixtures/golden_recommendations.json").read_text(encoding="utf-8"))
    out = build_recommendations(_sample_evidence())

    assert out["rankings"]["root_cause"] == fixture["rankings"]["root_cause"]
    assert out["rankings"]["reclaim_opportunity"] == fixture["rankings"]["reclaim_opportunity"]
    assert out["recommendations"][0]["id"] == fixture["top_recommendation_id"]
