from core.ai.action_catalog import build_action_step, get_catalog_entry, order_steps


def test_catalog_entry_has_required_tags():
    entry = get_catalog_entry("cache-cleanup")
    assert entry
    assert entry["reversibility"] == "reversible"
    assert entry["risk"] == "low"
    assert isinstance(entry["prerequisites"], list) and entry["prerequisites"]
    assert set(entry["typical_reclaim_range_gb"]) == {"min", "max"}


def test_irreversible_requires_confirmation_and_is_destructive_handoff():
    step = build_action_step("remove-duplicate-binaries")
    assert step
    assert step["reversibility"] == "irreversible"
    assert step["requires_confirmation_token"] is True
    assert step["confirmation_token"] == "CONFIRM:REMOVE-DUPLICATE-BINARIES"
    assert step["execution_handoff"] == "destructive"


def test_order_steps_places_irreversible_last():
    reversible = build_action_step("cache-cleanup")
    irreversible = build_action_step("remove-duplicate-binaries")
    ordered = order_steps([irreversible, reversible])
    assert ordered[0]["reversibility"] == "reversible"
    assert ordered[-1]["reversibility"] == "irreversible"
