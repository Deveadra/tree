# Release checklist mapped to CI gates (A-E)

A release is considered eligible only after all gate jobs pass in CI.

## Gate A — Core scan/rule correctness
- [ ] `tests/test_collector_plugins.py` passed.
- [ ] `tests/test_path_rules.py` passed.
- [ ] `tests/test_scan_progress_and_budget.py` passed.
- [ ] `tests/test_space_audit_metrics.py` passed.
- **Pass criteria:** scan/rule and metrics behavior remains deterministic and bounded.

## Gate B — Prune plan/apply behavior
- [ ] `tests/test_prune_plan_integrity.py` passed.
- [ ] `tests/test_prune_flows_integration.py` passed.
- [ ] `tests/test_space_audit_integration_and_safety.py` passed.
- **Pass criteria:** prune planning/apply paths remain stable and safety controls stay intact.

## Gate C — Policy firewall and prompt security
- [ ] `tests/test_policy_firewall.py` passed.
- [ ] `tests/test_prompt_security.py` passed.
- [ ] `tests/test_protection_policy_engine.py` passed.
- **Release blocker:** any failure blocks release.

## Gate D — Explainability and ranking reproducibility
- [ ] `tests/test_recommendation_engine.py` passed.
- [ ] `tests/test_ai_evidence_builder.py` passed.
- [ ] `tests/test_golden_recommendations.py` passed.
- **Release blocker:** any failure blocks release.

## Gate E — Non-destructive invariants + privacy lint
- [ ] `tests/test_cli_e2e_smoke.py` passed.
- [ ] `tests/test_golden_plan_output.py` passed.
- [ ] `tests/test_privacy_lint.py` passed.
- **Release blocker:** any failure blocks release.

## Final release decision
- [ ] Confirm the `release_blocker` workflow job succeeded (depends on Gates C/D/E).
- [ ] Archive CI run URL and test summary with release notes.
