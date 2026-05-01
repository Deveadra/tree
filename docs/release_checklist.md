# Release checklist mapped to CI gates (A-F)

A release is considered eligible only after all gate jobs pass in CI.

## Gate A — Core scan/rule correctness (unit + integration + E2E)
- [ ] `tests/test_scan_progress_and_budget.py` passed.
- [ ] `tests/test_collector_plugins.py` passed.
- [ ] `tests/test_path_rules.py` passed.
- [ ] `tests/test_cli_e2e_smoke.py` passed.
- **Pass criteria:** scan/rule behavior remains deterministic and bounded.

## Gate B — Prune safety/integrity behavior (unit + integration)
- [ ] `tests/test_prune_plan_integrity.py` passed.
- [ ] `tests/test_prune_flows_integration.py` passed.
- [ ] `tests/test_space_audit_integration_and_safety.py` passed.
- **Release blocker:** any failure blocks release.

## Gate C — Policy and audit safety (unit + integration)
- [ ] `tests/test_policy_firewall.py` passed.
- [ ] `tests/test_protection_policy_engine.py` passed.
- [ ] `tests/test_space_audit_integration_and_safety.py` passed.
- **Release blocker:** any safety failure blocks release.

## Gate D — Watch monitor robustness (integration + soak + recovery)
- [ ] `tests/test_free_space_watchdog.py` passed.
- [ ] `tests/test_watchdog_soak_and_recovery.py` passed.
- **Release blocker:** any cancellation/restart recovery failure blocks release.

## Gate E — AI findings reproducibility and schema compatibility
- [ ] `tests/test_ai_evidence_builder.py` passed.
- [ ] `tests/test_recommendation_engine.py` passed.
- [ ] `tests/test_golden_recommendations.py` passed.
- [ ] `tests/test_schema_compatibility_golden.py` passed.
- **Release blocker:** any reproducibility or schema compatibility failure blocks release.

## Gate F — Safety, integrity, reproducibility gate
- [ ] Confirm CI workflow `release_blocker` failed closed on any Gate B/C/D/E failure.
- [ ] Confirm no manual bypasses were used for gate failures.
- **Release blocker:** release is blocked unless all safety, integrity, and reproducibility gates are green.

## Final release decision
- [ ] Confirm the `release_blocker` workflow job succeeded (depends on Gates B/C/D/E/F).
- [ ] Archive CI run URL and test summary with release notes.

## Gate G — Supply chain integrity and reproducible release artifacts
- [ ] Built Linux/macOS/Windows artifacts using deterministic build script.
- [ ] Generated `checksums.sha256.json` and verified with `scripts/release/verify_checksums.py`.
- [ ] Generated SBOM artifacts (`*.spdx.json`) and provenance (`provenance.intoto.jsonl`).
- [ ] Signed artifacts (`*.sig`) and published verification instructions.
- [ ] Documented secure upgrade and rollback runbook.
- **Release blocker:** any Gate G failure blocks release.
