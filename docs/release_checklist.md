# Release checklist and CI gate policy

## Release tiers with explicit pass criteria

### Tier 1: `internal-beta`
- Purpose: fast internal validation with engineering-only distribution.
- Required CI gates:
  - Safety invariants gate: **pass**.
  - Schema compatibility gate: **pass**.
- Optional for this tier:
  - Soak tests and full E2E flow gates may run asynchronously.
- Flake policy:
  - Maximum tolerated flakiness: **<= 2%** observed over the last 20 relevant CI runs.
- Artifact policy:
  - Test reports and logs for all executed gates must be retained for at least 30 days.

### Tier 2: `internal-stable`
- Purpose: broad internal rollout / dogfooding.
- Required CI gates:
  - Safety invariants gate: **pass**.
  - Schema compatibility gate: **pass**.
  - Soak tests gate: **pass**.
  - E2E flow gate: **pass**.
- Flake policy:
  - Maximum tolerated flakiness: **<= 1%** observed over the last 30 relevant CI runs.
- Artifact policy:
  - Test reports and logs for all release-candidate gates must be retained for at least 30 days.

### Tier 3: `external-stable`
- Purpose: customer-facing release.
- Required CI gates:
  - Safety invariants gate: **pass**.
  - Schema compatibility gate: **pass**.
  - Soak tests gate: **pass**.
  - E2E flow gate: **pass**.
- Flake policy:
  - Maximum tolerated flakiness: **0%** (no known flakes and no retries used).
- Mandatory blockers:
  - External release is blocked if any required gate is skipped, cancelled, or fails.
  - External release is blocked if flaky rate exceeds threshold.
- Artifact policy:
  - Test reports and logs for every release-candidate run must be retained for at least 30 days.

## Required CI gates

### Gate: Safety invariants
- [ ] `tests/test_prune_plan_integrity.py` passed.
- [ ] `tests/test_prune_flows_integration.py` passed.
- [ ] `tests/test_space_audit_integration_and_safety.py` passed.
- [ ] `tests/test_policy_firewall.py` passed.
- [ ] `tests/test_prompt_security.py` passed.
- [ ] `tests/test_protection_policy_engine.py` passed.

### Gate: Schema compatibility
- [ ] `tests/test_schema_compatibility_golden.py` passed.
- [ ] `tests/test_golden_plan_output.py` passed.
- [ ] `tests/test_golden_recommendations.py` passed.

### Gate: Soak tests
- [ ] `tests/test_watchdog_soak_and_recovery.py` passed.
- [ ] `tests/test_free_space_watchdog.py` passed.

### Gate: End-to-end flows
- [ ] `tests/test_cli_e2e_smoke.py` passed.
- [ ] `tests/test_service_api_smoke.py` passed.

## Signed release checklist (required before tagging)

Before running `git tag`, a signed release checklist file must exist at:
- `docs/release_signoff.md`

Required entries in the signed checklist:
- Release tier and version candidate.
- CI run URL(s) and artifact URL(s).
- Confirmation all required gates passed with no skips.
- Recorded flaky-rate calculation and threshold compliance.
- Two signers (Release Manager + QA/Owner) with date.

## Final external release decision
- [ ] Confirm all required CI gates are green.
- [ ] Confirm no required gate was skipped.
- [ ] Confirm flaky rate is at or below tier threshold.
- [ ] Confirm artifacts (reports/logs) are retained for each gate.
- [ ] Confirm `docs/release_signoff.md` is completed and signed.
- [ ] Only then create and push release tag.
