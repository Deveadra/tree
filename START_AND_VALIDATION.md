# Application Startup and Validation Testing Guide

## 1) Prerequisites

- Python 3.10+ installed
- `pip` available
- Project dependencies installed from your environment requirements
- Terminal opened at repository root

## 2) Initial Setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Confirm Python and pytest are available.

Example:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
# Install project deps (use your repo's requirement source)
pip install -r requirements.txt
python --version
pytest --version
```

## 3) How to Start the Application

### A) Start the GUI

```bash
python dupe_finder_gui.py
```

Expected result:
- Main window opens
- Scan/Prune/Audit/Watch/AI-related controls render without immediate errors

### B) Start the CLI

```bash
python cli.py --help
```

Expected result:
- Help text prints
- All intended subcommands are listed

## 4) Validation Testing: What Must Be Tested

Run tests from repository root.

### A) Full automated test suite (required)

```bash
pytest -q
```

Pass criteria:
- Exit code 0
- No failed tests
- No unexpected skips in safety-critical modules

### B) Safety and policy enforcement tests (required)

```bash
pytest -q tests/test_policy_firewall.py tests/test_protection_policy_engine.py tests/test_prune_plan_integrity.py tests/test_prune_flows_integration.py
```

Pass criteria:
- All tests pass
- Any destructive path is blocked when policy or confirmation requirements are not met

### C) AI reliability and security tests (required)

```bash
pytest -q tests/test_ai_evidence_builder.py tests/test_recommendation_engine.py tests/test_prompt_security.py tests/test_ai_outcomes_tracker.py
```

Pass criteria:
- Evidence ingestion and recommendation outputs validate
- Prompt security tests pass
- Outcome tracking tests pass

### D) Space Audit / Space Watch tests (required)

```bash
pytest -q tests/test_space_audit_metrics.py tests/test_space_audit_diff.py tests/test_space_audit_integration_and_safety.py tests/test_free_space_watchdog.py tests/test_watchdog_soak_and_recovery.py tests/test_growth_attribution.py
```

Pass criteria:
- Snapshot creation and diff logic pass
- Watchdog/timeline tests pass
- Read-only safety assertions pass

### E) CLI end-to-end smoke test (required)

```bash
pytest -q tests/test_cli_e2e_smoke.py
```

Pass criteria:
- CLI core flows execute successfully in test mode

### F) Schema/golden compatibility tests (required)

```bash
pytest -q tests/test_schema_compatibility_golden.py tests/test_golden_plan_output.py tests/test_golden_recommendations.py
```

Pass criteria:
- No schema drift unless intentionally versioned
- Golden outputs match expected behavior

## 5) Manual Validation Checklist (Pre-Release)

1. Launch GUI and confirm no startup exceptions.
2. Run a read-only scan on a non-critical test directory.
3. Generate Space Audit reports and confirm artifacts are written.
4. Start Space Watch and verify timeline output updates over time.
5. Open AI Findings and verify:
   - findings cite evidence,
   - confidence labels are present,
   - dangerous recommendations are blocked/flagged.
6. Attempt a policy-violating action and confirm it is denied.
7. Run dry-run prune flow and verify plan artifacts are created.
8. Verify explicit confirmation is required for destructive apply.

## 6) Test Run Modes (Recommended)

### Internal test run
- Enable full monitoring and AI findings
- Keep destructive actions in dry-run unless actively validating apply flow
- Capture outcomes for recommendation quality review

### External pilot
- Default to read-only insights + guarded plans
- Require manual approval for all destructive operations
- Enable redacted report export for sharing

## 7) Release Readiness Criteria

A build is ready for broader testing only if:
- All required automated suites pass
- Manual checklist is complete
- No unresolved critical/high safety defects
- Policy enforcement and confirmation gates are verified
- AI findings are explainable and evidence-linked

## 8) Troubleshooting

- If imports fail during tests, ensure you are at repo root and virtualenv is active.
- If GUI fails to launch, run `python -m py_compile dupe_finder_gui.py cli.py` to catch syntax/import issues.
- If a subset fails, rerun with `-k` targeting and inspect fixture/environment assumptions.

