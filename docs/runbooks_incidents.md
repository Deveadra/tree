# Incident Runbooks

## 1) Space relapse (free space drops again after cleanup)

1. Generate a diagnostic bundle:
   - `python cli.py diagnostic-bundle --report-dir reports --output reports/diagnostic_bundle.zip --telemetry-opt-in --json`
2. Run a fresh space audit:
   - `python cli.py space-audit <ROOT> --report-dir reports --json`
3. Compare with previous snapshot and review `compare.summary` for unattributed deltas.
4. If relapse is rapid, run watchdog for 10-30 minutes and inspect timeline spikes.

## 2) False attribution (bytes blamed on wrong root/process)

1. Verify scan scope and excludes are identical between snapshots.
2. Re-run `scan`, `dupes`, and `report` to rebuild a clean baseline.
3. Check `reports/space_audit_diff.json` for `unattributed` categories.
4. Escalate with diagnostic bundle and note any backup/sync/update jobs active during capture.

## 3) Policy blocks (expected prune action skipped)

1. Run `apply-prune` with `--json` and inspect `error.code` or `blocked_reasons`.
2. Review `reports/prune_audit.jsonl/policy_block_report.json`.
3. Confirm `config/protection.toml` rules and safe roots.
4. Re-run in dry-run mode first before destructive apply.

## Structured error codes

- `PLAN_MISSING_FIELD`
- `PLAN_SCHEMA_UNSUPPORTED`
- `PLAN_VERSION_UNSUPPORTED`
- `PLAN_CHECKSUM_FAILED`
- `POLICY_BLOCKED`
- `CONFIRMATION_REQUIRED`

Use the CLI JSON `error.troubleshooting` field for first response guidance.
