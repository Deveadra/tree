# tree

## CLI entrypoint

Use `cli.py` with the following subcommands:

- `scan`
- `dupes`
- `plan-prune`
- `apply-prune`
- `report`

All commands support human-readable output by default and machine-readable output with `--json`.

## Claim audit: safety workflow, plan/apply semantics, and rule tracing

Legend:
- **Implemented**: behavior exists in current code and CLI.
- **Partially implemented**: some behavior exists, but scope is narrower than previously described.
- **Planned**: intentionally not shipped yet in current CLI/service path.

### Safety workflow claims

1. **Claim:** Prune-related operations default to dry-run mode (`plan-prune` and `apply-prune`).  
   **Status:** **Implemented**.  
   `apply-prune` has `--dry-run` default true, and `plan_prune(...)` emits metadata `dry_run_default: true` in the generated plan.

2. **Claim:** Destructive prune requires both `--no-dry-run` and `--yes`.  
   **Status:** **Implemented**.  
   `apply_prune(...)` raises `ValueError("Refusing destructive action without --yes")` when `dry_run` is false and `yes` is not passed.

### Plan/apply semantics claims

3. **Claim:** `plan-prune` constructs plan actions from duplicate groups and writes `prune_plan.json`.  
   **Status:** **Implemented**.  
   The CLI loads dupes, calls `service.plan_prune(...)`, and writes to `<report-dir>/prune_plan.json`.

4. **Claim:** `apply-prune` executes plan actions with audit logging support.  
   **Status:** **Implemented**.  
   For each action, non-dry-run uses recycle logic and (when `--audit-log` is provided/defaulted) appends JSONL audit events.

5. **Claim:** `plan-prune --dry-run/--no-dry-run` affects plan generation semantics.  
   **Status:** **Partially implemented** (flag currently accepted but not used by planner logic).  
   The parser accepts the flag for `plan-prune`, but current `service.plan_prune(...)` behavior does not branch on it.

### Rule tracing and rule-processing claims

6. **Claim:** Deterministic precedence is runtime CLI excludes > env overrides > global defaults.  
   **Status:** **Partially implemented** in the current CLI path.  
   Runtime `--exclude` is passed directly into scan/report calls, and separate env/default loading utilities exist; however, current `scan` command does not merge env/default excludes automatically.

7. **Claim:** Include/exclude conflict resolution is “exclude wins.”  
   **Status:** **Implemented** in `evaluate_rules(...)`.

8. **Claim:** Path normalization uses `canonicalize_path()` with `raw` and `canonical` forms.  
   **Status:** **Implemented**.

9. **Claim:** Validation warnings are emitted for unresolved `%ENV_VAR%` and malformed drive-prefix forms.  
   **Status:** **Implemented** in validation utility and exclude-loader warning output.

10. **Claim:** Pattern matching supports prefix style and glob/pathspec style (`*`, `?`, `[]`, `**`).  
    **Status:** **Implemented** via `match_pattern(...)`.

11. **Claim:** Scan internals collect and expose `rule_trace` from `_scan_root_append_to_con(...)`.  
    **Status:** **Planned**.  
    Current public CLI/service flow does not expose a `rule_trace` artifact.

## Current guarantees

Scope: guarantees below describe current shipped behavior of `cli.py` + `core.service` + `config.path_rules` in this repository.

- `apply-prune` is safe-by-default (dry-run unless explicitly overridden).
- destructive apply is guarded by an explicit confirmation (`--yes`) in addition to disabling dry-run.
- prune plans are deterministic for a given dupe-group input (newest-by-`mtime` then path retained per group).
- path-rule matching is case-normalized and slash-normalized before match evaluation.
- exclude precedence over include is guaranteed where `evaluate_rules(...)` is used.

Limitations:

- `plan-prune` currently accepts dry-run flags but does not change planner behavior.
- env/default exclude layering is available via config loader utilities but is not yet automatically wired into `scan` CLI exclude resolution.
- rule-hit trace export is not currently available from the CLI outputs.

## Verified command examples

The following commands were validated against the current CLI interface:

```bash
# Show top-level CLI commands
python cli.py --help

# Show plan-prune options
python cli.py plan-prune --help

# Show apply-prune options (including safety flags)
python cli.py apply-prune --help

# Dry-run apply against an empty plan (machine-readable)
printf '{"actions":[]}' > /tmp/empty_plan.json
python cli.py apply-prune --plan /tmp/empty_plan.json --json
```

## Testing

Canonical import strategy: **flat-module imports with explicit test-runner PYTHONPATH config**. `pytest.ini` sets `pythonpath = .`, so imports like `config.path_rules` resolve from repo root without manual environment variables.

- Local test command: `pytest -q`
- CI test command: `pytest -q`
- Import smoke check: `python -c "import config.path_rules; print('ok')"`

## Scan profiling, progress metrics, and error budget

Scanner progress now emits:
- `listed`, `indexed`, `skipped`, `errors`
- `dirs_visited`, `bytes_observed`, `elapsed_s`, and `depth_skipped`

Runtime toggles:
- `DUPE_SCAN_ERROR_BUDGET` (default `1000`): recoverable scan errors tolerated before early-stop.
- `DUPE_SCAN_TREE_DEPTH_CAP` (default `256`): maximum directory depth traversed per root.
- `DUPE_SCAN_PROFILE` (`0/1`): print one profile summary line per scanned root.

Critical init failures (DB open/schema issues) still fail immediately; directory/file permission and disappearance errors remain recoverable until the error budget is exhausted.

## Benchmarking large synthetic trees

Use:

```bash
python scripts/benchmark_scan.py --dirs 200 --files-per-dir 200 --file-size 256
```

Expected ballpark ranges on a modern dev machine:
- ~40k files: typically low single-digit seconds.
- ~100k files: typically several seconds to tens of seconds, depending on filesystem and AV activity.


## Protection config (`config/protection.toml`)

Schema:

- `enforce_safe_delete_roots` (bool, default `true`): when enabled, delete candidates should stay under `safe_delete_roots`.
- `protected_prefixes` (`list[str]`): absolute path prefixes that are always protected.
- `protected_dir_names` (`list[str]`): directory names that are always protected regardless of absolute location.
- `safe_delete_roots` (`list[str]`): allowed top-level roots for destructive delete operations when enforcement is enabled.

Defaults and precedence (lowest -> highest):

1. Built-in protected defaults (Windows system paths + reserved directory names).
2. `config/protection.toml` values.
3. Optional runtime/environment overrides:
   - `DUPES_ENFORCE_SAFE_DELETE_ROOTS`
   - `DUPES_PROTECTED_PREFIXES`
   - `DUPES_PROTECTED_DIR_NAMES`
   - `DUPES_SAFE_DELETE_ROOTS`

Validation warnings:

- malformed drive prefixes (example: `C:bad`) produce warnings.
- unresolved `%ENV_VAR%` segments in path entries produce warnings.
- enabling `enforce_safe_delete_roots` without any configured `safe_delete_roots` produces a warning.
