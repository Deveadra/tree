# tree

## CLI entrypoint

Use `cli.py` with the following subcommands:

- `scan`
- `dupes`
- `plan-prune`
- `apply-prune`
- `report`

All commands support human-readable output by default and machine-readable output with `--json`.

## Safety defaults

- Prune-related operations default to dry-run mode (`plan-prune` and `apply-prune`).
- To perform destructive prune actions, you must pass **both** `--no-dry-run` and `--yes` to `apply-prune`.

## Operational playbook: single-root workflow

1. Scan one root into the cache:
   - `python cli.py scan /data/root-a --report-dir reports/single --db reports/single/scan.db`
2. Inspect duplicate groups:
   - `python cli.py dupes --db reports/single/scan.db`
3. Create prune plan (dry-run default):
   - `python cli.py plan-prune --db reports/single/scan.db --report-dir reports/single`
4. (Optional) apply prune:
   - Dry run: `python cli.py apply-prune --plan reports/single/prune_plan.json`
   - Real apply: `python cli.py apply-prune --plan reports/single/prune_plan.json --no-dry-run --yes`
5. Write reporting artifacts:
   - `python cli.py report --db reports/single/scan.db --report-dir reports/single`

## Operational playbook: compare-root workflow

1. Scan two roots in compare mode:
   - `python cli.py scan /data/root-a /data/root-b --compare --report-dir reports/compare --db reports/compare/scan.db`
2. Inspect compare-mode dupes:
   - `python cli.py dupes --db reports/compare/scan.db --compare`
3. Create prune plan (dry-run default):
   - `python cli.py plan-prune --db reports/compare/scan.db --compare --report-dir reports/compare`
4. (Optional) apply prune with explicit confirmation:
   - `python cli.py apply-prune --plan reports/compare/prune_plan.json --no-dry-run --yes`
5. Export reports:
   - `python cli.py report --db reports/compare/scan.db --compare --report-dir reports/compare`
