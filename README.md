# tree

## Rule processing

Deterministic precedence is:
1. CLI/session overrides (runtime `excludes` inputs)  
2. User config env overrides (`DUPES_EXCLUDE_*`)  
3. Global defaults (`config/excludes.toml`)

When both include and exclude style patterns apply, **exclude wins**.

## Path normalization

All rule/path matching is funneled through `config.path_rules.canonicalize_path()`, which stores both:
- `raw`: original user string (for diagnostics)
- `canonical`: normalized form used for matching

## Validation warnings

The loader emits warnings for:
- unresolved `%ENV_VAR%` tokens
- malformed prefixes such as `C:bad`

## Pattern types

Rules support both:
- simple prefix/path matching
- glob/pathspec style matching (`*`, `?`, `[]`, `**`)

## Rule-hit tracing

Scan internals can collect a `rule_trace` list from `_scan_root_append_to_con(...)` to explain why directories/items were skipped.
