# Security Threat Model

## Scope
This model covers five primary interfaces:
- CLI (`cli.py`) inputs/paths/options.
- GUI (`dupe_finder_gui.py`) user-selected paths/actions.
- Report ingestion (loading prior JSON artifacts such as `space_snapshot.json`).
- AI prompt assembly and schema-constrained output (`core/ai/*`).
- Plugin interfaces (`core/collector_plugins.py`).

## Trust Boundaries
1. **User/device boundary**: Any path, filename, note, or log content from local users/processes is untrusted.
2. **Filesystem boundary**: Traversal can encounter adversarial names, symlinks, permissions, and malformed files.
3. **Artifact boundary**: Historical report JSON may be crafted/poisoned and must not be trusted blindly.
4. **LLM boundary**: AI context (notes/logs) is untrusted data, not instructions; model output is validated.
5. **Plugin boundary**: Plugin collectors are partially trusted extensions that can fail, over-collect, or return malformed data.

## Attacker Capabilities
Assume attackers can:
- Create malicious path names (control chars, long names, traversal-like names).
- Plant crafted logs/notes containing prompt-injection strings.
- Create poisoned bundles/artifacts with malformed JSON or deceptive metadata.
- Create symlink tricks that point outside scan/report roots.
- Trigger plugin failures or supply anomalous plugin output.

## Threats and Mitigations
### CLI/GUI
- **Threat**: unsafe path handling and writes outside intended roots.
- **Mitigations**: canonicalization, root constraints, deny-by-default policy checks, dry-run patterns.

### Report ingestion
- **Threat**: path traversal/symlink escape to ingest attacker-controlled snapshots outside report root.
- **Mitigations**: resolve path and enforce containment within report root; reject malformed JSON.

### AI prompts
- **Threat**: prompt injection through user notes/logs.
- **Mitigations**: sanitize/redact adversarial patterns, immutable policy clauses, output schema allowlist validation.

### Plugins
- **Threat**: plugin exceptions, malformed payloads, excessive permissions.
- **Mitigations**: explicit metadata/permissions, fault isolation (`run_*_safely`), bounded collector behavior.

## Security Testing Matrix
- Path traversal and symlink escape on artifact discovery.
- Malformed artifact parsing resilience.
- Prompt-injection redaction and policy retention.
- Plugin failure isolation.
