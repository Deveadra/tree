from __future__ import annotations

from datetime import datetime
from typing import Any

EVIDENCE_SCHEMA_VERSION = "1.0"
REQUIRED_PROVENANCE_FIELDS = ("source_file", "run_id", "event_id", "timestamp")


def _is_iso_timestamp(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return True


def validate_feature_provenance(feature: dict[str, Any], *, context: str) -> None:
    provenance = feature.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError(f"{context}: missing provenance map")
    missing = [field for field in REQUIRED_PROVENANCE_FIELDS if not provenance.get(field)]
    if missing:
        raise ValueError(f"{context}: missing provenance fields: {', '.join(missing)}")
    if not _is_iso_timestamp(str(provenance["timestamp"])):
        raise ValueError(f"{context}: invalid provenance timestamp: {provenance['timestamp']}")


def validate_evidence_schema(evidence: dict[str, Any]) -> None:
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a mapping")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise ValueError(
            f"schema_version mismatch: expected {EVIDENCE_SCHEMA_VERSION}, got {evidence.get('schema_version')}"
        )

    required_sections = (
        "space_audit_snapshot_features",
        "monitor_timeline_features",
        "protection_policy_state",
        "user_notes_context",
    )
    for section in required_sections:
        value = evidence.get(section)
        if not isinstance(value, list):
            raise ValueError(f"{section} must be a list")
        for idx, feature in enumerate(value):
            if not isinstance(feature, dict):
                raise ValueError(f"{section}[{idx}] must be an object")
            validate_feature_provenance(feature, context=f"{section}[{idx}]")
