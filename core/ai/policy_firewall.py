from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from config.protection_loader import ProtectionConfig
from core.protection_policy import evaluate_delete_permission

DESTRUCTIVE_ACTIONS = {"delete", "recycle", "move"}

RULE_ID_BY_REASON = {
    "outside_safe_roots": "PP-001",
    "protected_prefix": "PP-002",
    "protected_dir_name": "PP-003",
    "unsafe_quarantine_config": "PP-004",
    "invalid_path": "PP-005",
    "policy_deny": "PP-999",
}


@dataclass(frozen=True)
class PolicyViolation:
    rule_id: str
    reason_code: str
    message: str
    path: str
    action: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "reason_code": self.reason_code,
            "message": self.message,
            "path": self.path,
            "action": self.action,
        }


def validate_action_candidate(
    candidate: dict[str, Any],
    *,
    policy: ProtectionConfig,
    enforce_safe_delete_roots: bool,
    safe_delete_roots: list[Path] | None,
) -> list[PolicyViolation]:
    action = str(candidate.get("action", "")).lower()
    if action not in DESTRUCTIVE_ACTIONS:
        return []

    path = str(candidate.get("path") or "")
    decision = evaluate_delete_permission(
        path,
        mode=action,
        action_type="delete",
        safe_roots=safe_delete_roots if enforce_safe_delete_roots else None,
        policy=policy,
    )
    if bool(decision.get("allow")):
        return []

    reason_code = str(decision.get("reason_code", "policy_deny"))
    return [
        PolicyViolation(
            rule_id=RULE_ID_BY_REASON.get(reason_code, "PP-999"),
            reason_code=reason_code,
            message=str(decision.get("reason", "Blocked by protection policy.")),
            path=path,
            action=action,
        )
    ]


def enforce_plan_compliance(
    actions: list[dict[str, Any]],
    *,
    policy: ProtectionConfig,
    enforce_safe_delete_roots: bool,
    safe_delete_roots: list[Path] | None,
) -> dict[str, Any]:
    safe_actions: list[dict[str, Any]] = []
    rewritten: list[dict[str, Any]] = []
    violations: list[dict[str, str]] = []

    for action in actions:
        action_violations = validate_action_candidate(
            action,
            policy=policy,
            enforce_safe_delete_roots=enforce_safe_delete_roots,
            safe_delete_roots=safe_delete_roots,
        )
        if not action_violations:
            safe_actions.append(action)
            continue

        violations.extend(v.to_dict() for v in action_violations)
        rewritten.append(
            {
                "action": "skip",
                "path": action.get("path"),
                "reason": "blocked_by_policy_firewall",
                "violations": [v.to_dict() for v in action_violations],
            }
        )

    return {
        "ok": len(violations) == 0,
        "safe_actions": safe_actions,
        "rewritten_actions": rewritten,
        "violations": violations,
    }
