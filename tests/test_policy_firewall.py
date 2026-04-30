from pathlib import Path

from config.protection_loader import ProtectionConfig
from core.ai.policy_firewall import enforce_plan_compliance, validate_action_candidate


def _policy(enforce: bool = True) -> ProtectionConfig:
    return ProtectionConfig(
        protected_prefixes=[r"C:\\Windows", r"C:\\Program Files"],
        protected_dir_names=["windows", "program files", "system volume information"],
        safe_delete_roots=[r"D:\\safe"],
        enforce_safe_delete_roots=enforce,
        warnings=[],
    )


def test_validate_action_candidate_denies_protected_prefix_and_exposes_rule_id():
    violations = validate_action_candidate(
        {"action": "delete", "path": r"C:\\Windows\\System32\\kernel32.dll"},
        policy=_policy(enforce=False),
        enforce_safe_delete_roots=False,
        safe_delete_roots=None,
    )

    assert len(violations) == 1
    assert violations[0].reason_code == "protected_prefix"
    assert violations[0].rule_id == "PP-002"


def test_validate_action_candidate_denies_out_of_scope_root():
    violations = validate_action_candidate(
        {"action": "recycle", "path": r"D:\\outside\\file.tmp"},
        policy=_policy(),
        enforce_safe_delete_roots=True,
        safe_delete_roots=[Path(r"D:\\safe")],
    )

    assert len(violations) == 1
    assert violations[0].reason_code == "outside_safe_roots"
    assert violations[0].rule_id == "PP-001"


def test_enforce_plan_compliance_rewrites_non_compliant_steps_and_blocks_destructive_pass_through():
    actions = [
        {"action": "delete", "path": r"C:\\Windows\\x.dll", "size": 1},
        {"action": "recycle", "path": r"D:\\safe\\ok.tmp", "size": 2},
        {"action": "delete", "path": r"D:\\other\\bad.tmp", "size": 3},
    ]

    result = enforce_plan_compliance(
        actions,
        policy=_policy(),
        enforce_safe_delete_roots=True,
        safe_delete_roots=[Path(r"D:\\safe")],
    )

    assert result["ok"] is False
    assert len(result["violations"]) == 2
    assert all(a["path"] == r"D:\\safe\\ok.tmp" for a in result["safe_actions"])
    assert len(result["rewritten_actions"]) == 2
    assert all(step["action"] == "skip" for step in result["rewritten_actions"])
