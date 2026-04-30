from __future__ import annotations

from .models import PruneExecutionResult, PrunePlan
from pathlib import Path

from config.protection_loader import DEFAULT_TOML, resolve_protection_config
from .platform.windows import windows_recycle
from .protection_policy import evaluate_delete_permission


def build_prune_plan(paths: list[str], mode: str = "recycle") -> PrunePlan:
    return PrunePlan(total_candidates=len(paths), paths_to_remove=paths, mode=mode)


def execute_prune_plan(plan: PrunePlan, policy_path: Path | None = None) -> PruneExecutionResult:
    errors: list[str] = []
    removed = 0
    policy_cfg = resolve_protection_config(policy_path or DEFAULT_TOML)
    for p in plan.paths_to_remove:
        try:
            if plan.mode in {"recycle", "delete", "move"}:
                perm = evaluate_delete_permission(p, mode=plan.mode, action_type="delete", policy=policy_cfg)
                if not bool(perm.get("allow")):
                    errors.append(f"{p}: {perm.get('reason', 'Blocked by protection policy')}")
                    continue
            if plan.mode == "recycle":
                windows_recycle([p])
            else:
                import os

                os.remove(p)
            removed += 1
        except Exception as e:
            errors.append(f"{p}: {e}")
    return PruneExecutionResult(removed=removed, failed=len(errors), errors=errors)
