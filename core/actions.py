from __future__ import annotations

from .models import PruneExecutionResult, PrunePlan
from .platform.windows import windows_recycle


def build_prune_plan(paths: list[str], mode: str = "recycle") -> PrunePlan:
    return PrunePlan(total_candidates=len(paths), paths_to_remove=paths, mode=mode)


def execute_prune_plan(plan: PrunePlan) -> PruneExecutionResult:
    errors: list[str] = []
    removed = 0
    for p in plan.paths_to_remove:
        try:
            if plan.mode == "recycle":
                windows_recycle([p])
            else:
                import os

                os.remove(p)
            removed += 1
        except Exception as e:
            errors.append(f"{p}: {e}")
    return PruneExecutionResult(removed=removed, failed=len(errors), errors=errors)
