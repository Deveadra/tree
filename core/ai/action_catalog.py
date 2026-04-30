from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ActionCatalogEntry:
    action_id: str
    title: str
    reversibility: str
    risk: str
    prerequisites: tuple[str, ...]
    typical_reclaim_range_gb: tuple[float, float]
    verification_checkpoint: str
    rollback_path: str

    @property
    def irreversible(self) -> bool:
        return self.reversibility.lower() == "irreversible"


def _entry_dict(entry: ActionCatalogEntry) -> dict[str, Any]:
    return {
        "action_id": entry.action_id,
        "title": entry.title,
        "reversibility": entry.reversibility,
        "risk": entry.risk,
        "prerequisites": list(entry.prerequisites),
        "typical_reclaim_range_gb": {
            "min": entry.typical_reclaim_range_gb[0],
            "max": entry.typical_reclaim_range_gb[1],
        },
        "verification_checkpoint": entry.verification_checkpoint,
        "rollback_path": entry.rollback_path,
        "irreversible": entry.irreversible,
    }


_ACTIONS: tuple[ActionCatalogEntry, ...] = (
    ActionCatalogEntry(
        action_id="cache-cleanup",
        title="Clean package and build caches",
        reversibility="reversible",
        risk="low",
        prerequisites=("close package managers", "ensure active installs are complete"),
        typical_reclaim_range_gb=(0.5, 8.0),
        verification_checkpoint="Verify cache directories were recreated empty and key tools still launch.",
        rollback_path="Restore cache snapshot from recycle/quarantine location if tooling fails.",
    ),
    ActionCatalogEntry(
        action_id="archive-old-media",
        title="Archive old media to secondary storage",
        reversibility="reversible",
        risk="medium",
        prerequisites=("secondary storage mounted", "archive destination writable"),
        typical_reclaim_range_gb=(5.0, 250.0),
        verification_checkpoint="Open random archived files from destination and verify checksums/sample playback.",
        rollback_path="Move archived files back from destination using manifest generated during transfer.",
    ),
    ActionCatalogEntry(
        action_id="remove-duplicate-binaries",
        title="Remove duplicate installers/binaries",
        reversibility="irreversible",
        risk="high",
        prerequisites=("hash-match duplicates confirmed", "primary canonical copy tagged"),
        typical_reclaim_range_gb=(1.0, 40.0),
        verification_checkpoint="Rescan duplicate index and confirm canonical copy remains intact.",
        rollback_path="Recover from backup or redownload installers from trusted sources.",
    ),
)

ACTION_CATALOG: dict[str, dict[str, Any]] = {e.action_id: _entry_dict(e) for e in _ACTIONS}


def get_catalog_entry(action_id: str) -> dict[str, Any] | None:
    return ACTION_CATALOG.get(action_id)


def build_action_step(action_id: str) -> dict[str, Any] | None:
    entry = get_catalog_entry(action_id)
    if not entry:
        return None
    return {
        "action_id": entry["action_id"],
        "title": entry["title"],
        "reversibility": entry["reversibility"],
        "risk": entry["risk"],
        "prerequisites": list(entry["prerequisites"]),
        "expected_space_recovery_range_gb": dict(entry["typical_reclaim_range_gb"]),
        "verification_checkpoint": entry["verification_checkpoint"],
        "rollback_path": entry["rollback_path"],
        "requires_confirmation_token": bool(entry["irreversible"]),
        "confirmation_token": f"CONFIRM:{entry['action_id'].upper()}" if entry["irreversible"] else None,
        "execution_handoff": "destructive" if entry["irreversible"] else "guided",
    }


def order_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(steps, key=lambda s: (bool(s.get("reversibility", "").lower() == "irreversible"), str(s.get("action_id", ""))))
