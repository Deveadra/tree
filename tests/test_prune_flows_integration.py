import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core import service


class PruneFlowsIntegrationTests(unittest.TestCase):
    def _build_plan(self, target: Path) -> dict:
        return {
            "schema": "plan-prune",
            "metadata": {
                "plan_version": service.PRUNE_PLAN_SCHEMA_VERSION,
                "generated_at": "2026-01-01T00:00:00Z",
                "source_id": "test",
            },
            "groups": 1,
            "actions": [
                {
                    "action": "recycle",
                    "path": str(target),
                    "size": target.stat().st_size,
                    "snapshot": {
                        "exists": True,
                        "size": target.stat().st_size,
                        "mtime": int(target.stat().st_mtime),
                        "hash": None,
                    },
                }
            ],
            "files_to_prune": 1,
            "bytes_reclaimable": target.stat().st_size,
            "dry_run_default": True,
        }

    def test_manual_flow_blocked_file_never_deleted_and_is_audited(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            blocked_file = root / "Windows" / "blocked.txt"
            blocked_file.parent.mkdir(parents=True)
            blocked_file.write_text("x", encoding="utf-8")
            plan = self._build_plan(blocked_file)
            plan["plan_checksum"] = service._sha256_json(plan)

            with patch("core.service.windows_recycle", return_value=True) as mock_recycle:
                result = service.apply_prune(plan, dry_run=False, yes=True, audit_log=root / "audit")

            self.assertEqual(result["blocked"], 1)
            self.assertEqual(result["applied"], 0)
            mock_recycle.assert_not_called()
            self.assertTrue(blocked_file.exists())

            audit_lines = (root / "audit" / "prune_events.jsonl").read_text(encoding="utf-8").splitlines()
            event = json.loads(audit_lines[0])
            self.assertEqual(event["policy_decision"], "blocked")
            self.assertEqual(event["policy_reason_code"], "protected_dir_name")

    def test_auto_prune_flow_blocked_file_never_deleted_and_is_audited(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            keep = root / "safe" / "keep.txt"
            blocked = root / "Windows" / "dupe.txt"
            keep.parent.mkdir(parents=True)
            blocked.parent.mkdir(parents=True)
            keep.write_text("same", encoding="utf-8")
            blocked.write_text("same", encoding="utf-8")

            files = [
                type("F", (), {"path": str(keep), "size": 4, "mtime": keep.stat().st_mtime}),
                type("F", (), {"path": str(blocked), "size": 4, "mtime": blocked.stat().st_mtime - 10}),
            ]
            group = type("G", (), {"files": files, "sha256": "h", "size": 4})
            plan = service.plan_prune([group], source_id="auto")

            with patch("core.service.windows_recycle", return_value=True) as mock_recycle:
                result = service.apply_prune(plan, dry_run=False, yes=True, audit_log=root / "audit")

            self.assertEqual(result["blocked"], 1)
            self.assertEqual(result["applied"], 0)
            mock_recycle.assert_not_called()
            self.assertTrue(blocked.exists())

    def test_compare_prune_flow_blocked_file_never_deleted_and_is_audited(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            blocked = left / "System Volume Information" / "dupe.txt"
            blocked.parent.mkdir(parents=True)
            other = right / "dupe.txt"
            blocked.write_text("same", encoding="utf-8")
            other.write_text("same", encoding="utf-8")

            plan = self._build_plan(blocked)
            plan["plan_checksum"] = service._sha256_json(plan)
            with patch("core.service.windows_recycle", return_value=True) as mock_recycle:
                result = service.apply_prune(
                    plan,
                    dry_run=False,
                    yes=True,
                    audit_log=root / "audit",
                    enforce_safe_delete_roots=True,
                    safe_delete_roots=[left, right],
                )

            self.assertEqual(result["blocked"], 1)
            self.assertEqual(result["applied"], 0)
            self.assertIn("protected_dir_name", result["blocked_reasons"])
            mock_recycle.assert_not_called()
            self.assertTrue(blocked.exists())
            report = json.loads((root / "audit" / "policy_block_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["blocked_total"], 1)


if __name__ == "__main__":
    unittest.main()
