import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core import service


class PrunePlanIntegrityTests(unittest.TestCase):
    def test_tampered_plan_rejected(self):
        with TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "a.txt"
            f.write_text("x", encoding="utf-8")
            plan = {
                "schema": "plan-prune",
                "metadata": {"plan_version": service.PRUNE_PLAN_SCHEMA_VERSION, "generated_at": "2026-01-01T00:00:00Z", "source_id": "test"},
                "groups": 1,
                "actions": [{"action": "recycle", "path": str(f), "size": 1, "snapshot": {"exists": True, "size": 1, "mtime": int(f.stat().st_mtime), "hash": None}}],
                "files_to_prune": 1,
                "bytes_reclaimable": 1,
                "dry_run_default": True,
            }
            plan["plan_checksum"] = service._sha256_json(plan)
            plan["actions"][0]["path"] = str(Path(tmpdir) / "tampered.txt")

            with self.assertRaises(ValueError):
                service.apply_prune(plan, dry_run=True)

    def test_stale_metadata_skips_file(self):
        with TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "a.txt"
            f.write_text("x", encoding="utf-8")
            st = f.stat()
            plan = {
                "schema": "plan-prune",
                "metadata": {"plan_version": service.PRUNE_PLAN_SCHEMA_VERSION, "generated_at": "2026-01-01T00:00:00Z", "source_id": "test"},
                "groups": 1,
                "actions": [{"action": "recycle", "path": str(f), "size": 1, "snapshot": {"exists": True, "size": st.st_size + 1, "mtime": int(st.st_mtime), "hash": None}}],
                "files_to_prune": 1,
                "bytes_reclaimable": 1,
                "dry_run_default": True,
            }
            plan["plan_checksum"] = service._sha256_json(plan)
            with patch("core.service.append_prune_event") as mock_event:
                result = service.apply_prune(plan, dry_run=False, yes=True, audit_log=Path(tmpdir))
            self.assertEqual(result["skipped"], 1)
            mock_event.assert_called_once()
            self.assertEqual(mock_event.call_args.args[1]["reason_code"], "size_changed")

    def test_dry_run_vs_destructive_guard(self):
        with TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "a.txt"
            f.write_text("x", encoding="utf-8")
            st = f.stat()
            plan = {
                "schema": "plan-prune",
                "metadata": {"plan_version": service.PRUNE_PLAN_SCHEMA_VERSION, "generated_at": "2026-01-01T00:00:00Z", "source_id": "test"},
                "groups": 1,
                "actions": [{"action": "recycle", "path": str(f), "size": 1, "snapshot": {"exists": True, "size": st.st_size, "mtime": int(st.st_mtime), "hash": None}}],
                "files_to_prune": 1,
                "bytes_reclaimable": 1,
                "dry_run_default": True,
            }
            plan["plan_checksum"] = service._sha256_json(plan)
            dry = service.apply_prune(plan, dry_run=True, yes=False)
            self.assertEqual(dry["skipped"], 1)
            with self.assertRaises(ValueError):
                service.apply_prune(plan, dry_run=False, yes=False)
            with patch("core.service.windows_recycle", return_value=True) as mock_recycle:
                real = service.apply_prune(plan, dry_run=False, yes=True)
            self.assertEqual(real["applied"], 1)
            mock_recycle.assert_called_once()

    def test_denied_file_is_skipped_and_audited_in_batch(self):
        with TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            allowed_root = base / "safe"
            denied_root = base / "outside"
            allowed_root.mkdir()
            denied_root.mkdir()

            denied = denied_root / "denied.txt"
            allowed = allowed_root / "allowed.txt"
            denied.write_text("x", encoding="utf-8")
            allowed.write_text("x", encoding="utf-8")

            plan = {
                "schema": "plan-prune",
                "metadata": {"plan_version": service.PRUNE_PLAN_SCHEMA_VERSION, "generated_at": "2026-01-01T00:00:00Z", "source_id": "test"},
                "groups": 1,
                "actions": [
                    {"action": "recycle", "path": str(denied), "size": 1, "snapshot": {"exists": True, "size": 1, "mtime": int(denied.stat().st_mtime), "hash": None}},
                    {"action": "recycle", "path": str(allowed), "size": 1, "snapshot": {"exists": True, "size": 1, "mtime": int(allowed.stat().st_mtime), "hash": None}},
                ],
                "files_to_prune": 2,
                "bytes_reclaimable": 2,
                "dry_run_default": True,
            }
            plan["plan_checksum"] = service._sha256_json(plan)

            with patch("core.service.windows_recycle", return_value=True) as mock_recycle:
                with patch("core.service.evaluate_delete_permission", side_effect=[
                    {"allow": False, "reason_code": "outside_safe_roots", "reason": "Path is outside selected scan roots."},
                    {"allow": True, "reason_code": "allowed", "reason": "Allowed by protection policy."},
                ]):
                    with patch("core.service.append_prune_event") as mock_event:
                        result = service.apply_prune(
                            plan,
                            dry_run=False,
                            yes=True,
                            audit_log=base / "audit",
                            enforce_safe_delete_roots=True,
                            safe_delete_roots=[allowed_root],
                        )

            self.assertEqual(result["blocked"], 1)
            self.assertEqual(result["applied"], 1)
            self.assertEqual(result["blocked_reasons"]["outside_safe_roots"], 1)
            self.assertEqual(mock_recycle.call_count, 1)
            self.assertEqual(mock_event.call_count, 2)
            denied_event = mock_event.call_args_list[0].args[1]
            self.assertEqual(denied_event["policy_decision"], "blocked")
            self.assertEqual(denied_event["policy_reason_code"], "outside_safe_roots")
            self.assertEqual(denied_event["matched_rule"], "safe_delete_roots")

            report = json.loads((base / "audit" / "policy_block_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["blocked_total"], 1)
            self.assertEqual(report["blocked_by_reason"]["outside_safe_roots"], 1)
            self.assertEqual(len(report["blocked_paths_by_reason"]["outside_safe_roots"]), 1)
            summary_text = (base / "audit" / "prune_summary.txt").read_text(encoding="utf-8")
            self.assertIn("Policy summary", summary_text)
            self.assertIn("outside_safe_roots: 1", summary_text)


if __name__ == "__main__":
    unittest.main()
