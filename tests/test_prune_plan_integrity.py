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


if __name__ == "__main__":
    unittest.main()
