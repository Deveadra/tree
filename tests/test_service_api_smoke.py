from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from core import service
from core.models import ScanRequest


class ServiceApiSmokeTests(unittest.TestCase):
    def test_exported_apis_import_and_minimal_calls(self):
        expected_exports = {
            "scan_to_db",
            "load_dupes",
            "serialize_dupes",
            "plan_prune",
            "apply_prune",
            "write_reports",
            "scan",
            "find_duplicates",
            "build_prune_plan",
            "execute_prune_plan",
        }
        self.assertEqual(set(service.__all__), expected_exports)

        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "scan.db"
            root = tmp / "root"
            root.mkdir()

            with patch("core.service.scan_root_to_db", return_value={"scanned": 0}) as mock_scan:
                stats = service.scan_to_db([root], db_path, excludes=set())
                self.assertEqual(stats, {"scanned": 0})
                mock_scan.assert_called_once()

            with patch("core.service.find_dupes_from_db", return_value=[]) as mock_load:
                groups = service.load_dupes(db_path)
                self.assertEqual(groups, [])
                mock_load.assert_called_once()

            self.assertEqual(service.serialize_dupes([]), [])

            plan = service.plan_prune([])
            self.assertEqual(plan["files_to_prune"], 0)

            applied = service.apply_prune(service.plan_prune([]), dry_run=True)
            self.assertEqual(applied["skipped"], 0)

            service.write_reports(tmp / "reports", [], {"dupe_groups": 0}, set())

            with patch("core.service.scan_to_db", return_value={"scanned": 1}) as mock_scan_req:
                request = ScanRequest(db_path=db_path, roots=[root])
                result = service.scan(request)
                self.assertEqual(result, {"scanned": 1})
                mock_scan_req.assert_called_once()

            with patch("core.service.hash_find_duplicates", return_value=[]) as mock_find:
                dupes = service.find_duplicates(db_path, cancel_flag=lambda: False, metrics_cb=lambda _m: None)
                self.assertEqual(dupes, [])
                mock_find.assert_called_once()

            compat_plan = service.build_prune_plan([str(root / "a.txt")])
            self.assertEqual(compat_plan.total_candidates, 1)


if __name__ == "__main__":
    unittest.main()
