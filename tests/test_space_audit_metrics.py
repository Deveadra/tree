from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from core.space_audit import scan_space_usage


class SpaceAuditMetricsTests(unittest.TestCase):
    def test_collects_volume_reconciliation_and_size_modes(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "a.txt").write_bytes(b"a" * 10)
            (root / "sub").mkdir()
            (root / "sub" / "b.bin").write_bytes(b"b" * 20)

            snapshot = scan_space_usage(root, excludes=[])

            totals = snapshot["totals"]
            self.assertEqual(totals["tree_sum_bytes"], 30)
            self.assertEqual(totals["tree_bytes"], 30)
            self.assertEqual(totals["volume_used_bytes"], totals["volume_total_bytes"] - totals["volume_free_bytes"])
            self.assertEqual(totals["unattributed_bytes"], totals["volume_used_bytes"] - totals["tree_sum_bytes"])

            self.assertIn("tree_sum_allocated_bytes", totals)
            self.assertIn("reserved_or_system_managed_estimate", totals)
            self.assertIn("size_modes", snapshot)
            self.assertIn("confidence", snapshot)
            self.assertIn("caveats", snapshot)
            self.assertIn("dir_allocated_bytes", snapshot["tree"])
            self.assertIn("ext_allocated_bytes", snapshot["extensions"])

    def test_allocated_size_falls_back_when_st_blocks_unavailable(self):
        class FakeStat:
            def __init__(self, size: int):
                self.st_size = size

        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            file_path = root / "f.txt"
            file_path.write_bytes(b"x" * 7)

            with patch("pathlib.Path.stat", return_value=FakeStat(7)):
                snapshot = scan_space_usage(root, excludes=[])

            allocated_mode = snapshot["size_modes"]["allocated"]
            self.assertEqual(allocated_mode["confidence"], "low")
            self.assertIn("allocated size equals apparent size", allocated_mode["fallback_behavior"])
            self.assertEqual(snapshot["tree"]["dir_bytes"].get("."), snapshot["tree"]["dir_allocated_bytes"].get("."))



    def test_includes_category_rows_and_item_metadata(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "docs").mkdir()
            (root / "docs" / "file.txt").write_bytes(b"x" * 12)

            snapshot = scan_space_usage(root, excludes=[])

            self.assertIn("categories", snapshot)
            self.assertIn("rows", snapshot["categories"])
            self.assertIn("items", snapshot["categories"])
            self.assertGreaterEqual(len(snapshot["categories"]["items"]), 1)
            item = snapshot["categories"]["items"][0]
            self.assertIn("matched_rule", item)
            self.assertIn("category", item)
            self.assertIn("confidence", item)

            categories = {row["category"] for row in snapshot["categories"]["rows"]}
            self.assertIn("system-managed / unattributed", categories)

if __name__ == "__main__":
    unittest.main()
