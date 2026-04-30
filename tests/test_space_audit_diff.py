from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from core.space_audit import diff_space_snapshots, resolve_previous_snapshot, write_space_reports


class SpaceAuditDiffTests(unittest.TestCase):
    def test_diff_includes_rankings_and_summary(self):
        previous = {
            "run": {"finished_at": "2026-04-29T10:00:00+00:00"},
            "totals": {"tree_bytes": 150, "file_count": 3},
            "tree": {"dir_bytes": {".": 150, "a": 100, "b": 50}},
            "extensions": {"ext_bytes": {".txt": 100}},
        }
        current = {
            "run": {"finished_at": "2026-04-30T10:00:00+00:00"},
            "totals": {"tree_bytes": 185, "file_count": 4},
            "tree": {"dir_bytes": {".": 185, "a": 40, "c": 145}},
            "extensions": {"ext_bytes": {".txt": 120}},
        }

        diff = diff_space_snapshots(current, previous, noise_threshold_bytes=10)

        self.assertEqual(diff["summary"]["total_growth_bytes"], 180)
        self.assertEqual(diff["summary"]["total_shrink_bytes"], 110)
        self.assertEqual(diff["summary"]["net_change_bytes"], 70)
        self.assertEqual(diff["tree"]["ranked_growth"][0]["path"], "c")
        self.assertEqual(diff["tree"]["ranked_shrink"][0]["path"], "a")
        self.assertTrue(any(row["status"] == "deleted" and row["path"] == "b" for row in diff["tree"]["dir_delta_rows"]))

    def test_resolve_previous_snapshot_by_root(self):
        with TemporaryDirectory() as tmp:
            report_root = Path(tmp)
            run1 = report_root / "run_001"
            run2 = report_root / "run_002"
            run3 = report_root / "run_003"
            run1.mkdir(); run2.mkdir(); run3.mkdir()

            snap1 = {"run": {"root": str(report_root), "finished_at": "2026-04-28T00:00:00+00:00"}}
            snap2 = {"run": {"root": str(report_root), "finished_at": "2026-04-29T00:00:00+00:00"}}
            snap3 = {"run": {"root": "/other/root", "finished_at": "2026-04-30T00:00:00+00:00"}}
            (run1 / "space_snapshot.json").write_text(__import__("json").dumps(snap1), encoding="utf-8")
            (run2 / "space_snapshot.json").write_text(__import__("json").dumps(snap2), encoding="utf-8")
            (run3 / "space_snapshot.json").write_text(__import__("json").dumps(snap3), encoding="utf-8")

            found = resolve_previous_snapshot(report_root, run3, report_root)
            self.assertIsNotNone(found)
            self.assertEqual(found["run"]["finished_at"], "2026-04-29T00:00:00+00:00")

    def test_write_reports_emits_new_diff_filename(self):
        with TemporaryDirectory() as tmp:
            out = write_space_reports(
                tmp,
                snapshot={"schema_version": "1.1"},
                top_dirs=[],
                by_ext=[],
                diff={"schema_version": "1.1"},
            )
            self.assertIn("diff_vs_previous", out)
            self.assertTrue((Path(tmp) / "space_diff_vs_previous.json").exists())


if __name__ == "__main__":
    unittest.main()
