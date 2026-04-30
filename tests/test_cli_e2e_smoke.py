import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class CliE2ESmokeTests(unittest.TestCase):
    def _make_fixture(self, tmp: Path) -> Path:
        root = tmp / "fixture"
        root.mkdir()
        (root / "dupe_a.txt").write_text("same-content", encoding="utf-8")
        (root / "dupe_b.txt").write_text("same-content", encoding="utf-8")
        (root / "unique.txt").write_text("different", encoding="utf-8")
        return root

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "cli.py", *args],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_scan_dupes_plan_and_apply_dry_run(self):
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            root = self._make_fixture(tmp)
            report_dir = tmp / "reports"
            db_path = report_dir / "scan.db"
            audit_dir = report_dir / "audit"
            audit_events = audit_dir / "prune_events.jsonl"

            scan = self._run_cli(
                "scan",
                str(root),
                "--report-dir",
                str(report_dir),
                "--db",
                str(db_path),
                "--json",
            )
            self.assertEqual(scan.returncode, 0, scan.stderr)
            scan_payload = json.loads(scan.stdout)
            self.assertTrue(db_path.exists())
            self.assertEqual(scan_payload["db"], str(db_path))
            self.assertIn("scan_stats", scan_payload)

            dupes = self._run_cli("dupes", "--db", str(db_path), "--json")
            self.assertEqual(dupes.returncode, 0, dupes.stderr)
            dupes_payload = json.loads(dupes.stdout)
            self.assertGreaterEqual(dupes_payload["group_count"], 1)
            self.assertIn("groups", dupes_payload)
            first_group = dupes_payload["groups"][0]
            for required in ("sha256", "size", "count", "files"):
                self.assertIn(required, first_group)

            plan = self._run_cli(
                "plan-prune",
                "--db",
                str(db_path),
                "--report-dir",
                str(report_dir),
                "--json",
            )
            self.assertEqual(plan.returncode, 0, plan.stderr)
            plan_payload = json.loads(plan.stdout)
            plan_path = report_dir / "prune_plan.json"
            self.assertTrue(plan_path.exists())
            self.assertEqual(plan_payload["plan"], str(plan_path))
            self.assertEqual(plan_payload["schema"], "plan-prune")
            self.assertIn("metadata", plan_payload)
            self.assertIn("plan_checksum", plan_payload)
            self.assertTrue(plan_payload["dry_run_default"])

            apply_dry = self._run_cli(
                "apply-prune",
                "--plan",
                str(plan_path),
                "--audit-log",
                str(audit_dir),
                "--json",
            )
            self.assertEqual(apply_dry.returncode, 0, apply_dry.stderr)
            apply_payload = json.loads(apply_dry.stdout)
            self.assertTrue(apply_payload["dry_run"])
            self.assertGreaterEqual(apply_payload["skipped"], 1)
            self.assertTrue(audit_events.exists())
            first_audit = json.loads(audit_events.read_text(encoding="utf-8").splitlines()[0])
            for required in ("action", "path", "status", "reason_code"):
                self.assertIn(required, first_audit)

    def test_apply_prune_destructive_guard_without_yes(self):
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            root = self._make_fixture(tmp)
            report_dir = tmp / "reports"
            db_path = report_dir / "scan.db"

            scan = self._run_cli("scan", str(root), "--report-dir", str(report_dir), "--db", str(db_path))
            self.assertEqual(scan.returncode, 0, scan.stderr)

            plan = self._run_cli("plan-prune", "--db", str(db_path), "--report-dir", str(report_dir))
            self.assertEqual(plan.returncode, 0, plan.stderr)
            plan_path = report_dir / "prune_plan.json"

            blocked = self._run_cli("apply-prune", "--plan", str(plan_path), "--no-dry-run")
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("Refusing destructive action without --yes", blocked.stderr)


if __name__ == "__main__":
    unittest.main()
