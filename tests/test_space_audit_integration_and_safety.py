import json
from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
import tempfile

from core.space_audit import (
    diff_space_snapshots,
    scan_space_usage,
    summarize_by_extension,
    summarize_top_dirs,
    write_space_reports,
)


def test_first_and_second_snapshot_report_generation_with_diff():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir) / "root"
        root.mkdir()
        (root / "a.txt").write_text("a", encoding="utf-8")

        snapshot1 = scan_space_usage(root, excludes=[])
        reports1 = write_space_reports(root / "reports1", snapshot1, summarize_top_dirs(snapshot1), summarize_by_extension(snapshot1))
        assert Path(reports1["snapshot"]).exists()

        (root / "b.log").write_text("bbbb", encoding="utf-8")
        snapshot2 = scan_space_usage(root, excludes=[])
        diff = diff_space_snapshots(snapshot2, snapshot1)
        reports2 = write_space_reports(root / "reports2", snapshot2, summarize_top_dirs(snapshot2), summarize_by_extension(snapshot2), diff=diff)
        assert Path(reports2["diff"]).exists()
        assert Path(reports2["diff_vs_previous"]).exists()


def test_audit_scan_never_calls_delete_move_or_recycle(monkeypatch):
    tmpdir = tempfile.mkdtemp()
    try:
        root = Path(tmpdir)
        (root / "x.bin").write_bytes(b"x" * 16)

        calls: list[str] = []

        def _record(name: str):
            def inner(*_args, **_kwargs):
                calls.append(name)
                raise AssertionError(f"unexpected destructive call: {name}")
            return inner

        monkeypatch.setattr("core.space_audit.os.remove", _record("os.remove"), raising=False)
        monkeypatch.setattr("core.space_audit.os.unlink", _record("os.unlink"), raising=False)
        monkeypatch.setattr("core.space_audit.os.replace", _record("os.replace"), raising=False)
        monkeypatch.setattr("core.space_audit.Path.unlink", _record("Path.unlink"), raising=False)
        monkeypatch.setattr("core.space_audit.Path.rename", _record("Path.rename"), raising=False)

        scan_space_usage(root, excludes=[])
        assert calls == []
    finally:
        monkeypatch.undo()
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_schema_compatibility_for_json_outputs():
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir) / "root"
        out = Path(tmpdir) / "out"
        root.mkdir()
        (root / "a.txt").write_text("abc", encoding="utf-8")

        snapshot = scan_space_usage(root, excludes=[])
        top_dirs = summarize_top_dirs(snapshot)
        by_ext = summarize_by_extension(snapshot)
        diff = diff_space_snapshots(snapshot, snapshot)
        paths = write_space_reports(out, snapshot, top_dirs, by_ext, diff=diff, timeline_row={"ts": "now"})

        required_keys = {
            "snapshot": ["schema_version", "run", "totals", "tree", "extensions", "categories", "protection"],
            "top_dirs": ["schema_version", "generated_at", "rows"],
            "by_extension": ["schema_version", "generated_at", "rows"],
            "usage_by_dir": ["schema_version", "generated_at", "rows"],
            "usage_by_ext": ["schema_version", "generated_at", "rows"],
            "audit_summary": ["schema_version", "generated_at", "summary"],
            "audit_meta": ["schema_version", "generated_at", "run", "artifacts"],
            "diff": ["schema_version", "run", "config", "totals", "summary", "tree", "extensions"],
            "timeline_row": ["schema_version", "row"],
        }

        for artifact, expected_fields in required_keys.items():
            payload = json.loads(Path(paths[artifact]).read_text(encoding="utf-8"))
            for field in expected_fields:
                assert field in payload
            assert "schema_version" in payload
