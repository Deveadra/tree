import sqlite3
from pathlib import Path

from dupe_core import _db_create_schema, _scan_root_append_to_con


def test_scan_emits_progress_metrics_and_bytes(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("abc", encoding="utf-8")
    (root / "b.txt").write_text("abcdef", encoding="utf-8")
    db_path = tmp_path / "scan.db"
    con = sqlite3.connect(str(db_path))
    _db_create_schema(con)
    seen = []

    def metrics_cb(payload: dict) -> None:
        seen.append(payload)

    out = _scan_root_append_to_con(
        con=con,
        root=root,
        root_id=0,
        exclude_names=set(),
        exclude_prefixes=[],
        follow_symlinks=False,
        min_size=0,
        cancel_flag=lambda: False,
        metrics_cb=metrics_cb,
    )
    assert out["listed"] == 2
    assert out["dirs_visited"] >= 1
    assert out["bytes_observed"] >= 9
    assert any("elapsed_s" in m and "dirs_visited" in m and "bytes_observed" in m for m in seen)
    con.close()


def test_scan_stops_when_error_budget_is_exhausted(tmp_path: Path):
    missing_root = tmp_path / "missing"
    db_path = tmp_path / "scan.db"
    con = sqlite3.connect(str(db_path))
    _db_create_schema(con)
    out = _scan_root_append_to_con(
        con=con,
        root=missing_root,
        root_id=0,
        exclude_names=set(),
        exclude_prefixes=[],
        follow_symlinks=False,
        min_size=0,
        cancel_flag=lambda: False,
        metrics_cb=lambda _: None,
        error_budget=1,
    )
    assert out["errors"] == 1
    assert out["error_budget_exhausted"] is True
    con.close()
