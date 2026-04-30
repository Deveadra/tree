import json
from pathlib import Path

from core.service import plan_prune
from dupe_core import DupeGroup, FileRec


def test_golden_plan_fixture_is_reproducible(tmp_path):
    keep = tmp_path / "keep.txt"
    prune = tmp_path / "prune.txt"
    keep.write_text("keep", encoding="utf-8")
    prune.write_text("drop", encoding="utf-8")

    g = DupeGroup(
        sha256="deadbeef",
        size=4,
        files=[
            FileRec(path=str(keep), name="keep.txt", size=4, mtime=200),
            FileRec(path=str(prune), name="prune.txt", size=4, mtime=100),
        ],
    )
    fixture = json.loads(Path("tests/fixtures/golden_plan_output.json").read_text(encoding="utf-8"))
    out = plan_prune([g], source_id="golden")

    assert out["schema"] == fixture["schema"]
    assert out["groups"] == fixture["groups"]
    assert out["files_to_prune"] == fixture["files_to_prune"]
    assert out["bytes_reclaimable"] == fixture["bytes_reclaimable"]
    assert len(out["metadata"]["policy_firewall"]["violations"]) == fixture["blocked_violations"]
