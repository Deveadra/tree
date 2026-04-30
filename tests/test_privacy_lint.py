import json
import re
from pathlib import Path


PRIVACY_PATTERNS = [
    re.compile(r"[A-Za-z]:\\\\Users\\\\", re.IGNORECASE),
    re.compile(r"/home/"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
]


def _iter_strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)
    elif isinstance(value, str):
        yield value


def lint_share_safe_artifact(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    violations = []
    for text in _iter_strings(data):
        for p in PRIVACY_PATTERNS:
            if p.search(text):
                violations.append(text)
    return violations


def test_share_safe_fixture_has_no_privacy_leaks(tmp_path):
    artifact = tmp_path / "share_safe.json"
    artifact.write_text(json.dumps({"summary": "safe", "links": ["https://example.com"]}), encoding="utf-8")
    assert lint_share_safe_artifact(artifact) == []


def test_privacy_lint_detects_raw_user_paths_and_emails(tmp_path):
    artifact = tmp_path / "unsafe.json"
    artifact.write_text(
        json.dumps({"path": r"C:\\Users\\Alice\\secret.txt", "owner": "alice@example.com"}),
        encoding="utf-8",
    )
    violations = lint_share_safe_artifact(artifact)
    assert len(violations) == 2
