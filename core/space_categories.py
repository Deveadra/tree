from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CategoryRule:
    category: str
    rule_id: str
    confidence: float
    path_contains: tuple[str, ...] = ()
    path_suffixes: tuple[str, ...] = ()

    def matches(self, rel_path: str) -> bool:
        rel_lower = rel_path.lower()
        return (
            any(token in rel_lower for token in self.path_contains)
            or any(rel_lower.endswith(suffix) for suffix in self.path_suffixes)
        )


RULES: tuple[CategoryRule, ...] = (
    CategoryRule("recycle/trash", "trash-path", 0.99, path_contains=("/.trash", "$recycle.bin", "/trash/")),
    CategoryRule("backups/snapshots", "backup-keywords", 0.95, path_contains=("/backup", "/backups", "/snapshot", "/snapshots", "timemachine")),
    CategoryRule("package caches", "package-cache-paths", 0.97, path_contains=("/.cache/pip", "/.npm", "/.pnpm-store", "/.cache/yarn", "/.cache/pypoetry", "/.cargo/registry", "/.m2/repository", "/.gradle/caches")),
    CategoryRule("app installs", "application-install-paths", 0.92, path_contains=("/applications/", "/program files", "/appdata/local/programs", "/opt/homebrew/caskroom", "/usr/local/cellar")),
    CategoryRule("temp/caches", "temp-cache-paths", 0.9, path_contains=("/tmp/", "/temp/", "/.cache/", "/var/cache/", "/cache/")),
    CategoryRule("dev tooling", "dev-tooling-paths", 0.89, path_contains=("/.venv/", "/node_modules/", "/.tox/", "/.idea/", "/.vscode/", "/target/", "/dist/", "/build/")),
    CategoryRule("cloud placeholders/hydrated", "cloud-sync-paths", 0.8, path_contains=("onedrive", "dropbox", "google drive", "icloud drive")),
    CategoryRule("user content", "user-content-extensions", 0.75, path_suffixes=(".jpg", ".jpeg", ".png", ".gif", ".mov", ".mp4", ".mkv", ".mp3", ".wav", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".zip", ".7z", ".tar", ".gz")),
)


def classify_path(rel_path: str) -> dict[str, object]:
    normalized = rel_path.replace("\\", "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    for rule in RULES:
        if rule.matches(normalized):
            return {"category": rule.category, "matched_rule": rule.rule_id, "confidence": rule.confidence}
    return {"category": "system-managed / unattributed", "matched_rule": "unmatched", "confidence": 0.2}
