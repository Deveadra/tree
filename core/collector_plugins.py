from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
import platform


@dataclass(frozen=True)
class CollectorPluginMetadata:
    capability_name: str
    overhead_estimate: str
    permission_requirements: list[str]


@dataclass(frozen=True)
class CollectorPlugin:
    metadata: CollectorPluginMetadata
    supported_platforms: tuple[str, ...]
    is_available: Callable[[], bool]
    collect: Callable[[Path], dict[str, Any]]



def _platform_tag() -> str:
    return platform.system().lower()


def _collect_cloud_sync_state(root: Path) -> dict[str, Any]:
    hints = ["onedrive", "dropbox", "google drive", "icloud drive"]
    root_str = str(root).lower()
    detected = [h for h in hints if h in root_str]
    return {
        "detected_sync_clients": detected,
        "observations": "path-pattern heuristic",
    }


def _collect_package_manager_caches(root: Path) -> dict[str, Any]:
    candidates = [
        root / ".cache" / "pip",
        root / ".npm",
        root / ".pnpm-store",
        root / ".cache" / "yarn",
        root / ".cargo" / "registry",
        root / ".m2" / "repository",
    ]
    present = [str(p) for p in candidates if p.exists()]
    return {"present_cache_paths": present, "count": len(present)}


def _collect_container_runtime_storage(root: Path) -> dict[str, Any]:
    candidates = [root / "var" / "lib" / "docker", root / "var" / "lib" / "containerd"]
    present = [str(p) for p in candidates if p.exists()]
    return {"present_runtime_paths": present, "count": len(present)}


def _collect_vm_images(root: Path) -> dict[str, Any]:
    vm_exts = {".vdi", ".vmdk", ".qcow2", ".vhd", ".vhdx"}
    hits: list[str] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in vm_exts:
            hits.append(str(p))
            if len(hits) >= 50:
                break
    return {"vm_image_samples": hits, "sample_count": len(hits)}


def load_collector_plugins() -> list[CollectorPlugin]:
    current = _platform_tag()
    registry = [
        CollectorPlugin(
            metadata=CollectorPluginMetadata(
                capability_name="cloud sync state",
                overhead_estimate="low",
                permission_requirements=["read filesystem metadata"],
            ),
            supported_platforms=("windows", "darwin", "linux"),
            is_available=lambda: True,
            collect=_collect_cloud_sync_state,
        ),
        CollectorPlugin(
            metadata=CollectorPluginMetadata(
                capability_name="package manager caches",
                overhead_estimate="low",
                permission_requirements=["read filesystem metadata"],
            ),
            supported_platforms=("windows", "darwin", "linux"),
            is_available=lambda: True,
            collect=_collect_package_manager_caches,
        ),
        CollectorPlugin(
            metadata=CollectorPluginMetadata(
                capability_name="container/runtime storage",
                overhead_estimate="medium",
                permission_requirements=["read filesystem metadata", "access system runtime dirs"],
            ),
            supported_platforms=("linux",),
            is_available=lambda: True,
            collect=_collect_container_runtime_storage,
        ),
        CollectorPlugin(
            metadata=CollectorPluginMetadata(
                capability_name="VM images/snapshots",
                overhead_estimate="medium",
                permission_requirements=["read filesystem metadata", "directory traversal"],
            ),
            supported_platforms=("windows", "darwin", "linux"),
            is_available=lambda: True,
            collect=_collect_vm_images,
        ),
    ]
    return [p for p in registry if current in p.supported_platforms and p.is_available()]


def run_plugins_safely(root: Path, plugins: list[CollectorPlugin] | None = None) -> dict[str, Any]:
    loaded = plugins if plugins is not None else load_collector_plugins()
    out: list[dict[str, Any]] = []
    for plugin in loaded:
        entry = {
            "metadata": {
                "capability_name": plugin.metadata.capability_name,
                "overhead_estimate": plugin.metadata.overhead_estimate,
                "permission_requirements": list(plugin.metadata.permission_requirements),
            }
        }
        try:
            entry["status"] = "ok"
            entry["data"] = plugin.collect(root)
        except Exception as exc:
            entry["status"] = "failed"
            entry["error"] = {"type": type(exc).__name__, "message": str(exc)}
        out.append(entry)
    return {"plugins": out}
