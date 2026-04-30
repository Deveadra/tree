from pathlib import Path

from core.collector_plugins import CollectorPlugin, CollectorPluginMetadata, run_plugins_safely


def test_plugin_metadata_and_sandboxed_failures(tmp_path: Path):
    ok = CollectorPlugin(
        metadata=CollectorPluginMetadata(
            capability_name="cloud sync state",
            overhead_estimate="low",
            permission_requirements=["read filesystem metadata"],
        ),
        supported_platforms=("linux",),
        is_available=lambda: True,
        collect=lambda root: {"root": str(root)},
    )
    bad = CollectorPlugin(
        metadata=CollectorPluginMetadata(
            capability_name="VM images/snapshots",
            overhead_estimate="medium",
            permission_requirements=["read filesystem metadata", "directory traversal"],
        ),
        supported_platforms=("linux",),
        is_available=lambda: True,
        collect=lambda _root: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    payload = run_plugins_safely(tmp_path, plugins=[ok, bad])
    assert len(payload["plugins"]) == 2
    first = payload["plugins"][0]
    assert first["status"] == "ok"
    assert first["metadata"]["capability_name"] == "cloud sync state"
    assert first["metadata"]["overhead_estimate"] == "low"
    assert first["metadata"]["permission_requirements"] == ["read filesystem metadata"]

    second = payload["plugins"][1]
    assert second["status"] == "failed"
    assert second["error"]["type"] == "RuntimeError"
