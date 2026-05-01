# Release signing and verification

## Signing process

Release artifacts are built deterministically by `scripts/release/build_artifacts.py` for:
- Linux (`tree-linux.tar.gz`)
- macOS (`tree-macos.tar.gz`)
- Windows (`tree-windows.zip`)

CI then:
1. Generates `checksums.sha256.json`.
2. Generates per-artifact SBOM (`*.spdx.json`) via Syft.
3. Generates provenance (`provenance.intoto.jsonl`) in SLSA/in-toto statement format.
4. Signs each artifact with Cosign and publishes `*.sig`.

## Verification instructions (end users)

1. Download release artifacts, `checksums.sha256.json`, and matching `.sig` files.
2. Validate checksums:

```bash
python scripts/release/verify_checksums.py --dist <download_dir>
```

3. Verify signatures:

```bash
cosign verify-blob --key cosign.pub --signature <artifact>.sig <artifact>
```

4. Review provenance and SBOM:
- `provenance.intoto.jsonl` should contain the exact artifact SHA256 digests.
- `*.spdx.json` should enumerate package/component inventory.

## Secure upgrade procedure

1. Verify signature and checksum before replacing any installed binary.
2. Keep previous release artifact and checksum in a local rollback cache.
3. Install new release.
4. Run a post-upgrade smoke test (`python cli.py --help`, then expected command).
5. If smoke test fails, rollback immediately by restoring prior verified artifact.

## Rollback procedure

1. Stop current running process.
2. Reinstall the last known-good artifact from rollback cache.
3. Re-run checksum/signature verification on the restored artifact.
4. Restart and run smoke tests.
5. Record incident with failing version, restored version, and verification logs.
