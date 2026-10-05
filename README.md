# Zync Plugin Registry

Rust tooling and publication inputs for Zync's signed plugin registry. Current
desktop builds configured for this registry use the published `registry.json`.

## Community submissions

Follow the [publisher guide](https://zync.thesudoer.in/docs/plugin-publishing/)
and [submission checklist](CONTRIBUTING.md). New plugins use Manifest v2, an
approved publisher/repository/key binding, and signed GitHub release ZIPs with
matching `.sha256` assets. Do not edit generated `registry.json` or send private keys.

## Current scope

The `zync-registry` CLI downloads and verifies approved releases, prepares offline
signing bundles, signs registry metadata, and verifies signed registries without
executing plugin code. A key embedded in a package is not automatically trusted.

The verifier checks every payload hash, package identity, Ed25519 signature, and
the directory digest used by Zync. It rejects links and unsafe paths, and enforces
file-count and size limits.

```powershell
cargo run --locked -- verify-package PATH_TO_PACKAGE --approved-key-id sha256:APPROVED_FINGERPRINT
```

## Development

Modules are separated by responsibility. Standard Rust formatting and warning-free
Clippy checks are required, locally and in CI.

```powershell
cargo fmt --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

## Prepare the registry

Edit `registry-input.json` to add a release. Preserve earlier entries and cumulative
revocations. Publisher identity, repository, and key approvals are maintained
separately in `approved-publishers.json`; changes require operator review.
Existing releases remain immutable except for `thumbnailUrl` presentation updates.
Package identity, hashes, signing keys and trust fields cannot be changed, and
previous revocations must be retained.

```powershell
cargo run --locked -- prepare --input registry-input.json --approvals approved-publishers.json --output prepared-registry
```

The preparation workflow performs this same operation without signing secrets.
It uploads `verified-registry-signing-input`, containing packages, a release
descriptor, prepared metadata, and a verification report. None of these files is
a signed registry. Failed runs may leave partial output; use a new output directory
when retrying. Packages are never executed.

Each release must provide `assetName`, the exact signed ZIP filename attached to
its GitHub version tag, such as `docker-manager-0.2.0-signed.zip`. The checksum
asset must use the same filename with `.sha256` appended. No plugin-specific
Rust changes are needed to add another stable release.
Tags default to `v<version>` for existing releases. Set `releaseTag` for a
different tag convention, such as Zedit's `zedit-v0.1.0`.

Preparation accepts bounded regular-file archives with safe, unique paths.
The signed integrity metadata defines the complete payload; missing, modified,
or additional unsigned files fail verification. HTTPS-only redirects, checksums,
download limits, package identity and approved publisher/repository/key bindings
remain mandatory. Beta preparation is not currently supported.

## Sign, verify, and publish

See [registry operations](docs/REGISTRY_OPERATIONS.md) for automated publication,
protected CI key setup, local fallback commands, and increasing versions.

The signer produces the existing `zync.plugin-registry` envelope, including its
Ed25519 root signature. Canonical serialization is tested against the previous
JavaScript implementation. Signing re-verifies package payloads and approvals;
it does not trust the unsigned preparation report.

## Desktop integration

Package compatibility, release downloads, registry signing, root verification,
and history-preservation checks are implemented. For a new deployment or a
desktop build moving from a legacy URL:

1. Complete security review and staging tests against a Zync desktop build.
2. Configure the protected CI signing environment and public root variable.
3. Publish production `registry.json` using the existing root.
4. Configure a new Zync build with the new registry URL and public trust keys.

Do not substitute a test fixture root or unsigned JSON for production metadata.
The workflow refreshes metadata daily with a seven-day expiry and an increasing
registry version. Private keys belong only in protected
signing custody, never repository files or artifacts.
