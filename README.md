# Zync Plugin Registry

Rust tooling for the next Zync plugin registry. This repository is being built
alongside `zync-extensions`; it does not replace the legacy marketplace yet.

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

```powershell
cargo run --locked -- prepare --input registry-input.json --approvals approved-publishers.json --output prepared-registry
```

The preparation workflow performs this same operation without signing secrets.
It uploads `verified-registry-signing-input`, containing packages, a release
descriptor, prepared metadata, and a verification report. None of these files is
a signed registry. Failed runs may leave partial output; use a new output directory
when retrying. Packages are never executed.

The initial archive profile supports stable PM2 releases only. It enforces seven
expected files, HTTPS-only redirects, checksums, download limits, signatures, and
approved publisher/repository bindings. Other plugin layouts and beta preparation
require additional reviewed profiles, not relaxed archive checks.

## Sign, verify, and publish

See [registry operations](docs/REGISTRY_OPERATIONS.md) for automated publication,
protected CI key setup, local fallback commands, and increasing versions.

The signer produces the existing `zync.plugin-registry` envelope, including its
Ed25519 root signature. Canonical serialization is tested against the previous
JavaScript implementation. Signing re-verifies package payloads and approvals;
it does not trust the unsigned preparation report.

## Migration

Package compatibility, release downloads, registry signing, root verification,
and history-preservation checks are implemented. Before production migration:

1. Complete security review and staging tests against a Zync desktop build.
2. Configure the protected CI signing environment and public root variable.
3. Publish production `registry.json` using the existing root.
4. Configure a new Zync build with the new registry URL and public trust keys.
5. Retain `zync-extensions` for older clients until a separate retirement decision.

Do not substitute a test fixture root or unsigned JSON for production metadata.
The workflow signs non-expiring metadata (`expiresAtMs: 0`) with the approved root;
this requires a compatible Zync build. Private keys belong only in protected
signing custody, never repository files or artifacts.
