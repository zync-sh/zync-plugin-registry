# Submit a Zync plugin release

Start with the community [development](https://zync.thesudoer.in/docs/plugin-development/),
[API](https://zync.thesudoer.in/docs/plugin-api/),
[publishing](https://zync.thesudoer.in/docs/plugin-publishing/), and
[best-practices](https://zync.thesudoer.in/docs/plugin-best-practices/) guides.
This file describes the review boundary for this repository.

## Publisher checklist

- Use a Manifest v2 plugin ID under your publisher namespace.
- Build and test the declared minimum Zync version and supported platforms.
- Publish source with a matching release tag and include license/dependency notices.
- Sign the built package with your Ed25519 publisher key. Verify an extracted
  copy of the final ZIP, not only the directory before compression.
- Attach the signed ZIP and `<zip-name>.sha256` to a public GitHub release.
  The checksum must contain lowercase hex, two spaces, and the ZIP filename.
- Provide the public PEM and signer fingerprint for independent approval.
  Never provide a private key, passphrase, application key, or registry root.
- Explain permissions and data handling, and supply test results and a support contact.

## Files to propose

`approved-publishers.json` binds publisher, plugin ID, GitHub repository, and
approved public-key fingerprints. New bindings and key rotations require
maintainer review; submitting an entry is not approval.

Append a release to `registry-input.json`. Use the exact `assetName`, stable
semantic `version`, and repository. `releaseTag` defaults to `v<version>` and may
be supplied for another tag convention. Set `publisherVerified` to false unless
maintainers approve that identity label. A signature is not a verified-publisher badge.

Preserve earlier release entries and cumulative revocations. Published identities,
hashes, download URLs, and trust bindings are immutable; do not replace release
assets to fix an existing version. Use a new version. Presentation-only thumbnail
changes are handled separately by the registry's history checks.

Do not edit generated `registry.json`. Preparation output is unsigned and must
not be uploaded as trusted metadata. Maintainers publish through the protected
registry workflow after review.

## Checks

From this checkout:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- prepare --input registry-input.json --approvals approved-publishers.json --output prepared-review
```

Preparation downloads the input releases and requires a new output directory.
It never executes their code. It currently rejects prerelease and build-metadata
versions; desktop beta-channel support does not imply this preparer accepts beta
submissions. Coordinate that workflow with maintainers before publishing a beta.

## Review and publication

Review source, permission reasons, supported host versions, exact artifacts,
publisher ownership, and public-key fingerprints. Automated validation checks
integrity and provenance, not behavior safety. Do not expose signing secrets to
PR-validation jobs. See [operations](docs/REGISTRY_OPERATIONS.md) for registry
signing, expiry refresh, root rotation, and recovery.

After publication, validate installation and update in an installed Zync build
using this registry before announcing availability. Report suspected key or
release compromise to maintainers without posting private keys or sensitive logs.
