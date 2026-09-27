# Registry operations

## Automated publication

The publication workflow runs on approved input/source changes pushed to `main`,
daily on a schedule, or manually from `main`. Pull requests run checks only; they never receive keys.

1. Preparation formats, lints, tests, builds, and verifies release packages.
2. Signing uses the separate `registry-release` environment. It receives the
   private root only for signing and removes its temporary key file.
3. Publication receives no signing secret. It commits only verified `registry.json`
   and refuses publication if `main` changed during preparation.

Publication is serialized. Every update authenticates the previous registry with
configured public roots, increases its version, and retains all releases and
revocations. The generated commit does not trigger another publication.

## One-time GitHub setup

Create an environment named `registry-release` in `zync-sh/zync-plugin-registry`.
Restrict deployment to `main`. For unattended operation, do not require a manual
reviewer for every run; instead protect/review changes to source, workflows,
publisher approvals, and registry input before they reach main.

Use branch rulesets/protection requiring Rust checks and reviewed changes, with
narrowly scoped publication access for generated metadata. A main-only signing
environment does not prevent a main-branch workflow change from abusing secrets.
Verify these GitHub settings before production publication. Solo maintainers
should record self-review and restrict bypass/admin access, not claim independent review.

Use branch rulesets/protection requiring Rust checks and reviewed changes, with
narrowly scoped publication access for generated metadata. A main-only signing
environment does not prevent a main-branch workflow change from abusing secrets.
Verify these GitHub settings before production publication. Solo maintainers
should record self-review and restrict bypass/admin access, not claim independent review.

Set:

- Environment secret `REGISTRY_ROOT_PRIVATE_KEY`: complete unencrypted Ed25519
  PKCS#8 PEM root private key, separate from the PM2 publisher key.
- Repository variable `ZYNC_PLUGIN_REGISTRY_ROOT_KEYS`: raw 32-byte public root
  encoded as base64, or a comma-separated rotation bundle. This is not secret.

Enable GitHub Actions write permission for repository contents. Branch protection
must allow the publication identity to commit generated metadata. If rules block
bot pushes, publication fails; do not disable checks globally. Use a narrowly
scoped publishing identity or change publication to a reviewed PR.

Never commit private keys or include them in artifacts, chat, or logs. CI signing
is approved custody, but compromise of the signing job or secret permits registry
forgery. Restrict administrator access, retain encrypted recovery backups, and
use a separate root from every publisher. Independent review is recommended;
a solo maintainer may use documented self-review.

## Expiry and automatic refresh

Publication signs metadata valid for seven days and refreshes it daily. Monitor
failed or disabled scheduled runs; if refresh stops, marketplace metadata expires
and new marketplace operations fail closed until publication is restored.
Monitor Actions failures and scheduled-run status. GitHub can disable schedules
in inactive public repositories; re-enable or dispatch before expiry and
investigate publication failures.
Monitor Actions failures and scheduled-run status. GitHub can disable schedules
in inactive public repositories; re-enable or dispatch before expiry and
investigate publication failures.
Installed plugins are unaffected by registry expiry policy.

Expiry bounds replay but does not guarantee immediate delivery of revocations.
Retained version floors and cumulative revocations additionally protect clients
after they observe newer metadata. The verifier accepts historical zero-expiry
metadata for migration; the publication CLI refuses to produce it.

After the first expiring publication, raise Zync's release minimum registry
version to that version before rebuilding. Otherwise fresh clients can still
accept previously published non-expiring indexes. Keep legacy catalog URLs available.

## Local signing fallback

```powershell
zync-registry sign --descriptor prepared-registry/registry-releases.json --approvals approved-publishers.json --key PATH_TO_ROOT_PRIVATE_PEM --output registry.json --version 1 --minimum-version 1 --issued-at-ms ISSUE_TIME_MS --expires-at-ms EXPIRY_TIME_MS
zync-registry verify-registry registry.json --root-keys RAW_PUBLIC_KEY_BASE64 --now-ms CURRENT_TIME_MS --minimum-version 1
```

`--expires-at-ms` is required, later than issuance, and no more than seven days away.
Output must not exist; keys must stay outside the repository/bundle. Encrypted
PEM support has not been ported to Rust.

Updates require `--baseline PREVIOUS_SIGNED_REGISTRY_JSON --root-keys ROOT_KEYS`,
a greater version, and supplied minimum floor. Every published counter increases,
including retries after failed promotion. Never reset a published registry to one.

## Release validation

CI verifies provenance and integrity, not benign plugin behavior. Review
compatibility, permissions, manifests, and behavior before approval. Test the
published file in Zync before announcing marketplace availability.

The production URL after publication will be:

`https://raw.githubusercontent.com/zync-sh/zync-plugin-registry/main/registry.json`

Desktop builds receive only the URL, public root keys, and version floor.
Changing registry content does not require rebuilding Zync; changing its baked-in
URL, trust roots, or expiry semantics does.
