use std::{collections::BTreeSet, path::Path};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, pkcs8::DecodePrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{files, package};

const DOMAIN: &[u8] = b"zync-plugin-registry-v1\n";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    pub publisher: String,
    pub plugin_id: String,
    pub repository: String,
    pub key_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approvals {
    pub publishers: Vec<Approval>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseDescriptor {
    pub package_path: String,
    pub download_url: String,
    pub publisher_verified: bool,
    pub channel: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub releases: Vec<ReleaseDescriptor>,
    pub revocations: Vec<Value>,
}

pub fn fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Canonical serialization matches the existing JavaScript operator's UTF-16 key order.
pub fn canonical(value: &Value) -> Result<String> {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<_> = fields.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            let entries = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical(&fields[key])?
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("{{{}}}", entries.join(",")))
        }
        Value::Array(values) => {
            let entries = values.iter().map(canonical).collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", entries.join(",")))
        }
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .context("Metadata numbers must be safe integers")?;
            ensure!(
                integer.unsigned_abs() <= MAX_SAFE_INTEGER,
                "Metadata integer exceeds JavaScript compatibility limit"
            );
            Ok(integer.to_string())
        }
        _ => Ok(serde_json::to_string(value)?),
    }
}

fn message(payload: &Value) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(canonical(payload)?.as_bytes());
    Ok(bytes)
}

pub fn validate_url(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Expected HTTPS URL without credentials or fragment"
    );
    Ok(url)
}

pub fn assemble(descriptor_path: &Path, approvals: &Approvals) -> Result<Value> {
    let descriptor: Descriptor = files::read_json(descriptor_path)?;
    ensure!(
        descriptor.releases.len() <= 100,
        "At most 100 releases are supported"
    );
    ensure!(descriptor.revocations.len() <= 1000, "Too many revocations");
    let base = descriptor_path
        .parent()
        .context("Descriptor has no parent directory")?;
    let mut plugins = Vec::new();
    let mut identities = BTreeSet::new();

    for release in descriptor.releases {
        let package_path = base.join(&release.package_path);
        let manifest: Value = files::read_json(&package_path.join("manifest.json"))?;
        let id = text(&manifest, "id")?;
        let publisher = text(&manifest, "publisher")?;
        let signature: Value = files::read_json(&package_path.join("signature.json"))?;
        let key_id = text(&signature, "keyId")?;
        let approval = approvals
            .publishers
            .iter()
            .find(|approval| {
                approval.plugin_id == id
                    && approval.publisher == publisher
                    && approval.key_ids.iter().any(|key| key == key_id)
            })
            .context("Package publisher/key binding is not approved")?;
        let report = package::verify(&package_path, key_id)?;
        let version = semver::Version::parse(&report.version)?;
        ensure!(
            release.channel == "stable" || release.channel == "beta",
            "Unsupported channel"
        );
        ensure!(
            (release.channel == "stable") == version.pre.is_empty(),
            "Channel does not match version"
        );
        ensure!(
            version.pre.is_empty()
                || version.pre.as_str() == "beta"
                || version.pre.as_str().starts_with("beta."),
            "Only beta prereleases are supported"
        );
        let url = validate_url(&release.download_url)?;
        let prefix = format!(
            "/{}/releases/download/v{}/",
            approval.repository, report.version
        );
        ensure!(
            url.host_str() == Some("github.com")
                && url.path().starts_with(&prefix)
                && url.query().is_none(),
            "Release URL does not match approved repository and version"
        );
        ensure!(
            identities.insert((report.plugin_id.clone(), report.version.clone())),
            "Duplicate plugin release"
        );

        let mut plugin = json!({
            "id": report.plugin_id,
            "name": text(&manifest, "name")?,
            "version": report.version,
            "channel": release.channel,
            "description": manifest.get("description").and_then(Value::as_str).unwrap_or(""),
            "publisher": report.publisher,
            "downloadUrl": release.download_url,
            "packageDigest": report.package_digest,
            "publisherKeyId": report.publisher_key_id,
            "publisherPublicKey": text(&signature, "publicKey")?,
            "publisherVerified": release.publisher_verified,
        });
        for (target, source) in [
            ("icon", "icon"),
            ("thumbnailUrl", "thumbnailUrl"),
            ("pluginType", "type"),
        ] {
            if let Some(value) = manifest.get(source) {
                ensure!(
                    value.as_str().is_some_and(|value| !value.trim().is_empty()),
                    "Invalid {source} metadata"
                );
                plugin[target] = value.clone();
            }
        }
        plugins.push(plugin);
    }

    plugins.sort_by(|left, right| {
        (left["id"].as_str(), left["version"].as_str())
            .cmp(&(right["id"].as_str(), right["version"].as_str()))
    });
    for revocation in &descriptor.revocations {
        validate_revocation(revocation)?;
    }
    let mut revocations = descriptor.revocations;
    revocations.sort_by_key(|value| canonical(value).unwrap_or_default());
    ensure!(
        revocations.windows(2).all(|pair| pair[0] != pair[1]),
        "Duplicate revocation"
    );
    Ok(json!({"plugins": plugins, "revocations": revocations}))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("Missing {field}"))
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Invalid SHA-256 digest"
    );
    Ok(())
}

fn validate_revocation(value: &Value) -> Result<()> {
    let publisher = text(value, "publisher")?;
    let reason = text(value, "reason")?;
    ensure!(
        reason.chars().count() <= 500,
        "Revocation reason is too long"
    );
    let time = value["revokedAtMs"]
        .as_u64()
        .context("Invalid revocation timestamp")?;
    ensure!(
        time > 0 && time <= MAX_SAFE_INTEGER,
        "Invalid revocation timestamp"
    );
    match text(value, "kind")? {
        "publisherKey" => {
            validate_digest(text(value, "keyId")?)?;
            ensure!(
                value.get("pluginId").is_none()
                    && value.get("version").is_none()
                    && value.get("packageDigest").is_none(),
                "Unexpected release fields in key revocation"
            );
        }
        "pluginRelease" => {
            ensure!(
                text(value, "pluginId")?.starts_with(&format!("{publisher}.")),
                "Revoked plugin publisher mismatch"
            );
            semver::Version::parse(text(value, "version")?)?;
            validate_digest(text(value, "packageDigest")?)?;
            ensure!(
                value.get("keyId").is_none(),
                "Unexpected key ID in release revocation"
            );
        }
        _ => anyhow::bail!("Unsupported revocation kind"),
    }
    Ok(())
}

pub fn preserve_history(previous: &Value, current: &Value) -> Result<()> {
    for field in ["plugins", "revocations"] {
        let old_entries = previous[field]
            .as_array()
            .context("Invalid previous registry list")?;
        let new_entries = current[field]
            .as_array()
            .context("Invalid prepared registry list")?;
        ensure!(
            old_entries.iter().all(|old| new_entries.contains(old)),
            "Registry update removes or changes existing {field}"
        );
    }
    Ok(())
}

pub fn verify_envelope(
    envelope: &Value,
    roots: &str,
    now: u64,
    minimum_version: u64,
) -> Result<Value> {
    let signatures = envelope["signatures"]
        .as_array()
        .context("Missing signatures")?;
    ensure!(signatures.len() == 1, "Expected exactly one root signature");
    let signature = &signatures[0];
    let trusted: Vec<_> = roots
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    ensure!(
        !trusted.is_empty() && trusted.len() <= 4,
        "Configure between one and four root keys"
    );
    let mut selected = None;
    for encoded in trusted {
        let bytes = STANDARD.decode(encoded)?;
        ensure!(
            bytes.len() == 32 && STANDARD.encode(&bytes) == encoded,
            "Invalid trusted root key"
        );
        if fingerprint(&bytes) == text(signature, "keyId")? {
            selected = Some(bytes);
        }
    }
    let bytes: [u8; 32] = selected
        .context("Registry root is not trusted")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid root key"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    let detached = Signature::from_slice(&STANDARD.decode(text(signature, "signature")?)?)?;
    let payload = &envelope["signed"];
    key.verify_strict(&message(payload)?, &detached)?;
    validate_payload(payload, now, minimum_version)?;
    Ok(payload.clone())
}

fn validate_payload(payload: &Value, now: u64, minimum_version: u64) -> Result<()> {
    ensure!(
        text(payload, "_type")? == "zync.plugin-registry",
        "Unsupported registry type"
    );
    let version = payload["version"]
        .as_u64()
        .context("Invalid registry version")?;
    let issued = payload["issuedAtMs"]
        .as_u64()
        .context("Invalid issue time")?;
    let expires = payload["expiresAtMs"]
        .as_u64()
        .context("Invalid expiry time")?;
    ensure!(
        version > 0 && version >= minimum_version && version <= MAX_SAFE_INTEGER,
        "Registry version is below minimum or invalid"
    );
    ensure!(
        issued > 0
            && issued <= now.saturating_add(300_000)
            && (expires == 0 || (expires > now && expires > issued))
            && expires <= MAX_SAFE_INTEGER,
        "Registry is expired or has invalid timestamps"
    );
    let plugins = payload["plugins"]
        .as_array()
        .context("Invalid plugin list")?;
    let revocations = payload["revocations"]
        .as_array()
        .context("Invalid revocation list")?;
    ensure!(
        plugins.len() <= 100 && revocations.len() <= 1000,
        "Registry has too many entries"
    );
    let mut identities = BTreeSet::new();
    for plugin in plugins {
        let publisher = text(plugin, "publisher")?;
        let id = text(plugin, "id")?;
        let version = semver::Version::parse(text(plugin, "version")?)?;
        ensure!(
            id.starts_with(&format!("{publisher}.")),
            "Plugin publisher mismatch"
        );
        ensure!(
            identities.insert((id, version.to_string())),
            "Duplicate release"
        );
        text(plugin, "name")?;
        ensure!(
            plugin["description"].is_string() && plugin["publisherVerified"].is_boolean(),
            "Invalid release metadata"
        );
        validate_url(text(plugin, "downloadUrl")?)?;
        validate_digest(text(plugin, "packageDigest")?)?;
        let key = STANDARD.decode(text(plugin, "publisherPublicKey")?)?;
        ensure!(
            key.len() == 32 && fingerprint(&key) == text(plugin, "publisherKeyId")?,
            "Publisher key mismatch"
        );
        let channel = text(plugin, "channel")?;
        ensure!(channel == "stable" || channel == "beta", "Invalid channel");
        ensure!(
            (channel == "stable") == version.pre.is_empty(),
            "Channel/version mismatch"
        );
    }
    let mut seen = BTreeSet::new();
    for revocation in revocations {
        validate_revocation(revocation)?;
        ensure!(
            revocation["revokedAtMs"].as_u64().unwrap_or(u64::MAX) <= issued,
            "Revocation is newer than registry issue time"
        );
        let identity = match text(revocation, "kind")? {
            "publisherKey" => format!(
                "key:{}:{}",
                text(revocation, "publisher")?,
                text(revocation, "keyId")?
            ),
            _ => format!(
                "release:{}:{}:{}",
                text(revocation, "pluginId")?,
                text(revocation, "version")?,
                text(revocation, "packageDigest")?
            ),
        };
        ensure!(seen.insert(identity), "Duplicate revocation identity");
    }
    Ok(())
}

fn validate_publication_expiry(issued: u64, expires: u64) -> Result<()> {
    ensure!(
        expires > issued && expires - issued <= 7 * 24 * 60 * 60 * 1000,
        "Publication expiry must be later than issuance and no more than seven days away"
    );
    Ok(())
}

pub fn sign(
    payload: Value,
    key_path: &Path,
    version: u64,
    issued: u64,
    expires: u64,
) -> Result<Value> {
    validate_publication_expiry(issued, expires)?;
    let pem = Zeroizing::new(String::from_utf8(files::read_bounded(
        key_path,
        16 * 1024,
    )?)?);
    let key = SigningKey::from_pkcs8_pem(&pem)
        .context("Expected an unencrypted Ed25519 PKCS#8 PEM root key")?;
    sign_with_key(payload, &key, version, issued, expires)
}

fn sign_with_key(
    mut payload: Value,
    key: &SigningKey,
    version: u64,
    issued: u64,
    expires: u64,
) -> Result<Value> {
    payload["_type"] = json!("zync.plugin-registry");
    payload["version"] = json!(version);
    payload["issuedAtMs"] = json!(issued);
    payload["expiresAtMs"] = json!(expires);
    validate_payload(&payload, issued, version)?;
    let signature = key.sign(&message(&payload)?);
    Ok(
        json!({"signed": payload, "signatures": [{"keyId": fingerprint(&key.verifying_key().to_bytes()), "signature": STANDARD.encode(signature.to_bytes())}]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    #[test]
    fn publication_requires_bounded_expiry() {
        let issued = 1_000;
        let week = 7 * 24 * 60 * 60 * 1000;
        assert!(validate_publication_expiry(issued, 0).is_err());
        assert!(validate_publication_expiry(issued, issued).is_err());
        assert!(validate_publication_expiry(issued, issued - 1).is_err());
        assert!(validate_publication_expiry(issued, issued + week).is_ok());
        assert!(validate_publication_expiry(issued, issued + week + 1).is_err());
    }

    #[test]
    fn prepares_signed_packages_and_signs_with_a_test_pem() {
        let (directory, key_id) = crate::package::tests::signed_fixture();
        let bundle = tempfile::tempdir().unwrap();
        let descriptor = bundle.path().join("registry-releases.json");
        files::write_new_json(&descriptor, &json!({
            "releases": [{
                "packagePath": directory.path(),
                "downloadUrl": "https://github.com/example/plugin/releases/download/v1.0.0/plugin.zip",
                "channel": "stable",
                "publisherVerified": true,
            }],
            "revocations": [],
        })).unwrap();
        let approvals = Approvals {
            publishers: vec![Approval {
                publisher: "dev.example".into(),
                plugin_id: "dev.example.test".into(),
                repository: "example/plugin".into(),
                key_ids: vec![key_id],
            }],
        };
        let payload = assemble(&descriptor, &approvals).unwrap();
        assert_eq!(payload["plugins"][0]["name"], "Test plugin");
        assert!(assemble(&descriptor, &Approvals { publishers: vec![] }).is_err());

        let keys = tempfile::tempdir().unwrap();
        let key_path = keys.path().join("test-root.pem");
        let key = SigningKey::from_bytes(&[9; 32]);
        let pem = key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        std::fs::write(&key_path, pem.as_bytes()).unwrap();
        let envelope = sign(payload, &key_path, 1, 1000, 10000).unwrap();
        let roots = STANDARD.encode(key.verifying_key().to_bytes());
        verify_envelope(&envelope, &roots, 2000, 1).unwrap();
        let output = bundle.path().join("registry.json");
        files::write_new_json(&output, &envelope).unwrap();
        assert!(files::write_new_json(&output, &envelope).is_err());
    }

    #[test]
    fn agrees_with_existing_node_signature_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/legacy-registry.json")).unwrap();
        let roots = "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
        verify_envelope(&fixture, roots, 2_000, 2).unwrap();
        let generated = sign_with_key(
            json!({"plugins": [], "revocations": []}),
            &SigningKey::from_bytes(&[9; 32]),
            2,
            1_000,
            10_000,
        )
        .unwrap();
        assert_eq!(generated, fixture);
    }

    #[test]
    fn canonical_json_matches_operator_format() {
        assert_eq!(
            canonical(&json!({"z": [true, 1], "a": "line\n"})).unwrap(),
            "{\"a\":\"line\\n\",\"z\":[true,1]}"
        );
        assert!(canonical(&json!(1.5)).is_err());
        assert!(canonical(&json!(9_007_199_254_740_992_u64)).is_err());
    }

    #[test]
    fn signature_round_trip_rejects_tampering_expiry_and_rollback() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let roots = STANDARD.encode(key.verifying_key().to_bytes());
        let mut envelope = sign_with_key(
            json!({"plugins": [], "revocations": []}),
            &key,
            2,
            1_000,
            10_000,
        )
        .unwrap();
        assert!(verify_envelope(&envelope, &roots, 2_000, 2).is_ok());
        assert!(verify_envelope(&envelope, &roots, 2_000, 3).is_err());
        assert!(verify_envelope(&envelope, &roots, 10_000, 1).is_err());
        assert!(verify_envelope(&envelope, &STANDARD.encode([0; 32]), 2_000, 1).is_err());
        envelope["signed"]["version"] = json!(3);
        assert!(verify_envelope(&envelope, &roots, 2_000, 1).is_err());
    }

    #[test]
    fn non_expiring_metadata_still_requires_signature_and_version_checks() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let roots = STANDARD.encode(key.verifying_key().to_bytes());
        let mut envelope =
            sign_with_key(json!({"plugins": [], "revocations": []}), &key, 2, 1_000, 0).unwrap();
        assert!(verify_envelope(&envelope, &roots, 10_000_000, 2).is_ok());
        assert!(verify_envelope(&envelope, &roots, 10_000_000, 3).is_err());
        envelope["signed"]["expiresAtMs"] = json!(9999);
        assert!(verify_envelope(&envelope, &roots, 2000, 2).is_err());
    }

    #[test]
    fn updates_preserve_all_releases_and_revocations() {
        let previous =
            json!({"plugins": [{"id": "example"}], "revocations": [{"reason": "compromised"}]});
        assert!(preserve_history(&previous, &previous).is_ok());
        assert!(preserve_history(&previous, &json!({"plugins": [], "revocations": []})).is_err());
    }
}
