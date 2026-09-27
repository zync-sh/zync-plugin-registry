use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_FILES: usize = 2_048;
const MAX_METADATA_BYTES: usize = 512 * 1024;

#[derive(Deserialize)]
struct Manifest {
    id: String,
    publisher: String,
    version: String,
}

#[derive(Deserialize)]
struct Integrity {
    version: u32,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublisherSignature {
    version: u32,
    algorithm: String,
    publisher: String,
    plugin_id: String,
    plugin_version: String,
    key_id: String,
    public_key: String,
    published_at_ms: u64,
    manifest_digest: String,
    integrity_root: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub plugin_id: String,
    pub publisher: String,
    pub version: String,
    pub publisher_key_id: String,
    pub package_digest: String,
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 512,
        "Invalid package path length"
    );
    ensure!(
        !path.contains('\\'),
        "Backslashes are not allowed in package paths"
    );

    for component in path.split('/') {
        ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.contains(':')
                && !component.chars().any(char::is_control),
            "Unsafe package path: {path}"
        );
    }

    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "Package links are not allowed"
        );

        if metadata.is_dir() {
            collect_files(root, &path, files, total)?;
            continue;
        }

        ensure!(metadata.is_file(), "Only regular package files are allowed");
        ensure!(
            metadata.len() <= MAX_FILE_BYTES,
            "Package file exceeds 20 MiB"
        );
        *total += metadata.len();
        ensure!(*total <= MAX_PACKAGE_BYTES, "Package exceeds 100 MiB");

        let relative = path
            .strip_prefix(root)?
            .to_str()
            .context("Package path is not UTF-8")?
            .replace('\\', "/");
        validate_path(&relative)?;
        let bytes = fs::read(&path)?;
        ensure!(
            bytes.len() as u64 == metadata.len(),
            "Package changed during verification"
        );
        files.insert(relative, bytes);
        ensure!(files.len() <= MAX_FILES, "Package contains too many files");
    }

    Ok(())
}

fn metadata<T: serde::de::DeserializeOwned>(
    files: &BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<T> {
    let bytes = files.get(name).with_context(|| format!("Missing {name}"))?;
    ensure!(
        bytes.len() <= MAX_METADATA_BYTES,
        "Metadata exceeds 512 KiB"
    );
    serde_json::from_slice(bytes).with_context(|| format!("Invalid {name}"))
}

pub fn verify(root: &Path, approved_key_id: &str) -> Result<VerificationReport> {
    ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "Package must be a real directory"
    );
    let mut files = BTreeMap::new();
    collect_files(root, root, &mut files, &mut 0)?;

    let manifest: Manifest = metadata(&files, "manifest.json")?;
    let integrity: Integrity = metadata(&files, "integrity.json")?;
    let signature: PublisherSignature = metadata(&files, "signature.json")?;
    ensure!(
        integrity.version == 1 && signature.version == 1 && signature.algorithm == "ed25519",
        "Unsupported signing format"
    );
    ensure!(
        signature.key_id == approved_key_id,
        "Publisher key is not approved"
    );

    let payload: BTreeMap<_, _> = files
        .iter()
        .filter(|(name, _)| name.as_str() != "integrity.json" && name.as_str() != "signature.json")
        .map(|(name, bytes)| (name.clone(), sha256(bytes)))
        .collect();
    ensure!(payload == integrity.files, "Package integrity mismatch");

    let mut integrity_hash = Sha256::new();
    integrity_hash.update(b"zync-plugin-integrity-v1\n");
    for (name, digest) in &payload {
        integrity_hash.update(format!("{name}\0{digest}\n"));
    }
    let integrity_root = format!("sha256:{:x}", integrity_hash.finalize());

    ensure!(
        manifest.id.starts_with(&format!("{}.", manifest.publisher)),
        "Plugin is not namespaced to its publisher"
    );
    ensure!(
        signature.publisher == manifest.publisher
            && signature.plugin_id == manifest.id
            && signature.plugin_version == manifest.version,
        "Signature identity mismatch"
    );
    ensure!(
        payload.get("manifest.json") == Some(&signature.manifest_digest)
            && signature.integrity_root == integrity_root,
        "Signature digest mismatch"
    );
    ensure!(
        signature.published_at_ms > 0 && signature.published_at_ms <= 9_007_199_254_740_991,
        "Invalid publication timestamp"
    );

    let public_bytes = STANDARD.decode(&signature.public_key)?;
    ensure!(
        STANDARD.encode(&public_bytes) == signature.public_key,
        "Public key must use canonical base64"
    );
    ensure!(
        sha256(&public_bytes) == signature.key_id,
        "Publisher fingerprint mismatch"
    );
    let public_bytes: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected a 32-byte public key"))?;
    let key = VerifyingKey::from_bytes(&public_bytes)?;
    let signature_bytes = STANDARD.decode(&signature.signature)?;
    let detached = Signature::from_slice(&signature_bytes)?;
    let message = format!(
        "zync-plugin-signature-v1\npublisher={}\npluginId={}\nversion={}\nmanifestDigest={}\nintegrityRoot={}\npublishedAtMs={}\n",
        signature.publisher,
        signature.plugin_id,
        signature.plugin_version,
        signature.manifest_digest,
        signature.integrity_root,
        signature.published_at_ms
    );
    if key.verify_strict(message.as_bytes(), &detached).is_err() {
        bail!("Invalid publisher signature");
    }

    let mut package_hash = Sha256::new();
    for (name, bytes) in &files {
        package_hash.update((name.len() as u64).to_le_bytes());
        package_hash.update(name.as_bytes());
        package_hash.update((bytes.len() as u64).to_le_bytes());
        package_hash.update(bytes);
    }

    Ok(VerificationReport {
        plugin_id: manifest.id,
        publisher: manifest.publisher,
        version: manifest.version,
        publisher_key_id: signature.key_id,
        package_digest: format!("sha256:{:x}", package_hash.finalize()),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(crate) fn signed_fixture() -> (tempfile::TempDir, String) {
        let directory = tempfile::tempdir().unwrap();
        let manifest = br#"{"id":"dev.example.test","name":"Test plugin","publisher":"dev.example","version":"1.0.0"}"#;
        let manifest_digest = sha256(manifest);
        let files = BTreeMap::from([("manifest.json", &manifest_digest)]);
        let integrity = serde_json::json!({"version": 1, "files": files});
        let root = sha256(
            format!("zync-plugin-integrity-v1\nmanifest.json\0{manifest_digest}\n").as_bytes(),
        );

        // Deterministic test key only; never used by a real publisher.
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = key.verifying_key().to_bytes();
        let key_id = sha256(&public_key);
        let message = format!(
            "zync-plugin-signature-v1\npublisher=dev.example\npluginId=dev.example.test\nversion=1.0.0\nmanifestDigest={manifest_digest}\nintegrityRoot={root}\npublishedAtMs=1\n"
        );
        let signature = serde_json::json!({
            "version": 1,
            "algorithm": "ed25519",
            "publisher": "dev.example",
            "pluginId": "dev.example.test",
            "pluginVersion": "1.0.0",
            "keyId": key_id,
            "publicKey": STANDARD.encode(public_key),
            "publishedAtMs": 1,
            "manifestDigest": manifest_digest,
            "integrityRoot": root,
            "signature": STANDARD.encode(key.sign(message.as_bytes()).to_bytes()),
        });

        fs::write(directory.path().join("manifest.json"), manifest).unwrap();
        fs::write(
            directory.path().join("integrity.json"),
            integrity.to_string(),
        )
        .unwrap();
        fs::write(
            directory.path().join("signature.json"),
            signature.to_string(),
        )
        .unwrap();
        (directory, key_id)
    }

    #[test]
    fn verifies_signed_fixture_and_rejects_unapproved_key() {
        let (directory, key_id) = signed_fixture();
        let report = verify(directory.path(), &key_id).unwrap();
        assert_eq!(report.plugin_id, "dev.example.test");
        assert!(verify(directory.path(), "sha256:unapproved").is_err());
    }

    #[test]
    fn rejects_tampered_payload_and_added_files() {
        let (directory, key_id) = signed_fixture();
        fs::write(directory.path().join("extra.js"), b"unexpected").unwrap();
        assert!(verify(directory.path(), &key_id).is_err());

        let (directory, key_id) = signed_fixture();
        fs::write(directory.path().join("manifest.json"), b"{}").unwrap();
        assert!(verify(directory.path(), &key_id).is_err());
    }

    #[test]
    fn rejects_invalid_detached_signature() {
        let (directory, key_id) = signed_fixture();
        let path = directory.path().join("signature.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        metadata["signature"] = STANDARD.encode([0; 64]).into();
        fs::write(path, metadata.to_string()).unwrap();
        assert!(verify(directory.path(), &key_id).is_err());
    }

    #[test]
    fn rejects_unsafe_paths() {
        for path in ["../private.pem", "/absolute", "a\\b", "a:b", "a//b", "a\0b"] {
            assert!(validate_path(path).is_err(), "accepted {path:?}");
        }
        assert!(validate_path("ui/index.html").is_ok());
    }

    #[test]
    fn rejects_unsigned_packages() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("manifest.json"), b"{}").unwrap();
        assert!(verify(directory.path(), "untrusted").is_err());
    }
}
