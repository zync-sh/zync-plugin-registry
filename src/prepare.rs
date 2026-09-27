use std::{
    collections::BTreeSet,
    fs,
    io::{Cursor, Read},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    files, package,
    registry::{self, Approvals},
};

const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 2_048;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Release {
    plugin_id: String,
    publisher: String,
    repository: String,
    version: String,
    asset_name: String,
    channel: String,
    publisher_verified: bool,
    thumbnail_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    releases: Vec<Release>,
    revocations: Vec<Value>,
}

fn download(client: &reqwest::blocking::Client, url: &str, maximum: u64) -> Result<Vec<u8>> {
    registry::validate_url(url)?;
    let response = client.get(url).send()?.error_for_status()?;
    registry::validate_url(response.url().as_str())?;
    let mut bytes = Vec::new();
    response.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "Download exceeds size limit");
    Ok(bytes)
}

fn extract(bytes: &[u8], destination: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        !archive.is_empty() && archive.len() <= MAX_ARCHIVE_FILES,
        "Invalid archive file count"
    );
    let mut seen = BTreeSet::new();
    let mut total = 0;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        package::validate_path(&name)?;
        ensure!(seen.insert(name.clone()), "Duplicate archive entry");
        ensure!(
            !entry.is_dir() && !entry.is_symlink(),
            "Archive links and directories are not allowed"
        );
        ensure!(
            entry.size() <= MAX_ARCHIVE_BYTES,
            "Archive entry is too large"
        );
        let mut payload = Vec::new();
        (&mut entry)
            .take(MAX_ARCHIVE_BYTES + 1)
            .read_to_end(&mut payload)?;
        ensure!(
            payload.len() as u64 == entry.size(),
            "Archive entry size mismatch"
        );
        total += payload.len() as u64;
        ensure!(
            total <= MAX_EXTRACTED_BYTES,
            "Extracted archive exceeds limit"
        );
        let path = destination.join(name);
        fs::create_dir_all(path.parent().context("Missing package directory")?)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        std::io::Write::write_all(&mut file, &payload)?;
    }

    Ok(())
}

fn release_url(release: &Release) -> Result<String> {
    package::validate_path(&release.plugin_id)?;
    ensure!(
        !release.plugin_id.is_empty()
            && release
                .plugin_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
        "Invalid plugin identity"
    );
    let parts: Vec<_> = release.repository.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))),
        "Expected a GitHub owner/repository"
    );
    ensure!(
        release.asset_name.ends_with(".zip")
            && release.asset_name.len() <= 255
            && release
                .asset_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
        "Expected a ZIP asset filename without path or URL components"
    );
    Ok(format!(
        "https://github.com/{}/releases/download/v{}/{}",
        release.repository, release.version, release.asset_name
    ))
}

pub fn run(input_path: &Path, approvals_path: &Path, output: &Path) -> Result<()> {
    let input: Input = files::read_json(input_path)?;
    let approvals: Approvals = files::read_json(approvals_path)?;
    ensure!(
        !input.releases.is_empty() && input.releases.len() <= 100,
        "Expected between one and 100 releases"
    );
    ensure!(
        !output.exists(),
        "Output directory already exists; choose a new directory"
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("zync-registry/0.1.0")
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 || attempt.url().scheme() != "https" {
                attempt.error("Too many redirects or non-HTTPS redirect")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    fs::create_dir(output)?;
    let mut releases = Vec::new();

    for release in input.releases {
        let version = semver::Version::parse(&release.version)?;
        ensure!(
            version.to_string() == release.version
                && version.pre.is_empty()
                && version.build.is_empty(),
            "Preparation currently supports stable versions only"
        );
        let url = release_url(&release)?;
        ensure!(
            approvals
                .publishers
                .iter()
                .any(|approval| approval.plugin_id == release.plugin_id
                    && approval.publisher == release.publisher
                    && approval.repository == release.repository),
            "Release publisher/repository is not approved"
        );
        let name = &release.asset_name;
        let archive = download(&client, &url, MAX_ARCHIVE_BYTES)?;
        let checksum = String::from_utf8(download(&client, &format!("{url}.sha256"), 4096)?)?;
        let expected = format!(
            "{}  {name}",
            registry::fingerprint(&archive).trim_start_matches("sha256:")
        );
        ensure!(checksum.trim() == expected, "Release checksum mismatch");
        let relative = format!("packages/{}/{}", release.plugin_id, release.version);
        let destination = output.join(&relative);
        fs::create_dir_all(&destination)?;
        extract(&archive, &destination)?;
        let manifest: Value = files::read_json(&destination.join("manifest.json"))?;
        ensure!(
            manifest["id"] == release.plugin_id
                && manifest["publisher"] == release.publisher
                && manifest["version"] == release.version,
            "Package identity does not match registry input"
        );
        let mut descriptor = json!({
            "packagePath": relative,
            "downloadUrl": url,
            "publisherVerified": release.publisher_verified,
            "channel": release.channel,
        });
        if let Some(thumbnail) = &release.thumbnail_url {
            registry::validate_url(thumbnail)?;
            descriptor["thumbnailUrl"] = json!(thumbnail);
        }
        releases.push(descriptor);
    }

    let descriptor = output.join("registry-releases.json");
    files::write_new_json(
        &descriptor,
        &json!({"releases": releases, "revocations": input.revocations}),
    )?;
    let payload = registry::assemble(&descriptor, &approvals)?;
    files::write_new_json(&output.join("prepared-metadata.json"), &payload)?;
    files::write_new_json(
        &output.join("verification-report.json"),
        &json!({
            "unsignedPreparation": true,
            "pluginCount": payload["plugins"].as_array().map(Vec::len),
            "note": "Preparation succeeded. This is not registry.json; root signing and release review are still required.",
        }),
    )?;
    println!("Prepared and verified release bundle: {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn accepts_generic_signed_package_and_verifies_integrity() {
        let (source, key_id) = package::tests::signed_fixture();
        let contents: Vec<_> = ["manifest.json", "integrity.json", "signature.json"]
            .iter()
            .map(|name| (*name, fs::read(source.path().join(name)).unwrap()))
            .collect();
        let entries: Vec<_> = contents
            .iter()
            .map(|(name, bytes)| (*name, bytes.as_slice()))
            .collect();
        let destination = tempfile::tempdir().unwrap();
        extract(&archive(&entries), destination.path()).unwrap();
        package::verify(destination.path(), &key_id).unwrap();
        fs::write(destination.path().join("extra.js"), b"unsigned").unwrap();
        assert!(package::verify(destination.path(), &key_id).is_err());
    }

    #[test]
    fn rejects_unsafe_archive_entries_and_empty_archives() {
        for name in [
            "../escape",
            "/absolute",
            "a\\b",
            "a:b",
            "a//b",
            "directory/",
        ] {
            let destination = tempfile::tempdir().unwrap();
            assert!(extract(&archive(&[(name, b"test")]), destination.path()).is_err());
        }
        let destination = tempfile::tempdir().unwrap();
        assert!(extract(&archive(&[]), destination.path()).is_err());
    }

    #[test]
    fn release_assets_are_input_driven_and_cannot_escape_the_repository() {
        let mut release: Release = serde_json::from_value(json!({
            "pluginId": "dev.example.other", "publisher": "dev.example",
            "repository": "example/other", "version": "1.0.0",
            "assetName": "custom-release.zip", "channel": "stable",
            "publisherVerified": true
        }))
        .unwrap();
        assert_eq!(
            release_url(&release).unwrap(),
            "https://github.com/example/other/releases/download/v1.0.0/custom-release.zip"
        );
        for name in [
            "../other.zip",
            "file.zip?x=1",
            "file.zip#fragment",
            "https://evil/file.zip",
            "file.tar",
        ] {
            release.asset_name = name.into();
            assert!(release_url(&release).is_err());
        }
        release.asset_name = "safe.zip".into();
        release.repository = "example/../other".into();
        assert!(release_url(&release).is_err());
        release.repository = "example/other".into();
        release.plugin_id = "../escape".into();
        assert!(release_url(&release).is_err());
    }

    #[test]
    fn rejects_unexpected_archive_layout() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("../private.pem", zip::write::SimpleFileOptions::default())
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(extract(&bytes, directory.path()).is_err());
    }
}
