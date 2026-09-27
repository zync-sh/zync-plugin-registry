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
    files,
    registry::{self, Approvals},
};

const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024;
const PM2_FILES: [&str; 7] = [
    "LICENSE",
    "icons/process-manager.svg",
    "manifest.json",
    "ui/index.html",
    "worker.js",
    "integrity.json",
    "signature.json",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Release {
    plugin_id: String,
    publisher: String,
    repository: String,
    version: String,
    channel: String,
    publisher_verified: bool,
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
        archive.len() == PM2_FILES.len(),
        "Unexpected number of PM2 package files"
    );
    let mut seen = BTreeSet::new();
    let mut total = 0;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        ensure!(
            PM2_FILES.contains(&name.as_str()) && seen.insert(name.clone()),
            "Unexpected or duplicate archive entry"
        );
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
        ensure!(
            release.plugin_id == "com.zync.plugin.pm2-monitor",
            "This initial archive profile supports PM2 only"
        );
        ensure!(
            approvals
                .publishers
                .iter()
                .any(|approval| approval.plugin_id == release.plugin_id
                    && approval.publisher == release.publisher
                    && approval.repository == release.repository),
            "Release publisher/repository is not approved"
        );
        let name = format!("pm2-monitor-{}-signed.zip", release.version);
        let url = format!(
            "https://github.com/{}/releases/download/v{}/{}",
            release.repository, release.version, name
        );
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
        releases.push(json!({
            "packagePath": relative,
            "downloadUrl": url,
            "publisherVerified": release.publisher_verified,
            "channel": release.channel,
        }));
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
