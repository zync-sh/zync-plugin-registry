mod files;
mod package;
mod prepare;
mod registry;

use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the raw public root and fingerprint from a public Ed25519 PEM file.
    PublicKey { pem: PathBuf },
    /// Download approved releases and prepare an unsigned offline signing bundle.
    Prepare {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        approvals: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a reviewed descriptor using an unencrypted Ed25519 PEM key.
    Sign {
        #[arg(long)]
        descriptor: PathBuf,
        #[arg(long)]
        approvals: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        issued_at_ms: u64,
        /// Required expiry timestamp, strictly later than issuance.
        #[arg(long)]
        expires_at_ms: u64,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long, requires = "baseline")]
        root_keys: Option<String>,
        #[arg(long)]
        minimum_version: u64,
    },
    /// Verify registry signature, version floor, and validity period.
    VerifyRegistry {
        path: PathBuf,
        #[arg(long)]
        root_keys: String,
        #[arg(long)]
        now_ms: u64,
        #[arg(long, default_value_t = 1)]
        minimum_version: u64,
    },
    /// Verify an extracted package against an independently approved publisher key.
    VerifyPackage {
        directory: PathBuf,
        #[arg(long)]
        approved_key_id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::PublicKey { pem } => {
            use base64::{Engine, engine::general_purpose::STANDARD};
            use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};

            let text = String::from_utf8(files::read_bounded(&pem, 16 * 1024)?)?;
            let key = VerifyingKey::from_public_key_pem(&text)?;
            println!("{}", STANDARD.encode(key.as_bytes()));
            eprintln!("{}", registry::fingerprint(key.as_bytes()));
        }
        Command::Prepare {
            input,
            approvals,
            output,
        } => {
            prepare::run(&input, &approvals, &output)?;
        }
        Command::Sign {
            descriptor,
            approvals,
            key,
            output,
            version,
            issued_at_ms,
            expires_at_ms,
            baseline,
            root_keys,
            minimum_version,
        } => {
            ensure!(
                minimum_version > 0 && version >= minimum_version,
                "Registry version is below the supplied minimum"
            );
            ensure!(
                baseline.is_some() || version == 1,
                "Updates require the previous signed registry as baseline"
            );
            ensure!(!output.exists(), "Output already exists");
            let key_path = key.canonicalize()?;
            let source = descriptor.canonicalize()?;
            ensure!(
                !key_path.starts_with(source.parent().unwrap())
                    && !key_path.starts_with(std::env::current_dir()?),
                "Root private key must remain outside the source bundle and working repository"
            );
            let approvals: registry::Approvals = files::read_json(&approvals)?;
            let payload = registry::assemble(&descriptor, &approvals)?;
            if let Some(baseline) = baseline {
                let envelope: Value = files::read_json(&baseline)?;
                // An expired baseline may establish history, not current client validity.
                let previous = registry::verify_envelope(
                    &envelope,
                    root_keys.as_deref().ok_or_else(|| {
                        anyhow::anyhow!("Baseline verification requires trusted public root keys")
                    })?,
                    envelope["signed"]["issuedAtMs"].as_u64().unwrap_or(0),
                    1,
                )?;
                ensure!(
                    version > previous["version"].as_u64().unwrap_or(u64::MAX),
                    "Registry version must increase"
                );
                registry::preserve_history(&previous, &payload)?;
            }
            let envelope = registry::sign(payload, &key, version, issued_at_ms, expires_at_ms)?;
            files::write_new_json(&output, &envelope)?;
            println!("Signed registry version {version}: {}", output.display());
        }
        Command::VerifyRegistry {
            path,
            root_keys,
            now_ms,
            minimum_version,
        } => {
            let envelope: Value = files::read_json(&path)?;
            let payload =
                registry::verify_envelope(&envelope, &root_keys, now_ms, minimum_version)?;
            println!("Verified registry version {}", payload["version"]);
        }
        Command::VerifyPackage {
            directory,
            approved_key_id,
        } => {
            let report = package::verify(&directory, &approved_key_id)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    Ok(())
}
