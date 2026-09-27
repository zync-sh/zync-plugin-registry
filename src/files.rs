use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};

pub const MAX_REGISTRY_BYTES: u64 = 2 * 1024 * 1024;

pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file(),
        "Expected a regular file: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "File exceeds size limit: {}",
        path.display()
    );
    Ok(bytes)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bounded(path, MAX_REGISTRY_BYTES)?)
        .with_context(|| format!("Invalid JSON: {}", path.display()))
}

pub fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= MAX_REGISTRY_BYTES,
        "JSON exceeds 2 MiB"
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    Ok(())
}
