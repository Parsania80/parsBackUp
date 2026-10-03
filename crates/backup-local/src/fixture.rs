//! Test-only helpers shared by the store and the key module, so a temporary storage root
//! or a synthetic key pair is built the same way everywhere. The seeds written here are
//! fixed or random fixtures and protect nothing.

use backup_crypto::keystore::KeyFile;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!("backupctl-store-test-{}", Uuid::new_v4()))
}

pub(crate) fn temp_keys() -> PathBuf {
    std::env::temp_dir().join(format!("backupctl-keys-test-{}", Uuid::new_v4()))
}

/// Writes a key pair outside any storage root and returns both paths.
pub(crate) fn key_pair(dir: &Path) -> (PathBuf, PathBuf) {
    fs::create_dir_all(dir).unwrap();
    let identity = dir.join("identity.key");
    let recipient = dir.join("recipient.key");
    let key = KeyFile::create_identity(&identity).unwrap();
    KeyFile::write_recipient(&recipient, key.recipient()).unwrap();
    (identity, recipient)
}
