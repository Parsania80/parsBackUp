//! Authenticated scratch decryption and plaintext-view cleanup under the activity claim.

use crate::layout::{MANIFEST_FILE, MAX_MANIFEST_BYTES, SCRATCH_DIR};
use crate::{LocalPlaintext, LocalStore, ensure_regular_file, read_bounded};
use anyhow::{Context, Result, bail};
use backup_application::PlaintextView;
use backup_crypto::keystore::IdentityProvider;
use backup_crypto::stream::{decrypt, decrypt_with_limit};
use backup_domain::{ArtifactManifest, PublicHeader};
use backup_inventory::ActivityLock;
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use uuid::Uuid;

impl Drop for LocalPlaintext {
    fn drop(&mut self) {
        if let Some(dir) = &self.scratch {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

impl PlaintextView for LocalPlaintext {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl LocalStore {
    /// Decrypts an age file into a fresh scratch directory.
    ///
    /// `max_plaintext_bytes` is the size the manifest recorded for this payload when it
    /// has one; `None` applies the format-wide cap instead.
    /// A recorded ciphertext binding is checked against the stream before the view is returned.
    pub(crate) fn decrypt_to_scratch(
        &self,
        ciphertext: &Path,
        name: &str,
        max_plaintext_bytes: Option<u64>,
        expected_ciphertext: Option<(u64, &str)>,
    ) -> Result<LocalPlaintext> {
        let claim = ActivityLock::hold(&self.root)?;
        self.decrypt_to_scratch_owned(
            ciphertext,
            name,
            max_plaintext_bytes,
            expected_ciphertext,
            Some(claim),
        )
    }

    fn decrypt_to_scratch_owned(
        &self,
        ciphertext: &Path,
        name: &str,
        max_plaintext_bytes: Option<u64>,
        expected_ciphertext: Option<(u64, &str)>,
        claim: Option<ActivityLock>,
    ) -> Result<LocalPlaintext> {
        let keys = self
            .keys
            .as_ref()
            .context("artifact is encrypted but no key files are configured")?;
        ensure_regular_file(ciphertext)?;
        crate::ensure_real_dir(&self.root.join(SCRATCH_DIR))?;
        let scratch = self.root.join(SCRATCH_DIR).join(Uuid::new_v4().to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&scratch)
            .context("create private scratch directory")?;
        let view = LocalPlaintext {
            path: scratch.join(name),
            scratch: Some(scratch),
            _claim: claim,
            _use: None,
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&view.path)
            .context("create private scratch file")?;
        let ciphertext = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(ciphertext)
            .context("open encrypted payload")?;
        if !ciphertext.metadata()?.is_file() {
            bail!("encrypted payload must be a regular file");
        }
        let bound = match expected_ciphertext {
            Some((bytes, _)) => bytes.checked_add(1).context("ciphertext size overflow")?,
            None => u64::MAX,
        };
        let mut reader = DigestReader {
            inner: ciphertext.take(bound),
            digest: Sha256::new(),
            bytes: 0,
        };
        match max_plaintext_bytes {
            Some(limit) => decrypt_with_limit(keys.identity.identity()?, &mut reader, file, limit)?,
            None => decrypt(keys.identity.identity()?, &mut reader, file)?,
        };
        if let Some((bytes, digest)) = expected_ciphertext {
            // Bind the exact stream decrypted, including any bytes age did not consume.
            io::copy(&mut reader, &mut io::sink())?;
            if reader.bytes != bytes || format!("{:x}", reader.digest.finalize()) != digest {
                bail!("ciphertext changed after authentication; plaintext was not released");
            }
        }
        Ok(view)
    }

    /// Decrypts `manifest.age` into scratch, reads it under the manifest size cap, and
    /// returns the authenticated manifest. The scratch copy is gone before this returns.
    pub(crate) fn authenticated_manifest(
        &self,
        path: &Path,
        header: &PublicHeader,
        _claim: &ActivityLock,
    ) -> Result<ArtifactManifest> {
        let view = self.decrypt_to_scratch_owned(
            path,
            MANIFEST_FILE,
            Some(MAX_MANIFEST_BYTES),
            Some((header.manifest_ciphertext_bytes, &header.manifest_sha256)),
            None,
        )?;
        let result = (|| -> Result<ArtifactManifest> {
            let bytes = read_bounded(view.path(), MAX_MANIFEST_BYTES + 1)?;
            let manifest: ArtifactManifest = serde_json::from_slice(&bytes)
                .context("manifest.age does not hold a v1 artifact manifest")?;
            manifest.validate()?;
            Ok(manifest)
        })();
        drop(view);
        result
    }
}

struct DigestReader<R> {
    inner: R,
    digest: Sha256,
    bytes: u64,
}

impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buffer)?;
        self.digest.update(&buffer[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{key_pair, temp_keys, temp_root};
    use backup_crypto::keystore::KeyFile;

    #[test]
    fn manifest_decryption_binds_the_stream_to_the_verified_header() -> Result<()> {
        let root = temp_root();
        let keydir = temp_keys();
        let (identity, recipient) = key_pair(&keydir);
        let store = LocalStore::with_keys(root.clone(), &identity, &recipient)?;
        let recipient = KeyFile::load(&recipient, backup_crypto::keystore::KeyRole::Recipient)?;
        let path = root.join("manifest.age");
        let mut original = Vec::new();
        backup_crypto::stream::encrypt(recipient.recipient(), &b"{}"[..], &mut original)?;
        let header = PublicHeader {
            format_version: 1,
            backup_id: Uuid::new_v4(),
            recipient_id: "a".repeat(64),
            signer_id: "b".repeat(64),
            recipient_suite: "mlkem768x25519-v0".to_string(),
            signature_suite: "ed25519+ml-dsa-65".to_string(),
            manifest_ciphertext_bytes: original.len() as u64,
            payload_ciphertext_bytes: 1,
            manifest_sha256: format!("{:x}", Sha256::digest(&original)),
            payload_sha256: "c".repeat(64),
        };
        // A valid replacement stream cannot be mistaken for the authenticated JSON.
        let mut replacement = Vec::new();
        backup_crypto::stream::encrypt(recipient.recipient(), &b""[..], &mut replacement)?;
        fs::write(&path, replacement)?;
        let error = store
            .authenticated_manifest(&path, &header, &ActivityLock::hold(&store.root).unwrap())
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("ciphertext changed after authentication")
                || error.contains("failed to decrypt completely")
                || error.contains("artifact is not a readable age stream"),
            "{error}"
        );
        assert_eq!(fs::read_dir(root.join(SCRATCH_DIR))?.count(), 0);
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(keydir)?;
        Ok(())
    }
}
