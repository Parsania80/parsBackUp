//! The key-file lifecycle: the pair rule, the generate/publish/status commands an
//! operator runs, and the two file-system guarantees they depend on.
//!
//! Nothing here opens a storage root. A key is decided by configuration and read by the
//! store's constructors, so these functions exist to make the *files* correct before a
//! store is ever built, and to report them without ever returning secret material.

use anyhow::{Context, Result, bail};
use backup_crypto::keystore::{KeyFile, KeyRole, KeyStatus, status as read_key_file};
use backup_crypto::signing::{
    SigningKeyFile, SigningKeyStatus, SigningRole, status as signing_status,
};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

/// Loads both halves of a configured key pair and refuses a pair that cannot open
/// the artifacts it seals.
pub(crate) fn load_pair(identity_file: &Path, recipient_file: &Path) -> Result<(KeyFile, KeyFile)> {
    let identity = KeyFile::load(identity_file, KeyRole::Identity)?;
    let recipient = KeyFile::load(recipient_file, KeyRole::Recipient)?;
    if recipient.recipient() != identity.recipient() {
        bail!(
            "recipient key file {} is not the recipient of identity key file {}",
            recipient.path().display(),
            identity.path().display()
        );
    }
    Ok((identity, recipient))
}

/// Reports the two configured key files: path, role, suite, permission bits, and the
/// public recipient. Nothing secret is in the result, which is what makes this safe to
/// run on a host that may only write backups.
///
/// The files are loaded with the store's own rules before their status is read, so a
/// pair this reports as usable is a pair `with_keys` will accept.
pub fn key_status(
    identity_file: impl AsRef<Path>,
    recipient_file: impl AsRef<Path>,
) -> Result<(KeyStatus, KeyStatus)> {
    let (identity, recipient) = load_pair(identity_file.as_ref(), recipient_file.as_ref())?;
    Ok((
        read_key_file(identity.path(), KeyRole::Identity)?,
        read_key_file(recipient.path(), KeyRole::Recipient)?,
    ))
}

/// Refuses a key path that already holds something, a dangling symlink included, so
/// no key command can replace material an existing artifact depends on.
fn refuse_occupied(path: &Path) -> Result<()> {
    // Checked through the symlink so a dangling link is treated as the occupied path
    // it is, rather than as free space to write into.
    if fs::symlink_metadata(path).is_ok() {
        bail!(
            "refusing to overwrite the existing key file {}; a new key orphans every \
             artifact encrypted to the current one",
            path.display()
        );
    }
    Ok(())
}

/// Creates the directory a key file is configured into when it does not exist yet.
/// The configured location is the operator's own directory, and a first run is the
/// normal case, so it is created here rather than left as a write error. It is
/// private because it will hold a key: the same reason the key itself is 0600.
fn ensure_private_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if !parent.exists() {
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)?;
    }
    Ok(())
}

/// Generates the identity and publishes its recipient half, in one deliberate step.
///
/// Neither file is created unless neither already exists: an identity whose recipient
/// was never written cannot be encrypted to, and an operator who re-runs the command
/// after a half-finished attempt would silently generate an unrelated second key.
pub fn generate_key_pair(
    identity_file: impl AsRef<Path>,
    recipient_file: impl AsRef<Path>,
) -> Result<(KeyStatus, KeyStatus)> {
    let identity_file = identity_file.as_ref();
    let recipient_file = recipient_file.as_ref();
    for path in [identity_file, recipient_file] {
        refuse_occupied(path)?;
    }
    for path in [identity_file, recipient_file] {
        ensure_private_parent(path)?;
    }
    let identity = KeyFile::create_identity(identity_file)?;
    KeyFile::write_recipient(recipient_file, identity.recipient())?;
    key_status(identity_file, recipient_file)
}

/// Publishes the recipient half of an identity this CLI did not generate, so an
/// operator who supplied the seed themselves can make the store accept the pair.
///
/// Only the recipient file is written, and only into free space: the identity is read
/// and never modified, because rewriting a seed is the one action that makes every
/// artifact sealed under it permanently unreadable. The identity is loaded with the
/// store's own rules first, so a file the store would refuse to open never gets a
/// public half published beside it.
pub fn publish_recipient(
    identity_file: impl AsRef<Path>,
    recipient_file: impl AsRef<Path>,
) -> Result<(KeyStatus, KeyStatus)> {
    let identity_file = identity_file.as_ref();
    let recipient_file = recipient_file.as_ref();
    refuse_occupied(recipient_file)?;
    let identity = KeyFile::load(identity_file, KeyRole::Identity)?;
    ensure_private_parent(recipient_file)?;
    KeyFile::write_recipient(recipient_file, identity.recipient())?;
    key_status(identity_file, recipient_file)
}

/// Generates the signing key and publishes its verifying half, in one deliberate step.
///
/// The same all-or-nothing rule as [`generate_key_pair`]: neither file is created unless
/// neither already exists. A signing key whose verifying half was never written signs
/// artifacts this deployment cannot read, and re-running the command to find out would
/// replace the first key with an unrelated second one.
pub fn generate_signing_pair(
    signing_key_file: impl AsRef<Path>,
    verifying_key_file: impl AsRef<Path>,
) -> Result<Vec<SigningKeyStatus>> {
    let signing_key_file = signing_key_file.as_ref();
    let verifying_key_file = verifying_key_file.as_ref();
    for path in [signing_key_file, verifying_key_file] {
        refuse_occupied(path)?;
    }
    for path in [signing_key_file, verifying_key_file] {
        ensure_private_parent(path)?;
    }
    let signing = SigningKeyFile::create_signing(signing_key_file)?;
    SigningKeyFile::write_verifying(verifying_key_file, signing.verifier())?;
    signing_key_status(Some(signing_key_file), verifying_key_file)
}

/// Publishes the verifying half of a signing key this CLI did not generate, so an operator
/// who supplied the seed themselves can make the store trust the pair.
///
/// Only the verifying file is written, and only into free space: the signing seed is read
/// and never modified, because rewriting it is the one action that makes every artifact
/// signed under it unverifiable under the key a reader holds.
pub fn publish_verifying(
    signing_key_file: impl AsRef<Path>,
    verifying_key_file: impl AsRef<Path>,
) -> Result<Vec<SigningKeyStatus>> {
    let signing_key_file = signing_key_file.as_ref();
    let verifying_key_file = verifying_key_file.as_ref();
    refuse_occupied(verifying_key_file)?;
    let signing = SigningKeyFile::load(signing_key_file, SigningRole::Signing)
        .with_context(|| format!("load signing key file {}", signing_key_file.display()))?;
    ensure_private_parent(verifying_key_file)?;
    SigningKeyFile::write_verifying(verifying_key_file, signing.verifier())?;
    signing_key_status(Some(signing_key_file), verifying_key_file)
}

/// Reports the configured signing key files: path, role, suite, permission bits, and the
/// public signer id. No secret is in the result, which is what makes it safe to print.
///
/// The verifying file is required and the signing file optional, because that is the split
/// between the two hosts: a disaster-recovery machine trusts a public key and must not hold
/// a private one. When both are named they have to be the same key, since a store that signs
/// under one key while trusting another publishes artifacts its own next command refuses.
pub fn signing_key_status(
    signing_key_file: Option<&Path>,
    verifying_key_file: &Path,
) -> Result<Vec<SigningKeyStatus>> {
    let verifying = SigningKeyFile::load(verifying_key_file, SigningRole::Verifying)
        .with_context(|| format!("load verifying key file {}", verifying_key_file.display()))?;
    let mut statuses = Vec::new();
    if let Some(path) = signing_key_file {
        let signing = SigningKeyFile::load(path, SigningRole::Signing)
            .with_context(|| format!("load signing key file {}", path.display()))?;
        if signing.verifier() != verifying.verifier() {
            bail!(
                "verifying key file {} is not the public half of signing key file {}",
                verifying_key_file.display(),
                path.display()
            );
        }
        statuses.push(signing_status(signing.path(), SigningRole::Signing)?);
    }
    statuses.push(signing_status(verifying.path(), SigningRole::Verifying)?);
    Ok(statuses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalStore;
    use crate::fixture::{key_pair, temp_keys, temp_root};
    use backup_application::ArtifactStore;
    use backup_crypto::protocol::{IDENTITY_MARKER, SUITE_HYBRID};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// A generated pair reports the public recipient and the modes that make the
    /// identity usable, and what it reports is what `with_keys` accepts.
    #[test]
    fn a_generated_pair_reports_public_facts_and_opens_the_store() {
        let dir = temp_keys();
        fs::create_dir_all(&dir).unwrap();
        let identity = dir.join("identity.key");
        let recipient = dir.join("recipient.key");
        let (identity_status, recipient_status) = generate_key_pair(&identity, &recipient).unwrap();

        assert_eq!(identity_status.mode, 0o600);
        assert_eq!(recipient_status.mode, 0o644);
        assert_eq!(identity_status.suite, SUITE_HYBRID);
        assert_eq!(
            identity_status.recipient_hex, recipient_status.recipient_hex,
            "status is how an operator proves the two files match"
        );
        // The recipient is the 1216-byte public key; an identity-length seed here would
        // mean the report carried secret material.
        assert_eq!(identity_status.recipient_hex.len(), 2432);
        assert_eq!(
            key_status(&identity, &recipient).unwrap().0.recipient_hex,
            identity_status.recipient_hex
        );

        let root = temp_root();
        // A pair that reports these facts is a pair the store accepts: `key_status`
        // loads under exactly the rules `with_keys` applies.
        assert!(LocalStore::with_keys(root.clone(), &identity, &recipient).is_ok());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    /// Generating into a location the operator has not created yet is the normal
    /// first run, and the directory that will hold the identity is private.
    #[test]
    fn generation_creates_a_private_parent() {
        let dir = temp_keys();
        let identity = dir.join("nested/deeper/identity.key");
        let recipient = dir.join("nested/deeper/recipient.key");
        let (identity_status, _) = generate_key_pair(&identity, &recipient).unwrap();

        let parent = identity.parent().unwrap();
        assert_eq!(
            fs::metadata(parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(identity_status.mode, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    /// An identity the operator supplied is a key this CLI can still make usable: the
    /// public half is derived and written, and the identity is read and never rewritten.
    #[test]
    fn publishing_writes_the_recipient_of_a_hand_written_identity() {
        let dir = temp_keys();
        let identity = dir.join("identity.key");
        let recipient = dir.join("recipient.key");
        fs::create_dir_all(&dir).unwrap();
        // Any 32-byte seed is a valid identity. This one is fixed so the test stays
        // reproducible and carries nothing that protects real data.
        let seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&identity, format!("{IDENTITY_MARKER}\n{seed}\n")).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(&identity).unwrap();

        let (identity_status, recipient_status) = publish_recipient(&identity, &recipient).unwrap();
        assert_eq!(
            fs::read(&identity).unwrap(),
            before,
            "the identity was rewritten"
        );
        assert_eq!(identity_status.mode, 0o600);
        assert_eq!(recipient_status.mode, 0o644);
        assert_eq!(
            identity_status.recipient_hex,
            recipient_status.recipient_hex
        );
        assert_eq!(identity_status.recipient_hex.len(), 2432);
        // A published pair is a pair the store opens, which is the whole point: a
        // backup written under this identity is readable by the same configuration.
        let root = temp_root();
        let store = LocalStore::with_keys(root.clone(), &identity, &recipient).unwrap();
        assert!(store.list().is_ok());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    /// Publishing is not a way to replace a published key.
    #[test]
    fn publishing_refuses_an_occupied_recipient() {
        let dir = temp_keys();
        let (identity, recipient) = key_pair(&dir);
        let original = fs::read(&recipient).unwrap();
        let error = publish_recipient(&identity, &recipient)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert_eq!(fs::read(&recipient).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    /// The identity is loaded under the store's own rules before its half is written,
    /// so a key the store would refuse never acquires a usable partner.
    #[test]
    fn publishing_refuses_an_identity_the_store_would_not_open() {
        let dir = temp_keys();
        let identity = dir.join("identity.key");
        let recipient = dir.join("recipient.key");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &identity,
            format!("{IDENTITY_MARKER}\n{}\n", "ab".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(publish_recipient(&identity, &recipient).is_err());
        assert!(
            !recipient.exists(),
            "a refused identity still got a public half"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    /// Generating over a key would orphan every artifact sealed to it, so neither
    /// file is touched when the other already exists.
    #[test]
    fn generation_refuses_an_occupied_path_before_writing() {
        let dir = temp_keys();
        fs::create_dir_all(&dir).unwrap();
        let identity = dir.join("identity.key");
        let recipient = dir.join("recipient.key");
        let (first, _) = generate_key_pair(&identity, &recipient).unwrap();

        let error = format!(
            "{:#}",
            generate_key_pair(&identity, &recipient).err().unwrap()
        );
        assert!(error.contains("refusing to overwrite"), "got: {error}");

        // An occupied recipient with a free identity is refused the same way: writing a
        // new identity there would seal artifacts nobody can open.
        fs::remove_file(&identity).unwrap();
        let error = format!(
            "{:#}",
            generate_key_pair(&identity, &recipient).err().unwrap()
        );
        assert!(error.contains("refusing to overwrite"), "got: {error}");
        assert!(
            !identity.exists(),
            "a refused generation must not leave an unusable identity behind"
        );

        // The refusal left the original recipient intact, so the pair still resolves to
        // the key it was generated with.
        assert_eq!(
            KeyFile::load(&recipient, KeyRole::Recipient)
                .unwrap()
                .recipient()
                .to_string(),
            first.recipient_hex
        );

        fs::remove_dir_all(dir).unwrap();
    }

    /// Sealing under a recipient the configured identity cannot open would publish an
    /// artifact this deployment can never restore.
    #[test]
    fn a_mismatched_key_pair_is_refused_before_the_store_is_created() {
        let root = temp_root();
        let first = temp_keys();
        let second = temp_keys();
        let (identity_a, _) = key_pair(&first);
        let (_, recipient_b) = key_pair(&second);
        let error = LocalStore::with_keys(root.clone(), &identity_a, &recipient_b)
            .err()
            .expect("a mismatched key pair must be refused")
            .to_string();
        assert!(error.contains("is not the recipient of"), "{error}");
        assert!(!root.exists());
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }
}
