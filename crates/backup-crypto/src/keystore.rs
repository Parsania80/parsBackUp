//! Service-owned key files and the provider ports the backup and restore paths use
//! to reach them.
//!
//! A key file is two lines: the suite marker, then one lowercase hex key. Nothing in
//! either line is inferred from shape alone — the marker names the suite, and the
//! expected hex length follows from the role the caller asked for, so a reader never
//! has to guess which key it is holding.
//!
//! These files live outside the artifact store on purpose. An encrypted archive in a
//! directory that also contains the identity that opens it is a plaintext archive
//! with extra steps.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::protocol::{
    IDENTITY_MARKER, MAX_IDENTITY_HEX_CHARS, MAX_KEY_FILE_BYTES, PRIVATE_FILE_FORBIDDEN_MODE_BITS,
    PUBLIC_KEY_BYTES, RECIPIENT_MARKER, SEED_BYTES, STANZA_TAG, SUITE_HYBRID,
};
use crate::recipient::{HybridIdentity, HybridRecipient, hex};
use anyhow::{Context as _, Result, bail};

/// How a caller intends to use a key file. The role decides the expected key length,
/// so a recipient file can never be mistaken for an identity file at load time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    /// Decrypts artifacts; holds the 32-byte seed.
    Identity,
    /// Encrypts artifacts; holds the full hybrid public key.
    Recipient,
}

impl KeyRole {
    /// Hex characters a well-formed key line for this role contains.
    pub fn hex_chars(self) -> usize {
        match self {
            Self::Identity => crate::protocol::hex_len(SEED_BYTES),
            Self::Recipient => crate::protocol::hex_len(PUBLIC_KEY_BYTES),
        }
    }

    /// Only an identity is secret; a recipient file is public by design.
    fn is_secret(self) -> bool {
        matches!(self, Self::Identity)
    }
}

/// Gives the backup and restore paths an identity without naming where it came
/// from, so a file today can become a keyring or a KMS entry later.
pub trait IdentityProvider {
    fn identity(&self) -> Result<&HybridIdentity>;
}

/// Gives a writer the recipient to encrypt to. Kept separate from
/// [`IdentityProvider`] because a backup host legitimately holds only the public
/// half.
pub trait RecipientProvider {
    fn recipient(&self) -> Result<&HybridRecipient>;
}

/// A key file loaded from disk.
pub struct KeyFile {
    path: PathBuf,
    role: KeyRole,
    identity: Option<HybridIdentity>,
    recipient: HybridRecipient,
}

/// Names the file and its role, never its contents: a key file can end up inside an
/// error chain that reaches a log.
impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFile({:?} {})", self.role, self.path.display())
    }
}

impl KeyFile {
    /// Reads and validates a key file for the requested role.
    ///
    /// An identity file must be a regular, non-symlink file readable by its owner
    /// alone; anything else is refused before its contents are parsed.
    pub fn load(path: impl AsRef<Path>, role: KeyRole) -> Result<Self> {
        let path = path.as_ref();
        let line = read_key_line(path, role)?;
        let identity = match role {
            KeyRole::Identity => {
                let identity = HybridIdentity::from_seed_hex(&line)
                    .with_context(|| format!("{} key file {}", label(role), path.display()))?;
                Some(identity)
            }
            KeyRole::Recipient => None,
        };
        let recipient = match &identity {
            Some(identity) => identity.to_recipient(),
            None => {
                let bytes = hex::decode(&line)
                    .map_err(|e| anyhow::anyhow!("recipient key is not valid lowercase hex: {e}"))
                    .with_context(|| format!("{} key file {}", label(role), path.display()))?;
                HybridRecipient::from_bytes(&bytes)
                    .with_context(|| format!("{} key file {}", label(role), path.display()))?
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            role,
            identity,
            recipient,
        })
    }

    /// Generates a fresh identity and writes it to `path`, refusing to overwrite an
    /// existing file. The new identity's recipient is written nowhere: publishing it
    /// is a separate, deliberate step.
    pub fn create_identity(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let identity = HybridIdentity::generate();
        let text = format!("{IDENTITY_MARKER}\n{}\n", identity.to_seed_hex());
        write_key_file(path, text.as_bytes(), true)
            .with_context(|| format!("create identity key file {}", path.display()))?;
        let loaded = Self::load(path, KeyRole::Identity)?;
        // A generated key that fails to read back identically would mean the store
        // and the process disagree about the same bytes.
        if loaded.recipient != identity.to_recipient() {
            bail!(
                "identity key file {} did not read back as the key it was written with",
                path.display()
            );
        }
        Ok(loaded)
    }

    /// Writes the public half of an identity — or any recipient — to `path`. Public
    /// material, so no private-file mode is imposed.
    pub fn write_recipient(path: impl AsRef<Path>, recipient: &HybridRecipient) -> Result<Self> {
        let path = path.as_ref();
        let text = format!("{RECIPIENT_MARKER}\n{recipient}\n");
        write_key_file(path, text.as_bytes(), false)
            .with_context(|| format!("create recipient key file {}", path.display()))?;
        Self::load(path, KeyRole::Recipient)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }

    /// The suite this key belongs to, as a manifest records it.
    pub fn suite(&self) -> &'static str {
        SUITE_HYBRID
    }

    /// The public half, which is safe to print and is how an operator confirms two
    /// key files belong together.
    pub fn recipient(&self) -> &HybridRecipient {
        &self.recipient
    }
}

impl IdentityProvider for KeyFile {
    fn identity(&self) -> Result<&HybridIdentity> {
        self.identity
            .as_ref()
            .context("key file holds only a recipient; an identity is required to decrypt")
    }
}

impl RecipientProvider for KeyFile {
    fn recipient(&self) -> Result<&HybridRecipient> {
        Ok(&self.recipient)
    }
}

/// What `key status` reports: enough to confirm a deployment's keys line up, and
/// never a byte of secret material.
#[derive(Debug)]
pub struct KeyStatus {
    pub path: PathBuf,
    pub role: KeyRole,
    pub suite: &'static str,
    /// Owner permission bits, as the filesystem reports them.
    pub mode: u32,
    /// Lowercase hex of the public key. Secret files report the recipient they
    /// imply, which is public, and nothing else.
    pub recipient_hex: String,
}

/// Inspects a key file for an operator, without decrypting anything.
pub fn status(path: impl AsRef<Path>, role: KeyRole) -> Result<KeyStatus> {
    let path = path.as_ref();
    let key = KeyFile::load(path, role)?;
    let mode = fs::symlink_metadata(path)
        .context("inspect key file")?
        .permissions()
        .mode()
        & 0o777;
    Ok(KeyStatus {
        path: path.to_path_buf(),
        role,
        suite: key.suite(),
        mode,
        recipient_hex: key.recipient().to_string(),
    })
}

/// Reads a key file and returns its single key line, having checked every property
/// that must hold before key material is parsed: size, ownership, and the suite
/// marker.
fn read_key_line(path: &Path, role: KeyRole) -> Result<String> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {} key file {}", label(role), path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        bail!(
            "{} key file {} must be a regular non-symlink file",
            label(role),
            path.display()
        );
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        bail!(
            "{} key file {} is {} bytes, over the {} byte limit for a {}-byte {}",
            label(role),
            path.display(),
            meta.len(),
            MAX_KEY_FILE_BYTES,
            role.hex_chars() / 2,
            STANZA_TAG
        );
    }
    if role.is_secret() && meta.permissions().mode() & PRIVATE_FILE_FORBIDDEN_MODE_BITS != 0 {
        bail!(
            "identity key file {} must be mode 0600 or stricter, not {:04o}",
            path.display(),
            meta.permissions().mode() & 0o777
        );
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("read {} key file {}", label(role), path.display()))?;
    let mut lines = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let marker = lines.next();
    if marker != Some(IDENTITY_MARKER) {
        bail!(
            "{} key file {} must start with the suite marker {IDENTITY_MARKER}",
            label(role),
            path.display()
        );
    }
    let key = lines.next().with_context(|| {
        format!(
            "{} key file {} has a marker but no key line",
            label(role),
            path.display()
        )
    })?;
    if lines.next().is_some() {
        bail!(
            "{} key file {} must hold exactly one {}-character key line",
            label(role),
            path.display(),
            role.hex_chars()
        );
    }
    // Checked here rather than in the parser so the error names the file and the
    // expected length; the parser only knows about hex.
    if key.len() > MAX_IDENTITY_HEX_CHARS && role == KeyRole::Identity {
        bail!(
            "identity key file {} has a {}-character key line, over the {} limit",
            path.display(),
            key.len(),
            MAX_IDENTITY_HEX_CHARS
        );
    }
    if key.len() != role.hex_chars() {
        bail!(
            "{} key file {} has a {}-character key line, expected {}",
            label(role),
            path.display(),
            key.len(),
            role.hex_chars()
        );
    }
    Ok(key.to_string())
}

/// Writes a key file atomically enough for a key: create-only, owner-only for
/// secrets, and never through an existing path.
fn write_key_file(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    if secret {
        options.mode(0o600);
    } else {
        options.mode(0o644);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    // `mode` on create is masked by umask, so set the final permissions explicitly.
    file.set_permissions(fs::Permissions::from_mode(if secret {
        0o600
    } else {
        0o644
    }))?;
    Ok(())
}

fn label(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Identity => "identity",
        KeyRole::Recipient => "recipient",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// anyhow prints only the outermost context with `to_string`; assertions need
    /// the whole chain, because the refusal reason is the cause.
    fn chain(error: anyhow::Error) -> String {
        format!("{error:#}")
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("backupctl-keystore-{name}-{}", Uuid::new_v4()))
    }

    /// A generated identity round-trips through its own file, and its recipient is
    /// the same key the public file carries.
    #[test]
    fn generated_identity_and_recipient_files_agree() {
        let identity_path = temp_path("identity");
        let recipient_path = temp_path("recipient");
        let created = KeyFile::create_identity(&identity_path).unwrap();
        assert_eq!(created.role(), KeyRole::Identity);
        assert_eq!(created.suite(), SUITE_HYBRID);

        let public = KeyFile::write_recipient(&recipient_path, created.recipient()).unwrap();
        assert_eq!(public.role(), KeyRole::Recipient);
        assert_eq!(public.recipient(), created.recipient());

        let reloaded = KeyFile::load(&identity_path, KeyRole::Identity).unwrap();
        assert_eq!(reloaded.recipient(), created.recipient());

        // The two provider ports must agree on the same file for the writer path.
        let as_identity: &dyn IdentityProvider = &reloaded;
        let as_recipient: &dyn RecipientProvider = &public;
        assert_eq!(
            as_identity.identity().unwrap().to_recipient(),
            *as_recipient.recipient().unwrap()
        );

        for path in [identity_path, recipient_path] {
            let _ = fs::remove_file(path);
        }
    }

    /// An identity file is secret, so its permissions are enforced on read; a
    /// recipient file is public and is not.
    #[test]
    fn world_readable_identity_is_refused_and_recipient_is_not() {
        let path = temp_path("mode");
        let key = KeyFile::create_identity(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Identity).unwrap_err());
        assert!(error.contains("mode 0600"), "got: {error}");
        assert!(
            !error.contains(&key.to_seed_hex_cache()),
            "the refusal must not echo the seed"
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(KeyFile::load(&path, KeyRole::Identity).is_ok());

        let public_path = temp_path("public-mode");
        KeyFile::write_recipient(&public_path, key.recipient()).unwrap();
        fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            KeyFile::load(&public_path, KeyRole::Recipient).is_ok(),
            "a readable public key is not a finding"
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(public_path);
    }

    /// Malformed key files fail with a message that names the file and the reason,
    /// before any key material is parsed.
    #[test]
    fn malformed_files_are_rejected_by_name() {
        let path = temp_path("malformed");

        fs::write(&path, "AGE-KEY-MATTER\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Identity).unwrap_err());
        assert!(error.contains(IDENTITY_MARKER), "got: {error}");
        assert!(error.contains("marker"), "got: {error}");

        fs::write(&path, format!("{IDENTITY_MARKER}\n")).unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Identity).unwrap_err());
        assert!(error.contains("no key line"), "got: {error}");

        fs::write(
            &path,
            format!(
                "{IDENTITY_MARKER}\n{}\n{}\n",
                "f".repeat(64),
                "e".repeat(64)
            ),
        )
        .unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Identity).unwrap_err());
        assert!(error.contains("exactly one"), "got: {error}");

        // The right length for the other role is still the wrong length here.
        fs::write(&path, format!("{IDENTITY_MARKER}\n{}\n", "f".repeat(64))).unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Recipient).unwrap_err());
        assert!(
            error.contains("2432") && error.contains("64"),
            "a seed line must be refused as a recipient with both lengths named: {error}"
        );
        // A recipient line loaded as an identity is refused by the identity length
        // cap before parsing, so the secret file path never accepts 1216 bytes.
        fs::write(&path, format!("{RECIPIENT_MARKER}\n{}\n", "f".repeat(2432))).unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Identity).unwrap_err());
        assert!(
            error.contains("2432") && error.contains("limit"),
            "got: {error}"
        );

        // Correct length, but not hex.
        fs::write(&path, format!("{IDENTITY_MARKER}\n{}\n", "z".repeat(64))).unwrap();
        let error = chain(KeyFile::load(&path, KeyRole::Identity).unwrap_err());
        assert!(
            error.contains("lowercase hex") || error.contains("hex"),
            "got: {error}"
        );

        // A directory is not a key file.
        let dir = temp_path("directory");
        fs::create_dir(&dir).unwrap();
        assert!(KeyFile::load(&dir, KeyRole::Identity).is_err());

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(dir);
    }

    /// Generating over an existing key would silently orphan every artifact
    /// encrypted to the old one, so the writer refuses.
    #[test]
    fn creation_never_overwrites() {
        let path = temp_path("no-clobber");
        KeyFile::create_identity(&path).unwrap();
        let error = chain(KeyFile::create_identity(&path).unwrap_err());
        assert!(error.contains("File exists"), "got: {error}");
        assert!(
            KeyFile::load(&path, KeyRole::Identity).is_ok(),
            "the original key survives"
        );
        let _ = fs::remove_file(path);
    }

    /// `key status` reports what an operator needs to compare two files, and reports
    /// nothing that is secret.
    #[test]
    fn status_reports_public_facts_only() {
        let identity_path = temp_path("status-identity");
        let recipient_path = temp_path("status-recipient");
        let key = KeyFile::create_identity(&identity_path).unwrap();
        KeyFile::write_recipient(&recipient_path, key.recipient()).unwrap();

        let identity_status = status(&identity_path, KeyRole::Identity).unwrap();
        let recipient_status = status(&recipient_path, KeyRole::Recipient).unwrap();
        assert_eq!(identity_status.suite, SUITE_HYBRID);
        assert_eq!(identity_status.mode, 0o600);
        assert_eq!(recipient_status.mode, 0o644);
        assert_eq!(
            identity_status.recipient_hex, recipient_status.recipient_hex,
            "status is how an operator proves the two files match"
        );
        assert_eq!(
            identity_status.recipient_hex.len(),
            crate::protocol::hex_len(PUBLIC_KEY_BYTES)
        );
        let rendered = format!("{identity_status:?}");
        assert!(!rendered.contains(&key.to_seed_hex_cache()));

        for path in [identity_path, recipient_path] {
            let _ = fs::remove_file(path);
        }
    }

    impl KeyFile {
        /// Test-only accessor so a test can assert a seed never appears in an error
        /// string without holding the secret in an unguarded local.
        fn to_seed_hex_cache(&self) -> String {
            self.identity
                .as_ref()
                .map(HybridIdentity::to_seed_hex)
                .unwrap_or_default()
        }
    }
}
