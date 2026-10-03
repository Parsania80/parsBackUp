//! The storage root itself: how it is opened, what shape the store has, where its files live,
//! and how work a dead process left behind is cleared.
//!
//! These constructors are the only place in the crate that turns configuration into a store: a
//! root plus the keys named beside it, checked together before the root is touched. Everything
//! else here assumes that decision was already made, which is why publishing, reading and
//! recovering never inspect a key file.
//!
//! [`LocalStore::recover`] is the only code in this crate that deletes anything, and it does so
//! only under the store's exclusive maintenance claim — ADR 0004.

use crate::keys::load_pair;
use crate::layout::{
    ARTIFACTS_DIR, INVENTORY_FILE, LOCKS_DIR, PLAN_SUFFIX, PLANS_DIR, SCRATCH_DIR, STAGING_DIR,
};
use crate::{LocalStore, StoreKeys, ensure_real_dir};
use anyhow::{Context, Result, bail};
use backup_crypto::keystore::{KeyFile, KeyRole};
use backup_crypto::signing::{SigningKeyFile, SigningRole};
use backup_inventory::{ActivityLock, Inventory};
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// What one maintenance pass did, as its caller reports it.
#[derive(Clone, Debug, Default)]
pub struct Recovery {
    /// `false` means the store was busy: nothing was examined, swept, or removed.
    pub claimed: bool,
    /// Jobs a dead process left non-terminal, which this pass moved to `interrupted`.
    pub interrupted: Vec<Uuid>,
    /// Working directories this pass removed.
    pub removed: Vec<PathBuf>,
    /// Names under `staging/` or `scratch/` this tool would not have written, left alone on purpose.
    pub refused: Vec<PathBuf>,
}

impl LocalStore {
    /// A store that publishes plaintext artifacts.
    pub fn new(root: PathBuf) -> Result<Self> {
        Self::open(root, None)
    }

    /// A store that seals every artifact it publishes.
    ///
    /// Both files are loaded before the storage root is touched, and the recipient must
    /// be the one the configured identity can open: sealing under a stranger's recipient
    /// would publish an artifact this deployment can never restore.
    pub fn with_keys(
        root: PathBuf,
        identity_file: impl AsRef<Path>,
        recipient_file: impl AsRef<Path>,
    ) -> Result<Self> {
        let (identity, recipient) = load_pair(identity_file.as_ref(), recipient_file.as_ref())?;
        Self::open(
            root,
            Some(StoreKeys {
                identity,
                recipient: Some(recipient),
                signing: None,
                verifying: None,
            }),
        )
    }

    /// A store that writes signed v1 artifacts: it seals to the configured recipient and
    /// signs with the configured signing key.
    ///
    /// The two signing halves are loaded together and required to be the *same* key, because
    /// a store that signs under one key while trusting another publishes artifacts its own
    /// next command refuses to read. That failure is cheap to detect here and expensive to
    /// discover during a restore.
    #[allow(clippy::too_many_arguments)]
    pub fn with_signing_keys(
        root: PathBuf,
        identity_file: impl AsRef<Path>,
        recipient_file: impl AsRef<Path>,
        signing_key_file: impl AsRef<Path>,
        verifying_key_file: impl AsRef<Path>,
    ) -> Result<Self> {
        let (identity, recipient) = load_pair(identity_file.as_ref(), recipient_file.as_ref())?;
        let signing = SigningKeyFile::load(signing_key_file.as_ref(), SigningRole::Signing)
            .with_context(|| {
                format!(
                    "load signing key file {}",
                    signing_key_file.as_ref().display()
                )
            })?;
        let verifying = SigningKeyFile::load(verifying_key_file.as_ref(), SigningRole::Verifying)
            .with_context(|| {
            format!(
                "load verifying key file {}",
                verifying_key_file.as_ref().display()
            )
        })?;
        if signing.verifier() != verifying.verifier() {
            bail!(
                "verifying key file {} is not the public half of signing key file {}",
                verifying_key_file.as_ref().display(),
                signing_key_file.as_ref().display()
            );
        }
        Self::open(
            root,
            Some(StoreKeys {
                identity,
                recipient: Some(recipient),
                signing: Some(signing),
                verifying: Some(verifying),
            }),
        )
    }

    /// A store that reads, verifies, and restores v1 artifacts, and cannot write any.
    ///
    /// This is the disaster-recovery shape: the decryption identity plus the trusted
    /// verifying key, with no recipient and no signing secret to lose. `publish` and
    /// [`LocalStore::publish_signed`] both refuse here rather than producing something this
    /// host could not have authenticated.
    pub fn for_reading(
        root: PathBuf,
        identity_file: impl AsRef<Path>,
        verifying_key_file: impl AsRef<Path>,
    ) -> Result<Self> {
        let identity = KeyFile::load(identity_file.as_ref(), KeyRole::Identity)
            .with_context(|| format!("load identity file {}", identity_file.as_ref().display()))?;
        let verifying = SigningKeyFile::load(verifying_key_file.as_ref(), SigningRole::Verifying)
            .with_context(|| {
            format!(
                "load verifying key file {}",
                verifying_key_file.as_ref().display()
            )
        })?;
        Self::open(
            root,
            Some(StoreKeys {
                identity,
                recipient: None,
                signing: None,
                verifying: Some(verifying),
            }),
        )
    }

    fn open(root: PathBuf, keys: Option<StoreKeys>) -> Result<Self> {
        if !root.is_absolute() {
            bail!("storage root must be absolute");
        }
        fs::create_dir_all(&root).context("create storage root")?;
        ensure_real_dir(&root)?;
        let mut dirs = vec![STAGING_DIR, ARTIFACTS_DIR, PLANS_DIR, LOCKS_DIR];
        if keys.is_some() {
            dirs.push(SCRATCH_DIR);
        }
        for name in dirs {
            let dir = root.join(name);
            if !dir.exists() {
                DirBuilder::new().mode(0o700).create(&dir)?;
            }
            ensure_real_dir(&dir)?;
        }
        // Nothing is removed here. Every command opens a store, including the ones that only read,
        // and ADR 0004 makes clearing a working directory a decision that requires proof someone
        // else is not using it — which is [`LocalStore::recover`], under the store's exclusive
        // maintenance claim.
        Ok(Self { root, keys })
    }

    /// Clears working directories this store can prove are abandoned, and corrects the job rows a
    /// dead process left behind.
    ///
    /// The exclusive activity claim is the proof. While any operation holds the store shared, an
    /// entry in `staging/` or `scratch/` may be mid-write, so a busy store makes this pass examine
    /// nothing and remove nothing and the report says so; housekeeping that queued behind a two-hour
    /// dump would turn a cosmetic gap into an outage. That also means an abandoned entry can survive
    /// indefinitely on a continuously busy store, which is a documented limit rather than a bug.
    ///
    /// It runs before a scope is claimed, because after that the old row and the new job are
    /// indistinguishable to [`backup_inventory::JobLock::is_free`] — see ADR 0004's decision 6.
    pub fn recover(&self) -> Result<Recovery> {
        let Some(claim) = ActivityLock::hold_maintenance(&self.root)? else {
            return Ok(Recovery::default());
        };
        // The inventory is opened through its own binding: this pass cannot compute a source
        // fingerprint, because that needs the server major a preflight reads off a live database.
        let interrupted = match Inventory::open_bound(&self.root.join(INVENTORY_FILE))? {
            None => Vec::new(),
            Some(inventory) => inventory.sweep_interrupted(&self.root)?,
        };
        let mut removed = Vec::new();
        let mut refused = Vec::new();
        for name in [STAGING_DIR, SCRATCH_DIR] {
            self.clear_working_dir(&self.root.join(name), &mut removed, &mut refused)?;
        }
        // The claim drops after the removals, so a competing command cannot create a working
        // directory while this one is still deleting inside it.
        drop(claim);
        Ok(Recovery {
            claimed: true,
            interrupted,
            removed,
            refused,
        })
    }

    /// Removes the entries of one working directory that can only be leftovers.
    ///
    /// Qualification is by name and by type: a UUID-named *directory* is the only shape this tool
    /// writes there, so anything else — a symlink, a plain file, a name it did not make — is
    /// reported and left alone. Refusing is not a failure of the pass; an operator's own file in
    /// `staging/` is not evidence of a dirty store, and deleting it would make a backup tool the
    /// thing that loses data here.
    fn clear_working_dir(
        &self,
        dir: &Path,
        removed: &mut Vec<PathBuf>,
        refused: &mut Vec<PathBuf>,
    ) -> Result<()> {
        // A store configured without keys has no `scratch/` to clear, and an absent directory is
        // not a problem: there is nothing in it either way.
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", dir.display()));
            }
        };
        for entry in entries {
            let path = entry
                .with_context(|| format!("read {}", dir.display()))?
                .path();
            // `symlink_metadata` does not follow the name, so a symlink here reports as a symlink
            // rather than as the directory it points at.
            let meta = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect {}", path.display()))?;
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if Uuid::parse_str(name.as_ref()).is_err() || !meta.is_dir() {
                refused.push(path);
                continue;
            }
            fs::remove_dir_all(&path)
                .with_context(|| format!("remove abandoned {}", path.display()))?;
            removed.push(path);
        }
        Ok(())
    }

    pub(crate) fn encrypted(&self) -> bool {
        self.keys.is_some()
    }

    pub(crate) fn artifact_dir(&self, id: Uuid) -> PathBuf {
        self.root.join(ARTIFACTS_DIR).join(id.to_string())
    }

    pub(crate) fn plan_path(&self, id: Uuid) -> PathBuf {
        self.root.join(PLANS_DIR).join(format!("{id}{PLAN_SUFFIX}"))
    }
}
