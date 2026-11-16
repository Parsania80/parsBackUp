//! Read-only facade: no mutable local-store handle escapes this module.
use crate::{LocalStore, ProtectedRoot, layout::*, reconcile};
use anyhow::{Context, Result, ensure};
use backup_application::{ArtifactStore, StoreListing};
use backup_crypto::signing::SigningKeyFile;
use backup_domain::ConfigV1;
use backup_inventory::Inventory;
use std::{fs, fs::File, os::unix::fs::MetadataExt, path::Path, sync::Arc};
use uuid::Uuid;

const MAX_ENTRIES: usize = 4096;
const MAX_COMPONENTS: usize = 8;
const MAX_INVENTORY: u64 = 64 * 1024 * 1024;

pub(crate) struct SnapshotState {
    pub(crate) scratch: Option<Arc<ProtectedRoot>>,
    pub(crate) verifier: Option<SigningKeyFile>,
}
#[derive(Clone, Copy)]
pub enum SnapshotUse {
    Discovery,
    Signature,
    Authenticated,
}

pub struct SnapshotReader {
    store: LocalStore,
}
impl SnapshotReader {
    pub fn open(config: &ConfigV1, usage: SnapshotUse) -> Result<Self> {
        let root = ProtectedRoot::snapshot(config)?;
        let decrypt = matches!(usage, SnapshotUse::Authenticated);
        ensure!(
            !decrypt || config.access == backup_domain::Access::Reader,
            "ACCESS_DENIED"
        );
        let (keys, verifier, parents) = if matches!(usage, SnapshotUse::Discovery) {
            (None, None, Vec::new())
        } else {
            crate::custody::snapshot_keys(config, decrypt)?
        };
        for parent in &parents {
            root.reject_overlap(parent)?;
        }
        let scratch = if decrypt {
            let scratch = ProtectedRoot::external(
                &config.scratch.as_ref().context("SCRATCH_REQUIRED")?.root,
            )?;
            // Both directions: reject equal, ancestor and descendant inode trees.
            root.reject_overlap(scratch.directory())?;
            for parent in &parents {
                scratch.reject_overlap(parent)?;
            }
            Some(scratch)
        } else {
            None
        };
        let store = LocalStore {
            root: root.path().to_path_buf(),
            keys,
            resources: Some(config.resources.clone()),
            fs_guard: Some(root),
            scratch_budget: crate::resources::Budget::new(config.resources.max_scratch_bytes),
            snapshot: Some(Arc::new(SnapshotState { scratch, verifier })),
        };
        let this = Self { store };
        this.check_inventory()?;
        Ok(this)
    }
    pub fn root(&self) -> &Path {
        &self.store.root
    }
    pub fn list(&self) -> Result<StoreListing> {
        self.store.snapshot_listing()
    }
    pub fn inspect(&self, id: Uuid) -> Result<backup_domain::ArtifactManifest> {
        use backup_application::SignedArtifactHandle;
        Ok(self.store.open_signed(id)?.manifest().clone())
    }
    pub fn verify<E: backup_application::DatabaseAdapter>(
        self,
        engine: E,
        config: &backup_domain::Config,
        id: Uuid,
        level: &str,
    ) -> Result<backup_application::VerifyReport> {
        backup_application::VerifyService::new(engine, self.store)
            .verify_read_only(config, id, level)
    }
    pub fn discover_inventory(&self) -> Result<backup_application::ReconcileReport> {
        self.store.snapshot_catalogue()?;
        crate::LocalReconciler(self.store.root.clone()).discover_snapshot()
    }
    fn check_inventory(&self) -> Result<()> {
        let path = self.root().join(INVENTORY_FILE);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) => {
                let file = crate::open_regular(&path)?;
                ensure!(file.metadata()?.len() <= MAX_INVENTORY, "RESOURCE_LIMIT");
                Inventory::open_snapshot_bound(&path)?;
                Ok(())
            }
        }
    }
}
fn private_file(file: &File) -> Result<()> {
    let m = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 & !0o600 == 0
            && m.nlink() == 1,
        "SNAPSHOT_UNSAFE"
    );
    Ok(())
}
fn private_dir(file: &File) -> Result<()> {
    let m = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 & !0o700 == 0,
        "SNAPSHOT_UNSAFE"
    );
    Ok(())
}
fn entries(dir: &File, max: usize) -> Result<Vec<String>> {
    use std::os::fd::AsRawFd;
    let mut names = Vec::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        ensure!(names.len() < max, "RESOURCE_LIMIT");
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("SNAPSHOT_UNSAFE"))?,
        );
    }
    names.sort();
    Ok(names)
}
impl LocalStore {
    pub(crate) fn read_inventory(&self, path: &Path) -> Result<Inventory> {
        if self.snapshot.is_some() {
            Inventory::open_snapshot_bound(path)
        } else {
            Inventory::open_read_only_bound(path)
        }
    }
    pub(crate) fn snapshot_catalogue(&self) -> Result<Vec<Uuid>> {
        let dir = reconcile::directory(&self.root.join(ARTIFACTS_DIR))?;
        private_dir(&dir)?;
        let mut ids = Vec::new();
        for name in entries(&dir, MAX_ENTRIES)? {
            let id = Uuid::parse_str(&name).context("SNAPSHOT_UNSAFE")?;
            ensure!(id.to_string() == name, "SNAPSHOT_UNSAFE");
            self.snapshot_artifact(id, false)?;
            ids.push(id);
        }
        Ok(ids)
    }
    pub(crate) fn snapshot_artifact(&self, id: Uuid, signed: bool) -> Result<()> {
        let dir = reconcile::directory(&self.artifact_dir(id)).context("SNAPSHOT_UNSAFE")?;
        private_dir(&dir)?;
        let names = entries(&dir, MAX_COMPONENTS)?;
        for name in &names {
            ensure!(
                [
                    COMPLETE_MARKER,
                    PUBLIC_FILE,
                    SIGNATURE_FILE,
                    AGE_MANIFEST_FILE,
                    AGE_PAYLOAD_FILE,
                    AGE_GLOBALS_FILE,
                    MANIFEST_FILE,
                    PAYLOAD_FILE,
                    GLOBALS_FILE
                ]
                .contains(&name.as_str()),
                "SNAPSHOT_UNSAFE"
            );
            let file = reconcile::open_at(&dir, name, false).context("SNAPSHOT_UNSAFE")?;
            private_file(&file)?;
            let r = self.resources.as_ref().unwrap();
            let cap = match name.as_str() {
                COMPLETE_MARKER => 0,
                PUBLIC_FILE => backup_domain::MAX_PUBLIC_JSON_BYTES as u64,
                SIGNATURE_FILE => backup_crypto::protocol::HYBRID_SIGNATURE_BYTES as u64,
                MANIFEST_FILE => MAX_MANIFEST_BYTES,
                AGE_MANIFEST_FILE => {
                    backup_domain::ResourceLimits::ciphertext_limit(MAX_MANIFEST_BYTES)
                }
                GLOBALS_FILE => r.max_globals_bytes,
                AGE_GLOBALS_FILE => {
                    backup_domain::ResourceLimits::ciphertext_limit(r.max_globals_bytes)
                }
                PAYLOAD_FILE => r.max_payload_bytes,
                _ => backup_domain::ResourceLimits::ciphertext_limit(r.max_payload_bytes),
            };
            ensure!(file.metadata()?.len() <= cap, "RESOURCE_LIMIT");
        }
        if signed {
            ensure!(
                names
                    .iter()
                    .all(|n| ![MANIFEST_FILE, PAYLOAD_FILE, GLOBALS_FILE].contains(&n.as_str())),
                "SNAPSHOT_UNSAFE"
            );
            ensure!(
                [
                    COMPLETE_MARKER,
                    PUBLIC_FILE,
                    SIGNATURE_FILE,
                    AGE_MANIFEST_FILE,
                    AGE_PAYLOAD_FILE
                ]
                .iter()
                .all(|n| names.iter().any(|s| s == n)),
                "SNAPSHOT_UNSAFE"
            );
        }
        Ok(())
    }
    pub(crate) fn snapshot_listing(&self) -> Result<StoreListing> {
        let mut listing = StoreListing {
            signed: Vec::new(),
            unsigned: Vec::new(),
            rollback_warnings: Vec::new(),
            rollback_unknown: Vec::new(),
        };
        let inventory = self.completion_inventory()?;
        for id in self.snapshot_catalogue()? {
            if inventory
                .as_ref()
                .map(|i| i.artifact(id))
                .transpose()?
                .flatten()
                .is_some_and(|r| r.state.is_deletion())
            {
                continue;
            }
            let dir = self.artifact_dir(id);
            if !dir.join(COMPLETE_MARKER).try_exists()? {
                continue;
            }
            if dir.join(PUBLIC_FILE).try_exists()? {
                let header = self.read_header(&dir)?;
                ensure!(header.backup_id == id, "SNAPSHOT_UNSAFE");
                listing.signed.push(header);
            } else {
                listing.unsigned.push(id);
            }
        }
        listing.signed.sort_by_key(|h| h.backup_id);
        listing.unsigned.sort();
        self.list_rollback(&mut listing)?;
        Ok(listing)
    }
}
