use crate::LocalStore;
use crate::layout::INVENTORY_FILE;
use anyhow::{Context, Result};
use backup_domain::{ArtifactManifest, PublicHeader, profile_fingerprint};
use backup_inventory::{ArtifactRow, Estate, Shape, State};

impl LocalStore {
    /// Adds the just-published artifact to the store's inventory index.
    ///
    /// Every discovery field is read from the [`PublicHeader`] this command sealed, because that
    /// is the record a keyless reader will rebuild the index from later: a row stating anything
    /// the file does not would make an honest rebuild look like a corrupt one. Only the profile
    /// and the completion time come from the sealed manifest, and only because the writer host
    /// holds the key that just read it — the whole reason those two columns are nullable.
    ///
    /// Runs after `complete`, so a failure here cannot un-publish a backup. ADR 0003 makes the
    /// files authoritative for existence and the inventory an index over them, which means this
    /// is exactly the state the reconcile pass was designed for and the one retention can never
    /// act on: the artifact is reported as unregistered, never deleted as an unknown.
    pub(crate) fn record_published(
        &self,
        manifest: &ArtifactManifest,
        header: &PublicHeader,
    ) -> Result<()> {
        let estate = Estate::new(manifest.source_fingerprint.clone())?;
        let path = self.root.join(INVENTORY_FILE);
        let inventory = backup_inventory::Inventory::open(&path, &estate)
            .with_context(|| format!("cannot open inventory {}", path.display()))?;
        let row = ArtifactRow {
            backup_id: header.backup_id,
            source_fingerprint: estate.source_fingerprint,
            profile_fingerprint: Some(profile_fingerprint(&manifest.profile_snapshot.name)),
            shape: Shape::V1Signed,
            signer_id: Some(header.signer_id.clone()),
            recipient_id: Some(header.recipient_id.clone()),
            payload_sha256: Some(header.payload_sha256.clone()),
            manifest_sha256: Some(header.manifest_sha256.clone()),
            recipient_suite: Some(header.recipient_suite.clone()),
            signature_suite: Some(header.signature_suite.clone()),
            payload_bytes: Some(header.payload_ciphertext_bytes),
            manifest_bytes: Some(header.manifest_ciphertext_bytes),
            completed_at_utc: Some(manifest.completed_at_utc.clone()),
            state: State::Registered,
        };
        inventory.register(&row).with_context(|| {
            format!(
                "backup {} is published and restorable; only its inventory row failed, so it is \
                 unregistered until a reconcile pass adopts it",
                header.backup_id
            )
        })?;
        Ok(())
    }
}

/// A key-free, read-only view of an existing inventory.
pub struct LocalInventory(backup_inventory::Inventory);

impl LocalInventory {
    pub fn open(root: &std::path::Path) -> Result<Self> {
        Ok(Self(
            backup_inventory::Inventory::open_read_only_bound(&root.join(INVENTORY_FILE))
                .context("INVENTORY_OPEN_FAILED")?,
        ))
    }
}

impl backup_application::InventoryReader for LocalInventory {
    fn jobs(&self) -> Result<Vec<backup_application::JobInfo>> {
        self.0
            .jobs()
            .map(|jobs| jobs.into_iter().map(job_info).collect())
    }

    fn job(&self, id: uuid::Uuid) -> Result<Option<backup_application::JobInfo>> {
        self.0.job(id).map(|job| job.map(job_info))
    }

    fn check(&self) -> Result<backup_application::InventoryCheck> {
        Ok(backup_application::InventoryCheck {
            schema_version: self.0.schema_version()?,
            source_fingerprint: self.0.estate().source_fingerprint.clone(),
            problems: self.0.integrity_problems()?,
        })
    }
}

fn job_info(job: backup_inventory::JobRow) -> backup_application::JobInfo {
    backup_application::JobInfo {
        job_id: job.job_id,
        backup_id: job.backup_id,
        source_fingerprint: job.source_fingerprint,
        profile_fingerprint: job.profile_fingerprint,
        state: job.state.as_str().to_owned(),
        started_at_utc: job.started_at_utc,
        updated_at_utc: job.updated_at_utc,
    }
}
