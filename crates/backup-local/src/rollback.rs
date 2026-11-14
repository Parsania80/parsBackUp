//! Local history reads do not authenticate discovery or mutate read-only operation paths.
use crate::{LocalStore, SignedArtifact, layout::INVENTORY_FILE};
use anyhow::{Result, ensure};
use backup_application::StoreListing;
use backup_domain::{CompletionMark, RollbackWarning};
use backup_inventory::{Inventory, State};
use std::{fs, io::ErrorKind};

impl LocalStore {
    pub(crate) fn completion_inventory(&self) -> Result<Option<Inventory>> {
        let path = self.root.join(INVENTORY_FILE);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(Some(Inventory::open_read_only_bound(&path)?)),
        }
    }

    pub(crate) fn read_completion(
        &self,
        artifact: &SignedArtifact,
    ) -> Result<Option<CompletionMark>> {
        self.completion_inventory()?
            .map(|inventory| {
                inventory.completion_mark(
                    &artifact.manifest.source_fingerprint,
                    &artifact.manifest.signer_id,
                )
            })
            .transpose()
            .map(Option::flatten)
    }

    pub(crate) fn record_completion(
        &self,
        artifact: &SignedArtifact,
    ) -> Result<Option<CompletionMark>> {
        let Some(inventory) = self.completion_inventory()? else {
            return Ok(None);
        };
        ensure!(
            inventory.estate().source_fingerprint == artifact.manifest.source_fingerprint,
            "authenticated source conflicts with completion estate"
        );
        let estate = inventory.estate().clone();
        drop(inventory);
        let inventory = Inventory::open_existing_upgrade(&self.root.join(INVENTORY_FILE), &estate)?;
        inventory.ensure_readable(artifact.header.backup_id)?;
        let mark = CompletionMark {
            artifact_id: artifact.header.backup_id,
            completed_at_utc: artifact.manifest.completed_at_utc.clone(),
        };
        Ok(Some(inventory.observe_completion(
            &artifact.manifest.source_fingerprint,
            &artifact.manifest.signer_id,
            &mark,
        )?))
    }

    pub(crate) fn list_rollback(&self, listing: &mut StoreListing) -> Result<()> {
        let inventory = self.completion_inventory()?;
        for header in &listing.signed {
            let known = (|| -> Result<Option<(String, CompletionMark)>> {
                let Some(inventory) = &inventory else {
                    return Ok(None);
                };
                let Some(row) = inventory.artifact(header.backup_id)? else {
                    return Ok(None);
                };
                if row.state != State::Registered || !row.matches_header(header) {
                    return Ok(None);
                }
                let Some(completed) = row.completed_at_utc else {
                    return Ok(None);
                };
                Ok(inventory
                    .completion_mark(&row.source_fingerprint, &header.signer_id)?
                    .map(|mark| (completed, mark)))
            })()?;
            match known {
                Some((completed, high_water)) if completed < high_water.completed_at_utc => {
                    listing.rollback_warnings.push(RollbackWarning {
                        artifact_id: header.backup_id,
                        source_fingerprint: inventory
                            .as_ref()
                            .unwrap()
                            .estate()
                            .source_fingerprint
                            .clone(),
                        signer_id: header.signer_id.clone(),
                        completed_at_utc: completed,
                        high_water,
                    });
                }
                None => listing.rollback_unknown.push(header.backup_id),
                _ => {}
            }
        }
        Ok(())
    }
}
