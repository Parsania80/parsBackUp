use anyhow::{Context, Result, bail};
use backup_application::{ArtifactStore, StageHandle};
use backup_domain::DevelopmentManifest;
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

pub struct LocalStore {
    root: PathBuf,
}

pub struct LocalStage {
    id: Uuid,
    dir: PathBuf,
    payload: PathBuf,
}

impl Drop for LocalStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl StageHandle for LocalStage {
    fn payload_path(&self) -> &Path {
        &self.payload
    }
}

impl LocalStore {
    pub fn new(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            bail!("storage root must be absolute");
        }
        fs::create_dir_all(&root).context("create storage root")?;
        ensure_real_dir(&root)?;
        for name in ["staging", "artifacts"] {
            let dir = root.join(name);
            if !dir.exists() {
                DirBuilder::new().mode(0o700).create(&dir)?;
            }
            ensure_real_dir(&dir)?;
        }
        Ok(Self { root })
    }

    fn artifact_dir(&self, id: Uuid) -> PathBuf {
        self.root.join("artifacts").join(id.to_string())
    }

    fn inspect_at(&self, id: Uuid) -> Result<DevelopmentManifest> {
        let dir = self.artifact_dir(id);
        ensure_real_dir(&dir)?;
        let marker = dir.join("complete");
        ensure_regular_file(&marker)?;
        let manifest_path = dir.join("manifest.json");
        ensure_regular_file(&manifest_path)?;
        let payload_path = dir.join("payload.dump");
        ensure_regular_file(&payload_path)?;
        let mut bytes = Vec::new();
        File::open(&manifest_path)?
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            bail!("manifest exceeds size limit");
        }
        let manifest: DevelopmentManifest = serde_json::from_slice(&bytes)?;
        manifest.validate_shape()?;
        if manifest.id != id {
            bail!("manifest ID does not match artifact path");
        }
        let (size, digest) = hash_file(&payload_path)?;
        if size != manifest.size_bytes || digest != manifest.sha256 {
            bail!("payload checksum or size mismatch");
        }
        Ok(manifest)
    }
}

impl ArtifactStore for LocalStore {
    type Stage = LocalStage;

    fn begin(&self, id: Uuid) -> Result<Self::Stage> {
        let dir = self.root.join("staging").join(id.to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .context("create private staging directory")?;
        let payload = dir.join("payload.dump");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&payload)
            .context("create private payload file")?;
        Ok(LocalStage { id, dir, payload })
    }

    fn measure(&self, stage: &Self::Stage) -> Result<(u64, String)> {
        let (size, hash) = hash_file(&stage.payload)?;
        if size == 0 {
            bail!("pg_dump produced an empty archive");
        }
        Ok((size, hash))
    }

    fn publish(&self, stage: Self::Stage, manifest: &DevelopmentManifest) -> Result<()> {
        if stage.id != manifest.id {
            bail!("manifest ID does not match staging ID");
        }
        manifest.validate_shape()?;
        let (size, digest) = self.measure(&stage)?;
        if size != manifest.size_bytes || digest != manifest.sha256 {
            bail!("staged payload changed before publication");
        }
        File::open(&stage.payload)?.sync_all()?;
        let tmp_manifest = stage.dir.join("manifest.json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_manifest)?;
        serde_json::to_writer_pretty(&mut file, manifest)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp_manifest, stage.dir.join("manifest.json"))?;
        File::open(&stage.dir)?.sync_all()?;
        let final_dir = self.artifact_dir(stage.id);
        if final_dir.exists() {
            bail!("artifact ID already exists");
        }
        fs::rename(&stage.dir, &final_dir).context("publish staged artifact")?;
        File::open(self.root.join("artifacts"))?.sync_all()?;
        let marker = final_dir.join("complete");
        let marker_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(marker)?;
        marker_file.sync_all()?;
        File::open(&final_dir)?.sync_all()?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<DevelopmentManifest>> {
        let mut manifests = Vec::new();
        for entry in fs::read_dir(self.root.join("artifacts"))? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(&name) else {
                continue;
            };
            if !entry.path().join("complete").exists() {
                continue;
            }
            manifests.push(
                self.inspect_at(id)
                    .with_context(|| format!("invalid artifact {id}"))?,
            );
        }
        manifests.sort_by_key(|m| std::cmp::Reverse(m.created_unix_ms));
        Ok(manifests)
    }

    fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest> {
        self.inspect_at(id)
    }
}

fn ensure_real_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("expected a non-symlink directory: {}", path.display());
    }
    Ok(())
}

fn ensure_regular_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("expected a regular non-symlink file: {}", path.display());
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        hasher.update(&buffer[..n]);
    }
    Ok((bytes, format!("{:x}", hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_domain::DEV_FORMAT;

    #[test]
    fn publication_requires_marker_and_matching_payload() {
        let root = std::env::temp_dir().join(format!("backupctl-store-test-{}", Uuid::new_v4()));
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store.begin(id).unwrap();
        fs::write(stage.payload_path(), b"synthetic archive bytes").unwrap();
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        let manifest = DevelopmentManifest {
            format: DEV_FORMAT.to_string(),
            id,
            synthetic_only: true,
            database: "backupctl_fixture_test".to_string(),
            source_major: 16,
            source_version: "160000".to_string(),
            dump_client_version: "pg_dump 16".to_string(),
            application_version: "0.1.0".to_string(),
            archive_format: "custom".to_string(),
            compression: "gzip".to_string(),
            created_unix_ms: 1,
            size_bytes,
            sha256,
            status: "complete".to_string(),
        };
        store.publish(stage, &manifest).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.inspect(id).is_ok());
        fs::write(
            root.join("artifacts")
                .join(id.to_string())
                .join("payload.dump"),
            b"changed",
        )
        .unwrap();
        assert!(store.inspect(id).is_err());
        assert!(store.list().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dropped_stage_is_never_listed() {
        let root = std::env::temp_dir().join(format!("backupctl-store-test-{}", Uuid::new_v4()));
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store.begin(id).unwrap();
        drop(stage);
        assert!(store.list().unwrap().is_empty());
        assert!(!root.join("staging").join(id.to_string()).exists());
        fs::remove_dir_all(root).unwrap();
    }
}
