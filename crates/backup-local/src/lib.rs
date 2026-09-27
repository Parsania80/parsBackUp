use anyhow::{Context, Result, bail};
use backup_application::{ArtifactHandle, ArtifactStore, StageHandle, WriteOptions};
use backup_domain::{DevelopmentManifest, RestorePlan};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_PLAN_BYTES: u64 = 64 * 1024;

pub struct LocalStore {
    root: PathBuf,
}

pub struct LocalStage {
    id: Uuid,
    dir: PathBuf,
    payload: PathBuf,
    globals: Option<PathBuf>,
}

pub struct LocalArtifact {
    manifest: DevelopmentManifest,
    payload: PathBuf,
    globals: Option<PathBuf>,
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

    fn globals_path(&self) -> Option<&Path> {
        self.globals.as_deref()
    }
}

impl ArtifactHandle for LocalArtifact {
    fn id(&self) -> Uuid {
        self.manifest.id
    }

    fn manifest(&self) -> &DevelopmentManifest {
        &self.manifest
    }

    fn payload_path(&self) -> &Path {
        &self.payload
    }

    fn globals_path(&self) -> Option<&Path> {
        self.globals.as_deref()
    }
}

impl LocalStore {
    pub fn new(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            bail!("storage root must be absolute");
        }
        fs::create_dir_all(&root).context("create storage root")?;
        ensure_real_dir(&root)?;
        for name in ["staging", "artifacts", "plans"] {
            let dir = root.join(name);
            if !dir.exists() {
                DirBuilder::new().mode(0o700).create(&dir)?;
            }
            ensure_real_dir(&dir)?;
        }
        // A restart here implies any previous process died mid-dump; staged
        // data was never published and must not linger (single-owner store).
        let staging = root.join("staging");
        for entry in fs::read_dir(&staging)? {
            let path = entry?.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)
                    .with_context(|| format!("remove stale stage {}", path.display()))?;
            }
        }
        Ok(Self { root })
    }

    fn artifact_dir(&self, id: Uuid) -> PathBuf {
        self.root.join("artifacts").join(id.to_string())
    }

    fn plan_path(&self, id: Uuid) -> PathBuf {
        self.root.join("plans").join(format!("{id}.json"))
    }

    fn load_artifact(&self, id: Uuid) -> Result<LocalArtifact> {
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
        let globals_path = dir.join("globals.sql");
        let globals = if manifest.security_globals {
            ensure_regular_file(&globals_path)?;
            let (gsize, gdigest) = hash_file(&globals_path)?;
            if manifest.globals_size_bytes != Some(gsize)
                || manifest.globals_sha256.as_deref() != Some(&gdigest[..])
            {
                bail!("globals checksum or size mismatch");
            }
            Some(globals_path)
        } else {
            if globals_path.symlink_metadata().is_ok() {
                bail!("artifact contains a globals file not declared by its manifest");
            }
            None
        };
        Ok(LocalArtifact {
            manifest,
            payload: payload_path,
            globals,
        })
    }
}

impl ArtifactStore for LocalStore {
    type Stage = LocalStage;
    type Artifact = LocalArtifact;

    fn begin(&self, id: Uuid, options: &WriteOptions) -> Result<Self::Stage> {
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
        let globals = if options.with_globals {
            let path = dir.join("globals.sql");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .context("create private globals file")?;
            Some(path)
        } else {
            None
        };
        Ok(LocalStage {
            id,
            dir,
            payload,
            globals,
        })
    }

    fn measure(&self, stage: &Self::Stage) -> Result<(u64, String)> {
        let (size, hash) = hash_file(&stage.payload)?;
        if size == 0 {
            bail!("pg_dump produced an empty archive");
        }
        Ok((size, hash))
    }

    fn measure_globals(&self, stage: &Self::Stage) -> Result<(u64, String)> {
        let path = stage
            .globals
            .as_ref()
            .context("stage has no globals file")?;
        let (size, hash) = hash_file(path)?;
        if size == 0 {
            bail!("pg_dumpall produced an empty globals file");
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
        if manifest.security_globals {
            let (gsize, gdigest) = self.measure_globals(&stage)?;
            if manifest.globals_size_bytes != Some(gsize)
                || manifest.globals_sha256.as_deref() != Some(gdigest.as_str())
            {
                bail!("staged globals file changed before publication");
            }
            File::open(stage.globals.as_ref().expect("checked above"))?.sync_all()?;
        }
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
                self.load_artifact(id)
                    .with_context(|| format!("invalid artifact {id}"))?
                    .manifest,
            );
        }
        manifests.sort_by_key(|m| std::cmp::Reverse(m.created_unix_ms));
        Ok(manifests)
    }

    fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest> {
        Ok(self.load_artifact(id)?.manifest)
    }

    fn open(&self, id: Uuid) -> Result<Self::Artifact> {
        self.load_artifact(id)
    }

    fn rewrite_manifest(
        &self,
        artifact: &Self::Artifact,
        manifest: &DevelopmentManifest,
    ) -> Result<()> {
        if artifact.id() != manifest.id {
            bail!("replacement manifest ID mismatch");
        }
        if manifest.sha256 != artifact.manifest().sha256
            || manifest.size_bytes != artifact.manifest().size_bytes
        {
            bail!("replacement manifest must not alter payload bindings");
        }
        manifest.validate_shape()?;
        let dir = self.artifact_dir(manifest.id);
        let tmp = dir.join("manifest.json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        serde_json::to_writer_pretty(&mut file, manifest)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp, dir.join("manifest.json"))?;
        File::open(&dir)?.sync_all()?;
        Ok(())
    }

    fn save_plan(&self, plan: &RestorePlan) -> Result<()> {
        let path = self.plan_path(plan.id);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        serde_json::to_writer_pretty(&mut file, plan)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        File::open(self.root.join("plans"))?.sync_all()?;
        Ok(())
    }

    fn load_plan(&self, id: Uuid) -> Result<Option<RestorePlan>> {
        let path = self.plan_path(id);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    bail!("restore plan must be a regular non-symlink file");
                }
                let mut bytes = Vec::new();
                File::open(&path)?
                    .take(MAX_PLAN_BYTES + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_PLAN_BYTES {
                    bail!("restore plan exceeds size limit");
                }
                let plan: RestorePlan = serde_json::from_slice(&bytes)?;
                plan.validate(backup_application::now_unix_ms()?)?;
                Ok(Some(plan))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("inspect restore plan"),
        }
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
    use backup_domain::{DEV_FORMAT, PLAN_FORMAT, RestoreSecurityPolicy};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("backupctl-store-test-{}", Uuid::new_v4()))
    }

    fn manifest(id: Uuid, size_bytes: u64, sha256: String) -> DevelopmentManifest {
        DevelopmentManifest {
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
            security_globals: false,
            globals_sha256: None,
            globals_size_bytes: None,
            verification_level: None,
            verified_unix_ms: None,
        }
    }

    #[test]
    fn publication_requires_marker_and_matching_payload() {
        let root = temp_root();
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(
                id,
                &WriteOptions {
                    with_globals: false,
                },
            )
            .unwrap();
        fs::write(stage.payload_path(), b"synthetic archive bytes").unwrap();
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        store
            .publish(stage, &manifest(id, size_bytes, sha256))
            .unwrap();
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
        let root = temp_root();
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(
                id,
                &WriteOptions {
                    with_globals: false,
                },
            )
            .unwrap();
        drop(stage);
        assert!(store.list().unwrap().is_empty());
        assert!(!root.join("staging").join(id.to_string()).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn globals_file_is_bound_and_tamper_checked() {
        let root = temp_root();
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(id, &WriteOptions { with_globals: true })
            .unwrap();
        fs::write(stage.payload_path(), b"synthetic archive bytes").unwrap();
        fs::write(
            stage.globals_path().unwrap(),
            b"CREATE ROLE backupctl_fixture_alice;",
        )
        .unwrap();
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        let (gsize, gsha) = store.measure_globals(&stage).unwrap();
        let mut m = manifest(id, size_bytes, sha256);
        m.security_globals = true;
        m.globals_size_bytes = Some(gsize);
        m.globals_sha256 = Some(gsha);
        store.publish(stage, &m).unwrap();
        let artifact = store.open(id).unwrap();
        assert!(artifact.globals_path().is_some());
        // Tamper with the globals file: open must fail.
        fs::write(
            root.join("artifacts")
                .join(id.to_string())
                .join("globals.sql"),
            b"DROP ROLE everyone;",
        )
        .unwrap();
        assert!(store.open(id).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn undeclared_globals_file_is_rejected() {
        let root = temp_root();
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(
                id,
                &WriteOptions {
                    with_globals: false,
                },
            )
            .unwrap();
        fs::write(stage.payload_path(), b"synthetic archive bytes").unwrap();
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        store
            .publish(stage, &manifest(id, size_bytes, sha256))
            .unwrap();
        fs::write(
            root.join("artifacts")
                .join(id.to_string())
                .join("globals.sql"),
            b"CREATE ROLE intruder;",
        )
        .unwrap();
        assert!(store.open(id).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plans_round_trip_and_expiry_is_enforced_on_load() {
        let root = temp_root();
        let store = LocalStore::new(root.clone()).unwrap();
        let now = backup_application::now_unix_ms().unwrap();
        let plan = RestorePlan {
            format: PLAN_FORMAT.to_string(),
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            artifact_database: "backupctl_fixture_m1".to_string(),
            source_major: 16,
            client_version: "pg_restore (PostgreSQL) 16.4".to_string(),
            target_database: "backupctl_fixture_dr".to_string(),
            security: RestoreSecurityPolicy::dr_full(),
            created_unix_ms: now,
            expires_unix_ms: now + 900_000,
        };
        store.save_plan(&plan).unwrap();
        let loaded = store.load_plan(plan.id).unwrap().unwrap();
        assert_eq!(loaded.digest(), plan.digest());
        assert!(store.load_plan(Uuid::new_v4()).unwrap().is_none());
        // A rewritten (expired or edited) plan fails validation on load.
        let expired = RestorePlan {
            created_unix_ms: 1,
            expires_unix_ms: 2,
            ..plan.clone()
        };
        let path = root.join("plans").join(format!("{}.json", plan.id));
        fs::write(&path, serde_json::to_vec_pretty(&expired).unwrap()).unwrap();
        assert!(store.load_plan(plan.id).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
