//! The local filesystem store, and the one place in this workspace that touches key
//! material. It decides whether a staged payload is written as plaintext or as an age
//! stream, so the application layer can stay crypto-free and the dump tool never learns
//! a filename: `pg_dump` writes to a pipe, and this crate owns both ends of it.
//!
//! Plaintext therefore exists in exactly two places — a staging directory that becomes
//! the artifact, and a mode-0700 `scratch/` view that exists only while a decrypt is
//! being read. Neither is ever the published artifact tree.

mod layout;

use anyhow::{Context, Result, bail};
use backup_application::{
    ArtifactHandle, ArtifactStore, PayloadSink, PlaintextView, StageHandle, StagedBytes,
    WriteOptions,
};
use backup_crypto::keystore::{IdentityProvider, KeyFile, KeyRole};
use backup_crypto::stream::{EncryptSink, decrypt, decrypt_with_limit};
use backup_domain::{AGE_FORMAT, DevelopmentManifest, RestorePlan};
use layout::{
    AGE_GLOBALS_FILE, AGE_PAYLOAD_FILE, ARTIFACTS_DIR, COMPLETE_MARKER, GLOBALS_FILE,
    MANIFEST_FILE, MANIFEST_TMP_FILE, MAX_MANIFEST_BYTES, MAX_PLAN_BYTES, PAYLOAD_FILE,
    PLAN_SUFFIX, PLANS_DIR, SCRATCH_DIR, STAGING_DIR,
};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

/// The two key files an encrypted store seals with and opens with.
pub struct StoreKeys {
    identity: KeyFile,
    recipient: KeyFile,
}

pub struct LocalStore {
    root: PathBuf,
    /// `None` keeps every artifact plaintext, exactly as the tool did before the
    /// recipient stanza existed: encryption is a property of the configured store.
    keys: Option<StoreKeys>,
}

pub struct LocalStage {
    id: Uuid,
    dir: PathBuf,
    payload: PathBuf,
    globals: Option<PathBuf>,
    /// Set by a finished sink. A stream that was opened but never completed has
    /// written an age header and nothing else, which is not a backup.
    sealed_payload: AtomicBool,
    sealed_globals: AtomicBool,
}

pub struct LocalArtifact {
    manifest: DevelopmentManifest,
    payload: PathBuf,
    globals: Option<PathBuf>,
}

/// A plaintext file a PostgreSQL client tool may be pointed at.
///
/// When the artifact was an age stream, the plaintext is a temporary copy in the
/// store's scratch directory, and this type owns it: dropping the view removes the
/// directory, so decrypted bytes do not outlive the operation that needed them.
pub struct LocalPlaintext {
    path: PathBuf,
    scratch: Option<PathBuf>,
}

/// Which half of a stage a sink writes.
#[derive(Clone, Copy)]
enum Target {
    Payload,
    Globals,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Payload => "payload file",
            Self::Globals => "globals file",
        }
    }
}

enum Writer {
    /// Plaintext mode: the bytes land in the file exactly as they were written.
    Plain { file: File, written: u64 },
    /// Encrypted mode: age authenticates every chunk on its way into the file.
    Age(EncryptSink<File>),
}

struct StageSink<'a> {
    /// `None` only after the sink has been finished; a sealed stream cannot be reopened.
    writer: Option<Writer>,
    target: Target,
    stage: &'a LocalStage,
}

impl Drop for LocalStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

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

impl Write for StageSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.writer.as_mut() {
            None => Err(io::Error::other("staged stream was already finished")),
            Some(Writer::Plain { file, written }) => {
                let n = file.write(buf)?;
                *written += n as u64;
                Ok(n)
            }
            Some(Writer::Age(stream)) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.writer.as_mut() {
            None => Err(io::Error::other("staged stream was already finished")),
            Some(Writer::Plain { file, .. }) => file.flush(),
            Some(Writer::Age(stream)) => stream.flush(),
        }
    }
}

impl PayloadSink for StageSink<'_> {
    fn finish(&mut self) -> Result<StagedBytes> {
        let writer = self
            .writer
            .take()
            .context("staged stream was already finished")?;
        let staged = match writer {
            Writer::Plain { mut file, written } => {
                file.flush()?;
                file.sync_all()?;
                StagedBytes {
                    plaintext_bytes: written,
                    recipient_suite: None,
                }
            }
            Writer::Age(stream) => {
                let (file, outcome) = stream.finish()?;
                file.sync_all()?;
                StagedBytes {
                    plaintext_bytes: outcome.plaintext_bytes,
                    recipient_suite: Some(outcome.suite),
                }
            }
        };
        match self.target {
            Target::Payload => self.stage.sealed_payload.store(true, Ordering::Relaxed),
            Target::Globals => self.stage.sealed_globals.store(true, Ordering::Relaxed),
        }
        Ok(staged)
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
        let identity = KeyFile::load(identity_file, KeyRole::Identity)?;
        let recipient = KeyFile::load(recipient_file, KeyRole::Recipient)?;
        if recipient.recipient() != identity.recipient() {
            bail!(
                "recipient key file {} is not the recipient of identity key file {}",
                recipient.path().display(),
                identity.path().display()
            );
        }
        Self::open(
            root,
            Some(StoreKeys {
                identity,
                recipient,
            }),
        )
    }

    fn open(root: PathBuf, keys: Option<StoreKeys>) -> Result<Self> {
        if !root.is_absolute() {
            bail!("storage root must be absolute");
        }
        fs::create_dir_all(&root).context("create storage root")?;
        ensure_real_dir(&root)?;
        let mut dirs = vec![STAGING_DIR, ARTIFACTS_DIR, PLANS_DIR];
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
        // A restart here implies any previous process died mid-dump; staged
        // data was never published and must not linger (single-owner store).
        for name in [STAGING_DIR, SCRATCH_DIR] {
            let dir = root.join(name);
            if !dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    fs::remove_dir_all(&path).with_context(|| {
                        format!("remove stale {} entry {}", name, path.display())
                    })?;
                }
            }
        }
        Ok(Self { root, keys })
    }

    fn encrypted(&self) -> bool {
        self.keys.is_some()
    }

    fn artifact_dir(&self, id: Uuid) -> PathBuf {
        self.root.join(ARTIFACTS_DIR).join(id.to_string())
    }

    fn plan_path(&self, id: Uuid) -> PathBuf {
        self.root.join(PLANS_DIR).join(format!("{id}{PLAN_SUFFIX}"))
    }

    fn stage_sink<'a>(
        &'a self,
        stage: &'a LocalStage,
        target: Target,
    ) -> Result<Box<dyn PayloadSink + 'a>> {
        let path = match target {
            Target::Payload => stage.payload.clone(),
            Target::Globals => stage
                .globals
                .clone()
                .with_context(|| format!("stage has no {}", target.name()))?,
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create staged {}", target.name()))?;
        let writer = match &self.keys {
            None => Writer::Plain { file, written: 0 },
            Some(keys) => Writer::Age(
                EncryptSink::new(keys.recipient.recipient(), file)
                    .with_context(|| format!("open {} stream", target.name()))?,
            ),
        };
        Ok(Box::new(StageSink {
            writer: Some(writer),
            target,
            stage,
        }))
    }

    /// Decrypts an age file into a fresh scratch directory.
    ///
    /// `max_plaintext_bytes` is the size the manifest recorded for this payload when it
    /// has one; `None` applies the format-wide cap instead.
    fn decrypt_to_scratch(
        &self,
        ciphertext: &Path,
        name: &str,
        max_plaintext_bytes: Option<u64>,
    ) -> Result<LocalPlaintext> {
        let keys = self
            .keys
            .as_ref()
            .context("artifact is encrypted but no key files are configured")?;
        ensure_regular_file(ciphertext)?;
        let scratch = self.root.join(SCRATCH_DIR).join(Uuid::new_v4().to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&scratch)
            .context("create private scratch directory")?;
        let path = scratch.join(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context("create private scratch file")?;
        let ciphertext = File::open(ciphertext).context("open encrypted payload")?;
        match max_plaintext_bytes {
            Some(limit) => decrypt_with_limit(keys.identity.identity()?, ciphertext, file, limit)?,
            None => decrypt(keys.identity.identity()?, ciphertext, file)?,
        };
        Ok(LocalPlaintext {
            path,
            scratch: Some(scratch),
        })
    }

    fn load_artifact(&self, id: Uuid) -> Result<LocalArtifact> {
        let dir = self.artifact_dir(id);
        ensure_real_dir(&dir)?;
        let marker = dir.join(COMPLETE_MARKER);
        ensure_regular_file(&marker)?;
        let manifest_path = dir.join(MANIFEST_FILE);
        ensure_regular_file(&manifest_path)?;
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
        // The manifest names the files: an artifact's format decides whether its
        // payload is plaintext or ciphertext, not the store reading it.
        let (payload_name, globals_name) = if manifest.format == AGE_FORMAT {
            (AGE_PAYLOAD_FILE, AGE_GLOBALS_FILE)
        } else {
            (PAYLOAD_FILE, GLOBALS_FILE)
        };
        // A file of the other kind sitting beside a published artifact means either a
        // tampered manifest or a dump that leaked plaintext, so it is refused rather
        // than ignored.
        let (unused_payload, unused_globals) = if manifest.format == AGE_FORMAT {
            (PAYLOAD_FILE, GLOBALS_FILE)
        } else {
            (AGE_PAYLOAD_FILE, AGE_GLOBALS_FILE)
        };
        for name in [unused_payload, unused_globals] {
            if dir.join(name).symlink_metadata().is_ok() {
                bail!("artifact contains a {name} file its manifest does not use");
            }
        }
        let payload_path = dir.join(payload_name);
        ensure_regular_file(&payload_path)?;
        let (size, digest) = hash_file(&payload_path)?;
        if size != manifest.size_bytes || digest != manifest.sha256 {
            bail!("payload checksum or size mismatch");
        }
        let globals_path = dir.join(globals_name);
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
    type Plaintext = LocalPlaintext;

    fn begin(&self, id: Uuid, options: &WriteOptions) -> Result<Self::Stage> {
        let dir = self.root.join(STAGING_DIR).join(id.to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .context("create private staging directory")?;
        // The payload file is created by its sink, not here: in encrypted mode the
        // first bytes written are an age header, and an empty stage must not look like
        // a file an operator could publish.
        let (payload_name, globals_name) = if self.encrypted() {
            (AGE_PAYLOAD_FILE, AGE_GLOBALS_FILE)
        } else {
            (PAYLOAD_FILE, GLOBALS_FILE)
        };
        let payload = dir.join(payload_name);
        let globals = match options.with_globals {
            true => Some(dir.join(globals_name)),
            false => None,
        };
        Ok(LocalStage {
            id,
            dir,
            payload,
            globals,
            sealed_payload: AtomicBool::new(false),
            sealed_globals: AtomicBool::new(false),
        })
    }

    fn payload_sink<'a>(&'a self, stage: &'a LocalStage) -> Result<Box<dyn PayloadSink + 'a>> {
        self.stage_sink(stage, Target::Payload)
    }

    fn globals_sink<'a>(&'a self, stage: &'a LocalStage) -> Result<Box<dyn PayloadSink + 'a>> {
        self.stage_sink(stage, Target::Globals)
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
        if !stage.sealed_payload.load(Ordering::Relaxed) {
            bail!("payload stream was never finished; staged artifact was not published");
        }
        if manifest.security_globals && !stage.sealed_globals.load(Ordering::Relaxed) {
            bail!("globals stream was never finished; staged artifact was not published");
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
        let tmp_manifest = stage.dir.join(MANIFEST_TMP_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_manifest)?;
        serde_json::to_writer_pretty(&mut file, manifest)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp_manifest, stage.dir.join(MANIFEST_FILE))?;
        File::open(&stage.dir)?.sync_all()?;
        let final_dir = self.artifact_dir(stage.id);
        if final_dir.exists() {
            bail!("artifact ID already exists");
        }
        fs::rename(&stage.dir, &final_dir).context("publish staged artifact")?;
        File::open(self.root.join(ARTIFACTS_DIR))?.sync_all()?;
        let marker = final_dir.join(COMPLETE_MARKER);
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
        for entry in fs::read_dir(self.root.join(ARTIFACTS_DIR))? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(&name) else {
                continue;
            };
            if !entry.path().join(COMPLETE_MARKER).exists() {
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

    fn plaintext_payload(&self, artifact: &Self::Artifact) -> Result<Self::Plaintext> {
        if artifact.manifest.format != AGE_FORMAT {
            return Ok(LocalPlaintext {
                path: artifact.payload.clone(),
                scratch: None,
            });
        }
        // The recorded plaintext size is the bound: a ciphertext that inflates past what
        // the manifest promised is refused while streaming, not after allocation.
        let limit = artifact
            .manifest
            .payload_plaintext_bytes
            .context("encrypted artifact records no plaintext payload size")?;
        self.decrypt_to_scratch(&artifact.payload, PAYLOAD_FILE, Some(limit))
    }

    fn plaintext_staged_payload(&self, stage: &Self::Stage) -> Result<Self::Plaintext> {
        if !self.encrypted() {
            ensure_regular_file(&stage.payload)?;
            return Ok(LocalPlaintext {
                path: stage.payload.clone(),
                scratch: None,
            });
        }
        // A stage has no manifest yet, so only the format-wide cap applies.
        self.decrypt_to_scratch(&stage.payload, PAYLOAD_FILE, None)
    }

    fn plaintext_globals(&self, artifact: &Self::Artifact) -> Result<Self::Plaintext> {
        let path = artifact
            .globals
            .as_ref()
            .context("artifact has no globals file")?;
        if artifact.manifest.format != AGE_FORMAT {
            return Ok(LocalPlaintext {
                path: path.clone(),
                scratch: None,
            });
        }
        // Globals carry no recorded plaintext size, so the cap here is the format's own;
        // a role dump past it is refused rather than trusted.
        self.decrypt_to_scratch(path, GLOBALS_FILE, None)
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
            || manifest.format != artifact.manifest().format
        {
            bail!("replacement manifest must not alter payload bindings");
        }
        manifest.validate_shape()?;
        let dir = self.artifact_dir(manifest.id);
        let tmp = dir.join(MANIFEST_TMP_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        serde_json::to_writer_pretty(&mut file, manifest)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp, dir.join(MANIFEST_FILE))?;
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
        File::open(self.root.join(PLANS_DIR))?.sync_all()?;
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
    use backup_crypto::protocol::SUITE_HYBRID;
    use backup_domain::{DEV_FORMAT, PLAN_FORMAT, RestoreSecurityPolicy};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("backupctl-store-test-{}", Uuid::new_v4()))
    }

    fn temp_keys() -> PathBuf {
        std::env::temp_dir().join(format!("backupctl-keys-test-{}", Uuid::new_v4()))
    }

    /// Writes a key pair outside any storage root and returns both paths.
    fn key_pair(dir: &Path) -> (PathBuf, PathBuf) {
        fs::create_dir_all(dir).unwrap();
        let identity = dir.join("identity.key");
        let recipient = dir.join("recipient.key");
        let key = KeyFile::create_identity(&identity).unwrap();
        KeyFile::write_recipient(&recipient, key.recipient()).unwrap();
        (identity, recipient)
    }

    /// Streams bytes through the store's own sinks, the only way a stage becomes
    /// publishable.
    fn stage_bytes(store: &LocalStore, stage: &LocalStage, payload: &[u8], globals: Option<&[u8]>) {
        let mut sink = store.payload_sink(stage).unwrap();
        sink.write_all(payload).unwrap();
        sink.finish().unwrap();
        if let Some(globals) = globals {
            let mut globals_sink = store.globals_sink(stage).unwrap();
            globals_sink.write_all(globals).unwrap();
            globals_sink.finish().unwrap();
        }
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
            scope: None,
            toc_sha256: None,
            recipient_suite: None,
            payload_plaintext_bytes: None,
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
        stage_bytes(&store, &stage, b"synthetic archive bytes", None);
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

    /// A stage whose stream was opened but never finished holds an age header and no
    /// final chunk: it authenticates nothing, so it must not be publishable.
    #[test]
    fn an_unfinished_stream_is_not_publishable() {
        let root = temp_root();
        let keys = temp_keys();
        let (identity, recipient) = key_pair(&keys);
        let store = LocalStore::with_keys(root.clone(), &identity, &recipient).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(
                id,
                &WriteOptions {
                    with_globals: false,
                },
            )
            .unwrap();
        let mut sink = store.payload_sink(&stage).unwrap();
        sink.write_all(&[7_u8; 200_000]).unwrap();
        drop(sink);
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        let mut m = manifest(id, size_bytes, sha256);
        m.format = AGE_FORMAT.to_string();
        m.recipient_suite = Some(SUITE_HYBRID.to_string());
        m.payload_plaintext_bytes = Some(200_000);
        let error = store.publish(stage, &m).unwrap_err().to_string();
        assert!(error.contains("never finished"), "{error}");
        assert!(store.list().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(keys).unwrap();
    }

    #[test]
    fn an_encrypted_stage_publishes_ciphertext_and_no_plaintext() {
        let root = temp_root();
        let keys = temp_keys();
        let (identity, recipient) = key_pair(&keys);
        let store = LocalStore::with_keys(root.clone(), &identity, &recipient).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(id, &WriteOptions { with_globals: true })
            .unwrap();
        assert_eq!(stage.payload_path().file_name().unwrap(), "payload.age");
        let plaintext = b"synthetic archive bytes".to_vec().repeat(4096);
        let globals = b"CREATE ROLE backupctl_fixture_alice;";
        // Both sinks borrow the stage to seal it, so they end before publication.
        let (staged, globals_staged) = {
            let mut sink = store.payload_sink(&stage).unwrap();
            sink.write_all(&plaintext).unwrap();
            let staged = sink.finish().unwrap();
            let mut globals_sink = store.globals_sink(&stage).unwrap();
            globals_sink.write_all(globals).unwrap();
            (staged, globals_sink.finish().unwrap())
        };
        assert_eq!(staged.recipient_suite, Some(SUITE_HYBRID));
        assert_eq!(staged.plaintext_bytes, plaintext.len() as u64);
        assert_eq!(globals_staged.recipient_suite, Some(SUITE_HYBRID));
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        assert_ne!(
            size_bytes, staged.plaintext_bytes,
            "age does not compress, so the published size is not the plaintext size the \
             manifest records"
        );
        let (gsize, gsha) = store.measure_globals(&stage).unwrap();
        let mut m = manifest(id, size_bytes, sha256);
        m.format = AGE_FORMAT.to_string();
        m.recipient_suite = Some(SUITE_HYBRID.to_string());
        m.payload_plaintext_bytes = Some(staged.plaintext_bytes);
        m.security_globals = true;
        m.globals_size_bytes = Some(gsize);
        m.globals_sha256 = Some(gsha);
        store.publish(stage, &m).unwrap();
        let dir = root.join("artifacts").join(id.to_string());
        assert!(dir.join("payload.age").exists() && dir.join("globals.age").exists());
        assert!(!dir.join("payload.dump").exists() && !dir.join("globals.sql").exists());
        let ciphertext = fs::read(dir.join("payload.age")).unwrap();
        let needle = b"synthetic archive bytes";
        assert!(
            !ciphertext
                .windows(needle.len())
                .any(|window| window == needle),
            "published payload contains plaintext"
        );
        // Decryption lands in scratch and leaves nothing behind once the view drops.
        let artifact = store.open(id).unwrap();
        let view = store.plaintext_payload(&artifact).unwrap();
        assert_eq!(fs::read(view.path()).unwrap(), plaintext);
        let scratch = view.path().parent().unwrap().to_path_buf();
        assert!(scratch.starts_with(root.join("scratch")));
        drop(view);
        assert!(!scratch.exists());
        let globals_view = store.plaintext_globals(&artifact).unwrap();
        assert_eq!(fs::read(globals_view.path()).unwrap(), globals);
        // A stray plaintext sibling is refused, and a store without the identity
        // cannot be handed the artifact at all.
        drop(globals_view);
        fs::write(dir.join("payload.dump"), b"leaked").unwrap();
        assert!(store.open(id).is_err());
        fs::remove_file(dir.join("payload.dump")).unwrap();
        let keyless = LocalStore::new(root.clone()).unwrap();
        let artifact = keyless.open(id).unwrap();
        assert!(keyless.plaintext_payload(&artifact).is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(keys).unwrap();
    }

    /// Encryption is configured, not assumed: a store built without key files keeps
    /// writing the plaintext layout every earlier milestone expects.
    #[test]
    fn a_keyless_store_writes_the_plaintext_layout() {
        let root = temp_root();
        let store = LocalStore::new(root.clone()).unwrap();
        let id = Uuid::new_v4();
        let stage = store
            .begin(id, &WriteOptions { with_globals: true })
            .unwrap();
        assert_eq!(stage.payload_path().file_name().unwrap(), "payload.dump");
        stage_bytes(
            &store,
            &stage,
            b"synthetic archive bytes",
            Some(b"CREATE ROLE backupctl_fixture_alice;"),
        );
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        let (gsize, gsha) = store.measure_globals(&stage).unwrap();
        let mut m = manifest(id, size_bytes, sha256);
        m.security_globals = true;
        m.globals_size_bytes = Some(gsize);
        m.globals_sha256 = Some(gsha);
        store.publish(stage, &m).unwrap();
        assert!(!root.join("scratch").exists());
        let artifact = store.open(id).unwrap();
        assert!(artifact.payload_path().ends_with("payload.dump"));
        let view = store.plaintext_payload(&artifact).unwrap();
        assert_eq!(fs::read(view.path()).unwrap(), b"synthetic archive bytes");
        fs::remove_dir_all(root).unwrap();
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
        stage_bytes(
            &store,
            &stage,
            b"synthetic archive bytes",
            Some(b"CREATE ROLE backupctl_fixture_alice;"),
        );
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
        stage_bytes(&store, &stage, b"synthetic archive bytes", None);
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
            sections: backup_domain::RestoreSections::full(),
            artifact_scope: None,
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
