//! The local filesystem store, and the one place in this workspace that touches key
//! material. It decides whether a staged payload is written as plaintext or as an age
//! stream, so the application layer can stay crypto-free and the dump tool never learns
//! a filename: `pg_dump` writes to a pipe, and this crate owns both ends of it.
//!
//! Plaintext therefore exists in exactly two places — a staging directory that becomes
//! the artifact, and a mode-0700 `scratch/` view that exists only while a decrypt is
//! being read. Neither is ever the published artifact tree.

mod layout;

#[cfg(test)]
mod fixture;
mod keys;
mod stage;
mod store;

use anyhow::{Context, Result, bail};
use backup_application::{
    ArtifactHandle, ArtifactStore, JobHandle, JobRequest, PayloadSink, PlaintextView,
    SignedArtifactHandle, SignedKeyFacts, StageHandle, StoreListing, WriteOptions,
};
use backup_crypto::HybridRecipient;
use backup_crypto::keyid::{recipient_id, signer_id};
pub use backup_crypto::keystore::KeyStatus;
use backup_crypto::keystore::{IdentityProvider, KeyFile};
use backup_crypto::protocol::{DIGEST_BYTES, HYBRID_SIGNATURE_BYTES};
use backup_crypto::signing::{SigningKeyFile, signature_tuple};
pub use backup_crypto::signing::{SigningKeyStatus, SigningRole};
use backup_crypto::stream::{EncryptSink, decrypt, decrypt_with_limit};
use backup_domain::{
    AGE_FORMAT, ArtifactManifest, DevelopmentManifest, GLOBALS_POLICY_EXPORTED,
    GLOBALS_POLICY_SKIPPED, MAX_PUBLIC_JSON_BYTES, PublicHeader, RestorePlan, profile_fingerprint,
};
use backup_inventory::{ActivityLock, ArtifactRow, Estate, Shape, State};
pub use keys::{
    generate_key_pair, generate_signing_pair, key_status, publish_recipient, publish_verifying,
    signing_key_status,
};
use layout::{
    AGE_GLOBALS_FILE, AGE_MANIFEST_FILE, AGE_PAYLOAD_FILE, ARTIFACTS_DIR, COMPLETE_MARKER,
    GLOBALS_FILE, INVENTORY_FILE, MANIFEST_FILE, MANIFEST_TMP_FILE, MAX_MANIFEST_BYTES,
    MAX_PLAN_BYTES, PAYLOAD_FILE, PLANS_DIR, PUBLIC_FILE, SCRATCH_DIR, SIGNATURE_FILE, STAGING_DIR,
};
use sha2::{Digest, Sha256};
use stage::Target;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
pub use store::Recovery;
use uuid::Uuid;

/// The key material a store holds.
///
/// `identity` is set exactly when artifacts are encrypted. The other three are separate
/// because custody differs by host rather than by command: a backup writer holds
/// `recipient` plus `signing`, while a disaster-recovery host holds `identity` plus
/// `verifying` and must be *unable* to do anything else. An artifact is written as signed v1
/// precisely when this store holds a signing key, so the shape of the store follows from the
/// keys it was configured with rather than from a flag on the call.
pub struct StoreKeys {
    identity: KeyFile,
    recipient: Option<KeyFile>,
    /// The secret half of the origin signature. Never read on a host that only verifies, and
    /// never rendered: its `Debug` names the path.
    signing: Option<SigningKeyFile>,
    /// The public half this store trusts. Verification is what a reader does with it, so a
    /// store configured without it cannot read a signed artifact at all.
    verifying: Option<SigningKeyFile>,
}

/// A v1 artifact whose signature has been checked.
///
/// Reaching one of these means both ciphertext digests were recomputed from the files on
/// disk, the signature over them verified against the configured verifying key, and only
/// then was `manifest.age` decrypted and compared field by field with `public.json`. So a
/// value read off [`SignedArtifactHandle::manifest`] is a claim about bytes written by whoever
/// holds the signing key, not about bytes an attacker chose.
pub struct SignedArtifact {
    header: PublicHeader,
    manifest: ArtifactManifest,
    payload: PathBuf,
    globals: Option<PathBuf>,
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
    /// The store-wide claim that keeps this directory under a live process. A field rather than a
    /// local, so it drops *after* [`LocalStage`]'s drop has removed the directory — see ADR 0004.
    _claim: ActivityLock,
}

/// A held job, from this store.
///
/// The newtype is not ceremony: `backup_application` owns the `JobHandle` trait and
/// `backup_inventory` owns the guard, and neither of them may write an `impl` for the other's
/// type. This crate is the one place that is allowed to know both, so the seam between a port the
/// service can call and a row the index can write is stated here rather than in either of them.
pub struct LocalJob(backup_inventory::JobGuard);

impl JobHandle for LocalJob {
    fn staged(&self) -> Result<()> {
        self.0.staged()
    }

    fn complete(&self) -> Result<()> {
        self.0.complete()
    }
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
    /// Held while `scratch` exists, and dropped after it is removed. A view of a plaintext artifact
    /// owns no directory, so it claims nothing.
    _claim: Option<ActivityLock>,
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

impl StageHandle for LocalStage {
    fn payload_path(&self) -> &Path {
        &self.payload
    }

    fn globals_path(&self) -> Option<&Path> {
        self.globals.as_deref()
    }
}

impl SignedArtifactHandle for SignedArtifact {
    /// The untrusted-by-itself discovery record this artifact was opened from, now checked
    /// against the signature and the manifest.
    fn header(&self) -> &PublicHeader {
        &self.header
    }

    /// The manifest from `manifest.age`, authenticated by the signature over its ciphertext.
    fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

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
    fn record_published(&self, manifest: &ArtifactManifest, header: &PublicHeader) -> Result<()> {
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

    /// Decrypts an age file into a fresh scratch directory.
    ///
    /// `max_plaintext_bytes` is the size the manifest recorded for this payload when it
    /// has one; `None` applies the format-wide cap instead.
    /// A recorded ciphertext binding is checked against the stream before the view is returned.
    fn decrypt_to_scratch(
        &self,
        ciphertext: &Path,
        name: &str,
        max_plaintext_bytes: Option<u64>,
        expected_ciphertext: Option<(u64, &str)>,
    ) -> Result<LocalPlaintext> {
        let keys = self
            .keys
            .as_ref()
            .context("artifact is encrypted but no key files are configured")?;
        ensure_regular_file(ciphertext)?;
        let claim = ActivityLock::hold(&self.root)?;
        let scratch = self.root.join(SCRATCH_DIR).join(Uuid::new_v4().to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&scratch)
            .context("create private scratch directory")?;
        let view = LocalPlaintext {
            path: scratch.join(name),
            scratch: Some(scratch),
            _claim: Some(claim),
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&view.path)
            .context("create private scratch file")?;
        let ciphertext = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
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

    /// The ids this store's own key files derive, as a v1 manifest and `public.json` must
    /// record them.
    ///
    /// These are the two numbers that make a mis-set configuration visible instead of merely
    /// fatal: an artifact names the recipient it was sealed to and the key that signed it,
    /// and both are computed here from key bytes rather than copied from a config file.
    fn key_ids(&self) -> Result<(String, String)> {
        let keys = self
            .keys
            .as_ref()
            .context("no key files are configured, so there is no key to identify")?;
        let recipient = recipient_id(
            &keys
                .recipient
                .as_ref()
                .context("this store holds no recipient file, so it cannot name a recipient")?
                .recipient()
                .as_bytes(),
        );
        let signer = signer_id(
            &keys
                .verifying
                .as_ref()
                .context("this store holds no verifying key, so it cannot name a signer")?
                .verifier()
                .to_bytes(),
        );
        Ok((recipient, signer))
    }

    /// Writes `plaintext` to `path` as one age stream sealed to `recipient`, and leaves it
    /// on disk synced.
    ///
    /// The private manifest is sealed with the same recipient as the payload it describes:
    /// it names a database, a server version, and an operator's profile, none of which
    /// belongs in a directory that may be copied off-site for disaster recovery. Its
    /// ciphertext digest is what the signature covers, so it has to be a file on disk before
    /// anything is signed.
    fn seal_to_file(recipient: &HybridRecipient, path: &Path, plaintext: &[u8]) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create sealed {}", path.display()))?;
        let mut sink = EncryptSink::new(recipient, file)
            .with_context(|| format!("open stream for {}", path.display()))?;
        sink.write_all(plaintext)?;
        let (file, _) = sink.finish()?;
        file.sync_all()?;
        Ok(())
    }

    /// Creates one file the caller has sized and bounded, with the store's durability
    /// idiom: `create_new` so a second writer can never replace it, then `sync_all` so the
    /// bytes are on disk before the directory that names them is renamed.
    fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    /// Reads and validates `public.json`. The record is bounded before the parser sees it,
    /// and every field in it is still untrusted here — the signature check that follows is
    /// what makes it true.
    fn read_header(&self, dir: &Path) -> Result<PublicHeader> {
        let path = dir.join(PUBLIC_FILE);
        ensure_regular_file(&path)?;
        let bytes = read_bounded(&path, MAX_PUBLIC_JSON_BYTES as u64 + 1)?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
        PublicHeader::from_json(text)
    }

    /// Decrypts `manifest.age` into scratch, reads it under the manifest size cap, and
    /// returns the authenticated manifest. The scratch copy is gone before this returns.
    fn authenticated_manifest(
        &self,
        path: &Path,
        header: &PublicHeader,
    ) -> Result<ArtifactManifest> {
        let view = self.decrypt_to_scratch(
            path,
            MANIFEST_FILE,
            Some(MAX_MANIFEST_BYTES),
            Some((header.manifest_ciphertext_bytes, &header.manifest_sha256)),
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

    /// Refuses an artifact directory holding both a plaintext `manifest.json` and a sealed
    /// `manifest.age`: two manifests for one id means the store cannot say which record the
    /// payload belongs to, and guessing would let an older plaintext manifest describe a
    /// newer ciphertext.
    fn refuse_split_manifest(dir: &Path) -> Result<()> {
        let both = dir.join(MANIFEST_FILE).symlink_metadata().is_ok()
            && dir.join(AGE_MANIFEST_FILE).symlink_metadata().is_ok();
        if both {
            bail!(
                "artifact holds both {MANIFEST_FILE} and {AGE_MANIFEST_FILE}; a store with two manifests for one id cannot be read safely"
            );
        }
        Ok(())
    }

    fn load_artifact(&self, id: Uuid) -> Result<LocalArtifact> {
        let dir = self.artifact_dir(id);
        ensure_real_dir(&dir)?;
        let marker = dir.join(COMPLETE_MARKER);
        ensure_regular_file(&marker)?;
        // A v1 artifact carries no plaintext manifest, so reading it as an older shape would
        // report a missing file instead of the real reason: this artifact has a signature to
        // check first, and that is a different reader.
        Self::refuse_split_manifest(&dir)?;
        if dir.join(AGE_MANIFEST_FILE).symlink_metadata().is_ok() {
            bail!(
                "artifact {id} is a signed v1 artifact; the signed reader does, not the manifest.json reader"
            );
        }
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
    type Signed = SignedArtifact;

    /// True when this store's configuration names a signing key pair, i.e. its artifacts are
    /// the signed v1 shape. The older shapes stay readable through the other methods; what
    /// changes is that a new artifact gets a sealed manifest and a signature.
    fn is_signed(&self) -> bool {
        self.keys
            .as_ref()
            .is_some_and(|keys| keys.signing.is_some() || keys.verifying.is_some())
    }

    fn signed_key_facts(&self) -> Result<SignedKeyFacts> {
        let keys = self
            .keys
            .as_ref()
            .context("no key files are configured, so there is no key to identify")?;
        let (recipient, signer) = self.key_ids()?;
        Ok(SignedKeyFacts {
            recipient_id: recipient,
            signer_id: signer,
            // The suite the store's own verifying key belongs to: what a reader of this
            // store's artifacts sizes `signature.hybrid` by.
            signature_suite: keys
                .verifying
                .as_ref()
                .context("this store holds no verifying key, so it signs nothing")?
                .suite(),
        })
    }

    fn begin(&self, id: Uuid, options: &WriteOptions) -> Result<Self::Stage> {
        // Claimed before the directory exists: a maintenance pass that is still deleting inside
        // `staging/` must be finished before this command puts a live directory in it.
        let claim = ActivityLock::hold(&self.root)?;
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
            _claim: claim,
        })
    }

    /// Claims the scope and opens the row, in the inventory's own terms: two fingerprints and an
    /// artifact id. The name-to-digest step lives here rather than in the service, which hands
    /// over what an operator typed.
    fn begin_job(&self, request: &JobRequest) -> Result<Box<dyn JobHandle>> {
        let scope = backup_inventory::JobScope {
            source_fingerprint: request.source_fingerprint.clone(),
            profile_fingerprint: profile_fingerprint(&request.profile_name),
            backup_id: request.backup_id,
        };
        Ok(Box::new(LocalJob(backup_inventory::JobGuard::begin(
            &self.root, &scope,
        )?)))
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
        // The unsigned shape and the signed shape are mutually exclusive per store, and this
        // is where that is enforced: a store configured to sign has no way to publish a
        // plaintext manifest, so a configuration mistake cannot silently downgrade it.
        if self.is_signed() {
            bail!(
                "this store has [signing] configured, so it publishes only signed v1 artifacts; use publish_signed"
            );
        }
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
                _claim: None,
            });
        }
        // The recorded plaintext size is the bound: a ciphertext that inflates past what
        // the manifest promised is refused while streaming, not after allocation.
        let limit = artifact
            .manifest
            .payload_plaintext_bytes
            .context("encrypted artifact records no plaintext payload size")?;
        self.decrypt_to_scratch(
            &artifact.payload,
            PAYLOAD_FILE,
            Some(limit),
            Some((artifact.manifest.size_bytes, &artifact.manifest.sha256)),
        )
    }

    fn plaintext_staged_payload(&self, stage: &Self::Stage) -> Result<Self::Plaintext> {
        if !self.encrypted() {
            ensure_regular_file(&stage.payload)?;
            return Ok(LocalPlaintext {
                path: stage.payload.clone(),
                scratch: None,
                _claim: None,
            });
        }
        // A stage has no manifest yet, so only the format-wide cap applies.
        self.decrypt_to_scratch(&stage.payload, PAYLOAD_FILE, None, None)
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
                _claim: None,
            });
        }
        // Globals carry no recorded plaintext size, so the cap here is the format's own;
        // a role dump past it is refused rather than trusted.
        self.decrypt_to_scratch(
            path,
            GLOBALS_FILE,
            None,
            Some((
                artifact
                    .manifest
                    .globals_size_bytes
                    .context("globals size missing")?,
                artifact
                    .manifest
                    .globals_sha256
                    .as_deref()
                    .context("globals digest missing")?,
            )),
        )
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

    /// Publishes a staged dump as a signed v1 artifact, in the contract's writer order:
    /// the staged `payload.age` (and `globals.age` when declared), then `manifest.age`,
    /// `signature.hybrid`, and `public.json`, and only then the directory rename with
    /// `complete` last.
    ///
    /// Nothing reaches `artifacts/` before the signature has been written *and* checked
    /// against this store's own verifying key, so a v1 store has no reachable state in which
    /// an unsigned artifact is visible. That is the property the reader relies on: the only
    /// way an artifact in this store lacks a valid signature is that something changed it
    /// after publication.
    fn publish_signed(
        &self,
        stage: LocalStage,
        manifest: &ArtifactManifest,
    ) -> Result<PublicHeader> {
        let keys = self.keys.as_ref().context(
            "a signed artifact needs [encryption] and [signing] key files; this store has neither",
        )?;
        let signing = keys.signing.as_ref().context(
            "this store holds no signing key, so it publishes nothing: a host configured only \
             to verify cannot write artifacts",
        )?;
        let recipient = keys
            .recipient
            .as_ref()
            .context("this store holds no recipient file, so it cannot seal an artifact")?;
        if !stage.sealed_payload.load(Ordering::Relaxed) {
            bail!("payload stream was never finished; staged artifact was not published");
        }
        if manifest.backup_id != stage.id {
            bail!("manifest ID does not match staging ID");
        }
        manifest.validate_writable()?;
        let (derived_recipient, derived_signer) = self.key_ids()?;
        if manifest.recipient_id != derived_recipient {
            bail!(
                "manifest records recipient id {} but the configured recipient derives {derived_recipient}",
                manifest.recipient_id
            );
        }
        if manifest.signer_id != derived_signer {
            bail!(
                "manifest records signer id {} but the configured signing key derives {derived_signer}",
                manifest.signer_id
            );
        }
        let (payload_bytes, payload_digest) = self.measure(&stage)?;
        if payload_bytes != manifest.payload_ciphertext_bytes
            || payload_digest != manifest.payload_ciphertext_sha256
        {
            bail!("staged payload changed, or the manifest was not built from it");
        }
        match (
            manifest.globals_policy.as_str(),
            stage.globals.as_ref(),
            manifest.globals_sha256.as_ref(),
        ) {
            (GLOBALS_POLICY_EXPORTED, Some(path), Some(digest)) => {
                if !stage.sealed_globals.load(Ordering::Relaxed) {
                    bail!("globals stream was never finished; staged artifact was not published");
                }
                let (bytes, measured) = hash_file(path)?;
                if manifest.globals_ciphertext_bytes != Some(bytes) || digest != &measured {
                    bail!("staged globals file changed, or the manifest was not built from it");
                }
            }
            (GLOBALS_POLICY_SKIPPED, None, None) => {}
            _ => bail!(
                "manifest globals policy {:?} disagrees with what the stage holds",
                manifest.globals_policy
            ),
        };
        let manifest_path = stage.dir.join(AGE_MANIFEST_FILE);
        let mut manifest_bytes =
            serde_json::to_vec_pretty(manifest).context("serialize artifact manifest")?;
        manifest_bytes.push(b'\n');
        if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
            bail!(
                "private manifest is {} bytes, over the {MAX_MANIFEST_BYTES} byte limit",
                manifest_bytes.len()
            );
        }
        Self::seal_to_file(recipient.recipient(), &manifest_path, &manifest_bytes)?;
        let (manifest_ciphertext_bytes, manifest_digest) = hash_file(&manifest_path)?;
        let tuple = signature_tuple(
            stage.id.as_bytes(),
            &digest_bytes(&manifest_digest)?,
            &digest_bytes(&payload_digest)?,
        );
        let signature = signing
            .signer()?
            .try_sign(&tuple)
            .context("origin signature failed")?;
        let signature_path = stage.dir.join(SIGNATURE_FILE);
        Self::write_private_file(&signature_path, signature.as_bytes())?;
        // Re-read and checked from the bytes on disk, at exactly the length the reader will
        // require: publishing a signature this store could not verify would produce an
        // artifact that is unreadable by design.
        let stored = read_bounded(&signature_path, HYBRID_SIGNATURE_BYTES as u64 + 1)?;
        let written = backup_crypto::signing::HybridSignature::from_bytes(&stored)
            .context("signature.hybrid was not written at the suite's exact length")?;
        signing
            .verifier()
            .verify(&tuple, &written)
            .context("freshly written signature does not verify against this store's key")?;
        let header = PublicHeader::seal(manifest, &manifest_digest, manifest_ciphertext_bytes)?;
        Self::write_private_file(
            stage.dir.join(PUBLIC_FILE).as_path(),
            header.to_json()?.as_bytes(),
        )?;
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
        self.record_published(manifest, &header)?;
        Ok(header)
    }

    /// Lists what the store holds using only `public.json`, so this works while holding no
    /// key material at all — which is exactly why the fields it reports stay untrusted.
    ///
    /// Nothing here is decrypted and no signature is checked: a listing is how an operator
    /// finds an artifact to verify, and verifying is [`LocalStore::verify_signed`]. Pre-v1
    /// artifacts are reported by id rather than skipped, because an unsigned artifact that a
    /// signature-first listing hides is the failure mode this function exists to catch.
    fn list_signed(&self) -> Result<StoreListing> {
        let mut listing = StoreListing {
            signed: Vec::new(),
            unsigned: Vec::new(),
        };
        for entry in fs::read_dir(self.root.join(ARTIFACTS_DIR))? {
            let path = entry?.path();
            let Some(id) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            if !path.join(COMPLETE_MARKER).exists() {
                continue;
            }
            if path.join(PUBLIC_FILE).symlink_metadata().is_ok() {
                listing.signed.push(self.read_header(&path)?);
            } else {
                listing.unsigned.push(id);
            }
        }
        listing.signed.sort_by_key(|header| header.backup_id);
        listing.unsigned.sort();
        Ok(listing)
    }

    /// The reader's first three steps and no further: parse `public.json`, recompute both
    /// ciphertext digests from the files on disk, and verify the signature over the backup id
    /// and those digests against the configured verifying key.
    ///
    /// No manifest is decrypted here, so this is the whole of what a host holding nothing but
    /// a verifying key can prove about an artifact.
    fn verify_signed(&self, id: Uuid) -> Result<PublicHeader> {
        let keys = self
            .keys
            .as_ref()
            .context("artifact is signed but no key files are configured")?;
        let verifying = keys
            .verifying
            .as_ref()
            .context("no verifying key is configured, so no signature can be trusted")?;
        let dir = self.artifact_dir(id);
        ensure_real_dir(&dir)?;
        ensure_regular_file(&dir.join(COMPLETE_MARKER))?;
        Self::refuse_split_manifest(&dir)?;
        let header = self.read_header(&dir)?;
        if header.backup_id != id {
            bail!(
                "public.json records backup id {}, found under directory {id}",
                header.backup_id
            );
        }
        let payload = dir.join(AGE_PAYLOAD_FILE);
        ensure_regular_file(&payload)?;
        let (payload_bytes, payload_digest) = hash_file(&payload)?;
        if payload_bytes != header.payload_ciphertext_bytes
            || payload_digest != header.payload_sha256
        {
            bail!(
                "payload.age is not the ciphertext public.json describes: {payload_bytes} bytes digesting {payload_digest}"
            );
        }
        let manifest_path = dir.join(AGE_MANIFEST_FILE);
        ensure_regular_file(&manifest_path)?;
        let (manifest_bytes, manifest_digest) = hash_file(&manifest_path)?;
        if manifest_bytes != header.manifest_ciphertext_bytes
            || manifest_digest != header.manifest_sha256
        {
            bail!(
                "manifest.age is not the ciphertext public.json describes: {manifest_bytes} bytes digesting {manifest_digest}"
            );
        }
        let signature_path = dir.join(SIGNATURE_FILE);
        ensure_regular_file(&signature_path)?;
        let stored = read_bounded(&signature_path, HYBRID_SIGNATURE_BYTES as u64 + 1)?;
        let signature = backup_crypto::signing::HybridSignature::from_bytes(&stored)
            .with_context(|| format!("read {}", signature_path.display()))?;
        let tuple = signature_tuple(
            id.as_bytes(),
            &digest_bytes(&manifest_digest)?,
            &digest_bytes(&payload_digest)?,
        );
        verifying
            .verifier()
            .verify(&tuple, &signature)
            .with_context(|| format!("origin signature of artifact {id} does not verify"))?;
        Ok(header)
    }

    /// Reads one v1 artifact, authenticating it before decrypting anything.
    ///
    /// The order is the contract's, and it is the whole point of the type: [`Self::verify_signed`]
    /// first, and only then is `manifest.age` opened — under a size bound, and checked field by
    /// field against the header it was sealed beside.
    ///
    /// `globals.age` is bound one step further in, by the digest inside the signed manifest,
    /// so a swapped globals file is caught through the signature rather than by its own
    /// metadata.
    fn open_signed(&self, id: Uuid) -> Result<SignedArtifact> {
        let header = self.verify_signed(id)?;
        // Everything from here in was written by whoever holds the configured signing key.
        let dir = self.artifact_dir(id);
        let manifest = self.authenticated_manifest(&dir.join(AGE_MANIFEST_FILE), &header)?;
        manifest.matches_header(&header)?;
        if manifest.backup_id != id {
            bail!(
                "authenticated manifest records backup id {}, requested {id}",
                manifest.backup_id
            );
        }
        let payload = dir.join(AGE_PAYLOAD_FILE);
        let globals_path = dir.join(AGE_GLOBALS_FILE);
        let globals = match manifest.globals_policy.as_str() {
            GLOBALS_POLICY_EXPORTED => {
                ensure_regular_file(&globals_path)?;
                let (bytes, digest) = hash_file(&globals_path)?;
                if manifest.globals_sha256.as_deref() != Some(digest.as_str())
                    || manifest.globals_ciphertext_bytes != Some(bytes)
                {
                    bail!(
                        "globals.age does not match the digest inside the signed manifest; the file was changed after publication"
                    );
                }
                Some(globals_path)
            }
            GLOBALS_POLICY_SKIPPED => {
                if globals_path.symlink_metadata().is_ok() {
                    bail!(
                        "artifact holds a globals file its authenticated manifest declares skipped"
                    );
                }
                None
            }
            other => bail!("manifest globals policy {other:?} is not a known policy"),
        };
        Ok(SignedArtifact {
            header,
            manifest,
            payload,
            globals,
        })
    }

    /// The authenticated payload as plaintext, decrypted into the store's scratch directory
    /// and removed when the returned view is dropped.
    ///
    /// The bound is `archive_plaintext_bytes`, a number from inside the signature, so a
    /// ciphertext that inflates past what the manifest promised is refused while streaming
    /// rather than after the write.
    fn payload_plaintext(&self, artifact: &SignedArtifact) -> Result<LocalPlaintext> {
        self.decrypt_to_scratch(
            &artifact.payload,
            PAYLOAD_FILE,
            Some(artifact.manifest.archive_plaintext_bytes),
            Some((
                artifact.manifest.payload_ciphertext_bytes,
                &artifact.manifest.payload_ciphertext_sha256,
            )),
        )
    }

    /// The authenticated globals file as plaintext, under the format-wide bound: role
    /// metadata carries no recorded plaintext size in the manifest.
    fn globals_plaintext(&self, artifact: &SignedArtifact) -> Result<LocalPlaintext> {
        let path = artifact
            .globals
            .as_ref()
            .context("authenticated manifest declares no globals file")?;
        self.decrypt_to_scratch(
            path,
            GLOBALS_FILE,
            None,
            Some((
                artifact
                    .manifest
                    .globals_ciphertext_bytes
                    .context("globals size missing")?,
                artifact
                    .manifest
                    .globals_sha256
                    .as_deref()
                    .context("globals digest missing")?,
            )),
        )
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

/// Reads at most `limit` bytes, refusing a file that turns out to be larger.
///
/// The cap is applied while reading rather than from the file's reported size, because a
/// size an attacker controls is not a bound: the reader has to stop on its own terms.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!(
            "{} is larger than the {limit} byte bound this reader applies",
            path.display()
        );
    }
    Ok(bytes)
}

/// A recorded digest as the raw bytes the signed tuple needs.
///
/// The text has already been validated as lowercase hex by the record it came from, and is
/// re-checked here rather than trusted: a hostile `public.json` reaches this function, and
/// bytes that are not a digest must be a refusal, not a panic or a silent padding.
fn digest_bytes(value: &str) -> Result<[u8; DIGEST_BYTES]> {
    let text = value.as_bytes();
    if text.len() != DIGEST_BYTES * 2 {
        bail!("{value:?} is not a SHA-256 digest");
    }
    let mut digest = [0u8; DIGEST_BYTES];
    for (byte, pair) in digest.iter_mut().zip(text.chunks_exact(2)) {
        let nibble = |value: u8| -> Result<u8> {
            match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => bail!("{value:?} is not a lowercase hex digit"),
            }
        };
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{key_pair, temp_keys, temp_root};
    use backup_crypto::protocol::SUITE_HYBRID;
    use backup_domain::{DEV_FORMAT, PLAN_FORMAT, RestoreSecurityPolicy};

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
        // A shorter valid unsigned stream cannot be mistaken for the authenticated JSON.
        let mut replacement = Vec::new();
        backup_crypto::stream::encrypt(recipient.recipient(), &b""[..], &mut replacement)?;
        fs::write(&path, replacement)?;
        let error = store.authenticated_manifest(&path, &header).unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("ciphertext changed after authentication")
                || error.contains("failed to decrypt completely"),
            "{error}"
        );
        assert_eq!(fs::read_dir(root.join(SCRATCH_DIR))?.count(), 0);
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(keydir)?;
        Ok(())
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

    /// The scratch view is a promise about failures, not only about success. A stream
    /// this identity cannot open is refused part-way through, and the directory it was
    /// decrypted into has to disappear with it, so a refused restore leaves no
    /// half-written plaintext file in the store.
    #[test]
    fn a_refused_decryption_leaves_no_scratch_behind() {
        let root = temp_root();
        let written = temp_keys();
        let reader = temp_keys();
        let (identity, recipient) = key_pair(&written);
        let store = LocalStore::with_keys(root.clone(), &identity, &recipient).unwrap();
        let id = Uuid::new_v4();
        let plaintext = b"synthetic archive bytes";
        let stage = store
            .begin(
                id,
                &WriteOptions {
                    with_globals: false,
                },
            )
            .unwrap();
        stage_bytes(&store, &stage, plaintext, None);
        let (size_bytes, sha256) = store.measure(&stage).unwrap();
        let mut m = manifest(id, size_bytes, sha256);
        m.format = AGE_FORMAT.to_string();
        m.recipient_suite = Some(SUITE_HYBRID.to_string());
        m.payload_plaintext_bytes = Some(plaintext.len() as u64);
        store.publish(stage, &m).unwrap();

        // A second, unrelated pair: the same bytes, the same store, no way in.
        let (stranger, stranger_recipient) = key_pair(&reader);
        let other = LocalStore::with_keys(root.clone(), &stranger, &stranger_recipient).unwrap();
        let artifact = other.open(id).unwrap();
        assert!(other.plaintext_payload(&artifact).is_err());
        let leftovers: Vec<_> = fs::read_dir(root.join("scratch")).unwrap().collect();
        assert!(
            leftovers.is_empty(),
            "a refused decryption left a scratch entry"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(written).unwrap();
        fs::remove_dir_all(reader).unwrap();
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
