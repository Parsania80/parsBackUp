use anyhow::{Context, Result, bail};
use backup_domain::{
    AGE_FORMAT, ARCHIVE_COMPRESSION, ARCHIVE_FORMAT, ArtifactScope, BACKUP_STATUS, Config,
    DEV_FORMAT, DevelopmentManifest, DumpOptions, Profile, ResolvedSelection, RestorePlan,
    RestoreSections, RestoreSecurityPolicy, Source, VERIFICATION_NONE, VERIFY_ARCHIVE,
    VERIFY_CHECKSUM, VERIFY_RESTORE_TESTED,
};
use sha2::Digest as _;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const PLAN_TTL: Duration = Duration::from_secs(backup_domain::PLAN_TTL_SECONDS);

#[derive(Clone, Debug)]
pub struct EngineInfo {
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
}

pub trait DatabaseAdapter {
    fn preflight(&self, source: &Source, timeout: Duration) -> Result<EngineInfo>;
    /// Read the live catalog and turn a profile's requested names into the
    /// exact object set a dump would write, including anything it references
    /// from outside that set.
    fn resolve_selection(
        &self,
        source: &Source,
        profile: &Profile,
        timeout: Duration,
    ) -> Result<ResolvedSelection>;
    /// Runs `pg_dump` and hands its standard output to `consume`.
    ///
    /// There is deliberately no output path here: the adapter that talks to
    /// PostgreSQL does not get to decide whether plaintext reaches a disk, and the
    /// only way to make that a property of the tool rather than of each call site is
    /// to keep the bytes in a stream the caller owns. A dump that fails or warns
    /// returns an error before `consume` has been given anything to finish.
    fn dump_stream(
        &self,
        source: &Source,
        options: &DumpOptions,
        timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()>;
    /// The `pg_dumpall` equivalent of [`DatabaseAdapter::dump_stream`], for the
    /// cluster role metadata.
    fn dump_globals_stream(
        &self,
        source: &Source,
        timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()>;
    /// Returns the archive table of contents, one entry per line.
    fn inspect_archive(
        &self,
        source: &Source,
        archive: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>>;
    fn database_exists(&self, source: &Source, database: &str, timeout: Duration) -> Result<bool>;
    fn role_conflicts(
        &self,
        source: &Source,
        globals: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>>;
    fn apply_globals(&self, source: &Source, globals: &Path, timeout: Duration) -> Result<()>;
    fn create_database(&self, source: &Source, database: &str, timeout: Duration) -> Result<()>;
    /// Create namespaces the archive assumes to exist (table-selected dumps
    /// carry no CREATE SCHEMA entries). Implementations must validate every
    /// name before issuing DDL.
    fn create_schemas(
        &self,
        source: &Source,
        database: &str,
        schemas: &[String],
        timeout: Duration,
    ) -> Result<()>;
    fn restore_to_database(
        &self,
        source: &Source,
        database: &str,
        archive: &Path,
        security: RestoreSecurityPolicy,
        sections: RestoreSections,
        timeout: Duration,
    ) -> Result<()>;
}

pub struct WriteOptions {
    pub with_globals: bool,
}

pub trait StageHandle {
    fn payload_path(&self) -> &Path;
    fn globals_path(&self) -> Option<&Path>;
}

/// What one staged file holds once its writer is finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedBytes {
    /// Plaintext bytes absorbed, which for an encrypted file is not the number of
    /// bytes published.
    pub plaintext_bytes: u64,
    /// The recipient suite the bytes were sealed under, or `None` when the store
    /// published them as plaintext.
    pub recipient_suite: Option<&'static str>,
}

/// The writer for one staged file.
///
/// The store, not the service, decides whether the bytes land as plaintext or as an
/// authenticated ciphertext, because the store is what an attacker can read. This is
/// the only place the two cases differ, and both must be finished before publication:
/// a stream that was never completed leaves nothing publishable behind.
pub trait PayloadSink: Write {
    /// Completes the stream and reports what was staged. Publishing a stage whose
    /// sink was not finished must fail.
    fn finish(&mut self) -> Result<StagedBytes>;
}

/// A file a PostgreSQL client tool may be pointed at, as plaintext.
///
/// The implementor owns any temporary decrypted copy behind that path and removes it
/// on drop, so a restore cannot leave plaintext in the artifact store.
pub trait PlaintextView {
    fn path(&self) -> &Path;
}

pub trait ArtifactHandle {
    fn id(&self) -> Uuid;
    fn manifest(&self) -> &DevelopmentManifest;
    fn payload_path(&self) -> &Path;
    fn globals_path(&self) -> Option<&Path>;
}

pub trait ArtifactStore {
    type Stage: StageHandle;
    type Artifact: ArtifactHandle;
    type Plaintext: PlaintextView;

    fn begin(&self, id: Uuid, options: &WriteOptions) -> Result<Self::Stage>;
    /// The writer for the staged payload file.
    ///
    /// `'a` is shared between the store and the stage: sealing a stream also marks the
    /// stage publishable, so the sink has to outlive the call while the stage does.
    fn payload_sink<'a>(&'a self, stage: &'a Self::Stage) -> Result<Box<dyn PayloadSink + 'a>>;
    /// The writer for the staged globals file, when the stage declares one.
    fn globals_sink<'a>(&'a self, stage: &'a Self::Stage) -> Result<Box<dyn PayloadSink + 'a>>;
    fn measure(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn measure_globals(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn publish(&self, stage: Self::Stage, manifest: &DevelopmentManifest) -> Result<()>;
    fn list(&self) -> Result<Vec<DevelopmentManifest>>;
    fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest>;
    fn open(&self, id: Uuid) -> Result<Self::Artifact>;
    /// The payload as a plaintext file, decrypting it into private storage when the
    /// artifact is an age ciphertext.
    fn plaintext_payload(&self, artifact: &Self::Artifact) -> Result<Self::Plaintext>;
    /// The staged payload as plaintext, for the table-of-contents digest taken before
    /// publication. A stage holds no manifest yet, so the caller's own recorded
    /// plaintext size is the only bound available; this view is bounded by the
    /// format's own limit instead.
    fn plaintext_staged_payload(&self, stage: &Self::Stage) -> Result<Self::Plaintext>;
    /// The globals file as plaintext, same contract as
    /// [`ArtifactStore::plaintext_payload`].
    fn plaintext_globals(&self, artifact: &Self::Artifact) -> Result<Self::Plaintext>;
    fn rewrite_manifest(
        &self,
        artifact: &Self::Artifact,
        manifest: &DevelopmentManifest,
    ) -> Result<()>;
    fn save_plan(&self, plan: &RestorePlan) -> Result<()>;
    fn load_plan(&self, id: Uuid) -> Result<Option<RestorePlan>>;
}

pub fn now_unix_ms() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_millis())
}

/// SHA-256 over the archive table of contents. The payload digest binds the
/// bytes; this binds the content set, so `verify --level archive` can prove the
/// archive still lists what the manifest recorded rather than merely being
/// unread-but-intact.
pub fn toc_digest(lines: &[String]) -> Result<String> {
    if lines.is_empty() {
        bail!("archive table of contents is empty");
    }
    Ok(format!(
        "{:x}",
        sha2::Sha256::digest(lines.join("\n").as_bytes())
    ))
}

pub struct BackupService<E, S> {
    engine: E,
    store: S,
}

impl<E: DatabaseAdapter, S: ArtifactStore> BackupService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    /// Resolve a profile against the live catalog and refuse a selection that
    /// pg_dump could not restore on its own. `create` uses this before writing
    /// anything, so a dry run reports exactly what a backup would contain.
    pub fn resolve(
        &self,
        config: &Config,
        profile_name: Option<&str>,
    ) -> Result<(EngineInfo, ResolvedSelection)> {
        config.validate()?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let info = self.engine.preflight(&config.source, timeout)?;
        let profile = match profile_name {
            Some(name) => Some(config.profile(name)?),
            None => None,
        };
        let resolved = match profile {
            Some(profile) => self
                .engine
                .resolve_selection(&config.source, profile, timeout)?,
            None => ResolvedSelection {
                whole_database: true,
                ..Default::default()
            },
        };
        if !resolved.dangling.is_empty() {
            let named = resolved
                .dangling
                .iter()
                .map(|reference| {
                    format!(
                        "{} depends on {} ({})",
                        reference.dependent, reference.referenced, reference.kind
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            let who = match profile {
                Some(profile) => format!("profile {}", profile.name),
                None => "this selection".to_string(),
            };
            bail!(
                "{who} is not self-contained: {named}. pg_dump does not write objects from outside \
                 the selection, so this archive could not restore into an empty database on its \
                 own; widen the selection or restore into a database that already holds those objects"
            );
        }
        Ok((info, resolved))
    }

    pub fn create(
        &self,
        config: &Config,
        profile_name: Option<&str>,
    ) -> Result<DevelopmentManifest> {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let (info, resolved) = self.resolve(config, profile_name)?;
        let profile = match profile_name {
            Some(name) => Some(config.profile(name)?),
            None => None,
        };
        let none_extensions: Vec<String> = Vec::new();
        let exclude_extensions = match profile {
            Some(profile) => &profile.exclude_extensions,
            None => &none_extensions,
        };
        let options = DumpOptions {
            major: info.source_major,
            mode: profile.map(|profile| profile.mode).unwrap_or_default(),
            selection: &resolved,
            large_objects: profile.map(|profile| profile.large_objects),
            exclude_extensions,
        };
        let id = Uuid::new_v4();
        let stage = self.store.begin(
            id,
            &WriteOptions {
                with_globals: config.export_globals,
            },
        )?;
        let staged = {
            let mut payload_sink = self.store.payload_sink(&stage)?;
            self.engine
                .dump_stream(&config.source, &options, timeout, &mut |stream| {
                    io::copy(stream, &mut payload_sink)?;
                    Ok(())
                })
                .context("PostgreSQL dump failed; staged artifact was not published")?;
            payload_sink
                .finish()
                .context("payload stream was never finished; staged artifact was not published")?
        };
        // The published file is the ciphertext, so its size cannot prove the dump
        // produced anything: an empty archive still encrypts to an age header.
        if staged.plaintext_bytes == 0 {
            bail!("pg_dump produced an empty archive");
        }
        let inspected = self.store.plaintext_staged_payload(&stage)?;
        let toc = self
            .engine
            .inspect_archive(&config.source, inspected.path(), timeout)
            .context("PostgreSQL archive inspection failed; artifact was not published")?;
        let toc_sha256 = toc_digest(&toc)?;
        let (size_bytes, sha256) = self.store.measure(&stage)?;
        let mut globals_sha256 = None;
        let mut globals_size_bytes = None;
        if config.export_globals {
            let mut globals_sink = self.store.globals_sink(&stage)?;
            self.engine
                .dump_globals_stream(&config.source, timeout, &mut |stream| {
                    io::copy(stream, &mut globals_sink)?;
                    Ok(())
                })
                .context("PostgreSQL globals export failed; staged artifact was not published")?;
            let globals_staged = globals_sink
                .finish()
                .context("globals stream was never finished; staged artifact was not published")?;
            if globals_staged.plaintext_bytes == 0 {
                bail!("pg_dumpall produced an empty globals file");
            }
            let (gsize, gsha) = self.store.measure_globals(&stage)?;
            globals_size_bytes = Some(gsize);
            globals_sha256 = Some(gsha);
        }
        // Whether the artifact is encrypted is a fact the store reported through its
        // sink, not a flag the service carries: the format tag follows that report.
        let encrypted = staged.recipient_suite.is_some();
        let created_unix_ms = now_unix_ms()?;
        let manifest = DevelopmentManifest {
            format: if encrypted {
                AGE_FORMAT.to_string()
            } else {
                DEV_FORMAT.to_string()
            },
            id,
            synthetic_only: true,
            database: config.source.database.clone(),
            source_major: info.source_major,
            source_version: info.source_version,
            dump_client_version: info.dump_client_version,
            application_version: env!("CARGO_PKG_VERSION").to_string(),
            archive_format: ARCHIVE_FORMAT.to_string(),
            compression: ARCHIVE_COMPRESSION.to_string(),
            created_unix_ms,
            size_bytes,
            sha256,
            status: BACKUP_STATUS.to_string(),
            security_globals: config.export_globals,
            globals_sha256,
            globals_size_bytes,
            verification_level: None,
            verified_unix_ms: None,
            scope: profile.map(|profile| ArtifactScope::from_profile(profile, &resolved)),
            toc_sha256: Some(toc_sha256),
            recipient_suite: staged.recipient_suite.map(str::to_string),
            payload_plaintext_bytes: encrypted.then_some(staged.plaintext_bytes),
        };
        manifest.validate_shape()?;
        self.store.publish(stage, &manifest)?;
        Ok(manifest)
    }

    pub fn list(&self) -> Result<Vec<DevelopmentManifest>> {
        self.store.list()
    }

    pub fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest> {
        self.store.inspect(id)
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub artifact_id: Uuid,
    pub level: String,
    pub payload_size_bytes: u64,
    pub payload_sha256: String,
    pub globals_size_bytes: Option<u64>,
    pub globals_sha256: Option<String>,
}

pub struct VerifyService<E, S> {
    engine: E,
    store: S,
}

impl<E: DatabaseAdapter, S: ArtifactStore> VerifyService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    pub fn verify(&self, config: &Config, id: Uuid, level: &str) -> Result<VerifyReport> {
        if !matches!(level, VERIFY_CHECKSUM | VERIFY_ARCHIVE) {
            bail!("verification level must be checksum or archive");
        }
        let timeout = Duration::from_secs(config.timeout_seconds);
        // Opening the artifact already recomputes payload and globals digests
        // and rejects marker/manifest/shape mismatches: that is checksum level.
        let artifact = self.store.open(id)?;
        let manifest = artifact.manifest();
        if level == VERIFY_ARCHIVE {
            // The tool boundary reads plaintext, so an encrypted artifact is
            // decrypted into private storage that this scope ends the view of.
            let payload = self.store.plaintext_payload(&artifact)?;
            let toc = self
                .engine
                .inspect_archive(&config.source, payload.path(), timeout)
                .context("archive table of contents failed to parse")?;
            let digest = toc_digest(&toc)?;
            if let Some(recorded) = &manifest.toc_sha256
                && recorded != &digest
            {
                bail!(
                    "archive table of contents does not match the manifest; the payload was replaced or re-dumped"
                );
            }
        }
        Ok(VerifyReport {
            artifact_id: id,
            level: level.to_string(),
            payload_size_bytes: manifest.size_bytes,
            payload_sha256: manifest.sha256.clone(),
            globals_size_bytes: manifest.globals_size_bytes,
            globals_sha256: manifest.globals_sha256.clone(),
        })
    }
}

pub struct RestoreService<E, S> {
    engine: E,
    store: S,
}

#[derive(Debug)]
pub struct RestoreOutcome {
    pub plan: RestorePlan,
    /// The artifact's verification level after this run.
    pub verification_level: String,
}

impl<E: DatabaseAdapter, S: ArtifactStore> RestoreService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    pub fn plan(
        &self,
        config: &Config,
        artifact_id: Uuid,
        target: &str,
        security: RestoreSecurityPolicy,
        sections: RestoreSections,
    ) -> Result<RestorePlan> {
        config.validate()?;
        sections.validate()?;
        // Fail on the contradiction between sections and security before any
        // environment probe, so the refusal names the real reason.
        sections.check_security(&security)?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let info = self.engine.preflight(&config.source, timeout)?;
        let artifact = self.store.open(artifact_id)?;
        let manifest = artifact.manifest();
        if security.roles && !manifest.security_globals {
            bail!("restore policy requires roles but the backup contains no globals security file");
        }
        if manifest.source_major != info.source_major {
            bail!("client major does not match the backup source major; same-major restore only");
        }
        if target == manifest.database {
            bail!("restore target must differ from the backup source database");
        }
        if self
            .engine
            .database_exists(&config.source, target, timeout)?
        {
            bail!("target database already exists; restore only creates a new database");
        }
        if security.roles {
            let globals = self.store.plaintext_globals(&artifact)?;
            let conflicts = self
                .engine
                .role_conflicts(&config.source, globals.path(), timeout)?;
            if !conflicts.is_empty() {
                bail!(
                    "DR role restore refused: these roles already exist in the cluster: {}; use the portable policy or remove them first",
                    conflicts.join(", ")
                );
            }
        }
        let created = now_unix_ms()?;
        let plan = RestorePlan {
            format: backup_domain::PLAN_FORMAT.to_string(),
            id: Uuid::new_v4(),
            artifact_id,
            artifact_database: manifest.database.clone(),
            source_major: manifest.source_major,
            client_version: info.dump_client_version,
            target_database: target.to_string(),
            security,
            sections,
            artifact_scope: manifest.scope.as_ref().map(|scope| scope.profile.clone()),
            created_unix_ms: created,
            expires_unix_ms: created + PLAN_TTL.as_millis(),
        };
        plan.validate(now_unix_ms()?)?;
        self.store.save_plan(&plan)?;
        Ok(plan)
    }

    pub fn run(
        &self,
        config: &Config,
        plan_id: Uuid,
        confirm_target: &str,
    ) -> Result<RestoreOutcome> {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let plan = self
            .store
            .load_plan(plan_id)?
            .context("restore plan not found")?;
        plan.validate(now_unix_ms()?)?;
        if plan.target_database != confirm_target {
            bail!("confirmation target does not match the planned database");
        }
        if plan.artifact_database != config.source.database {
            bail!("plan source database does not match the configuration");
        }
        let info = self.engine.preflight(&config.source, timeout)?;
        if info.source_major != plan.source_major {
            bail!("client or server major changed since the plan was created");
        }
        let artifact = self.store.open(plan.artifact_id)?;
        if artifact.manifest().database != plan.artifact_database {
            bail!("artifact database identity does not match the plan");
        }
        // Step 1 of the DR order: security metadata validated (digest binding
        // happened in open()); re-check role conflicts at execution time.
        if plan.security.roles {
            let globals = self.store.plaintext_globals(&artifact)?;
            let conflicts = self
                .engine
                .role_conflicts(&config.source, globals.path(), timeout)?;
            if !conflicts.is_empty() {
                bail!(
                    "DR role restore refused: these roles already exist in the cluster: {}",
                    conflicts.join(", ")
                );
            }
            // Step 2: roles, attributes, and memberships before any object
            // can be owned by or granted to them.
            self.engine
                .apply_globals(&config.source, globals.path(), timeout)
                .context("globals restore failed; cluster roles may be partially applied")?;
        }
        // Step 3: fresh target database; existence re-checked here.
        if self
            .engine
            .database_exists(&config.source, &plan.target_database, timeout)?
        {
            bail!("target database appeared after planning; refusing to touch it");
        }
        self.engine
            .create_database(&config.source, &plan.target_database, timeout)
            .context("target database creation failed")?;
        // A table-selected archive restores its relations but never creates
        // their namespaces; prepare them so the restore targets an otherwise
        // empty database, matching the schema-selection behavior.
        if let Some(scope) = artifact.manifest().scope.as_ref() {
            let required = scope.restore_required_schemas();
            if !required.is_empty() {
                self.engine
                    .create_schemas(&config.source, &plan.target_database, &required, timeout)
                    .context("target schema preparation failed")?;
            }
        }
        // Steps 4-6: schema/data, then ownership and privileges from the
        // archive's own ALTER OWNER/GRANT entries (skipped per policy). The view is
        // held for the length of the restore and its plaintext is removed after.
        let payload = self.store.plaintext_payload(&artifact)?;
        let restored = self.engine.restore_to_database(
            &config.source,
            &plan.target_database,
            payload.path(),
            plan.security,
            plan.sections,
            timeout,
        );
        if let Err(error) = restored {
            bail!(
                "database restore failed: {error:#}; target {} may be partially modified and was left in place for operator inspection",
                plan.target_database
            );
        }
        if !plan.sections.is_full() {
            // A section-limited restore proves nothing about the rest of the
            // archive, so the artifact keeps its recorded verification level.
            return Ok(RestoreOutcome {
                plan,
                verification_level: artifact
                    .manifest()
                    .verification_level
                    .clone()
                    .unwrap_or_else(|| VERIFICATION_NONE.to_string()),
            });
        }
        // Record restore-tested verification on the artifact (additive field
        // update; payload and digests are unchanged).
        let mut updated = artifact.manifest().clone();
        updated.verification_level = Some(VERIFY_RESTORE_TESTED.to_string());
        updated.verified_unix_ms = Some(now_unix_ms()?);
        updated.validate_shape()?;
        self.store
            .rewrite_manifest(&artifact, &updated)
            .context("restore succeeded but verification marking failed")?;
        Ok(RestoreOutcome {
            plan,
            verification_level: VERIFY_RESTORE_TESTED.to_string(),
        })
    }
}
