use anyhow::{Context, Result, bail};
use backup_domain::{
    Config, DEV_FORMAT, DevelopmentManifest, RestorePlan, RestoreSecurityPolicy, Source,
    VERIFY_ARCHIVE, VERIFY_CHECKSUM, VERIFY_RESTORE_TESTED,
};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const PLAN_TTL: Duration = Duration::from_secs(900);

#[derive(Clone, Debug)]
pub struct EngineInfo {
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
}

pub trait DatabaseAdapter {
    fn preflight(&self, source: &Source, timeout: Duration) -> Result<EngineInfo>;
    fn dump_to(&self, source: &Source, output: &Path, timeout: Duration) -> Result<()>;
    fn dump_globals(&self, source: &Source, output: &Path, timeout: Duration) -> Result<()>;
    fn inspect_archive(&self, source: &Source, archive: &Path, timeout: Duration) -> Result<()>;
    fn database_exists(&self, source: &Source, database: &str, timeout: Duration) -> Result<bool>;
    fn role_conflicts(
        &self,
        source: &Source,
        globals: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>>;
    fn apply_globals(&self, source: &Source, globals: &Path, timeout: Duration) -> Result<()>;
    fn create_database(&self, source: &Source, database: &str, timeout: Duration) -> Result<()>;
    fn restore_to_database(
        &self,
        source: &Source,
        database: &str,
        archive: &Path,
        security: RestoreSecurityPolicy,
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

pub trait ArtifactHandle {
    fn id(&self) -> Uuid;
    fn manifest(&self) -> &DevelopmentManifest;
    fn payload_path(&self) -> &Path;
    fn globals_path(&self) -> Option<&Path>;
}

pub trait ArtifactStore {
    type Stage: StageHandle;
    type Artifact: ArtifactHandle;

    fn begin(&self, id: Uuid, options: &WriteOptions) -> Result<Self::Stage>;
    fn measure(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn measure_globals(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn publish(&self, stage: Self::Stage, manifest: &DevelopmentManifest) -> Result<()>;
    fn list(&self) -> Result<Vec<DevelopmentManifest>>;
    fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest>;
    fn open(&self, id: Uuid) -> Result<Self::Artifact>;
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

pub struct BackupService<E, S> {
    engine: E,
    store: S,
}

impl<E: DatabaseAdapter, S: ArtifactStore> BackupService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    pub fn create(&self, config: &Config) -> Result<DevelopmentManifest> {
        config.validate()?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let info = self.engine.preflight(&config.source, timeout)?;
        let id = Uuid::new_v4();
        let stage = self.store.begin(
            id,
            &WriteOptions {
                with_globals: config.export_globals,
            },
        )?;
        self.engine
            .dump_to(&config.source, stage.payload_path(), timeout)
            .context("PostgreSQL dump failed; staged artifact was not published")?;
        self.engine
            .inspect_archive(&config.source, stage.payload_path(), timeout)
            .context("PostgreSQL archive inspection failed; artifact was not published")?;
        let (size_bytes, sha256) = self.store.measure(&stage)?;
        let mut globals_sha256 = None;
        let mut globals_size_bytes = None;
        if config.export_globals {
            self.engine
                .dump_globals(
                    &config.source,
                    stage
                        .globals_path()
                        .context("staged globals file expected")?,
                    timeout,
                )
                .context("PostgreSQL globals export failed; staged artifact was not published")?;
            let (gsize, gsha) = self.store.measure_globals(&stage)?;
            globals_size_bytes = Some(gsize);
            globals_sha256 = Some(gsha);
        }
        let created_unix_ms = now_unix_ms()?;
        let manifest = DevelopmentManifest {
            format: DEV_FORMAT.to_string(),
            id,
            synthetic_only: true,
            database: config.source.database.clone(),
            source_major: info.source_major,
            source_version: info.source_version,
            dump_client_version: info.dump_client_version,
            application_version: env!("CARGO_PKG_VERSION").to_string(),
            archive_format: "custom".to_string(),
            compression: "gzip".to_string(),
            created_unix_ms,
            size_bytes,
            sha256,
            status: "complete".to_string(),
            security_globals: config.export_globals,
            globals_sha256,
            globals_size_bytes,
            verification_level: None,
            verified_unix_ms: None,
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
            bail!("verification level must be checksum or archive in M2");
        }
        let timeout = Duration::from_secs(config.timeout_seconds);
        // Opening the artifact already recomputes payload and globals digests
        // and rejects marker/manifest/shape mismatches: that is checksum level.
        let artifact = self.store.open(id)?;
        let manifest = artifact.manifest();
        if level == VERIFY_ARCHIVE {
            self.engine
                .inspect_archive(&config.source, artifact.payload_path(), timeout)
                .context("archive table of contents failed to parse")?;
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
    ) -> Result<RestorePlan> {
        config.validate()?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let info = self.engine.preflight(&config.source, timeout)?;
        let artifact = self.store.open(artifact_id)?;
        let manifest = artifact.manifest();
        if security.roles && !manifest.security_globals {
            bail!("restore policy requires roles but the backup contains no globals security file");
        }
        if manifest.source_major != info.source_major {
            bail!(
                "client major does not match the backup source major; M2 supports same-major restore only"
            );
        }
        if target == manifest.database {
            bail!("restore target must differ from the backup source database");
        }
        if self
            .engine
            .database_exists(&config.source, target, timeout)?
        {
            bail!("target database already exists; M2 restores only into a new database");
        }
        if security.roles {
            let conflicts = self.engine.role_conflicts(
                &config.source,
                artifact
                    .globals_path()
                    .context("artifact globals file expected")?,
                timeout,
            )?;
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
            created_unix_ms: created,
            expires_unix_ms: created + PLAN_TTL.as_millis(),
        };
        plan.validate(now_unix_ms()?)?;
        self.store.save_plan(&plan)?;
        Ok(plan)
    }

    pub fn run(&self, config: &Config, plan_id: Uuid, confirm_target: &str) -> Result<RestorePlan> {
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
            let globals = artifact
                .globals_path()
                .context("artifact globals file expected")?;
            let conflicts = self
                .engine
                .role_conflicts(&config.source, globals, timeout)?;
            if !conflicts.is_empty() {
                bail!(
                    "DR role restore refused: these roles already exist in the cluster: {}",
                    conflicts.join(", ")
                );
            }
            // Step 2: roles, attributes, and memberships before any object
            // can be owned by or granted to them.
            self.engine
                .apply_globals(&config.source, globals, timeout)
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
        // Steps 4-6: schema/data, then ownership and privileges from the
        // archive's own ALTER OWNER/GRANT entries (skipped per policy).
        let restored = self.engine.restore_to_database(
            &config.source,
            &plan.target_database,
            artifact.payload_path(),
            plan.security,
            timeout,
        );
        if let Err(error) = restored {
            bail!(
                "database restore failed: {error:#}; target {} may be partially modified and was left in place for operator inspection",
                plan.target_database
            );
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
        Ok(plan)
    }
}
