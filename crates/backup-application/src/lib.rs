use anyhow::{Context, Result};
use backup_domain::{Config, DEV_FORMAT, DevelopmentManifest, Source};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct EngineInfo {
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
}

pub trait DatabaseAdapter {
    fn preflight(&self, source: &Source, timeout: Duration) -> Result<EngineInfo>;
    fn dump_to(&self, source: &Source, output: &Path, timeout: Duration) -> Result<()>;
    fn inspect_archive(&self, source: &Source, archive: &Path, timeout: Duration) -> Result<()>;
}

pub trait StageHandle {
    fn payload_path(&self) -> &Path;
}

pub trait ArtifactStore {
    type Stage: StageHandle;

    fn begin(&self, id: Uuid) -> Result<Self::Stage>;
    fn measure(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn publish(&self, stage: Self::Stage, manifest: &DevelopmentManifest) -> Result<()>;
    fn list(&self) -> Result<Vec<DevelopmentManifest>>;
    fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest>;
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
        let stage = self.store.begin(id)?;
        self.engine
            .dump_to(&config.source, stage.payload_path(), timeout)
            .context("PostgreSQL dump failed; staged artifact was not published")?;
        self.engine
            .inspect_archive(&config.source, stage.payload_path(), timeout)
            .context("PostgreSQL archive inspection failed; artifact was not published")?;
        let (size_bytes, sha256) = self.store.measure(&stage)?;
        let created_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_millis();
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
