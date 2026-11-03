use anyhow::{Context, Result, bail};
use uuid::Uuid;

/// Key-free facts recorded for a job. Schema v2 does not record its operation.
pub struct JobInfo {
    pub job_id: Uuid,
    pub backup_id: Option<Uuid>,
    pub source_fingerprint: String,
    pub profile_fingerprint: String,
    pub state: String,
    pub started_at_utc: String,
    pub updated_at_utc: String,
}

pub struct InventoryCheck {
    pub schema_version: i64,
    pub source_fingerprint: String,
    pub problems: Vec<String>,
}

pub trait InventoryReader {
    fn jobs(&self) -> Result<Vec<JobInfo>>;
    fn job(&self, id: Uuid) -> Result<Option<JobInfo>>;
    fn check(&self) -> Result<InventoryCheck>;
}

pub struct InventoryService<R> {
    reader: R,
}

impl<R: InventoryReader> InventoryService<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn jobs(&self) -> Result<Vec<JobInfo>> {
        self.ensure_healthy()?;
        self.reader.jobs().context("INVENTORY_READ_FAILED")
    }

    pub fn job(&self, id: Uuid) -> Result<JobInfo> {
        self.ensure_healthy()?;
        match self.reader.job(id).context("INVENTORY_READ_FAILED")? {
            Some(job) => Ok(job),
            None => {
                self.reader.jobs().context("INVENTORY_READ_FAILED")?;
                bail!("JOB_NOT_FOUND: job {id} is absent from the inventory")
            }
        }
    }

    pub fn check(&self) -> Result<InventoryCheck> {
        self.reader.check().context("INVENTORY_READ_FAILED")
    }

    fn ensure_healthy(&self) -> Result<()> {
        if !self.check()?.problems.is_empty() {
            bail!("INVENTORY_READ_FAILED: inventory failed structural integrity check");
        }
        Ok(())
    }
}

pub struct DiscoveryEntry {
    pub backup_id: Option<Uuid>,
    pub shape: Option<&'static str>,
    pub status: &'static str,
    pub reason: Option<&'static str>,
    pub provenance: Option<&'static str>,
}

pub struct ReconcileReport {
    pub entries: Vec<DiscoveryEntry>,
    pub audit_recorded: bool,
}

pub trait Reconciler {
    fn discover(&self) -> Result<ReconcileReport>;
    fn reconcile(&self) -> Result<ReconcileReport>;
}

pub fn discover<R: Reconciler>(reader: &R) -> Result<ReconcileReport> {
    reader.discover()
}

pub fn reconcile<R: Reconciler>(reader: &R) -> Result<ReconcileReport> {
    reader.reconcile()
}
