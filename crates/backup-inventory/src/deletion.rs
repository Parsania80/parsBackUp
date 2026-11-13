//! Durable, keyless deletion intent and progress. Files are never removed inside a transaction.
use crate::{AuditAction, Inventory, JobRow, JobState, State, in_transaction, job, now_utc};
use anyhow::{Context, Result, ensure};
use backup_domain::{RetentionOperation, SavedDeletionPlan};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct DeletionDependency {
    pub backup_id: Uuid,
    pub role: String,
    pub progress: String,
}
#[derive(Debug)]
pub struct DeletionJob {
    pub job: JobRow,
    pub plan_id: Uuid,
    pub digest: String,
    pub operation: RetentionOperation,
    pub dependencies: Vec<DeletionDependency>,
}
impl DeletionJob {
    pub fn validate(&self, saved: &SavedDeletionPlan) -> Result<()> {
        saved.validate_structure(self.plan_id, saved.plan.operation)?;
        ensure!(
            self.operation == saved.plan.operation
                && self.digest == saved.digest
                && self.job.source_fingerprint == saved.plan.source_fingerprint
                && self.job.profile_fingerprint == saved.plan.profile_fingerprint
                && self.job.backup_id.is_none(),
            "DELETION_RECOVERY_REQUIRED: intent scope mismatch"
        );
        let mut expected: Vec<_> = saved
            .plan
            .candidates
            .iter()
            .map(|a| (a.backup_id, "candidate"))
            .chain(
                saved
                    .plan
                    .retained
                    .iter()
                    .map(|a| (a.backup_id, "retained")),
            )
            .collect();
        expected.sort_unstable();
        ensure!(
            self.dependencies
                .iter()
                .map(|d| (d.backup_id, d.role.as_str()))
                .eq(expected),
            "DELETION_RECOVERY_REQUIRED: exact dependencies disagree"
        );
        ensure!(
            self.job.state != JobState::Complete
                || self
                    .dependencies
                    .iter()
                    .filter(|d| d.role == "candidate")
                    .all(|d| d.progress == "deleted"),
            "DELETION_RECOVERY_REQUIRED: incomplete receipt"
        );
        Ok(())
    }
}
impl Inventory {
    pub fn deletion_job(&self, plan_id: Uuid) -> Result<Option<DeletionJob>> {
        if self.schema_version()? < 7 {
            return Ok(None);
        }
        let found: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT job_id,digest FROM deletion_job WHERE plan_id=?1",
                [plan_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((id, digest)) = found else {
            return Ok(None);
        };
        let job_id: Uuid = id.parse()?;
        ensure!(
            job_id.to_string() == id && job_id.get_version_num() == 4 && crate::is_hex(&digest, 64),
            "DELETION_RECOVERY_REQUIRED: invalid intent identity"
        );
        let row = self
            .job(job_id)?
            .context("DELETION_RECOVERY_REQUIRED: missing job")?;
        let (kind, target) = self
            .job_operation(job_id)?
            .context("DELETION_RECOVERY_REQUIRED: missing operation")?;
        ensure!(
            matches!(kind.as_str(), "prune" | "delete") && target.is_none(),
            "DELETION_RECOVERY_REQUIRED: invalid operation"
        );
        let dependencies = self.deletion_dependencies(job_id)?;
        ensure!(
            !dependencies.is_empty(),
            "DELETION_RECOVERY_REQUIRED: missing dependencies"
        );
        let events = self.audit_events()?;
        ensure!(
            events
                .iter()
                .any(|e| e.job_id == Some(job_id) && e.action == AuditAction::JobStarted),
            "DELETION_RECOVERY_REQUIRED: missing start evidence"
        );
        for d in &dependencies {
            if d.role == "candidate" && d.progress != "pending" {
                let state = if d.progress == "deleting" {
                    State::Deleting
                } else {
                    State::Deleted
                };
                ensure!(
                    self.artifact(d.backup_id)?
                        .is_some_and(|a| a.state == state)
                        && events.iter().any(|e| e.job_id == Some(job_id)
                            && e.backup_id == Some(d.backup_id)
                            && e.action == AuditAction::ArtifactDeleting)
                        && (state != State::Deleted
                            || events.iter().any(|e| e.job_id == Some(job_id)
                                && e.backup_id == Some(d.backup_id)
                                && e.action == AuditAction::ArtifactDeleted)),
                    "DELETION_RECOVERY_REQUIRED: lifecycle evidence disagrees"
                );
            }
        }
        if row.state == JobState::Complete {
            ensure!(
                events
                    .iter()
                    .any(|e| e.job_id == Some(job_id) && e.action == AuditAction::JobCompleted),
                "DELETION_RECOVERY_REQUIRED: missing completion evidence"
            );
        }
        let operation = if kind == "prune" {
            RetentionOperation::Prune
        } else {
            RetentionOperation::Delete
        };
        Ok(Some(DeletionJob {
            job: row,
            plan_id,
            digest,
            operation,
            dependencies,
        }))
    }

    pub fn deletion_job_for_job(&self, job_id: Uuid) -> Result<DeletionJob> {
        let id: String = self.conn.query_row(
            "SELECT plan_id FROM deletion_job WHERE job_id=?1",
            [job_id.to_string()],
            |r| r.get(0),
        )?;
        let plan_id: Uuid = id.parse()?;
        ensure!(
            plan_id.to_string() == id,
            "DELETION_RECOVERY_REQUIRED: invalid plan ID"
        );
        let job = self
            .deletion_job(plan_id)?
            .context("DELETION_RECOVERY_REQUIRED: missing intent")?;
        ensure!(
            job.job.job_id == job_id,
            "DELETION_RECOVERY_REQUIRED: job binding mismatch"
        );
        Ok(job)
    }

    pub fn deletion_dependencies(&self, job_id: Uuid) -> Result<Vec<DeletionDependency>> {
        let mut stmt = self.conn.prepare(
            "SELECT backup_id,role,progress FROM job_artifact WHERE job_id=?1 ORDER BY backup_id",
        )?;
        let raw = stmt
            .query_map([job_id.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raw.into_iter()
            .map(|(id, role, progress)| {
                let backup_id: Uuid = id.parse()?;
                ensure!(
                    backup_id.to_string() == id
                        && backup_id.get_version_num() == 4
                        && matches!(role.as_str(), "candidate" | "retained")
                        && matches!(progress.as_str(), "pending" | "deleting" | "deleted")
                        && (role != "retained" || progress == "pending"),
                    "DELETION_RECOVERY_REQUIRED: invalid dependency"
                );
                Ok(DeletionDependency {
                    backup_id,
                    role,
                    progress,
                })
            })
            .collect()
    }

    pub fn deletion_recovery_ids(&self) -> Result<Vec<Uuid>> {
        let mut stmt = self
            .conn
            .prepare("SELECT plan_id FROM deletion_job WHERE EXISTS (SELECT 1 FROM job_artifact WHERE job_artifact.job_id=deletion_job.job_id AND progress='deleting') ORDER BY plan_id")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.into_iter()
            .map(|id| {
                let parsed: Uuid = id.parse()?;
                ensure!(
                    parsed.to_string() == id && parsed.get_version_num() == 4,
                    "DELETION_RECOVERY_REQUIRED: invalid plan ID"
                );
                Ok(parsed)
            })
            .collect()
    }

    pub fn begin_deletion(&self, saved: &SavedDeletionPlan) -> Result<Uuid> {
        saved.validate_structure(saved.plan.plan_id, saved.plan.operation)?;
        ensure!(
            saved.plan.source_fingerprint == self.estate.source_fingerprint,
            "deletion estate mismatch"
        );
        let id = Uuid::new_v4();
        let time = now_utc()?;
        let kind = match saved.plan.operation {
            RetentionOperation::Prune => "prune",
            RetentionOperation::Delete => "delete",
        };
        in_transaction(&self.conn, |conn| {
            conn.execute("INSERT INTO job (job_id,backup_id,source_fingerprint,profile_fingerprint,state,started_at_utc,updated_at_utc) VALUES (?1,NULL,?2,?3,'running',?4,?4)",
                params![id.to_string(),saved.plan.source_fingerprint,saved.plan.profile_fingerprint,time])?;
            conn.execute(
                "INSERT INTO job_operation VALUES (?1,?2,NULL)",
                params![id.to_string(), kind],
            )?;
            conn.execute(
                "INSERT INTO deletion_job VALUES (?1,?2,?3)",
                params![id.to_string(), saved.plan.plan_id.to_string(), saved.digest],
            )?;
            for (set, role) in [
                (&saved.plan.candidates, "candidate"),
                (&saved.plan.retained, "retained"),
            ] {
                for a in set {
                    ensure!(
                        self.artifact(a.backup_id)?
                            .is_some_and(|r| r.state == State::Registered),
                        "RETENTION_PLAN_STALE: lifecycle changed"
                    );
                    conn.execute(
                        "INSERT INTO job_artifact VALUES (?1,?2,?3,'pending')",
                        params![id.to_string(), a.backup_id.to_string(), role],
                    )?;
                }
            }
            job::record(conn, AuditAction::JobStarted, Some(id), None)?;
            Ok(id)
        })
    }

    pub fn mark_deleting(&self, job_id: Uuid, id: Uuid) -> Result<()> {
        in_transaction(&self.conn, |conn| {
            ensure!(
                self.job(job_id)?
                    .is_some_and(|j| j.state == JobState::Running),
                "deletion job is not running"
            );
            ensure!(
                self.protection(id)? == Some(false),
                "RETENTION_PROTECTED: candidate protection changed"
            );
            ensure!(conn.execute("UPDATE job_artifact SET progress='deleting' WHERE job_id=?1 AND backup_id=?2 AND role='candidate' AND progress='pending'",params![job_id.to_string(),id.to_string()])? == 1, "invalid deletion intent transition");
            ensure!(conn.execute("UPDATE artifact SET state='deleting' WHERE backup_id=?1 AND state='registered'",[id.to_string()])? == 1, "candidate lifecycle changed");
            job::record(conn, AuditAction::ArtifactDeleting, Some(job_id), Some(id))
        })
    }

    pub fn mark_deleted(&self, job_id: Uuid, id: Uuid) -> Result<()> {
        in_transaction(&self.conn, |conn| {
            ensure!(conn.execute("UPDATE job_artifact SET progress='deleted' WHERE job_id=?1 AND backup_id=?2 AND role='candidate' AND progress='deleting'",params![job_id.to_string(),id.to_string()])? == 1, "invalid deleted transition");
            ensure!(
                conn.execute(
                    "UPDATE artifact SET state='deleted' WHERE backup_id=?1 AND state='deleting'",
                    [id.to_string()]
                )? == 1,
                "missing deletion tombstone"
            );
            conn.execute(
                "UPDATE verification_event SET current=0 WHERE backup_id=?1",
                [id.to_string()],
            )?;
            job::record(conn, AuditAction::ArtifactDeleted, Some(job_id), Some(id))
        })
    }

    pub fn finish_deletion(&self, job_id: Uuid, complete: bool) -> Result<()> {
        in_transaction(&self.conn, |conn| {
            if complete {
                ensure!(
                    self.deletion_dependencies(job_id)?
                        .iter()
                        .filter(|d| d.role == "candidate")
                        .all(|d| d.progress == "deleted"),
                    "deletion has unfinished candidates"
                );
            }
            let (state, action) = if complete {
                ("complete", AuditAction::JobCompleted)
            } else {
                ("failed", AuditAction::JobFailed)
            };
            ensure!(
                conn.execute(
                    "UPDATE job SET state=?1,updated_at_utc=?2 WHERE job_id=?3 AND state='running'",
                    params![state, now_utc()?, job_id.to_string()]
                )? == 1,
                "cannot rewrite terminal deletion job"
            );
            job::record(conn, action, Some(job_id), None)
        })
    }
}
