use anyhow::Result;
use backup_domain::{RetentionExclusion, RetentionOperation, RetentionRequest};
use uuid::Uuid;

/// Preview creates intent only: no inventory write, verification event or deletion.
#[derive(Debug)]
pub struct RetentionPreview {
    pub operation: RetentionOperation,
    pub source_fingerprint: String,
    pub profile_fingerprint: String,
    pub keep_last: Option<u64>,
    pub candidates: Vec<Uuid>,
    pub retained: Vec<Uuid>,
    pub excluded: Vec<RetentionExclusion>,
    pub plan_id: Option<Uuid>,
    pub digest: Option<String>,
    pub expires_unix_ms: Option<u64>,
    pub audit_recorded: bool,
}

pub trait RetentionPlanner {
    fn preview(&self, request: &RetentionRequest) -> Result<RetentionPreview>;
}

pub fn preview_retention(
    planner: &impl RetentionPlanner,
    request: &RetentionRequest,
) -> Result<RetentionPreview> {
    planner.preview(request)
}

/// Exact durable candidate partition, also returned on handled post-start failures.
#[derive(Debug)]
pub struct DeletionResult {
    pub operation: RetentionOperation,
    pub plan_id: Uuid,
    pub digest: String,
    pub job_id: Uuid,
    pub outcome: &'static str,
    pub completed: Vec<Uuid>,
    pub deleting: Vec<Uuid>,
    pub pending: Vec<Uuid>,
    pub audit_recorded: bool,
}
#[derive(Debug)]
pub struct DeletionOutcome {
    pub result: DeletionResult,
    pub error: Option<&'static str>,
}

pub trait DeletionExecutor {
    fn run(
        &self,
        id: Uuid,
        operation: RetentionOperation,
        confirmation: &str,
    ) -> Result<DeletionOutcome>;
}
pub fn execute_deletion(
    executor: &impl DeletionExecutor,
    id: Uuid,
    operation: RetentionOperation,
    confirmation: &str,
) -> Result<DeletionOutcome> {
    executor.run(id, operation, confirmation)
}
