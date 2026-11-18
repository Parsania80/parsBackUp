use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const IPC_LIMIT: usize = 1024 * 1024;
pub(crate) const MAX_TIME: u64 = 9_007_199_254_740_991;

pub(crate) fn now() -> Result<u64> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    ensure!(millis <= u128::from(MAX_TIME), "CLOCK_INVALID");
    Ok(millis as u64)
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn binding(domain: &str, value: &impl Serialize) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(serde_json::to_vec(value)?);
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn uuid4(id: Uuid) -> bool {
    id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Backup,
    Inspection,
    Verification,
    RestorePlan,
    Restore,
    RetentionPreview,
    RetentionRun,
    ArtifactProtection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    Portable,
    DrFull,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sections {
    Full,
    PreData,
    PreDataData,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyLevel {
    Signature,
    Checksum,
    Archive,
}
impl VerifyLevel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Checksum => "checksum",
            Self::Archive => "archive",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Backup {
        profile_id: Option<String>,
        confirm_synthetic: bool,
    },
    Inspection {
        artifact_id: Uuid,
    },
    Verification {
        artifact_id: Uuid,
        level: VerifyLevel,
    },
    RestorePlan {
        artifact_id: Uuid,
        target_database: String,
        security: Security,
        sections: Sections,
        acknowledge_older_snapshot: bool,
        confirm_synthetic: bool,
    },
    Restore {
        intent_id: Uuid,
        confirm_digest: String,
        confirm_target: String,
        confirm_synthetic: bool,
    },
    RetentionPreview {
        selection: RetentionSelection,
    },
    RetentionRun {
        intent_id: Uuid,
        confirm_digest: String,
    },
    ArtifactProtection {
        artifact_id: Uuid,
        protected: bool,
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetentionSelection {
    Prune {
        profile_id: Option<String>,
        keep_last: u64,
    },
    Delete {
        artifact_id: Uuid,
    },
}

impl Request {
    pub fn operation(&self) -> Operation {
        match self {
            Self::Backup { .. } => Operation::Backup,
            Self::Inspection { .. } => Operation::Inspection,
            Self::Verification { .. } => Operation::Verification,
            Self::RestorePlan { .. } => Operation::RestorePlan,
            Self::Restore { .. } => Operation::Restore,
            Self::RetentionPreview { .. } => Operation::RetentionPreview,
            Self::RetentionRun { .. } => Operation::RetentionRun,
            Self::ArtifactProtection { .. } => Operation::ArtifactProtection,
        }
    }

    pub(crate) fn route(&self) -> &'static str {
        match self.operation() {
            Operation::Backup => "/api/v1/backups",
            Operation::Inspection => "/api/v1/inspections",
            Operation::Verification => "/api/v1/verifications",
            Operation::RestorePlan => "/api/v1/restore-plans",
            Operation::Restore => "/api/v1/restores",
            Operation::RetentionPreview => "/api/v1/retention-previews",
            Operation::RetentionRun => "/api/v1/retention-runs",
            Operation::ArtifactProtection => "/api/v1/artifact-protections",
        }
    }

    pub(crate) fn requested_profile(&self) -> &str {
        match self {
            Self::Backup { profile_id, .. }
            | Self::RetentionPreview {
                selection: RetentionSelection::Prune { profile_id, .. },
            } => profile_id.as_deref().unwrap_or("default"),
            _ => "default",
        }
    }

    pub(crate) fn normalize(&mut self) {
        match self {
            Self::Backup { profile_id, .. }
            | Self::RetentionPreview {
                selection: RetentionSelection::Prune { profile_id, .. },
            } if profile_id.as_deref() == Some("default") => *profile_id = None,
            _ => {}
        }
    }

    pub(crate) fn confirmation(&self) -> Option<(Uuid, &str, Option<&str>)> {
        match self {
            Self::Restore {
                intent_id,
                confirm_digest,
                confirm_target,
                ..
            } => Some((*intent_id, confirm_digest, Some(confirm_target))),
            Self::RetentionRun {
                intent_id,
                confirm_digest,
            } => Some((*intent_id, confirm_digest, None)),
            _ => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let target = |name: &str| {
            backup_domain::is_literal_database_name(name)
                && name
                    .strip_prefix(backup_domain::FIXTURE_PREFIX)
                    .is_some_and(|s| {
                        !s.is_empty()
                            && s.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    })
        };
        let valid = match self {
            Self::Backup {
                confirm_synthetic, ..
            } => *confirm_synthetic,
            Self::Inspection { artifact_id }
            | Self::Verification { artifact_id, .. }
            | Self::RetentionPreview {
                selection: RetentionSelection::Delete { artifact_id },
            } => uuid4(*artifact_id),
            Self::RestorePlan {
                artifact_id,
                target_database,
                security,
                sections,
                confirm_synthetic,
                ..
            } => {
                *confirm_synthetic
                    && uuid4(*artifact_id)
                    && target(target_database)
                    && (*sections == Sections::Full || *security == Security::Portable)
            }
            Self::Restore {
                intent_id,
                confirm_digest,
                confirm_target,
                confirm_synthetic,
            } => {
                *confirm_synthetic
                    && uuid4(*intent_id)
                    && digest(confirm_digest)
                    && target(confirm_target)
            }
            Self::RetentionRun {
                intent_id,
                confirm_digest,
            } => uuid4(*intent_id) && digest(confirm_digest),
            Self::RetentionPreview {
                selection: RetentionSelection::Prune { keep_last, .. },
            } => (1..=4096).contains(keep_last),
            Self::ArtifactProtection {
                artifact_id,
                reason,
                ..
            } => {
                uuid4(*artifact_id)
                    && !reason.trim().is_empty()
                    && reason.chars().count() <= 256
                    && !reason.chars().any(char::is_control)
            }
        };
        ensure!(valid, ErrorCode::InvalidRequest);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Queued,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    Partial,
    Cancelled,
    Interrupted,
}
impl State {
    pub fn terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running | Self::CancelRequested)
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effects {
    None,
    PreparationOnly,
    ArtifactMayBePublished,
    DatabaseMayBeModified,
    ArtifactsMayBeDeleted,
    InventoryMayBeModified,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidRequest,
    AuthRequired,
    AccessDenied,
    NotFound,
    IdempotencyConflict,
    IntentConflict,
    ConfigChanged,
    IntentExpired,
    PolicyRefused,
    BodyTooLarge,
    UnsupportedMedia,
    RateLimit,
    QueueFull,
    NotReady,
    ContainmentUnavailable,
    ControlCapacity,
    DiscoveryLimit,
    OperationCancelled,
    OperationFailed,
    OperationInterrupted,
    InternalError,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_value(self)
            .map_err(|_| std::fmt::Error)?
            .as_str()
            .ok_or(std::fmt::Error)?
            .fmt(f)
    }
}
impl std::error::Error for ErrorCode {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeError {
    pub code: ErrorCode,
    pub retryable: bool,
}
impl From<ErrorCode> for SafeError {
    fn from(code: ErrorCode) -> Self {
        Self {
            code,
            retryable: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Restore,
    Retention,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Confirmation {
    Restore(RestoreConfirmation),
    Retention(RetentionConfirmation),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreConfirmation {
    pub target_database: String,
    pub artifact_id: Uuid,
    pub security: Security,
    pub sections: Sections,
    pub acknowledge_older_snapshot: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfirmation {
    pub candidates: Vec<Uuid>,
    pub retained: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentBinding {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub planning_job_id: Uuid,
    pub kind: IntentKind,
    pub store_instance_id: Uuid,
    pub config_revision: String,
    pub core_plan_id: Uuid,
    pub core_plan_digest: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub confirmation: Confirmation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    #[serde(flatten)]
    pub bound: IntentBinding,
    pub digest: String,
    pub consumed_by_job_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobResult {
    Backup {
        artifact_id: Uuid,
    },
    Inspection {
        artifact_id: Uuid,
        database: String,
        source_major: u32,
        scope: Option<String>,
        created_unix_ms: u64,
    },
    Verification {
        artifact_id: Uuid,
        level: VerifyLevel,
        passed: bool,
        inventory_recorded: bool,
    },
    RestorePlan {
        intent: Box<Intent>,
    },
    Restore {
        artifact_id: Uuid,
        target_database: String,
        verification_level: String,
        recorded_in_artifact: bool,
    },
    RetentionPreview {
        intent: Option<Box<Intent>>,
        excluded: Vec<Exclusion>,
    },
    RetentionRun {
        completed: Vec<Uuid>,
        deleting: Vec<Uuid>,
        pending: Vec<Uuid>,
        audit_recorded: bool,
    },
    ArtifactProtection {
        artifact_id: Uuid,
        protected: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub operation: Operation,
    pub state: State,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub core_job_id: Option<Uuid>,
    pub effects: Effects,
    pub result: Option<JobResult>,
    pub error: Option<SafeError>,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outcome {
    pub state: State,
    pub core_job_id: Option<Uuid>,
    pub effects: Effects,
    pub result: Option<JobResult>,
    pub error: Option<SafeError>,
}
impl Outcome {
    pub fn success(result: JobResult, core_job_id: Option<Uuid>, effects: Effects) -> Self {
        Self {
            state: State::Succeeded,
            core_job_id,
            effects,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(state: State, code: ErrorCode, effects: Effects) -> Self {
        Self {
            state,
            core_job_id: None,
            effects,
            result: None,
            error: Some(code.into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub artifact_id: Option<Uuid>,
    pub reasons: Vec<String>,
}
