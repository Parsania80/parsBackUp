//! Jobs and the audit trail: which operation held which scope, and what happened to it.
//!
//! A job is one operation that held resources and could be interrupted, which is what separates it
//! from an [`AuditEvent`]: `backup verify` is an event, `backup create` is a job. The state column
//! says where a job is now; only the event table can say how long it sat there, which is the
//! difference between an audit trail and a status line.
//!
//! The two halves are deliberately not interchangeable, and the reason is the crash case ADR 0003
//! chose persisted states for. A process killed mid-dump runs no code on the way out, so nothing it
//! was supposed to write gets written: its row stays in `running` and its lock is already free.
//! Only a *later* open of the index can notice that, which is what [`crate::Inventory`]'s sweep
//! does, and only by asking the kernel rather than by trusting a timestamp.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::job_lock::JobLock;
use crate::{Estate, INVENTORY_FILE, Inventory, now_utc};

/// The columns of `job`, in the order [`JOB_COLUMNS`] selects them.
pub(super) const JOB_COLUMNS: &str = "job_id, backup_id, source_fingerprint, profile_fingerprint, state, started_at_utc, \
     updated_at_utc";

const INSERT_JOB: &str = "INSERT INTO job (job_id, backup_id, source_fingerprint, \
     profile_fingerprint, state, started_at_utc, updated_at_utc) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

/// The vocabulary a live build can leave a row in.
///
/// Five words, each with a writer that means something. `planned` is absent because a row written
/// before the lock is taken describes a job that held nothing, and the sweep would then have no
/// honest way to tell it apart from a crash. `verified`, `cancelled` and `quarantined` are absent
/// because nothing writes them yet: a v1 manifest freezes `verification_level: none`, and `job
/// cancel` belongs with the worker pool in M6/M7. The column has no `CHECK`, so adding one later is
/// a new variant here rather than a rebuild of every row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    /// The lock is held and this row exists. Nothing about the artifact is claimed yet.
    Running,
    /// Every stream this operation sealed is finished; only publication remains. Sealed rather
    /// than dumped, because the payload can be complete while globals are still running.
    Staged,
    Complete,
    /// A guard dropped without reaching a terminal state, which is what an ordinary `Err` return
    /// from the command looks like from inside this file.
    Failed,
    /// A row a killed process left behind, found by a later open whose probe of the scope's lock
    /// came back free.
    Interrupted,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Running => "running",
            JobState::Staged => "staged",
            JobState::Complete => "complete",
            JobState::Failed => "failed",
            JobState::Interrupted => "interrupted",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "running" => Ok(JobState::Running),
            "staged" => Ok(JobState::Staged),
            "complete" => Ok(JobState::Complete),
            "failed" => Ok(JobState::Failed),
            "interrupted" => Ok(JobState::Interrupted),
            other => bail!("inventory holds job state {other:?}, which this build cannot write"),
        }
    }

    /// Whether a row in this state is finished with. The sweep's whole question.
    pub fn is_terminal(self) -> bool {
        !matches!(self, JobState::Running | JobState::Staged)
    }
}

/// The states a job can be left in by a process that never finished with it.
const OPEN_STATES: &[JobState] = &[JobState::Running, JobState::Staged];

/// One `job` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRow {
    pub job_id: Uuid,
    /// NULL for a job whose scope is a set of artifacts rather than one, which is M5b's shape for
    /// `prune` and `delete`. Every writer today names exactly one artifact.
    pub backup_id: Option<Uuid>,
    pub source_fingerprint: String,
    pub profile_fingerprint: String,
    pub state: JobState,
    pub started_at_utc: String,
    pub updated_at_utc: String,
}

/// What happened, in the audit trail. Each of these is written by exactly one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    JobStarted,
    JobStaged,
    JobCompleted,
    JobFailed,
    /// Written by the command that *found* the abandoned row, not by the process that died, so the
    /// trail says when the gap became known as well as when it happened.
    JobInterrupted,
    ArtifactRegistered,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::JobStarted => "job_started",
            AuditAction::JobStaged => "job_staged",
            AuditAction::JobCompleted => "job_completed",
            AuditAction::JobFailed => "job_failed",
            AuditAction::JobInterrupted => "job_interrupted",
            AuditAction::ArtifactRegistered => "artifact_registered",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "job_started" => Ok(AuditAction::JobStarted),
            "job_staged" => Ok(AuditAction::JobStaged),
            "job_completed" => Ok(AuditAction::JobCompleted),
            "job_failed" => Ok(AuditAction::JobFailed),
            "job_interrupted" => Ok(AuditAction::JobInterrupted),
            "artifact_registered" => Ok(AuditAction::ArtifactRegistered),
            other => bail!("inventory holds audit action {other:?}, which this build cannot write"),
        }
    }
}

/// One `audit_event` row, ordered by its rowid rather than by its timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// SQLite's rowid: monotone within this file, which a second-precision timestamp is not.
    pub id: i64,
    pub at_utc: String,
    pub action: AuditAction,
    pub job_id: Option<Uuid>,
    pub backup_id: Option<Uuid>,
}

/// The scope a job claims, in the only form this file may store.
///
/// Two fingerprints and an artifact id. There is no profile name and no database name here because
/// the row lives in the one file an operator copies off-site without copying a key, and because the
/// lock is named by the same two digests — a row and a lock that described different scopes would
/// make the sweep mark live jobs dead.
#[derive(Clone, Debug)]
pub struct JobScope {
    pub source_fingerprint: String,
    pub profile_fingerprint: String,
    pub backup_id: Uuid,
}

/// Appends one event. `job_id` and `backup_id` are NULL on the events that genuinely have no such
/// end: an artifact registered by a publish that holds no job, or a command naming no artifact.
pub(super) fn record(
    conn: &Connection,
    action: AuditAction,
    job_id: Option<Uuid>,
    backup_id: Option<Uuid>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_event (at_utc, action, job_id, backup_id) VALUES (?1, ?2, ?3, ?4)",
        params![
            now_utc()?,
            action.as_str(),
            job_id.map(|id| id.to_string()),
            backup_id.map(|id| id.to_string())
        ],
    )?;
    Ok(())
}

/// Opens one job: the row and its `job_started` event, in one transaction.
///
/// The pair is written together because a row with no event would leave the audit trail starting
/// mid-story, and an event with no row would name a job that never existed.
pub(super) fn start(conn: &Connection, row: &JobRow) -> Result<()> {
    debug_assert_eq!(row.state, JobState::Running);
    crate::in_transaction(conn, |conn| {
        conn.execute(
            INSERT_JOB,
            params![
                row.job_id.to_string(),
                row.backup_id.map(|id| id.to_string()),
                row.source_fingerprint,
                row.profile_fingerprint,
                row.state.as_str(),
                row.started_at_utc,
                row.updated_at_utc
            ],
        )?;
        record(
            conn,
            AuditAction::JobStarted,
            Some(row.job_id),
            row.backup_id,
        )
    })
}

/// Moves one job to a new state and appends the event that says so, in one transaction. This is
/// the only write path for a transition, so the row and the trail cannot disagree about which one
/// happened.
pub(super) fn transition(
    conn: &Connection,
    job_id: Uuid,
    to: JobState,
    action: AuditAction,
) -> Result<()> {
    crate::in_transaction(conn, |conn| {
        let stored = conn
            .query_row(
                "SELECT backup_id FROM job WHERE job_id = ?1",
                [job_id.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        let changed = conn.execute(
            "UPDATE job SET state = ?1, updated_at_utc = ?2 WHERE job_id = ?3",
            params![to.as_str(), now_utc()?, job_id.to_string()],
        )?;
        ensure!(
            changed == 1,
            "job {job_id} is not in this inventory, so its state cannot move to {}",
            to.as_str()
        );
        let backup_id = stored
            .flatten()
            .map(|text| {
                Uuid::parse_str(&text)
                    .with_context(|| format!("inventory holds job {job_id}'s backup_id = {text:?}"))
            })
            .transpose()?;
        record(conn, action, Some(job_id), backup_id)
    })
}

pub(super) fn one(conn: &Connection, job_id: Uuid) -> Result<Option<JobRow>> {
    let mut stmt = conn.prepare(&format!("SELECT {JOB_COLUMNS} FROM job WHERE job_id = ?1"))?;
    let mut rows = stmt.query([job_id.to_string()])?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => Ok(Some(read(row)?)),
    }
}

/// Every job, oldest start first, across all scopes.
///
/// `started_at_utc` orders this and `job_id` only breaks ties: a job id is a random UUIDv4, so
/// ordering by it alone would interleave two runs of the same scope in whatever order the UUIDs
/// happened to fall.
pub(super) fn all(conn: &Connection) -> Result<Vec<JobRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {JOB_COLUMNS} FROM job ORDER BY started_at_utc, job_id"
    ))?;
    read_many(&mut stmt)
}

/// The rows a sweep has to decide about.
///
/// The state list is built from [`OPEN_STATES`] rather than written into the SQL, so a new
/// non-terminal state cannot be added to the enum and quietly left out of the sweep: the same
/// slice answers both this query and the check in [`JobGuard`]'s drop.
pub(super) fn open(conn: &Connection) -> Result<Vec<JobRow>> {
    let placeholders = (1..=OPEN_STATES.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT {JOB_COLUMNS} FROM job WHERE state IN ({placeholders}) \
         ORDER BY started_at_utc, job_id"
    ))?;
    let states = OPEN_STATES.iter().map(|state| state.as_str());
    let mut rows = stmt.query(rusqlite::params_from_iter(states))?;
    let mut found = Vec::new();
    while let Some(row) = rows.next()? {
        found.push(read(row)?);
    }
    Ok(found)
}

pub(super) fn events(conn: &Connection) -> Result<Vec<AuditEvent>> {
    let mut stmt = conn.prepare(
        "SELECT event_id, at_utc, action, job_id, backup_id FROM audit_event ORDER BY event_id",
    )?;
    let mut rows = stmt.query([])?;
    let mut found = Vec::new();
    while let Some(row) = rows.next()? {
        found.push(AuditEvent {
            id: row.get("event_id")?,
            at_utc: checked_timestamp("at_utc", text_column(row, "at_utc")?)?,
            action: AuditAction::parse(&text_column(row, "action")?)?,
            job_id: opt_uuid_column(row, "job_id")?,
            backup_id: opt_uuid_column(row, "backup_id")?,
        });
    }
    Ok(found)
}

fn read(row: &Row<'_>) -> Result<JobRow> {
    let started = text_column(row, "started_at_utc")?;
    let updated = text_column(row, "updated_at_utc")?;
    Ok(JobRow {
        job_id: uuid_column(row, "job_id")?,
        backup_id: opt_uuid_column(row, "backup_id")?,
        source_fingerprint: text_column(row, "source_fingerprint")?,
        profile_fingerprint: text_column(row, "profile_fingerprint")?,
        state: JobState::parse(&text_column(row, "state")?)?,
        started_at_utc: checked_timestamp("started_at_utc", started)?,
        updated_at_utc: checked_timestamp("updated_at_utc", updated)?,
    })
}

fn read_many(stmt: &mut rusqlite::Statement) -> Result<Vec<JobRow>> {
    let mut rows = stmt.query([])?;
    let mut found = Vec::new();
    while let Some(row) = rows.next()? {
        found.push(read(row)?);
    }
    Ok(found)
}

fn text_column(row: &Row<'_>, column: &str) -> Result<String> {
    Ok(row.get(column)?)
}

/// A column this crate only ever writes as a lowercase UUID, read back through the one parser that
/// can say what it found instead.
fn uuid_column(row: &Row<'_>, column: &str) -> Result<Uuid> {
    let text = text_column(row, column)?;
    Uuid::parse_str(&text).with_context(|| format!("inventory holds {column} = {text:?}"))
}

fn opt_uuid_column(row: &Row<'_>, column: &str) -> Result<Option<Uuid>> {
    let Some(text) = row.get::<_, Option<String>>(column)? else {
        return Ok(None);
    };
    Uuid::parse_str(&text)
        .map(Some)
        .with_context(|| format!("inventory holds {column} = {text:?}"))
}

/// A stored timestamp that is not the artifact form is a damaged or edited row, and reading it as
/// though it were a time would put a job in the wrong place in an ordering nothing else checks.
fn checked_timestamp(column: &str, value: String) -> Result<String> {
    ensure!(
        backup_domain::is_utc_timestamp(&value),
        "inventory holds {column} = {value:?}, which is not the artifact timestamp form"
    );
    Ok(value)
}

/// The held lock and the row that describes it, together.
///
/// The two cannot be separated: a row in a non-terminal state with no lock would be a lie about a
/// running job, and a lock with no row would leave no history of the operation that took it. So a
/// guard owns both, and dropping it ends both — which is also how a command that returns `Err` from
/// anywhere reaches `failed` without every error site having to remember to say so.
#[derive(Debug)]
pub struct JobGuard {
    inventory: Inventory,
    lock: JobLock,
    job_id: Uuid,
    /// `None` once the job reaches a terminal state, so a drop after `complete` writes nothing.
    open: Cell<Option<JobState>>,
}

impl JobGuard {
    /// Claims one scope for the duration of one operation.
    ///
    /// The lock is taken *before* any SQL, including before the inventory file is opened: a refusal
    /// must not have created a database it was then refused entry to, and it must not have taken a
    /// write lock that a second later holder would have to wait out.
    pub fn begin(root: &Path, scope: &JobScope) -> Result<Self> {
        let lock = JobLock::acquire(root, &scope.source_fingerprint, &scope.profile_fingerprint)?;
        let estate = Estate::new(scope.source_fingerprint.clone())?;
        let inventory = Inventory::open(&root.join(INVENTORY_FILE), &estate)?;
        let started = now_utc()?;
        let job_id = Uuid::new_v4();
        inventory.begin_job(&JobRow {
            job_id,
            backup_id: Some(scope.backup_id),
            source_fingerprint: scope.source_fingerprint.clone(),
            profile_fingerprint: scope.profile_fingerprint.clone(),
            state: JobState::Running,
            started_at_utc: started.clone(),
            updated_at_utc: started,
        })?;
        Ok(Self {
            inventory,
            lock,
            job_id,
            open: Cell::new(Some(JobState::Running)),
        })
    }

    /// This job's id, which is what an audit event names to point back here.
    pub fn id(&self) -> Uuid {
        self.job_id
    }

    /// Which file holds this scope's lock, so a report can name it.
    pub fn lock_path(&self) -> PathBuf {
        self.lock.path().to_path_buf()
    }

    /// Every stream is sealed and only publication remains.
    pub fn staged(&self) -> Result<()> {
        self.move_to(JobState::Staged)
    }

    /// The artifact is published. After this the guard's drop writes nothing.
    pub fn complete(&self) -> Result<()> {
        self.move_to(JobState::Complete)
    }

    /// Reads this job back through its own inventory, which is how a caller proves a transition
    /// landed rather than assuming it did.
    pub fn state(&self) -> Result<JobState> {
        self.inventory
            .job(self.job_id)?
            .map(|row| row.state)
            .ok_or_else(|| anyhow::anyhow!("job {} vanished from its own inventory", self.job_id))
    }

    fn move_to(&self, to: JobState) -> Result<()> {
        let from = self.open.get();
        let action = match (from, to) {
            (Some(JobState::Running), JobState::Staged) => AuditAction::JobStaged,
            (Some(JobState::Running) | Some(JobState::Staged), JobState::Complete) => {
                AuditAction::JobCompleted
            }
            (_, other) => {
                bail!(
                    "job {} cannot move to {} from {}",
                    self.job_id,
                    other.as_str(),
                    from.map_or("a finished state", JobState::as_str)
                )
            }
        };
        self.inventory.set_job_state(self.job_id, to, action)?;
        // Only after the write, so a failed transition leaves the drop to record `failed` against
        // the state the row is actually in rather than the one this call was asked for.
        self.open
            .set(if to.is_terminal() { None } else { Some(to) });
        Ok(())
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        let Some(state) = self.open.get() else {
            return;
        };
        debug_assert!(!state.is_terminal());
        // Nothing here can report a failure: a `Drop` has no return value, and panicking while
        // unwinding from the error this is recording would turn a handled refusal into an abort.
        // A row the write missed stays non-terminal, which is exactly the case the sweep on the
        // next open handles, so the cost of swallowing it is a delayed `interrupted` rather than a
        // lost job.
        let _ = self
            .inventory
            .set_job_state(self.job_id, JobState::Failed, AuditAction::JobFailed);
    }
}
