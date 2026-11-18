//! SQLite writes belong to the supervisor. Worker processes read one admitted job.
use crate::{
    Actor, Config,
    config::{pinned_parent, private_file, uid},
    model::*,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

const QUEUE_LIMIT: i64 = 16;
const RECEIPT_LIMIT: i64 = 100_000;
const QUEUE_MS: u64 = 30 * 60 * 1000;

struct Location {
    _directory: File,
    pinned: PathBuf,
}

impl Location {
    fn open(path: &Path) -> Result<Self> {
        let (directory, pinned) = pinned_parent(path)?;
        let meta = directory.metadata()?;
        ensure!(
            meta.uid() == uid() && meta.mode() & 0o7777 == 0o700,
            "UNSAFE_CONTROL_DIRECTORY"
        );
        Ok(Self {
            _directory: directory,
            pinned,
        })
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.pinned.as_os_str().to_os_string();
        path.push(suffix);
        path.into()
    }

    fn connect(&self, writable: bool) -> Result<Connection> {
        for suffix in ["-journal", "-wal", "-shm"] {
            let path = self.sidecar(suffix);
            match path.symlink_metadata() {
                Ok(_) if suffix == "-journal" => {
                    private_file(&path, false)?;
                }
                Ok(_) => anyhow::bail!("UNEXPECTED_CONTROL_SIDECAR"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        private_file(&self.pinned, writable)?;
        let mode = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        // SQLite's NOFOLLOW also rejects the trusted /proc/self/fd hop.
        // The leaf was opened without following links, in the pinned 0700
        // directory. Only the service UID can replace its files.
        let db = Connection::open_with_flags(&self.pinned, mode)?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.pragma_update(None, "foreign_keys", true)?;
        Ok(db)
    }
}

pub(crate) struct Store {
    db: Connection,
    _lock: File,
    _location: Location,
    pub(crate) instance: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Work {
    pub actor: Actor,
    pub request: Request,
    pub profile: String,
    pub revision: String,
    pub api_config_hash: String,
    pub deadline: u64,
    pub intent: Option<Uuid>,
}

// SQL state is the dispatch/index key. The Job document is changed in the same transaction.
const SCHEMA: &str = "
CREATE TABLE metadata (instance TEXT NOT NULL, owner_group TEXT NOT NULL);
CREATE TABLE jobs (
    seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, state TEXT NOT NULL,
    job TEXT NOT NULL, work TEXT NOT NULL, worker_pid INTEGER
);
CREATE INDEX jobs_dispatch ON jobs(state, seq);
CREATE TABLE receipts (
    actor TEXT NOT NULL, route TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(id), PRIMARY KEY(actor, route, key)
);
CREATE TABLE intents (
    id TEXT PRIMARY KEY, profile TEXT NOT NULL, binding TEXT NOT NULL,
    digest TEXT NOT NULL, consumed_by TEXT REFERENCES jobs(id)
);
PRAGMA user_version = 1;";

const SCHEMA_V2: &str = "
CREATE TABLE sessions (
    token_sha256 TEXT PRIMARY KEY, actor TEXT NOT NULL,
    created INTEGER NOT NULL, expires INTEGER NOT NULL
);
CREATE INDEX jobs_actor_page ON jobs(json_extract(job, '$.actor_id'), id);
PRAGMA user_version = 2;";

#[derive(Clone, Copy)]
pub(crate) struct Session {
    pub actor: Actor,
    pub expires: u64,
}

#[derive(Default, Serialize)]
pub(crate) struct Metrics {
    pub accepted_total: u64,
    pub succeeded_total: u64,
    pub failed_total: u64,
    pub partial_total: u64,
    pub cancelled_total: u64,
    pub interrupted_total: u64,
    pub rejected_total: u64,
}

impl Store {
    pub fn open(path: &Path, group: Option<&str>) -> Result<Self> {
        let location = Location::open(path)?;
        let lock = private_file(&location.sidecar(".lock"), true)?;
        // SAFETY: the descriptor is live and this process keeps it for the Store lifetime.
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "CONTROL_ALREADY_OWNED"
        );
        let mut db = location.connect(true)?;
        let journal: String = db.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let sync: u32 = db.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        ensure!(
            journal == "delete" && sync == 2,
            "CONTROL_DURABILITY_UNAVAILABLE"
        );
        let tx = db.transaction()?;
        let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 0 {
            let objects: i64 =
                tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
            ensure!(objects == 0, "UNKNOWN_CONTROL_SCHEMA");
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO metadata VALUES (?,?)",
                params![Uuid::new_v4().to_string(), group.unwrap_or_default()],
            )?;
        }
        ensure!(version <= 2, "UNKNOWN_CONTROL_SCHEMA");
        if version < 2 {
            tx.execute_batch(SCHEMA_V2)?;
        }
        tx.execute("DELETE FROM sessions", [])?;
        if let Some(group) = group {
            let owner: String =
                tx.query_row("SELECT owner_group FROM metadata", [], |r| r.get(0))?;
            ensure!(
                owner.is_empty() || owner == group,
                ErrorCode::ContainmentUnavailable
            );
            if owner.is_empty() {
                tx.execute("UPDATE metadata SET owner_group=?", [group])?;
            }
            interrupt_abandoned(&tx)?;
        }
        let instance = instance(&tx)?;
        tx.commit()?;
        location._directory.sync_all()?;
        Ok(Self {
            db,
            _lock: lock,
            _location: location,
            instance,
        })
    }

    pub fn job(&self, id: Uuid) -> Result<Job> {
        read_job(&self.db, id)
    }
    pub fn intent(&self, id: Uuid) -> Result<(Intent, String)> {
        read_intent(&self.db, id)
    }

    pub fn new_session(
        &mut self,
        hash: &str,
        actor: Actor,
        previous: Option<&str>,
    ) -> Result<Session> {
        let time = now()?;
        let expires = time
            .checked_add(8 * 60 * 60 * 1000)
            .filter(|expiry| *expiry <= MAX_TIME)
            .context("CLOCK_INVALID")?;
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM sessions WHERE expires <= ?", [time as i64])?;
        if let Some(previous) = previous {
            tx.execute("DELETE FROM sessions WHERE token_sha256=?", [previous])?;
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))?;
        ensure!(count < 4096, ErrorCode::ControlCapacity);
        tx.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            params![
                hash,
                serde_json::to_string(&actor)?,
                time as i64,
                expires as i64
            ],
        )?;
        tx.commit()?;
        Ok(Session { actor, expires })
    }

    pub fn session(&self, hash: &str) -> Result<Session> {
        let time = now()? as i64;
        let (actor, expires) = self.db.query_row(
            "SELECT actor,expires FROM sessions WHERE token_sha256=? AND created<=? AND expires>?",
            params![hash, time, time], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        ).optional()?.context(ErrorCode::AuthRequired)?;
        Ok(Session {
            actor: serde_json::from_str(&actor)?,
            expires: expires.try_into()?,
        })
    }

    pub fn revoke_session(&mut self, hash: &str) -> Result<()> {
        self.db
            .execute("DELETE FROM sessions WHERE token_sha256=?", [hash])?;
        Ok(())
    }

    pub fn queue_depth(&self) -> Result<u32> {
        Ok(self.db.query_row(
            "SELECT count(*) FROM jobs WHERE state='queued'",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn metrics(&self) -> Result<Metrics> {
        let mut statement = self
            .db
            .prepare("SELECT state, count(*) FROM jobs GROUP BY state")?;
        let mut rows = statement.query([])?;
        let mut result = Metrics::default();
        while let Some(row) = rows.next()? {
            let state = row.get::<_, String>(0)?;
            let count = u64::from(row.get::<_, u32>(1)?);
            result.accepted_total += count;
            match state.as_str() {
                "succeeded" => result.succeeded_total = count,
                "failed" => result.failed_total = count,
                "partial" => result.partial_total = count,
                "cancelled" => result.cancelled_total = count,
                "interrupted" => result.interrupted_total = count,
                _ => {}
            }
        }
        Ok(result)
    }

    pub fn page_jobs(
        &self,
        actor: Actor,
        authority: &crate::config::Authority,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<(Vec<Job>, Option<Uuid>)> {
        let cursor = after.map(|id| id.to_string()).unwrap_or_default();
        let mut statement;
        let mut rows = if authority.admin() {
            statement = self
                .db
                .prepare("SELECT job FROM jobs WHERE id>? ORDER BY id LIMIT ?")?;
            statement.query(params![cursor, limit as i64 + 1])?
        } else {
            statement = self.db.prepare(
                "SELECT job FROM jobs WHERE json_extract(job,'$.actor_id')=? AND id>?
                 AND json_extract(job,'$.operation') IN (SELECT value FROM json_each(?))
                 ORDER BY id LIMIT ?",
            )?;
            statement.query(params![
                actor.actor_id.to_string(),
                cursor,
                serde_json::to_string(&authority.operations())?,
                limit as i64 + 1
            ])?
        };
        let mut jobs: Vec<Job> = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let raw: String = row.get(0)?;
            if jobs.len() == limit || (!jobs.is_empty() && bytes + raw.len() > 2 * IPC_LIMIT) {
                let next = jobs.last().map(|job| job.id);
                return Ok((jobs, next));
            }
            bytes += raw.len();
            jobs.push(serde_json::from_str(&raw)?);
        }
        Ok((jobs, None))
    }

    pub fn admit(
        &mut self,
        config: &Config,
        actor: Actor,
        key: Uuid,
        mut request: Request,
    ) -> Result<Job> {
        request.validate()?;
        ensure!(uuid4(key), ErrorCode::InvalidRequest);
        let operation = request.operation();
        config.authorize(actor, Some(operation))?;
        request.normalize();
        let route = request.route();
        let fingerprint = binding("backupctl-api-request-v1", &("POST", route, &request))?;
        let tx = self.db.transaction()?;
        if let Some(job) = replay(&tx, actor, route, key, &fingerprint)? {
            return Ok(job);
        }
        check_receipt_capacity(&tx)?;
        let queued: i64 =
            tx.query_row("SELECT count(*) FROM jobs WHERE state='queued'", [], |r| {
                r.get(0)
            })?;
        ensure!(queued < QUEUE_LIMIT, ErrorCode::QueueFull);
        let time = now()?;
        let id = Uuid::new_v4();
        let mut profile = request.requested_profile().to_owned();
        let mut deadline = time + QUEUE_MS;
        let confirmed = if let Some((intent_id, _, _)) = request.confirmation() {
            let (intent, intent_profile) = read_intent(&tx, intent_id)?;
            check_intent(&intent, &request, actor, self.instance, time, None)?;
            profile = intent_profile;
            deadline = deadline.min(intent.bound.expires_unix_ms);
            Some(intent)
        } else {
            None
        };
        let selected = config.select(&profile, operation)?;
        if let Some(intent) = &confirmed {
            ensure!(
                selected.revision == intent.bound.config_revision,
                ErrorCode::ConfigChanged
            );
            crate::operation::check_core_plan(&selected.config, intent)?;
        }
        let job = Job {
            id,
            actor_id: actor.actor_id,
            operation,
            state: State::Queued,
            created_unix_ms: time,
            updated_unix_ms: time,
            core_job_id: None,
            effects: Effects::None,
            result: None,
            error: None,
            url: format!("/api/v1/jobs/{id}"),
        };
        let work = Work {
            actor,
            request,
            profile,
            revision: selected.revision,
            api_config_hash: config.source_hash.clone(),
            deadline,
            intent: confirmed.as_ref().map(|x| x.bound.id),
        };
        tx.execute(
            "INSERT INTO jobs(id,state,job,work) VALUES (?,'queued',?,?)",
            params![
                id.to_string(),
                serde_json::to_string(&job)?,
                serde_json::to_string(&work)?
            ],
        )?;
        if let Some(intent) = confirmed {
            let count = tx.execute(
                "UPDATE intents SET consumed_by=? WHERE id=? AND consumed_by IS NULL",
                params![id.to_string(), intent.bound.id.to_string()],
            )?;
            ensure!(count == 1, ErrorCode::IntentConflict);
        }
        insert_receipt(&tx, actor, route, key, &fingerprint, id)?;
        tx.commit()?;
        Ok(job)
    }

    pub fn cancel(&mut self, config: &Config, actor: Actor, id: Uuid, key: Uuid) -> Result<Job> {
        ensure!(uuid4(id) && uuid4(key), ErrorCode::InvalidRequest);
        let authority = config.authorize(actor, None)?;
        ensure!(authority.cancel(), ErrorCode::AccessDenied);
        let tx = self.db.transaction()?;
        let mut job = read_job(&tx, id)?;
        ensure!(
            job.actor_id == actor.actor_id || authority.admin(),
            ErrorCode::NotFound
        );
        ensure!(authority.allows(job.operation), ErrorCode::AccessDenied);
        // The bodyless, job-scoped cancellation is idempotent through the
        // job state itself. It must remain available at the admission cap.
        let time = now()?;
        match job.state {
            State::Queued => {
                apply(
                    &mut job,
                    Outcome::error(
                        State::Cancelled,
                        ErrorCode::OperationCancelled,
                        Effects::None,
                    ),
                    time,
                );
                update(&tx, &job)?;
            }
            State::Running => {
                job.state = State::CancelRequested;
                job.updated_unix_ms = job.updated_unix_ms.max(time);
                update(&tx, &job)?;
            }
            _ => {}
        }
        tx.commit()?;
        Ok(job)
    }

    pub fn shutdown_cancel(&mut self, id: Uuid) -> Result<()> {
        let tx = self.db.transaction()?;
        let mut job = read_job(&tx, id)?;
        if job.state == State::Running {
            job.state = State::CancelRequested;
            job.updated_unix_ms = job.updated_unix_ms.max(now()?);
            update(&tx, &job)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn claim(&mut self) -> Result<Option<Uuid>> {
        let tx = self.db.transaction()?;
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE state IN ('running','cancel_requested'))",
            [],
            |r| r.get(0),
        )?;
        ensure!(!active, "CONTROL_ACTIVE_WORKER");
        loop {
            let next = tx
                .query_row(
                    "SELECT job,work FROM jobs WHERE state='queued' ORDER BY seq LIMIT 1",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            let Some((job, work)) = next else {
                tx.commit()?;
                return Ok(None);
            };
            let mut job: Job = serde_json::from_str(&job)?;
            let work: Work = serde_json::from_str(&work)?;
            let time = now()?;
            if time < job.created_unix_ms || time >= work.deadline {
                let code = if work.intent.is_some() {
                    ErrorCode::IntentExpired
                } else {
                    ErrorCode::PolicyRefused
                };
                apply(
                    &mut job,
                    Outcome::error(State::Failed, code, Effects::None),
                    time,
                );
                update(&tx, &job)?;
                continue;
            }
            job.state = State::Running;
            job.updated_unix_ms = time;
            job.effects = Effects::Unknown;
            update(&tx, &job)?;
            tx.commit()?;
            return Ok(Some(job.id));
        }
    }

    pub fn bind_worker(&mut self, id: Uuid, pid: u32) -> Result<bool> {
        let changes = self.db.execute(
            "UPDATE jobs SET worker_pid=? WHERE id=? AND state='running' AND worker_pid IS NULL",
            params![pid, id.to_string()],
        )?;
        Ok(changes == 1)
    }

    pub fn finish(&mut self, id: Uuid, outcome: Outcome) -> Result<Job> {
        let tx = self.db.transaction()?;
        let mut job = read_job(&tx, id)?;
        ensure!(
            matches!(job.state, State::Running | State::CancelRequested)
                && outcome.state.terminal(),
            "INVALID_TERMINAL_TRANSITION"
        );
        let intent = match &outcome.result {
            Some(JobResult::RestorePlan { intent }) => Some(intent.as_ref()),
            Some(JobResult::RetentionPreview {
                intent: Some(intent),
                ..
            }) => Some(intent.as_ref()),
            _ => None,
        };
        if let Some(intent) = intent {
            let work = read_work(&tx, id)?;
            ensure!(
                outcome.state == State::Succeeded
                    && intent.bound.actor_id == job.actor_id
                    && intent.bound.planning_job_id == job.id
                    && intent.bound.store_instance_id == self.instance
                    && intent.bound.config_revision == work.revision
                    && intent.consumed_by_job_id.is_none()
                    && binding("backupctl-api-intent-v1", &intent.bound)? == intent.digest,
                "INVALID_WORKER_INTENT"
            );
            tx.execute(
                "INSERT INTO intents(id,profile,binding,digest) VALUES (?,?,?,?)",
                params![
                    intent.bound.id.to_string(),
                    work.profile,
                    serde_json::to_string(&intent.bound)?,
                    intent.digest
                ],
            )?;
        }
        apply(&mut job, outcome, now()?);
        update(&tx, &job)?;
        tx.commit()?;
        Ok(job)
    }
}

fn interrupt_abandoned(tx: &Transaction<'_>) -> Result<()> {
    let abandoned = {
        let mut statement = tx.prepare(
            "SELECT job FROM jobs WHERE state IN ('queued','running','cancel_requested')",
        )?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let time = now()?;
    for raw in abandoned {
        let mut job: Job = serde_json::from_str(&raw)?;
        let effects = if job.state == State::Queued {
            Effects::None
        } else {
            Effects::Unknown
        };
        apply(
            &mut job,
            Outcome::error(State::Interrupted, ErrorCode::OperationInterrupted, effects),
            time,
        );
        update(tx, &job)?;
    }
    Ok(())
}

fn apply(job: &mut Job, outcome: Outcome, time: u64) {
    job.state = outcome.state;
    job.updated_unix_ms = job.updated_unix_ms.max(time);
    job.core_job_id = outcome.core_job_id;
    job.effects = outcome.effects;
    job.result = outcome.result;
    job.error = outcome.error;
}

fn update(tx: &Transaction<'_>, job: &Job) -> Result<()> {
    ensure!(
        tx.execute(
            "UPDATE jobs SET state=?,job=? WHERE id=?",
            params![
                job.state.as_str(),
                serde_json::to_string(job)?,
                job.id.to_string()
            ]
        )? == 1,
        "CONTROL_JOB_MISSING"
    );
    Ok(())
}

fn instance(db: &Connection) -> Result<Uuid> {
    let value: String = db.query_row("SELECT instance FROM metadata", [], |r| r.get(0))?;
    Ok(Uuid::parse_str(&value)?)
}
fn read_job(db: &Connection, id: Uuid) -> Result<Job> {
    let value: String = db
        .query_row("SELECT job FROM jobs WHERE id=?", [id.to_string()], |r| {
            r.get(0)
        })
        .optional()?
        .context(ErrorCode::NotFound)?;
    Ok(serde_json::from_str(&value)?)
}
fn read_work(db: &Connection, id: Uuid) -> Result<Work> {
    let value: String =
        db.query_row("SELECT work FROM jobs WHERE id=?", [id.to_string()], |r| {
            r.get(0)
        })?;
    Ok(serde_json::from_str(&value)?)
}
fn read_intent(db: &Connection, id: Uuid) -> Result<(Intent, String)> {
    let (bound, digest, consumed_by, profile) = db
        .query_row(
            "SELECT binding,digest,consumed_by,profile FROM intents WHERE id=?",
            [id.to_string()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get(3)?,
                ))
            },
        )
        .optional()?
        .context(ErrorCode::NotFound)?;
    let intent = Intent {
        bound: serde_json::from_str(&bound)?,
        digest,
        consumed_by_job_id: consumed_by.as_deref().map(Uuid::parse_str).transpose()?,
    };
    Ok((intent, profile))
}
fn check_receipt_capacity(db: &Connection) -> Result<()> {
    let total: i64 = db.query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))?;
    ensure!(total < RECEIPT_LIMIT, ErrorCode::ControlCapacity);
    Ok(())
}
fn replay(
    db: &Connection,
    actor: Actor,
    route: &str,
    key: Uuid,
    fingerprint: &str,
) -> Result<Option<Job>> {
    let existing = db
        .query_row(
            "SELECT fingerprint,job_id FROM receipts WHERE actor=? AND route=? AND key=?",
            params![actor.actor_id.to_string(), route, key.to_string()],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((expected, id)) = existing else {
        return Ok(None);
    };
    ensure!(expected == fingerprint, ErrorCode::IdempotencyConflict);
    Ok(Some(read_job(db, Uuid::parse_str(&id)?)?))
}
fn insert_receipt(
    db: &Connection,
    actor: Actor,
    route: &str,
    key: Uuid,
    fingerprint: &str,
    id: Uuid,
) -> Result<()> {
    db.execute(
        "INSERT INTO receipts VALUES (?,?,?,?,?)",
        params![
            actor.actor_id.to_string(),
            route,
            key.to_string(),
            fingerprint,
            id.to_string()
        ],
    )?;
    Ok(())
}

fn check_intent(
    intent: &Intent,
    request: &Request,
    actor: Actor,
    instance: Uuid,
    time: u64,
    consumer: Option<Uuid>,
) -> Result<()> {
    let (id, supplied, target) = request.confirmation().context(ErrorCode::IntentConflict)?;
    let bound = &intent.bound;
    ensure!(bound.actor_id == actor.actor_id, ErrorCode::NotFound);
    ensure!(
        bound.created_unix_ms <= time && time < bound.expires_unix_ms,
        ErrorCode::IntentExpired
    );
    ensure!(
        bound.id == id
            && bound.store_instance_id == instance
            && intent.consumed_by_job_id == consumer
            && supplied == intent.digest
            && binding("backupctl-api-intent-v1", bound)? == intent.digest,
        ErrorCode::IntentConflict
    );
    match (&bound.confirmation, bound.kind, target) {
        (Confirmation::Restore(c), IntentKind::Restore, Some(target))
            if c.target_database == target =>
        {
            Ok(())
        }
        (Confirmation::Retention(_), IntentKind::Retention, None) => Ok(()),
        _ => Err(ErrorCode::IntentConflict.into()),
    }
}

pub(crate) fn load_worker(
    config: &Config,
    id: Uuid,
    this_pid: u32,
) -> Result<(Job, Work, Option<Intent>, Uuid)> {
    let location = Location::open(&config.database)?;
    let mut db = location.connect(false)?;
    let tx = db.transaction()?;
    let job = read_job(&tx, id)?;
    let pid: Option<u32> = tx.query_row(
        "SELECT worker_pid FROM jobs WHERE id=?",
        [id.to_string()],
        |r| r.get(0),
    )?;
    ensure!(pid == Some(this_pid), ErrorCode::AccessDenied);
    ensure!(
        job.state != State::CancelRequested,
        ErrorCode::OperationCancelled
    );
    ensure!(job.state == State::Running, ErrorCode::AccessDenied);
    let work = read_work(&tx, id)?;
    let time = now()?;
    ensure!(
        time >= job.created_unix_ms && time < work.deadline,
        if work.intent.is_some() {
            ErrorCode::IntentExpired
        } else {
            ErrorCode::PolicyRefused
        }
    );
    ensure!(
        work.api_config_hash == config.source_hash,
        ErrorCode::ConfigChanged
    );
    config.authorize(work.actor, Some(job.operation))?;
    work.request.validate()?;
    ensure!(
        work.request.operation() == job.operation && work.actor.actor_id == job.actor_id,
        ErrorCode::AccessDenied
    );
    let instance = instance(&tx)?;
    let intent = if let Some(intent_id) = work.intent {
        let (intent, profile) = read_intent(&tx, intent_id)?;
        ensure!(
            profile == work.profile && intent.bound.config_revision == work.revision,
            ErrorCode::ConfigChanged
        );
        check_intent(
            &intent,
            &work.request,
            work.actor,
            instance,
            time,
            Some(job.id),
        )?;
        Some(intent)
    } else {
        ensure!(
            work.request.confirmation().is_none(),
            ErrorCode::IntentConflict
        );
        None
    };
    tx.commit()?;
    Ok((job, work, intent, instance))
}
