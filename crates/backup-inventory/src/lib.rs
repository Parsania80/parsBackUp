//! The inventory: what this host has seen of a backup store, and what happened to it.
//!
//! A published artifact already proves its own existence, integrity and origin — that is what
//! artifact v1 froze. What no file in `artifacts/<id>/` can state is lifecycle: whether anyone
//! ever verified it, whether it is protected, whether a newer one exists. That is this crate, and
//! it is a single SQLite file beside the store it describes. Alongside lifecycle sits the record of
//! operations: a [`JobRow`] is one command that held resources and could be interrupted, which no
//! artifact file can describe about itself at all.
//!
//! Two properties are load-bearing and the open rules below exist to keep them true:
//!
//! - **Key-free.** No column names a database, a host, a port, a profile, or a resolved scope.
//!   The store's own layout comment says the sealed manifest hides "a database, a host's shape,
//!   and an operator's profile"; an index that repeated them in plaintext would undo that with the
//!   one file operators casually copy off-site. Profiles are stored as
//!   [`backup_domain::profile_fingerprint`] digests for exactly this reason.
//! - **Not a witness.** The file lives inside the artifact store's failure domain, so an editor
//!   who can rewrite artifacts can rewrite these rows too. It is an index and an audit trail, and
//!   ADR 0003 keeps saying so wherever a control might be mistaken for it.
//!
//! There is no async here and no connection pool: this tool is a synchronous CLI, so an
//! [`Inventory`] is one opened connection, held for the duration of one command.

mod deletion;
pub use deletion::{DeletionDependency, DeletionJob};

mod activity;
mod artifact;
mod job;
mod job_lock;
mod resource_lock;
mod rollback;
mod schema;

pub use activity::{ACTIVITY_FILE, ActivityLock};
pub use artifact::{ArtifactRow, Shape, State};
pub use job::{AuditAction, AuditEvent, JobGuard, JobRow, JobScope, JobState, RestoreGuard};
pub use job_lock::{JobLock, LOCK_DIR};
pub use resource_lock::ResourceLock;
pub use schema::SCHEMA_VERSION;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

/// The name of the inventory inside a storage root. It is not a layout constant of
/// `backup-local`, because the store's frozen six-file artifact shape is a format decision while
/// this is only where an index happens to sit.
pub const INVENTORY_FILE: &str = "inventory.db";

/// How long a statement waits for the write lock before giving up.
///
/// rusqlite's own default is 5000 ms, which the spike learned by being surprised: a CLI that
/// forgets to ask waits five seconds on a busy database instead of answering. Two seconds is
/// generous for a table this small and short enough that an operator sees a refusal rather than
/// assumes the tool has hung.
const BUSY_TIMEOUT: Duration = Duration::from_millis(2000);

/// Whether `text` is exactly `len` lowercase hex characters.
pub(crate) fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A `signer_id`, `recipient_id`, `source_fingerprint` or `profile_fingerprint`.
pub(crate) fn is_hex_id(text: &str) -> bool {
    is_hex(text, backup_domain::ID_HEX_LEN)
}

/// The instant a row is written, in the one timestamp form this file stores.
///
/// Produced here rather than passed in by callers: a state and its timestamp written from two
/// separate clock reads are a claim about ordering nothing checks, and a caller that forgot to ask
/// would store an empty string in a NOT NULL column.
pub(crate) fn now_utc() -> Result<String> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?;
    let unix_ms: i128 = since_epoch
        .as_millis()
        .try_into()
        .context("system clock is past the year this format can hold")?;
    backup_domain::format_utc(unix_ms)
}

/// Runs one write inside an exclusive transaction, rolling back on any error.
///
/// Statements here are otherwise autocommitted one at a time, which is fine for a single row. It is
/// not fine for a transition, which is an `UPDATE` and an `INSERT`: half of a job's state change
/// would leave the audit trail contradicting the status column it describes. `IMMEDIATE` because
/// the second statement must not be the one that discovers another writer holds the database.
pub(crate) fn in_transaction<T>(
    conn: &Connection,
    write: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    // Shaped like `schema::migrate` on purpose, including rolling back a failed `COMMIT`: a
    // connection left inside a transaction still holds the write lock, so a refusal here would
    // make every later command on this host wait out the busy timeout.
    let outcome = (|| -> Result<T> {
        let result = write(conn)?;
        conn.execute_batch("COMMIT")?;
        Ok(result)
    })();
    if outcome.is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    outcome
}

/// Which estate an inventory belongs to, checked on every open.
///
/// The source fingerprint and not the storage root path is the identity, because choice 2's whole
/// argument for keeping the file inside the root is that a copy of the root is a copy of the
/// index: binding the index to an absolute path would make the DR copy this crate exists to serve
/// refuse to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Estate {
    pub source_fingerprint: String,
}

impl Estate {
    /// Rejects anything that is not a source fingerprint before it reaches a column, so a
    /// misconfigured binding is a clear error here rather than a row nothing can match later.
    pub fn new(source_fingerprint: String) -> Result<Self> {
        ensure!(
            is_hex_id(&source_fingerprint),
            "an inventory indexes a {}-character lowercase source fingerprint, not {source_fingerprint:?}",
            backup_domain::ID_HEX_LEN
        );
        Ok(Self { source_fingerprint })
    }
}

/// An opened inventory.
#[derive(Debug)]
pub struct Inventory {
    conn: Connection,
    estate: Estate,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerificationEvent {
    pub backup_id: Uuid,
    pub at_utc: String,
    pub level: String,
    pub outcome: String,
    pub payload_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub current: bool,
}

impl Inventory {
    pub fn probe_version(path: &Path) -> Result<i64> {
        Self::check_read_header(path)?;
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        Ok(schema::user_version(&conn)?)
    }

    /// Initialize a securely pre-created empty staging file.
    pub fn initialize_staged(path: &Path, estate: &Estate) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        ensure!(
            schema::user_version(&conn)? == 0,
            "staged inventory is not empty"
        );
        Self::configure(&conn, path, false)?;
        schema::migrate(&conn)?;
        let inventory = Self {
            conn,
            estate: estate.clone(),
        };
        inventory.bind_or_check(path)?;
        Ok(inventory)
    }
    /// Opens for writing, creating the file and migrating the schema as needed.
    ///
    /// `Estate` is checked, not assumed: a database left behind by a different source is refused
    /// rather than adopted, because merging two estates into one index would make every "newest
    /// backup for this source" answer wrong for both of them.
    ///
    /// Opening corrects nothing. An earlier build swept interrupted rows here, which meant that
    /// *any* write open — including one that was about to be refused — could rewrite a live job's
    /// history; ADR 0004 moves that into the maintenance pass, where it happens under an exclusive
    /// claim on the store.
    pub fn open(path: &Path, estate: &Estate) -> Result<Self> {
        // `Connection::open` *creates* a missing file, which is what makes the read-only open
        // below a separate function rather than a flag: an audit read must never be able to
        // invent an inventory.
        let conn = Connection::open(path)
            .with_context(|| format!("cannot open inventory {}", path.display()))?;
        Self::configure(&conn, path, false)?;
        let version = schema::migrate(&conn)
            .with_context(|| format!("cannot migrate inventory {}", path.display()))?;
        ensure!(
            version <= SCHEMA_VERSION,
            "inventory {} is schema version {version}; this build understands up to {SCHEMA_VERSION}. Upgrade backupctl before writing to it.",
            path.display()
        );
        let this = Self {
            conn,
            estate: estate.clone(),
        };
        this.bind_or_check(path)?;
        Ok(this)
    }

    /// Opens an existing inventory for writing without being told which source it indexes.
    ///
    /// The recovery pass needs to correct rows in a store whose source fingerprint it cannot
    /// compute: that fingerprint is made from a resolved connection plus the server major a preflight
    /// reads off the database, and a housekeeping run cannot ask the database anything. Reading the
    /// binding off the file is the honest version of the same check — the estate is what the
    /// inventory already says it is, and a file that disagrees with its own rows is refused by
    /// [`Inventory::open`] all the same later.
    ///
    /// `Ok(None)` means there is no inventory to recover, which is every store before its first
    /// job. It never creates one: a command whose whole job is deleting leftovers inventing an
    /// index would leave a file nothing wrote.
    pub fn open_bound(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("cannot open inventory {}", path.display()))?;
        Self::configure(&conn, path, false)?;
        let version = schema::user_version(&conn)?;
        ensure!(
            version != 0,
            "{} is not a backupctl inventory: it declares no schema version, which means it holds \
             no tables this build knows. A zero-byte file and a foreign database both read to \
             SQLite as a valid empty database, and a recovery pass must not build tables into one.",
            path.display()
        );
        let version = schema::migrate(&conn)
            .with_context(|| format!("cannot migrate inventory {}", path.display()))?;
        ensure!(
            version <= SCHEMA_VERSION,
            "inventory {} is schema version {version}; this build understands up to {SCHEMA_VERSION}. Upgrade backupctl before writing to it.",
            path.display()
        );
        let found = Self::binding(&conn)?.with_context(|| {
            format!(
                "{} is an inventory a recovery pass has to correct, but it carries no source \
                 binding; refusing to guess whose estate it indexes",
                path.display()
            )
        })?;
        Ok(Some(Self {
            conn,
            estate: Estate::new(found)?,
        }))
    }

    /// Opens an existing current-schema inventory for writing without migrating it.
    pub fn open_existing_current(path: &Path, estate: &Estate) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        ensure!(
            schema::user_version(&conn)? == SCHEMA_VERSION,
            "inventory schema changed during reconciliation"
        );
        let binding = Self::binding(&conn)?.context("inventory has no source binding")?;
        ensure!(
            binding == estate.source_fingerprint,
            "inventory estate changed during reconciliation"
        );
        Self::configure(&conn, path, false)?;
        Ok(Self {
            conn,
            estate: Estate::new(binding)?,
        })
    }

    /// Upgrade an existing bound inventory without creating a database or following a symlink.
    pub fn open_existing_upgrade(path: &Path, estate: &Estate) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let version = schema::user_version(&conn)?;
        ensure!(
            version > 0 && version <= SCHEMA_VERSION,
            "unsupported inventory schema"
        );
        ensure!(
            Self::binding(&conn)?.as_deref() == Some(&estate.source_fingerprint),
            "inventory estate mismatch"
        );
        Self::configure(&conn, path, false)?;
        schema::migrate(&conn)?;
        Ok(Self {
            conn,
            estate: estate.clone(),
        })
    }

    /// Opens an existing inventory without writing, creating, or migrating anything.
    ///
    /// `PRAGMA query_only` is *not* how this works: the spike measured it creating the file it was
    /// supposed to be sparing. Only `SQLITE_OPEN_READ_ONLY` never creates, and the reason that
    /// matters here is the database's own journal mode — a WAL database copied without its
    /// sidecars cannot be opened read-only at all, which is why the inventory is not WAL.
    pub fn open_read_only(path: &Path, estate: &Estate) -> Result<Self> {
        let conn = Self::read_only_connection(path)?;
        let this = Self {
            conn,
            estate: estate.clone(),
        };
        this.check_binding(path)?;
        Ok(this)
    }

    /// Opens an existing inventory read-only using its recorded estate binding.
    pub fn open_read_only_bound(path: &Path) -> Result<Self> {
        let conn = Self::read_only_connection(path)?;
        let found = Self::binding(&conn)?.with_context(|| {
            format!(
                "{} has no source binding; refusing to guess its estate",
                path.display()
            )
        })?;
        Ok(Self {
            conn,
            estate: Estate::new(found)?,
        })
    }

    // SQLite READONLY can create WAL/SHM files while querying journal_mode.
    fn check_read_header(path: &Path) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "inventory must be a regular file"
        );
        let mut header = Vec::with_capacity(20);
        file.take(20).read_to_end(&mut header)?;
        if header.len() == 20 && &header[..16] == b"SQLite format 3\0" {
            ensure!(
                header[18] == 1 && header[19] == 1,
                "unsupported inventory journal format; a single delete-mode SQLite file is required"
            );
        }
        Ok(())
    }

    fn read_only_connection(path: &Path) -> Result<Connection> {
        ensure!(
            path.is_file(),
            "no inventory at {}: the file does not exist, and a read of the store's history is not \
             the moment to create one",
            path.display()
        );
        Self::check_read_header(path)?;
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("cannot open inventory {} read-only", path.display()))?;
        Self::configure(&conn, path, true)
            .with_context(|| format!("cannot open inventory {} read-only", path.display()))?;
        let version = schema::user_version(&conn)?;
        ensure!(
            version != 0,
            "{} is not a backupctl inventory: it declares no schema version, which means it holds \
             no tables this build knows. A zero-byte file and a foreign database both read to \
             SQLite as a valid empty database, so this is the only check that tells them apart.",
            path.display()
        );
        ensure!(
            version <= SCHEMA_VERSION,
            "inventory {} is schema version {version}; this build understands up to {SCHEMA_VERSION}. Upgrade backupctl before reading it.",
            path.display()
        );
        Ok(conn)
    }

    /// Applies and then *reads back* the pragmas this format depends on.
    ///
    /// Read-back is the point. A `PRAGMA journal_mode` that silently stays `wal` — a locked
    /// directory, a filesystem without it — is invisible in the code and obvious here, and ADR
    /// 0003's disaster recovery story rests on the answer being `delete`.
    fn configure(conn: &Connection, path: &Path, read_only: bool) -> Result<()> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let asked = BUSY_TIMEOUT.as_millis();
        let effective: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
        ensure!(
            effective == asked as i64,
            "inventory {}: busy_timeout reads back as {effective}ms, not the {asked}ms asked for",
            path.display()
        );

        if !read_only {
            // Persistent in the file, so this only takes effect once; re-setting it is a no-op.
            conn.execute_batch("PRAGMA journal_mode=delete; PRAGMA synchronous=FULL;")?;
        }
        let journal: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        ensure!(
            journal == "delete",
            "inventory {}: journal mode is {journal:?}, not \"delete\". A WAL database whose -wal \
             and -shm sidecars are missing cannot be opened read-only at all, and a copy without \
             them is the normal shape of a DR read, so this file stays in the one mode that can be \
             read from a single copied file.",
            path.display()
        );
        let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        ensure!(
            read_only || synchronous == 2,
            "inventory {}: synchronous is {synchronous}, not FULL. The inventory is one file an \
             operator may be reading after the host that wrote it is gone, so its writes are \
             synced even where the volume makes that nearly free.",
            path.display()
        );
        Ok(())
    }

    /// Records the estate on a fresh inventory, or holds an existing one to it.
    fn bind_or_check(&self, path: &Path) -> Result<()> {
        match Self::binding(&self.conn)? {
            None => self.set_binding().with_context(|| {
                format!("cannot record which source {} belongs to", path.display())
            }),
            Some(found) => self.refuse_mismatch(path, &found),
        }
    }

    fn check_binding(&self, path: &Path) -> Result<()> {
        let found = Self::binding(&self.conn)?.with_context(|| {
            format!(
                "{} is an inventory at a schema version this build knows but carries no source \
                 binding; refusing to guess whose estate it indexes",
                path.display()
            )
        })?;
        self.refuse_mismatch(path, &found)
    }

    fn refuse_mismatch(&self, path: &Path, found: &str) -> Result<()> {
        ensure!(
            found == self.estate.source_fingerprint,
            "inventory {} belongs to source {found}, not to {}; refusing to merge two estates into one index.",
            path.display(),
            self.estate.source_fingerprint
        );
        Ok(())
    }

    fn binding(conn: &Connection) -> Result<Option<String>> {
        Ok(conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'source_fingerprint'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    fn set_binding(&self) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('source_fingerprint', ?1)",
            [self.estate.source_fingerprint.as_str()],
        )?;
        Ok(())
    }

    /// The source this index belongs to, as configured and re-checked on open.
    pub fn estate(&self) -> &Estate {
        &self.estate
    }

    /// The schema version actually on disk.
    pub fn schema_version(&self) -> Result<i64> {
        Ok(schema::user_version(&self.conn)?)
    }

    /// Runs SQLite's own structural check and returns its complaints; empty means clean.
    ///
    /// This exists because a corrupt inventory is not loud: the spike zeroed 512 bytes into a
    /// populated database, `integrity_check` reported a misplaced rowid and a bad fragmentation
    /// count, and `SELECT count(*)` on that same file answered instantly and cheerfully. So "a
    /// query worked" is not evidence about this file, and a command that has to trust its contents
    /// asks here first.
    pub fn integrity_problems(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("PRAGMA integrity_check")?;
        let mut rows = stmt.query([])?;
        let mut problems = Vec::new();
        while let Some(row) = rows.next()? {
            let line: String = row.get(0)?;
            // SQLite answers a clean check with the single word "ok" rather than no rows.
            if line != "ok" {
                problems.push(line);
            }
        }
        Ok(problems)
    }

    /// Registers an artifact without replacing existing observations or conflicting facts.
    ///
    /// The [`AuditAction::ArtifactRegistered`] event carries no job id, because the store's publish
    /// path is what calls this and it holds no job; the link back to a `backup create` is the
    /// `backup_id` the job row already names.
    pub fn register(&self, row: &ArtifactRow) -> Result<()> {
        self.register_inner(row, false)
    }

    /// Publication knows private facts; generic registration/adoption do not establish a mark.
    pub fn register_published(&self, row: &ArtifactRow) -> Result<()> {
        self.register_inner(row, true)
    }

    fn register_inner(&self, row: &ArtifactRow, published: bool) -> Result<()> {
        row.validate(&self.estate)
            .with_context(|| format!("cannot register backup {}", row.backup_id))?;
        in_transaction(&self.conn, |conn| {
            let present: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifact WHERE backup_id = ?1)",
                [row.backup_id.to_string()],
                |r| r.get(0),
            )?;
            self.ensure_readable(row.backup_id)?;
            artifact::write(conn, row)?;
            // Only a new publication establishes false; refresh never repairs lost knowledge.
            if !present && row.shape == Shape::V1Signed {
                conn.execute(
                    "UPDATE artifact SET protected = 0 WHERE backup_id = ?1",
                    [row.backup_id.to_string()],
                )?;
            }
            job::record(
                conn,
                AuditAction::ArtifactRegistered,
                None,
                Some(row.backup_id),
            )?;
            if published
                && row.shape == Shape::V1Signed
                && let (Some(signer), Some(completed)) = (&row.signer_id, &row.completed_at_utc)
            {
                self.advance_completion(
                    &row.source_fingerprint,
                    signer,
                    &backup_domain::CompletionMark {
                        artifact_id: row.backup_id,
                        completed_at_utc: completed.clone(),
                    },
                )?;
            }
            Ok(())
        })
    }

    /// A tombstone wins over restored files, even while the completion marker still exists.
    pub fn ensure_readable(&self, id: Uuid) -> Result<()> {
        ensure!(
            self.artifact(id)?
                .is_none_or(|row| !row.state.is_deletion()),
            "DELETION_RECOVERY_REQUIRED: artifact is deleting or deleted"
        );
        Ok(())
    }

    /// Unknown is distinct from false, including every row read from a pre-protection schema.
    pub fn protection(&self, id: Uuid) -> Result<Option<bool>> {
        let row = self.artifact(id)?.context("artifact is not registered")?;
        row.validate(&self.estate)?;
        if self.schema_version()? < 6 {
            return Ok(None);
        }
        let value: Option<i64> = self.conn.query_row(
            "SELECT protected FROM artifact WHERE backup_id = ?1",
            [id.to_string()],
            |r| r.get(0),
        )?;
        ensure!(
            matches!(value, None | Some(0 | 1)),
            "invalid artifact protection"
        );
        Ok(value.map(|value| value == 1))
    }

    /// Establish protection knowledge and its audit event together; return the previous value.
    pub fn set_protection(&self, id: Uuid, protected: bool) -> Result<(Option<bool>, bool)> {
        in_transaction(&self.conn, |conn| {
            self.ensure_readable(id)?;
            let previous = self.protection(id)?;
            if previous == Some(protected) {
                return Ok((previous, false));
            }
            conn.execute(
                "UPDATE artifact SET protected = ?1 WHERE backup_id = ?2",
                rusqlite::params![protected, id.to_string()],
            )?;
            let action = if protected {
                AuditAction::ArtifactProtected
            } else {
                AuditAction::ArtifactUnprotected
            };
            job::record(conn, action, None, Some(id))?;
            Ok((previous, true))
        })
    }

    /// Record an observed artifact without claiming its source or signature is authenticated.
    pub fn adopt(&self, row: &ArtifactRow) -> Result<()> {
        row.validate(&self.estate)?;
        ensure!(
            row.profile_fingerprint.is_none() && row.completed_at_utc.is_none(),
            "adoption cannot assert private facts"
        );
        in_transaction(&self.conn, |conn| {
            let present: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifact WHERE backup_id = ?1)",
                [row.backup_id.to_string()],
                |r| r.get(0),
            )?;
            ensure!(!present, "artifact is already registered");
            artifact::write(conn, row)?;
            conn.execute(
                "INSERT INTO provisional_artifact (backup_id) VALUES (?1)",
                [row.backup_id.to_string()],
            )?;
            job::record(
                conn,
                AuditAction::ArtifactAdopted,
                None,
                Some(row.backup_id),
            )
        })
    }

    /// Check provenance after a signed manifest has been authenticated, without mutating it.
    pub fn check_provisional_source(&self, id: Uuid, source: &str) -> Result<()> {
        let provisional: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM provisional_artifact WHERE backup_id = ?1)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        ensure!(
            !provisional || source == self.estate.source_fingerprint,
            "authenticated artifact source conflicts with its provisional inventory estate"
        );
        Ok(())
    }

    pub fn is_provisional(&self, id: Uuid) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM provisional_artifact WHERE backup_id = ?1)",
            [id.to_string()],
            |r| r.get(0),
        )?)
    }

    pub fn record_rebuild(&self) -> Result<()> {
        in_transaction(&self.conn, |conn| {
            job::record(conn, AuditAction::InventoryRebuilt, None, None)
        })
    }

    /// Append one verification observation and enrich a matching signed row atomically.
    pub fn record_verification(
        &self,
        id: Uuid,
        level: &str,
        success: bool,
        digests: Option<(&str, Option<&str>)>,
        authenticated: Option<(&str, &str, &str)>,
    ) -> Result<()> {
        ensure!(
            matches!(level, "signature" | "checksum" | "archive"),
            "invalid verification level"
        );
        ensure!(
            !success || digests.is_some(),
            "successful verification requires a payload digest"
        );
        ensure!(
            authenticated.is_none() || (success && level != "signature"),
            "invalid authenticated enrichment"
        );
        if let Some((payload, manifest)) = digests {
            ensure!(
                is_hex(payload, backup_domain::DIGEST_HEX_LEN)
                    && manifest.is_none_or(|value| is_hex(value, backup_domain::DIGEST_HEX_LEN)),
                "invalid verification digests"
            );
        }
        let conflict = std::cell::Cell::new(false);
        in_transaction(&self.conn, |conn| {
            let row = self.artifact(id)?.context("artifact is not registered")?;
            row.validate(&self.estate)?;
            self.ensure_readable(id)?;
            if let Some((payload, manifest)) = digests {
                if row.shape == Shape::V1Signed
                    && row.state == State::Registered
                    && (row.payload_sha256.as_deref() != Some(payload)
                        || row.manifest_sha256.as_deref() != manifest)
                {
                    conn.execute(
                        "UPDATE verification_event SET current = 0 WHERE backup_id = ?1",
                        [id.to_string()],
                    )?;
                    conn.execute(
                        "UPDATE artifact SET state = 'conflict' WHERE backup_id = ?1",
                        [id.to_string()],
                    )?;
                    job::record(conn, AuditAction::ArtifactConflict, None, Some(id))?;
                    conn.execute("INSERT INTO verification_event (backup_id, at_utc, level, outcome, payload_sha256, manifest_sha256) VALUES (?1, ?2, ?3, 'failure', ?4, ?5)", rusqlite::params![id.to_string(), now_utc()?, level, payload, manifest])?;
                    conflict.set(true);
                    return Ok(());
                }
                ensure!(
                    row.state == State::Registered
                        && ((row.shape == Shape::V1Signed
                            && row.payload_sha256.as_deref() == Some(payload)
                            && row.manifest_sha256.as_deref() == manifest
                            && manifest.is_some())
                            || (row.shape != Shape::V1Signed && manifest.is_none())),
                    "verified bytes conflict with inventory"
                );
            }
            if let Some((source, profile, completed)) = authenticated {
                ensure!(
                    row.shape == Shape::V1Signed,
                    "unsigned artifacts cannot be enriched as authenticated"
                );
                ensure!(
                    source == self.estate.source_fingerprint,
                    "authenticated source conflicts with inventory estate"
                );
                ensure!(
                    is_hex_id(profile) && backup_domain::is_utc_timestamp(completed),
                    "invalid authenticated facts"
                );
                ensure!(
                    row.profile_fingerprint
                        .as_deref()
                        .is_none_or(|known| known == profile)
                        && row
                            .completed_at_utc
                            .as_deref()
                            .is_none_or(|known| known == completed),
                    "authenticated facts conflict with inventory"
                );
                conn.execute("UPDATE artifact SET profile_fingerprint = COALESCE(profile_fingerprint, ?1), completed_at_utc = COALESCE(completed_at_utc, ?2) WHERE backup_id = ?3", rusqlite::params![profile, completed, id.to_string()])?;
                conn.execute(
                    "DELETE FROM provisional_artifact WHERE backup_id = ?1",
                    [id.to_string()],
                )?;
                self.advance_completion(
                    source,
                    row.signer_id
                        .as_deref()
                        .context("missing authenticated signer")?,
                    &backup_domain::CompletionMark {
                        artifact_id: id,
                        completed_at_utc: completed.to_owned(),
                    },
                )?;
            }
            if !success {
                conn.execute(
                    "UPDATE verification_event SET current = 0 WHERE backup_id = ?1",
                    [id.to_string()],
                )?;
            }
            let (payload, manifest) = digests.map_or((None, None), |(p, m)| (Some(p), m));
            conn.execute("INSERT INTO verification_event (backup_id, at_utc, level, outcome, payload_sha256, manifest_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", rusqlite::params![id.to_string(), now_utc()?, level, if success { "success" } else { "failure" }, payload, manifest])?;
            Ok(())
        })?;
        ensure!(!conflict.get(), "verified bytes conflict with inventory");
        Ok(())
    }

    pub fn verification_events(&self, id: Uuid) -> Result<Vec<VerificationEvent>> {
        ensure!(
            self.schema_version()? >= 4,
            "inventory has no verification event table"
        );
        let mut stmt = self.conn.prepare("SELECT at_utc, level, outcome, payload_sha256, manifest_sha256, current FROM verification_event WHERE backup_id = ?1 ORDER BY event_id")?;
        let rows = stmt.query_map([id.to_string()], |row| {
            Ok(VerificationEvent {
                backup_id: id,
                at_utc: row.get(0)?,
                level: row.get(1)?,
                outcome: row.get(2)?,
                payload_sha256: row.get(3)?,
                manifest_sha256: row.get(4)?,
                current: row.get(5)?,
            })
        })?;
        let events = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        for event in &events {
            ensure!(
                backup_domain::is_utc_timestamp(&event.at_utc)
                    && matches!(event.level.as_str(), "signature" | "checksum" | "archive")
                    && matches!(event.outcome.as_str(), "success" | "failure"),
                "invalid verification event"
            );
            for digest in [&event.payload_sha256, &event.manifest_sha256]
                .into_iter()
                .flatten()
            {
                ensure!(
                    is_hex(digest, backup_domain::DIGEST_HEX_LEN),
                    "invalid verification event digest"
                );
            }
            ensure!(
                event.outcome != "success" || event.payload_sha256.is_some(),
                "successful verification event has no payload digest"
            );
        }
        Ok(events)
    }

    /// Internal policy evidence, retaining SQL identity without changing public event JSON.
    pub fn current_archive_event(
        &self,
        id: Uuid,
        payload: &str,
        manifest: &str,
    ) -> Result<Option<i64>> {
        self.verification_events(id)?;
        let event: Option<i64> = self.conn.query_row(
            "SELECT MAX(event_id) FROM verification_event WHERE backup_id = ?1 AND level = 'archive' AND outcome = 'success' AND current = 1 AND payload_sha256 = ?2 AND manifest_sha256 = ?3",
            rusqlite::params![id.to_string(), payload, manifest], |r| r.get(0))?;
        ensure!(
            event.is_none_or(|id| id > 0),
            "invalid verification event identity"
        );
        Ok(event)
    }

    /// Every row, oldest completion first, with the never-completed ones last.
    ///
    /// `completed_at_utc` orders this, and only it: `backup_id` is a random UUIDv4 and orders
    /// nothing, which is ADR 0003's first constraint on the frozen format. NULLs sort last because
    /// an unknown time is not the oldest time.
    pub fn artifacts(&self) -> Result<Vec<ArtifactRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM artifact ORDER BY completed_at_utc IS NULL, completed_at_utc, backup_id",
            artifact::ARTIFACT_COLUMNS
        ))?;
        let rows = self.read_rows(&mut stmt)?;
        for row in &rows {
            row.validate(&self.estate)?;
        }
        Ok(rows)
    }

    /// Applies observations without replacing discovery or authenticated fields.
    pub fn reconcile_states(
        &self,
        snapshot: &[ArtifactRow],
        changes: &[(Uuid, State, State)],
    ) -> Result<()> {
        in_transaction(&self.conn, |conn| {
            ensure!(
                self.artifacts()? == snapshot,
                "inventory changed during reconciliation"
            );
            for &(id, from, to) in changes {
                ensure!(
                    !from.is_deletion() && !to.is_deletion(),
                    "cannot reconcile deletion lifecycle"
                );
                let count = conn.execute(
                    "UPDATE artifact SET state = ?1 WHERE backup_id = ?2 AND state = ?3",
                    rusqlite::params![to.as_str(), id.to_string(), from.as_str()],
                )?;
                ensure!(count == 1, "inventory changed during reconciliation");
                if to != State::Registered && self.schema_version()? >= 4 {
                    conn.execute(
                        "UPDATE verification_event SET current = 0 WHERE backup_id = ?1",
                        [id.to_string()],
                    )?;
                }
                let action = match to {
                    State::Registered => AuditAction::ArtifactObserved,
                    State::Missing => AuditAction::ArtifactMissing,
                    State::Conflict => AuditAction::ArtifactConflict,
                    State::Deleting | State::Deleted => unreachable!(),
                };
                job::record(conn, action, None, Some(id))?;
            }
            Ok(())
        })
    }

    /// The row for one id, if this index has seen it.
    pub fn artifact(&self, backup_id: uuid::Uuid) -> Result<Option<ArtifactRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM artifact WHERE backup_id = ?1",
            artifact::ARTIFACT_COLUMNS
        ))?;
        let mut rows = stmt.query([backup_id.to_string()])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(ArtifactRow::from_row(row)?)),
        }
    }

    fn read_rows(&self, stmt: &mut rusqlite::Statement) -> Result<Vec<ArtifactRow>> {
        let mut rows = stmt.query([])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            found.push(ArtifactRow::from_row(row)?);
        }
        Ok(found)
    }

    /// Opens one job row alongside its `job_started` event. [`JobGuard::begin`] is the only caller
    /// that can reach this, which is what keeps a non-terminal row from ever existing without a
    /// held lock to make it true.
    pub(crate) fn begin_job(&self, row: &JobRow) -> Result<()> {
        job::start(&self.conn, row)
    }

    /// Moves one job and appends the event for that transition, together or not at all.
    pub(crate) fn set_job_state(
        &self,
        job_id: Uuid,
        to: JobState,
        action: AuditAction,
    ) -> Result<()> {
        job::transition(&self.conn, job_id, to, action)
    }

    /// Every job, oldest start first, across all scopes.
    pub fn jobs(&self) -> Result<Vec<JobRow>> {
        let jobs = job::all(&self.conn)?;
        ensure!(
            jobs.iter()
                .all(|row| row.source_fingerprint == self.estate.source_fingerprint),
            "inventory holds a job from a different source estate"
        );
        Ok(jobs)
    }

    /// The row for one job id, if this index has seen it.
    pub fn job(&self, job_id: Uuid) -> Result<Option<JobRow>> {
        let job = job::one(&self.conn, job_id)?;
        ensure!(
            job.as_ref()
                .is_none_or(|row| row.source_fingerprint == self.estate.source_fingerprint),
            "inventory holds a job from a different source estate"
        );
        Ok(job)
    }

    pub fn job_operation(&self, id: Uuid) -> Result<Option<(String, Option<String>)>> {
        if self.schema_version()? < 5 {
            return Ok(None);
        }
        let operation: Option<(String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT operation, target_fingerprint FROM job_operation WHERE job_id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((kind, target)) = &operation {
            ensure!(
                matches!(kind.as_str(), "backup" | "restore" | "prune" | "delete"),
                "invalid job operation"
            );
            ensure!(
                (kind == "restore") == target.is_some()
                    && target.as_ref().is_none_or(|value| is_hex_id(value)),
                "invalid job target fingerprint"
            );
            if matches!(kind.as_str(), "prune" | "delete") {
                ensure!(
                    self.job(id)?
                        .context("deletion association has no job")?
                        .backup_id
                        .is_none(),
                    "invalid deletion job association"
                );
            }
            if kind == "restore" {
                let row = self.job(id)?.context("restore association has no job")?;
                ensure!(
                    row.backup_id.is_some() && row.profile_fingerprint == "0000000000000000",
                    "invalid restore job association"
                );
            }
        }
        Ok(operation)
    }

    /// The whole audit trail, in the order it was written.
    pub fn audit_events(&self) -> Result<Vec<AuditEvent>> {
        job::events(&self.conn)
    }

    /// Marks every row left non-terminal by a process that no longer holds its lock, and returns the
    /// jobs it actually moved.
    ///
    /// The kernel is the only witness here. A row in `running` says "a process is dumping right
    /// now", and the one thing that can answer whether that is still true is [`JobLock::is_free`],
    /// because `flock` is released by death of any kind — including the `SIGKILL` ADR 0003 gate 1
    /// tests. A timestamp cannot answer it: a dump of a large database legitimately sits in
    /// `running` for hours.
    ///
    /// Callers take the store's exclusive maintenance claim first (ADR 0004): this corrects the
    /// history of operations that are provably finished, so running it beside a live job would
    /// produce a report about a job that is not done yet. Each transition is a conditional update
    /// rather than an assignment, because the decision above came from a read taken before the lock
    /// probe; a job that reached a terminal state inside that window is left exactly as it is, since
    /// a `complete` row read back as `interrupted` would tell an operator that a backup they can
    /// restore never happened.
    ///
    /// Two limits carry over from the probe itself and are documented rather than engineered away:
    /// a holder that has created its lock file but not yet locked it reads as free, so its row can
    /// be marked `interrupted` a moment too early; and the sweep's own instant of holding can
    /// refuse a genuine second `backup create` of that scope. Both are windows of microseconds, and
    /// ADR 0003's standing answer is that the files, not this table, are the truth.
    pub fn sweep_interrupted(&self, root: &Path) -> Result<Vec<Uuid>> {
        let mut swept = Vec::new();
        for row in job::open(&self.conn)? {
            // Probed per row rather than once for the file, because the scope is per lock: one
            // dead `running` row must not stand in for a live row of a different profile, which is
            // exactly how a sweep would kill a job that is running right now.
            let free = match self.job_operation(row.job_id)? {
                Some((kind, Some(target))) if kind == "restore" => {
                    ResourceLock::target(root, &target)?.is_some()
                }
                Some((kind, None)) if matches!(kind.as_str(), "prune" | "delete") => true,
                _ => JobLock::is_free(root, &row.source_fingerprint, &row.profile_fingerprint)?,
            };
            if free && job::mark_interrupted(&self.conn, row.job_id)? {
                swept.push(row.job_id);
            }
        }
        Ok(swept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_domain::{DIGEST_HEX_LEN, ID_HEX_LEN};
    use std::fs;
    use uuid::Uuid;

    /// anyhow prints only the outermost context with `to_string`; assertions need the whole
    /// chain, because the refusal reason is the cause.
    fn chain(error: anyhow::Error) -> String {
        format!("{error:#}")
    }

    const SOURCE: &str = "c1cb425f097b6522";
    const OTHER_SOURCE: &str = "0123456789abcdef";

    fn estate() -> Estate {
        Estate::new(SOURCE.to_string()).unwrap()
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("backupctl-inventory-{name}-{}", Uuid::new_v4()))
    }

    /// A fresh inventory in its own directory, as a storage root would hold one.
    fn created(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = temp_dir(name);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(INVENTORY_FILE);
        (dir, path)
    }

    fn signed_row(id: &str) -> ArtifactRow {
        ArtifactRow {
            backup_id: Uuid::parse_str(id).unwrap(),
            source_fingerprint: SOURCE.to_string(),
            profile_fingerprint: Some("651dd7a74505b176".to_string()),
            shape: Shape::V1Signed,
            signer_id: Some("a".repeat(ID_HEX_LEN)),
            recipient_id: Some("b".repeat(ID_HEX_LEN)),
            payload_sha256: Some("c".repeat(DIGEST_HEX_LEN)),
            manifest_sha256: Some("d".repeat(DIGEST_HEX_LEN)),
            recipient_suite: Some("mlkem768x25519-v0".to_string()),
            signature_suite: Some("ed25519+ml-dsa-65".to_string()),
            payload_bytes: Some(4096),
            manifest_bytes: Some(1024),
            completed_at_utc: Some("2026-09-28T06:15:00Z".to_string()),
            state: State::Registered,
        }
    }

    /// The first file an operator ever writes: nothing exists, and opening must not merely
    /// tolerate that but *report* the mode and the version it settled on.
    #[test]
    fn opening_creates_a_versioned_inventory_in_the_mode_the_format_needs() {
        let (dir, path) = created("create");
        let inventory = Inventory::open(&path, &estate()).unwrap();

        assert_eq!(inventory.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(inventory.estate(), &estate());
        assert_eq!(
            inventory.integrity_problems().unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(inventory.artifacts().unwrap(), Vec::new());

        // Read back rather than assumed, on the file itself: these three answers are what a DR
        // read of a copied single file depends on.
        let raw = Connection::open(&path).unwrap();
        let journal: String = raw
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal, "delete");
        let version: i64 = raw
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // Every table this build's statements name, read back from the file rather than trusted to
        // have been created: a migration that ran half its statements would still set the version.
        let mut tables: Vec<String> = raw
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        tables.sort();
        assert_eq!(
            tables,
            [
                "artifact",
                "audit_event",
                "completion_high_water",
                "deletion_job",
                "job",
                "job_artifact",
                "job_operation",
                "meta",
                "provisional_artifact",
                "verification_event"
            ]
        );
        assert_eq!(
            tables,
            vec![
                "artifact".to_string(),
                "audit_event".to_string(),
                "completion_high_water".to_string(),
                "deletion_job".to_string(),
                "job".to_string(),
                "job_artifact".to_string(),
                "job_operation".to_string(),
                "meta".to_string(),
                "provisional_artifact".to_string(),
                "verification_event".to_string()
            ]
        );
        // And with it the jobs the sweep reads.
        assert_eq!(inventory.jobs().unwrap(), Vec::new());
        assert_eq!(inventory.audit_events().unwrap(), Vec::new());
        // No sidecars left behind at rest, which is the whole point of not being WAL.
        assert!(!dir.join(format!("{INVENTORY_FILE}-wal")).exists());
        assert!(!dir.join(format!("{INVENTORY_FILE}-shm")).exists());

        drop(inventory);
        drop(raw);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Creating is not a special case: a brand-new database runs the same `0 -> 1`, then `1 -> 2`
    /// steps an upgrade from an older host's file runs, and a second open must find nothing to do.
    #[test]
    fn reopening_is_idempotent_and_keeps_the_rows() {
        let (dir, path) = created("reopen");
        Inventory::open(&path, &estate())
            .unwrap()
            .register(&signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a"))
            .unwrap();

        let again = Inventory::open(&path, &estate()).unwrap();
        assert_eq!(again.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(again.artifacts().unwrap().len(), 1);
        // The binding survived, and it is the estate rather than a path: a copy of the root is a
        // copy of the index.
        assert_eq!(
            Inventory::binding(&again.conn).unwrap().as_deref(),
            Some(SOURCE)
        );

        drop(again);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_foreign_estate_is_refused_rather_than_merged() {
        let (dir, path) = created("estate");
        Inventory::open(&path, &estate()).unwrap();

        let other = Estate::new(OTHER_SOURCE.to_string()).unwrap();
        let error = Inventory::open(&path, &other)
            .expect_err("two estates in one index answer both of them wrongly")
            .to_string();
        assert!(error.contains("refusing to merge two estates"), "{error}");
        assert!(
            error.contains(SOURCE) && error.contains(OTHER_SOURCE),
            "{error}"
        );

        // And the same refusal on the read path, where it is more likely: a DR host pointed at the
        // wrong copy of the store.
        let error = Inventory::open_read_only(&path, &other)
            .expect_err("reading must hold to the binding too")
            .to_string();
        assert!(error.contains("refusing to merge two estates"), "{error}");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn job_start_and_transitions_roll_back_when_audit_insertion_fails() {
        let (root, path) = created("job-audit-rollback");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let scope = JobScope {
            source_fingerprint: SOURCE.into(),
            profile_fingerprint: "651dd7a74505b176".into(),
            backup_id: Uuid::new_v4(),
        };
        inventory.conn.execute_batch("CREATE TRIGGER reject_start BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        assert!(JobGuard::begin(&root, &scope).is_err());
        assert!(RestoreGuard::begin(&root, "0123456789abcdef", scope.backup_id).is_err());
        assert!(inventory.jobs().unwrap().is_empty());
        assert!(inventory.audit_events().unwrap().is_empty());
        assert_eq!(
            inventory
                .conn
                .query_row("SELECT count(*) FROM job_operation", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_start")
            .unwrap();
        let guard = JobGuard::begin(&root, &scope).unwrap();
        let before = inventory.job(guard.id()).unwrap().unwrap();
        let events = inventory.audit_events().unwrap();
        inventory.conn.execute_batch("CREATE TRIGGER reject_transition BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        for (state, action) in [
            (JobState::Staged, AuditAction::JobStaged),
            (JobState::Complete, AuditAction::JobCompleted),
            (JobState::Failed, AuditAction::JobFailed),
        ] {
            assert!(inventory.set_job_state(guard.id(), state, action).is_err());
            assert_eq!(inventory.job(guard.id()).unwrap().unwrap(), before);
            assert_eq!(inventory.audit_events().unwrap(), events);
        }
        assert!(job::mark_interrupted(&inventory.conn, guard.id()).is_err());
        assert_eq!(inventory.job(guard.id()).unwrap().unwrap(), before);
        assert_eq!(inventory.audit_events().unwrap(), events);
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_transition")
            .unwrap();
        guard.complete().unwrap();
        drop(guard);
        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_state_and_observations_roll_back_when_events_cannot_commit() {
        let (root, path) = created("artifact-audit-rollback");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row("00000000-0000-4000-8000-000000000001");
        inventory.conn.execute_batch("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        assert!(inventory.register(&row).is_err());
        assert!(inventory.artifacts().unwrap().is_empty());
        assert!(inventory.audit_events().unwrap().is_empty());
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_audit")
            .unwrap();
        inventory.register(&row).unwrap();
        inventory
            .record_verification(
                row.backup_id,
                "signature",
                true,
                Some((
                    row.payload_sha256.as_deref().unwrap(),
                    row.manifest_sha256.as_deref(),
                )),
                None,
            )
            .unwrap();
        let rows = inventory.artifacts().unwrap();
        let events = inventory.audit_events().unwrap();
        let observations = inventory.verification_events(row.backup_id).unwrap();
        for table in ["audit_event", "verification_event"] {
            inventory.conn.execute_batch(&format!("CREATE TRIGGER reject_event BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'injected'); END;")).unwrap();
            if table == "audit_event" {
                assert!(
                    inventory
                        .reconcile_states(
                            &rows,
                            &[(row.backup_id, State::Registered, State::Missing)]
                        )
                        .is_err()
                );
                assert_eq!(inventory.artifacts().unwrap(), rows);
                assert_eq!(
                    inventory.verification_events(row.backup_id).unwrap(),
                    observations
                );
            } else {
                assert!(
                    inventory
                        .record_verification(row.backup_id, "checksum", false, None, None)
                        .is_err()
                );
                assert_eq!(
                    inventory.verification_events(row.backup_id).unwrap(),
                    observations
                );
            }
            // The mismatch branch changes lifecycle, invalidates history and inserts two events.
            assert!(
                inventory
                    .record_verification(
                        row.backup_id,
                        "checksum",
                        true,
                        Some((&"e".repeat(64), row.manifest_sha256.as_deref())),
                        None
                    )
                    .is_err()
            );
            assert_eq!(inventory.artifacts().unwrap(), rows);
            assert_eq!(inventory.audit_events().unwrap(), events);
            assert_eq!(
                inventory.verification_events(row.backup_id).unwrap(),
                observations
            );
            inventory
                .conn
                .execute_batch("DROP TRIGGER reject_event")
                .unwrap();
        }
        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn protection_is_idempotent_atomic_and_survives_registration() {
        let (root, path) = created("protection");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row("00000000-0000-4000-8000-000000000001");
        inventory.register(&row).unwrap();
        inventory
            .record_verification(
                row.backup_id,
                "archive",
                true,
                Some((
                    row.payload_sha256.as_deref().unwrap(),
                    row.manifest_sha256.as_deref(),
                )),
                None,
            )
            .unwrap();
        let guard = JobGuard::begin(
            &root,
            &JobScope {
                source_fingerprint: SOURCE.into(),
                profile_fingerprint: "651dd7a74505b176".into(),
                backup_id: row.backup_id,
            },
        )
        .unwrap();
        guard.complete().unwrap();
        drop(guard);
        let jobs = inventory.jobs().unwrap();
        let observations = inventory.verification_events(row.backup_id).unwrap();
        assert!(!jobs.is_empty() && !observations.is_empty());
        assert_eq!(inventory.protection(row.backup_id).unwrap(), Some(false));
        assert_eq!(
            inventory.set_protection(row.backup_id, true).unwrap(),
            (Some(false), true)
        );
        let events = inventory.audit_events().unwrap();
        assert_eq!(
            events.last().unwrap().action,
            AuditAction::ArtifactProtected
        );
        assert_eq!(
            inventory.set_protection(row.backup_id, true).unwrap(),
            (Some(true), false)
        );
        assert_eq!(inventory.audit_events().unwrap(), events);
        inventory.register(&row).unwrap();
        assert_eq!(inventory.protection(row.backup_id).unwrap(), Some(true));
        let events = inventory.audit_events().unwrap();
        inventory.conn.execute_batch("CREATE TRIGGER reject_protection BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        assert!(inventory.set_protection(row.backup_id, false).is_err());
        assert_eq!(inventory.protection(row.backup_id).unwrap(), Some(true));
        assert_eq!(
            inventory.artifact(row.backup_id).unwrap(),
            Some(row.clone())
        );
        assert_eq!(inventory.audit_events().unwrap(), events);
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_protection")
            .unwrap();
        assert_eq!(
            inventory.set_protection(row.backup_id, false).unwrap(),
            (Some(true), true)
        );
        assert_eq!(
            inventory.audit_events().unwrap().last().unwrap().action,
            AuditAction::ArtifactUnprotected
        );
        let mut adopted = signed_row("00000000-0000-4000-8000-000000000002");
        adopted.profile_fingerprint = None;
        adopted.completed_at_utc = None;
        inventory.adopt(&adopted).unwrap();
        inventory.register(&adopted).unwrap();
        assert_eq!(inventory.protection(adopted.backup_id).unwrap(), None);
        let events = inventory.audit_events().unwrap();
        inventory.conn.execute_batch("CREATE TRIGGER reject_unknown BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        assert!(inventory.set_protection(adopted.backup_id, false).is_err());
        assert_eq!(inventory.protection(adopted.backup_id).unwrap(), None);
        assert_eq!(inventory.audit_events().unwrap(), events);
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_unknown")
            .unwrap();
        assert_eq!(
            inventory.set_protection(adopted.backup_id, false).unwrap(),
            (None, true)
        );
        assert!(inventory.set_protection(Uuid::new_v4(), true).is_err());
        assert_eq!(inventory.jobs().unwrap(), jobs);
        assert_eq!(
            inventory.verification_events(row.backup_id).unwrap(),
            observations
        );
        assert!(inventory.is_provisional(adopted.backup_id).unwrap());
        assert!(
            inventory
                .conn
                .execute("UPDATE artifact SET protected = 2", [])
                .is_err()
        );
        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verification_enrichment_is_digest_bound_and_atomic() {
        let (dir, path) = created("verify-observation");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let mut row = signed_row("00000000-0000-4000-8000-000000000001");
        row.profile_fingerprint = None;
        row.completed_at_utc = None;
        inventory.adopt(&row).unwrap();
        let payload = row.payload_sha256.as_deref().unwrap();
        let manifest = row.manifest_sha256.as_deref().unwrap();
        let facts = Some((SOURCE, "651dd7a74505b176", "2026-09-28T06:15:00Z"));
        assert!(
            inventory
                .record_verification(
                    row.backup_id,
                    "checksum",
                    true,
                    Some((payload, Some(manifest))),
                    Some((OTHER_SOURCE, "651dd7a74505b176", "2026-09-28T06:15:00Z"))
                )
                .is_err()
        );
        assert!(inventory.is_provisional(row.backup_id).unwrap());
        assert!(
            inventory
                .verification_events(row.backup_id)
                .unwrap()
                .is_empty()
        );
        assert!(
            inventory
                .record_verification(
                    row.backup_id,
                    "checksum",
                    true,
                    Some((&"e".repeat(64), Some(manifest))),
                    facts
                )
                .is_err()
        );
        assert!(inventory.is_provisional(row.backup_id).unwrap());
        assert_eq!(
            inventory.artifact(row.backup_id).unwrap().unwrap().state,
            State::Conflict
        );
        let snapshot = inventory.artifacts().unwrap();
        inventory
            .reconcile_states(
                &snapshot,
                &[(row.backup_id, State::Conflict, State::Registered)],
            )
            .unwrap();
        let before_enrichment = inventory.artifact(row.backup_id).unwrap().unwrap();
        let before_observations = inventory.verification_events(row.backup_id).unwrap();
        let before_audit = inventory.audit_events().unwrap();
        inventory.conn.execute_batch("CREATE TRIGGER reject_verification BEFORE INSERT ON verification_event BEGIN SELECT RAISE(FAIL, 'injected'); END;").unwrap();
        assert!(
            inventory
                .record_verification(
                    row.backup_id,
                    "checksum",
                    true,
                    Some((payload, Some(manifest))),
                    facts
                )
                .is_err()
        );
        assert_eq!(
            inventory.artifact(row.backup_id).unwrap().unwrap(),
            before_enrichment
        );
        assert_eq!(
            inventory.verification_events(row.backup_id).unwrap(),
            before_observations
        );
        assert_eq!(inventory.audit_events().unwrap(), before_audit);
        assert!(inventory.is_provisional(row.backup_id).unwrap());
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_verification")
            .unwrap();
        inventory
            .record_verification(
                row.backup_id,
                "checksum",
                true,
                Some((payload, Some(manifest))),
                facts,
            )
            .unwrap();
        assert!(!inventory.is_provisional(row.backup_id).unwrap());
        assert_eq!(inventory.protection(row.backup_id).unwrap(), None);
        inventory.set_protection(row.backup_id, true).unwrap();
        inventory
            .record_verification(
                row.backup_id,
                "archive",
                true,
                Some((payload, Some(manifest))),
                facts,
            )
            .unwrap();
        assert_eq!(inventory.protection(row.backup_id).unwrap(), Some(true));
        assert_eq!(
            inventory
                .artifact(row.backup_id)
                .unwrap()
                .unwrap()
                .profile_fingerprint
                .as_deref(),
            Some("651dd7a74505b176")
        );
        let count: i64 = inventory
            .conn
            .query_row("SELECT COUNT(*) FROM verification_event", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);
        let snapshot = inventory.artifacts().unwrap();
        inventory
            .reconcile_states(
                &snapshot,
                &[(row.backup_id, State::Registered, State::Missing)],
            )
            .unwrap();
        let events = inventory.verification_events(row.backup_id).unwrap();
        assert!(events.iter().all(|event| !event.current));
        let snapshot = inventory.artifacts().unwrap();
        inventory
            .reconcile_states(
                &snapshot,
                &[(row.backup_id, State::Missing, State::Registered)],
            )
            .unwrap();
        assert!(
            inventory
                .verification_events(row.backup_id)
                .unwrap()
                .iter()
                .all(|event| !event.current)
        );
        assert_eq!(inventory.protection(row.backup_id).unwrap(), Some(true));
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn adoption_rolls_back_row_and_provenance_when_audit_fails() {
        let (dir, path) = created("adopt-rollback");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let mut row = signed_row("00000000-0000-4000-8000-000000000001");
        row.profile_fingerprint = None;
        row.completed_at_utc = None;
        inventory.conn.execute_batch("CREATE TRIGGER reject_adopt BEFORE INSERT ON audit_event WHEN NEW.action = 'artifact_adopted' BEGIN SELECT RAISE(FAIL, 'injected'); END;").unwrap();
        assert!(inventory.adopt(&row).is_err());
        assert!(inventory.artifact(row.backup_id).unwrap().is_none());
        assert!(!inventory.is_provisional(row.backup_id).unwrap());
        assert!(inventory.audit_events().unwrap().is_empty());
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_guard_tracks_associations_and_does_not_sweep_live_work() {
        let (root, path) = created("restore-ownership");
        drop(Inventory::open(&path, &estate()).unwrap());
        let id = Uuid::new_v4();
        let target = "0123456789abcdef";
        let guard = RestoreGuard::begin(&root, target, id).unwrap();
        assert!(RestoreGuard::begin(&root, target, id).is_err());
        let other = RestoreGuard::begin(&root, "fedcba9876543210", id).unwrap();
        assert!(ResourceLock::artifact(&root, id, true).unwrap().is_none());
        let inventory = Inventory::open_read_only_bound(&path).unwrap();
        let rows = inventory.jobs().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|row| row.backup_id == Some(id) && row.state == JobState::Running)
        );
        assert!(
            rows.iter()
                .all(|row| inventory.job_operation(row.job_id).unwrap().unwrap().0 == "restore")
        );
        assert!(inventory.sweep_interrupted(&root).unwrap().is_empty());
        drop(inventory);
        guard.complete().unwrap();
        drop(guard);
        drop(other);
        let inventory = Inventory::open_read_only_bound(&path).unwrap();
        let states = inventory
            .jobs()
            .unwrap()
            .into_iter()
            .map(|row| row.state)
            .collect::<Vec<_>>();
        assert!(states.contains(&JobState::Complete));
        assert!(states.contains(&JobState::Failed));
        assert!(inventory.sweep_interrupted(&root).unwrap().is_empty());
        assert!(ResourceLock::artifact(&root, id, true).unwrap().is_some());
        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_records_existing_inventory_estate_when_target_connection_differs() {
        let (root, path) = created("restore-foreign-target");
        drop(Inventory::open(&path, &estate()).unwrap());
        let guard = RestoreGuard::begin(&root, "0123456789abcdef", Uuid::new_v4()).unwrap();
        guard.complete().unwrap();
        drop(guard);
        let inventory = Inventory::open_read_only_bound(&path).unwrap();
        assert_eq!(inventory.jobs().unwrap()[0].source_fingerprint, SOURCE);
        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_refuses_missing_inventory_without_guessing_an_estate() {
        let (root, path) = created("restore-no-index");
        let error = RestoreGuard::begin(&root, "0123456789abcdef", Uuid::new_v4())
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("rebuild it explicitly"));
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_restore_completion_record_does_not_claim_the_restore_failed() {
        let (root, path) = created("restore-completion-error");
        drop(Inventory::open(&path, &estate()).unwrap());
        let guard = RestoreGuard::begin(&root, "0123456789abcdef", Uuid::new_v4()).unwrap();
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let id = inventory.jobs().unwrap()[0].job_id;
        inventory.conn.execute_batch("CREATE TRIGGER reject_finish BEFORE UPDATE ON job WHEN NEW.state = 'complete' BEGIN SELECT RAISE(FAIL, 'injected'); END;").unwrap();
        assert!(guard.complete().is_err());
        drop(guard);
        assert_eq!(inventory.job(id).unwrap().unwrap().state, JobState::Running);
        inventory
            .conn
            .execute_batch("DROP TRIGGER reject_finish")
            .unwrap();
        assert_eq!(inventory.sweep_interrupted(&root).unwrap(), vec![id]);
        assert_eq!(
            inventory.job(id).unwrap().unwrap().state,
            JobState::Interrupted
        );
        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_estate_is_a_fingerprint_not_a_name() {
        for value in [
            "nightly",
            "",
            "C1CB425F097B6522",
            "c1cb425f097b652",
            "c1cb425f097b65222",
        ] {
            let error = Estate::new(value.to_string())
                .expect_err(&format!("{value:?} is not a source fingerprint"));
            assert!(error.to_string().contains("lowercase"), "{error}");
        }
        assert!(Estate::new(SOURCE.to_string()).is_ok());
    }

    /// Three files an operator might hand to `backup list` that are not an inventory, each
    /// refused by name rather than read as an empty history.
    #[test]
    fn a_read_never_invents_and_never_guesses_an_inventory() {
        let dir = temp_dir("read-only");
        fs::create_dir_all(&dir).unwrap();

        let missing = dir.join(INVENTORY_FILE);
        let error = Inventory::open_read_only(&missing, &estate())
            .expect_err("an audit read must not create a file")
            .to_string();
        assert!(error.contains("the file does not exist"), "{error}");
        assert!(
            !missing.exists(),
            "a refused read created the file it refused on"
        );

        // A zero-byte file is a *valid empty database* to SQLite, at version 0, with no tables.
        let zero = dir.join("zero.db");
        fs::write(&zero, []).unwrap();
        let error = Inventory::open_read_only(&zero, &estate())
            .expect_err("nothing here is a backup history")
            .to_string();
        assert!(error.contains("declares no schema version"), "{error}");

        // A foreign database: real tables, real rows, no `user_version`.
        let foreign = dir.join("foreign.db");
        {
            let conn = Connection::open(&foreign).unwrap();
            conn.execute_batch("CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT);")
                .unwrap();
        }
        let error = Inventory::open_read_only(&foreign, &estate())
            .expect_err("someone's SQLite file is not this store's index")
            .to_string();
        assert!(error.contains("declares no schema version"), "{error}");

        // And a real inventory at a version this build has never heard of.
        let newer = dir.join("newer.db");
        let next = SCHEMA_VERSION + 1;
        {
            let inventory = Inventory::open(&newer, &estate()).unwrap();
            inventory
                .conn
                .execute_batch(&format!("PRAGMA user_version={next}; DROP TABLE meta;"))
                .unwrap();
        }
        let error = Inventory::open_read_only(&newer, &estate())
            .expect_err("a newer schema is not this build's schema")
            .to_string();
        assert!(error.contains(&format!("schema version {next}")), "{error}");
        let error = Inventory::open(&newer, &estate())
            .expect_err("and it is not writable by this build either")
            .to_string();
        assert!(error.contains(&format!("schema version {next}")), "{error}");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_keyless_rebuild_leaves_unknowns_unknown_and_a_later_read_fills_them_in() {
        let (dir, path) = created("partial");
        let inventory = Inventory::open(&path, &estate()).unwrap();

        // What `public.json` says, and nothing more: no profile, no completion time.
        let mut row = signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a");
        row.profile_fingerprint = None;
        row.completed_at_utc = None;
        inventory.register(&row).unwrap();
        let read = inventory.artifact(row.backup_id).unwrap().unwrap();
        assert_eq!(read.profile_fingerprint, None);
        assert_eq!(read.completed_at_utc, None);
        assert_eq!(read.shape, Shape::V1Signed);
        assert_eq!(read.signature_suite.as_deref(), Some("ed25519+ml-dsa-65"));

        // The same id, now that the keys are on this host: the fuller row replaces the partial
        // one, which is what `INSERT OR REPLACE` is for here.
        inventory.register(&row_with_keys(&row)).unwrap();
        let read = inventory.artifact(row.backup_id).unwrap().unwrap();
        assert_eq!(
            read,
            ArtifactRow {
                profile_fingerprint: Some("651dd7a74505b176".to_string()),
                completed_at_utc: Some("2026-09-28T06:15:00Z".to_string()),
                ..row.clone()
            }
        );
        assert_eq!(inventory.artifacts().unwrap().len(), 1, "one id is one row");

        drop(inventory);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn row_with_keys(row: &ArtifactRow) -> ArtifactRow {
        ArtifactRow {
            profile_fingerprint: Some("651dd7a74505b176".to_string()),
            completed_at_utc: Some("2026-09-28T06:15:00Z".to_string()),
            ..row.clone()
        }
    }

    #[test]
    fn registration_preserves_known_facts_and_observed_state() {
        let (dir, path) = created("preserve-observations");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a");
        inventory.register(&row).unwrap();
        inventory
            .reconcile_states(
                std::slice::from_ref(&row),
                &[(row.backup_id, State::Registered, State::Missing)],
            )
            .unwrap();
        let mut partial = row.clone();
        partial.profile_fingerprint = None;
        partial.completed_at_utc = None;
        inventory.register(&partial).unwrap();
        let stored = inventory.artifact(row.backup_id).unwrap().unwrap();
        assert_eq!(stored.profile_fingerprint, row.profile_fingerprint);
        assert_eq!(stored.completed_at_utc, row.completed_at_utc);
        assert_eq!(stored.state, State::Missing);
        let before = inventory.audit_events().unwrap();
        partial.payload_sha256 = Some("e".repeat(64));
        assert!(inventory.register(&partial).is_err());
        assert_eq!(inventory.artifact(row.backup_id).unwrap().unwrap(), stored);
        assert_eq!(inventory.audit_events().unwrap(), before);
        let snapshot = inventory.artifacts().unwrap();
        inventory.conn.execute(
            "UPDATE artifact SET completed_at_utc = '2026-09-29T06:15:00Z' WHERE backup_id = ?1",
            [row.backup_id.to_string()],
        ).unwrap();
        assert!(
            inventory
                .reconcile_states(
                    &snapshot,
                    &[(row.backup_id, State::Missing, State::Conflict)]
                )
                .is_err()
        );
        assert_eq!(
            inventory.artifact(row.backup_id).unwrap().unwrap().state,
            State::Missing
        );
        assert_eq!(inventory.audit_events().unwrap(), before);
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    /// The ordering the retention rule and the replay ledger both read: by completion, with the
    /// never-completed last, and never by an id that is random by format.
    #[test]
    fn rows_order_by_completion_and_never_by_the_random_id() {
        let (dir, path) = created("order");
        let inventory = Inventory::open(&path, &estate()).unwrap();

        let mut newest = signed_row("11111111-1111-4111-8111-111111111111");
        newest.completed_at_utc = Some("2026-09-30T00:00:00Z".to_string());
        let mut oldest = signed_row("99999999-9999-4999-8999-999999999999");
        oldest.completed_at_utc = Some("2026-09-28T00:00:00Z".to_string());
        let mut unknown = signed_row("55555555-5555-4555-8555-555555555555");
        unknown.completed_at_utc = None;

        // Registered newest first, id ascending for the two knowns, to prove the read reorders.
        for row in [&newest, &oldest, &unknown] {
            inventory.register(row).unwrap();
        }
        let order = inventory
            .artifacts()
            .unwrap()
            .into_iter()
            .map(|row| row.completed_at_utc)
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                Some("2026-09-28T00:00:00Z".to_string()),
                Some("2026-09-30T00:00:00Z".to_string()),
                None,
            ]
        );

        drop(inventory);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A row this build cannot have written is reported, not defaulted. The two halves differ in
    /// how reachable they are, and that difference is the point: `shape` is guarded by the
    /// schema's `CHECK`, so an edit to it fails at the database, while `state` is deliberately
    /// unconstrained, so a bad one survives to the read. That is choice 2's residual made visible.
    #[test]
    fn an_edited_row_is_refused_rather_than_defaulted() {
        let (dir, path) = created("edited");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a");
        inventory.register(&row).unwrap();

        let error = inventory
            .conn
            .execute(
                "UPDATE artifact SET shape = ?1 WHERE backup_id = ?2",
                rusqlite::params!["v1-unsigned", row.backup_id.to_string()],
            )
            .expect_err("a shape word no build writes must not be storable at all");
        assert!(
            error
                .to_string()
                .contains("CHECK constraint failed: shape IN"),
            "{error}"
        );

        inventory
            .conn
            .execute(
                "UPDATE artifact SET state = 'erased' WHERE backup_id = ?1",
                [row.backup_id.to_string()],
            )
            .unwrap();
        let error = inventory
            .artifacts()
            .expect_err("unknown vocabulary must refuse")
            .to_string();
        assert!(error.contains("erased"), "{error}");
        let error = inventory
            .artifact(row.backup_id)
            .expect_err("and the same refusal on the single-row read")
            .to_string();
        assert!(error.contains("erased"), "{error}");

        drop(inventory);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn registering_validates_before_touching_the_database() {
        let (dir, path) = created("validate");
        let inventory = Inventory::open(&path, &estate()).unwrap();

        let mut foreign = signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a");
        foreign.source_fingerprint = OTHER_SOURCE.to_string();
        let error = chain(
            inventory
                .register(&foreign)
                .expect_err("a row for another estate"),
        );
        assert!(error.contains("cannot register backup"), "{error}");
        assert!(error.contains("refusing to register"), "{error}");

        // The schema's own CHECK fires from the SQLite side too, and the sentence the operator
        // sees names the constraint rather than pretending the row was fine.
        let mut empty_digest = signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a");
        empty_digest.payload_sha256 = None;
        let error = chain(
            inventory
                .register(&empty_digest)
                .expect_err("a signed row without its payload digest"),
        );
        assert!(error.contains("payload_sha256"), "{error}");
        assert_eq!(inventory.artifacts().unwrap().len(), 0);

        drop(inventory);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Two inventories in one process, which is what a concurrent `backup create` and
    /// `backup list` are: the busy timeout makes the second one wait briefly and then answer,
    /// rather than hanging for rusqlite's five-second default.
    #[test]
    fn a_locked_inventory_answers_instead_of_waiting_five_seconds() {
        let (dir, path) = created("busy");
        let writer = Inventory::open(&path, &estate()).unwrap();
        let blocker = Connection::open(&path).unwrap();
        blocker
            .execute_batch(
                "BEGIN IMMEDIATE; INSERT INTO meta (key, value) VALUES ('lock', 'held');",
            )
            .unwrap();

        let started = std::time::Instant::now();
        let error = writer
            .register(&signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a"))
            .expect_err("a held write lock must be refused");
        let waited = started.elapsed();
        let text = format!("{error:#}");
        assert!(text.contains("database is locked"), "{text}");
        assert!(
            waited.as_millis() < 4_000,
            "waited {waited:?}; the busy timeout is not the two seconds this format asks for"
        );

        blocker.execute_batch("COMMIT").unwrap();
        writer
            .register(&signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a"))
            .unwrap();

        drop(writer);
        drop(blocker);
        fs::remove_dir_all(&dir).unwrap();
    }

    const PROFILE: &str = "651dd7a74505b176";
    const OTHER_PROFILE: &str = "1111111111111111";

    fn scope(profile: &str) -> JobScope {
        JobScope {
            source_fingerprint: SOURCE.to_string(),
            profile_fingerprint: profile.to_string(),
            backup_id: Uuid::new_v4(),
        }
    }

    /// A job row built by hand, for the test that needs one to exist without a guard holding its
    /// lock — which is exactly what a process killed mid-dump leaves behind.
    fn job_row(profile: &str) -> JobRow {
        let now = now_utc().unwrap();
        JobRow {
            job_id: Uuid::new_v4(),
            backup_id: None,
            source_fingerprint: SOURCE.to_string(),
            profile_fingerprint: profile.to_string(),
            state: JobState::Running,
            started_at_utc: now.clone(),
            updated_at_utc: now,
        }
    }

    /// The trail as a *later* command sees it: a second handle, opened read-only, so what a test
    /// asserts is what is on the file rather than what a guard remembers writing.
    fn trail(root: &std::path::Path) -> Vec<(AuditAction, Option<Uuid>)> {
        let inventory = Inventory::open_read_only(&root.join(INVENTORY_FILE), &estate()).unwrap();
        inventory
            .audit_events()
            .unwrap()
            .into_iter()
            .map(|event| (event.action, event.job_id))
            .collect()
    }

    /// Every state has a writer, and every write leaves an event behind. This is the whole
    /// vocabulary in one run.
    #[test]
    fn a_job_walks_its_states_and_the_trail_records_every_move() {
        let (root, _) = created("walk");
        let scope = scope(PROFILE);
        let backup_id = scope.backup_id;
        let guard = JobGuard::begin(&root, &scope).unwrap();

        assert_eq!(guard.state().unwrap(), JobState::Running);
        guard.staged().unwrap();
        guard.complete().unwrap();
        let state = guard.state().unwrap();
        assert_eq!(state, JobState::Complete);
        assert!(state.is_terminal());

        let events = trail(&root);
        assert_eq!(
            events.iter().map(|(action, _)| *action).collect::<Vec<_>>(),
            vec![
                AuditAction::JobStarted,
                AuditAction::JobStaged,
                AuditAction::JobCompleted
            ]
        );
        // Every event names this job, so the trail can be read per job rather than per file, and
        // the row names the artifact the job was for.
        assert!(
            events.iter().all(|(_, job)| *job == Some(guard.id())),
            "{events:?}"
        );
        let row = Inventory::open_read_only(&root.join(INVENTORY_FILE), &estate())
            .unwrap()
            .job(guard.id())
            .unwrap()
            .unwrap();
        assert_eq!(row.backup_id, Some(backup_id));
        assert_eq!(row.source_fingerprint, SOURCE);
        assert_eq!(row.profile_fingerprint, PROFILE);

        // A finished job cannot be moved again, so the trail cannot gain a second completion.
        let error = chain(
            guard
                .complete()
                .expect_err("a complete job is not completing a second time"),
        );
        assert!(
            error.contains("cannot move to complete from a finished state"),
            "{error}"
        );
        assert_eq!(trail(&root), events);

        // And the drop after a terminal state writes nothing at all.
        drop(guard);
        assert_eq!(trail(&root), events);

        fs::remove_dir_all(&root).unwrap();
    }

    /// `failed` has no call site that writes it, and that is the design: an ordinary `Err` return
    /// from anywhere in a command reaches it through the guard's drop, so no error path in the
    /// tool has to remember to report — and none can forget.
    #[test]
    fn a_guard_dropped_on_the_error_path_reads_as_failed_and_frees_the_lock() {
        let (root, _) = created("dropped");
        let guard = JobGuard::begin(&root, &scope(PROFILE)).unwrap();
        let id = guard.id();
        guard.staged().unwrap();
        drop(guard);

        let inventory = Inventory::open_read_only(&root.join(INVENTORY_FILE), &estate()).unwrap();
        assert_eq!(inventory.job(id).unwrap().unwrap().state, JobState::Failed);
        assert_eq!(
            inventory
                .audit_events()
                .unwrap()
                .into_iter()
                .map(|event| event.action)
                .collect::<Vec<_>>(),
            vec![
                AuditAction::JobStarted,
                AuditAction::JobStaged,
                AuditAction::JobFailed
            ]
        );
        // A `failed` row is finished with, so the scope is open for the next run.
        assert!(JobLock::is_free(&root, SOURCE, PROFILE).unwrap());

        fs::remove_dir_all(&root).unwrap();
    }

    /// The case ADR 0003 chose persisted states for, and the reason the sweep asks the kernel
    /// rather than a timestamp: a dump of a large database legitimately sits in `running` for
    /// hours, and only a free lock says nobody is dumping.
    ///
    /// ADR 0004 moved the sweep out of [`Inventory::open`], so this also proves the other half: an
    /// open — which every writable command performs, including one that then refuses — corrects
    /// nothing until a maintenance pass asks it to.
    #[test]
    fn only_an_explicit_pass_marks_a_dead_row_interrupted_and_a_live_one_is_left_alone() {
        let (root, path) = created("sweep");
        let live = JobGuard::begin(&root, &scope(PROFILE)).unwrap();
        let live_id = live.id();

        // A second write open while the first job is still running — `backup list` during a nightly
        // dump. Same process here, which is the harder direction to get wrong: a rule that trusted
        // the pid would see its own holder and call it dead.
        let other = Inventory::open(&path, &estate()).unwrap();
        assert_eq!(
            other.job(live_id).unwrap().unwrap().state,
            JobState::Running,
            "a bystander's open must not interrupt a live job"
        );

        // A row for a scope that holds no lock at all, which is what a killed process leaves once
        // the kernel closed its descriptor.
        let dead = job_row(OTHER_PROFILE);
        let dead_id = dead.job_id;
        other.begin_job(&dead).unwrap();
        drop(other);

        let opened = Inventory::open(&path, &estate()).unwrap();
        assert_eq!(
            opened.job(dead_id).unwrap().unwrap().state,
            JobState::Running,
            "opening swept a row nothing asked it to sweep"
        );
        assert_eq!(
            opened.sweep_interrupted(&root).unwrap(),
            vec![dead_id],
            "the pass reported something other than the one job it moved"
        );
        assert_eq!(
            opened.job(dead_id).unwrap().unwrap().state,
            JobState::Interrupted
        );
        assert_eq!(
            opened.job(live_id).unwrap().unwrap().state,
            JobState::Running
        );
        // The sweep is the writer of `job_interrupted`, so the trail says when the gap became
        // known as well as that it happened.
        let interrupted = opened
            .audit_events()
            .unwrap()
            .into_iter()
            .filter(|event| event.action == AuditAction::JobInterrupted)
            .collect::<Vec<_>>();
        assert_eq!(interrupted.len(), 1);
        assert_eq!(interrupted[0].job_id, Some(dead_id));
        // Marking a row is a transition, so `updated_at_utc` moves and `started_at_utc` does not.
        assert_eq!(
            opened.job(dead_id).unwrap().unwrap().started_at_utc,
            dead.started_at_utc
        );
        // And once is enough: the row is terminal now, so a second pass on the same handle moves
        // nothing and appends nothing.
        assert!(opened.sweep_interrupted(&root).unwrap().is_empty());
        assert_eq!(
            opened
                .audit_events()
                .unwrap()
                .iter()
                .filter(|event| event.action == AuditAction::JobInterrupted)
                .count(),
            1
        );
        drop(opened);

        // A guard dropped *cleanly* is a job that finished with, not an interrupted one: `failed`
        // is what its own drop writes, and the sweep exists only for the case where no code ran on
        // the way out. So this row never enters the interrupted count.
        drop(live);
        let after = Inventory::open(&path, &estate()).unwrap();
        assert_eq!(after.job(live_id).unwrap().unwrap().state, JobState::Failed);
        assert!(after.sweep_interrupted(&root).unwrap().is_empty());
        assert_eq!(
            after
                .audit_events()
                .unwrap()
                .iter()
                .filter(|event| event.action == AuditAction::JobInterrupted)
                .count(),
            1
        );
        drop(after);

        // And once each is enough across handles too: both terminal states stay put, so a later open
        // neither repeats the sweep nor grows the trail.
        let again = Inventory::open(&path, &estate()).unwrap();
        assert_eq!(
            again.job(dead_id).unwrap().unwrap().state,
            JobState::Interrupted
        );
        assert_eq!(again.job(live_id).unwrap().unwrap().state, JobState::Failed);
        assert_eq!(
            again
                .audit_events()
                .unwrap()
                .iter()
                .filter(|event| event.action == AuditAction::JobInterrupted)
                .count(),
            1
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// ADR 0004's conditional transition, which is what §18's "must not overwrite a job that
    /// completed after a snapshot read" is made of. The sweep reads the open rows, then probes each
    /// scope's lock; a job that reaches a terminal state inside that window has already answered the
    /// question the pass was about to write, so the update has to miss.
    #[test]
    fn a_row_that_finished_after_the_snapshot_is_not_written_as_interrupted() {
        let (root, path) = created("late");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = job_row(PROFILE);
        let id = row.job_id;
        inventory.begin_job(&row).unwrap();
        // The snapshot has been taken — and before the pass writes, this job completes.
        inventory
            .set_job_state(id, JobState::Complete, AuditAction::JobCompleted)
            .unwrap();

        assert!(
            !job::mark_interrupted(&inventory.conn, id).unwrap(),
            "a completed job was rewritten as interrupted"
        );
        assert_eq!(
            inventory.job(id).unwrap().unwrap().state,
            JobState::Complete
        );
        assert_eq!(
            inventory
                .audit_events()
                .unwrap()
                .iter()
                .filter(|event| event.action == AuditAction::JobInterrupted)
                .count(),
            0,
            "the trail records a transition that did not happen"
        );

        // The same write on a row that really is still open lands, once.
        let abandoned = job_row(OTHER_PROFILE);
        inventory.begin_job(&abandoned).unwrap();
        assert!(job::mark_interrupted(&inventory.conn, abandoned.job_id).unwrap());
        assert!(!job::mark_interrupted(&inventory.conn, abandoned.job_id).unwrap());
        drop(inventory);
        fs::remove_dir_all(&root).unwrap();
    }

    /// The recovery pass cannot compute a source fingerprint — that needs a live database to learn
    /// the server major — so it reads the estate off the file it is correcting, and a store with no
    /// index at all gets no index invented for it.
    #[test]
    fn a_bound_open_reads_the_estate_off_the_file_and_creates_nothing() {
        let (root, path) = created("bound");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let dead = job_row(PROFILE);
        let dead_id = dead.job_id;
        inventory.begin_job(&dead).unwrap();
        drop(inventory);

        let recovered = Inventory::open_bound(&path).unwrap().unwrap();
        assert_eq!(recovered.estate().source_fingerprint, SOURCE);
        assert_eq!(recovered.sweep_interrupted(&root).unwrap(), vec![dead_id]);
        drop(recovered);

        // No file, nothing to recover — and the pass that deletes things is the last one that
        // should be able to leave a database behind.
        let dir = temp_dir("unbound");
        let missing = dir.join(INVENTORY_FILE);
        assert!(Inventory::open_bound(&missing).unwrap().is_none());
        assert!(!missing.exists());
        fs::remove_dir_all(&root).unwrap();
    }

    /// The refusal [`crate::artifact`] applies to `state`, applied to the two tables that leave
    /// their vocabulary to Rust: `job.state` has no `CHECK`, and a word from a later build is
    /// reported rather than defaulted to something a retention rule could act on.
    #[test]
    fn an_edited_job_row_is_refused_rather_than_defaulted() {
        let (root, path) = created("edited-job");
        let guard = JobGuard::begin(&root, &scope(PROFILE)).unwrap();
        let id = guard.id();
        let inventory = Inventory::open(&path, &estate()).unwrap();

        inventory
            .conn
            .execute(
                "UPDATE job SET state = 'planned' WHERE job_id = ?1",
                [id.to_string()],
            )
            .unwrap();
        let error = inventory
            .jobs()
            .expect_err("a state no build of this tool writes is not a state")
            .to_string();
        assert!(error.contains("planned"), "{error}");

        // The timestamps carry the same rule as the artifact's: a value that is not the artifact
        // form would put a job in the wrong place in an ordering nothing else checks.
        inventory
            .conn
            .execute(
                "UPDATE job SET state = 'running', started_at_utc = 'yesterday' WHERE job_id = ?1",
                [id.to_string()],
            )
            .unwrap();
        let error = inventory
            .job(id)
            .expect_err("and a timestamp nobody wrote is refused too")
            .to_string();
        assert!(error.contains("not the artifact timestamp form"), "{error}");

        drop(guard);
        fs::remove_dir_all(&root).unwrap();
    }

    /// A refusal that leaves nothing behind is what makes the overlap rule safe to run on a store
    /// an operator is also reading: two fingerprints, no more.
    #[test]
    fn a_second_holder_of_one_scope_is_refused_without_touching_the_inventory() {
        let (root, path) = created("overlap");
        let held = JobGuard::begin(&root, &scope(PROFILE)).unwrap();
        let before = fs::read(&path).unwrap();

        let error = chain(
            JobGuard::begin(&root, &scope(PROFILE))
                .expect_err("one scope cannot have two running jobs"),
        );
        assert!(error.contains("already running"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), before, "a refusal wrote");
        assert_eq!(
            trail(&root)
                .iter()
                .map(|(action, _)| *action)
                .collect::<Vec<_>>(),
            vec![AuditAction::JobStarted]
        );

        // Another profile of the same source is another scope, and runs.
        let weekly = JobGuard::begin(&root, &scope(OTHER_PROFILE)).unwrap();
        assert_ne!(weekly.lock_path(), held.lock_path());

        drop(weekly);
        drop(held);
        fs::remove_dir_all(&root).unwrap();
    }

    /// A registered artifact is an event even though it is not a job: the publish path holds no
    /// lock, so `job_id` is NULL and the link back to a `backup create` is the `backup_id` that
    /// job's own row already names.
    #[test]
    fn registering_an_artifact_appends_an_event_naming_no_job() {
        let (dir, path) = created("register-event");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a");
        inventory.register(&row).unwrap();
        inventory.register(&row).unwrap();

        let events = inventory.audit_events().unwrap();
        assert_eq!(events.len(), 2, "a re-registration is still an event");
        assert!(
            events
                .iter()
                .all(|event| event.action == AuditAction::ArtifactRegistered)
        );
        assert!(events.iter().all(|event| event.job_id.is_none()));
        assert!(
            events
                .iter()
                .all(|event| event.backup_id == Some(row.backup_id))
        );
        // A backup id is random and orders nothing, so the trail's ordering is its own rowid.
        assert_eq!(
            events.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![1, 2]
        );

        // And a refused registration writes neither half, which is what the transaction is for: a
        // trail claiming an artifact the table does not hold would be read as a lost backup.
        let mut foreign = signed_row("11111111-1111-4111-8111-111111111111");
        foreign.source_fingerprint = OTHER_SOURCE.to_string();
        assert!(inventory.register(&foreign).is_err());
        assert_eq!(inventory.audit_events().unwrap().len(), 2);
        assert_eq!(inventory.artifacts().unwrap().len(), 1);

        drop(inventory);
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn retention_evidence_selects_latest_current_exact_archive_event() {
        let (dir, path) = created("retention-event");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row("20000000-0000-4000-8000-000000000001");
        inventory.register(&row).unwrap();
        let payload = row.payload_sha256.as_deref().unwrap();
        let manifest = row.manifest_sha256.as_deref().unwrap();
        let evidence = || {
            inventory
                .current_archive_event(row.backup_id, payload, manifest)
                .unwrap()
        };
        assert_eq!(evidence(), None);
        for level in ["signature", "checksum"] {
            inventory
                .record_verification(
                    row.backup_id,
                    level,
                    true,
                    Some((payload, Some(manifest))),
                    None,
                )
                .unwrap();
            assert_eq!(evidence(), None);
        }
        inventory
            .record_verification(
                row.backup_id,
                "archive",
                true,
                Some((payload, Some(manifest))),
                None,
            )
            .unwrap();
        let first = evidence().unwrap();
        inventory
            .record_verification(
                row.backup_id,
                "archive",
                true,
                Some((payload, Some(manifest))),
                None,
            )
            .unwrap();
        let second = evidence().unwrap();
        assert!(second > first);
        assert_eq!(
            inventory
                .current_archive_event(row.backup_id, &"e".repeat(64), manifest)
                .unwrap(),
            None
        );
        inventory
            .conn
            .execute(
                "UPDATE verification_event SET manifest_sha256=NULL WHERE event_id=?1",
                [second],
            )
            .unwrap();
        assert_eq!(evidence(), Some(first));
        inventory
            .record_verification(row.backup_id, "signature", false, None, None)
            .unwrap();
        assert_eq!(evidence(), None);
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn read_only_wal_refusal_never_creates_sqlite_sidecars() {
        let (dir, path) = created("read-wal");
        drop(Inventory::open(&path, &estate()).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=wal").unwrap();
        drop(conn);
        // Positive control: the same SQLite read without the header gate creates sidecars.
        let raw =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            raw.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert!(dir.join("inventory.db-wal").exists() && dir.join("inventory.db-shm").exists());
        drop(raw);
        for suffix in ["-wal", "-shm"] {
            let path = dir.join(format!("inventory.db{suffix}"));
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        let before = fs::read(&path).unwrap();
        assert!(
            Inventory::open_read_only_bound(&path)
                .unwrap_err()
                .to_string()
                .contains("journal")
        );
        assert!(
            Inventory::open_read_only(&path, &estate())
                .unwrap_err()
                .to_string()
                .contains("journal")
        );
        assert!(
            Inventory::probe_version(&path)
                .unwrap_err()
                .to_string()
                .contains("journal")
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
    fn deletion_fixture() -> (
        std::path::PathBuf,
        Inventory,
        backup_domain::SavedDeletionPlan,
    ) {
        let (dir, path) = created("deletion");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        use backup_domain::{
            ArtifactSnapshot, DELETION_PLAN_FORMAT, DELETION_PLAN_TTL_MS, DeletionPlan,
            FileSnapshot, Protection, RetentionOperation,
        };
        let member = |n: u128| ArtifactSnapshot {
            backup_id: Uuid::from_u128(0x20000000000040008000000000000000 + n),
            completed_at_utc: "2026-09-28T06:15:00Z".into(),
            signer_id: "a".repeat(16),
            protection: Protection::Unprotected,
            verification_event_id: 1,
            files: backup_domain::DELETION_FILES
                .iter()
                .map(|name| FileSnapshot {
                    name: name.to_string(),
                    bytes: match *name {
                        "complete" => 0,
                        "signature.hybrid" => 3373,
                        _ => 1,
                    },
                    sha256: if *name == "complete" {
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
                    } else {
                        "a".repeat(64)
                    },
                })
                .collect(),
        };
        let plan = DeletionPlan {
            format: DELETION_PLAN_FORMAT.into(),
            plan_id: Uuid::new_v4(),
            operation: RetentionOperation::Delete,
            source_fingerprint: SOURCE.into(),
            profile_fingerprint: "651dd7a74505b176".into(),
            keep_last: None,
            created_unix_ms: 0,
            expires_unix_ms: DELETION_PLAN_TTL_MS,
            inventory_sha256: "a".repeat(64),
            candidates: vec![member(1)],
            retained: vec![member(2)],
        };
        for a in plan.candidates.iter().chain(&plan.retained) {
            let mut row = signed_row(&a.backup_id.to_string());
            row.profile_fingerprint = Some(plan.profile_fingerprint.clone());
            inventory.register(&row).unwrap();
        }
        let saved = backup_domain::SavedDeletionPlan {
            digest: plan.digest().unwrap(),
            plan,
        };
        (dir, inventory, saved)
    }

    #[test]
    fn deletion_start_intent_completion_and_terminal_audits_are_atomic() {
        for action in [
            "job_started",
            "artifact_deleting",
            "artifact_deleted",
            "job_completed",
        ] {
            let (dir, inventory, saved) = deletion_fixture();
            let id = saved.plan.candidates[0].backup_id;
            if action == "job_started" {
                inventory.conn.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON audit_event WHEN NEW.action='job_started' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
                let events = inventory.audit_events().unwrap();
                assert!(inventory.begin_deletion(&saved).is_err());
                assert!(inventory.jobs().unwrap().is_empty());
                assert!(inventory.deletion_recovery_ids().unwrap().is_empty());
                assert_eq!(
                    inventory
                        .conn
                        .query_row("SELECT COUNT(*) FROM job_artifact", [], |r| r
                            .get::<_, i64>(0))
                        .unwrap(),
                    0
                );
                assert_eq!(inventory.audit_events().unwrap(), events);
            } else {
                let job_id = inventory.begin_deletion(&saved).unwrap();
                if action != "artifact_deleting" {
                    inventory.mark_deleting(job_id, id).unwrap();
                }
                if action == "job_completed" {
                    inventory.mark_deleted(job_id, id).unwrap();
                }
                inventory.conn.execute_batch(&format!("CREATE TRIGGER reject_event BEFORE INSERT ON audit_event WHEN NEW.action='{action}' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
                let rows = inventory.artifacts().unwrap();
                let events = inventory.audit_events().unwrap();
                let before = inventory
                    .deletion_dependencies(job_id)
                    .unwrap()
                    .into_iter()
                    .map(|d| (d.backup_id, d.role, d.progress))
                    .collect::<Vec<_>>();
                let result = match action {
                    "artifact_deleting" => inventory.mark_deleting(job_id, id),
                    "artifact_deleted" => inventory.mark_deleted(job_id, id),
                    _ => inventory.finish_deletion(job_id, true),
                };
                assert!(result.is_err());
                assert_eq!(inventory.artifacts().unwrap(), rows);
                assert_eq!(inventory.audit_events().unwrap(), events);
                assert_eq!(
                    inventory
                        .deletion_dependencies(job_id)
                        .unwrap()
                        .into_iter()
                        .map(|d| (d.backup_id, d.role, d.progress))
                        .collect::<Vec<_>>(),
                    before
                );
                assert_eq!(
                    inventory.job(job_id).unwrap().unwrap().state,
                    JobState::Running
                );
            }
            drop(inventory);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn deletion_recovery_evidence_rejects_missing_dependencies_operation_and_audit() {
        for mutation in [
            "DELETE FROM job_artifact WHERE role='retained'",
            "UPDATE job_operation SET operation='prune'",
            "DELETE FROM audit_event WHERE action='artifact_deleting'",
            "UPDATE artifact SET state='registered' WHERE state='deleting'",
        ] {
            let (dir, inventory, saved) = deletion_fixture();
            let job_id = inventory.begin_deletion(&saved).unwrap();
            inventory
                .mark_deleting(job_id, saved.plan.candidates[0].backup_id)
                .unwrap();
            inventory.conn.execute_batch(mutation).unwrap();
            let result = inventory
                .deletion_job(saved.plan.plan_id)
                .and_then(|j| j.unwrap().validate(&saved));
            assert!(result.is_err(), "accepted {mutation}");
            drop(inventory);
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn registration_and_adoption_cannot_create_tombstones_without_intent() {
        let (dir, path) = created("forged-tombstone");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let mut row = signed_row(&Uuid::new_v4().to_string());
        row.profile_fingerprint = None;
        row.completed_at_utc = None;
        for state in [State::Deleting, State::Deleted] {
            row.state = state;
            assert!(inventory.register(&row).is_err());
            assert!(inventory.adopt(&row).is_err());
            assert!(inventory.artifacts().unwrap().is_empty());
            assert!(inventory.audit_events().unwrap().is_empty());
        }
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn completion_marks_are_scoped_monotone_validated_and_survive_lifecycle_changes() {
        let (dir, path) = created("completion");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let signer = "a".repeat(16);
        let row = signed_row(&Uuid::new_v4().to_string());
        inventory.register(&row).unwrap();
        assert!(
            inventory
                .completion_mark(SOURCE, &signer)
                .unwrap()
                .is_none()
        );
        let mark = backup_domain::CompletionMark {
            artifact_id: row.backup_id,
            completed_at_utc: row.completed_at_utc.clone().unwrap(),
        };
        assert_eq!(
            inventory
                .observe_completion(SOURCE, &signer, &mark)
                .unwrap(),
            mark
        );
        let events = inventory.audit_events().unwrap();
        let tie = backup_domain::CompletionMark {
            artifact_id: Uuid::new_v4(),
            ..mark.clone()
        };
        assert_eq!(
            inventory.observe_completion(SOURCE, &signer, &tie).unwrap(),
            mark
        );
        let old = backup_domain::CompletionMark {
            completed_at_utc: "2026-01-01T00:00:00Z".into(),
            ..tie.clone()
        };
        assert_eq!(
            inventory.observe_completion(SOURCE, &signer, &old).unwrap(),
            mark
        );
        assert_eq!(inventory.audit_events().unwrap(), events);
        assert!(
            inventory
                .completion_mark(SOURCE, &"b".repeat(16))
                .unwrap()
                .is_none()
        );
        assert!(
            inventory
                .observe_completion(OTHER_SOURCE, &signer, &mark)
                .is_err()
        );
        assert!(inventory.observe_completion(SOURCE, "bad", &mark).is_err());
        for time in ["", "2026-02-30T00:00:00Z", "2026-01-01T00:00:00+00:00"] {
            assert!(
                inventory
                    .observe_completion(
                        SOURCE,
                        &signer,
                        &backup_domain::CompletionMark {
                            completed_at_utc: time.into(),
                            ..tie.clone()
                        }
                    )
                    .is_err()
            );
        }
        let newest = backup_domain::CompletionMark {
            completed_at_utc: "2026-11-14T00:00:00Z".into(),
            ..tie
        };
        inventory
            .observe_completion(SOURCE, &signer, &newest)
            .unwrap();
        inventory
            .record_verification(row.backup_id, "checksum", false, None, None)
            .unwrap();
        inventory
            .conn
            .execute(
                "UPDATE artifact SET state='deleted' WHERE backup_id=?1",
                [row.backup_id.to_string()],
            )
            .unwrap();
        assert_eq!(
            inventory.completion_mark(SOURCE, &signer).unwrap(),
            Some(newest)
        );
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn completion_advancement_rolls_back_with_publication_and_verification_audit_failures() {
        let (dir, path) = created("completion-atomic");
        let inventory = Inventory::open(&path, &estate()).unwrap();
        let row = signed_row(&Uuid::new_v4().to_string());
        let signer = row.signer_id.as_deref().unwrap();
        inventory.conn.execute_batch("CREATE TRIGGER refuse_mark BEFORE INSERT ON audit_event WHEN NEW.action='completion_advanced' BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert!(inventory.register_published(&row).is_err());
        assert!(inventory.artifacts().unwrap().is_empty());
        assert!(inventory.audit_events().unwrap().is_empty());
        assert!(inventory.completion_mark(SOURCE, signer).unwrap().is_none());
        let mut discovered = row.clone();
        discovered.profile_fingerprint = None;
        discovered.completed_at_utc = None;
        inventory.adopt(&discovered).unwrap();
        assert!(inventory.completion_mark(SOURCE, signer).unwrap().is_none());
        let events = inventory.audit_events().unwrap();
        assert!(
            inventory
                .record_verification(
                    row.backup_id,
                    "checksum",
                    true,
                    Some((
                        row.payload_sha256.as_deref().unwrap(),
                        row.manifest_sha256.as_deref()
                    )),
                    Some((
                        SOURCE,
                        row.profile_fingerprint.as_deref().unwrap(),
                        row.completed_at_utc.as_deref().unwrap()
                    ))
                )
                .is_err()
        );
        assert!(inventory.is_provisional(row.backup_id).unwrap());
        assert!(
            inventory
                .verification_events(row.backup_id)
                .unwrap()
                .is_empty()
        );
        assert!(inventory.completion_mark(SOURCE, signer).unwrap().is_none());
        assert_eq!(inventory.audit_events().unwrap(), events);
        inventory.conn.execute_batch("DROP TRIGGER refuse_mark; CREATE TRIGGER refuse_verification BEFORE INSERT ON verification_event BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert!(
            inventory
                .record_verification(
                    row.backup_id,
                    "checksum",
                    true,
                    Some((
                        row.payload_sha256.as_deref().unwrap(),
                        row.manifest_sha256.as_deref()
                    )),
                    Some((
                        SOURCE,
                        row.profile_fingerprint.as_deref().unwrap(),
                        row.completed_at_utc.as_deref().unwrap()
                    ))
                )
                .is_err()
        );
        assert!(inventory.completion_mark(SOURCE, signer).unwrap().is_none());
        assert_eq!(inventory.audit_events().unwrap(), events);
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }
}
