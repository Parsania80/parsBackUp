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

mod activity;
mod artifact;
mod job;
mod job_lock;
mod schema;

pub use activity::{ACTIVITY_FILE, ActivityLock};
pub use artifact::{ArtifactRow, Shape, State};
pub use job::{AuditAction, AuditEvent, JobGuard, JobRow, JobScope, JobState};
pub use job_lock::{JobLock, LOCK_DIR};
pub use schema::SCHEMA_VERSION;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension};
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
pub(crate) fn in_transaction(
    conn: &Connection,
    write: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    // Shaped like `schema::migrate` on purpose, including rolling back a failed `COMMIT`: a
    // connection left inside a transaction still holds the write lock, so a refusal here would
    // make every later command on this host wait out the busy timeout.
    let outcome = (|| -> Result<()> {
        write(conn)?;
        conn.execute_batch("COMMIT")?;
        Ok(())
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

impl Inventory {
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
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
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

    /// Opens an existing inventory without writing, creating, or migrating anything.
    ///
    /// `PRAGMA query_only` is *not* how this works: the spike measured it creating the file it was
    /// supposed to be sparing. Only `SQLITE_OPEN_READ_ONLY` never creates, and the reason that
    /// matters here is the database's own journal mode — a WAL database copied without its
    /// sidecars cannot be opened read-only at all, which is why the inventory is not WAL.
    pub fn open_read_only(path: &Path, estate: &Estate) -> Result<Self> {
        ensure!(
            path.is_file(),
            "no inventory at {}: the file does not exist, and a read of the store's history is not \
             the moment to create one",
            path.display()
        );
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
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
        let this = Self {
            conn,
            estate: estate.clone(),
        };
        this.check_binding(path)?;
        Ok(this)
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

    /// Inserts or replaces the row for one artifact. Idempotent by design: a successful backup and
    /// a reconcile pass both land here, and re-recording what the files already say is not an
    /// error — see [`UPSERT`][artifact::UPSERT_ARTIFACT] for why replacement, not merge.
    ///
    /// The [`AuditAction::ArtifactRegistered`] event carries no job id, because the store's publish
    /// path is what calls this and it holds no job; the link back to a `backup create` is the
    /// `backup_id` the job row already names.
    pub fn register(&self, row: &ArtifactRow) -> Result<()> {
        row.validate(&self.estate)
            .with_context(|| format!("cannot register backup {}", row.backup_id))?;
        in_transaction(&self.conn, |conn| {
            artifact::write(conn, row)?;
            job::record(
                conn,
                AuditAction::ArtifactRegistered,
                None,
                Some(row.backup_id),
            )
        })
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
        self.read_rows(&mut stmt)
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
        job::all(&self.conn)
    }

    /// The row for one job id, if this index has seen it.
    pub fn job(&self, job_id: Uuid) -> Result<Option<JobRow>> {
        job::one(&self.conn, job_id)
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
            if JobLock::is_free(root, &row.source_fingerprint, &row.profile_fingerprint)?
                && job::mark_interrupted(&self.conn, row.job_id)?
            {
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
        assert_eq!(tables, ["artifact", "audit_event", "job", "meta"]);
        assert_eq!(
            tables,
            vec![
                "artifact".to_string(),
                "audit_event".to_string(),
                "job".to_string(),
                "meta".to_string()
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
                "UPDATE artifact SET state = 'deleted' WHERE backup_id = ?1",
                [row.backup_id.to_string()],
            )
            .unwrap();
        let error = inventory
            .artifacts()
            .expect_err("M5b's vocabulary is not this build's")
            .to_string();
        assert!(error.contains("deleted"), "{error}");
        let error = inventory
            .artifact(row.backup_id)
            .expect_err("and the same refusal on the single-row read")
            .to_string();
        assert!(error.contains("deleted"), "{error}");

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
}
