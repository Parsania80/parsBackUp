//! The inventory: what this host has seen of a backup store, and what happened to it.
//!
//! A published artifact already proves its own existence, integrity and origin — that is what
//! artifact v1 froze. What no file in `artifacts/<id>/` can state is lifecycle: whether anyone
//! ever verified it, whether it is protected, whether a newer one exists. That is this crate, and
//! it is a single SQLite file beside the store it describes.
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

mod artifact;
mod job_lock;
mod schema;

pub use artifact::{ArtifactRow, Shape, State};
pub use job_lock::{JobLock, LOCK_DIR};
pub use schema::SCHEMA_VERSION;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::time::Duration;

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
        match self.binding()? {
            None => self.set_binding().with_context(|| {
                format!("cannot record which source {} belongs to", path.display())
            }),
            Some(found) => self.refuse_mismatch(path, &found),
        }
    }

    fn check_binding(&self, path: &Path) -> Result<()> {
        let found = self.binding()?.with_context(|| {
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

    fn binding(&self) -> Result<Option<String>> {
        Ok(self
            .conn
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
    pub fn register(&self, row: &ArtifactRow) -> Result<()> {
        row.validate(&self.estate)
            .with_context(|| format!("cannot register backup {}", row.backup_id))?;
        artifact::write(&self.conn, row)?;
        Ok(())
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
    fn opening_creates_a_version_one_inventory_in_the_mode_the_format_needs() {
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
        assert_eq!(version, 1);
        // No sidecars left behind at rest, which is the whole point of not being WAL.
        assert!(!dir.join(format!("{INVENTORY_FILE}-wal")).exists());
        assert!(!dir.join(format!("{INVENTORY_FILE}-shm")).exists());

        drop(inventory);
        drop(raw);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Creating is not a special case: a brand-new database runs the same `0 -> 1` step an upgrade
    /// from an older host's file runs, and a second open must find nothing to do.
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
        assert_eq!(again.binding().unwrap().as_deref(), Some(SOURCE));

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
        {
            let inventory = Inventory::open(&newer, &estate()).unwrap();
            inventory
                .conn
                .execute_batch("PRAGMA user_version=2; DROP TABLE meta;")
                .unwrap();
        }
        let error = Inventory::open_read_only(&newer, &estate())
            .expect_err("a newer schema is not this build's schema")
            .to_string();
        assert!(error.contains("schema version 2"), "{error}");
        let error = Inventory::open(&newer, &estate())
            .expect_err("and it is not writable by this build either")
            .to_string();
        assert!(error.contains("schema version 2"), "{error}");

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
}
