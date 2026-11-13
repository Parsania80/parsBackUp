//! The inventory's schema, and the only code path allowed to change it.
//!
//! The version is `PRAGMA user_version` rather than a row in a table, because that is what a
//! database with no usable tables still carries: a 0-byte file and a foreign database both read
//! back as 0, which is exactly the answer the open rules need (see [`crate::Inventory::open`]).
//!
//! Creating a new inventory is not a special case. A brand-new database is at version 0 and runs
//! every step in order — the same `0 -> 1`, then `1 -> 2` an upgrade from an older host's file
//! runs — so there is one code path that produces a schema and one test that exercises it.

/// The schema version this build writes, and the maximum it will open.
pub const SCHEMA_VERSION: i64 = 7;

/// One step up the schema. `MIGRATIONS` must stay dense and ordered: a gap would be a version
/// no build can reach, and an out-of-order pair would run a later step against an earlier shape.
struct Migration {
    from: i64,
    to: i64,
    sql: &'static str,
}

/// The whole history, oldest first. A new step is appended here and never edited: an operator
/// with a version 1 database has to be brought forward by the same statements everyone else
/// was, because those statements are the ones their data went through.
static MIGRATIONS: &[Migration] = &[
    Migration {
        from: 0,
        to: 1,
        sql: SCHEMA_V1,
    },
    Migration {
        from: 1,
        to: 2,
        sql: SCHEMA_V2,
    },
    Migration {
        from: 2,
        to: 3,
        sql: "CREATE TABLE provisional_artifact (backup_id TEXT PRIMARY KEY) WITHOUT ROWID;",
    },
    Migration {
        from: 3,
        to: 4,
        sql: "CREATE TABLE verification_event (\
            event_id INTEGER PRIMARY KEY, backup_id TEXT NOT NULL, at_utc TEXT NOT NULL, \
            level TEXT NOT NULL, outcome TEXT NOT NULL, payload_sha256 TEXT, manifest_sha256 TEXT, \
            current INTEGER NOT NULL DEFAULT 1 CHECK (current IN (0,1)));\
            CREATE INDEX verification_artifact ON verification_event (backup_id, event_id);",
    },
    Migration {
        from: 4,
        to: 5,
        sql: "CREATE TABLE job_operation (job_id TEXT PRIMARY KEY, operation TEXT NOT NULL, target_fingerprint TEXT) WITHOUT ROWID;",
    },
    Migration {
        from: 5,
        to: 6,
        sql: "ALTER TABLE artifact ADD COLUMN protected INTEGER CHECK (protected IN (0,1));",
    },
    Migration {
        from: 6,
        to: 7,
        sql: "CREATE TABLE deletion_job (job_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL) WITHOUT ROWID;              CREATE TABLE job_artifact (job_id TEXT NOT NULL, backup_id TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('candidate','retained')), progress TEXT NOT NULL CHECK(progress IN ('pending','deleting','deleted')), PRIMARY KEY(job_id,backup_id)) WITHOUT ROWID;",
    },
];

/// The v1 inventory. Every column is one ADR 0003 choice 2 allows a keyless file to hold: a
/// fingerprint, a digest, a size, or a lifecycle state. Nothing here names a database, a host, a
/// port, a profile, or a resolved scope — a profile is a [`backup_domain::profile_fingerprint`],
/// because `manifest.age` was sealed partly to keep profile names out of a directory that gets
/// copied off-site, and the retention scope key needs to group by that name without storing it.
const SCHEMA_V1: &str = "
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE artifact (
  backup_id           TEXT PRIMARY KEY,
  source_fingerprint  TEXT NOT NULL,
  -- Sealed in `manifest.age`, alongside `completed_at_utc` below: a v1 signature covers the id
  -- and two ciphertext digests and nothing else, so a host with no key can list an artifact and
  -- still not know which profile produced it. NULL means this host has never read the manifest,
  -- and ADR 0003's per-(source, profile) `keep_last` must skip such a row rather than guess a
  -- scope for it.
  profile_fingerprint TEXT,
  shape               TEXT NOT NULL
                      CHECK (shape IN ('v1-signed', 'age-unsigned', 'plaintext-dev')),
  -- A v1 artifact's discovery record states all of these; an older shape has no `public.json` at
  -- all, so its values are absent rather than empty. The CHECK below is the signed half of that
  -- rule and the schema's only one: Rust's ArtifactRow::validate enforces the whole agreement,
  -- including that an unsigned row may not claim these fields. Deliberately a subset rather than a
  -- mirror — two copies of one rule drift, and only one of them can say why.
  signer_id           TEXT,
  recipient_id        TEXT,
  payload_sha256      TEXT,
  manifest_sha256     TEXT,
  recipient_suite     TEXT,
  signature_suite     TEXT,
  payload_bytes       INTEGER,
  manifest_bytes      INTEGER,
  -- Sealed in `manifest.age`, so a rebuild on a host with no key records it as unknown.
  completed_at_utc    TEXT,
  -- Deliberately without a CHECK: the reconcile pass adds 'missing' and M5b adds 'deleted', and a
  -- lifecycle vocabulary that lives in a table constraint would force a rebuild of every row to
  -- add one word. Rust validates it instead.
  state               TEXT NOT NULL,
  CHECK (
    shape != 'v1-signed'
    OR (signer_id IS NOT NULL AND payload_sha256 IS NOT NULL AND manifest_sha256 IS NOT NULL)
  )
);

-- Retention counts per (source, profile) over the ordering field, and ADR 0003's first
-- constraint says that ordering is `completed_at_utc` and never `backup_id`, which is a random
-- UUIDv4 and orders nothing.
CREATE INDEX artifact_scope ON artifact (source_fingerprint, profile_fingerprint, completed_at_utc);
";

/// The jobs and the audit trail, added as the `1 -> 2` step rather than folded into v1, so a
/// version 1 file an older host wrote is brought forward by the same statements everyone else's
/// data went through.
///
/// A job is one operation that held resources and could be interrupted. That definition is what
/// the state vocabulary is bounded by: there is no `planned` state, because a row written before
/// the lock is taken would describe a job that held nothing and the sweep would have no honest
/// way to tell it apart from a crash, and there is no `verified` state, because a v1 manifest
/// freezes `verification_level: none` and no `backup create` ever verifies what it just signed.
const SCHEMA_V2: &str = "
-- The current state of one operation. The history of how it got there is `audit_event`; this
-- table is the part a command queries.
CREATE TABLE job (
  -- Also a random UUIDv4, and for the same reason the ordering columns are below it rather than
  -- this one: an id proves which job is which and nothing about which came first.
  job_id              TEXT PRIMARY KEY,
  -- NULL for a job whose scope is a set of artifacts rather than one, which is the shape M5b's
  -- `prune` and `delete` are already designed to have. Every writer today names exactly one.
  backup_id           TEXT,
  source_fingerprint  TEXT NOT NULL,
  -- Not nullable the way artifact.profile_fingerprint is: that column is unknown to a host with
  -- no key, while a job is opened by the command that was configured with the profile and always
  -- knows the scope whose lock it is taking.
  profile_fingerprint TEXT NOT NULL,
  -- No CHECK, for the same reason artifact.state has none: adding a word must not force a rebuild
  -- of every row. The vocabulary lives in Rust, and JobState::parse refuses an unknown one.
  --
  -- There is deliberately no column for *why* a job failed. An error message in this project can
  -- name a database or a host, and gate 5 greps this file's raw bytes for exactly that, so the
  -- reason goes to the operator's terminal and this row records only that there was one.
  state               TEXT NOT NULL,
  started_at_utc      TEXT NOT NULL,
  -- The last transition rather than a separate finish time, so a row a killed process left behind
  -- reports when it was last touched as well as when it began.
  updated_at_utc      TEXT NOT NULL
);

-- Which jobs belong to one retention scope, oldest first.
CREATE INDEX job_scope ON job (source_fingerprint, profile_fingerprint, started_at_utc);

-- The append-only half. job.state says where a job is now; only this table can say that a row sat
-- in running for an hour before a later command found it and marked it interrupted, which is the
-- difference between an audit trail and a status line.
CREATE TABLE audit_event (
  -- A rowid, which makes it the one identifier in this schema that orders by insertion. Unlike a
  -- backup_id or a job_id it is monotone, so a reader replays history in the order it happened
  -- without trusting a second-resolution timestamp to separate two events.
  event_id   INTEGER PRIMARY KEY,
  at_utc     TEXT NOT NULL,
  action     TEXT NOT NULL,
  -- Either end of the history can be absent: an artifact is registered by the publish path, which
  -- holds no job, and a command-level event may name no artifact at all.
  job_id     TEXT,
  backup_id  TEXT
);
";

/// Runs every step between the database's current version and [`SCHEMA_VERSION`], in one
/// transaction so a crash mid-migration leaves the old schema and the old version together.
///
/// Returns the version the database ended at. Steps are `execute_batch` rather than prepared
/// statements because they are DDL: nothing to bind, and a parameter in a `CREATE TABLE` would
/// mean a schema that varies with data.
pub(super) fn migrate(conn: &rusqlite::Connection) -> anyhow::Result<i64> {
    let mut version = user_version(conn)?;
    while version < SCHEMA_VERSION {
        let step = MIGRATIONS
            .iter()
            .find(|m| m.from == version)
            .ok_or_else(|| {
                anyhow::anyhow!("no schema step is registered from version {version}")
            })?;
        debug_assert_eq!(step.to, step.from + 1, "MIGRATIONS must be dense");
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let outcome = (|| -> rusqlite::Result<()> {
            conn.execute_batch(step.sql)?;
            set_user_version(conn, step.to)?;
            conn.execute_batch("COMMIT")
        })();
        if let Err(e) = outcome {
            // The rollback matters more than the message: a half-created schema must never be
            // left at the new version, or the next open would trust tables that do not exist.
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e.into());
        }
        version = step.to;
    }
    Ok(version)
}

pub(super) fn user_version(conn: &rusqlite::Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
}

fn set_user_version(conn: &rusqlite::Connection, to: i64) -> Result<(), rusqlite::Error> {
    // The version is a PRAGMA, so it cannot be a bound parameter; the value is an `i64` this
    // crate owns, never operator text.
    conn.execute_batch(&format!("PRAGMA user_version={to}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactRow, Estate, INVENTORY_FILE, Shape, State, artifact};
    use rusqlite::Connection;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    const SOURCE: &str = "c1cb425f097b6522";

    fn estate() -> Estate {
        Estate::new(SOURCE.to_string()).unwrap()
    }

    /// A v1 inventory path in a directory of its own, so a copy of one host's file is what the
    /// upgrade is handed rather than a fixture this build arranged.
    fn fresh(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("backupctl-schema-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(INVENTORY_FILE);
        (dir, path)
    }

    fn signed_row() -> ArtifactRow {
        ArtifactRow {
            backup_id: Uuid::parse_str("3f7a1c92-8a3e-4b6d-9c21-0d5f7a1c928a").unwrap(),
            source_fingerprint: SOURCE.to_string(),
            profile_fingerprint: Some("651dd7a74505b176".to_string()),
            shape: Shape::V1Signed,
            signer_id: Some("a".repeat(16)),
            recipient_id: Some("b".repeat(16)),
            payload_sha256: Some("c".repeat(64)),
            manifest_sha256: Some("d".repeat(64)),
            recipient_suite: Some("mlkem768x25519-v0".to_string()),
            signature_suite: Some("ed25519+ml-dsa-65".to_string()),
            payload_bytes: Some(4096),
            manifest_bytes: Some(1024),
            completed_at_utc: Some("2026-09-28T06:15:00Z".to_string()),
            state: State::Registered,
        }
    }

    /// Reads the artifact table back through the same row type the crate uses, from a connection
    /// that may be at either schema version.
    fn rows(conn: &Connection) -> Vec<ArtifactRow> {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {} FROM artifact",
                artifact::ARTIFACT_COLUMNS
            ))
            .unwrap();
        let mut query = stmt.query([]).unwrap();
        let mut found = Vec::new();
        while let Some(row) = query.next().unwrap() {
            found.push(ArtifactRow::from_row(row).unwrap());
        }
        found
    }

    /// Writes a database the way a version 1 build did: the frozen statements of that step, its
    /// version, its binding, and one artifact row. Nothing from this build touches it afterwards.
    fn as_v1(path: &std::path::Path) -> ArtifactRow {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        set_user_version(&conn, 1).unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('source_fingerprint', ?1)",
            [SOURCE],
        )
        .unwrap();
        let row = signed_row();
        artifact::write(&conn, &row).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
        assert_eq!(rows(&conn), vec![row.clone()]);
        drop(conn);
        row
    }

    /// Gate 2's first half, run against a file that has only ever had the v1 statements applied to
    /// it: the `1 -> 2` step adds two tables and rewrites nothing that was already there.
    #[test]
    fn a_version_one_inventory_is_brought_forward_without_rewriting_its_rows() {
        let (dir, path) = fresh("upgrade");
        let row = as_v1(&path);

        let inventory = crate::Inventory::open(&path, &estate()).unwrap();
        assert_eq!(inventory.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(inventory.artifacts().unwrap(), vec![row]);
        // The new half arrives empty rather than back-filled. An upgrade cannot invent history for
        // the backups an older build ran without recording, and a table that started full would
        // mean it had tried.
        assert_eq!(inventory.jobs().unwrap(), Vec::new());
        assert_eq!(inventory.audit_events().unwrap(), Vec::new());
        assert_eq!(
            inventory.integrity_problems().unwrap(),
            Vec::<String>::new()
        );
        // And one file, still: the shape a DR copy depends on did not change with the version.
        assert_eq!(
            fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            vec![INVENTORY_FILE]
        );

        drop(inventory);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn version_two_upgrades_without_inventing_provenance() {
        let (dir, path) = fresh("upgrade-v2");
        let row = as_v1(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        set_user_version(&conn, 2).unwrap();
        drop(conn);
        let inventory = crate::Inventory::open_existing_upgrade(&path, &estate()).unwrap();
        assert_eq!(inventory.artifacts().unwrap(), vec![row.clone()]);
        assert!(!inventory.is_provisional(row.backup_id).unwrap());
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn version_three_upgrades_and_preserves_provisional_rows() {
        let (dir, path) = fresh("upgrade-v3");
        let row = as_v1(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch(MIGRATIONS.iter().find(|m| m.from == 2).unwrap().sql)
            .unwrap();
        conn.execute(
            "INSERT INTO provisional_artifact (backup_id) VALUES (?1)",
            [row.backup_id.to_string()],
        )
        .unwrap();
        set_user_version(&conn, 3).unwrap();
        drop(conn);
        let inventory = crate::Inventory::open_existing_upgrade(&path, &estate()).unwrap();
        assert_eq!(inventory.artifacts().unwrap(), vec![row.clone()]);
        assert!(inventory.is_provisional(row.backup_id).unwrap());
        assert!(
            inventory
                .verification_events(row.backup_id)
                .unwrap()
                .is_empty()
        );
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn version_four_jobs_upgrade_without_inventing_an_operation() {
        let (dir, path) = fresh("upgrade-v4");
        as_v1(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        for version in 2..4 {
            conn.execute_batch(MIGRATIONS.iter().find(|m| m.from == version).unwrap().sql)
                .unwrap();
        }
        let id = uuid::Uuid::new_v4();
        conn.execute("INSERT INTO job (job_id, backup_id, source_fingerprint, profile_fingerprint, state, started_at_utc, updated_at_utc) VALUES (?1, NULL, ?2, '0123456789abcdef', 'complete', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", rusqlite::params![id.to_string(), SOURCE]).unwrap();
        set_user_version(&conn, 4).unwrap();
        drop(conn);
        let readonly = crate::Inventory::open_read_only_bound(&path).unwrap();
        assert!(readonly.job(id).unwrap().is_some());
        assert_eq!(readonly.job_operation(id).unwrap(), None);
        drop(readonly);
        let inventory = crate::Inventory::open_existing_upgrade(&path, &estate()).unwrap();
        assert!(inventory.job(id).unwrap().is_some());
        assert_eq!(inventory.job_operation(id).unwrap(), None);
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn version_five_protection_migration_preserves_facts_and_unknown_knowledge() {
        let (dir, path) = fresh("upgrade-v5");
        let row = as_v1(&path);
        let conn = Connection::open(&path).unwrap();
        for version in 1..5 {
            conn.execute_batch(MIGRATIONS.iter().find(|m| m.from == version).unwrap().sql)
                .unwrap();
        }
        set_user_version(&conn, 5).unwrap();
        conn.execute(
            "INSERT INTO provisional_artifact VALUES (?1)",
            [row.backup_id.to_string()],
        )
        .unwrap();
        conn.execute("INSERT INTO verification_event (backup_id, at_utc, level, outcome, payload_sha256, manifest_sha256) VALUES (?1, '2026-09-28T06:15:00Z', 'archive', 'success', ?2, ?3)", rusqlite::params![row.backup_id.to_string(), row.payload_sha256, row.manifest_sha256]).unwrap();
        let job_id = Uuid::new_v4();
        conn.execute("INSERT INTO job (job_id, backup_id, source_fingerprint, profile_fingerprint, state, started_at_utc, updated_at_utc) VALUES (?1, ?2, ?3, '651dd7a74505b176', 'complete', '2026-09-28T06:15:00Z', '2026-09-28T06:15:00Z')", rusqlite::params![job_id.to_string(), row.backup_id.to_string(), SOURCE]).unwrap();
        conn.execute(
            "INSERT INTO job_operation VALUES (?1, 'backup', NULL)",
            [job_id.to_string()],
        )
        .unwrap();
        conn.execute("INSERT INTO audit_event (at_utc, action, job_id, backup_id) VALUES ('2026-09-28T06:15:00Z', 'job_completed', ?1, ?2)", rusqlite::params![job_id.to_string(), row.backup_id.to_string()]).unwrap();
        drop(conn);
        let readonly = crate::Inventory::open_read_only_bound(&path).unwrap();
        let observations = readonly.verification_events(row.backup_id).unwrap();
        let jobs = readonly.jobs().unwrap();
        let operation = readonly.job_operation(job_id).unwrap();
        let audit = readonly.audit_events().unwrap();
        assert_eq!(readonly.schema_version().unwrap(), 5);
        assert_eq!(readonly.protection(row.backup_id).unwrap(), None);
        drop(readonly);
        let inventory = crate::Inventory::open_existing_upgrade(&path, &estate()).unwrap();
        assert_eq!(inventory.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(inventory.artifacts().unwrap(), vec![row.clone()]);
        assert_eq!(inventory.protection(row.backup_id).unwrap(), None);
        assert!(inventory.is_provisional(row.backup_id).unwrap());
        assert_eq!(
            inventory.verification_events(row.backup_id).unwrap(),
            observations
        );
        assert_eq!(inventory.jobs().unwrap(), jobs);
        assert_eq!(inventory.job_operation(job_id).unwrap(), operation);
        assert_eq!(inventory.audit_events().unwrap(), audit);
        inventory.register(&row).unwrap();
        assert_eq!(inventory.protection(row.backup_id).unwrap(), None);
        drop(inventory);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn version_six_upgrade_preserves_every_table_and_failed_step_rolls_back() {
        for fail in [false, true] {
            let (dir, path) = fresh("upgrade-v6");
            let row = as_v1(&path);
            let conn = Connection::open(&path).unwrap();
            for version in 1..6 {
                conn.execute_batch(MIGRATIONS.iter().find(|m| m.from == version).unwrap().sql)
                    .unwrap();
            }
            set_user_version(&conn, 6).unwrap();
            conn.execute("UPDATE artifact SET protected=1", []).unwrap();
            if fail {
                conn.execute_batch("CREATE TABLE job_artifact (fixture TEXT)")
                    .unwrap();
            }
            drop(conn);
            let result = crate::Inventory::open_existing_upgrade(&path, &estate());
            if fail {
                assert!(result.is_err());
                let conn = Connection::open(&path).unwrap();
                assert_eq!(user_version(&conn).unwrap(), 6);
                assert_eq!(
                    conn.query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE name='deletion_job'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                    0
                );
                assert_eq!(rows(&conn), vec![row]);
            } else {
                let inventory = result.unwrap();
                assert_eq!(inventory.schema_version().unwrap(), SCHEMA_VERSION);
                assert_eq!(inventory.artifacts().unwrap(), vec![row.clone()]);
                assert_eq!(inventory.protection(row.backup_id).unwrap(), Some(true));
                assert!(inventory.deletion_recovery_ids().unwrap().is_empty());
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn failed_protection_migration_keeps_the_old_version_and_facts() {
        let (dir, path) = fresh("failed-v6");
        let row = as_v1(&path);
        let conn = Connection::open(&path).unwrap();
        for version in 1..5 {
            conn.execute_batch(MIGRATIONS.iter().find(|m| m.from == version).unwrap().sql)
                .unwrap();
        }
        set_user_version(&conn, 5).unwrap();
        conn.execute_batch("ALTER TABLE artifact ADD COLUMN protected INTEGER")
            .unwrap();
        assert!(migrate(&conn).is_err());
        assert_eq!(user_version(&conn).unwrap(), 5);
        assert_eq!(rows(&conn), vec![row]);
        drop(conn);
        fs::remove_dir_all(dir).unwrap();
    }

    /// A step that fails partway has to leave the old schema *and* the old version together, or the
    /// next open would trust tables that were never created. Here the `1 -> 2` step's first
    /// statement is made to fail by a name already taken, which is the shape of every mid-DDL
    /// failure: a disk full, a lock lost, a statement that does not apply to this data.
    #[test]
    fn a_failed_step_leaves_the_old_version_and_the_old_rows_behind() {
        let (dir, path) = fresh("failed");
        let row = as_v1(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE job (job_id TEXT);")
                .unwrap();
        }

        let failure = crate::Inventory::open(&path, &estate())
            .expect_err("the upgrade accepted a name already in use");
        let error = format!("{failure:#}");
        assert!(error.contains("cannot migrate inventory"), "{error}");
        assert!(error.contains("already exists"), "{error}");

        // The version is still the one the data fits, and the row is still the one that was there.
        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            user_version(&conn).unwrap(),
            1,
            "a rolled-back step raised the version"
        );
        assert_eq!(rows(&conn), vec![row]);
        // Nothing half-built is left to be trusted: `audit_event` was never created, because the
        // step's first statement is what failed.
        let names: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(!names.iter().any(|name| name == "audit_event"), "{names:?}");

        drop(conn);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The history stays dense. A gap would be a version no build could ever reach, and a step
    /// that skipped a number would leave an operator's file stranded at a schema this build has
    /// no statements for. `migrate` only `debug_assert!`s this, which a release build does not
    /// run, so the shape of the list is checked here instead.
    #[test]
    fn the_migration_list_is_dense_and_ends_at_this_builds_version() {
        assert!(!MIGRATIONS.is_empty());
        for (index, step) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                step.from, index as i64,
                "MIGRATIONS must start at 0 and never skip a version"
            );
            assert_eq!(step.to, step.from + 1, "each step moves exactly one");
            assert!(!step.sql.trim().is_empty(), "step {} is empty", step.from);
        }
        assert_eq!(MIGRATIONS.last().unwrap().to, SCHEMA_VERSION);
    }
}
