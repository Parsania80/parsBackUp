//! The inventory's schema, and the only code path allowed to change it.
//!
//! The version is `PRAGMA user_version` rather than a row in a table, because that is what a
//! database with no usable tables still carries: a 0-byte file and a foreign database both read
//! back as 0, which is exactly the answer the open rules need (see [`crate::Inventory::open`]).
//!
//! Creating a new inventory is not a special case. A brand-new database is at version 0 and runs
//! the same `0 -> 1` step an upgrade from an older host's file runs, so there is one code path
//! that produces a schema and one test that exercises it.

/// The schema version this build writes, and the maximum it will open.
pub const SCHEMA_VERSION: i64 = 1;

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
static MIGRATIONS: &[Migration] = &[Migration {
    from: 0,
    to: 1,
    sql: SCHEMA_V1,
}];

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
