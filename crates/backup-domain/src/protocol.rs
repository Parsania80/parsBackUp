//! The values that are part of this project's vocabulary: manifest and plan
//! format tags, verification levels, archive sections, and the numbers a
//! `pg_dump`/`pg_restore` invocation or a checksum implicitly promises.
//!
//! Anything here is observable from the outside (written into a manifest, a
//! plan, or a tool's argv), which is why it lives in one file instead of being
//! repeated as literals at each use site.

pub const DEV_FORMAT: &str = "m1-development-plaintext";
pub const FIXTURE_PREFIX: &str = "backupctl_fixture_";
pub const PLAN_FORMAT: &str = "m3-restore-plan";
pub const VERIFY_CHECKSUM: &str = "checksum";
pub const VERIFY_ARCHIVE: &str = "archive";
pub const VERIFY_RESTORE_TESTED: &str = "restore-tested";
/// A manifest or plan that was never verified reports this level instead.
pub const VERIFICATION_NONE: &str = "none";
pub const SECTION_PRE_DATA: &str = "pre-data";
pub const SECTION_DATA: &str = "data";
pub const SECTION_POST_DATA: &str = "post-data";
/// `pg_dump --exclude-extension` arrived after PostgreSQL 16.
pub const MIN_MAJOR_EXCLUDE_EXTENSION: u32 = 17;
/// Server majors this tool is willing to talk to.
pub const SUPPORTED_MAJORS: std::ops::RangeInclusive<u32> = 16..=18;
/// The human-readable form of `SUPPORTED_MAJORS`, for error text.
pub const SUPPORTED_MAJOR_RANGE: &str = "16 through 18";

/// The `pg_dump --format` value, mirrored by the manifest's `archive_format`.
pub const ARCHIVE_FORMAT: &str = "custom";
/// The archive's compression, as recorded by the manifest even though
/// `--compress` names a level rather than an algorithm.
pub const ARCHIVE_COMPRESSION: &str = "gzip";
/// The only status a published manifest may carry.
pub const BACKUP_STATUS: &str = "complete";

/// Length of a lowercase hex SHA-256 digest.
pub const DIGEST_HEX_LEN: usize = 64;
/// Per-tool timeout a configuration falls back to when it omits one.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
/// How long a restore plan stays executable before it must be recreated.
pub const PLAN_TTL_SECONDS: u64 = 900;
/// A table-based profile is expanded into an explicit `--table` list, so the
/// argv vector and the recorded scope stay bounded.
pub const MAX_RESOLVED_TABLES: usize = 512;
