//! The values that are part of this project's vocabulary: manifest and plan
//! format tags, verification levels, archive sections, and the numbers a
//! `pg_dump`/`pg_restore` invocation or a checksum implicitly promises.
//!
//! Anything here is observable from the outside (written into a manifest, a
//! plan, or a tool's argv), which is why it lives in one file instead of being
//! repeated as literals at each use site.

pub const DEV_FORMAT: &str = "m1-development-plaintext";
/// Manifest format tag for an artifact whose payload and globals files are age
/// ciphertext. It is deliberately distinct from `DEV_FORMAT`: a reader that cannot
/// decrypt has to reject the artifact instead of handing a ciphertext to
/// `pg_restore`, and the format tag is what it branches on.
pub const AGE_FORMAT: &str = "m4a-development-age";
/// The recipient suites this build records in a manifest. A reader that refuses any
/// suite outside this list is the artifact contract's suite-downgrade rule, so the
/// values must stay equal to the names `backup-crypto` reports — checked by a test
/// rather than by care.
pub const RECIPIENT_SUITES: &[&str] = &["mlkem768x25519-v0"];
/// Recipient suites a reader may load. `x25519` is age's classical suite: the writer
/// has no path that selects it, but naming it here is what lets a reader refuse an
/// artifact for a recorded, wrong suite instead of failing to parse it at all.
pub const READABLE_RECIPIENT_SUITES: &[&str] = &["mlkem768x25519-v0", "x25519"];
/// Signature suites this build writes. See [`READABLE_SIGNATURE_SUITES`].
pub const SIGNATURE_SUITES: &[&str] = &["ed25519+ml-dsa-65"];
/// Signature suites a reader may load, so a classical-only artifact can be reported
/// by name as the downgrade it is.
pub const READABLE_SIGNATURE_SUITES: &[&str] = &["ed25519+ml-dsa-65", "ed25519"];
pub const FIXTURE_PREFIX: &str = "backupctl_fixture_";
pub const PLAN_FORMAT: &str = "m3-restore-plan";
pub const VERIFY_CHECKSUM: &str = "checksum";
pub const VERIFY_ARCHIVE: &str = "archive";
pub const VERIFY_RESTORE_TESTED: &str = "restore-tested";
/// Digests, suites and origin only, with nothing decrypted. A v1 artifact is verified at
/// this level before its manifest is even opened.
pub const VERIFY_SIGNATURE: &str = "signature";
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

/// The only `format_version` a v1 artifact may state. A reader rejects an unknown major
/// version rather than parsing fields it does not understand.
pub const ARTIFACT_FORMAT_VERSION: u32 = 1;
/// The manifest's `engine` value. Only PostgreSQL is dumped or restored.
pub const ENGINE_POSTGRESQL: &str = "postgresql";
/// The manifest's `subscription_policy`: `pg_dump --no-subscriptions` is always passed,
/// because restoring a subscription definition on a new host would start it replicating
/// from the source it was dumped from.
pub const SUBSCRIPTION_POLICY_DROPPED: &str = "dropped";
/// The `profile_snapshot.name` a v1 manifest records when the dump named no profile. A
/// signed manifest has no absent fields, so a whole-database dump states the selection it
/// actually made — every object in the database — under a name an operator cannot configure,
/// because `[[profile]]` names are validated against this one being reserved.
pub const WHOLE_DATABASE_PROFILE: &str = "whole-database";
/// The manifest's `globals_policy` when `globals.age` is part of the artifact.
pub const GLOBALS_POLICY_EXPORTED: &str = "exported";
/// The manifest's `globals_policy` when it is not.
pub const GLOBALS_POLICY_SKIPPED: &str = "skipped";
/// Length of a `recipient_id` or `signer_id`: 16 lowercase hex characters, the prefix of
/// a SHA-256 over the public key. An id is a fingerprint, never a name an operator types,
/// so anything else — a path, a label, a hostname — is refused on shape alone.
pub const ID_HEX_LEN: usize = 16;
/// The prefix a manifest's `source_fingerprint` hashes, so the digest of where a dump came
/// from cannot collide with a key fingerprint and changing it is a format change.
pub const SOURCE_FINGERPRINT_DOMAIN: &[u8] = b"backupctl-source-v1\0";
/// `public.json` is bounded before it is parsed, so a hostile file cannot make a reader
/// allocate first and complain later.
pub const MAX_PUBLIC_JSON_BYTES: usize = 4096;
/// A single free-text field carried by a manifest, bounded so a version string or note
/// cannot hold a document.
pub const MAX_TEXT_FIELD_CHARS: usize = 200;
/// The manifest's `compatibility_notes` list is bounded in count as well as per note.
pub const MAX_COMPATIBILITY_NOTES: usize = 32;
/// Length of the fixed-precision UTC timestamp form a v1 manifest records.
pub const UTC_TIMESTAMP_CHARS: usize = 20;
