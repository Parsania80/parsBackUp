//! The on-disk layout of a storage root. These names are what an operator sees
//! when browsing the directory, so they live in one place rather than being
//! retyped at every join.

pub(crate) const STAGING_DIR: &str = "staging";
pub(crate) const ARTIFACTS_DIR: &str = "artifacts";
pub(crate) const PLANS_DIR: &str = "plans";
/// Decrypted payloads live here, and only for as long as one view is alive.
pub(crate) const SCRATCH_DIR: &str = "scratch";
pub(crate) const PAYLOAD_FILE: &str = "payload.dump";
pub(crate) const GLOBALS_FILE: &str = "globals.sql";
/// The same two files for an artifact whose payload is an age stream. The name differs
/// so an operator can tell which files are secret material without opening them.
pub(crate) const AGE_PAYLOAD_FILE: &str = "payload.age";
pub(crate) const AGE_GLOBALS_FILE: &str = "globals.age";
pub(crate) const MANIFEST_FILE: &str = "manifest.json";
pub(crate) const MANIFEST_TMP_FILE: &str = "manifest.json.tmp";
/// Written last, so its presence is what makes a published artifact durable.
pub(crate) const COMPLETE_MARKER: &str = "complete";
pub(crate) const PLAN_SUFFIX: &str = ".json";
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_PLAN_BYTES: u64 = 64 * 1024;
