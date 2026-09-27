//! The on-disk layout of a storage root. These names are what an operator sees
//! when browsing the directory, so they live in one place rather than being
//! retyped at every join.

pub(crate) const STAGING_DIR: &str = "staging";
pub(crate) const ARTIFACTS_DIR: &str = "artifacts";
pub(crate) const PLANS_DIR: &str = "plans";
pub(crate) const PAYLOAD_FILE: &str = "payload.dump";
pub(crate) const GLOBALS_FILE: &str = "globals.sql";
pub(crate) const MANIFEST_FILE: &str = "manifest.json";
pub(crate) const MANIFEST_TMP_FILE: &str = "manifest.json.tmp";
/// Written last, so its presence is what makes a published artifact durable.
pub(crate) const COMPLETE_MARKER: &str = "complete";
pub(crate) const PLAN_SUFFIX: &str = ".json";
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_PLAN_BYTES: u64 = 64 * 1024;
