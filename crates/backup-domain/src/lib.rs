//! The vocabulary of this tool: what a configuration may say, what a profile
//! may select, what a manifest and a restore plan record, and the rules that
//! keep those shapes honest. No I/O and no PostgreSQL here, only the shapes
//! every other crate is allowed to reason about.
//!
//! Items are declared in the module that owns them and re-exported here, so
//! consumers import everything from the crate root.

pub mod protocol;

mod artifact;
mod config;
mod profile;
mod restore;
mod selection;

#[cfg(test)]
mod fixture;

pub use artifact::{ArtifactScope, DevelopmentManifest};
pub use config::{Config, Source, Storage};
pub use profile::{Profile, SelectionMode, is_safe_created_schema_name};
pub use restore::{RestorePlan, RestoreSections, RestoreSecurityPolicy};
pub use selection::{DanglingReference, DumpOptions, ResolvedSelection};

pub use protocol::*;
