use crate::profile::SelectionMode;
use serde::{Deserialize, Serialize};

/// A reference from an object inside the selection to an object outside it.
/// `pg_dump` does not follow these, so a selective artifact cannot be assumed
/// to restore into a clean database on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DanglingReference {
    pub dependent: String,
    pub referenced: String,
    pub kind: String,
}

/// The concrete object set a selection resolved to, produced by reading the
/// live catalog before any dump runs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSelection {
    pub whole_database: bool,
    pub schemas: Vec<String>,
    pub exclude_schemas: Vec<String>,
    pub tables: Vec<String>,
    pub exclude_tables: Vec<String>,
    pub dangling: Vec<DanglingReference>,
    /// Extensions owning objects inside the selection, recorded so a restore
    /// operator can see that member objects came from an extension.
    pub extension_members: Vec<String>,
}

impl ResolvedSelection {
    pub fn is_filtered(&self) -> bool {
        !self.whole_database
    }
}

/// Everything the dump step needs, resolved before the tool runs.
#[derive(Clone, Debug)]
pub struct DumpOptions<'a> {
    pub major: u32,
    pub mode: SelectionMode,
    pub selection: &'a ResolvedSelection,
    /// `None` leaves large-object handling to the native default, which is the
    /// profile-less whole-database path.
    pub large_objects: Option<bool>,
    pub exclude_extensions: &'a [String],
}
