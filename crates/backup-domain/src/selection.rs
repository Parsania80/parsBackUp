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

    /// The namespaces a restore target must hold even though the archive does not create
    /// them: `pg_dump --table` selections carry no `CREATE SCHEMA` entries, while schema
    /// selections (and whole-database dumps) do.
    ///
    /// This is the rule a restore runs on, so it is stated once here rather than being
    /// derived twice — once from a development manifest's scope and once from a signed
    /// manifest's resolved selection.
    pub fn restore_required_schemas(&self) -> Vec<String> {
        if !self.schemas.is_empty() || self.tables.is_empty() {
            return Vec::new();
        }
        let mut schemas: Vec<String> = self
            .tables
            .iter()
            .filter_map(|table| table.split_once('.').map(|(schema, _)| schema.to_string()))
            .collect();
        schemas.sort();
        schemas.dedup();
        schemas
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
