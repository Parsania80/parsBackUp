use crate::protocol::FIXTURE_PREFIX;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// What a profile asks `pg_dump` to write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionMode {
    #[default]
    SchemaAndData,
    SchemaOnly,
    DataOnly,
}

/// Exact, non-pattern object names. `pg_dump` treats its own filters as
/// patterns with case folding, so accepting wildcards or mixed case here would
/// let a profile name objects the resolver cannot match one-to-one.
fn is_valid_schema_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_lowercase())
        && chars.all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit() || c == '$')
}

fn is_valid_table_name(name: &str) -> bool {
    let Some((schema, table)) = name.split_once('.') else {
        return false;
    };
    !table.contains('.') && is_valid_schema_name(schema) && is_valid_schema_name(table)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub database: String,
    #[serde(default)]
    pub mode: SelectionMode,
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(default)]
    pub exclude_schemas: Vec<String>,
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub exclude_tables: Vec<String>,
    #[serde(default)]
    pub exclude_extensions: Vec<String>,
    #[serde(default)]
    pub large_objects: bool,
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.chars().any(char::is_whitespace) {
            bail!("profile name must be non-empty and contain no whitespace");
        }
        if !self.database.starts_with(FIXTURE_PREFIX) {
            bail!(
                "profile {} must target a {FIXTURE_PREFIX} database",
                self.name
            );
        }
        for list in [&self.schemas, &self.exclude_schemas] {
            for schema in list {
                if !is_valid_schema_name(schema) {
                    bail!(
                        "profile {}: schema {schema:?} must be an exact lower-case identifier without wildcards",
                        self.name
                    );
                }
                if starts_with_system_prefix(schema) {
                    bail!(
                        "profile {}: system schema {schema:?} cannot be selected",
                        self.name
                    );
                }
            }
        }
        for table in &self.tables {
            if !is_valid_table_name(table) {
                bail!(
                    "profile {}: table {table:?} must be an exact schema.table identifier without wildcards",
                    self.name
                );
            }
        }
        for table in &self.exclude_tables {
            if !is_valid_table_name(table) {
                bail!(
                    "profile {}: excluded table {table:?} must be an exact schema.table identifier",
                    self.name
                );
            }
        }
        for extension in &self.exclude_extensions {
            if !is_valid_schema_name(extension) {
                bail!(
                    "profile {}: excluded extension {extension:?} must be an exact lower-case name",
                    self.name
                );
            }
        }
        for (list, what) in [
            (&self.schemas, "schema"),
            (&self.tables, "table"),
            (&self.exclude_tables, "table"),
        ] {
            if let Some(duplicate) = first_duplicate(list) {
                bail!("profile {} lists {} {duplicate} twice", self.name, what);
            }
        }
        if let Some(duplicate) = first_duplicate(&self.exclude_schemas) {
            bail!("profile {} excludes schema {duplicate} twice", self.name);
        }
        if !self.tables.is_empty() && (!self.schemas.is_empty() || !self.exclude_schemas.is_empty())
        {
            bail!(
                "profile {} mixes tables with schema filters: pg_dump ignores --schema/--exclude-schema when --table is given; select one kind",
                self.name
            );
        }
        if self.mode == SelectionMode::SchemaOnly && self.large_objects {
            bail!(
                "profile {} requests large objects but a schema-only dump contains no object bytes",
                self.name
            );
        }
        Ok(())
    }

    pub fn is_whole_database(&self) -> bool {
        self.schemas.is_empty() && self.tables.is_empty()
    }
}

fn starts_with_system_prefix(name: &str) -> bool {
    name.starts_with("pg_") || name == "information_schema"
}

/// Names the restore path may issue `CREATE SCHEMA` for: the same exact
/// lower-case identifier shape a profile may select, and never a system
/// namespace.
pub fn is_safe_created_schema_name(name: &str) -> bool {
    is_valid_schema_name(name) && !starts_with_system_prefix(name)
}

fn first_duplicate(list: &[String]) -> Option<&String> {
    let mut sorted: Vec<&String> = list.iter().collect();
    sorted.sort_unstable();
    sorted
        .windows(2)
        .find(|pair| pair[0] == pair[1])
        .map(|pair| pair[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;

    #[test]
    fn profiles_are_exact_names_and_single_kind_of_selection() {
        assert!(fixture::profile("app-only").validate().is_ok());

        let mut wildcard = fixture::profile("wildcard");
        wildcard.schemas = vec!["app*".to_string()];
        assert!(wildcard.validate().is_err());

        let mut quoted = fixture::profile("quoted");
        quoted.schemas = vec!["App".to_string()];
        assert!(quoted.validate().is_err());

        let mut system = fixture::profile("system");
        system.schemas = vec!["pg_catalog".to_string()];
        assert!(system.validate().is_err());

        let mut mixed = fixture::profile("mixed");
        mixed.tables = vec!["app.accounts".to_string()];
        assert!(mixed.validate().is_err());

        let mut bad_table = fixture::profile("bad-table");
        bad_table.schemas = Vec::new();
        bad_table.tables = vec!["accounts".to_string()];
        assert!(bad_table.validate().is_err());

        let mut duplicate = fixture::profile("duplicate");
        duplicate.schemas = vec!["app".to_string(), "app".to_string()];
        assert!(duplicate.validate().is_err());

        let mut schema_only_objects = fixture::profile("schema-only-los");
        schema_only_objects.mode = SelectionMode::SchemaOnly;
        schema_only_objects.large_objects = true;
        assert!(schema_only_objects.validate().is_err());

        let mut whole = fixture::profile("whole");
        whole.schemas = Vec::new();
        assert!(whole.is_whole_database());
        assert!(!fixture::profile("app-only").is_whole_database());
    }
}
