//! The pg_dump argument vector, built from a resolved selection.
//!
//! Kept separate from the adapter so the exact flag set per PostgreSQL major
//! and selection mode is unit-testable without a server: these arguments
//! decide what an artifact contains.

use crate::tools::{
    DUMP_COMPRESSION, DUMP_FORMAT, DUMP_LOCK_WAIT_TIMEOUT, DUMP_NO_SUBSCRIPTIONS, LARGE_OBJECTS,
    NO_LARGE_OBJECTS,
};
use anyhow::{Result, bail};
use backup_domain::{DumpOptions, MIN_MAJOR_EXCLUDE_EXTENSION, SelectionMode};

/// Build the pg_dump argument vector for a resolved selection. Pure so the
/// exact flag set per PostgreSQL major and selection mode is unit-testable
/// without a server.
pub(crate) fn dump_arguments(options: &DumpOptions) -> Result<Vec<String>> {
    let mut arguments = vec![
        DUMP_FORMAT.to_string(),
        DUMP_COMPRESSION.to_string(),
        DUMP_NO_SUBSCRIPTIONS.to_string(),
        DUMP_LOCK_WAIT_TIMEOUT.to_string(),
    ];
    match options.mode {
        SelectionMode::SchemaAndData => {}
        SelectionMode::SchemaOnly => arguments.push("--schema-only".to_string()),
        SelectionMode::DataOnly => arguments.push("--data-only".to_string()),
    }
    let selection = options.selection;
    for schema in &selection.exclude_schemas {
        arguments.push(format!("--exclude-schema={schema}"));
    }
    for table in &selection.exclude_tables {
        arguments.push(format!("--exclude-table={table}"));
    }
    if !options.exclude_extensions.is_empty() {
        if options.major < MIN_MAJOR_EXCLUDE_EXTENSION {
            bail!(
                "excluding extensions needs pg_dump from PostgreSQL {MIN_MAJOR_EXCLUDE_EXTENSION} or newer, but this source is major {}",
                options.major
            );
        }
        for extension in options.exclude_extensions {
            arguments.push(format!("--exclude-extension={extension}"));
        }
    }
    if selection.whole_database {
        // None keeps the native default, which is what profile-less M1/M2
        // dumps produced.
        if let Some(large_objects) = options.large_objects {
            arguments.push(if large_objects {
                LARGE_OBJECTS.to_string()
            } else {
                NO_LARGE_OBJECTS.to_string()
            });
        }
        return Ok(arguments);
    }
    for schema in &selection.schemas {
        arguments.push(format!("--schema={schema}"));
    }
    for table in &selection.tables {
        arguments.push(format!("--table={table}"));
    }
    arguments.push("--strict-names".to_string());
    // A filtered dump omits large objects unless asked; the resolver refuses
    // selections that would leave stored large objects unaccounted for.
    if options.large_objects.unwrap_or(false) {
        arguments.push(LARGE_OBJECTS.to_string());
    }
    Ok(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_domain::ResolvedSelection;

    fn whole_database() -> ResolvedSelection {
        ResolvedSelection {
            whole_database: true,
            ..Default::default()
        }
    }

    fn dump_options<'a>(
        selection: &'a ResolvedSelection,
        major: u32,
        mode: SelectionMode,
        large_objects: Option<bool>,
        exclude_extensions: &'a [String],
    ) -> DumpOptions<'a> {
        DumpOptions {
            major,
            mode,
            selection,
            large_objects,
            exclude_extensions,
        }
    }

    #[test]
    fn a_profile_less_dump_keeps_the_m2_argument_vector() {
        let selection = whole_database();
        let arguments = dump_arguments(&dump_options(
            &selection,
            16,
            SelectionMode::default(),
            None,
            &[],
        ))
        .unwrap();
        assert_eq!(
            arguments,
            vec![
                "--format=custom",
                "--compress=6",
                "--no-subscriptions",
                "--lock-wait-timeout=5s",
            ]
        );
    }

    #[test]
    fn schema_selection_dumps_named_schemas_and_strict_names() {
        let selection = ResolvedSelection {
            schemas: vec!["app".to_string(), "aux".to_string()],
            exclude_schemas: vec!["aux".to_string()],
            ..Default::default()
        };
        let arguments = dump_arguments(&dump_options(
            &selection,
            18,
            SelectionMode::SchemaOnly,
            Some(false),
            &[],
        ))
        .unwrap();
        assert!(arguments.contains(&"--schema-only".to_string()));
        assert!(arguments.contains(&"--schema=app".to_string()));
        assert!(arguments.contains(&"--schema=aux".to_string()));
        assert!(arguments.contains(&"--exclude-schema=aux".to_string()));
        // A filtered dump omits large objects natively; only an explicit
        // request adds them, and the resolver refuses that combination.
        assert!(!arguments.contains(&"--no-large-objects".to_string()));
        assert!(!arguments.contains(&"--large-objects".to_string()));
        assert!(arguments.contains(&"--strict-names".to_string()));
    }

    #[test]
    fn table_selection_and_data_only_are_passed_through_expanded() {
        let selection = ResolvedSelection {
            tables: vec![
                "app.partitioned_events".to_string(),
                "app.partitioned_events_2025".to_string(),
            ],
            exclude_tables: vec!["app.audit_events".to_string()],
            ..Default::default()
        };
        let arguments = dump_arguments(&dump_options(
            &selection,
            17,
            SelectionMode::DataOnly,
            None,
            &[],
        ))
        .unwrap();
        assert!(arguments.contains(&"--data-only".to_string()));
        assert!(arguments.contains(&"--table=app.partitioned_events".to_string()));
        assert!(
            arguments.contains(&"--table=app.partitioned_events_2025".to_string()),
            "family members must be dumped explicitly: {arguments:?}"
        );
        assert!(arguments.contains(&"--exclude-table=app.audit_events".to_string()));
        assert!(!arguments.contains(&"--large-objects".to_string()));
    }

    #[test]
    fn excluding_extensions_requires_pg_dump_17_or_newer() {
        let selection = whole_database();
        let extensions = vec!["hstore".to_string()];
        assert!(
            dump_arguments(&dump_options(
                &selection,
                16,
                SelectionMode::default(),
                None,
                &extensions
            ))
            .is_err()
        );
        let arguments = dump_arguments(&dump_options(
            &selection,
            17,
            SelectionMode::default(),
            None,
            &extensions,
        ))
        .unwrap();
        assert!(arguments.contains(&"--exclude-extension=hstore".to_string()));
    }
}
