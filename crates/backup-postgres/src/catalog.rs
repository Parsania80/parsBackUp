//! Building the read-only catalog queries the resolver runs.
//!
//! Object names reach PostgreSQL only through `sql_literal`, and the relation
//! set a selection resolves to is expressed once, as a CTE, so the dangling
//! reference probe asks about exactly what `pg_dump` would write.

use backup_domain::ResolvedSelection;

pub(crate) fn sql_literal(value: &str) -> String {
    if value.contains('\0') {
        // Caller-provided names are validated elsewhere; a NUL can never be
        // represented in a client encoding, so fail closed.
        panic!("database or role name contains a NUL byte");
    }
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn literal_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| sql_literal(value))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Turn validated `schema.table` names into SQL row values for catalog joins.
pub(crate) fn value_pairs(tables: &[String]) -> String {
    tables
        .iter()
        .map(|table| {
            let (schema, name) = table.split_once('.').unwrap_or((table.as_str(), ""));
            format!("({}, {})", sql_literal(schema), sql_literal(name))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn missing_names(requested: &[String], found: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|name| !found.iter().any(|present| present == *name))
        .cloned()
        .collect()
}

/// The relation set a selection resolves to, as a reusable CTE prefix.
pub(crate) fn included_relations_cte(selection: &ResolvedSelection) -> String {
    let mut predicate = if !selection.tables.is_empty() {
        format!(
            "(n.nspname, c.relname) IN (VALUES {})",
            value_pairs(&selection.tables)
        )
    } else {
        format!("n.nspname IN ({})", literal_list(&selection.schemas))
    };
    if !selection.exclude_schemas.is_empty() {
        predicate.push_str(&format!(
            " AND n.nspname NOT IN ({})",
            literal_list(&selection.exclude_schemas)
        ));
    }
    if !selection.exclude_tables.is_empty() {
        predicate.push_str(&format!(
            " AND (n.nspname || '.' || c.relname) NOT IN ({})",
            literal_list(&selection.exclude_tables)
        ));
    }
    // Standalone objects (types, functions) belong to a schema, not to a
    // table. pg_dump writes them for --schema selections and never for
    // --table selections, so a table-based scope covers no namespace at all.
    let namespaces = if selection.tables.is_empty() {
        let mut scope = format!(
            "SELECT ns.oid FROM pg_catalog.pg_namespace ns WHERE ns.nspname IN ({})",
            literal_list(&selection.schemas)
        );
        if !selection.exclude_schemas.is_empty() {
            scope.push_str(&format!(
                " AND ns.nspname NOT IN ({})",
                literal_list(&selection.exclude_schemas)
            ));
        }
        scope
    } else {
        "SELECT ns.oid FROM pg_catalog.pg_namespace ns WHERE false".to_string()
    };
    format!(
        "WITH included AS (SELECT c.oid FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND {predicate}), \
         included_namespace AS ({namespaces})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_literals_are_escaped_and_names_never_interpolated_raw() {
        assert_eq!(sql_literal("simple"), "'simple'");
        assert_eq!(sql_literal("it's"), "'it''s'");
        assert_eq!(
            sql_literal("a'); DROP TABLE t;--"),
            "'a''); DROP TABLE t;--'"
        );
    }

    #[test]
    fn catalog_lookups_only_ever_see_escaped_literals() {
        assert_eq!(
            literal_list(&["a".to_string(), "b'o".to_string()]),
            "'a', 'b''o'"
        );
        assert_eq!(
            value_pairs(&["app.accounts".to_string()]),
            "('app', 'accounts')"
        );
        // A name without a dot cannot silently become a schema-wide match.
        assert_eq!(value_pairs(&["accounts".to_string()]), "('accounts', '')");
        assert_eq!(
            missing_names(
                &["app.a".to_string(), "app.b".to_string()],
                &["app.a".to_string()]
            ),
            vec!["app.b".to_string()]
        );
    }

    #[test]
    fn the_included_scope_cte_names_relations_and_dumpable_namespaces() {
        let by_schema = included_relations_cte(&ResolvedSelection {
            schemas: vec!["app".to_string()],
            ..Default::default()
        });
        assert!(by_schema.contains("n.nspname IN ('app')"));
        assert!(by_schema.contains("ns.nspname IN ('app')"));

        // pg_dump writes no standalone types or functions for --table, so a
        // table-based scope must cover no namespace at all.
        let by_table = included_relations_cte(&ResolvedSelection {
            tables: vec!["app.accounts".to_string()],
            ..Default::default()
        });
        assert!(by_table.contains("(n.nspname, c.relname) IN (VALUES ('app', 'accounts'))"));
        assert!(by_table.contains("pg_namespace ns WHERE false"));
        assert!(by_table.contains("relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"));
    }
}
