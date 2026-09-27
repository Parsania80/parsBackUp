//! Reading and re-building a `pg_dumpall --roles-only` globals script.
//!
//! The script is the only security metadata an artifact carries, so it is
//! parsed rather than replayed: statements that are not role or membership
//! DDL must never reach the cluster.

use crate::MAX_GLOBALS_BYTES;
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StatementKind {
    /// CREATE/ALTER ROLE for the named role.
    Role(String),
    /// GRANT <role> TO <grantee>: membership keyed on the grantee.
    Membership(String),
    /// Anything else in the globals script; never replayed.
    Other,
}

/// Defense in depth: our export path uses --no-role-passwords, so a PASSWORD
/// clause means the file was forged or exported wrongly. Substring scan is
/// deliberately over-approximate; false positives only refuse a restore.
pub(crate) fn has_password_clause(script: &[u8]) -> bool {
    let upper = script
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect::<Vec<_>>();
    upper.windows(b"PASSWORD".len()).any(|w| w == b"PASSWORD")
}

fn sql_role_name(token: &str) -> String {
    let token = token.trim_end_matches(';').trim();
    if token.starts_with('"') {
        // Identifier quoting doubles embedded quotes.
        return token.trim_matches('"').replace("\"\"", "\"");
    }
    token.to_string()
}

fn classify_statement(statement: &str) -> StatementKind {
    let mut parts = statement.split_whitespace();
    let first = loop {
        match parts.next() {
            Some(word) if word.starts_with("--") => continue,
            other => break other,
        }
    };
    match first {
        Some("CREATE") => match parts.next() {
            Some(kind)
                if kind.eq_ignore_ascii_case("ROLE") || kind.eq_ignore_ascii_case("USER") =>
            {
                match parts.next() {
                    Some(name) => StatementKind::Role(sql_role_name(name)),
                    None => StatementKind::Other,
                }
            }
            _ => StatementKind::Other,
        },
        Some("ALTER") => match parts.next() {
            Some(kind) if kind.eq_ignore_ascii_case("ROLE") => match parts.next() {
                Some(name) => StatementKind::Role(sql_role_name(name)),
                None => StatementKind::Other,
            },
            _ => StatementKind::Other,
        },
        Some("GRANT") => {
            // GRANT <member-role> [,...] TO <grantee> [,...]
            let grantee = parts
                .position(|token| token.eq_ignore_ascii_case("TO"))
                .and_then(|_| parts.next());
            match grantee {
                Some(name) => StatementKind::Membership(sql_role_name(name)),
                None => StatementKind::Other,
            }
        }
        _ => StatementKind::Other,
    }
}

/// Split a semicolon-delimited SQL script into statements, dropping trailing
/// empty fragments. String literals in role statements contain no semicolons
/// in our exports, so a naive split is safe here.
fn split_statements(text: &str) -> Vec<String> {
    text.split(';')
        .map(|chunk| {
            chunk
                .lines()
                .filter(|line| !line.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string()
        })
        .filter(|statement| !statement.is_empty())
        .collect()
}

pub(crate) fn parse_role_statements(path: &Path) -> Result<Vec<(StatementKind, String)>> {
    let meta = fs::metadata(path).context("inspect globals file")?;
    if meta.len() > MAX_GLOBALS_BYTES {
        bail!("globals file exceeds size limit");
    }
    let bytes = fs::read(path).context("read globals file")?;
    let text = String::from_utf8(bytes).context("globals file is not valid UTF-8")?;
    Ok(split_statements(&text)
        .into_iter()
        .map(|statement| {
            let kind = classify_statement(&statement);
            (kind, statement)
        })
        .collect())
}

/// Build the script replayed against the cluster. Role statements for a role
/// that already exists are dropped so an existing role is never rewritten,
/// memberships are always replayed (re-granting is a no-op), and every other
/// statement, including psql meta-commands, is excluded.
pub(crate) fn build_globals_script(
    statements: &[(StatementKind, String)],
    existing: &[String],
) -> (String, usize) {
    let mut script = String::from("-- filtered role security statements\n");
    let mut applied = 0usize;
    for (kind, statement) in statements {
        let skip = match kind {
            StatementKind::Role(name) => existing.iter().any(|e| e == name),
            StatementKind::Membership(_) => false,
            StatementKind::Other => true,
        };
        if skip {
            continue;
        }
        script.push_str(statement);
        script.push_str(";\n");
        applied += 1;
    }
    (script, applied)
}

pub(crate) fn exported_role_names(statements: &[(StatementKind, String)]) -> Vec<String> {
    let mut names: Vec<String> = statements
        .iter()
        .filter_map(|(kind, _)| match kind {
            StatementKind::Role(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn password_clause_detection_is_fail_closed() {
        assert!(has_password_clause(
            b"CREATE ROLE x PASSWORD 'SCRAM-SHA-256$1';"
        ));
        assert!(has_password_clause(b"ALTER ROLE x password NULL;"));
        assert!(has_password_clause(b"CREATE ROLE x   PASSWORD   NULL ;"));
        assert!(!has_password_clause(b"CREATE ROLE x NOINHERIT LOGIN;"));
        assert!(!has_password_clause(
            b"-- generated by pg_dumpall\nCREATE ROLE x;"
        ));
    }

    #[test]
    fn role_statements_are_classified_from_pg_dumpall_shape() {
        let dir = std::env::temp_dir().join(format!("backupctl-pg-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("globals.sql");
        std::fs::write(
            &path,
            "--\n-- Roles\n--\n\
             \\restrict abc123\n\
             SET default_transaction_read_only = off;\n\
             CREATE ROLE backupctl_fixture_alice;\n\
             ALTER ROLE backupctl_fixture_alice WITH NOSUPERUSER LOGIN;\n\
             CREATE ROLE postgres;\n\
             ALTER ROLE postgres WITH SUPERUSER;\n\
             CREATE USER bob WITH LOGIN;\n\
             GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;\n\
             \\unrestrict abc123\n",
        )
        .unwrap();
        let statements = parse_role_statements(&path).unwrap();
        assert_eq!(
            exported_role_names(&statements),
            ["backupctl_fixture_alice", "bob", "postgres"]
        );
        assert_eq!(
            statements
                .iter()
                .filter_map(|(kind, _)| match kind {
                    StatementKind::Membership(grantee) => Some(grantee.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec!["backupctl_fixture_alice".to_string()]
        );
        // SET and meta-command lines must never be replayed.
        assert!(
            statements
                .iter()
                .all(|(kind, statement)| kind == &StatementKind::Other
                    || (statement.starts_with("CREATE")
                        || statement.starts_with("ALTER")
                        || statement.starts_with("GRANT")))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn globals_script_replays_memberships_but_never_touches_existing_roles() {
        let dir = std::env::temp_dir().join(format!("backupctl-pg-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("globals.sql");
        std::fs::write(
            &path,
            "\\restrict abc123\n\
             SET default_transaction_read_only = off;\n\
             CREATE ROLE backupctl_fixture_alice;\n\
             ALTER ROLE backupctl_fixture_alice WITH LOGIN;\n\
             CREATE ROLE postgres;\n\
             ALTER ROLE postgres WITH SUPERUSER;\n\
             GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;\n\
             \\unrestrict abc123\n",
        )
        .unwrap();
        let statements = parse_role_statements(&path).unwrap();
        let (script, applied) = build_globals_script(&statements, &["postgres".to_string()]);
        assert_eq!(applied, 3);
        assert!(script.contains("CREATE ROLE backupctl_fixture_alice;"));
        assert!(script.contains("ALTER ROLE backupctl_fixture_alice WITH LOGIN;"));
        // Membership is rebuilt even though the grantee is being created here.
        assert!(script.contains("GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;"));
        // Predefined roles and psql meta-commands stay untouched.
        assert!(!script.contains("postgres;"));
        assert!(!script.contains("restrict"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quoted_role_names_are_decoded() {
        assert_eq!(sql_role_name("\"Mixed Case\""), "Mixed Case");
        assert_eq!(sql_role_name("plain"), "plain");
        assert_eq!(sql_role_name("trailing;"), "trailing");
    }
}
