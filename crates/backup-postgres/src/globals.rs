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
    let token = token.trim();
    if token.starts_with('"') {
        // Identifier quoting doubles embedded quotes.
        return token
            .strip_prefix('"')
            .and_then(|name| name.strip_suffix('"'))
            .unwrap_or(token)
            .replace("\"\"", "\"");
    }
    token.to_string()
}

// ponytail: only pg_dumpall role syntax; use a full SQL parser if arbitrary SQL is accepted.
// Quoted identifiers/strings, doubled quotes, E-string escapes and line comments are supported.
fn sql_tokens(text: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped_string = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(delimiter) = quote {
            token.push(ch);
            if escaped_string && ch == '\\' {
                token.push(chars.next().context("unterminated SQL escape in globals")?);
            } else if ch == delimiter {
                if chars.peek() == Some(&delimiter) {
                    token.push(chars.next().expect("peeked quote"));
                } else {
                    quote = None;
                }
            }
        } else if ch == '-' && chars.peek() == Some(&'-') {
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else if ch == '\'' || ch == '"' {
            escaped_string = ch == '\'' && token.eq_ignore_ascii_case("E");
            quote = Some(ch);
            token.push(ch);
        } else if ch.is_whitespace() || ch == ';' {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
            if ch == ';' {
                tokens.push(";".to_string());
            }
        } else {
            token.push(ch);
        }
    }
    if quote.is_some() {
        bail!("unterminated SQL quote in globals");
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

fn classify_statement(parts: &[String]) -> StatementKind {
    match parts {
        [command, kind, name, ..]
            if (command == "CREATE" && matches!(kind.as_str(), "ROLE" | "USER"))
                || (command == "ALTER" && kind == "ROLE") =>
        {
            StatementKind::Role(sql_role_name(name))
        }
        [command, rest @ ..] if command == "GRANT" => rest
            .iter()
            .position(|token| token == "TO")
            .and_then(|index| rest.get(index + 1))
            .map_or(StatementKind::Other, |name| {
                StatementKind::Membership(sql_role_name(name))
            }),
        _ => StatementKind::Other,
    }
}

pub(crate) fn parse_role_statements(path: &Path) -> Result<Vec<(StatementKind, String)>> {
    let meta = fs::metadata(path).context("inspect globals file")?;
    if meta.len() > MAX_GLOBALS_BYTES {
        bail!("globals file exceeds size limit");
    }
    let bytes = fs::read(path).context("read globals file")?;
    let text = String::from_utf8(bytes).context("globals file is not valid UTF-8")?;
    let tokens = sql_tokens(&text)?;
    Ok(tokens
        .split(|token| token == ";")
        .filter(|parts| !parts.is_empty())
        .map(|parts| (classify_statement(parts), parts.join(" ")))
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
    fn quoted_identifiers_and_literals_survive_the_complete_parser() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("backupctl-quoted-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir)?;
        let path = dir.join("globals.sql");
        let input = "-- roles\nCREATE ROLE \"Mixed Case\";\nCREATE ROLE \"semi;colon\";\nCREATE ROLE \"a\"\"quote\"\"\";\nALTER ROLE \"Mixed Case\" SET application_name TO 'semi;--colon';\nGRANT \"semi;colon\" TO \"Mixed Case\";";
        fs::write(&path, input)?;
        let statements = parse_role_statements(&path)?;
        assert_eq!(
            exported_role_names(&statements),
            ["Mixed Case", "a\"quote\"", "semi;colon"]
        );
        assert_eq!(statements.len(), 5);
        assert_eq!(
            statements[4].0,
            StatementKind::Membership("Mixed Case".to_string())
        );
        let (script, applied) = build_globals_script(&statements, &["Mixed Case".to_string()]);
        assert_eq!(applied, 3);
        assert!(!script.contains("ALTER ROLE"));
        assert!(script.contains("GRANT \"semi;colon\" TO \"Mixed Case\";"));
        assert!(sql_tokens("CREATE ROLE \"unfinished").is_err());
        assert!(sql_tokens("ALTER ROLE x SET application_name TO 'unfinished").is_err());
        assert_eq!(
            sql_tokens("ALTER ROLE x SET application_name TO E'it\\'s;ok';")?
                .last()
                .unwrap(),
            ";"
        );
        fs::remove_dir_all(dir)?;
        Ok(())
    }
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
        assert_eq!(sql_role_name("trailing"), "trailing");
    }
}
