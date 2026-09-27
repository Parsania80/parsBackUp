use anyhow::{Context, Result, bail};
use backup_application::{DatabaseAdapter, EngineInfo};
use backup_domain::{RestoreSecurityPolicy, Source};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CAPTURE: usize = 64 * 1024;
const MAX_GLOBALS_BYTES: u64 = 8 * 1024 * 1024;

pub struct PostgresAdapter;

impl DatabaseAdapter for PostgresAdapter {
    fn preflight(&self, source: &Source, timeout: Duration) -> Result<EngineInfo> {
        if let Some(path) = &source.password_file {
            let meta = fs::symlink_metadata(path).context("inspect password file")?;
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || meta.permissions().mode() & 0o077 != 0
            {
                bail!(
                    "password_file must be a regular non-symlink file with mode 0600 or stricter"
                );
            }
        }
        let dump = tool(source, "pg_dump")?;
        let restore = tool(source, "pg_restore")?;
        let psql = tool(source, "psql")?;
        let dumpall = tool(source, "pg_dumpall")?;
        let createdb = tool(source, "createdb")?;
        let dump_version = tool_version(&dump, timeout)?;
        let restore_version = tool_version(&restore, timeout)?;
        let psql_version = tool_version(&psql, timeout)?;
        let dumpall_version = tool_version(&dumpall, timeout)?;
        let createdb_version = tool_version(&createdb, timeout)?;
        let majors = [
            dump_version.0,
            restore_version.0,
            psql_version.0,
            dumpall_version.0,
            createdb_version.0,
        ];
        if majors.windows(2).any(|pair| pair[0] != pair[1]) {
            bail!("PostgreSQL client tools are from different major versions");
        }
        let mut command = base_command(&psql, source);
        command.args([
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command=SHOW server_version_num",
        ]);
        let result = run(command, timeout, None).context("query PostgreSQL server version")?;
        let server_num: u32 = String::from_utf8(result.stdout)?
            .trim()
            .parse()
            .context("parse PostgreSQL server version")?;
        let major = server_num / 10_000;
        if !matches!(major, 16..=18) {
            bail!("M1 supports PostgreSQL server majors 16 through 18");
        }
        if major != dump_version.0 {
            bail!("pg_dump major does not match source server major");
        }
        Ok(EngineInfo {
            source_major: major,
            source_version: server_num.to_string(),
            dump_client_version: dump_version.1,
        })
    }

    fn dump_to(&self, source: &Source, output: &Path, timeout: Duration) -> Result<()> {
        let dump = tool(source, "pg_dump")?;
        let mut command = base_command(&dump, source);
        command.args([
            "--format=custom",
            "--compress=6",
            "--no-subscriptions",
            "--lock-wait-timeout=5s",
        ]);
        command.arg(format!("--file={}", output.display()));
        let result = run(command, timeout, None).context("run pg_dump")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_dump emitted a warning; artifact was not published");
        }
        Ok(())
    }

    fn dump_globals(&self, source: &Source, output: &Path, timeout: Duration) -> Result<()> {
        let dumpall = tool(source, "pg_dumpall")?;
        let mut command = cluster_command(&dumpall, source);
        // --no-role-passwords keeps password verifiers out of the artifact;
        // plaintext artifacts are development-only until M4 encryption.
        // --roles-only avoids tablespaces and database attributes, which
        // belong to later cluster-object milestones.
        command.args(["--roles-only", "--no-role-passwords", "--no-sync"]);
        command.arg(format!("--file={}", output.display()));
        let result = run(command, timeout, None).context("run pg_dumpall globals export")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_dumpall emitted a warning; artifact was not published");
        }
        Ok(())
    }

    fn inspect_archive(&self, source: &Source, archive: &Path, timeout: Duration) -> Result<()> {
        let restore = tool(source, "pg_restore")?;
        let mut command = isolated_command(&restore, source);
        command.arg("--list").arg(archive);
        let result = run(command, timeout, None).context("inspect pg_dump archive")?;
        if result.stdout.is_empty() {
            bail!("pg_restore returned an empty table of contents");
        }
        Ok(())
    }

    fn database_exists(&self, source: &Source, database: &str, timeout: Duration) -> Result<bool> {
        let psql = tool(source, "psql")?;
        let mut command = base_command(&psql, source);
        let statement = format!(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = {}",
            sql_literal(database)
        );
        command.args(["--no-psqlrc", "--tuples-only", "--no-align"]);
        command.arg(format!("--command={statement}"));
        let result = run(command, timeout, None).context("query target database existence")?;
        let text = String::from_utf8(result.stdout)?;
        Ok(!text.trim().is_empty())
    }

    fn role_conflicts(
        &self,
        source: &Source,
        globals: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>> {
        let statements = parse_role_statements(globals)?;
        let names = exported_role_names(&statements);
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let existing = self.existing_roles(source, &names, timeout)?;
        // A cluster that already contains every exported role (e.g. the
        // original one) is a real conflict. A baseline cluster that merely
        // shares maintenance roles is handled statement-by-statement when
        // applying.
        if names.iter().all(|name| existing.iter().any(|e| e == name)) {
            Ok(names)
        } else {
            Ok(Vec::new())
        }
    }

    fn apply_globals(&self, source: &Source, globals: &Path, timeout: Duration) -> Result<()> {
        let statements = parse_role_statements(globals)?;
        let text = fs::read_to_string(globals).context("read staged globals file")?;
        if text.len() as u64 > MAX_GLOBALS_BYTES {
            bail!("globals file exceeds size limit");
        }
        if has_password_clause(text.as_bytes()) {
            bail!(
                "globals file contains a PASSWORD clause; refusing to apply an unexported verifier"
            );
        }
        let names = exported_role_names(&statements);
        if names.is_empty() {
            bail!(
                "globals export contains no role statements; refusing to treat it as security metadata"
            );
        }
        let existing = self.existing_roles(source, &names, timeout)?;
        let (script, applied) = build_globals_script(&statements, &existing);
        if applied > 0 {
            let psql = tool(source, "psql")?;
            let mut command = base_command(&psql, source);
            command.args([
                "--no-psqlrc",
                "--quiet",
                "--single-transaction",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "-",
            ]);
            let result =
                run(command, timeout, Some(script.into_bytes())).context("apply globals script")?;
            if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
                bail!("globals apply emitted a warning; the transaction result is unknown");
            }
        }
        // A script that reaches the server but changes nothing must never read
        // as success: the roles the manifest promised are the post-condition.
        let after = self.existing_roles(source, &names, timeout)?;
        if let Some(missing) = names.iter().find(|name| !after.iter().any(|e| e == *name)) {
            bail!(
                "role {missing} is absent after the globals apply; security metadata was not reconstructed"
            );
        }
        Ok(())
    }

    fn create_database(&self, source: &Source, database: &str, timeout: Duration) -> Result<()> {
        if !database.starts_with(backup_domain::FIXTURE_PREFIX) {
            bail!("M2 only creates synthetic fixture databases");
        }
        let createdb = tool(source, "createdb")?;
        let mut command = cluster_command(&createdb, source);
        command.arg("--template=template0");
        command.arg(database);
        run(command, timeout, None).context("create target database")?;
        Ok(())
    }

    fn restore_to_database(
        &self,
        source: &Source,
        database: &str,
        archive: &Path,
        security: RestoreSecurityPolicy,
        timeout: Duration,
    ) -> Result<()> {
        let restore = tool(source, "pg_restore")?;
        let mut command = isolated_command(&restore, source);
        command
            .arg("--no-password")
            .arg(format!("--host={}", source.host))
            .arg(format!("--port={}", source.port))
            .arg(format!("--username={}", source.user))
            .arg(format!("--dbname={database}"));
        command.args(["--exit-on-error"]);
        if !security.ownership {
            command.arg("--no-owner");
        }
        if !security.privileges {
            command.arg("--no-privileges");
        }
        command.arg(archive);
        let result = run(command, timeout, None).context("run pg_restore")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_restore emitted output on stderr; restore result is unverified");
        }
        Ok(())
    }
}

impl PostgresAdapter {
    fn existing_roles(
        &self,
        source: &Source,
        names: &[String],
        timeout: Duration,
    ) -> Result<Vec<String>> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let psql = tool(source, "psql")?;
        let mut command = base_command(&psql, source);
        let list = names
            .iter()
            .map(|name| sql_literal(name))
            .collect::<Vec<_>>()
            .join(", ");
        let statement = format!(
            "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname IN ({list}) ORDER BY rolname"
        );
        command.args(["--no-psqlrc", "--tuples-only", "--no-align"]);
        command.arg(format!("--command={statement}"));
        let result = run(command, timeout, None).context("probe existing roles")?;
        let text = String::from_utf8(result.stdout)?;
        Ok(text
            .lines()
            .map(str::to_owned)
            .filter(|l| !l.is_empty())
            .collect())
    }
}

fn cluster_command(path: &Path, source: &Source) -> Command {
    let mut command = isolated_command(path, source);
    command
        .arg("--no-password")
        .arg(format!("--host={}", source.host))
        .arg(format!("--port={}", source.port))
        .arg(format!("--username={}", source.user));
    command
}

fn sql_literal(value: &str) -> String {
    if value.contains('\0') {
        // Caller-provided names are validated elsewhere; a NUL can never be
        // represented in a client encoding, so fail closed.
        panic!("database or role name contains a NUL byte");
    }
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatementKind {
    /// CREATE/ALTER ROLE for the named role.
    Role(String),
    /// GRANT <role> TO <grantee>: membership keyed on the grantee.
    Membership(String),
    /// Anything else in the globals script; never replayed in M2.
    Other,
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

fn parse_role_statements(path: &Path) -> Result<Vec<(StatementKind, String)>> {
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
fn build_globals_script(
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

fn exported_role_names(statements: &[(StatementKind, String)]) -> Vec<String> {
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

fn tool(source: &Source, name: &str) -> Result<PathBuf> {
    let path = source.client_bin_dir.join(name);
    if !path.is_absolute() || !fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        bail!("missing PostgreSQL client tool: {name}");
    }
    Ok(path)
}

fn tool_version(path: &Path, timeout: Duration) -> Result<(u32, String)> {
    let mut command = Command::new(path);
    command.arg("--version").env_clear().env("LC_ALL", "C");
    let result = run(command, timeout, None)?;
    let version = String::from_utf8(result.stdout)?.trim().to_owned();
    let major = version
        .split_whitespace()
        .find_map(|part| part.split('.').next()?.parse::<u32>().ok())
        .context("parse PostgreSQL client version")?;
    Ok((major, version))
}

fn base_command(path: &Path, source: &Source) -> Command {
    let mut command = isolated_command(path, source);
    command
        .arg("--no-password")
        .arg(format!("--host={}", source.host))
        .arg(format!("--port={}", source.port))
        .arg(format!("--username={}", source.user))
        .arg(format!("--dbname={}", source.database));
    command
}

fn isolated_command(path: &Path, source: &Source) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PGCONNECT_TIMEOUT", "10")
        .env("PGSSLMODE", "disable");
    if let Some(password_file) = &source.password_file {
        command.env("PGPASSFILE", password_file);
    } else {
        command.env("PGPASSFILE", "/dev/null");
    }
    command
}

struct ProcessResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(
    mut command: Command,
    timeout: Duration,
    stdin_data: Option<Vec<u8>>,
) -> Result<ProcessResult> {
    let mut child = match stdin_data {
        Some(script) => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn PostgreSQL client tool")?;
            let mut stdin = child.stdin.take().context("capture stdin")?;
            thread::spawn(move || {
                let _ = stdin.write_all(&script);
                let _ = stdin.flush();
            });
            child
        }
        None => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command.spawn().context("spawn PostgreSQL client tool")?
        }
    };
    let stdout = child.stdout.take().context("capture stdout")?;
    let stderr = child.stderr.take().context("capture stderr")?;
    let out_reader = thread::spawn(move || read_bounded(stdout));
    let err_reader = thread::spawn(move || read_bounded(stderr));
    let started = Instant::now();
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_reader.join();
            let _ = err_reader.join();
            bail!("PostgreSQL client tool timed out");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let stdout = out_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader failed"))??;
    let stderr = err_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    if !status.success() {
        bail!(
            "PostgreSQL client tool failed with status {status}; output withheld to protect data"
        );
    }
    Ok(ProcessResult { stdout, stderr })
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let remaining = MAX_CAPTURE.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..n.min(remaining)]);
    }
    Ok(captured)
}

/// Defense in depth: our export path uses --no-role-passwords, so a PASSWORD
/// clause means the file was forged or exported wrongly. Substring scan is
/// deliberately over-approximate; false positives only refuse a restore.
fn has_password_clause(script: &[u8]) -> bool {
    let upper = script
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect::<Vec<_>>();
    upper.windows(b"PASSWORD".len()).any(|w| w == b"PASSWORD")
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
    fn sql_literals_are_escaped_and_names_never_interpolated_raw() {
        assert_eq!(sql_literal("simple"), "'simple'");
        assert_eq!(sql_literal("it's"), "'it''s'");
        assert_eq!(
            sql_literal("a'); DROP TABLE t;--"),
            "'a''); DROP TABLE t;--'"
        );
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
