//! Finding the PostgreSQL client binaries and running them.
//!
//! Everything here is about the tool boundary: the names it invokes, the
//! argument values it passes, and the rule that a client tool's output is never
//! repeated into an error (it can carry credentials or data).

use anyhow::{Context, Result, bail};
use backup_domain::Source;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How much of a tool's stdout/stderr is kept for parsing; the rest is dropped
/// rather than buffered, so a runaway query cannot exhaust memory.
const MAX_CAPTURE: usize = 64 * 1024;

pub(crate) const PG_DUMP: &str = "pg_dump";
pub(crate) const PG_RESTORE: &str = "pg_restore";
pub(crate) const PG_DUMPALL: &str = "pg_dumpall";
pub(crate) const PSQL: &str = "psql";
pub(crate) const CREATEDB: &str = "createdb";

/// The arguments every archive is written with. `DUMP_FORMAT` and
/// `DUMP_COMPRESSION` mirror the manifest's `archive_format`/`compression`
/// values (`ARCHIVE_FORMAT`, `ARCHIVE_COMPRESSION`), so the recorded shape and
/// the written shape cannot drift apart silently.
pub(crate) const DUMP_FORMAT: &str = "--format=custom";
pub(crate) const DUMP_COMPRESSION: &str = "--compress=6";
pub(crate) const DUMP_NO_SUBSCRIPTIONS: &str = "--no-subscriptions";
pub(crate) const DUMP_LOCK_WAIT_TIMEOUT: &str = "--lock-wait-timeout=5s";
/// Large objects are database-wide and have no schema or owner, so the only
/// choice a selection has is all of them or none of them.
pub(crate) const LARGE_OBJECTS: &str = "--large-objects";
pub(crate) const NO_LARGE_OBJECTS: &str = "--no-large-objects";
/// The psql arguments that turn a query into one bare value per line.
pub(crate) const PSQL_QUERY_ARGS: [&str; 3] = ["--no-psqlrc", "--tuples-only", "--no-align"];

pub(crate) const ARG_NO_PASSWORD: &str = "--no-password";
pub(crate) const ARG_HOST: &str = "--host=";
pub(crate) const ARG_PORT: &str = "--port=";
pub(crate) const ARG_USERNAME: &str = "--username=";
pub(crate) const ARG_DBNAME: &str = "--dbname=";

pub(crate) struct ProcessResult {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

/// Resolve a client binary inside the configured bin directory.
pub(crate) fn tool(source: &Source, name: &str) -> Result<PathBuf> {
    let path = source.client_bin_dir.join(name);
    if !path.is_absolute() || !fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        bail!("missing PostgreSQL client tool: {name}");
    }
    Ok(path)
}

pub(crate) fn tool_version(path: &Path, timeout: Duration) -> Result<(u32, String)> {
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

pub(crate) fn base_command(path: &Path, source: &Source) -> Command {
    let mut command = isolated_command(path, source);
    command
        .arg(ARG_NO_PASSWORD)
        .arg(format!("{ARG_HOST}{}", source.host))
        .arg(format!("{ARG_PORT}{}", source.port))
        .arg(format!("{ARG_USERNAME}{}", source.user))
        .arg(format!("{ARG_DBNAME}{}", source.database));
    command
}

pub(crate) fn cluster_command(path: &Path, source: &Source) -> Command {
    let mut command = isolated_command(path, source);
    command
        .arg(ARG_NO_PASSWORD)
        .arg(format!("{ARG_HOST}{}", source.host))
        .arg(format!("{ARG_PORT}{}", source.port))
        .arg(format!("{ARG_USERNAME}{}", source.user));
    command
}

/// A command that never inherits the caller's environment: the connect
/// settings below are the only ones a client tool may act on.
pub(crate) fn isolated_command(path: &Path, source: &Source) -> Command {
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

pub(crate) fn run(
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
