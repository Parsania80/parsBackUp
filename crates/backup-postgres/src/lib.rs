use anyhow::{Context, Result, bail};
use backup_application::{DatabaseAdapter, EngineInfo};
use backup_domain::Source;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CAPTURE: usize = 64 * 1024;

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
        let dump_version = tool_version(&dump, timeout)?;
        let restore_version = tool_version(&restore, timeout)?;
        let psql_version = tool_version(&psql, timeout)?;
        if dump_version.0 != restore_version.0 || dump_version.0 != psql_version.0 {
            bail!("PostgreSQL client tools are from different major versions");
        }
        let mut command = base_command(&psql, source);
        command.args([
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command=SHOW server_version_num",
        ]);
        let result = run(command, timeout).context("query PostgreSQL server version")?;
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
        let result = run(command, timeout).context("run pg_dump")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_dump emitted a warning; artifact was not published");
        }
        Ok(())
    }

    fn inspect_archive(&self, source: &Source, archive: &Path, timeout: Duration) -> Result<()> {
        let restore = tool(source, "pg_restore")?;
        let mut command = isolated_command(&restore, source);
        command.arg("--list").arg(archive);
        let result = run(command, timeout).context("inspect pg_dump archive")?;
        if result.stdout.is_empty() {
            bail!("pg_restore returned an empty table of contents");
        }
        Ok(())
    }
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
    let result = run(command, timeout)?;
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

fn run(mut command: Command, timeout: Duration) -> Result<ProcessResult> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("spawn PostgreSQL client tool")?;
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
