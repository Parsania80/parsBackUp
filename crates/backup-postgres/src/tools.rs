//! Finding the PostgreSQL client binaries and running them.
//!
//! Everything here is about the tool boundary: the names it invokes, the
//! argument values it passes, and the rule that a client tool's output is never
//! repeated into an error (it can carry credentials or data).

use anyhow::{Context, Result, bail};
use backup_domain::Source;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

/// Capture remains bounded; overflow is drained and refused rather than parsed as complete.
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
    parse_tool_version(result.stdout)
}

pub(crate) fn parse_tool_version(stdout: Vec<u8>) -> Result<(u32, String)> {
    let version = String::from_utf8(stdout)?.trim().to_owned();
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
    backup_application::control::check()?;
    command
        .process_group(0)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut group =
        crate::process::Group::new(command.spawn().context("spawn PostgreSQL client tool")?);
    let stdin_writer = stdin_data.map(|script| {
        let mut stdin = group.child.stdin.take().expect("piped stdin");
        thread::spawn(move || {
            let _ = stdin.write_all(&script);
            let _ = stdin.flush();
        })
    });
    let stdout = group.child.stdout.take().context("capture stdout")?;
    let stderr = group.child.stderr.take().context("capture stderr")?;
    let out_reader = thread::spawn(move || read_bounded(stdout));
    let err_reader = thread::spawn(move || read_bounded(stderr));
    let status = group.wait(timeout, &AtomicBool::new(false));
    if let Some(writer) = stdin_writer {
        let _ = writer.join();
    }
    let stdout = out_reader.join();
    let stderr = err_reader.join();
    let status = status?;
    let stdout = stdout.map_err(|_| anyhow::anyhow!("stdout reader failed"))??;
    let stderr = stderr.map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    if !status.success() {
        bail!(
            "PostgreSQL client tool failed with status {status}; output withheld to protect data"
        );
    }
    Ok(ProcessResult { stdout, stderr })
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let remaining = MAX_CAPTURE.saturating_sub(captured.len());
        overflow |= n > remaining;
        captured.extend_from_slice(&buffer[..n.min(remaining)]);
    }
    if overflow {
        bail!(
            "PostgreSQL client output exceeds the {MAX_CAPTURE} byte capture limit; output withheld to protect data"
        );
    }
    Ok(captured)
}

struct StopOnDrop<'a> {
    stop: &'a AtomicBool,
    armed: bool,
}
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.stop.store(true, Ordering::Relaxed);
        }
    }
}

/// Streams native stdout into the caller's sink. A scoped watchdog observes the
/// owned process group while the consuming thread can be blocked reading its pipe.
/// Consumer error/panic requests immediate group cleanup before either thread joins.
pub(crate) fn run_streaming(
    mut command: Command,
    name: &'static str,
    timeout: Duration,
    consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
) -> Result<()> {
    backup_application::control::check()?;
    let child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {name}"))?;
    let mut group = crate::process::Group::new(child);
    let stdout = group.child.stdout.take().context("capture stdout")?;
    let mut stdout = backup_application::control::Reader(stdout);
    let stderr = group.child.stderr.take().context("capture stderr")?;
    let stop = AtomicBool::new(false);
    let (streamed, status, stderr) = thread::scope(|scope| {
        let err_reader = scope.spawn(move || read_bounded(stderr));
        let watcher = scope.spawn(|| group.wait(timeout, &stop));
        let mut cleanup = StopOnDrop {
            stop: &stop,
            armed: true,
        };
        let streamed = consume(&mut stdout);
        drop(stdout);
        cleanup.armed = streamed.is_err();
        drop(cleanup);
        let status = watcher.join();
        let stderr = err_reader.join();
        (streamed, status, stderr)
    });
    backup_application::control::check()?;
    streamed?;
    let status = status.map_err(|_| anyhow::anyhow!("client watcher failed"))??;
    let stderr = stderr.map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    if !status.success() {
        bail!("{name} failed with status {status}; output withheld to protect data");
    }
    if stderr.iter().any(|byte| !byte.is_ascii_whitespace()) {
        bail!("{name} emitted a warning; artifact was not published");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subject here is the pipe, not PostgreSQL, so `/bin/sh` stands in for a client
    /// tool: it is the only way to test a watchdog that has to kill a process while
    /// another thread is blocked reading it.
    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        command
    }

    fn collect(script: &str, timeout: Duration) -> Result<Vec<u8>> {
        let mut collected = Vec::new();
        run_streaming(shell(script), "sh", timeout, &mut |stream| {
            stream.read_to_end(&mut collected)?;
            Ok(())
        })?;
        Ok(collected)
    }

    #[test]
    fn deadlines_close_descendant_pipes_in_both_runners() {
        for script in ["echo started; sleep 5", "sleep 5 & exit 0"] {
            let started = Instant::now();
            let result = run(shell(script), Duration::from_millis(100), None);
            if !script.contains("exit 0") {
                assert!(result.err().unwrap().to_string().contains("timed out"));
            } else {
                assert!(result.is_ok());
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            let started = Instant::now();
            let result = collect(script, Duration::from_millis(100));
            if !script.contains("exit 0") {
                assert!(result.unwrap_err().to_string().contains("timed out"));
            } else {
                assert!(result.is_ok());
            }
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    fn capture_overflow_is_drained_and_refused() {
        assert_eq!(
            read_bounded(&vec![b'x'; MAX_CAPTURE][..]).unwrap().len(),
            MAX_CAPTURE
        );
        for script in ["head -c 70000 /dev/zero", "head -c 70000 /dev/zero >&2"] {
            let error = run(shell(script), Duration::from_secs(5), None)
                .err()
                .unwrap();
            assert!(error.to_string().contains("capture limit"), "{error}");
        }
        let error = collect(
            "echo payload; head -c 70000 /dev/zero >&2",
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(error.to_string().contains("capture limit"), "{error}");
    }
    #[test]
    fn streaming_is_not_bounded_by_the_capture_limit() {
        // Thirty times `MAX_CAPTURE`: a dump the size of a real database has to survive
        // this path, so the bound that protects captured output must not apply to it.
        let bytes = collect(
            "head -c 2097152 /dev/zero | tr '\\0' 'x'",
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(bytes.len(), 2 * 1024 * 1024);
        assert!(bytes.iter().all(|byte| *byte == b'x'));
    }

    #[test]
    fn a_refusing_consumer_is_the_reported_failure() {
        // The consumer stops after one byte; the tool then dies on a closed pipe and
        // exits nonzero, which is a consequence of the refusal rather than its cause.
        let error = run_streaming(
            shell("yes x"),
            "sh",
            Duration::from_secs(10),
            &mut |stream| {
                let mut byte = [0_u8; 1];
                let _ = stream.read(&mut byte);
                bail!("sink refused the stream");
            },
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "sink refused the stream");
    }

    #[test]
    fn a_stalled_producer_is_killed_at_the_deadline() {
        // `exec` keeps the killed process the one holding the pipe open; a plain `sleep`
        // would leave a grandchild writing to it past its own parent's death.
        let started = Instant::now();
        let error = collect("echo started; exec sleep 5", Duration::from_millis(300))
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the deadline must cut the tool off, not the sleep"
        );
    }

    #[test]
    fn output_on_stderr_refuses_the_whole_stream() {
        // A tool that warns about the bytes it produced cannot vouch for them, however
        // complete those bytes look.
        let error = collect("echo payload; echo noisy >&2", Duration::from_secs(10))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("emitted a warning; artifact was not published"),
            "{error}"
        );
    }
    #[test]
    fn refusing_consumer_stops_a_stalled_producer_promptly_and_panic_unwinds() {
        let start = Instant::now();
        let error = run_streaming(
            shell("echo x; sleep 20"),
            "sh",
            Duration::from_secs(30),
            &mut |r| {
                let mut byte = [0];
                r.read_exact(&mut byte)?;
                bail!("sink failed");
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "sink failed");
        assert!(start.elapsed() < Duration::from_secs(2));
        let start = Instant::now();
        let panic = std::panic::catch_unwind(|| {
            let _ = run_streaming(
                shell("echo x; sleep 20"),
                "sh",
                Duration::from_secs(30),
                &mut |r| {
                    let mut byte = [0];
                    r.read_exact(&mut byte)?;
                    panic!("consumer panicked");
                },
            );
        });
        assert!(panic.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn deadline_joins_a_blocked_stdin_writer() {
        let start = Instant::now();
        let error = run(
            shell("exec sleep 20"),
            Duration::from_millis(100),
            Some(vec![b'x'; 1024 * 1024]),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
