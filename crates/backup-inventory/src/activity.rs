//! Store-activity ownership: who may be using a working directory, and who may clear one.
//!
//! The scope lock in [`crate::JobLock`] answers a different question — "is someone dumping this
//! source and profile right now" — and ADR 0004 keeps the two apart on purpose. A staging directory
//! or a decrypted scratch view is not scoped: a verification, a restore, and a dump of an unrelated
//! profile can all own one at the same time, and none of them cares which database is being read.
//! What they all care about is that nobody deletes the directory underneath them.
//!
//! So this is one lock for the whole store, with two modes:
//!
//! - **shared**, taken by an operation that is about to create or read a working directory. Shared
//!   against shared is compatible, which is what lets two profiles back up at the same time while
//!   still being proof that a cleanup pass cannot run.
//! - **exclusive**, taken by the only pass that removes anything. It is refused — not queued — while
//!   any operation holds the store, because a housekeeping run that had to wait would be a housekeeping
//!   run that delayed a backup for no safety.
//!
//! `flock` gives the same death property the scope lock relies on: the claim belongs to the open file
//! description, so a process killed by `SIGKILL` stops holding it, and nothing here has to decide what
//! a stale claim means. That is also why a *live* operation is the only possible reason to be refused:
//! there is no staleness rule to get wrong, and no timestamp or pid is consulted.

use anyhow::{Context, Result, bail, ensure};
use std::fs::{DirBuilder, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::LOCK_DIR;

/// The one claim file, named the same for every holder so two processes cannot lock two different
/// inodes and both believe they won.
pub const ACTIVITY_FILE: &str = "activity.lock";

/// How long a shared claim waits for a maintenance pass, and how often it asks again.
///
/// The wait is bounded and stated, as ADR 0003's choice 4 requires of any acquisition that is not
/// plain nonblocking: the only holder a shared claim can collide with is a recovery pass, which does
/// a handful of updates and some `remove_dir_all` calls and never streams a dump. Beyond a second,
/// the operator is better served by a legible refusal than by a command that appears to have hung.
const MAINTENANCE_WAIT: Duration = Duration::from_millis(1000);
const MAINTENANCE_POLL: Duration = Duration::from_millis(10);

/// A held claim on the store's working directories.
///
/// Dropping it releases the claim, which is also how a panic or an error return releases it; the
/// guards in `backup-local` hold one for exactly as long as the directory they own exists.
#[derive(Debug)]
pub struct ActivityLock {
    file: File,
    path: PathBuf,
}

impl ActivityLock {
    /// Claims the store for an operation that is about to use a working directory.
    ///
    /// Shared, so it does not serialize anything that shares it: two backups of different profiles,
    /// a verification reading one artifact while a dump writes another, and a restore decrypting a
    /// third all hold this at once.
    pub fn hold(root: &Path) -> Result<Self> {
        let (file, path) = Self::open_claim(root)?;
        let deadline = Instant::now() + MAINTENANCE_WAIT;
        loop {
            let outcome = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
            if outcome == 0 {
                return Ok(Self { file, path });
            }
            let error = std::io::Error::last_os_error();
            if !would_block(&error) {
                return Err(anyhow::Error::new(error))
                    .with_context(|| format!("cannot claim store activity {}", path.display()));
            }
            if Instant::now() >= deadline {
                bail!(
                    "another command is clearing this store's working directories and did not finish \
                     within {}; nothing was written. Run this command again once it ends.",
                    format_duration(MAINTENANCE_WAIT)
                );
            }
            std::thread::sleep(MAINTENANCE_POLL);
        }
    }

    /// Claims the store for a pass that removes working directories, or reports that an operation is
    /// live and nothing may be removed.
    ///
    /// The refusal is the whole design: exclusivity is not a convenience here, it is the *proof* that
    /// whatever is in `staging/` and `scratch/` belongs to a process that no longer exists. While any
    /// operation holds the claim shared, an entry could be mid-write, and removing it would be the
    /// defect ADR 0004 exists to close. Nonblocking, because a cleanup that queues behind a two-hour
    /// dump would turn housekeeping into an outage.
    pub fn hold_maintenance(root: &Path) -> Result<Option<Self>> {
        let (file, path) = Self::open_claim(root)?;
        let outcome = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if outcome == 0 {
            return Ok(Some(Self { file, path }));
        }
        let error = std::io::Error::last_os_error();
        if would_block(&error) {
            return Ok(None);
        }
        Err(anyhow::Error::new(error))
            .with_context(|| format!("cannot claim store maintenance {}", path.display()))
    }

    /// Opens the claim file without ever following it.
    ///
    /// Two checks, because one is not enough: the visible name is inspected first so a symlink or a
    /// FIFO gets a message that names it, and `O_NOFOLLOW` closes the window between that look and the
    /// open, in which the same name could otherwise be swapped for a link to somewhere else. The mode
    /// is checked after the open rather than before, since a file this tool did not create may have
    /// any permissions and the answer has to describe the inode actually locked.
    fn open_claim(root: &Path) -> Result<(File, PathBuf)> {
        let dir = root.join(LOCK_DIR);
        if !dir.exists() {
            DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .with_context(|| {
                    format!("cannot create {} for a store activity claim", dir.display())
                })?;
        }
        let meta = std::fs::symlink_metadata(&dir)
            .with_context(|| format!("inspect {}", dir.display()))?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "{} is not a real directory, so no lock file can be trusted inside it",
            dir.display()
        );
        let path = dir.join(ACTIVITY_FILE);
        if let Some(meta) = optional_metadata(&path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "{} is not a regular file; refusing to lock there",
                path.display()
            );
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("cannot open store activity claim {}", path.display()))?;
        let mode = file
            .metadata()
            .with_context(|| format!("inspect {}", path.display()))?
            .permissions()
            .mode();
        ensure!(
            mode & 0o077 == 0,
            "{} has mode {mode:04o}; a lock file this tool writes is 0600, and a group- or \
             world-readable one means something else made it",
            path.display()
        );
        Ok((file, path))
    }

    /// Which file this claim is held on, so a report can name it.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ActivityLock {
    fn drop(&mut self) {
        // Only reaches here if the descriptor is already gone, which nothing in this workspace does.
        // Deleting the file would be the real bug: another process may hold this very inode and a
        // replacement created underneath it would be a second, uncoordinated lock.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Whether a `flock` refusal means someone else holds the lock rather than that the call failed.
fn would_block(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EWOULDBLOCK)
}

/// A name that does not exist yet is not a problem to report; it is free space for the claim file.
/// Anything else that cannot be inspected is reported by the open that follows, which names this path.
fn optional_metadata(path: &Path) -> Option<std::fs::Metadata> {
    std::fs::symlink_metadata(path).ok()
}

/// The wait an operator has to know about, in the sentence that reports it.
fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis.is_multiple_of(1000) {
        return format!("{} second(s)", millis / 1000);
    }
    format!("{millis} milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "backupctl-activity-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn two_shared_claims_coexist_and_a_maintenance_claim_refuses_them() {
        let root = root("shared");
        let first = ActivityLock::hold(&root).unwrap();
        // Same process, second descriptor: mechanically a different holder, because `flock` locks an
        // open file description rather than a pid. This is the shape two live backups take.
        let second = ActivityLock::hold(&root).unwrap();
        assert!(
            ActivityLock::hold_maintenance(&root).unwrap().is_none(),
            "a cleanup claimed a store two operations were using"
        );
        drop(second);
        assert!(ActivityLock::hold_maintenance(&root).unwrap().is_none());
        drop(first);
        let maintenance = ActivityLock::hold_maintenance(&root).unwrap();
        assert!(
            maintenance.is_some(),
            "a quiet store was refused maintenance"
        );
        // The other direction is a bounded wait rather than a refusal: an operation cannot join a
        // cleanup that is already running, and it is told so instead of hanging.
        let error = format!("{:#}", ActivityLock::hold(&root).unwrap_err());
        assert!(
            error.contains("clearing this store's working directories"),
            "{error}"
        );
        drop(maintenance);
        assert!(ActivityLock::hold(&root).is_ok());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_claim_file_is_private_regular_and_never_unlinked() {
        let root = root("shape");
        let held = ActivityLock::hold(&root).unwrap();
        let path = root.join(LOCK_DIR).join(ACTIVITY_FILE);
        assert_eq!(path, held.path());
        let dir_mode = fs::metadata(root.join(LOCK_DIR))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "locks/ is not private");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the claim file is not private");
        drop(held);
        // Releasing is not unlinking: the next holder must lock the same inode.
        assert!(path.is_file());
        ActivityLock::hold(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_symlinked_claim_name_is_refused_rather_than_locked() {
        let root = root("symlink");
        let dir = root.join(LOCK_DIR);
        fs::create_dir_all(&dir).unwrap();
        let elsewhere = root.join("somewhere-else.lock");
        fs::write(&elsewhere, b"").unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join(ACTIVITY_FILE)).unwrap();
        let error = format!("{:#}", ActivityLock::hold(&root).unwrap_err());
        assert!(error.contains("not a regular file"), "{error}");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_world_readable_claim_name_is_refused() {
        let root = root("mode");
        let dir = root.join(LOCK_DIR);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ACTIVITY_FILE);
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = format!("{:#}", ActivityLock::hold(&root).unwrap_err());
        assert!(error.contains("0644"), "{error}");
        fs::remove_dir_all(&root).unwrap();
    }
}
