//! The job lock: one operation at a time on one scope, guaranteed by the kernel.
//!
//! ADR 0003's choice 4 needs a `backup create` that is already running to make the second one
//! refuse (roadmap T15), and a row in a database cannot do that: the transaction that would
//! record "I am running" commits in milliseconds, while the dump it describes runs for minutes.
//! The spike measured exactly this — a held write transaction left the file's `flock` free — so
//! the lock is a separate file and the row is only its history.
//!
//! What `flock` buys over a lock file whose existence is the lock:
//!
//! - The kernel releases it when the process dies, by any exit including `SIGKILL` and a power
//!   loss on the way down. No pid inside means no staleness rule to get wrong, because there is
//!   no staleness to detect: a dead holder stops holding.
//! - It is non-blocking by option, so a refusal is immediate and legible rather than a timeout a
//!   waiting operator reads as a hang.
//!
//! The lock is per (`source_fingerprint`, `profile_fingerprint`), because that is the scope two
//! backups actually collide on: same database, same selection, so the second would double the
//! load on a dump whose result nothing distinguishes from the first's. Two different profiles of
//! one database take two locks and may run at once — a decision, not an oversight: the
//! alternative serialises an operator's nightly selective dump behind a weekly whole-database one
//! for no safety the fingerprints do not already give.

use anyhow::{Context, Result, bail, ensure};
use std::fs::{DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Where lock files live inside a storage root. A directory of its own so a store's top level
/// stays as frozen, and so `ls` of a root shows one new thing rather than a scatter.
pub const LOCK_DIR: &str = "locks";

/// A held job lock. Released on drop, which is also the release on panic and on exit.
#[derive(Debug)]
pub struct JobLock {
    file: File,
    path: PathBuf,
}

impl JobLock {
    /// Takes the lock for one job's scope, or refuses immediately if another process holds it.
    ///
    /// `profile_fingerprint` is what [`backup_domain::profile_fingerprint`] returns for the
    /// profile this command was *configured* with — or for the reserved `whole-database` name when
    /// it named none — so a lock file never carries a profile name an operator chose.
    pub fn acquire(
        root: &Path,
        source_fingerprint: &str,
        profile_fingerprint: &str,
    ) -> Result<Self> {
        for (kind, fingerprint) in [
            ("source", source_fingerprint),
            ("profile", profile_fingerprint),
        ] {
            ensure!(
                crate::is_hex_id(fingerprint),
                "a job lock is named by fingerprints, so the {kind} must be {id} lowercase hex \
                 characters, not {fingerprint:?}",
                id = backup_domain::ID_HEX_LEN
            );
        }
        let dir = root.join(LOCK_DIR);
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .with_context(|| format!("cannot create {} for a job lock", dir.display()))?;

        let path = Self::path_for(root, source_fingerprint, profile_fingerprint);
        // 0600 like every other file this tool writes: the lock is only two fingerprints, but the
        // root is a backup store and the mode is not something to reason about per file.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("cannot open job lock {}", path.display()))?;

        // `LOCK_EX | LOCK_NB`: exclusive, and never wait. Waiting would put an operator in front of
        // a command that appears to have hung, which is the failure mode this whole file exists to
        // avoid, and the schedule that wants waiting is M6's systemd timer, not this command.
        let outcome = unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        if outcome != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                bail!(
                    "a job for source {source_fingerprint} and profile {profile_fingerprint} is \
                     already running: {} is held by another process. Two dumps of one scope at the \
                     same time would produce two artifacts nothing can tell apart, so this command \
                     stops rather than adds a second.",
                    path.display()
                );
            }
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot take job lock {}", path.display()));
        }

        Ok(Self { file, path })
    }

    /// The path a scope's lock lives at. Public so `backup list` and the operator guide can name
    /// the file a refusal pointed at, and so a test can prove two profiles cannot collide.
    pub fn path_for(root: &Path, source_fingerprint: &str, profile_fingerprint: &str) -> PathBuf {
        root.join(LOCK_DIR)
            .join(format!("{source_fingerprint}-{profile_fingerprint}.lock"))
    }

    /// Which file this handle holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for JobLock {
    fn drop(&mut self) {
        // The unlock can only fail if the descriptor is already gone, which nothing here does.
        // Deleting the file would be the actual bug: a second process may already have it open and
        // be about to lock the *new* inode that a `create` just made, which is two holders.
        let _ = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    const SOURCE: &str = "c1cb425f097b6522";
    const NIGHTLY: &str = "651dd7a74505b176";
    const WEEKLY: &str = "1111111111111111";

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("backupctl-lock-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A lock that is taken cannot be taken again, and the refusal is a sentence about a running
    /// job rather than an errno. It is also *instant*, which is what `LOCK_NB` is for: a second
    /// `backup create` is refused while the first is still printing its header.
    #[test]
    fn a_held_lock_is_refused_immediately_and_names_the_scope() {
        let root = temp_root("held");
        let held = JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();

        // Off the main thread, so a missing `LOCK_NB` — which would block forever — fails this
        // test instead of hanging the suite.
        let (sender, receiver) = mpsc::channel();
        let moved = root.clone();
        let second = std::thread::spawn(move || {
            let started = Instant::now();
            let outcome = JobLock::acquire(&moved, SOURCE, NIGHTLY)
                .err()
                .map(|error| {
                    let text = format!("{error:#}");
                    (text, started.elapsed())
                });
            let _ = sender.send(outcome);
        });
        let refused = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("the second acquire neither refused nor returned");
        second.join().unwrap();

        let (text, waited) = refused.expect("a second holder of one lock was accepted");
        assert!(text.contains("already running"), "{text}");
        assert!(text.contains(&held.path().display().to_string()), "{text}");
        assert!(waited < Duration::from_millis(500), "waited {waited:?}");

        // And the same after the first lets go, which is the whole of why the kernel owns this
        // rather than a file: nothing stale is left to clean up.
        drop(held);
        JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_lock_is_per_scope_and_its_name_discloses_nothing() {
        let root = temp_root("scope");
        let nightly = JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();

        // Another profile of the same database is another lock: the choice, not an accident, and
        // it has to keep working or a weekly whole-database dump blocks every nightly.
        let weekly = JobLock::acquire(&root, SOURCE, WEEKLY).unwrap();
        assert_ne!(nightly.path(), weekly.path());

        // The same profile on another database is also another lock.
        let other_source = JobLock::acquire(&root, WEEKLY, NIGHTLY).unwrap();
        assert_ne!(other_source.path(), nightly.path());

        // Names are two fingerprints and nothing else, so `ls locks/` on a store copied off-site
        // reveals no more than `inventory.db` does.
        for path in [nightly.path(), weekly.path(), other_source.path()] {
            let name = path.file_name().unwrap().to_str().unwrap();
            let stems = name
                .strip_suffix(".lock")
                .unwrap_or_else(|| panic!("{name} is not a lock file"))
                .split('-')
                .collect::<Vec<_>>();
            assert_eq!(stems.len(), 2, "{name} is not one scope");
            for stem in stems {
                assert!(
                    crate::is_hex_id(stem),
                    "{name} says more than a fingerprint"
                );
            }
            assert_eq!(path.parent().unwrap().file_name().unwrap(), LOCK_DIR);
        }

        // A scope is one path, computed the same way from both sides of the refusal.
        assert_eq!(
            JobLock::path_for(&root, SOURCE, NIGHTLY),
            nightly.path().to_path_buf()
        );

        drop(nightly);
        drop(weekly);
        drop(other_source);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A lock named by something other than fingerprints is a bug in the caller, and the message
    /// has to say so instead of creating `locks/Nightly.lock`.
    #[test]
    fn a_lock_name_is_built_from_fingerprints_only() {
        let root = temp_root("validate");
        for (source, profile, kind) in [
            ("nightly", NIGHTLY, "source"),
            (SOURCE, "Nightly", "profile"),
            (SOURCE, &"a".repeat(15), "profile"),
            (SOURCE, "", "profile"),
        ] {
            let error = JobLock::acquire(&root, source, profile)
                .expect_err(&format!("{source}/{profile} is not a scope"))
                .to_string();
            assert!(error.contains("named by fingerprints"), "{error}");
            assert!(error.contains(kind), "{error}");
        }
        // Nothing was created by the refusals.
        assert!(!root.join(LOCK_DIR).exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// An existing `locks/` directory — every run after the first, and any root prepared by hand —
    /// is not an error.
    #[test]
    fn an_existing_lock_directory_is_reused() {
        let root = temp_root("existing");
        DirBuilder::new()
            .mode(0o700)
            .create(root.join(LOCK_DIR))
            .unwrap();
        let held = JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();
        drop(held);
        let again = JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();

        // The mode is the store's, because the file is in a backup store.
        let mode = std::fs::metadata(again.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        drop(again);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A root with no `locks/` to put one in is reported by path. This is the recovery case: an
    /// operator who pointed a config at a mount that is not there gets that answer from the lock,
    /// rather than a `No such file or directory (os error 2)` with no name in it.
    #[test]
    fn a_root_that_cannot_hold_locks_says_which_path_failed() {
        let missing = temp_root("absent").join("not-mounted");
        let error = JobLock::acquire(&missing, SOURCE, NIGHTLY)
            .expect_err("nothing is mounted where the store should be");
        let text = format!("{error:#}");
        assert!(text.contains("cannot create"), "{text}");
        assert!(
            text.contains(&missing.join(LOCK_DIR).display().to_string()),
            "{text}"
        );
    }

    /// The reason this mechanism was chosen over a lock file whose existence is the lock, and the
    /// one part no in-process test can reach: a holder killed by `SIGKILL` leaves no stale lock
    /// file, because the kernel closed the descriptor. The spike ran exactly that (ADR 0003,
    /// round 10) and found the next `flock` succeed instantly with the file untouched;
    /// `tests/m5a_docker_smoke.sh` re-runs it against a real `backup create` killed mid-dump,
    /// which is the case that has to keep working, and is where the dropped `locks/*.lock` file is
    /// asserted to still be there and still be free.
    #[test]
    fn a_dropped_handle_frees_the_lock_without_removing_the_file() {
        let root = temp_root("dropped");
        let path = JobLock::path_for(&root, SOURCE, NIGHTLY);

        let held = JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();
        assert!(held.path().exists());
        drop(held);
        assert!(path.exists(), "the file was unlinked, which is the race");

        // Free again with nothing cleaned up, and the very next holder needs no ceremony.
        let again = JobLock::acquire(&root, SOURCE, NIGHTLY).unwrap();
        assert!(JobLock::acquire(&root, SOURCE, NIGHTLY).is_err());

        drop(again);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
