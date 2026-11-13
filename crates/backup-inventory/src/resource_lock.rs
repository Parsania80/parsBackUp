//! Target and artifact-use claims held for the lifetime of file consumers.
use anyhow::{Context, Result, ensure};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use uuid::Uuid;

use crate::{LOCK_DIR, is_hex_id};

#[derive(Debug)]
pub struct ResourceLock(File);

impl ResourceLock {
    pub fn inherit_in_children(&self) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_GETFD) };
        ensure!(
            flags >= 0
                && unsafe {
                    libc::fcntl(self.0.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC)
                } == 0,
            "cannot retain resource claim in native subprocesses"
        );
        Ok(())
    }
    pub fn target(root: &Path, fingerprint: &str) -> Result<Option<Self>> {
        ensure!(is_hex_id(fingerprint), "invalid target fingerprint");
        Self::acquire(root, &format!("target-{fingerprint}.lock"), true)
    }

    pub fn artifact(root: &Path, id: Uuid, exclusive: bool) -> Result<Option<Self>> {
        Self::acquire(root, &format!("artifact-{id}.lock"), exclusive)
    }

    fn acquire(root: &Path, name: &str, exclusive: bool) -> Result<Option<Self>> {
        let dir = root.join(LOCK_DIR);
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).context("cannot create resource lock directory"),
        }
        let meta = std::fs::symlink_metadata(&dir)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "resource lock directory is not a real directory"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join(name))
            .context("cannot open resource lock")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
            "resource lock is not a private regular file"
        );
        let mode = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
            return Ok(Some(Self(file)));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        Err(error).context("cannot acquire resource lock")
    }
}

impl Drop for ResourceLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets_are_exclusive_and_artifact_use_is_shared() {
        let root = std::env::temp_dir().join(format!("backupctl-resource-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let target = ResourceLock::target(&root, "0123456789abcdef")
            .unwrap()
            .unwrap();
        assert!(
            ResourceLock::target(&root, "0123456789abcdef")
                .unwrap()
                .is_none()
        );
        assert!(
            ResourceLock::target(&root, "fedcba9876543210")
                .unwrap()
                .is_some()
        );
        let id = Uuid::new_v4();
        let a = ResourceLock::artifact(&root, id, false).unwrap().unwrap();
        let b = ResourceLock::artifact(&root, id, false).unwrap().unwrap();
        assert!(ResourceLock::artifact(&root, id, true).unwrap().is_none());
        drop((a, b));
        assert!(ResourceLock::artifact(&root, id, true).unwrap().is_some());
        drop(target);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn symlink_and_public_lock_are_refused() {
        let root = std::env::temp_dir().join(format!("backupctl-resource-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join(LOCK_DIR)).unwrap();
        let path = root.join(LOCK_DIR).join("target-0123456789abcdef.lock");
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(ResourceLock::target(&root, "0123456789abcdef").is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ResourceLock::target(&root, "0123456789abcdef").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
