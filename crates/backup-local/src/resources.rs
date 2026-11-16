//! Streaming byte and observed-free-space budgets for versioned native operations.
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};

pub(crate) struct Budget {
    used: AtomicU64,
    limit: u64,
}
impl Budget {
    pub(crate) fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicU64::new(0),
            limit,
        })
    }
    pub(crate) fn lease(self: &Arc<Self>) -> Arc<Lease> {
        Arc::new(Lease {
            budget: self.clone(),
            held: AtomicU64::new(0),
            release: AtomicBool::new(true),
        })
    }
}
pub(crate) struct Lease {
    budget: Arc<Budget>,
    held: AtomicU64,
    release: AtomicBool,
}
impl Lease {
    fn charge(&self, n: u64) -> io::Result<()> {
        self.budget
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(n)
                    .filter(|total| *total <= self.budget.limit)
            })
            .map_err(|_| io::Error::other("RESOURCE_LIMIT"))?;
        self.held.fetch_add(n, Ordering::SeqCst);
        Ok(())
    }
    pub(crate) fn keep_charge(&self) {
        self.release.store(false, Ordering::SeqCst);
    }
    fn refund(&self, n: u64) {
        self.held.fetch_sub(n, Ordering::SeqCst);
        self.budget.used.fetch_sub(n, Ordering::SeqCst);
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.release.load(Ordering::SeqCst) {
            self.budget
                .used
                .fetch_sub(self.held.load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }
}

pub(crate) struct ResourceWriter {
    file: File,
    limit: u64,
    written: u64,
    reserve: u64,
    lease: Option<Arc<Lease>>,
    failure: Arc<AtomicU8>,
}
impl ResourceWriter {
    pub(crate) fn new(file: File, limit: u64, reserve: u64, lease: Option<Arc<Lease>>) -> Self {
        Self {
            file,
            limit,
            written: 0,
            reserve,
            lease,
            failure: Arc::new(AtomicU8::new(0)),
        }
    }
    /// age's header serializer embeds writer errors in a diagnostic string.
    /// Preserve only our locally recorded codes across that lossy boundary.
    pub(crate) fn encrypt(
        self,
        recipient: &backup_crypto::HybridRecipient,
    ) -> anyhow::Result<backup_crypto::stream::EncryptSink<Self>> {
        let failure = self.failure.clone();
        backup_crypto::stream::EncryptSink::new(recipient, self).map_err(|error| {
            match failure.load(Ordering::SeqCst) {
                1 => error.context("RESOURCE_LIMIT"),
                2 => error.context("DISK_RESERVE_LOW"),
                3 => error.context("OPERATION_CANCELLED"),
                _ => error,
            }
        })
    }
    fn refusal(&self, code: u8) -> io::Error {
        self.failure.store(code, Ordering::SeqCst);
        io::Error::other(if code == 1 {
            "RESOURCE_LIMIT"
        } else {
            "DISK_RESERVE_LOW"
        })
    }
    pub(crate) fn into_inner(self) -> File {
        self.file
    }
}
impl Write for ResourceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if backup_application::control::is_cancelled() {
            self.failure.store(3, Ordering::SeqCst);
            return Err(io::Error::other("OPERATION_CANCELLED"));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len() as u64;
        if self
            .written
            .checked_add(n)
            .is_none_or(|sum| sum > self.limit)
        {
            return Err(self.refusal(1));
        }
        if self.reserve > 0 {
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            // SAFETY: live file descriptor and correctly-sized output storage.
            if unsafe { libc::fstatvfs(self.file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(self.refusal(2));
            }
            // SAFETY: fstatvfs succeeded and initialized the storage.
            let stat = unsafe { stat.assume_init() };
            let available = (stat.f_bavail as u128)
                .checked_mul(stat.f_frsize as u128)
                .ok_or_else(|| self.refusal(2))?;
            check_reserve(available, self.reserve, n).map_err(|_| self.refusal(2))?;
        }
        if let Some(lease) = &self.lease {
            lease.charge(n).map_err(|_| self.refusal(1))?;
        }
        match self.file.write(buf) {
            Ok(written) => {
                if let Some(lease) = &self.lease {
                    lease.refund(n - written as u64);
                }
                self.written += written as u64;
                Ok(written)
            }
            Err(error) => {
                if let Some(lease) = &self.lease {
                    lease.refund(n);
                }
                Err(error)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn check_reserve(available: u128, reserve: u64, write: u64) -> io::Result<()> {
    if available < u128::from(reserve) + u128::from(write) {
        return Err(io::Error::other("DISK_RESERVE_LOW"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    fn file() -> File {
        let path = std::env::temp_dir().join(format!("budget-{}", uuid::Uuid::new_v4()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        fs::remove_file(path).unwrap();
        file
    }
    #[test]
    fn exact_file_and_shared_limits_refuse_whole_buffer_and_release_leases() {
        let budget = Budget::new(5);
        let lease = budget.lease();
        let mut a = ResourceWriter::new(file(), 3, 0, Some(lease.clone()));
        let mut b = ResourceWriter::new(file(), 9, 0, Some(lease.clone()));
        a.write_all(b"abc").unwrap();
        assert_eq!(a.write(b"d").unwrap_err().to_string(), "RESOURCE_LIMIT");
        b.write_all(b"de").unwrap();
        assert_eq!(b.write(b"f").unwrap_err().to_string(), "RESOURCE_LIMIT");
        assert_eq!(a.file.metadata().unwrap().len(), 3);
        assert_eq!(b.file.metadata().unwrap().len(), 2);
        assert_eq!(budget.used.load(Ordering::SeqCst), 5);
        drop(a);
        drop(b);
        drop(lease);
        assert_eq!(budget.used.load(Ordering::SeqCst), 0);
        let held = budget.lease();
        held.charge(5).unwrap();
        assert!(budget.lease().charge(1).is_err());
        held.keep_charge();
        drop(held);
        assert_eq!(budget.used.load(Ordering::SeqCst), 5);
    }
    #[test]
    fn encrypted_headers_preserve_generated_resource_codes() {
        let keydir = crate::fixture::temp_keys();
        let (_, recipient) = crate::fixture::key_pair(&keydir);
        let recipient = backup_crypto::keystore::KeyFile::load(
            &recipient,
            backup_crypto::keystore::KeyRole::Recipient,
        )
        .unwrap();
        for (stage_limit, reserve, code) in [
            (1, 0, "RESOURCE_LIMIT"),
            (u64::MAX, u64::MAX, "DISK_RESERVE_LOW"),
        ] {
            let writer = ResourceWriter::new(
                file(),
                u64::MAX,
                reserve,
                Some(Budget::new(stage_limit).lease()),
            );
            let error = writer.encrypt(recipient.recipient()).err().unwrap();
            assert!(
                error.chain().any(|cause| cause.to_string() == code),
                "{error:#}"
            );
        }
        fs::remove_dir_all(keydir).unwrap();
    }
    #[test]
    fn failed_write_refunds_and_reserve_checks_do_not_overflow() {
        let budget = Budget::new(3);
        let mut w =
            ResourceWriter::new(File::open("/dev/null").unwrap(), 3, 0, Some(budget.lease()));
        assert!(w.write(b"abc").is_err());
        assert_eq!(budget.used.load(Ordering::SeqCst), 0);
        assert_eq!(w.written, 0);
        assert!(check_reserve(15, 10, 5).is_ok());
        assert!(check_reserve(14, 10, 5).is_err());
        assert!(check_reserve(u64::MAX as u128, u64::MAX, 1).is_err());
        assert!(check_reserve(u128::MAX, u64::MAX, u64::MAX).is_ok());
        let mut w = ResourceWriter::new(file(), 10, u64::MAX, None);
        assert_eq!(w.write(b"a").unwrap_err().to_string(), "DISK_RESERVE_LOW");
        assert_eq!(w.file.metadata().unwrap().len(), 0);
    }
}
