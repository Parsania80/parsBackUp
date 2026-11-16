//! One CLI invocation's sticky, cooperative cancellation request.
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
static CANCELLED: AtomicBool = AtomicBool::new(false);

/// Signal handlers may call this: one lock-free atomic store, no allocation or I/O.
pub fn request_cancel() {
    CANCELLED.store(true, Ordering::Relaxed);
}
pub fn is_cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}
pub fn check() -> io::Result<()> {
    if is_cancelled() {
        Err(io::Error::other("OPERATION_CANCELLED"))
    } else {
        Ok(())
    }
}
pub struct Reader<R>(pub R);
impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        check()?;
        self.0.read(buf)
    }
}

/// Safe facts attached by the service that owns the actual job; no inferred history.
#[derive(Debug)]
pub struct ExecutionFailure {
    pub job_id: Option<uuid::Uuid>,
    pub artifact_id: uuid::Uuid,
    pub effects: &'static str,
}
impl std::fmt::Display for ExecutionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation failed; inspect its job and effect receipt")
    }
}
impl std::error::Error for ExecutionFailure {}
