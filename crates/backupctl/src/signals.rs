//! Handlers request cancellation; ordinary Rust control flow owns cleanup.
use anyhow::{Context, Result};
extern "C" fn cancel(_: libc::c_int) {
    backup_application::control::request_cancel();
}
pub(crate) fn install() -> Result<()> {
    // SAFETY: sigaction is initialized, the handler only stores a lock-free atomic,
    // and this single-invocation CLI owns SIGINT/SIGTERM until process exit.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = cancel as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error()).context("SIGNAL_SETUP_FAILED");
            }
        }
    }
    Ok(())
}
