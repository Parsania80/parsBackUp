//! Own the process group until its leader is cleaned up and reaped.
use anyhow::{Context, Result, bail};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) struct Group {
    pub(crate) child: Child,
    reaped: bool,
}
impl Group {
    pub(crate) fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }
    fn finish(&mut self) -> Result<ExitStatus> {
        // The unreaped leader pins the group ID until after this signal.
        // SAFETY: the command created its own process group with this leader ID.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let status = self
            .child
            .wait()
            .context("wait for PostgreSQL client tool")?;
        self.reaped = true;
        Ok(status)
    }
    fn exited(&self) -> Result<bool> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: valid storage; WNOWAIT observes without releasing our leader PID.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error).context("observe client exit");
        }
        // SAFETY: waitid succeeded, and initialized siginfo including si_pid.
        Ok(unsafe { info.assume_init().si_pid() } != 0)
    }
    pub(crate) fn wait(&mut self, timeout: Duration, stop: &AtomicBool) -> Result<ExitStatus> {
        let started = Instant::now();
        let result = (|| {
            loop {
                backup_application::control::check()?;
                if stop.load(Ordering::Relaxed) || self.exited()? {
                    return self.finish();
                }
                if started.elapsed() >= timeout {
                    bail!("PostgreSQL client tool timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();
        if result.is_err() {
            let _ = self.finish();
        }
        result
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish();
        }
    }
}
