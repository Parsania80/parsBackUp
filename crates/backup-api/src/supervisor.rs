//! One supervised child owns each core invocation, including its sticky cancellation.
use crate::{Actor, Config, Intent, Job, Request, State, control::Store, model::*};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::{Instant, sleep, timeout},
};
use uuid::Uuid;

const POLL: Duration = Duration::from_millis(100);
const CANCEL_GRACE: Duration = Duration::from_secs(25);

// Failed ownership checks stop the unit. Returning to the HTTP loop would allow
// a second worker while descendants of the previous one could still be active.
fn fail_stop() -> ! {
    eprintln!("BACKUP_API_CONTAINMENT_LOST");
    std::process::exit(1);
}

struct Group {
    name: String,
    directory: PathBuf,
}

impl Group {
    async fn detect() -> Result<Self> {
        let contents = fs::read_to_string("/proc/self/cgroup")?;
        let name = contents
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .context(ErrorCode::ContainmentUnavailable)?;
        let unit = name
            .rsplit('/')
            .next()
            .filter(|name| name.ends_with(".service") && !name.starts_with('-'))
            .context(ErrorCode::ContainmentUnavailable)?;
        ensure!(
            name.split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
            ErrorCode::ContainmentUnavailable
        );
        let mut command = Command::new("/usr/bin/systemctl");
        if name.starts_with("user.slice/")
            && name
                .split('/')
                .any(|part| part.starts_with("user@") && part.ends_with(".service"))
        {
            command.arg("--user");
        }
        let output = timeout(Duration::from_secs(3), command.args([
            "show", "--property=MainPID,ControlGroup,KillMode,KillSignal,FinalKillSignal,SendSIGKILL,TimeoutStopUSec,Delegate",
            "--", unit,
        ]).kill_on_drop(true).stdin(Stdio::null()).stderr(Stdio::null()).output()).await??;
        let properties = std::str::from_utf8(&output.stdout)?;
        let pid = format!("MainPID={}", std::process::id());
        let path = format!("ControlGroup=/{name}");
        ensure!(
            output.status.success()
                && [
                    pid.as_str(),
                    path.as_str(),
                    "KillMode=mixed",
                    "KillSignal=15",
                    "FinalKillSignal=9",
                    "SendSIGKILL=yes",
                    "TimeoutStopUSec=30s",
                    "Delegate=no",
                ]
                .iter()
                .all(|required| properties.lines().any(|line| line == *required)),
            ErrorCode::ContainmentUnavailable
        );
        let group = Self {
            directory: Path::new("/sys/fs/cgroup").join(name),
            name: name.to_owned(),
        };
        ensure!(group.alone()?, ErrorCode::ContainmentUnavailable);
        Ok(group)
    }

    fn alone(&self) -> Result<bool> {
        let pids = fs::read_to_string(self.directory.join("cgroup.procs"))?;
        let members = pids
            .lines()
            .map(str::parse::<u32>)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let children = fs::read_to_string(self.directory.join("cgroup.stat"))?;
        Ok(members == BTreeSet::from([std::process::id()])
            && children.lines().any(|line| line == "nr_descendants 0"))
    }
}

struct Shared {
    config: Config,
    store: Mutex<Store>,
    supervised: bool,
    accepting: AtomicBool,
}

/// Interface for the HTTP adapter. Callers supply identities already
/// authenticated by the transport. Registry permissions are rechecked here.
#[derive(Clone)]
pub struct Control(Arc<Shared>);

impl Control {
    fn open(config: Config, group: Option<&str>) -> Result<Self> {
        let store = Store::open(&config.database, group)?;
        Ok(Self(Arc::new(Shared {
            config,
            store: Mutex::new(store),
            supervised: group.is_some(),
            accepting: AtomicBool::new(group.is_some()),
        })))
    }

    pub(crate) fn read_only(config: Config) -> Result<Self> {
        Self::open(config, None)
    }

    pub(crate) fn config(&self) -> &Config {
        &self.0.config
    }

    pub(crate) fn supervised(&self) -> bool {
        self.0.supervised
    }

    pub(crate) fn accepting(&self) -> bool {
        self.0.accepting.load(Ordering::Acquire)
    }

    pub(crate) fn stop_admission(&self) {
        self.0.accepting.store(false, Ordering::Release);
    }

    pub(crate) fn store(&self) -> Result<MutexGuard<'_, Store>> {
        self.0
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("CONTROL_LOCK_POISONED"))
    }

    pub fn submit(&self, actor: Actor, key: Uuid, request: Request) -> Result<Job> {
        let mut store = self.store()?;
        self.check_admission()?;
        store.admit(&self.0.config, actor, key, request)
    }

    pub fn cancel(&self, actor: Actor, job: Uuid, key: Uuid) -> Result<Job> {
        let mut store = self.store()?;
        self.check_admission()?;
        store.cancel(&self.0.config, actor, job, key)
    }

    fn check_admission(&self) -> Result<()> {
        ensure!(self.supervised(), ErrorCode::ContainmentUnavailable);
        ensure!(self.accepting(), ErrorCode::NotReady);
        Ok(())
    }

    pub fn job(&self, actor: Actor, id: Uuid) -> Result<Job> {
        let authority = self.0.config.authorize(actor, None)?;
        let job = self.store()?.job(id)?;
        ensure!(
            (job.actor_id == actor.actor_id || authority.admin())
                && authority.allows(job.operation),
            ErrorCode::NotFound
        );
        Ok(job)
    }

    pub fn intent(&self, actor: Actor, id: Uuid) -> Result<Intent> {
        let authority = self.0.config.authorize(actor, None)?;
        let (intent, _) = self.store()?.intent(id)?;
        let permission = match intent.bound.kind {
            IntentKind::Restore => Operation::RestorePlan,
            IntentKind::Retention => Operation::RetentionPreview,
        };
        ensure!(
            (intent.bound.actor_id == actor.actor_id || authority.admin())
                && authority.allows(permission),
            ErrorCode::NotFound
        );
        Ok(intent)
    }
}

/// Exclusive dispatcher for one service cgroup and control database.
pub struct Supervisor {
    control: Control,
    group: Group,
    executable: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    job_id: Uuid,
    supervisor_pid: u32,
    config_hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    job_id: Uuid,
    outcome: Outcome,
}

// Dropping the dispatcher future during an active job is also a fail-stop. The
// Tokio child handle alone cannot establish descendant containment.
struct Active;
impl Drop for Active {
    fn drop(&mut self) {
        fail_stop();
    }
}

impl Supervisor {
    pub async fn open(config: Config, executable: PathBuf) -> Result<Self> {
        let group = Group::detect()
            .await
            .context(ErrorCode::ContainmentUnavailable)?;
        ensure!(executable.is_absolute(), "WORKER_EXECUTABLE_INVALID");
        let control = Control::open(config, Some(&group.name))?;
        Ok(Self {
            control,
            group,
            executable,
        })
    }

    pub fn control(&self) -> Control {
        self.control.clone()
    }

    /// Drive the dispatcher until SIGTERM/SIGINT. P03 drives this same dispatcher
    /// alongside its listener and uses Control on a blocking lane.
    pub async fn serve(&mut self) -> Result<()> {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let stop = async {
            tokio::select! { _ = term.recv() => {}, _ = interrupt.recv() => {} }
            self.control.stop_admission();
        };
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                _ = stop.as_mut() => return Ok(()),
                _ = std::future::ready(()) => {},
            }
            if let Some(id) = self.claim()? {
                let mut shutting_down = false;
                let run = self.run_claimed(id, &mut shutting_down, stop.as_mut());
                if run.await? {
                    return Ok(());
                }
            } else {
                tokio::select! {
                    _ = stop.as_mut() => return Ok(()),
                    _ = sleep(POLL) => {},
                }
            }
        }
    }

    /// Dispatch the oldest accepted request, if any. A transport may schedule
    /// this independently of its request handling. Drop only while idle.
    pub async fn run_next(&mut self) -> Result<bool> {
        let Some(id) = self.claim()? else {
            return Ok(false);
        };
        self.run_claimed(id, &mut false, std::future::pending())
            .await?;
        Ok(true)
    }

    fn claim(&self) -> Result<Option<Uuid>> {
        if !self.group.alone().unwrap_or(false) {
            fail_stop();
        }
        self.control.store()?.claim()
    }

    async fn run_claimed(
        &self,
        id: Uuid,
        stopping: &mut bool,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<bool> {
        let mut command = Command::new(&self.executable);
        let child = command
            .arg("--worker")
            .arg(&self.control.0.config.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let interrupted = || {
            Outcome::error(
                State::Interrupted,
                ErrorCode::OperationInterrupted,
                Effects::Unknown,
            )
        };
        let Ok(mut child) = child else {
            self.control.store()?.finish(id, interrupted())?;
            return Ok(false);
        };
        let active = Active;
        let pid = child.id().context("WORKER_PID_MISSING")?;
        let mut stdin = child.stdin.take().context("WORKER_STDIN_MISSING")?;
        let mut stdout = child
            .stdout
            .take()
            .context("WORKER_STDOUT_MISSING")?
            .take((IPC_LIMIT + 1) as u64);
        let permitted = self.control.store()?.bind_worker(id, pid)?;
        if permitted {
            let permit = Permit {
                job_id: id,
                supervisor_pid: std::process::id(),
                config_hash: self.control.0.config.source_hash.clone(),
            };
            let bytes = serde_json::to_vec(&permit)?;
            let _ = timeout(Duration::from_secs(2), stdin.write_all(&bytes)).await;
        }
        drop(stdin);
        let mut bytes = Vec::new();
        let read = stdout.read_to_end(&mut bytes);
        tokio::pin!(read, stop);
        let mut read_done = false;
        let mut exit: Option<ExitStatus> = None;
        let mut deadline = None;
        let mut drain_deadline = None;
        let mut shutdown_bound = false;
        loop {
            if let Some(status) = child.try_wait()? {
                exit = Some(status);
                drain_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(1));
            }
            if (exit.is_some() && read_done)
                || drain_deadline.is_some_and(|limit| Instant::now() >= limit)
            {
                break;
            }
            let state = self.control.store()?.job(id)?.state;
            if exit.is_none()
                && deadline.is_none()
                && (state == State::CancelRequested || *stopping)
            {
                // SAFETY: this direct child has not been reaped and still owns its PID.
                let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                    fail_stop();
                }
                deadline = Some(Instant::now() + CANCEL_GRACE);
            }
            if exit.is_none() && deadline.is_some_and(|limit| Instant::now() >= limit) {
                fail_stop();
            }
            tokio::select! {
                _ = sleep(POLL) => {},
                result = &mut read, if !read_done => { result?; read_done = true; },
                _ = &mut stop, if !shutdown_bound => {
                    *stopping = true;
                    shutdown_bound = true;
                    self.control.store()?.shutdown_cancel(id)?;
                },
            }
        }
        if !self.group.alone().unwrap_or(false) {
            fail_stop();
        }
        std::mem::forget(active);
        let outcome = if !permitted {
            Outcome::error(
                State::Cancelled,
                ErrorCode::OperationCancelled,
                Effects::None,
            )
        } else if read_done
            && exit.is_some_and(|status| status.success())
            && bytes.len() <= IPC_LIMIT
        {
            serde_json::from_slice::<Reply>(&bytes)
                .ok()
                .filter(|reply| reply.job_id == id && reply.outcome.state.terminal())
                .map(|reply| reply.outcome)
                .unwrap_or_else(interrupted)
        } else {
            interrupted()
        };
        self.control.store()?.finish(id, outcome)?;
        Ok(*stopping)
    }
}

pub fn worker(config_path: &Path) -> Result<()> {
    install_worker_signals()?;
    let mut input = Vec::new();
    std::io::stdin().take(1025).read_to_end(&mut input)?;
    ensure!(input.len() <= 1024, "INVALID_WORKER_PERMIT");
    let permit: Permit = serde_json::from_slice(&input)?;
    // SAFETY: getppid has no preconditions.
    ensure!(
        unsafe { libc::getppid() } as u32 == permit.supervisor_pid,
        "INVALID_WORKER_PARENT"
    );
    let outcome = match Config::load(config_path) {
        Ok(config) if config.source_hash == permit.config_hash => {
            crate::operation::run(&config, permit.job_id)
        }
        _ => Outcome::error(State::Failed, ErrorCode::ConfigChanged, Effects::None),
    };
    let reply = serde_json::to_vec(&Reply {
        job_id: permit.job_id,
        outcome,
    })?;
    ensure!(reply.len() <= IPC_LIMIT, "WORKER_REPLY_LIMIT");
    std::io::stdout().lock().write_all(&reply)?;
    Ok(())
}

extern "C" fn request_stop(_: libc::c_int) {
    backup_application::control::request_cancel();
}

fn install_worker_signals() -> Result<()> {
    // SAFETY: initialized sigaction and an async-signal-safe atomic flag handler.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_stop as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    Ok(())
}
