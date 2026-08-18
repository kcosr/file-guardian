use super::sandbox::{
    compile_pi_process_command, PiProcessCommand, PiProcessInvocation, PiSandboxError,
    PreparedPiRuntime,
};
use std::ffi::OsString;
#[cfg(unix)]
use std::os::fd::{BorrowedFd, RawFd};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

#[derive(Clone, Debug)]
pub(crate) struct PiRunLimits {
    pub startup_timeout: Duration,
    pub idle_timeout: Duration,
    pub wall_timeout: Duration,
    pub termination_grace: Duration,
    pub memory_bytes: u64,
    pub cpu_seconds: u64,
    pub open_files: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

impl PiRunLimits {
    fn valid(&self) -> bool {
        !self.startup_timeout.is_zero()
            && !self.idle_timeout.is_zero()
            && !self.wall_timeout.is_zero()
            && !self.termination_grace.is_zero()
            && self.memory_bytes > 0
            && self.cpu_seconds > 0
            && self.open_files > 0
            && self.stdout_bytes > 0
            && self.stderr_bytes > 0
            && self.startup_timeout <= self.wall_timeout
            && self.idle_timeout <= self.wall_timeout
    }
}

pub(crate) struct PiRunSignals {
    /// The proxy sends this only after validating Pi's runtime handshake.
    pub runtime_ready: oneshot::Receiver<()>,
    /// The proxy increments this for every accepted protocol operation.
    pub activity: watch::Receiver<u64>,
}

pub(crate) struct PiInvocationSpec<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub thinking: &'a str,
    pub proxy_socket_path: &'a Path,
    pub proxy_directory_fd: std::os::fd::RawFd,
    pub analyzer_input_view: &'a Path,
    pub max_search_results: u64,
    pub proxy_token: &'a str,
    pub analyzer_id: &'a str,
    pub run_id: &'a str,
    pub manifest_identity: &'a str,
    pub credential_environment: &'a [(OsString, OsString)],
    pub fixed_task: &'a [u8],
    pub limits: PiRunLimits,
    pub signals: PiRunSignals,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PiTimeoutKind {
    Startup,
    Idle,
    Wall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PiOutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum PiRunError {
    #[error(transparent)]
    Runtime(#[from] PiSandboxError),
    #[error("Pi process could not be started")]
    Spawn,
    #[error("Pi runtime handshake failed")]
    RuntimeHandshake,
    #[error("Pi process exceeded its {0:?} time budget")]
    Timeout(PiTimeoutKind),
    #[error("Pi process exceeded its {0:?} output budget")]
    OutputLimit(PiOutputStream),
    #[error("Pi process exited unsuccessfully")]
    NonZeroExit,
    #[error("Pi process supervision failed")]
    Supervision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PiRunOutcome {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct PiRunner {
    runtime: PreparedPiRuntime,
}

impl PiRunner {
    pub(crate) fn new(runtime: PreparedPiRuntime) -> Self {
        Self { runtime }
    }

    pub(crate) async fn run(
        &self,
        invocation: PiInvocationSpec<'_>,
    ) -> Result<PiRunOutcome, PiRunError> {
        if !invocation.limits.valid() || invocation.fixed_task.is_empty() {
            return Err(PiRunError::Supervision);
        }
        self.runtime.verify_bubblewrap_version().await?;
        let command = compile_pi_process_command(
            &self.runtime,
            &PiProcessInvocation {
                provider: invocation.provider,
                model: invocation.model,
                thinking: invocation.thinking,
                proxy_socket_path: invocation.proxy_socket_path,
                proxy_directory_fd: invocation.proxy_directory_fd,
                analyzer_input_view: invocation.analyzer_input_view,
                max_search_results: invocation.max_search_results,
                proxy_token: invocation.proxy_token,
                analyzer_id: invocation.analyzer_id,
                run_id: invocation.run_id,
                manifest_identity: invocation.manifest_identity,
                credential_environment: invocation.credential_environment,
            },
        )?;
        self.runtime.revalidate()?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let mut supervisor = tokio::spawn(run_command(
            command,
            invocation.fixed_task.to_vec(),
            invocation.limits,
            invocation.signals,
            cancel_rx,
        ));
        let mut cancellation = SupervisorCancellation::new(cancel_tx);
        let result = (&mut supervisor)
            .await
            .map_err(|_| PiRunError::Supervision)?;
        cancellation.disarm();
        result
    }
}

#[derive(Clone, Copy, Debug)]
struct StreamResult {
    stream: PiOutputStream,
    bytes: u64,
    exceeded: bool,
    failed: bool,
}

async fn run_command(
    plan: PiProcessCommand,
    fixed_task: Vec<u8>,
    limits: PiRunLimits,
    mut signals: PiRunSignals,
    mut cancellation: oneshot::Receiver<()>,
) -> Result<PiRunOutcome, PiRunError> {
    let started = Instant::now();
    let mut command = Command::new(&plan.program);
    command
        .args(&plan.arguments)
        .env_clear()
        .envs(plan.environment.iter().cloned())
        .current_dir(&plan.current_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        command.process_group(0);
        let child_limits = limits.clone();
        let inherited_proxy_fd = plan.inherited_proxy_fd;
        // SAFETY: the pre-exec closure only invokes setrlimit and umask syscalls.
        unsafe {
            command
                .as_std_mut()
                .pre_exec(move || install_child_limits(&child_limits, inherited_proxy_fd));
        }
    }
    let mut child = command.spawn().map_err(|_| PiRunError::Spawn)?;
    let raw_pid = child.id().ok_or(PiRunError::Spawn)?;
    let mut group_guard = ProcessGroupGuard::new(raw_pid);

    let stdout = match child.stdout.take() {
        Some(value) => value,
        None => {
            terminate_and_reap(
                &mut child,
                raw_pid,
                limits.termination_grace,
                &mut group_guard,
            )
            .await;
            return Err(PiRunError::Supervision);
        }
    };
    let stderr = match child.stderr.take() {
        Some(value) => value,
        None => {
            terminate_and_reap(
                &mut child,
                raw_pid,
                limits.termination_grace,
                &mut group_guard,
            )
            .await;
            return Err(PiRunError::Supervision);
        }
    };
    let (overflow_tx, mut overflow_rx) = mpsc::channel(2);
    let _overflow_guard = overflow_tx.clone();
    let stdout_task = drain_stream(
        stdout,
        PiOutputStream::Stdout,
        limits.stdout_bytes,
        overflow_tx.clone(),
    );
    let stderr_task = drain_stream(
        stderr,
        PiOutputStream::Stderr,
        limits.stderr_bytes,
        overflow_tx,
    );
    let mut stdin = match child.stdin.take() {
        Some(value) => value,
        None => {
            terminate_and_reap(
                &mut child,
                raw_pid,
                limits.termination_grace,
                &mut group_guard,
            )
            .await;
            return finish_tasks(stdout_task, stderr_task, Err(PiRunError::Supervision)).await;
        }
    };
    let stdin_result = timeout(limits.startup_timeout, async {
        stdin.write_all(&fixed_task).await?;
        stdin.shutdown().await
    })
    .await;
    if stdin_result.is_err() {
        terminate_and_reap(
            &mut child,
            raw_pid,
            limits.termination_grace,
            &mut group_guard,
        )
        .await;
        return finish_tasks(
            stdout_task,
            stderr_task,
            Err(PiRunError::Timeout(PiTimeoutKind::Startup)),
        )
        .await;
    }
    if matches!(stdin_result, Ok(Err(_))) {
        let remaining = limits.startup_timeout.saturating_sub(started.elapsed());
        let status = timeout(remaining, child.wait()).await;
        let error = match status {
            Ok(Ok(status)) => {
                kill_group(raw_pid, rustix::process::Signal::KILL);
                group_guard.disarm();
                if status.success() {
                    PiRunError::Supervision
                } else {
                    PiRunError::NonZeroExit
                }
            }
            Ok(Err(_)) | Err(_) => {
                terminate_and_reap(
                    &mut child,
                    raw_pid,
                    limits.termination_grace,
                    &mut group_guard,
                )
                .await;
                PiRunError::Supervision
            }
        };
        return finish_tasks(stdout_task, stderr_task, Err(error)).await;
    }
    drop(stdin);

    let startup_remaining = limits.startup_timeout.saturating_sub(started.elapsed());
    let ready = tokio::select! {
        result = &mut signals.runtime_ready => result.map(|()| true).map_err(|_| PiRunError::RuntimeHandshake),
        result = child.wait() => {
            let error = match result { Ok(status) if !status.success() => PiRunError::NonZeroExit, _ => PiRunError::RuntimeHandshake };
            kill_group(raw_pid, rustix::process::Signal::KILL);
            group_guard.disarm();
            return finish_tasks(stdout_task, stderr_task, Err(error)).await;
        }
        _ = &mut cancellation => {
            terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
            return finish_tasks(stdout_task, stderr_task, Err(PiRunError::Supervision)).await;
        }
        overflow = overflow_rx.recv() => {
            terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
            let error = overflow.map_or(PiRunError::Supervision, PiRunError::OutputLimit);
            return finish_tasks(stdout_task, stderr_task, Err(error)).await;
        }
        _ = sleep(startup_remaining) => Ok(false),
    };
    let ready = match ready {
        Ok(ready) => ready,
        Err(error) => {
            terminate_and_reap(
                &mut child,
                raw_pid,
                limits.termination_grace,
                &mut group_guard,
            )
            .await;
            return finish_tasks(stdout_task, stderr_task, Err(error)).await;
        }
    };
    if !ready {
        terminate_and_reap(
            &mut child,
            raw_pid,
            limits.termination_grace,
            &mut group_guard,
        )
        .await;
        return finish_tasks(
            stdout_task,
            stderr_task,
            Err(PiRunError::Timeout(PiTimeoutKind::Startup)),
        )
        .await;
    }

    let wall_deadline = started + limits.wall_timeout;
    let mut idle_deadline = Instant::now() + limits.idle_timeout;
    let status = loop {
        tokio::select! {
            result = child.wait() => match result {
                Ok(status) => break status,
                Err(_) => {
                    terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
                    return finish_tasks(stdout_task, stderr_task, Err(PiRunError::Supervision)).await;
                }
            },
            _ = &mut cancellation => {
                terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
                return finish_tasks(stdout_task, stderr_task, Err(PiRunError::Supervision)).await;
            }
            overflow = overflow_rx.recv() => {
                terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
                let error = overflow.map_or(PiRunError::Supervision, PiRunError::OutputLimit);
                return finish_tasks(stdout_task, stderr_task, Err(error)).await;
            }
            changed = signals.activity.changed() => {
                if changed.is_err() {
                    terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
                    return finish_tasks(stdout_task, stderr_task, Err(PiRunError::RuntimeHandshake)).await;
                }
                idle_deadline = Instant::now() + limits.idle_timeout;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
                return finish_tasks(stdout_task, stderr_task, Err(PiRunError::Timeout(PiTimeoutKind::Idle))).await;
            }
            _ = tokio::time::sleep_until(wall_deadline) => {
                terminate_and_reap(&mut child, raw_pid, limits.termination_grace, &mut group_guard).await;
                return finish_tasks(stdout_task, stderr_task, Err(PiRunError::Timeout(PiTimeoutKind::Wall))).await;
            }
        }
    };

    // A completed main process may have descendants holding inherited pipes. Avoid
    // signaling a now-free process-group id when both pipes already reached EOF.
    let _ = timeout(Duration::from_millis(20), async {
        while !stdout_task.is_finished() || !stderr_task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if !stdout_task.is_finished() || !stderr_task.is_finished() {
        kill_group(raw_pid, rustix::process::Signal::KILL);
    }
    group_guard.disarm();
    let result = if status.success() {
        Ok(())
    } else {
        Err(PiRunError::NonZeroExit)
    };
    finish_tasks(stdout_task, stderr_task, result).await
}

async fn finish_tasks(
    mut stdout: JoinHandle<StreamResult>,
    mut stderr: JoinHandle<StreamResult>,
    result: Result<(), PiRunError>,
) -> Result<PiRunOutcome, PiRunError> {
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
    let joined = timeout(DRAIN_TIMEOUT, async {
        let stdout = (&mut stdout).await;
        let stderr = (&mut stderr).await;
        (stdout, stderr)
    })
    .await;
    let (stdout_result, stderr_result) = match joined {
        Ok(results) => results,
        Err(_) => {
            stdout.abort();
            stderr.abort();
            let _ = stdout.await;
            let _ = stderr.await;
            return Err(PiRunError::Supervision);
        }
    };
    let stdout = stdout_result.map_err(|_| PiRunError::Supervision)?;
    let stderr = stderr_result.map_err(|_| PiRunError::Supervision)?;
    if stdout.exceeded {
        return Err(PiRunError::OutputLimit(stdout.stream));
    }
    if stderr.exceeded {
        return Err(PiRunError::OutputLimit(stderr.stream));
    }
    if stdout.failed || stderr.failed {
        return Err(PiRunError::Supervision);
    }
    result?;
    Ok(PiRunOutcome {
        stdout_bytes: stdout.bytes,
        stderr_bytes: stderr.bytes,
    })
}

fn drain_stream(
    mut input: impl AsyncRead + Unpin + Send + 'static,
    stream: PiOutputStream,
    limit: u64,
    overflow: mpsc::Sender<PiOutputStream>,
) -> JoinHandle<StreamResult> {
    tokio::spawn(async move {
        let mut bytes = 0_u64;
        let mut exceeded = false;
        let mut failed = false;
        let mut buffer = [0_u8; 8192];
        loop {
            match input.read(&mut buffer).await {
                Ok(0) => break,
                Err(_) => {
                    failed = true;
                    break;
                }
                Ok(count) => {
                    bytes = bytes.saturating_add(count as u64);
                    if bytes > limit && !exceeded {
                        exceeded = true;
                        let _ = overflow.send(stream).await;
                    }
                }
            }
        }
        StreamResult {
            stream,
            bytes: bytes.min(limit.saturating_add(1)),
            exceeded,
            failed,
        }
    })
}

async fn terminate_and_reap(
    child: &mut Child,
    raw_pid: u32,
    grace: Duration,
    group_guard: &mut ProcessGroupGuard,
) {
    kill_group(raw_pid, rustix::process::Signal::TERM);
    if timeout(grace, child.wait()).await.is_err() {
        kill_group(raw_pid, rustix::process::Signal::KILL);
        let _ = child.wait().await;
    }
    // Kill descendants which outlived the group leader or ignored TERM.
    kill_group(raw_pid, rustix::process::Signal::KILL);
    group_guard.disarm();
}

fn kill_group(raw_pid: u32, signal: rustix::process::Signal) {
    if let Some(pid) = rustix::process::Pid::from_raw(raw_pid as i32) {
        let _ = rustix::process::kill_process_group(pid, signal);
    }
}

#[cfg(unix)]
fn install_child_limits(limits: &PiRunLimits, inherited_proxy_fd: RawFd) -> std::io::Result<()> {
    for (resource, value) in [
        (rustix::process::Resource::As, limits.memory_bytes),
        (rustix::process::Resource::Cpu, limits.cpu_seconds),
        (rustix::process::Resource::Nofile, limits.open_files),
        (rustix::process::Resource::Core, 0),
    ] {
        rustix::process::setrlimit(
            resource,
            rustix::process::Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )?;
    }
    // RLIMIT_NPROC is deliberately not lowered. Linux accounts it across all
    // processes and threads owned by the real UID, not this invocation, so it
    // cannot provide a deterministic per-Pi or per-sidecar isolation limit.
    // SAFETY: the descriptor is held by the invocation proxy for the complete
    // child lifetime and is only borrowed across this syscall.
    let proxy_fd = unsafe { BorrowedFd::borrow_raw(inherited_proxy_fd) };
    rustix::io::fcntl_setfd(proxy_fd, rustix::io::FdFlags::empty())?;
    rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    Ok(())
}

struct ProcessGroupGuard {
    raw_pid: u32,
    armed: bool,
}

struct SupervisorCancellation {
    cancel: Option<oneshot::Sender<()>>,
    armed: bool,
}

impl SupervisorCancellation {
    fn new(cancel: oneshot::Sender<()>) -> Self {
        Self {
            cancel: Some(cancel),
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SupervisorCancellation {
    fn drop(&mut self) {
        if self.armed {
            if let Some(cancel) = self.cancel.take() {
                let _ = cancel.send(());
            }
        }
    }
}

impl ProcessGroupGuard {
    fn new(raw_pid: u32) -> Self {
        Self {
            raw_pid,
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            kill_group(self.raw_pid, rustix::process::Signal::KILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fake_command(script: &Path) -> PiProcessCommand {
        PiProcessCommand {
            program: script.to_owned(),
            arguments: Vec::new(),
            environment: Vec::new(),
            current_directory: script.parent().unwrap().to_owned(),
            inherited_proxy_fd: 0,
        }
    }

    #[cfg(target_os = "linux")]
    fn pid_contained_command(script: &Path) -> PiProcessCommand {
        PiProcessCommand {
            program: PathBuf::from("/usr/bin/bwrap"),
            arguments: vec![
                "--unshare-pid".into(),
                "--die-with-parent".into(),
                "--bind".into(),
                "/".into(),
                "/".into(),
                "--dev-bind".into(),
                "/dev".into(),
                "/dev".into(),
                "--chdir".into(),
                script.parent().unwrap().as_os_str().to_owned(),
                "--".into(),
                script.as_os_str().to_owned(),
            ],
            environment: vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
            current_directory: script.parent().unwrap().to_owned(),
            inherited_proxy_fd: 0,
        }
    }

    fn limits() -> PiRunLimits {
        PiRunLimits {
            startup_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            wall_timeout: Duration::from_secs(3),
            termination_grace: Duration::from_millis(50),
            memory_bytes: 256 * 1024 * 1024,
            cpu_seconds: 2,
            open_files: 64,
            stdout_bytes: 64,
            stderr_bytes: 64,
        }
    }

    fn script(body: &str) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("launcher");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, path)
    }

    fn signals() -> (PiRunSignals, oneshot::Sender<()>, watch::Sender<u64>) {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (activity_tx, activity_rx) = watch::channel(0);
        (
            PiRunSignals {
                runtime_ready: ready_rx,
                activity: activity_rx,
            },
            ready_tx,
            activity_tx,
        )
    }

    fn never_cancel() -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        std::mem::forget(sender);
        receiver
    }

    #[tokio::test]
    async fn successful_process_returns_only_byte_counts() {
        let (_dir, path) = script("read _; printf ok; printf warn >&2");
        let (run_signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let outcome = run_command(
            fake_command(&path),
            b"classify\n".to_vec(),
            limits(),
            run_signals,
            never_cancel(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            PiRunOutcome {
                stdout_bytes: 2,
                stderr_bytes: 4
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_directory_descriptor_is_inherited_through_bubblewrap() {
        let directory = tempfile::tempdir().unwrap();
        let _listener = UnixListener::bind(directory.path().join("proxy.sock")).unwrap();
        let directory_fd = std::fs::File::open(directory.path()).unwrap();
        let (_script_dir, path) =
            script("read _; test -S \"/proc/self/fd/${PROXY_FD}/proxy.sock\" || exit 9");
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let mut plan = pid_contained_command(&path);
        plan.environment.push((
            OsString::from("PROXY_FD"),
            OsString::from(directory_fd.as_raw_fd().to_string()),
        ));
        plan.inherited_proxy_fd = directory_fd.as_raw_fd();
        assert!(run_command(
            plan,
            b"classify\n".to_vec(),
            limits(),
            signals,
            never_cancel(),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn nonzero_exit_is_safe_typed_failure() {
        let (_dir, path) = script("read _; printf secret >&2; exit 7");
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        assert_eq!(
            run_command(
                fake_command(&path),
                b"classify\n".to_vec(),
                limits(),
                signals,
                never_cancel(),
            )
            .await,
            Err(PiRunError::NonZeroExit)
        );
    }

    #[tokio::test]
    async fn independently_bounds_both_output_streams() {
        for body in ["read _; yes x", "read _; yes x >&2"] {
            let (_dir, path) = script(body);
            let (signals, ready, _activity) = signals();
            ready.send(()).unwrap();
            let error = run_command(
                fake_command(&path),
                b"classify\n".to_vec(),
                limits(),
                signals,
                never_cancel(),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, PiRunError::OutputLimit(_)));
        }
    }

    #[tokio::test]
    async fn startup_and_idle_timeouts_kill_process_group() {
        let (_dir, path) = script("trap '' TERM; while :; do :; done");
        let mut short = limits();
        short.startup_timeout = Duration::from_millis(30);
        let (startup_signals, _ready, _activity) = signals();
        assert_eq!(
            run_command(
                fake_command(&path),
                b"classify\n".to_vec(),
                short,
                startup_signals,
                never_cancel(),
            )
            .await,
            Err(PiRunError::Timeout(PiTimeoutKind::Startup))
        );

        let (_dir, path) = script("trap '' TERM; while :; do :; done");
        let mut short = limits();
        short.idle_timeout = Duration::from_millis(30);
        let (idle_signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        assert_eq!(
            run_command(
                fake_command(&path),
                b"classify\n".to_vec(),
                short,
                idle_signals,
                never_cancel(),
            )
            .await,
            Err(PiRunError::Timeout(PiTimeoutKind::Idle))
        );
    }

    #[tokio::test]
    async fn closed_runtime_ready_channel_is_a_handshake_failure() {
        let (_dir, path) = script("trap '' TERM; while :; do :; done");
        let (run_signals, ready, _activity) = signals();
        drop(ready);
        assert_eq!(
            run_command(
                fake_command(&path),
                b"classify\n".to_vec(),
                limits(),
                run_signals,
                never_cancel(),
            )
            .await,
            Err(PiRunError::RuntimeHandshake)
        );
    }

    #[tokio::test]
    async fn descendant_pipe_holder_is_killed_and_reaped() {
        let (_dir, path) = script("read _; (trap '' TERM; while :; do sleep 1; done) & exit 0");
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let result = timeout(
            Duration::from_secs(1),
            run_command(
                fake_command(&path),
                b"classify\n".to_vec(),
                limits(),
                signals,
                never_cancel(),
            ),
        )
        .await;
        assert!(
            result.is_ok(),
            "descendant inherited pipe must not stall completion"
        );
        assert!(matches!(
            result.unwrap(),
            Ok(_) | Err(PiRunError::Supervision)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pid_namespace_destroys_setsid_descendant_after_success() {
        let dir = tempfile::tempdir().unwrap();
        let started = dir.path().join("started");
        let survived = dir.path().join("survived");
        let path = dir.path().join("launcher");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nread _\nsetsid sh -c 'touch {}; sleep 0.2; touch {}' &\nwhile test ! -f {}; do :; done\nexit 0\n",
                started.display(),
                survived.display(),
                started.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let result = timeout(
            Duration::from_secs(2),
            run_command(
                pid_contained_command(&path),
                b"classify\n".to_vec(),
                limits(),
                signals,
                never_cancel(),
            ),
        )
        .await;
        assert!(result.unwrap().is_ok());
        assert!(started.exists(), "the escaped descendant must have started");
        sleep(Duration::from_millis(400)).await;
        assert!(
            !survived.exists(),
            "the escaped descendant survived successful Pi completion"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pid_namespace_destroys_setsid_descendant_after_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let started = dir.path().join("started");
        let survived = dir.path().join("survived");
        let path = dir.path().join("launcher");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nread _\nsetsid sh -c 'touch {}; sleep 0.2; touch {}' &\nwhile test ! -f {}; do :; done\nwhile :; do :; done\n",
                started.display(),
                survived.display(),
                started.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let mut short = limits();
        short.idle_timeout = Duration::from_millis(30);
        assert_eq!(
            run_command(
                pid_contained_command(&path),
                b"classify\n".to_vec(),
                short,
                signals,
                never_cancel(),
            )
            .await,
            Err(PiRunError::Timeout(PiTimeoutKind::Idle))
        );
        assert!(started.exists(), "the escaped descendant must have started");
        sleep(Duration::from_millis(400)).await;
        assert!(
            !survived.exists(),
            "the escaped descendant survived Pi timeout"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pid_namespace_destroys_setsid_descendant_after_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let started = dir.path().join("started");
        let survived = dir.path().join("survived");
        let path = dir.path().join("launcher");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nread _\nsetsid sh -c 'touch {}; sleep 0.2; touch {}' &\nwhile test ! -f {}; do :; done\nwhile :; do :; done\n",
                started.display(),
                survived.display(),
                started.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let (cancel, cancelled) = oneshot::channel();
        let supervisor = tokio::spawn(run_command(
            pid_contained_command(&path),
            b"classify\n".to_vec(),
            limits(),
            signals,
            cancelled,
        ));
        timeout(Duration::from_secs(1), async {
            while !started.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancel.send(()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), supervisor)
                .await
                .unwrap()
                .unwrap(),
            Err(PiRunError::Supervision)
        );
        sleep(Duration::from_millis(400)).await;
        assert!(
            !survived.exists(),
            "the escaped descendant survived Pi cancellation"
        );
    }

    #[tokio::test]
    async fn cancellation_signal_keeps_supervisor_alive_through_reap() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let path = dir.path().join("launcher");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s' $$ > {}\ntrap '' TERM\nwhile :; do :; done\n",
                pid_file.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (signals, ready, _activity) = signals();
        ready.send(()).unwrap();
        let (cancel, cancelled) = oneshot::channel();
        let supervisor = tokio::spawn(run_command(
            fake_command(&path),
            b"classify\n".to_vec(),
            limits(),
            signals,
            cancelled,
        ));
        let raw_pid: i32 = timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(value) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = value.parse() {
                        break pid;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancel.send(()).unwrap();
        let result = timeout(Duration::from_secs(1), supervisor).await;
        assert!(
            result.is_ok(),
            "cancelled supervisor must terminate and reap"
        );
        assert_eq!(result.unwrap().unwrap(), Err(PiRunError::Supervision));
        let pid = rustix::process::Pid::from_raw(raw_pid).unwrap();
        assert!(
            matches!(
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG),
                Err(rustix::io::Errno::CHILD)
            ),
            "supervisor must reap rather than leave a zombie",
        );
    }
}
