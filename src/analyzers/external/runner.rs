use super::adapter::{
    FirstPartyScannerAdapter, ScannerAdapterError, ScannerVersion, ScannerVersionRequirement,
};
use super::gitleaks::GitleaksAdapter;
use super::protocol::ScannerKind;
use super::sandbox::{
    compile_confined_command, PreparedProtectedFile, PreparedScannerExecutable,
    PreparedScannerSandbox, ScannerSandboxError,
};
use super::trufflehog::TrufflehogAdapter;
use std::ffi::OsString;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::fd::{BorrowedFd, RawFd};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

const GITLEAKS_REPORT: &str = "findings.json";

#[derive(Clone, Debug)]
pub struct ScannerRunLimits {
    pub wall_timeout: Duration,
    pub termination_grace: Duration,
    pub max_output_bytes: u64,
    pub cpu_seconds: u64,
    pub open_files: u64,
}

impl ScannerRunLimits {
    fn valid(&self) -> bool {
        !self.wall_timeout.is_zero()
            && !self.termination_grace.is_zero()
            && self.max_output_bytes > 0
            && self.cpu_seconds > 0
            && self.open_files > 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScannerCancellation {
    inner: Arc<CancellationInner>,
}

#[derive(Debug, Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl ScannerCancellation {
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

pub enum FirstPartyScannerInvocation<'a> {
    Gitleaks {
        input_view: &'a Path,
        output_directory: &'a Path,
        config: &'a PreparedProtectedFile,
        ignore: &'a PreparedProtectedFile,
    },
    Trufflehog {
        input_view: &'a Path,
        output_directory: &'a Path,
    },
}

impl std::fmt::Debug for FirstPartyScannerInvocation<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Gitleaks { .. } => ScannerKind::Gitleaks,
            Self::Trufflehog { .. } => ScannerKind::Trufflehog,
        };
        formatter
            .debug_struct("FirstPartyScannerInvocation")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl FirstPartyScannerInvocation<'_> {
    fn kind(&self) -> ScannerKind {
        match self {
            Self::Gitleaks { .. } => ScannerKind::Gitleaks,
            Self::Trufflehog { .. } => ScannerKind::Trufflehog,
        }
    }

    fn paths(&self) -> (&Path, &Path) {
        match self {
            Self::Gitleaks {
                input_view,
                output_directory,
                ..
            }
            | Self::Trufflehog {
                input_view,
                output_directory,
            } => (input_view, output_directory),
        }
    }

    fn command(&self) -> (Vec<OsString>, Vec<(&PreparedProtectedFile, &'static str)>) {
        match self {
            Self::Gitleaks { config, ignore, .. } => (
                strings(&[
                    "dir",
                    "--config",
                    "/scanner-config/gitleaks.toml",
                    "--gitleaks-ignore-path",
                    "/scanner-config/gitleaks.ignore",
                    "--report-format",
                    "json",
                    "--report-path",
                    "/output/findings.json",
                    "--redact=100",
                    "--exit-code",
                    "42",
                    "--no-banner",
                    "--no-color",
                    "--log-level",
                    "error",
                    "--max-target-megabytes",
                    "0",
                    "/input",
                ]),
                vec![
                    (config, "/scanner-config/gitleaks.toml"),
                    (ignore, "/scanner-config/gitleaks.ignore"),
                ],
            ),
            Self::Trufflehog { .. } => (
                strings(&[
                    "--json",
                    "--no-update",
                    "--no-verification",
                    "--results=unverified",
                    "--fail",
                    "--fail-on-scan-errors",
                    "--no-color",
                    "filesystem",
                    "/input",
                ]),
                Vec::new(),
            ),
        }
    }
}

fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

pub struct ScannerRunOutput {
    pub kind: ScannerKind,
    pub version: ScannerVersion,
    pub exit: NativeExit,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    report: Vec<u8>,
}

impl ScannerRunOutput {
    /// Private native bytes for the in-crate first-party parser. Callers must
    /// never log, report, or project this content.
    #[doc(hidden)]
    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }
    #[doc(hidden)]
    pub(crate) fn report(&self) -> &[u8] {
        &self.report
    }
}

impl std::fmt::Debug for ScannerRunOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScannerRunOutput")
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("exit", &self.exit)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("report_bytes", &self.report.len())
            .finish()
    }
}

impl Drop for ScannerRunOutput {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
        self.report.fill(0);
    }
}

pub struct ExternalScannerRunner {
    sandbox: PreparedScannerSandbox,
}

impl ExternalScannerRunner {
    pub fn new(sandbox: PreparedScannerSandbox) -> Self {
        Self { sandbox }
    }

    pub async fn run(
        &self,
        executable: &PreparedScannerExecutable,
        version_requirement: ScannerVersionRequirement,
        invocation: FirstPartyScannerInvocation<'_>,
        limits: ScannerRunLimits,
        cancellation: ScannerCancellation,
    ) -> Result<ScannerRunOutput, ScannerRunError> {
        if !limits.valid() || executable.kind() != invocation.kind() {
            return Err(ScannerRunError::InvalidInvocation);
        }
        if cancellation.is_cancelled() {
            return Err(ScannerRunError::Cancelled);
        }
        self.verify_sandbox_version(cancellation.clone()).await?;
        verify_empty_output_directory(invocation.paths().1)?;
        let _output_guard = OutputDirectoryGuard(invocation.paths().1);
        let version = self
            .verify_scanner_version(
                executable,
                version_requirement,
                invocation.paths().0,
                invocation.paths().1,
                &limits,
                cancellation.clone(),
            )
            .await?;
        // Version preflight runs inside the same confinement. It is not
        // allowed to seed or replace the scan's host-owned output channel.
        verify_empty_output_directory(invocation.paths().1)?;
        let (native_arguments, protected_files) = invocation.command();
        let (input_view, output_directory) = invocation.paths();
        let plan = compile_confined_command(
            &self.sandbox,
            executable,
            input_view,
            output_directory,
            &native_arguments,
            &protected_files,
        )?;
        self.sandbox.revalidate()?;
        executable.revalidate()?;

        let result = run_command(plan, limits.clone(), cancellation.clone()).await?;
        if cancellation.is_cancelled() {
            return Err(ScannerRunError::Cancelled);
        }
        self.sandbox.revalidate()?;
        executable.revalidate()?;
        for (protected, _) in protected_files {
            protected.revalidate()?;
        }

        let mut output = ScannerRunOutput {
            kind: invocation.kind(),
            version,
            exit: result.exit,
            stdout: result.stdout,
            stderr: result.stderr,
            report: Vec::new(),
        };
        if invocation.kind() == ScannerKind::Gitleaks {
            let report_path = output_directory.join(GITLEAKS_REPORT);
            output.report = read_bounded_private(&report_path, limits.max_output_bytes)?;
            fs::remove_file(&report_path).map_err(|_| ScannerRunError::PrivateOutput)?;
        }
        verify_empty_output_directory(output_directory)?;
        let total_output = output
            .stdout
            .len()
            .saturating_add(output.stderr.len())
            .saturating_add(output.report.len());
        if total_output as u128 > u128::from(limits.max_output_bytes) {
            return Err(ScannerRunError::OutputLimit);
        }
        Ok(output)
    }

    async fn verify_scanner_version(
        &self,
        executable: &PreparedScannerExecutable,
        version_requirement: ScannerVersionRequirement,
        input_view: &Path,
        output_directory: &Path,
        limits: &ScannerRunLimits,
        cancellation: ScannerCancellation,
    ) -> Result<ScannerVersion, ScannerRunError> {
        let arguments = match executable.kind() {
            ScannerKind::Gitleaks => strings(&["version"]),
            ScannerKind::Trufflehog => strings(&["--version"]),
        };
        let plan = compile_confined_command(
            &self.sandbox,
            executable,
            input_view,
            output_directory,
            &arguments,
            &[],
        )?;
        let version_limits = ScannerRunLimits {
            wall_timeout: limits.wall_timeout.min(Duration::from_secs(2)),
            termination_grace: limits.termination_grace,
            max_output_bytes: limits.max_output_bytes.min(128),
            cpu_seconds: limits.cpu_seconds.min(2),
            open_files: limits.open_files,
        };
        let mut native = run_command(plan, version_limits, cancellation).await?;
        self.sandbox.revalidate()?;
        executable.revalidate()?;
        if native.exit
            != (NativeExit {
                code: Some(0),
                signal: None,
            })
            || !native.stderr.is_empty()
            || native.stdout.is_empty()
            || native.stdout.len() > 128
        {
            native.stdout.fill(0);
            native.stderr.fill(0);
            return Err(ScannerRunError::ScannerVersion);
        }
        let parsed = match executable.kind() {
            ScannerKind::Gitleaks => GitleaksAdapter::default().parse_version(&native.stdout),
            ScannerKind::Trufflehog => TrufflehogAdapter::default().parse_version(&native.stdout),
        };
        native.stdout.fill(0);
        native.stderr.fill(0);
        let version = parsed.map_err(ScannerRunError::Adapter)?;
        if !version_requirement.accepts(version) {
            return Err(ScannerRunError::ScannerVersion);
        }
        Ok(version)
    }

    async fn verify_sandbox_version(
        &self,
        cancellation: ScannerCancellation,
    ) -> Result<(), ScannerRunError> {
        self.sandbox.revalidate()?;
        let expected = self.sandbox.expected_version_line();
        let mut child = Command::new(self.sandbox.program())
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| ScannerRunError::SandboxVersion)?;
        let stdout = child.stdout.take().ok_or(ScannerRunError::SandboxVersion)?;
        let mut output_task = tokio::spawn(async move {
            let mut bytes = Vec::with_capacity(64);
            stdout
                .take(128)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| ScannerRunError::SandboxVersion)?;
            Ok::<_, ScannerRunError>(bytes)
        });
        let status = tokio::select! {
            checked = timeout(Duration::from_secs(2), child.wait()) => checked,
            _ = cancellation.cancelled() => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(1), child.wait()).await;
                output_task.abort();
                return Err(ScannerRunError::Cancelled);
            }
        };
        let status = match status {
            Ok(result) => result.map_err(|_| ScannerRunError::SandboxVersion)?,
            Err(_) => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(1), child.wait()).await;
                output_task.abort();
                return Err(ScannerRunError::SandboxVersion);
            }
        };
        let bytes = match timeout(Duration::from_secs(1), &mut output_task).await {
            Ok(result) => result.map_err(|_| ScannerRunError::SandboxVersion)??,
            Err(_) => {
                output_task.abort();
                return Err(ScannerRunError::SandboxVersion);
            }
        };
        if !status.success() || bytes != expected {
            return Err(ScannerRunError::SandboxVersion);
        }
        self.sandbox.revalidate()?;
        Ok(())
    }
}

struct RawRunResult {
    exit: NativeExit,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_command(
    plan: super::sandbox::ConfinedCommand,
    limits: ScannerRunLimits,
    cancellation: ScannerCancellation,
) -> Result<RawRunResult, ScannerRunError> {
    let mut command = Command::new(&plan.program);
    command
        .args(&plan.arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        command.process_group(0);
        let fds = plan.inherited_fds.clone();
        let child_limits = limits.clone();
        // SAFETY: only async-signal-safe limit, fcntl, and umask syscalls run.
        unsafe {
            command
                .as_std_mut()
                .pre_exec(move || install_child_limits(&child_limits, &fds));
        }
    }
    let mut child = command.spawn().map_err(|_| ScannerRunError::Spawn)?;
    let raw_pid = child.id().ok_or(ScannerRunError::Spawn)?;
    let mut group_guard = ProcessGroupGuard::new(raw_pid);
    let stdout = child.stdout.take().ok_or(ScannerRunError::Supervision)?;
    let stderr = child.stderr.take().ok_or(ScannerRunError::Supervision)?;
    let (overflow_tx, mut overflow_rx) = mpsc::channel(2);
    let stdout_task = drain(stdout, limits.max_output_bytes, overflow_tx.clone());
    let stderr_task = drain(stderr, limits.max_output_bytes, overflow_tx);
    let deadline = Instant::now() + limits.wall_timeout;
    let leader_exited = tokio::select! {
        status = observe_exit_without_reaping(raw_pid) => status,
        _ = tokio::time::sleep_until(deadline) => Err(ScannerRunError::Timeout),
        _ = cancellation.cancelled() => Err(ScannerRunError::Cancelled),
        _ = overflow_rx.recv() => Err(ScannerRunError::OutputLimit),
    };
    match leader_exited {
        Ok(()) => {}
        Err(error) => {
            terminate_and_reap(
                &mut child,
                raw_pid,
                limits.termination_grace,
                &mut group_guard,
            )
            .await;
            let _ = finish_drains(stdout_task, stderr_task).await;
            return Err(error);
        }
    }
    // A scanner which lets its leader exit while retaining descendants is not
    // allowed to outlive the invocation or keep an output pipe open. WNOWAIT
    // keeps the leader as a zombie, pinning its PID/PGID until after the group
    // is killed so a recycled process group can never be signalled.
    kill_group(raw_pid, rustix::process::Signal::KILL);
    group_guard.disarm();
    let status = child
        .wait()
        .await
        .map_err(|_| ScannerRunError::Supervision)?;
    let (stdout, stderr) = finish_drains(stdout_task, stderr_task).await?;
    if stdout.exceeded || stderr.exceeded {
        return Err(ScannerRunError::OutputLimit);
    }
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal = None;
    Ok(RawRunResult {
        exit: NativeExit {
            code: status.code(),
            signal,
        },
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

struct Drained {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn drain(
    mut stream: impl AsyncRead + Unpin + Send + 'static,
    limit: u64,
    overflow: mpsc::Sender<()>,
) -> JoinHandle<Result<Drained, io::Error>> {
    tokio::spawn(async move {
        let capacity = usize::try_from(limit.min(64 * 1024)).unwrap_or(64 * 1024);
        let mut bytes = Vec::with_capacity(capacity);
        let mut buffer = [0_u8; 8192];
        let mut exceeded = false;
        loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            let remaining =
                usize::try_from(limit.saturating_sub(bytes.len() as u64)).unwrap_or(usize::MAX);
            bytes.extend_from_slice(&buffer[..count.min(remaining)]);
            if count > remaining && !exceeded {
                exceeded = true;
                let _ = overflow.send(()).await;
            }
        }
        Ok(Drained { bytes, exceeded })
    })
}

async fn finish_drains(
    stdout: JoinHandle<Result<Drained, io::Error>>,
    stderr: JoinHandle<Result<Drained, io::Error>>,
) -> Result<(Drained, Drained), ScannerRunError> {
    let joined = timeout(Duration::from_secs(2), async {
        tokio::join!(stdout, stderr)
    })
    .await
    .map_err(|_| ScannerRunError::Supervision)?;
    let stdout = joined
        .0
        .map_err(|_| ScannerRunError::Supervision)?
        .map_err(|_| ScannerRunError::Supervision)?;
    let stderr = joined
        .1
        .map_err(|_| ScannerRunError::Supervision)?
        .map_err(|_| ScannerRunError::Supervision)?;
    Ok((stdout, stderr))
}

async fn terminate_and_reap(
    child: &mut Child,
    raw_pid: u32,
    grace: Duration,
    guard: &mut ProcessGroupGuard,
) {
    kill_group(raw_pid, rustix::process::Signal::TERM);
    if timeout(grace, observe_exit_without_reaping(raw_pid))
        .await
        .is_err()
    {
        kill_group(raw_pid, rustix::process::Signal::KILL);
    }
    kill_group(raw_pid, rustix::process::Signal::KILL);
    guard.disarm();
    let _ = child.wait().await;
}

async fn observe_exit_without_reaping(raw_pid: u32) -> Result<(), ScannerRunError> {
    let pid = rustix::process::Pid::from_raw(raw_pid as i32).ok_or(ScannerRunError::Supervision)?;
    loop {
        let status = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOWAIT
                | rustix::process::WaitIdOptions::NOHANG,
        )
        .map_err(|_| ScannerRunError::Supervision)?;
        if status.is_some() {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
}

fn kill_group(raw_pid: u32, signal: rustix::process::Signal) {
    if let Some(pid) = rustix::process::Pid::from_raw(raw_pid as i32) {
        let _ = rustix::process::kill_process_group(pid, signal);
    }
}

#[cfg(unix)]
fn install_child_limits(limits: &ScannerRunLimits, inherited_fds: &[RawFd]) -> io::Result<()> {
    for (resource, value) in [
        (rustix::process::Resource::Cpu, limits.cpu_seconds),
        (rustix::process::Resource::Nofile, limits.open_files),
        (rustix::process::Resource::Fsize, limits.max_output_bytes),
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
    for raw_fd in inherited_fds {
        // SAFETY: each descriptor is owned by a prepared runtime object held
        // across `spawn` and borrowed only for this fcntl syscall.
        let fd = unsafe { BorrowedFd::borrow_raw(*raw_fd) };
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty())?;
    }
    rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    Ok(())
}

struct ProcessGroupGuard {
    raw_pid: u32,
    armed: bool,
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

fn verify_empty_output_directory(path: &Path) -> Result<(), ScannerRunError> {
    let mut entries = fs::read_dir(path).map_err(|_| ScannerRunError::PrivateOutput)?;
    if entries
        .next()
        .transpose()
        .map_err(|_| ScannerRunError::PrivateOutput)?
        .is_some()
    {
        return Err(ScannerRunError::PrivateOutput);
    }
    Ok(())
}

struct OutputDirectoryGuard<'a>(&'a Path);

impl Drop for OutputDirectoryGuard<'_> {
    fn drop(&mut self) {
        clean_output_directory(self.0);
    }
}

fn clean_output_directory(path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&entry_path) else {
            continue;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let _ = fs::remove_dir_all(entry_path);
        } else {
            let _ = fs::remove_file(entry_path);
        }
    }
}

fn read_bounded_private(path: &Path, limit: u64) -> Result<Vec<u8>, ScannerRunError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ScannerRunError::PrivateOutput)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(ScannerRunError::OutputLimit);
    }
    fs::read(path).map_err(|_| ScannerRunError::PrivateOutput)
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScannerRunError {
    #[error(transparent)]
    Sandbox(#[from] ScannerSandboxError),
    #[error(transparent)]
    Adapter(#[from] ScannerAdapterError),
    #[error("external scanner invocation is invalid")]
    InvalidInvocation,
    #[error("external scanner could not be started")]
    Spawn,
    #[error("scanner sandbox version verification failed")]
    SandboxVersion,
    #[error("native scanner version verification failed")]
    ScannerVersion,
    #[error("external scanner exceeded its wall-time budget")]
    Timeout,
    #[error("external scanner exceeded its output budget")]
    OutputLimit,
    #[error("external scanner was cancelled")]
    Cancelled,
    #[error("external scanner private output is invalid")]
    PrivateOutput,
    #[error("external scanner supervision failed")]
    Supervision,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn limits() -> ScannerRunLimits {
        ScannerRunLimits {
            wall_timeout: Duration::from_secs(2),
            termination_grace: Duration::from_millis(50),
            max_output_bytes: 1024,
            cpu_seconds: 2,
            open_files: 64,
        }
    }

    fn shell_plan(script: &str, extra: Option<&Path>) -> super::super::sandbox::ConfinedCommand {
        let mut arguments = vec![OsString::from("-c"), OsString::from(script)];
        if let Some(extra) = extra {
            arguments.push(OsString::from("scanner-test"));
            arguments.push(extra.as_os_str().to_owned());
        }
        super::super::sandbox::ConfinedCommand {
            program: PathBuf::from("/bin/sh"),
            arguments,
            inherited_fds: Vec::new(),
            _owned_fds: Vec::new(),
        }
    }

    #[tokio::test]
    async fn cancellation_kills_and_reaps_the_process_group() {
        let root = TempDir::new().unwrap();
        let pid_path = root.path().join("child.pid");
        let cancellation = ScannerCancellation::default();
        let supervisor = tokio::spawn(run_command(
            shell_plan(
                "sleep 30 & child=$!; printf '%s' \"$child\" > \"$1\"; wait",
                Some(&pid_path),
            ),
            limits(),
            cancellation.clone(),
        ));
        let descendant = timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(value) = fs::read_to_string(&pid_path) {
                    if let Ok(pid) = value.parse::<i32>() {
                        break pid;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.cancel();
        assert!(matches!(
            supervisor.await.unwrap(),
            Err(ScannerRunError::Cancelled)
        ));
        timeout(Duration::from_secs(1), async {
            while Path::new(&format!("/proc/{descendant}")).exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn output_flood_is_bounded_and_fails_closed() {
        let result = run_command(
            shell_plan("while :; do printf 'xxxxxxxxxxxxxxxx'; done", None),
            limits(),
            ScannerCancellation::default(),
        )
        .await;
        assert!(matches!(result, Err(ScannerRunError::OutputLimit)));
    }

    #[tokio::test]
    async fn exited_leader_keeps_its_pgid_pinned_until_descendants_are_killed() {
        let root = TempDir::new().unwrap();
        let pid_path = root.path().join("descendant.pid");
        let result = run_command(
            shell_plan(
                "sleep 30 & child=$!; printf '%s' \"$child\" > \"$1\"; exit 0",
                Some(&pid_path),
            ),
            limits(),
            ScannerCancellation::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.exit.code, Some(0));
        let descendant = fs::read_to_string(pid_path)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while Path::new(&format!("/proc/{descendant}")).exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn output_guard_removes_unexpected_files_directories_and_symlinks() {
        let root = TempDir::new().unwrap();
        fs::write(root.path().join("unexpected"), b"withheld").unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::write(root.path().join("nested/file"), b"withheld").unwrap();
        std::os::unix::fs::symlink("unexpected", root.path().join("link")).unwrap();
        drop(OutputDirectoryGuard(root.path()));
        verify_empty_output_directory(root.path()).unwrap();
    }
}
