//! Bounded, non-interactive Git acquisition and immutable history enumeration.
//!
//! Git is treated as a trusted, configured acquisition executable. It is
//! invoked directly (never through a shell), with a cleared environment and a
//! closed authentication-variable allowlist. Repository-controlled hooks,
//! filters, replace objects, alternate object stores, submodules, and LFS
//! pointers are not part of the supported acquisition surface.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::domain::{Digest, LogicalPath, PathSegment};
use crate::processing::acquisition::local::{
    capture_owned_stage, AcquisitionCancellation, LocalAcquisitionResult,
    LocalAcquisitionStatistics,
};
use crate::processing::config::{CaptureLimits, SymlinkPolicy};
use crate::processing::domain::{
    GitBlobMode, GitBlobOccurrence, GitHistoryScope, GitObjectId, GitProvenance, GitRefSnapshot,
    GitTransport,
};

const FIXED_GIT_ENVIRONMENT: &[(&str, &str)] = &[
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_LFS_SKIP_SMUDGE", "1"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("LC_ALL", "C"),
    ("LANG", "C"),
];

const ALLOWED_AUTH_ENVIRONMENT: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "SSH_AUTH_SOCK",
    "GIT_SSH",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

const GIT_CONFIG_ARGUMENTS: &[&str] = &[
    "--no-replace-objects",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "filter.lfs.required=false",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.process=",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.ext.allow=never",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitCommandLimits {
    pub wall_timeout: Duration,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
}

impl GitCommandLimits {
    pub fn validate(self) -> Result<Self, GitAcquisitionError> {
        if self.wall_timeout.is_zero() || self.max_stdout_bytes == 0 || self.max_stderr_bytes == 0 {
            return Err(GitAcquisitionError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct GitExecutableIdentity {
    pub digest: Digest,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct SanitizedGitEnvironment(BTreeMap<OsString, OsString>);

impl fmt::Debug for SanitizedGitEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedGitEnvironment")
            .field("configured_entries", &self.0.len())
            .finish()
    }
}

impl SanitizedGitEnvironment {
    /// Captures the complete reviewed ambient authentication allowlist while
    /// continuing to discard every other variable, including all unapproved
    /// `GIT_*` controls. This is the ordinary HTTPS/SSH acquisition setup.
    pub fn from_current_authentication() -> Result<Self, GitAcquisitionError> {
        Self::from_current(ALLOWED_AUTH_ENVIRONMENT)
    }

    /// Captures only the named entries from the closed authentication
    /// allowlist. All other process environment, including hostile `GIT_*`
    /// controls and arbitrary credential variables, is discarded.
    pub fn from_current(allow: &[&str]) -> Result<Self, GitAcquisitionError> {
        let permitted: BTreeSet<&str> = ALLOWED_AUTH_ENVIRONMENT.iter().copied().collect();
        let mut values = BTreeMap::new();
        for name in allow {
            if !permitted.contains(name) {
                return Err(GitAcquisitionError::DisallowedEnvironment);
            }
            if let Some(value) = std::env::var_os(name) {
                validate_auth_environment(name, &value)?;
                values.insert(OsString::from(name), value);
            }
        }
        Ok(Self(values))
    }

    pub fn empty() -> Self {
        Self::default()
    }
}

fn validate_auth_environment(name: &str, value: &OsStr) -> Result<(), GitAcquisitionError> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(GitAcquisitionError::DisallowedEnvironment);
    }
    if matches!(
        name,
        "GIT_SSH" | "SSL_CERT_FILE" | "SSL_CERT_DIR" | "HOME" | "XDG_CONFIG_HOME"
    ) && !Path::new(value).is_absolute()
    {
        return Err(GitAcquisitionError::DisallowedEnvironment);
    }
    if name == "GIT_SSH" {
        let metadata = fs::symlink_metadata(Path::new(value))
            .map_err(|_| GitAcquisitionError::DisallowedEnvironment)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(GitAcquisitionError::DisallowedEnvironment);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommandOutput {
    pub stdout: Vec<u8>,
    pub diagnostic: RedactedGitDiagnostic,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedGitDiagnostic {
    None,
    Withheld,
}

#[derive(Clone)]
pub struct GitCommandRunner {
    executable: PathBuf,
    identity: GitExecutableIdentity,
    limits: GitCommandLimits,
    environment: SanitizedGitEnvironment,
}

impl fmt::Debug for GitCommandRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitCommandRunner")
            .field("identity", &self.identity)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl GitCommandRunner {
    pub fn new(
        executable: impl Into<PathBuf>,
        limits: GitCommandLimits,
        environment: SanitizedGitEnvironment,
    ) -> Result<Self, GitAcquisitionError> {
        let executable = executable.into();
        if !executable.is_absolute() {
            return Err(GitAcquisitionError::InvalidExecutable);
        }
        let identity = executable_identity(&executable)?;
        Ok(Self {
            executable,
            identity,
            limits: limits.validate()?,
            environment,
        })
    }

    pub const fn identity(&self) -> GitExecutableIdentity {
        self.identity
    }

    /// Runs one exact Git argv. Output is bounded, stderr is reduced to a
    /// secret-free presence marker, and every descendant in the process group
    /// is killed on timeout or output overflow.
    pub async fn run(
        &self,
        current_directory: Option<&Path>,
        arguments: &[OsString],
    ) -> Result<GitCommandOutput, GitAcquisitionError> {
        self.revalidate_executable()?;
        let mut command = Command::new(&self.executable);
        command
            .args(GIT_CONFIG_ARGUMENTS)
            .args(arguments)
            .env_clear()
            .envs(self.environment.0.iter())
            .envs(FIXED_GIT_ENVIRONMENT.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(directory) = current_directory {
            command.current_dir(directory);
        }
        command.process_group(0);
        let mut child = command.spawn().map_err(|_| GitAcquisitionError::Spawn)?;
        let pid = child.id().ok_or(GitAcquisitionError::Spawn)?;
        let stdout = child.stdout.take().ok_or(GitAcquisitionError::Spawn)?;
        let stderr = child.stderr.take().ok_or(GitAcquisitionError::Spawn)?;
        let mut stdout_task = tokio::spawn(read_bounded(stdout, self.limits.max_stdout_bytes));
        let mut stderr_task = tokio::spawn(read_bounded(stderr, self.limits.max_stderr_bytes));

        match timeout(self.limits.wall_timeout, observe_exit_without_reaping(pid)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                kill_process_group(pid);
                let _ = child.wait().await;
                return Err(error);
            }
            Err(_) => {
                kill_process_group(pid);
                let _ = child.wait().await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(GitAcquisitionError::Timeout);
            }
        }
        // The group leader remains an unreaped zombie here, so its PID cannot
        // be recycled while we decide whether escaped descendants still hold
        // the output pipes. This avoids signaling an unrelated, newly reused
        // process group under high process churn.
        let drained = timeout(
            Duration::from_secs(1),
            await_output_tasks(&mut stdout_task, &mut stderr_task),
        )
        .await;
        let (stdout, stderr) = match drained {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                kill_process_group(pid);
                stdout_task.abort();
                stderr_task.abort();
                let _ = child.wait().await;
                return Err(error);
            }
            Err(_) => {
                kill_process_group(pid);
                stdout_task.abort();
                stderr_task.abort();
                let _ = child.wait().await;
                return Err(GitAcquisitionError::OutputRead);
            }
        };
        let status = child.wait().await.map_err(|_| GitAcquisitionError::Wait)?;
        self.revalidate_executable()?;
        if stdout.exceeded || stderr.exceeded {
            return Err(GitAcquisitionError::OutputLimit);
        }
        if !status.success() {
            return Err(GitAcquisitionError::CommandFailed {
                exit_code: status.code(),
                diagnostic: if stderr.bytes.is_empty() {
                    RedactedGitDiagnostic::None
                } else {
                    RedactedGitDiagnostic::Withheld
                },
            });
        }
        Ok(GitCommandOutput {
            stdout: stdout.bytes,
            diagnostic: if stderr.bytes.is_empty() {
                RedactedGitDiagnostic::None
            } else {
                RedactedGitDiagnostic::Withheld
            },
        })
    }

    fn revalidate_executable(&self) -> Result<(), GitAcquisitionError> {
        if executable_identity(&self.executable)? != self.identity {
            return Err(GitAcquisitionError::ExecutableChanged);
        }
        Ok(())
    }
}

async fn observe_exit_without_reaping(raw_pid: u32) -> Result<(), GitAcquisitionError> {
    let pid = rustix::process::Pid::from_raw(raw_pid as i32).ok_or(GitAcquisitionError::Wait)?;
    loop {
        let status = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOWAIT
                | rustix::process::WaitIdOptions::NOHANG,
        )
        .map_err(|_| GitAcquisitionError::Wait)?;
        if status.is_some() {
            return Ok(());
        }
        sleep(Duration::from_millis(5)).await;
    }
}

async fn await_output_tasks(
    stdout: &mut JoinHandle<Result<BoundedRead, GitAcquisitionError>>,
    stderr: &mut JoinHandle<Result<BoundedRead, GitAcquisitionError>>,
) -> Result<(BoundedRead, BoundedRead), GitAcquisitionError> {
    let stdout = stdout
        .await
        .map_err(|_| GitAcquisitionError::OutputRead)??;
    let stderr = stderr
        .await
        .map_err(|_| GitAcquisitionError::OutputRead)??;
    Ok((stdout, stderr))
}

struct BoundedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    maximum: u64,
) -> Result<BoundedRead, GitAcquisitionError> {
    let capacity = usize::try_from(maximum.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut kept = Vec::with_capacity(capacity);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| GitAcquisitionError::OutputRead)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        let maximum_usize = usize::try_from(maximum).unwrap_or(usize::MAX);
        if kept.len() < maximum_usize {
            let remaining = maximum_usize.saturating_sub(kept.len());
            kept.extend_from_slice(&buffer[..count.min(remaining)]);
        }
    }
    Ok(BoundedRead {
        bytes: kept,
        exceeded: total > maximum,
    })
}

fn kill_process_group(raw_pid: u32) {
    if let Some(pid) = rustix::process::Pid::from_raw(raw_pid as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

fn executable_identity(path: &Path) -> Result<GitExecutableIdentity, GitAcquisitionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GitAcquisitionError::InvalidExecutable)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(GitAcquisitionError::InvalidExecutable);
    }
    let bytes = fs::read(path).map_err(|_| GitAcquisitionError::InvalidExecutable)?;
    Ok(GitExecutableIdentity {
        digest: Digest::sha256(bytes),
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
    })
}

/// A validated remote locator. Its raw value is deliberately omitted from
/// `Debug`, errors, provenance, and diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteLocator {
    raw: OsString,
    transport: GitTransport,
}

impl fmt::Debug for RemoteLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteLocator")
            .field("transport", &self.transport)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl RemoteLocator {
    pub fn parse(value: impl AsRef<OsStr>) -> Result<Self, GitAcquisitionError> {
        let value = value.as_ref();
        let raw = value.to_str().ok_or(GitAcquisitionError::InvalidRemote)?;
        if raw.is_empty()
            || raw.starts_with('-')
            || raw
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
        {
            return Err(GitAcquisitionError::InvalidRemote);
        }
        let transport = if let Some(rest) = raw.strip_prefix("https://") {
            validate_url_remote(rest, true)?;
            GitTransport::Https
        } else if let Some(rest) = raw.strip_prefix("ssh://") {
            validate_url_remote(rest, false)?;
            GitTransport::Ssh
        } else {
            if raw.contains("://") {
                return Err(GitAcquisitionError::InvalidRemote);
            }
            validate_scp_remote(raw)?;
            GitTransport::Ssh
        };
        Ok(Self {
            raw: value.to_os_string(),
            transport,
        })
    }

    pub const fn transport(&self) -> GitTransport {
        self.transport
    }

    fn argument(&self) -> OsString {
        self.raw.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvertisedGitRef {
    pub name: LogicalPath,
    pub object_id: GitObjectId,
    pub peeled_commit_id: GitObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenRemoteAdvertisement {
    pub transport: GitTransport,
    pub object_format: String,
    pub symbolic_head: Option<LogicalPath>,
    pub head_object_id: Option<GitObjectId>,
    pub refs: Vec<AdvertisedGitRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedRemoteRef {
    pub advertised: AdvertisedGitRef,
    pub private_ref: String,
}

/// Freezes the branch/tag advertisement before any fetch. The locator remains
/// private even when Git fails or returns hostile diagnostics.
pub async fn freeze_remote_advertisement(
    runner: &GitCommandRunner,
    locator: &RemoteLocator,
    max_refs: u64,
) -> Result<FrozenRemoteAdvertisement, GitAcquisitionError> {
    if max_refs == 0 {
        return Err(GitAcquisitionError::InvalidLimits);
    }
    let arguments = vec![
        OsString::from("ls-remote"),
        OsString::from("--symref"),
        OsString::from("--"),
        locator.argument(),
        OsString::from("HEAD"),
        OsString::from("refs/heads/*"),
        OsString::from("refs/tags/*"),
    ];
    let output = runner.run(None, &arguments).await?.stdout;
    parse_remote_advertisement(locator.transport(), &output, max_refs)
}

fn parse_remote_advertisement(
    transport: GitTransport,
    output: &[u8],
    max_refs: u64,
) -> Result<FrozenRemoteAdvertisement, GitAcquisitionError> {
    let mut symbolic_head = None;
    let mut head_hex: Option<Vec<u8>> = None;
    let mut direct: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut peeled: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let (left, right) =
            split_once_byte(line, b'\t').ok_or(GitAcquisitionError::MalformedOutput)?;
        if let Some(target) = left.strip_prefix(b"ref: ") {
            if right != b"HEAD" || symbolic_head.is_some() {
                return Err(GitAcquisitionError::MalformedOutput);
            }
            symbolic_head = Some(logical_path_from_slashes(target)?);
            continue;
        }
        if right == b"HEAD" {
            if head_hex.replace(left.to_vec()).is_some() {
                return Err(GitAcquisitionError::MalformedOutput);
            }
            continue;
        }
        let (name, is_peeled) = right
            .strip_suffix(b"^{}")
            .map_or((right, false), |name| (name, true));
        if !(name.starts_with(b"refs/heads/") || name.starts_with(b"refs/tags/")) {
            return Err(GitAcquisitionError::MalformedOutput);
        }
        let map = if is_peeled { &mut peeled } else { &mut direct };
        if map.insert(name.to_vec(), left.to_vec()).is_some() {
            return Err(GitAcquisitionError::MalformedOutput);
        }
        if direct.len().saturating_add(peeled.len()) as u64 > max_refs.saturating_mul(2) {
            return Err(GitAcquisitionError::RefLimit);
        }
    }
    if direct.is_empty() || direct.len() as u64 > max_refs {
        return Err(GitAcquisitionError::MalformedOutput);
    }
    let oid_length = direct
        .values()
        .next()
        .ok_or(GitAcquisitionError::MalformedOutput)?
        .len();
    let object_format = match oid_length {
        40 => "sha1",
        64 => "sha256",
        _ => return Err(GitAcquisitionError::UnsupportedObjectFormat),
    }
    .to_owned();
    let head_object_id = head_hex
        .as_deref()
        .map(|value| parse_oid_bytes(&object_format, value))
        .transpose()?;
    let mut refs = Vec::with_capacity(direct.len());
    for (name, object) in direct {
        let object_id = parse_oid_bytes(&object_format, &object)?;
        let peeled_commit_id = peeled
            .remove(&name)
            .as_deref()
            .map(|value| parse_oid_bytes(&object_format, value))
            .transpose()?
            .unwrap_or_else(|| object_id.clone());
        refs.push(AdvertisedGitRef {
            name: logical_path_from_slashes(&name)?,
            object_id,
            peeled_commit_id,
        });
    }
    if !peeled.is_empty() {
        return Err(GitAcquisitionError::MalformedOutput);
    }
    refs.sort_by(|left, right| left.name.cmp(&right.name));
    if let (Some(symbolic), Some(head)) = (&symbolic_head, &head_object_id) {
        let matching = refs
            .iter()
            .find(|reference| &reference.name == symbolic)
            .ok_or(GitAcquisitionError::MalformedOutput)?;
        if &matching.object_id != head && &matching.peeled_commit_id != head {
            return Err(GitAcquisitionError::MalformedOutput);
        }
    }
    Ok(FrozenRemoteAdvertisement {
        transport,
        object_format,
        symbolic_head,
        head_object_id,
        refs,
    })
}

/// Fetches an exact frozen set of advertised refs into opaque private refs in
/// a newly initialized bare repository and verifies that none moved. The
/// caller chooses the selected original ref names; unadvertised names fail.
pub async fn fetch_frozen_remote_refs(
    runner: &GitCommandRunner,
    locator: &RemoteLocator,
    advertisement: &FrozenRemoteAdvertisement,
    selected: &[LogicalPath],
    destination: &Path,
) -> Result<Vec<FetchedRemoteRef>, GitAcquisitionError> {
    if selected.is_empty()
        || !destination.is_absolute()
        || fs::symlink_metadata(destination).is_ok()
        || locator.transport() != advertisement.transport
    {
        return Err(GitAcquisitionError::InvalidDestination);
    }
    let mut chosen = Vec::with_capacity(selected.len());
    let mut seen = BTreeSet::new();
    for name in selected {
        if !seen.insert(name.clone()) {
            return Err(GitAcquisitionError::RefPatternAmbiguous);
        }
        let advertised = advertisement
            .refs
            .iter()
            .find(|candidate| &candidate.name == name)
            .cloned()
            .ok_or(GitAcquisitionError::RefPatternUnmatched)?;
        let original = utf8_logical_ref(name)?;
        let digest = Digest::sha256(original.as_bytes()).to_string();
        let private_ref = format!("refs/file-guardian/frozen/{}", &digest[7..]);
        chosen.push((advertised, original, private_ref));
    }
    let init = vec![
        OsString::from("init"),
        OsString::from("--bare"),
        OsString::from("--template="),
        OsString::from(format!("--object-format={}", advertisement.object_format)),
        destination.as_os_str().to_os_string(),
    ];
    runner.run(None, &init).await?;
    let mut fetch = vec![
        OsString::from("-C"),
        destination.as_os_str().to_os_string(),
        OsString::from("fetch"),
        OsString::from("--atomic"),
        OsString::from("--no-tags"),
        OsString::from("--no-write-fetch-head"),
        OsString::from("--no-recurse-submodules"),
        OsString::from("--"),
        locator.argument(),
    ];
    fetch.extend(
        chosen
            .iter()
            .map(|(_, original, private_ref)| OsString::from(format!("+{original}:{private_ref}"))),
    );
    runner.run(None, &fetch).await?;
    let mut fetched = Vec::with_capacity(chosen.len());
    for (advertised, _, private_ref) in chosen {
        let output = run_repo(
            runner,
            destination,
            &["show-ref", "--verify", "--hash", &private_ref],
        )
        .await?;
        let actual = parse_oid_bytes(&advertisement.object_format, trim_ascii(&output))?;
        if actual != advertised.object_id {
            return Err(GitAcquisitionError::RepositoryMoved);
        }
        let expression = format!("{}^{{commit}}", oid_argument(&actual));
        let peeled = parse_oid_bytes(
            &advertisement.object_format,
            trim_ascii(
                &run_repo(runner, destination, &["rev-parse", "--verify", &expression]).await?,
            ),
        )?;
        if peeled != advertised.peeled_commit_id {
            return Err(GitAcquisitionError::RepositoryMoved);
        }
        fetched.push(FetchedRemoteRef {
            advertised,
            private_ref,
        });
    }
    Ok(fetched)
}

fn utf8_logical_ref(path: &LogicalPath) -> Result<String, GitAcquisitionError> {
    let mut output = String::new();
    for (index, segment) in path.segments().iter().enumerate() {
        let value = std::str::from_utf8(segment.as_slice())
            .map_err(|_| GitAcquisitionError::MalformedOutput)?;
        if index != 0 {
            output.push('/');
        }
        output.push_str(value);
    }
    Ok(output)
}

fn validate_url_remote(rest: &str, https: bool) -> Result<(), GitAcquisitionError> {
    if rest.contains(['?', '#']) || rest.is_empty() {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    let (authority, path) = rest
        .split_once('/')
        .ok_or(GitAcquisitionError::InvalidRemote)?;
    if authority.is_empty() || path.is_empty() {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    let host_port = match authority.rsplit_once('@') {
        Some((userinfo, host)) => {
            if userinfo.is_empty() || userinfo.contains(':') || userinfo.contains('%') {
                return Err(GitAcquisitionError::InvalidRemote);
            }
            host
        }
        None => authority,
    };
    if host_port.is_empty() || host_port.contains('@') {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    if https && authority.starts_with('[') && !authority.contains(']') {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    validate_host_port(host_port)
}

fn validate_host_port(value: &str) -> Result<(), GitAcquisitionError> {
    if value.starts_with('[') {
        let close = value.find(']').ok_or(GitAcquisitionError::InvalidRemote)?;
        if close == 1 {
            return Err(GitAcquisitionError::InvalidRemote);
        }
        let suffix = &value[close + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix[1..]
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .is_none())
        {
            return Err(GitAcquisitionError::InvalidRemote);
        }
        return Ok(());
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        _ => (value, None),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || port.is_some_and(|port| {
            port.parse::<u16>()
                .ok()
                .filter(|value| *value != 0)
                .is_none()
        })
    {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    Ok(())
}

fn validate_scp_remote(raw: &str) -> Result<(), GitAcquisitionError> {
    if raw.contains(['/', '?', '#']) && !raw.contains(':') {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    let (authority, path) = raw
        .split_once(':')
        .ok_or(GitAcquisitionError::InvalidRemote)?;
    if authority.is_empty() || path.is_empty() || path.starts_with('-') || path.contains(':') {
        return Err(GitAcquisitionError::InvalidRemote);
    }
    let host = match authority.split_once('@') {
        Some((user, host)) => {
            if user.is_empty()
                || !user
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(GitAcquisitionError::InvalidRemote);
            }
            host
        }
        None => authority,
    };
    validate_host_port(host)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitEnumerationLimits {
    pub max_refs: u64,
    pub max_commits: u64,
    pub max_unique_blobs: u64,
    pub max_provenance_occurrences: u64,
    pub max_git_bytes: u64,
}

impl GitEnumerationLimits {
    fn validate(&self) -> Result<(), GitAcquisitionError> {
        if self.max_refs == 0
            || self.max_commits == 0
            || self.max_unique_blobs == 0
            || self.max_provenance_occurrences == 0
            || self.max_git_bytes == 0
            || self.max_unique_blobs > self.max_provenance_occurrences
        {
            return Err(GitAcquisitionError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitEnumerationRequest {
    pub history: GitHistoryScope,
    pub history_ref_patterns: Vec<String>,
    pub checkout_ref: Option<String>,
    pub allowed_checkout_ref_patterns: Vec<String>,
    pub limits: GitEnumerationLimits,
}

impl GitEnumerationRequest {
    fn validate(&self) -> Result<(), GitAcquisitionError> {
        self.limits.validate()?;
        if self.allowed_checkout_ref_patterns.is_empty()
            || self.allowed_checkout_ref_patterns.len()
                != self
                    .allowed_checkout_ref_patterns
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
        {
            return Err(GitAcquisitionError::InvalidRefPattern);
        }
        match self.history {
            GitHistoryScope::Reachable if self.history_ref_patterns.is_empty() => {
                Err(GitAcquisitionError::InvalidRefPattern)
            }
            GitHistoryScope::Reachable => Ok(()),
            _ if !self.history_ref_patterns.is_empty() => {
                Err(GitAcquisitionError::InvalidRefPattern)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenGitBlob {
    pub object_id: GitObjectId,
    pub object_store_identity: Digest,
    pub bytes: Vec<u8>,
    pub provenance: GitProvenance,
    pub symbolic_link: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenGitHeadEntry {
    pub path: LogicalPath,
    pub object_id: GitObjectId,
    pub object_store_identity: Digest,
    pub bytes: Vec<u8>,
    pub mode: GitBlobMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenGitRepository {
    pub repository_identity: Digest,
    pub git_version: String,
    pub object_format: String,
    pub bare: bool,
    pub resolved_head: GitObjectId,
    pub frozen_refs: Vec<GitRefSnapshot>,
    pub commits: Vec<GitObjectId>,
    pub head_tree: Vec<FrozenGitHeadEntry>,
    pub blobs: Vec<FrozenGitBlob>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquiredRemoteRepository {
    pub repository: FrozenGitRepository,
    pub working_tree: LocalAcquisitionResult,
    pub summary: GitAcquisitionSummary,
}

/// Report-safe acquisition facts. It deliberately excludes the source path,
/// remote locator, diagnostics, environment, and temporary repository path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitAcquisitionSummary {
    pub transport: Option<GitTransport>,
    pub repository_identity: Digest,
    pub object_format: String,
    pub resolved_head: GitObjectId,
    pub frozen_ref_count: u64,
    pub commit_count: u64,
    pub history_blob_count: u64,
    pub working_tree_manifest_identity: Option<Digest>,
    pub working_tree_statistics: Option<LocalAcquisitionStatistics>,
}

/// Acquires a validated remote directly into the job-owned stage. The stage is
/// the only clone: its `.git` directory is retained for Pi and Git-aware
/// analyzers, while the working tree is materialized without running hooks or
/// repository-controlled filters.
pub async fn acquire_remote_repository_source(
    runner: &GitCommandRunner,
    locator: &RemoteLocator,
    request: &GitEnumerationRequest,
    stage: &Path,
    capture_limits: &CaptureLimits,
    symlinks: SymlinkPolicy,
    cancellation: &AcquisitionCancellation,
) -> Result<AcquiredRemoteRepository, GitAcquisitionError> {
    request.validate()?;
    let jobs_root = validate_remote_stage(stage)?;
    let git_directory = stage.join(".git");
    acquire_remote_repository_inner(
        runner,
        locator,
        request,
        &git_directory,
        stage,
        capture_limits,
        symlinks,
        cancellation,
        &jobs_root,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn acquire_remote_repository_inner(
    runner: &GitCommandRunner,
    locator: &RemoteLocator,
    request: &GitEnumerationRequest,
    source_repository: &Path,
    stage: &Path,
    capture_limits: &CaptureLimits,
    symlinks: SymlinkPolicy,
    cancellation: &AcquisitionCancellation,
    jobs_root: &Path,
) -> Result<AcquiredRemoteRepository, GitAcquisitionError> {
    let advertisement =
        freeze_remote_advertisement(runner, locator, request.limits.max_refs).await?;
    let selection = select_remote_advertisement(&advertisement, request)?;
    let fetched = fetch_frozen_remote_refs(
        runner,
        locator,
        &advertisement,
        &selection.selected_refs,
        source_repository,
    )
    .await?;
    fs::set_permissions(source_repository, fs::Permissions::from_mode(0o700))
        .map_err(|_| GitAcquisitionError::InvalidDestination)?;
    install_frozen_remote_refs(runner, source_repository, &fetched, &selection.checkout_ref)
        .await?;
    run_repo(runner, source_repository, &["config", "core.bare", "false"]).await?;
    run_repo(
        runner,
        source_repository,
        &["config", "core.worktree", ".."],
    )
    .await?;

    let mut local_request = request.clone();
    local_request.checkout_ref = Some(logical_ref_name(&selection.checkout_ref)?);
    let repository = enumerate_local_repository(runner, stage, &local_request).await?;
    validate_frozen_remote_result(&repository, &advertisement, &selection, request)?;
    materialize_frozen_head(&repository, stage, symlinks == SymlinkPolicy::Preserve)?;
    let working_tree =
        capture_owned_stage(stage, jobs_root, capture_limits, symlinks, cancellation)
            .map_err(|_| GitAcquisitionError::WorkingTreeCapture)?;
    let summary = acquisition_summary(
        Some(advertisement.transport),
        &repository,
        Some(&working_tree),
    )?;
    Ok(AcquiredRemoteRepository {
        repository,
        working_tree,
        summary,
    })
}

fn acquisition_summary(
    transport: Option<GitTransport>,
    repository: &FrozenGitRepository,
    working_tree: Option<&LocalAcquisitionResult>,
) -> Result<GitAcquisitionSummary, GitAcquisitionError> {
    Ok(GitAcquisitionSummary {
        transport,
        repository_identity: repository.repository_identity,
        object_format: repository.object_format.clone(),
        resolved_head: repository.resolved_head.clone(),
        frozen_ref_count: u64::try_from(repository.frozen_refs.len())
            .map_err(|_| GitAcquisitionError::RefLimit)?,
        commit_count: u64::try_from(repository.commits.len())
            .map_err(|_| GitAcquisitionError::CommitLimit)?,
        history_blob_count: u64::try_from(repository.blobs.len())
            .map_err(|_| GitAcquisitionError::BlobLimit)?,
        working_tree_manifest_identity: working_tree.map(|tree| tree.manifest_identity),
        working_tree_statistics: working_tree.map(|tree| tree.statistics),
    })
}

#[derive(Clone, Debug)]
struct RemoteSelection {
    checkout_ref: LogicalPath,
    selected_refs: Vec<LogicalPath>,
}

fn select_remote_advertisement(
    advertisement: &FrozenRemoteAdvertisement,
    request: &GitEnumerationRequest,
) -> Result<RemoteSelection, GitAcquisitionError> {
    let checkout_ref = if let Some(requested) = &request.checkout_ref {
        validate_checkout_ref(requested)?;
        let matching = advertisement
            .refs
            .iter()
            .filter(|candidate| {
                logical_ref_name(&candidate.name)
                    .is_ok_and(|name| ref_matches_request(name.as_bytes(), requested))
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(GitAcquisitionError::CheckoutRefResolution);
        }
        matching[0].name.clone()
    } else if let Some(symbolic) = &advertisement.symbolic_head {
        symbolic.clone()
    } else {
        let head = advertisement
            .head_object_id
            .as_ref()
            .ok_or(GitAcquisitionError::CheckoutRefResolution)?;
        let matching = advertisement
            .refs
            .iter()
            .filter(|candidate| &candidate.object_id == head || &candidate.peeled_commit_id == head)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(GitAcquisitionError::CheckoutRefResolution);
        }
        matching[0].name.clone()
    };
    let checkout_name = logical_ref_name(&checkout_ref)?;
    let allowed = compile_globs(&request.allowed_checkout_ref_patterns, false)?;
    if !allowed.is_match(&checkout_name) {
        return Err(GitAcquisitionError::CheckoutRefForbidden);
    }
    let mut selected_refs = match request.history {
        GitHistoryScope::None | GitHistoryScope::Head => Vec::new(),
        GitHistoryScope::AllRefs => advertisement
            .refs
            .iter()
            .map(|reference| reference.name.clone())
            .collect(),
        GitHistoryScope::Reachable => {
            let compiled = request
                .history_ref_patterns
                .iter()
                .map(|pattern| Glob::new(pattern).map(|glob| glob.compile_matcher()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| GitAcquisitionError::InvalidRefPattern)?;
            let mut matched_patterns = vec![false; compiled.len()];
            let selected = advertisement
                .refs
                .iter()
                .filter(|reference| {
                    let Ok(name) = logical_ref_name(&reference.name) else {
                        return false;
                    };
                    let mut selected = false;
                    for (index, matcher) in compiled.iter().enumerate() {
                        if matcher.is_match(&name) {
                            matched_patterns[index] = true;
                            selected = true;
                        }
                    }
                    selected
                })
                .map(|reference| reference.name.clone())
                .collect::<Vec<_>>();
            if matched_patterns.iter().any(|matched| !matched) {
                return Err(GitAcquisitionError::RefPatternUnmatched);
            }
            for (index, pattern) in request.history_ref_patterns.iter().enumerate() {
                if !contains_glob_meta(pattern)
                    && advertisement
                        .refs
                        .iter()
                        .filter(|reference| {
                            logical_ref_name(&reference.name)
                                .is_ok_and(|name| compiled[index].is_match(name))
                        })
                        .count()
                        != 1
                {
                    return Err(GitAcquisitionError::RefPatternAmbiguous);
                }
            }
            selected
        }
    };
    if !selected_refs.contains(&checkout_ref) {
        selected_refs.push(checkout_ref.clone());
    }
    selected_refs.sort();
    Ok(RemoteSelection {
        checkout_ref,
        selected_refs,
    })
}

async fn install_frozen_remote_refs(
    runner: &GitCommandRunner,
    repository: &Path,
    fetched: &[FetchedRemoteRef],
    checkout_ref: &LogicalPath,
) -> Result<(), GitAcquisitionError> {
    for reference in fetched {
        let original = logical_ref_name(&reference.advertised.name)?;
        let object = oid_argument(&reference.advertised.object_id);
        run_repo(runner, repository, &["update-ref", &original, &object]).await?;
    }
    let checkout = logical_ref_name(checkout_ref)?;
    run_repo(runner, repository, &["symbolic-ref", "HEAD", &checkout]).await?;
    Ok(())
}

fn validate_frozen_remote_result(
    repository: &FrozenGitRepository,
    advertisement: &FrozenRemoteAdvertisement,
    selection: &RemoteSelection,
    request: &GitEnumerationRequest,
) -> Result<(), GitAcquisitionError> {
    let checkout = advertisement
        .refs
        .iter()
        .find(|reference| reference.name == selection.checkout_ref)
        .ok_or(GitAcquisitionError::RepositoryMoved)?;
    if repository.object_format != advertisement.object_format
        || repository.resolved_head != checkout.peeled_commit_id
    {
        return Err(GitAcquisitionError::RepositoryMoved);
    }
    let expected_names = match request.history {
        GitHistoryScope::None => Vec::new(),
        GitHistoryScope::Head => vec![selection.checkout_ref.clone()],
        GitHistoryScope::Reachable | GitHistoryScope::AllRefs => selection.selected_refs.clone(),
    };
    let mut expected = expected_names
        .iter()
        .map(|name| {
            let advertised = advertisement
                .refs
                .iter()
                .find(|reference| &reference.name == name)
                .ok_or(GitAcquisitionError::RepositoryMoved)?;
            GitRefSnapshot::new(
                advertised.name.clone(),
                advertised.object_id.clone(),
                advertised.peeled_commit_id.clone(),
            )
            .map_err(|_| GitAcquisitionError::MalformedOutput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    expected.sort_by(|left, right| left.name.cmp(&right.name));
    if repository.frozen_refs != expected {
        return Err(GitAcquisitionError::RepositoryMoved);
    }
    Ok(())
}

fn logical_ref_name(path: &LogicalPath) -> Result<String, GitAcquisitionError> {
    utf8_logical_ref(path)
}

fn validate_remote_stage(stage: &Path) -> Result<PathBuf, GitAcquisitionError> {
    if !stage.is_absolute() || fs::symlink_metadata(stage.join(".git")).is_ok() {
        return Err(GitAcquisitionError::InvalidDestination);
    }
    let jobs_root = stage
        .parent()
        .ok_or(GitAcquisitionError::InvalidDestination)?
        .to_path_buf();
    let root_metadata =
        fs::symlink_metadata(&jobs_root).map_err(|_| GitAcquisitionError::InvalidDestination)?;
    let stage_metadata =
        fs::symlink_metadata(stage).map_err(|_| GitAcquisitionError::InvalidDestination)?;
    let effective_user = rustix::process::geteuid().as_raw();
    if !root_metadata.file_type().is_dir()
        || !stage_metadata.file_type().is_dir()
        || root_metadata.uid() != effective_user
        || stage_metadata.uid() != effective_user
        || root_metadata.permissions().mode() & 0o777 != 0o700
        || stage_metadata.permissions().mode() & 0o777 != 0o700
        || fs::read_dir(stage)
            .map_err(|_| GitAcquisitionError::InvalidDestination)?
            .next()
            .is_some()
    {
        return Err(GitAcquisitionError::InvalidDestination);
    }
    Ok(jobs_root)
}

/// Freezes and enumerates one local repository using plumbing only. It never
/// invokes checkout, filters, hooks, submodules, or LFS hydration.
pub async fn enumerate_local_repository(
    runner: &GitCommandRunner,
    repository: &Path,
    request: &GitEnumerationRequest,
) -> Result<FrozenGitRepository, GitAcquisitionError> {
    request.validate()?;
    if !repository.is_absolute() {
        return Err(GitAcquisitionError::InvalidRepository);
    }
    let metadata =
        fs::symlink_metadata(repository).map_err(|_| GitAcquisitionError::InvalidRepository)?;
    if !metadata.file_type().is_dir() {
        return Err(GitAcquisitionError::InvalidRepository);
    }

    let git_version = parse_single_line(runner.run(None, &os_args(&["--version"])).await?.stdout)?;
    if !git_version.starts_with("git version ") {
        return Err(GitAcquisitionError::MalformedOutput);
    }
    let bare = parse_bool_output(
        &run_repo(runner, repository, &["rev-parse", "--is-bare-repository"]).await?,
    )?;
    if parse_bool_output(
        &run_repo(
            runner,
            repository,
            &["rev-parse", "--is-shallow-repository"],
        )
        .await?,
    )? {
        return Err(GitAcquisitionError::ShallowRepository);
    }
    reject_unsupported_repository_state(runner, repository).await?;
    let object_format = parse_single_line(
        run_repo(runner, repository, &["rev-parse", "--show-object-format"]).await?,
    )?;
    if !matches!(object_format.as_str(), "sha1" | "sha256") {
        return Err(GitAcquisitionError::UnsupportedObjectFormat);
    }

    let refs_before =
        read_local_refs(runner, repository, &object_format, request.limits.max_refs).await?;
    let checkout = resolve_checkout(runner, repository, &refs_before, request).await?;
    let head = checkout.snapshot.peeled_commit_id.clone();
    let mut selected_refs = select_history_refs(&refs_before, request)?;
    if request.history.includes_history()
        && !selected_refs
            .iter()
            .any(|reference| reference.name_bytes == checkout.name_bytes)
    {
        selected_refs.push(checkout.clone());
        selected_refs.sort_by(|left, right| left.name_bytes.cmp(&right.name_bytes));
    }
    let commits = enumerate_commits(runner, repository, &head, &selected_refs, request).await?;
    let blob_commits = if commits.is_empty() {
        vec![head.clone()]
    } else {
        commits.clone()
    };
    let all_blobs = enumerate_blobs(
        runner,
        repository,
        &object_format,
        &blob_commits,
        &selected_refs,
        &request.limits,
    )
    .await?;
    let head_tree = derive_head_tree(&head, &all_blobs)?;
    let blobs = if request.history.includes_history() {
        all_blobs
    } else {
        Vec::new()
    };
    let refs_after =
        read_local_refs(runner, repository, &object_format, request.limits.max_refs).await?;
    if refs_before != refs_after {
        return Err(GitAcquisitionError::RepositoryMoved);
    }
    let checkout_after = resolve_checkout(runner, repository, &refs_after, request).await?;
    if checkout_after != checkout {
        return Err(GitAcquisitionError::RepositoryMoved);
    }

    let frozen_refs = selected_refs
        .into_iter()
        .map(|reference| reference.snapshot)
        .collect::<Vec<_>>();
    let repository_identity = repository_identity(&object_format, &head, &frozen_refs);
    Ok(FrozenGitRepository {
        repository_identity,
        git_version,
        object_format,
        bare,
        resolved_head: head,
        frozen_refs,
        commits,
        head_tree,
        blobs,
    })
}

fn derive_head_tree(
    head: &GitObjectId,
    blobs: &[FrozenGitBlob],
) -> Result<Vec<FrozenGitHeadEntry>, GitAcquisitionError> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for blob in blobs {
        for occurrence in &blob.provenance.occurrences {
            if &occurrence.commit_id != head {
                continue;
            }
            if !seen.insert(occurrence.path.clone()) {
                return Err(GitAcquisitionError::MalformedOutput);
            }
            entries.push(FrozenGitHeadEntry {
                path: occurrence.path.clone(),
                object_id: blob.object_id.clone(),
                object_store_identity: blob.object_store_identity,
                bytes: blob.bytes.clone(),
                mode: blob.provenance.mode,
            });
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

async fn run_repo(
    runner: &GitCommandRunner,
    repository: &Path,
    arguments: &[&str],
) -> Result<Vec<u8>, GitAcquisitionError> {
    let mut argv = vec![OsString::from("-C"), repository.as_os_str().to_os_string()];
    argv.extend(arguments.iter().map(OsString::from));
    Ok(runner.run(None, &argv).await?.stdout)
}

async fn reject_unsupported_repository_state(
    runner: &GitCommandRunner,
    repository: &Path,
) -> Result<(), GitAcquisitionError> {
    let config = run_repo(
        runner,
        repository,
        &["config", "--local", "--null", "--list"],
    )
    .await?;
    for entry in config
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let lower = entry.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
        let key = lower.split(|byte| *byte == b'\n').next().unwrap_or(&lower);
        if key == b"extensions.partialclone"
            || (key.starts_with(b"remote.") && key.ends_with(b".promisor"))
            || key == b"objects.infoalternates"
        {
            return Err(GitAcquisitionError::PartialOrAlternateRepository);
        }
    }
    let git_dir = parse_single_line(
        run_repo(runner, repository, &["rev-parse", "--absolute-git-dir"]).await?,
    )?;
    let alternates = Path::new(&git_dir).join("objects/info/alternates");
    if fs::symlink_metadata(alternates).is_ok() {
        return Err(GitAcquisitionError::PartialOrAlternateRepository);
    }
    let replace = run_repo(
        runner,
        repository,
        &["for-each-ref", "--format=%(refname)", "refs/replace/"],
    )
    .await?;
    if !replace.is_empty() {
        return Err(GitAcquisitionError::ReplaceRefs);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalRef {
    name_bytes: Vec<u8>,
    snapshot: GitRefSnapshot,
}

async fn read_local_refs(
    runner: &GitCommandRunner,
    repository: &Path,
    object_format: &str,
    max_refs: u64,
) -> Result<Vec<LocalRef>, GitAcquisitionError> {
    let output = run_repo(
        runner,
        repository,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(*objectname)",
            "refs/heads/",
            "refs/remotes/",
            "refs/tags/",
        ],
    )
    .await?;
    let mut refs = Vec::new();
    for record in output
        .split(|byte| *byte == b'\n')
        .filter(|record| !record.is_empty())
    {
        let fields = record.split(|byte| *byte == 0).collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(GitAcquisitionError::MalformedOutput);
        }
        let name = fields[0];
        let object = fields[1];
        let peeled = fields[2];
        if name.is_empty() || refs.len() as u64 >= max_refs {
            return Err(GitAcquisitionError::RefLimit);
        }
        let object_id = parse_oid_bytes(object_format, object)?;
        let peeled_commit_id = if peeled.is_empty() {
            object_id.clone()
        } else {
            parse_oid_bytes(object_format, peeled)?
        };
        refs.push(LocalRef {
            name_bytes: name.to_vec(),
            snapshot: GitRefSnapshot::new(
                logical_path_from_slashes(name)?,
                object_id,
                peeled_commit_id,
            )?,
        });
    }
    refs.sort_by(|left, right| left.name_bytes.cmp(&right.name_bytes));
    Ok(refs)
}

async fn resolve_checkout(
    runner: &GitCommandRunner,
    repository: &Path,
    refs: &[LocalRef],
    request: &GitEnumerationRequest,
) -> Result<LocalRef, GitAcquisitionError> {
    let allowed = compile_globs(&request.allowed_checkout_ref_patterns, false)?;
    let requested = if let Some(reference) = &request.checkout_ref {
        validate_checkout_ref(reference)?;
        reference.clone()
    } else {
        parse_single_line(
            run_repo(runner, repository, &["symbolic-ref", "-q", "HEAD"])
                .await
                .map_err(|_| GitAcquisitionError::CheckoutRefResolution)?,
        )?
    };
    let matches = refs
        .iter()
        .filter(|candidate| ref_matches_request(&candidate.name_bytes, &requested))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(GitAcquisitionError::CheckoutRefResolution);
    }
    let name = std::str::from_utf8(&matches[0].name_bytes)
        .map_err(|_| GitAcquisitionError::CheckoutRefResolution)?;
    if !allowed.is_match(name) {
        return Err(GitAcquisitionError::CheckoutRefForbidden);
    }
    let expression = format!(
        "{}^{{commit}}",
        oid_argument(&matches[0].snapshot.object_id)
    );
    let resolved = parse_oid_bytes(
        matches[0].snapshot.object_id.algorithm(),
        trim_ascii(&run_repo(runner, repository, &["rev-parse", "--verify", &expression]).await?),
    )?;
    let selected = (*matches[0]).clone();
    if resolved != selected.snapshot.peeled_commit_id {
        return Err(GitAcquisitionError::MalformedOutput);
    }
    Ok(selected)
}

fn ref_matches_request(candidate: &[u8], requested: &str) -> bool {
    candidate == requested.as_bytes()
        || candidate.strip_prefix(b"refs/heads/") == Some(requested.as_bytes())
        || candidate.strip_prefix(b"refs/tags/") == Some(requested.as_bytes())
        || candidate.strip_prefix(b"refs/remotes/") == Some(requested.as_bytes())
}

fn validate_checkout_ref(reference: &str) -> Result<(), GitAcquisitionError> {
    if reference.is_empty()
        || reference.len() > 1024
        || reference.starts_with('-')
        || reference.bytes().any(|byte| byte.is_ascii_control())
        || (matches!(reference.len(), 40 | 64)
            && reference.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(GitAcquisitionError::CheckoutRefResolution);
    }
    Ok(())
}

fn select_history_refs(
    refs: &[LocalRef],
    request: &GitEnumerationRequest,
) -> Result<Vec<LocalRef>, GitAcquisitionError> {
    match request.history {
        GitHistoryScope::None | GitHistoryScope::Head => Ok(Vec::new()),
        GitHistoryScope::AllRefs => Ok(refs.to_vec()),
        GitHistoryScope::Reachable => {
            let patterns = compile_globs(&request.history_ref_patterns, true)?;
            let mut matched_patterns = vec![false; request.history_ref_patterns.len()];
            let compiled = request
                .history_ref_patterns
                .iter()
                .map(|pattern| Glob::new(pattern).map(|glob| glob.compile_matcher()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| GitAcquisitionError::InvalidRefPattern)?;
            let selected = refs
                .iter()
                .filter(|reference| {
                    let Ok(name) = std::str::from_utf8(&reference.name_bytes) else {
                        return false;
                    };
                    for (index, matcher) in compiled.iter().enumerate() {
                        if matcher.is_match(name) {
                            matched_patterns[index] = true;
                        }
                    }
                    patterns.is_match(name)
                })
                .cloned()
                .collect::<Vec<_>>();
            if matched_patterns.iter().any(|matched| !matched) {
                return Err(GitAcquisitionError::RefPatternUnmatched);
            }
            for (index, pattern) in request.history_ref_patterns.iter().enumerate() {
                if !contains_glob_meta(pattern)
                    && refs
                        .iter()
                        .filter(|reference| {
                            std::str::from_utf8(&reference.name_bytes)
                                .is_ok_and(|name| compiled[index].is_match(name))
                        })
                        .count()
                        != 1
                {
                    return Err(GitAcquisitionError::RefPatternAmbiguous);
                }
            }
            Ok(selected)
        }
    }
}

fn compile_globs(
    patterns: &[String],
    require_nonempty: bool,
) -> Result<GlobSet, GitAcquisitionError> {
    if (require_nonempty && patterns.is_empty())
        || patterns.iter().any(|pattern| pattern.is_empty())
    {
        return Err(GitAcquisitionError::InvalidRefPattern);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(|_| GitAcquisitionError::InvalidRefPattern)?);
    }
    builder
        .build()
        .map_err(|_| GitAcquisitionError::InvalidRefPattern)
}

fn contains_glob_meta(pattern: &str) -> bool {
    pattern
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b'{'))
}

async fn enumerate_commits(
    runner: &GitCommandRunner,
    repository: &Path,
    head: &GitObjectId,
    refs: &[LocalRef],
    request: &GitEnumerationRequest,
) -> Result<Vec<GitObjectId>, GitAcquisitionError> {
    if request.history == GitHistoryScope::None {
        return Ok(Vec::new());
    }
    if request.history == GitHistoryScope::Head {
        return Ok(vec![head.clone()]);
    }
    let mut argv = vec![
        "rev-list".to_owned(),
        "--topo-order".to_owned(),
        "--reverse".to_owned(),
    ];
    argv.push(oid_argument(head));
    argv.extend(
        refs.iter()
            .map(|reference| oid_argument(&reference.snapshot.peeled_commit_id)),
    );
    let borrowed = argv.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_repo(runner, repository, &borrowed).await?;
    let mut commits = Vec::new();
    let mut seen = BTreeSet::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let oid = parse_oid_bytes(head.algorithm(), line)?;
        if seen.insert(oid.clone()) {
            if commits.len() as u64 >= request.limits.max_commits {
                return Err(GitAcquisitionError::CommitLimit);
            }
            commits.push(oid);
        }
    }
    if commits.is_empty() || !seen.contains(head) {
        return Err(GitAcquisitionError::MissingObject);
    }
    Ok(commits)
}

async fn enumerate_blobs(
    runner: &GitCommandRunner,
    repository: &Path,
    object_format: &str,
    commits: &[GitObjectId],
    refs: &[LocalRef],
    limits: &GitEnumerationLimits,
) -> Result<Vec<FrozenGitBlob>, GitAcquisitionError> {
    #[derive(Clone)]
    struct Accumulator {
        oid: GitObjectId,
        mode: u32,
        occurrences: Vec<GitBlobOccurrence>,
    }
    let mut accumulators: BTreeMap<(GitObjectId, u32), Accumulator> = BTreeMap::new();
    let ref_by_commit = refs
        .iter()
        .map(|reference| {
            (
                reference.snapshot.peeled_commit_id.clone(),
                reference.snapshot.name.clone(),
            )
        })
        .fold(
            BTreeMap::<GitObjectId, Vec<LogicalPath>>::new(),
            |mut map, (oid, name)| {
                map.entry(oid).or_default().push(name);
                map
            },
        );
    let mut occurrence_count = 0_u64;
    for commit in commits {
        let commit_argument = oid_argument(commit);
        let output = run_repo(
            runner,
            repository,
            &["ls-tree", "-rz", "--full-tree", &commit_argument],
        )
        .await?;
        for record in output
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
        {
            let (header, path) =
                split_once_byte(record, b'\t').ok_or(GitAcquisitionError::MalformedOutput)?;
            let fields = header.split(|byte| *byte == b' ').collect::<Vec<_>>();
            if fields.len() != 3 || fields[1] != b"blob" {
                if fields.first() == Some(&b"160000".as_slice())
                    || fields.get(1) == Some(&b"commit".as_slice())
                {
                    return Err(GitAcquisitionError::Submodule);
                }
                return Err(GitAcquisitionError::UnsupportedTreeEntry);
            }
            let mode = parse_mode(fields[0])?;
            if mode == 0o160000 {
                return Err(GitAcquisitionError::Submodule);
            }
            let oid = parse_oid_bytes(object_format, fields[2])?;
            occurrence_count = occurrence_count.saturating_add(1);
            if occurrence_count > limits.max_provenance_occurrences {
                return Err(GitAcquisitionError::ProvenanceLimit);
            }
            let occurrence = GitBlobOccurrence {
                commit_id: commit.clone(),
                path: logical_path_from_slashes(path)?,
                refs: ref_by_commit.get(commit).cloned().unwrap_or_default(),
            };
            accumulators
                .entry((oid.clone(), mode))
                .or_insert_with(|| Accumulator {
                    oid,
                    mode,
                    occurrences: Vec::new(),
                })
                .occurrences
                .push(occurrence);
        }
    }
    if accumulators.len() as u64 > limits.max_unique_blobs {
        return Err(GitAcquisitionError::BlobLimit);
    }
    let mut total = 0_u64;
    let mut blobs = Vec::with_capacity(accumulators.len());
    for (_, accumulator) in accumulators {
        let blob_argument = oid_argument(&accumulator.oid);
        let bytes = run_repo(runner, repository, &["cat-file", "blob", &blob_argument]).await?;
        total = total.saturating_add(bytes.len() as u64);
        if total > limits.max_git_bytes {
            return Err(GitAcquisitionError::GitByteLimit);
        }
        if is_lfs_pointer(&bytes) {
            return Err(GitAcquisitionError::LfsPointer);
        }
        blobs.push(FrozenGitBlob {
            object_id: accumulator.oid.clone(),
            object_store_identity: Digest::sha256(&bytes),
            bytes,
            provenance: GitProvenance::new(
                accumulator.oid,
                match accumulator.mode {
                    0o100644 => GitBlobMode::Regular,
                    0o100755 => GitBlobMode::Executable,
                    0o120000 => GitBlobMode::SymbolicLink,
                    _ => return Err(GitAcquisitionError::UnsupportedTreeEntry),
                },
                accumulator.occurrences,
            )?,
            symbolic_link: accumulator.mode == 0o120000,
        });
    }
    Ok(blobs)
}

fn parse_mode(value: &[u8]) -> Result<u32, GitAcquisitionError> {
    let text = std::str::from_utf8(value).map_err(|_| GitAcquisitionError::MalformedOutput)?;
    let mode = u32::from_str_radix(text, 8).map_err(|_| GitAcquisitionError::MalformedOutput)?;
    if !matches!(mode, 0o100644 | 0o100755 | 0o120000 | 0o160000) {
        return Err(GitAcquisitionError::UnsupportedTreeEntry);
    }
    Ok(mode)
}

fn is_lfs_pointer(bytes: &[u8]) -> bool {
    bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
        && bytes.windows(5).any(|window| window == b"oid s")
}

/// Materializes exactly the frozen HEAD tree beside an existing `.git`
/// directory, without invoking checkout hooks or repository-controlled
/// filters. Symbolic links require explicit opt-in and are never followed.
pub fn materialize_frozen_head(
    frozen: &FrozenGitRepository,
    destination: &Path,
    preserve_symlinks: bool,
) -> Result<(), GitAcquisitionError> {
    let metadata =
        fs::symlink_metadata(destination).map_err(|_| GitAcquisitionError::InvalidDestination)?;
    if !metadata.file_type().is_dir() {
        return Err(GitAcquisitionError::InvalidDestination);
    }
    let existing = fs::read_dir(destination)
        .map_err(|_| GitAcquisitionError::InvalidDestination)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GitAcquisitionError::InvalidDestination)?;
    if existing.len() > 1
        || existing
            .first()
            .is_some_and(|entry| entry.file_name() != OsStr::new(".git"))
        || existing.first().is_some_and(|entry| {
            fs::symlink_metadata(entry.path()).map_or(true, |metadata| !metadata.is_dir())
        })
    {
        return Err(GitAcquisitionError::InvalidDestination);
    }
    for entry in &frozen.head_tree {
        let relative = os_path(&entry.path)?;
        if relative.components().next().is_none()
            || relative.file_name() == Some(OsStr::new(".git"))
            || relative
                .components()
                .any(|component| component.as_os_str() == ".git")
        {
            return Err(GitAcquisitionError::UnsafePath);
        }
        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            create_private_directories(destination, parent)?;
        }
        if entry.mode == GitBlobMode::SymbolicLink {
            if !preserve_symlinks {
                return Err(GitAcquisitionError::SymbolicLink);
            }
            symlink(OsString::from_vec(entry.bytes.clone()), &target)
                .map_err(|_| GitAcquisitionError::Materialization)?;
        } else {
            fs::write(&target, &entry.bytes).map_err(|_| GitAcquisitionError::Materialization)?;
            let mode = if entry.mode == GitBlobMode::Executable {
                0o700
            } else {
                0o600
            };
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                .map_err(|_| GitAcquisitionError::Materialization)?;
        }
    }
    Ok(())
}

fn create_private_directories(root: &Path, target: &Path) -> Result<(), GitAcquisitionError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| GitAcquisitionError::UnsafePath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            return Err(GitAcquisitionError::UnsafePath);
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(GitAcquisitionError::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_| GitAcquisitionError::Materialization)?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                    .map_err(|_| GitAcquisitionError::Materialization)?;
            }
            Err(_) => return Err(GitAcquisitionError::Materialization),
        }
    }
    Ok(())
}

fn os_path(path: &LogicalPath) -> Result<PathBuf, GitAcquisitionError> {
    let mut result = PathBuf::new();
    for segment in path.segments() {
        result.push(OsString::from_vec(segment.as_slice().to_vec()));
    }
    Ok(result)
}

fn repository_identity(object_format: &str, head: &GitObjectId, refs: &[GitRefSnapshot]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"file-guardian-repository-v1\0");
    hasher.update(object_format.as_bytes());
    hasher.update([0]);
    hasher.update(head.to_string().as_bytes());
    for reference in refs {
        hasher.update([0]);
        for segment in reference.name.segments() {
            hasher.update(segment.as_slice());
            hasher.update([b'/']);
        }
        hasher.update(reference.object_id.to_string().as_bytes());
        hasher.update(reference.peeled_commit_id.to_string().as_bytes());
    }
    Digest::from_array(hasher.finalize().into())
}

fn logical_path_from_slashes(bytes: &[u8]) -> Result<LogicalPath, GitAcquisitionError> {
    if bytes.starts_with(b"/") || bytes.ends_with(b"/") || bytes.contains(&0) {
        return Err(GitAcquisitionError::UnsafePath);
    }
    let segments = bytes
        .split(|byte| *byte == b'/')
        .map(PathSegment::from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LogicalPath::new(segments)?)
}

fn parse_oid_bytes(algorithm: &str, value: &[u8]) -> Result<GitObjectId, GitAcquisitionError> {
    let value = std::str::from_utf8(value).map_err(|_| GitAcquisitionError::MalformedOutput)?;
    GitObjectId::from_str(&format!("{algorithm}:{value}"))
        .map_err(|_| GitAcquisitionError::MalformedOutput)
}

fn oid_argument(oid: &GitObjectId) -> String {
    oid.to_string()
        .split_once(':')
        .expect("canonical Git object ID")
        .1
        .to_owned()
}

fn parse_single_line(bytes: Vec<u8>) -> Result<String, GitAcquisitionError> {
    let trimmed = trim_ascii(&bytes);
    if trimmed.is_empty() || trimmed.contains(&b'\n') || trimmed.contains(&b'\r') {
        return Err(GitAcquisitionError::MalformedOutput);
    }
    std::str::from_utf8(trimmed)
        .map(str::to_owned)
        .map_err(|_| GitAcquisitionError::MalformedOutput)
}

fn parse_bool_output(bytes: &[u8]) -> Result<bool, GitAcquisitionError> {
    match trim_ascii(bytes) {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(GitAcquisitionError::MalformedOutput),
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn split_once_byte(bytes: &[u8], needle: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|byte| *byte == needle)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

fn os_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum GitAcquisitionError {
    #[error("Git acquisition limits are invalid")]
    InvalidLimits,
    #[error("the configured Git executable is invalid")]
    InvalidExecutable,
    #[error("the configured Git executable changed during acquisition")]
    ExecutableChanged,
    #[error("the requested authentication environment is not allowlisted")]
    DisallowedEnvironment,
    #[error("the Git process could not be started")]
    Spawn,
    #[error("the Git process could not be reaped")]
    Wait,
    #[error("the Git process exceeded its wall timeout")]
    Timeout,
    #[error("Git process output could not be read")]
    OutputRead,
    #[error("Git process output exceeded its configured bound")]
    OutputLimit,
    #[error("Git command failed with exit {exit_code:?}; diagnostic {diagnostic:?}")]
    CommandFailed {
        exit_code: Option<i32>,
        diagnostic: RedactedGitDiagnostic,
    },
    #[error("the remote locator is not an allowed HTTPS or SSH form")]
    InvalidRemote,
    #[error("the local repository path is invalid")]
    InvalidRepository,
    #[error("a bare repository cannot provide a working tree")]
    BareWorkingTree,
    #[error("the local repository working tree could not be captured safely")]
    WorkingTreeCapture,
    #[error("temporary Git repository metadata could not be removed")]
    RepositoryCleanup,
    #[error("local repository acquisition was cancelled")]
    Cancelled,
    #[error("Git returned malformed or inconsistent plumbing output")]
    MalformedOutput,
    #[error("the Git object format is unsupported")]
    UnsupportedObjectFormat,
    #[error("shallow Git repositories are not accepted")]
    ShallowRepository,
    #[error("partial clones and alternate object stores are not accepted")]
    PartialOrAlternateRepository,
    #[error("Git replace refs are not accepted")]
    ReplaceRefs,
    #[error("the repository contains an unsupported submodule entry")]
    Submodule,
    #[error("the repository contains an unsupported Git LFS pointer")]
    LfsPointer,
    #[error("the repository contains an unsupported tree entry")]
    UnsupportedTreeEntry,
    #[error("the repository changed while its scope was being frozen")]
    RepositoryMoved,
    #[error("a required Git object is missing")]
    MissingObject,
    #[error("the configured Git ref limit was exceeded")]
    RefLimit,
    #[error("the configured Git commit limit was exceeded")]
    CommitLimit,
    #[error("the configured unique Git blob limit was exceeded")]
    BlobLimit,
    #[error("the configured Git provenance limit was exceeded")]
    ProvenanceLimit,
    #[error("the configured Git byte limit was exceeded")]
    GitByteLimit,
    #[error("a history ref pattern is invalid")]
    InvalidRefPattern,
    #[error("a history ref pattern matched no refs")]
    RefPatternUnmatched,
    #[error("an exact history ref pattern did not match exactly one ref")]
    RefPatternAmbiguous,
    #[error("the checkout ref is missing or ambiguous")]
    CheckoutRefResolution,
    #[error("the checkout ref is forbidden by policy")]
    CheckoutRefForbidden,
    #[error("a Git path is unsafe")]
    UnsafePath,
    #[error("symbolic links are rejected by acquisition policy")]
    SymbolicLink,
    #[error("the materialization destination is invalid")]
    InvalidDestination,
    #[error("Git tree materialization failed")]
    Materialization,
    #[error(transparent)]
    LogicalPath(#[from] crate::domain::LogicalPathError),
    #[error(transparent)]
    ProcessingDomain(#[from] crate::processing::domain::ProcessingDomainError),
}
