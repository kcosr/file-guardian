use super::protocol::ScannerKind;
use crate::domain::Digest;
use sha2::{Digest as _, Sha256};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PROTECTED_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableIdentity {
    pub digest: Digest,
    pub device: u64,
    pub inode: u64,
    pub byte_len: u64,
    pub mode: u32,
}

pub struct PreparedScannerExecutable {
    kind: ScannerKind,
    canonical_path: PathBuf,
    file: File,
    identity: ExecutableIdentity,
}

impl std::fmt::Debug for PreparedScannerExecutable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedScannerExecutable")
            .field("kind", &self.kind)
            .field("executable_name", &self.kind.executable_name())
            .field("identity", &self.identity)
            .finish()
    }
}

impl PreparedScannerExecutable {
    pub fn discover(
        kind: ScannerKind,
        configured: &OsStr,
        startup_path: Option<&OsStr>,
    ) -> Result<Self, ScannerSandboxError> {
        platform_supported()?;
        let resolved = resolve_executable(configured, startup_path)?;
        let canonical_path =
            fs::canonicalize(&resolved).map_err(|_| ScannerSandboxError::ToolUnavailable)?;
        if !canonical_path.is_absolute() {
            return Err(ScannerSandboxError::ToolUnavailable);
        }
        let file = OpenOptions::new()
            .read(true)
            .open(&canonical_path)
            .map_err(|_| ScannerSandboxError::ToolUnavailable)?;
        let identity = stamp_executable(&mut file.try_clone().map_err(private_io)?)?;
        ensure_static_elf(&mut file.try_clone().map_err(private_io)?)?;
        Ok(Self {
            kind,
            canonical_path,
            file,
            identity,
        })
    }

    pub fn discover_from_environment(
        kind: ScannerKind,
        configured: &OsStr,
    ) -> Result<Self, ScannerSandboxError> {
        Self::discover(kind, configured, env::var_os("PATH").as_deref())
    }

    pub fn identity(&self) -> &ExecutableIdentity {
        &self.identity
    }

    pub fn revalidate(&self) -> Result<(), ScannerSandboxError> {
        let mut descriptor = self.file.try_clone().map_err(private_io)?;
        let actual = stamp_executable(&mut descriptor)?;
        if actual != self.identity {
            return Err(ScannerSandboxError::ExecutableChanged);
        }
        let path_metadata = fs::metadata(&self.canonical_path)
            .map_err(|_| ScannerSandboxError::ExecutableChanged)?;
        if path_metadata.dev() != self.identity.device || path_metadata.ino() != self.identity.inode
        {
            return Err(ScannerSandboxError::ExecutableChanged);
        }
        Ok(())
    }

    pub(super) fn inherited_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub(super) fn kind(&self) -> ScannerKind {
        self.kind
    }
}

pub struct PreparedProtectedFile {
    file: File,
    identity: ExecutableIdentity,
}

impl std::fmt::Debug for PreparedProtectedFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedProtectedFile")
            .field("identity", &self.identity)
            .finish()
    }
}

impl PreparedProtectedFile {
    pub fn open(path: &Path) -> Result<Self, ScannerSandboxError> {
        platform_supported()?;
        if !path.is_absolute() {
            return Err(ScannerSandboxError::ProtectedFileInvalid);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ScannerSandboxError::ProtectedFileInvalid)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_PROTECTED_FILE_BYTES
        {
            return Err(ScannerSandboxError::ProtectedFileInvalid);
        }
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|_| ScannerSandboxError::ProtectedFileInvalid)?;
        let identity = stamp_regular(
            &mut file.try_clone().map_err(private_io)?,
            false,
            MAX_PROTECTED_FILE_BYTES,
        )?;
        Ok(Self { file, identity })
    }

    pub fn identity(&self) -> &ExecutableIdentity {
        &self.identity
    }

    pub fn revalidate(&self) -> Result<(), ScannerSandboxError> {
        let actual = stamp_regular(
            &mut self.file.try_clone().map_err(private_io)?,
            false,
            MAX_PROTECTED_FILE_BYTES,
        )?;
        (actual == self.identity)
            .then_some(())
            .ok_or(ScannerSandboxError::ProtectedFileChanged)
    }

    pub(super) fn inherited_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

pub struct ScannerSandboxSpec {
    pub bubblewrap_executable: PathBuf,
    pub expected_bubblewrap_version: String,
}

#[derive(Clone)]
pub struct PreparedScannerSandbox {
    bubblewrap_path: PathBuf,
    bubblewrap_identity: ExecutableIdentity,
    expected_version: String,
}

impl std::fmt::Debug for ScannerSandboxSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScannerSandboxSpec")
            .field("bubblewrap_configured", &true)
            .field("expected_version", &self.expected_bubblewrap_version)
            .finish()
    }
}

impl std::fmt::Debug for PreparedScannerSandbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedScannerSandbox")
            .field("bubblewrap_identity", &self.bubblewrap_identity)
            .field("expected_version", &self.expected_version)
            .finish()
    }
}

impl PreparedScannerSandbox {
    pub fn prepare(spec: ScannerSandboxSpec) -> Result<Self, ScannerSandboxError> {
        platform_supported()?;
        if !spec.bubblewrap_executable.is_absolute()
            || spec.expected_bubblewrap_version.is_empty()
            || spec
                .expected_bubblewrap_version
                .chars()
                .any(char::is_control)
        {
            return Err(ScannerSandboxError::SandboxInvalid);
        }
        let bubblewrap_path = fs::canonicalize(&spec.bubblewrap_executable)
            .map_err(|_| ScannerSandboxError::SandboxUnavailable)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&bubblewrap_path)
            .map_err(|_| ScannerSandboxError::SandboxUnavailable)?;
        let bubblewrap_identity = stamp_executable(&mut file)?;
        Ok(Self {
            bubblewrap_path,
            bubblewrap_identity,
            expected_version: spec.expected_bubblewrap_version,
        })
    }

    pub fn revalidate(&self) -> Result<(), ScannerSandboxError> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.bubblewrap_path)
            .map_err(|_| ScannerSandboxError::SandboxChanged)?;
        let actual = stamp_executable(&mut file)?;
        (actual == self.bubblewrap_identity)
            .then_some(())
            .ok_or(ScannerSandboxError::SandboxChanged)
    }

    pub fn identity(&self) -> &ExecutableIdentity {
        &self.bubblewrap_identity
    }

    pub(super) fn program(&self) -> &Path {
        &self.bubblewrap_path
    }

    pub(super) fn expected_version_line(&self) -> Vec<u8> {
        format!("bubblewrap {}\n", self.expected_version).into_bytes()
    }
}

pub(super) struct ConfinedCommand {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub inherited_fds: Vec<RawFd>,
    pub _owned_fds: Vec<OwnedFd>,
}

pub(super) fn compile_confined_command(
    sandbox: &PreparedScannerSandbox,
    scanner: &PreparedScannerExecutable,
    input_view: &Path,
    output_directory: &Path,
    native_arguments: &[OsString],
    protected_files: &[(&PreparedProtectedFile, &'static str)],
) -> Result<ConfinedCommand, ScannerSandboxError> {
    platform_supported()?;
    sandbox.revalidate()?;
    scanner.revalidate()?;
    validate_directory(input_view, false)?;
    validate_directory(output_directory, true)?;

    let input_fd = open_directory_descriptor(input_view, false)?;
    let output_fd = open_directory_descriptor(output_directory, true)?;
    let scanner_fd = scanner.inherited_fd();
    let mut inherited_fds = vec![scanner_fd, input_fd.as_raw_fd(), output_fd.as_raw_fd()];
    let mut arguments = Vec::new();
    push_args(
        &mut arguments,
        &[
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-net",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/scanner-config",
        ],
    );
    push_os_args(
        &mut arguments,
        &[
            OsStr::new("--ro-bind"),
            OsStr::new(&format!("/proc/self/fd/{}", input_fd.as_raw_fd())),
            OsStr::new("/input"),
        ],
    );
    push_os_args(
        &mut arguments,
        &[
            OsStr::new("--bind"),
            OsStr::new(&format!("/proc/self/fd/{}", output_fd.as_raw_fd())),
            OsStr::new("/output"),
        ],
    );
    let scanner_source = format!("/proc/self/fd/{scanner_fd}");
    push_os_args(
        &mut arguments,
        &[
            OsStr::new("--ro-bind"),
            OsStr::new(&scanner_source),
            OsStr::new("/scanner"),
        ],
    );
    for (file, destination) in protected_files {
        file.revalidate()?;
        let fd = file.inherited_fd();
        inherited_fds.push(fd);
        let source = format!("/proc/self/fd/{fd}");
        push_os_args(
            &mut arguments,
            &[
                OsStr::new("--ro-bind"),
                OsStr::new(&source),
                OsStr::new(destination),
            ],
        );
    }
    push_args(
        &mut arguments,
        &[
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "XDG_CONFIG_HOME",
            "/tmp/config",
            "--setenv",
            "XDG_CACHE_HOME",
            "/tmp/cache",
            "--setenv",
            "PATH",
            "/nonexistent",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "NO_COLOR",
            "1",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--setenv",
            "GIT_OPTIONAL_LOCKS",
            "0",
            "--setenv",
            "GIT_TERMINAL_PROMPT",
            "0",
            "--chdir",
            "/input",
            "--",
            "/scanner",
        ],
    );
    arguments.extend(native_arguments.iter().cloned());
    Ok(ConfinedCommand {
        program: sandbox.program().to_path_buf(),
        arguments,
        inherited_fds,
        _owned_fds: vec![input_fd, output_fd],
    })
}

fn open_directory_descriptor(path: &Path, writable: bool) -> Result<OwnedFd, ScannerSandboxError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ScannerSandboxError::SandboxPathInvalid)?;
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| ScannerSandboxError::SandboxPathInvalid)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || (writable && metadata.st_mode & 0o077 != 0)
    {
        return Err(ScannerSandboxError::SandboxPathInvalid);
    }
    Ok(descriptor)
}

fn push_args(target: &mut Vec<OsString>, values: &[&str]) {
    target.extend(values.iter().map(OsString::from));
}

fn push_os_args(target: &mut Vec<OsString>, values: &[&OsStr]) {
    target.extend(values.iter().map(|value| value.to_os_string()));
}

fn resolve_executable(
    configured: &OsStr,
    startup_path: Option<&OsStr>,
) -> Result<PathBuf, ScannerSandboxError> {
    let configured_path = Path::new(configured);
    if configured.is_empty()
        || configured_path
            .as_os_str()
            .to_string_lossy()
            .starts_with('-')
    {
        return Err(ScannerSandboxError::ToolUnavailable);
    }
    if configured_path.components().count() > 1 || configured_path.is_absolute() {
        return configured_path
            .is_absolute()
            .then(|| configured_path.to_path_buf())
            .ok_or(ScannerSandboxError::ToolPathInvalid);
    }
    if matches!(
        configured_path.components().next(),
        Some(Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_))
    ) {
        return Err(ScannerSandboxError::ToolPathInvalid);
    }
    let path = startup_path.ok_or(ScannerSandboxError::ToolUnavailable)?;
    let mut match_path = None;
    for component in env::split_paths(path) {
        if component.as_os_str().is_empty() || !component.is_absolute() {
            return Err(ScannerSandboxError::PathEnvironmentInvalid);
        }
        let candidate = component.join(configured_path);
        if match_path.is_none()
            && fs::metadata(&candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        {
            match_path = Some(candidate);
        }
    }
    match_path.ok_or(ScannerSandboxError::ToolUnavailable)
}

fn stamp_executable(file: &mut File) -> Result<ExecutableIdentity, ScannerSandboxError> {
    stamp_regular(file, true, MAX_EXECUTABLE_BYTES)
}

fn stamp_regular(
    file: &mut File,
    executable: bool,
    max_bytes: u64,
) -> Result<ExecutableIdentity, ScannerSandboxError> {
    let metadata = file.metadata().map_err(private_io)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || metadata.nlink() == 0
    {
        return Err(ScannerSandboxError::FileIdentityInvalid);
    }
    let mode = metadata.permissions().mode();
    if executable && mode & 0o111 == 0 {
        return Err(ScannerSandboxError::FileIdentityInvalid);
    }
    file.seek(SeekFrom::Start(0)).map_err(private_io)?;
    let mut hasher = Sha256::new();
    let mut limited = file.take(max_bytes.saturating_add(1));
    let copied = io::copy(&mut limited, &mut hasher).map_err(private_io)?;
    let after = file.metadata().map_err(private_io)?;
    if copied != metadata.len()
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || after.permissions().mode() != mode
    {
        return Err(ScannerSandboxError::FileIdentityInvalid);
    }
    let digest = format!("sha256:{:x}", hasher.finalize())
        .parse()
        .map_err(|_| ScannerSandboxError::FileIdentityInvalid)?;
    Ok(ExecutableIdentity {
        digest,
        device: metadata.dev(),
        inode: metadata.ino(),
        byte_len: metadata.len(),
        mode: mode & 0o7777,
    })
}

fn ensure_static_elf(file: &mut File) -> Result<(), ScannerSandboxError> {
    file.seek(SeekFrom::Start(0)).map_err(private_io)?;
    let byte_len = file.metadata().map_err(private_io)?.len();
    let mut header = [0_u8; 64];
    file.read_exact(&mut header).map_err(private_io)?;
    if &header[..4] != b"\x7fELF" || header[5] != 1 {
        return Err(ScannerSandboxError::ExecutableNotSelfContained);
    }
    let class = header[4];
    let (phoff, phentsize, phnum) = match class {
        1 => (
            u64::from(read_u32(&header, 28)?),
            u64::from(read_u16(&header, 42)?),
            u64::from(read_u16(&header, 44)?),
        ),
        2 => (
            read_u64(&header, 32)?,
            u64::from(read_u16(&header, 54)?),
            u64::from(read_u16(&header, 56)?),
        ),
        _ => return Err(ScannerSandboxError::ExecutableNotSelfContained),
    };
    if phentsize < 4
        || phnum == 0
        || phoff
            .checked_add(phentsize.saturating_mul(phnum))
            .is_none_or(|end| end > byte_len)
    {
        return Err(ScannerSandboxError::ExecutableNotSelfContained);
    }
    for index in 0..phnum {
        file.seek(SeekFrom::Start(phoff + index * phentsize))
            .map_err(private_io)?;
        let mut program_type = [0_u8; 4];
        file.read_exact(&mut program_type).map_err(private_io)?;
        if u32::from_le_bytes(program_type) == 3 {
            return Err(ScannerSandboxError::ExecutableNotSelfContained);
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ScannerSandboxError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(ScannerSandboxError::ExecutableNotSelfContained)?
        .try_into()
        .unwrap();
    Ok(u16::from_le_bytes(raw))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ScannerSandboxError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(ScannerSandboxError::ExecutableNotSelfContained)?
        .try_into()
        .unwrap();
    Ok(u32::from_le_bytes(raw))
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ScannerSandboxError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(ScannerSandboxError::ExecutableNotSelfContained)?
        .try_into()
        .unwrap();
    Ok(u64::from_le_bytes(raw))
}

fn validate_directory(path: &Path, writable: bool) -> Result<(), ScannerSandboxError> {
    if !path.is_absolute() {
        return Err(ScannerSandboxError::SandboxPathInvalid);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ScannerSandboxError::SandboxPathInvalid)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || (writable && metadata.permissions().mode() & 0o077 != 0)
    {
        return Err(ScannerSandboxError::SandboxPathInvalid);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_supported() -> Result<(), ScannerSandboxError> {
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn platform_supported() -> Result<(), ScannerSandboxError> {
    Err(ScannerSandboxError::UnsupportedPlatform)
}

fn private_io(_: io::Error) -> ScannerSandboxError {
    ScannerSandboxError::FileIdentityInvalid
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScannerSandboxError {
    #[error("external scanners are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("scanner executable is unavailable")]
    ToolUnavailable,
    #[error("scanner executable path is invalid")]
    ToolPathInvalid,
    #[error("startup PATH contains an empty or relative component")]
    PathEnvironmentInvalid,
    #[error("scanner executable identity is invalid")]
    FileIdentityInvalid,
    #[error("scanner executable is not a self-contained static ELF binary")]
    ExecutableNotSelfContained,
    #[error("scanner executable changed after preflight")]
    ExecutableChanged,
    #[error("protected scanner input is invalid")]
    ProtectedFileInvalid,
    #[error("protected scanner input changed after preflight")]
    ProtectedFileChanged,
    #[error("scanner sandbox is unavailable")]
    SandboxUnavailable,
    #[error("scanner sandbox configuration is invalid")]
    SandboxInvalid,
    #[error("scanner sandbox changed after preflight")]
    SandboxChanged,
    #[error("scanner sandbox path is invalid")]
    SandboxPathInvalid,
}
