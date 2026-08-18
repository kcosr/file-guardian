//! Descriptor-relative acquisition of one literal local filesystem source.
//!
//! Caller-owned content is copied into an empty, owner-only stage. Source
//! entries are opened without following links, checked before and after every
//! read, and directory contents are re-enumerated. No caller path is retained
//! in the result or in an error.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::domain::{Digest, LogicalPath, PathSegment};
use crate::processing::config::{CaptureLimits, SymlinkPolicy};
use crate::processing::domain::PathInputKind;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const SOURCE_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const DESTINATION_FILE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH_DIRECTORY_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

#[cfg(target_vendor = "apple")]
const SEARCH_DIRECTORY_FLAGS: OFlags = OFlags::from_bits_retain(0x4000_0000)
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SEARCH_DIRECTORY_FLAGS: OFlags = DIRECTORY_FLAGS;

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_SAFE_RECURSION_DEPTH: usize = 256;

/// Cooperative cancellation shared with a processing job.
#[derive(Clone, Default)]
pub struct AcquisitionCancellation {
    cancelled: Arc<AtomicBool>,
}

impl AcquisitionCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<(), LocalAcquisitionError> {
        if self.is_cancelled() {
            Err(LocalAcquisitionError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for AcquisitionCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Inputs to one local acquisition. Paths are intentionally redacted from
/// `Debug`; they must not enter report DTOs or diagnostics through formatting.
pub struct LocalAcquisitionRequest<'a> {
    pub source: &'a Path,
    pub stage: &'a Path,
    pub jobs_root: &'a Path,
    pub limits: &'a CaptureLimits,
    pub symlinks: SymlinkPolicy,
    pub cancellation: &'a AcquisitionCancellation,
}

impl fmt::Debug for LocalAcquisitionRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalAcquisitionRequest")
            .field("source", &"<redacted>")
            .field("stage", &"<private>")
            .field("jobs_root", &"<private>")
            .field("limits", self.limits)
            .field("symlinks", &self.symlinks)
            .field("cancellation", self.cancellation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquiredEntryKind {
    Directory,
    RegularFile,
    SymbolicLink,
}

/// Internal publication-manifest material. It contains logical paths and
/// integrity digests, never a caller or private filesystem path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquiredEntry {
    pub logical_path: LogicalPath,
    pub kind: AcquiredEntryKind,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub publication_mode: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAcquisitionStatistics {
    pub entries: u64,
    pub files: u64,
    pub symbolic_links: u64,
    pub total_file_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAcquisitionResult {
    pub input_kind: PathInputKind,
    pub manifest_identity: Digest,
    pub entries: Vec<AcquiredEntry>,
    pub statistics: LocalAcquisitionStatistics,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAcquisitionIssueCode {
    Cancelled,
    InputUnavailable,
    InputUnstable,
    InvalidInputName,
    SourceJobsOverlap,
    StageUnavailable,
    StageNotPrivate,
    StageNotEmpty,
    SymlinkRejected,
    SpecialFileRejected,
    FilesystemCrossingRejected,
    EntryLimitExceeded,
    FileLimitExceeded,
    FileSizeLimitExceeded,
    TotalSizeLimitExceeded,
    DepthLimitExceeded,
    CopyFailed,
    StageVerificationFailed,
}

/// Bounded public-safe projection of a local acquisition failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAcquisitionIssue {
    pub code: LocalAcquisitionIssueCode,
    pub message: &'static str,
}

#[derive(Debug, Error)]
pub enum LocalAcquisitionError {
    #[error("local acquisition was cancelled")]
    Cancelled,
    #[error("local input is unavailable")]
    InputUnavailable,
    #[error("local input changed during acquisition")]
    InputUnstable,
    #[error("local input contains an invalid entry name")]
    InvalidInputName,
    #[error("local input overlaps the protected jobs tree")]
    SourceJobsOverlap,
    #[error("the private stage is unavailable")]
    StageUnavailable,
    #[error("the private stage does not satisfy owner-only constraints")]
    StageNotPrivate,
    #[error("the private stage is not fresh and empty")]
    StageNotEmpty,
    #[error("symbolic links are not allowed by this profile")]
    SymlinkRejected,
    #[error("special filesystem entries are not supported")]
    SpecialFileRejected,
    #[error("local acquisition cannot cross a filesystem boundary")]
    FilesystemCrossingRejected,
    #[error("local input exceeds the configured entry limit")]
    EntryLimitExceeded,
    #[error("local input exceeds the configured file limit")]
    FileLimitExceeded,
    #[error("a local input file exceeds the configured size limit")]
    FileSizeLimitExceeded,
    #[error("local input exceeds the configured total byte limit")]
    TotalSizeLimitExceeded,
    #[error("local input exceeds the configured depth limit")]
    DepthLimitExceeded,
    #[error("a local input entry could not be copied safely")]
    CopyFailed,
    #[error("the copied stage failed integrity verification")]
    StageVerificationFailed,
}

impl LocalAcquisitionError {
    pub const fn issue(&self) -> LocalAcquisitionIssue {
        use LocalAcquisitionError as Error;
        use LocalAcquisitionIssueCode as Code;
        let (code, message) = match self {
            Error::Cancelled => (Code::Cancelled, "acquisition cancelled"),
            Error::InputUnavailable => (Code::InputUnavailable, "input unavailable"),
            Error::InputUnstable => (Code::InputUnstable, "input changed during acquisition"),
            Error::InvalidInputName => (Code::InvalidInputName, "invalid input entry name"),
            Error::SourceJobsOverlap => (
                Code::SourceJobsOverlap,
                "input overlaps protected job storage",
            ),
            Error::StageUnavailable => (Code::StageUnavailable, "private stage unavailable"),
            Error::StageNotPrivate => (
                Code::StageNotPrivate,
                "private stage ownership or mode is invalid",
            ),
            Error::StageNotEmpty => (Code::StageNotEmpty, "private stage is not empty"),
            Error::SymlinkRejected => (Code::SymlinkRejected, "symbolic link rejected"),
            Error::SpecialFileRejected => (
                Code::SpecialFileRejected,
                "special filesystem entry rejected",
            ),
            Error::FilesystemCrossingRejected => (
                Code::FilesystemCrossingRejected,
                "filesystem boundary crossing rejected",
            ),
            Error::EntryLimitExceeded => (Code::EntryLimitExceeded, "input entry limit exceeded"),
            Error::FileLimitExceeded => (Code::FileLimitExceeded, "input file limit exceeded"),
            Error::FileSizeLimitExceeded => (
                Code::FileSizeLimitExceeded,
                "input file size limit exceeded",
            ),
            Error::TotalSizeLimitExceeded => (
                Code::TotalSizeLimitExceeded,
                "input total byte limit exceeded",
            ),
            Error::DepthLimitExceeded => (Code::DepthLimitExceeded, "input depth limit exceeded"),
            Error::CopyFailed => (Code::CopyFailed, "input copy failed"),
            Error::StageVerificationFailed => (
                Code::StageVerificationFailed,
                "copied stage verification failed",
            ),
        };
        LocalAcquisitionIssue { code, message }
    }
}

/// Copy one literal local file or directory into an already-created empty job
/// stage. The stage must be a direct or indirect child of `jobs_root`, owned by
/// the effective user, and mode `0700`.
pub fn acquire_local(
    request: LocalAcquisitionRequest<'_>,
) -> Result<LocalAcquisitionResult, LocalAcquisitionError> {
    acquire_local_copy(request)
}

/// Descriptor-captures the current contents of an existing private job
/// stage. This is the source of truth for post-action verification and action
/// rollback proofs; it never trusts the initial acquisition manifest.
pub fn capture_owned_stage(
    stage: &Path,
    jobs_root: &Path,
    input_kind: PathInputKind,
    limits: &CaptureLimits,
    symlinks: SymlinkPolicy,
    cancellation: &AcquisitionCancellation,
) -> Result<LocalAcquisitionResult, LocalAcquisitionError> {
    let stage = open_private_stage(stage, jobs_root, false)?;
    let root = fs::fstat(&stage).map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
    let mut capture = OwnedStageCapture {
        limits,
        symlinks,
        cancellation,
        root_device: StatKey::from_stat(&root)?.device,
        entries: Vec::new(),
        statistics: LocalAcquisitionStatistics::default(),
    };
    capture.capture_directory(&stage, &[], 0)?;
    capture
        .entries
        .sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok(LocalAcquisitionResult {
        input_kind,
        manifest_identity: manifest_identity(&capture.entries)?,
        entries: capture.entries,
        statistics: capture.statistics,
    })
}

struct OwnedStageCapture<'a> {
    limits: &'a CaptureLimits,
    symlinks: SymlinkPolicy,
    cancellation: &'a AcquisitionCancellation,
    root_device: u64,
    entries: Vec<AcquiredEntry>,
    statistics: LocalAcquisitionStatistics,
}

impl OwnedStageCapture<'_> {
    fn capture_directory(
        &mut self,
        directory: &OwnedFd,
        parent: &[PathSegment],
        depth: usize,
    ) -> Result<(), LocalAcquisitionError> {
        self.cancellation.check()?;
        if depth > self.limits.max_depth || depth > MAX_SAFE_RECURSION_DEPTH {
            return Err(LocalAcquisitionError::DepthLimitExceeded);
        }
        let before = fs::fstat(directory).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        let before_key = StatKey::from_stat(&before)?;
        if before_key.device != self.root_device {
            return Err(LocalAcquisitionError::FilesystemCrossingRejected);
        }
        let remaining = self
            .limits
            .max_entries
            .checked_sub(self.statistics.entries)
            .ok_or(LocalAcquisitionError::EntryLimitExceeded)?;
        let entries = enumerate(directory, remaining)?;
        self.statistics.entries = self
            .statistics
            .entries
            .checked_add(
                u64::try_from(entries.len())
                    .map_err(|_| LocalAcquisitionError::EntryLimitExceeded)?,
            )
            .ok_or(LocalAcquisitionError::EntryLimitExceeded)?;
        for entry in &entries {
            self.cancellation.check()?;
            if entry.stat.device != self.root_device {
                return Err(LocalAcquisitionError::FilesystemCrossingRejected);
            }
            let mut logical = parent.to_vec();
            logical.push(entry.segment.clone());
            if entry.stat.file_type.is_dir() {
                let child = fs::openat(
                    directory,
                    entry.name.as_c_str(),
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )
                .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                ensure_same_key(
                    entry.stat(),
                    &fs::fstat(&child).map_err(|_| LocalAcquisitionError::InputUnstable)?,
                )?;
                self.entries.push(AcquiredEntry {
                    logical_path: logical_path(logical.clone())?,
                    kind: AcquiredEntryKind::Directory,
                    byte_len: 0,
                    content_digest: Digest::sha256([]),
                    publication_mode: 0o755,
                });
                self.capture_directory(&child, &logical, depth + 1)?;
            } else if entry.stat.file_type.is_file() {
                if entry.stat.link_count != 1 {
                    return Err(LocalAcquisitionError::StageVerificationFailed);
                }
                let child = fs::openat(
                    directory,
                    entry.name.as_c_str(),
                    SOURCE_FILE_FLAGS,
                    Mode::empty(),
                )
                .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                ensure_same_key(
                    entry.stat(),
                    &fs::fstat(&child).map_err(|_| LocalAcquisitionError::InputUnstable)?,
                )?;
                let (byte_len, content_digest) = hash_file(
                    File::from(
                        child
                            .try_clone()
                            .map_err(|_| LocalAcquisitionError::InputUnstable)?,
                    ),
                    self.cancellation,
                )?;
                let after = fs::fstat(&child).map_err(|_| LocalAcquisitionError::InputUnstable)?;
                ensure_stable(&entry.raw, &after)?;
                let expected_length = u64::try_from(entry.stat.byte_len)
                    .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                if byte_len != expected_length {
                    return Err(LocalAcquisitionError::InputUnstable);
                }
                if byte_len > self.limits.max_file_bytes {
                    return Err(LocalAcquisitionError::FileSizeLimitExceeded);
                }
                if self.statistics.files >= self.limits.max_files {
                    return Err(LocalAcquisitionError::FileLimitExceeded);
                }
                self.statistics.total_file_bytes = self
                    .statistics
                    .total_file_bytes
                    .checked_add(byte_len)
                    .filter(|total| *total <= self.limits.max_total_bytes)
                    .ok_or(LocalAcquisitionError::TotalSizeLimitExceeded)?;
                self.statistics.files += 1;
                self.entries.push(AcquiredEntry {
                    logical_path: logical_path(logical)?,
                    kind: AcquiredEntryKind::RegularFile,
                    byte_len,
                    content_digest,
                    publication_mode: if entry.stat.mode & 0o111 == 0 {
                        0o644
                    } else {
                        0o755
                    },
                });
            } else if entry.stat.file_type.is_symlink() {
                if self.symlinks == SymlinkPolicy::Reject {
                    return Err(LocalAcquisitionError::SymlinkRejected);
                }
                let target = fs::readlinkat(directory, entry.name.as_c_str(), Vec::new())
                    .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                let after = fs::statat(directory, entry.name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                ensure_same_key(entry.stat(), &after)?;
                self.statistics.symbolic_links += 1;
                self.entries.push(AcquiredEntry {
                    logical_path: logical_path(logical)?,
                    kind: AcquiredEntryKind::SymbolicLink,
                    byte_len: u64::try_from(target.as_bytes().len())
                        .map_err(|_| LocalAcquisitionError::EntryLimitExceeded)?,
                    content_digest: Digest::sha256(target.as_bytes()),
                    publication_mode: 0o777,
                });
            } else {
                return Err(LocalAcquisitionError::SpecialFileRejected);
            }
        }
        let permitted =
            u64::try_from(entries.len()).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        let after_entries =
            enumerate(directory, permitted).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        let after = fs::fstat(directory).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        if entries != after_entries {
            return Err(LocalAcquisitionError::InputUnstable);
        }
        ensure_stable(&before, &after)
    }
}

fn acquire_local_copy(
    request: LocalAcquisitionRequest<'_>,
) -> Result<LocalAcquisitionResult, LocalAcquisitionError> {
    request.cancellation.check()?;
    let root_stat = fs::statat(fs::CWD, request.source, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| LocalAcquisitionError::InputUnavailable)?;
    let root_kind = FileType::from_raw_mode(root_stat.st_mode);
    if root_kind.is_symlink() {
        return Err(LocalAcquisitionError::SymlinkRejected);
    }
    if !root_kind.is_file() && !root_kind.is_dir() {
        return Err(LocalAcquisitionError::SpecialFileRejected);
    }

    reject_path_overlap(request.source, request.stage, request.jobs_root)?;
    let stage = open_private_empty_stage(request.stage, request.jobs_root)?;
    let root_key = StatKey::from_stat(&root_stat)?;
    let mut state = CopyState {
        limits: request.limits,
        symlinks: request.symlinks,
        cancellation: request.cancellation,
        root_device: root_key.device,
        entries: Vec::new(),
        statistics: LocalAcquisitionStatistics::default(),
    };

    let input_kind = if root_kind.is_dir() {
        let source = fs::open(request.source, DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| LocalAcquisitionError::InputUnavailable)?;
        ensure_same_entry(
            &root_stat,
            &fs::fstat(&source).map_err(|_| LocalAcquisitionError::InputUnstable)?,
        )?;
        reject_jobs_ancestry(&source, request.jobs_root)?;
        reject_jobs_descendant(&source, request.jobs_root)?;
        state.copy_directory(&source, &stage, &[], 0)?;
        let after = fs::fstat(&source).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        ensure_stable(&root_stat, &after)?;
        PathInputKind::Directory
    } else {
        let name = request
            .source
            .file_name()
            .filter(|name| !name.as_bytes().is_empty())
            .ok_or(LocalAcquisitionError::InvalidInputName)?;
        let segment =
            PathSegment::try_from(name).map_err(|_| LocalAcquisitionError::InvalidInputName)?;
        let parent_path = request
            .source
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = fs::open(parent_path, SEARCH_DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| LocalAcquisitionError::InputUnavailable)?;
        reject_jobs_ancestry(&parent, request.jobs_root)?;
        let before = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| LocalAcquisitionError::InputUnstable)?;
        ensure_stable(&root_stat, &before)?;
        let source = fs::openat(&parent, name, SOURCE_FILE_FLAGS, Mode::empty())
            .map_err(|_| LocalAcquisitionError::InputUnavailable)?;
        ensure_same_entry(
            &before,
            &fs::fstat(&source).map_err(|_| LocalAcquisitionError::InputUnstable)?,
        )?;
        state.copy_regular_file(source, &stage, name, vec![segment], before)?;
        let after = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| LocalAcquisitionError::InputUnstable)?;
        ensure_stable(&root_stat, &after)?;
        PathInputKind::File
    };

    request.cancellation.check()?;
    let final_root = fs::statat(fs::CWD, request.source, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| LocalAcquisitionError::InputUnstable)?;
    ensure_stable(&root_stat, &final_root)?;
    state
        .entries
        .sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    let manifest_identity = manifest_identity(&state.entries)?;
    verify_stage(&stage, &state.entries, request.cancellation)?;
    Ok(LocalAcquisitionResult {
        input_kind,
        manifest_identity,
        entries: state.entries,
        statistics: state.statistics,
    })
}

fn reject_path_overlap(
    source: &Path,
    stage: &Path,
    jobs_root: &Path,
) -> Result<(), LocalAcquisitionError> {
    let source =
        std::fs::canonicalize(source).map_err(|_| LocalAcquisitionError::InputUnavailable)?;
    let stage =
        std::fs::canonicalize(stage).map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    let jobs =
        std::fs::canonicalize(jobs_root).map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    if !stage.starts_with(&jobs) || paths_overlap(&source, &jobs) || paths_overlap(&source, &stage)
    {
        return Err(LocalAcquisitionError::SourceJobsOverlap);
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn open_private_empty_stage(
    stage: &Path,
    jobs_root: &Path,
) -> Result<OwnedFd, LocalAcquisitionError> {
    open_private_stage(stage, jobs_root, true)
}

fn open_private_stage(
    stage: &Path,
    jobs_root: &Path,
    require_empty: bool,
) -> Result<OwnedFd, LocalAcquisitionError> {
    let stage_fd = fs::open(stage, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    let stat = fs::fstat(&stage_fd).map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    let mode = checked_u64(stat.st_mode).map_err(|_| LocalAcquisitionError::StageNotPrivate)?;
    if stat.st_uid != geteuid().as_raw() || mode & 0o777 != 0o700 {
        return Err(LocalAcquisitionError::StageNotPrivate);
    }
    let jobs_fd = fs::open(jobs_root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    if !descriptor_is_beneath(&stage_fd, &jobs_fd)? {
        return Err(LocalAcquisitionError::SourceJobsOverlap);
    }
    if require_empty && !enumerate(&stage_fd, u64::MAX)?.is_empty() {
        return Err(LocalAcquisitionError::StageNotEmpty);
    }
    Ok(stage_fd)
}

fn descriptor_is_beneath(
    child: &OwnedFd,
    ancestor: &OwnedFd,
) -> Result<bool, LocalAcquisitionError> {
    let ancestor = Identity::from_stat(
        &fs::fstat(ancestor).map_err(|_| LocalAcquisitionError::StageUnavailable)?,
    )?;
    let mut current = child
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    for _ in 0..4096 {
        let current_identity = Identity::from_stat(
            &fs::fstat(&current).map_err(|_| LocalAcquisitionError::StageUnavailable)?,
        )?;
        if current_identity == ancestor {
            return Ok(true);
        }
        let parent = fs::openat(&current, "..", SEARCH_DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| LocalAcquisitionError::StageUnavailable)?;
        let parent_identity = Identity::from_stat(
            &fs::fstat(&parent).map_err(|_| LocalAcquisitionError::StageUnavailable)?,
        )?;
        if parent_identity == current_identity {
            return Ok(false);
        }
        current = parent;
    }
    Err(LocalAcquisitionError::StageUnavailable)
}

fn reject_jobs_ancestry(
    source_or_parent: &OwnedFd,
    jobs_root: &Path,
) -> Result<(), LocalAcquisitionError> {
    let jobs = fs::open(jobs_root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    if descriptor_is_beneath(source_or_parent, &jobs)? {
        Err(LocalAcquisitionError::SourceJobsOverlap)
    } else {
        Ok(())
    }
}

fn reject_jobs_descendant(source: &OwnedFd, jobs_root: &Path) -> Result<(), LocalAcquisitionError> {
    let jobs = fs::open(jobs_root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|_| LocalAcquisitionError::StageUnavailable)?;
    if descriptor_is_beneath(&jobs, source)? {
        Err(LocalAcquisitionError::SourceJobsOverlap)
    } else {
        Ok(())
    }
}

struct CopyState<'a> {
    limits: &'a CaptureLimits,
    symlinks: SymlinkPolicy,
    cancellation: &'a AcquisitionCancellation,
    root_device: u64,
    entries: Vec<AcquiredEntry>,
    statistics: LocalAcquisitionStatistics,
}

impl CopyState<'_> {
    fn copy_directory(
        &mut self,
        source: &OwnedFd,
        destination: &OwnedFd,
        parent: &[PathSegment],
        depth: usize,
    ) -> Result<(), LocalAcquisitionError> {
        self.cancellation.check()?;
        if depth > self.limits.max_depth || depth > MAX_SAFE_RECURSION_DEPTH {
            return Err(LocalAcquisitionError::DepthLimitExceeded);
        }
        let before = fs::fstat(source).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        let before_key = StatKey::from_stat(&before)?;
        self.require_root_device(&before_key)?;
        let remaining = self
            .limits
            .max_entries
            .checked_sub(self.statistics.entries)
            .ok_or(LocalAcquisitionError::EntryLimitExceeded)?;
        let entries = enumerate(source, remaining)?;
        let visible_entry_count = entries.len();
        self.statistics.entries = self
            .statistics
            .entries
            .checked_add(
                u64::try_from(visible_entry_count)
                    .map_err(|_| LocalAcquisitionError::EntryLimitExceeded)?,
            )
            .ok_or(LocalAcquisitionError::EntryLimitExceeded)?;

        for entry in &entries {
            self.cancellation.check()?;
            let mut logical = parent.to_vec();
            logical.push(entry.segment.clone());
            self.require_root_device(entry.stat())?;
            if entry.stat.file_type.is_dir() {
                fs::mkdirat(
                    destination,
                    entry.name.as_c_str(),
                    Mode::from_raw_mode(0o700),
                )
                .map_err(|_| LocalAcquisitionError::CopyFailed)?;
                fs::chmodat(
                    destination,
                    entry.name.as_c_str(),
                    Mode::from_raw_mode(0o700),
                    AtFlags::empty(),
                )
                .map_err(|_| LocalAcquisitionError::CopyFailed)?;
                let source_child = fs::openat(
                    source,
                    entry.name.as_c_str(),
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )
                .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                ensure_same_key(
                    entry.stat(),
                    &fs::fstat(&source_child).map_err(|_| LocalAcquisitionError::InputUnstable)?,
                )?;
                let destination_child = fs::openat(
                    destination,
                    entry.name.as_c_str(),
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )
                .map_err(|_| LocalAcquisitionError::CopyFailed)?;
                self.entries.push(AcquiredEntry {
                    logical_path: logical_path(logical.clone())?,
                    kind: AcquiredEntryKind::Directory,
                    byte_len: 0,
                    content_digest: Digest::sha256([]),
                    publication_mode: 0o755,
                });
                self.copy_directory(&source_child, &destination_child, &logical, depth + 1)?;
            } else if entry.stat.file_type.is_file() {
                let source_child = fs::openat(
                    source,
                    entry.name.as_c_str(),
                    SOURCE_FILE_FLAGS,
                    Mode::empty(),
                )
                .map_err(|_| LocalAcquisitionError::InputUnstable)?;
                ensure_same_key(
                    entry.stat(),
                    &fs::fstat(&source_child).map_err(|_| LocalAcquisitionError::InputUnstable)?,
                )?;
                self.copy_regular_file(
                    source_child,
                    destination,
                    entry.name.as_c_str(),
                    logical,
                    entry.raw,
                )?;
            } else if entry.stat.file_type.is_symlink() {
                self.copy_symlink(source, destination, entry, logical)?;
            } else {
                return Err(LocalAcquisitionError::SpecialFileRejected);
            }
        }

        let after_entries =
            enumerate(source, self.limits.max_entries).map_err(|error| match error {
                LocalAcquisitionError::EntryLimitExceeded => LocalAcquisitionError::InputUnstable,
                other => other,
            })?;
        let after = fs::fstat(source).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        if entries != after_entries {
            return Err(LocalAcquisitionError::InputUnstable);
        }
        ensure_stable(&before, &after)
    }

    fn copy_regular_file(
        &mut self,
        source: OwnedFd,
        destination_parent: &OwnedFd,
        destination_name: impl rustix::path::Arg,
        logical: Vec<PathSegment>,
        before: Stat,
    ) -> Result<(), LocalAcquisitionError> {
        self.cancellation.check()?;
        let before_key = StatKey::from_stat(&before)?;
        self.require_root_device(&before_key)?;
        let byte_len =
            u64::try_from(before_key.byte_len).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        if byte_len > self.limits.max_file_bytes {
            return Err(LocalAcquisitionError::FileSizeLimitExceeded);
        }
        if self.statistics.files >= self.limits.max_files {
            return Err(LocalAcquisitionError::FileLimitExceeded);
        }
        let total = self
            .statistics
            .total_file_bytes
            .checked_add(byte_len)
            .ok_or(LocalAcquisitionError::TotalSizeLimitExceeded)?;
        if total > self.limits.max_total_bytes {
            return Err(LocalAcquisitionError::TotalSizeLimitExceeded);
        }

        let destination_fd = fs::openat(
            destination_parent,
            destination_name,
            DESTINATION_FILE_FLAGS,
            Mode::from_raw_mode(if before_key.mode & 0o111 == 0 {
                0o600
            } else {
                0o700
            }),
        )
        .map_err(|_| LocalAcquisitionError::CopyFailed)?;
        fs::fchmod(
            &destination_fd,
            Mode::from_raw_mode(if before_key.mode & 0o111 == 0 {
                0o600
            } else {
                0o700
            }),
        )
        .map_err(|_| LocalAcquisitionError::CopyFailed)?;
        let mut source = File::from(source);
        let mut destination = File::from(destination_fd);
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        loop {
            self.cancellation.check()?;
            let read = source
                .read(&mut buffer)
                .map_err(|_| LocalAcquisitionError::InputUnstable)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).map_err(|_| LocalAcquisitionError::InputUnstable)?)
                .ok_or(LocalAcquisitionError::FileSizeLimitExceeded)?;
            if copied > byte_len || copied > self.limits.max_file_bytes {
                return Err(LocalAcquisitionError::InputUnstable);
            }
            hasher.update(&buffer[..read]);
            destination
                .write_all(&buffer[..read])
                .map_err(|_| LocalAcquisitionError::CopyFailed)?;
        }
        destination
            .sync_all()
            .map_err(|_| LocalAcquisitionError::CopyFailed)?;
        let after = fs::fstat(&source).map_err(|_| LocalAcquisitionError::InputUnstable)?;
        ensure_stable(&before, &after)?;
        if copied != byte_len {
            return Err(LocalAcquisitionError::InputUnstable);
        }
        let digest = Digest::from_array(hasher.finalize().into());
        drop(destination);
        let destination_read = fs::openat(
            destination_parent,
            path_name(&logical)?,
            SOURCE_FILE_FLAGS,
            Mode::empty(),
        );
        // For nested files `path_name` is exactly the already-open parent's
        // terminal entry; for root files it is the sole logical segment.
        let destination_read =
            destination_read.map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
        let verified = hash_file(File::from(destination_read), self.cancellation)?;
        if verified.0 != byte_len || verified.1 != digest {
            return Err(LocalAcquisitionError::StageVerificationFailed);
        }

        self.statistics.files += 1;
        self.statistics.total_file_bytes = total;
        self.entries.push(AcquiredEntry {
            logical_path: logical_path(logical)?,
            kind: AcquiredEntryKind::RegularFile,
            byte_len,
            content_digest: digest,
            publication_mode: if before_key.mode & 0o111 == 0 {
                0o644
            } else {
                0o755
            },
        });
        Ok(())
    }

    fn copy_symlink(
        &mut self,
        source_parent: &OwnedFd,
        destination_parent: &OwnedFd,
        entry: &Entry,
        logical: Vec<PathSegment>,
    ) -> Result<(), LocalAcquisitionError> {
        if self.symlinks == SymlinkPolicy::Reject {
            return Err(LocalAcquisitionError::SymlinkRejected);
        }
        let target = fs::readlinkat(source_parent, entry.name.as_c_str(), Vec::new())
            .map_err(|_| LocalAcquisitionError::InputUnstable)?;
        let after = fs::statat(
            source_parent,
            entry.name.as_c_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| LocalAcquisitionError::InputUnstable)?;
        ensure_same_key(entry.stat(), &after)?;
        fs::symlinkat(target.as_c_str(), destination_parent, entry.name.as_c_str())
            .map_err(|_| LocalAcquisitionError::CopyFailed)?;
        let destination_target =
            fs::readlinkat(destination_parent, entry.name.as_c_str(), Vec::new())
                .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
        if destination_target.as_bytes() != target.as_bytes() {
            return Err(LocalAcquisitionError::StageVerificationFailed);
        }
        let byte_len = u64::try_from(target.as_bytes().len())
            .map_err(|_| LocalAcquisitionError::EntryLimitExceeded)?;
        self.statistics.symbolic_links += 1;
        self.entries.push(AcquiredEntry {
            logical_path: logical_path(logical)?,
            kind: AcquiredEntryKind::SymbolicLink,
            byte_len,
            content_digest: Digest::sha256(target.as_bytes()),
            publication_mode: 0o777,
        });
        Ok(())
    }

    fn require_root_device(&self, stat: &StatKey) -> Result<(), LocalAcquisitionError> {
        if stat.device == self.root_device {
            Ok(())
        } else {
            Err(LocalAcquisitionError::FilesystemCrossingRejected)
        }
    }
}

fn path_name(logical: &[PathSegment]) -> Result<CString, LocalAcquisitionError> {
    let terminal = logical
        .last()
        .ok_or(LocalAcquisitionError::InvalidInputName)?;
    CString::new(terminal.as_slice()).map_err(|_| LocalAcquisitionError::InvalidInputName)
}

fn logical_path(segments: Vec<PathSegment>) -> Result<LogicalPath, LocalAcquisitionError> {
    LogicalPath::new(segments).map_err(|_| LocalAcquisitionError::InvalidInputName)
}

fn hash_file(
    mut file: File,
    cancellation: &AcquisitionCancellation,
) -> Result<(u64, Digest), LocalAcquisitionError> {
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation.check()?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(
                u64::try_from(read).map_err(|_| LocalAcquisitionError::StageVerificationFailed)?,
            )
            .ok_or(LocalAcquisitionError::StageVerificationFailed)?;
        hasher.update(&buffer[..read]);
    }
    Ok((length, Digest::from_array(hasher.finalize().into())))
}

fn verify_stage(
    stage: &OwnedFd,
    expected: &[AcquiredEntry],
    cancellation: &AcquisitionCancellation,
) -> Result<(), LocalAcquisitionError> {
    let mut observed = Vec::new();
    collect_stage(stage, &[], &mut observed, cancellation, 0).map_err(|error| match error {
        LocalAcquisitionError::Cancelled => LocalAcquisitionError::Cancelled,
        _ => LocalAcquisitionError::StageVerificationFailed,
    })?;
    observed.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    if observed == expected {
        Ok(())
    } else {
        Err(LocalAcquisitionError::StageVerificationFailed)
    }
}

fn collect_stage(
    directory: &OwnedFd,
    parent: &[PathSegment],
    entries: &mut Vec<AcquiredEntry>,
    cancellation: &AcquisitionCancellation,
    depth: usize,
) -> Result<(), LocalAcquisitionError> {
    if depth > MAX_SAFE_RECURSION_DEPTH {
        return Err(LocalAcquisitionError::StageVerificationFailed);
    }
    for entry in enumerate(directory, u64::MAX)? {
        cancellation.check()?;
        let mut logical = parent.to_vec();
        logical.push(entry.segment.clone());
        if entry.stat.file_type.is_dir() {
            entries.push(AcquiredEntry {
                logical_path: logical_path(logical.clone())?,
                kind: AcquiredEntryKind::Directory,
                byte_len: 0,
                content_digest: Digest::sha256([]),
                publication_mode: 0o755,
            });
            let child = fs::openat(
                directory,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
            collect_stage(&child, &logical, entries, cancellation, depth + 1)?;
        } else if entry.stat.file_type.is_file() {
            let child = fs::openat(
                directory,
                entry.name.as_c_str(),
                SOURCE_FILE_FLAGS,
                Mode::empty(),
            )
            .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
            let (byte_len, digest) = hash_file(File::from(child), cancellation)?;
            entries.push(AcquiredEntry {
                logical_path: logical_path(logical)?,
                kind: AcquiredEntryKind::RegularFile,
                byte_len,
                content_digest: digest,
                publication_mode: if entry.stat.mode & 0o111 == 0 {
                    0o644
                } else {
                    0o755
                },
            });
        } else if entry.stat.file_type.is_symlink() {
            let target = fs::readlinkat(directory, entry.name.as_c_str(), Vec::new())
                .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
            entries.push(AcquiredEntry {
                logical_path: logical_path(logical)?,
                kind: AcquiredEntryKind::SymbolicLink,
                byte_len: u64::try_from(target.as_bytes().len())
                    .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?,
                content_digest: Digest::sha256(target.as_bytes()),
                publication_mode: 0o777,
            });
        } else {
            return Err(LocalAcquisitionError::StageVerificationFailed);
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct Entry {
    name: CString,
    segment: PathSegment,
    stat: StatKey,
    raw: Stat,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.segment == other.segment && self.stat == other.stat
    }
}

impl Eq for Entry {}

impl Entry {
    fn stat(&self) -> &StatKey {
        &self.stat
    }
}

fn enumerate(directory: &OwnedFd, permitted: u64) -> Result<Vec<Entry>, LocalAcquisitionError> {
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut stream =
        Dir::read_from(directory).map_err(|_| LocalAcquisitionError::InputUnavailable)?;
    for item in &mut stream {
        let item = item.map_err(|_| LocalAcquisitionError::InputUnstable)?;
        let name = item.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if u64::try_from(entries.len()).map_or(true, |length| length >= permitted) {
            return Err(LocalAcquisitionError::EntryLimitExceeded);
        }
        let owned = name.to_owned();
        if !names.insert(owned.clone()) {
            return Err(LocalAcquisitionError::InputUnstable);
        }
        let segment = PathSegment::try_from(OsStr::from_bytes(name.to_bytes()))
            .map_err(|_| LocalAcquisitionError::InvalidInputName)?;
        let stat = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| LocalAcquisitionError::InputUnstable)?;
        entries.push(Entry {
            name: owned,
            segment,
            stat: StatKey::from_stat(&stat)?,
            raw: stat,
        });
    }
    entries.sort_by(|left, right| left.segment.cmp(&right.segment));
    Ok(entries)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StatKey {
    device: u64,
    inode: u64,
    mode: u64,
    byte_len: i64,
    link_count: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
    file_type: FileType,
}

impl StatKey {
    fn from_stat(stat: &Stat) -> Result<Self, LocalAcquisitionError> {
        Ok(Self {
            device: checked_u64(stat.st_dev)?,
            inode: checked_u64(stat.st_ino)?,
            mode: checked_u64(stat.st_mode)?,
            byte_len: checked_i64(stat.st_size)?,
            link_count: checked_u64(stat.st_nlink)?,
            modified_seconds: checked_i64(stat.st_mtime)?,
            modified_nanoseconds: checked_u64(stat.st_mtime_nsec)?,
            changed_seconds: checked_i64(stat.st_ctime)?,
            changed_nanoseconds: checked_u64(stat.st_ctime_nsec)?,
            file_type: FileType::from_raw_mode(stat.st_mode),
        })
    }

    fn identity(&self) -> Identity {
        Identity {
            device: self.device,
            inode: self.inode,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn from_stat(stat: &Stat) -> Result<Self, LocalAcquisitionError> {
        Ok(StatKey::from_stat(stat)?.identity())
    }
}

fn ensure_same_entry(expected: &Stat, actual: &Stat) -> Result<(), LocalAcquisitionError> {
    let expected = StatKey::from_stat(expected)?;
    ensure_same_key(&expected, actual)
}

fn ensure_same_key(expected: &StatKey, actual: &Stat) -> Result<(), LocalAcquisitionError> {
    let actual = StatKey::from_stat(actual)?;
    if expected.identity() == actual.identity() && expected.file_type == actual.file_type {
        Ok(())
    } else {
        Err(LocalAcquisitionError::InputUnstable)
    }
}

fn ensure_stable(expected: &Stat, actual: &Stat) -> Result<(), LocalAcquisitionError> {
    if StatKey::from_stat(expected)? == StatKey::from_stat(actual)? {
        Ok(())
    } else {
        Err(LocalAcquisitionError::InputUnstable)
    }
}

#[allow(clippy::useless_conversion)]
fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, LocalAcquisitionError> {
    value
        .try_into()
        .map_err(|_| LocalAcquisitionError::InputUnstable)
}

#[allow(clippy::useless_conversion)]
fn checked_i64<T: TryInto<i64>>(value: T) -> Result<i64, LocalAcquisitionError> {
    value
        .try_into()
        .map_err(|_| LocalAcquisitionError::InputUnstable)
}

#[derive(Serialize)]
struct ManifestInput<'a> {
    schema: &'static str,
    entries: &'a [AcquiredEntry],
}

fn manifest_identity(entries: &[AcquiredEntry]) -> Result<Digest, LocalAcquisitionError> {
    let bytes = serde_json::to_vec(&ManifestInput {
        schema: "file-guardian-publication-manifest/2",
        entries,
    })
    .map_err(|_| LocalAcquisitionError::StageVerificationFailed)?;
    Ok(Digest::sha256(bytes))
}
