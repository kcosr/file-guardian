use super::workspace::FilesystemIdentity;
use super::{InvocationWorkspace, StoredObject, WorkspaceError};
use crate::domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactManifest, FileTimestamp, LogicalPath,
    ManifestError, ObjectId, PathSegment, PhysicalSubject, Provenance, SourceFileType,
    SourceIdentity, SubjectId,
};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use thiserror::Error;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

// An ancestry walk only needs search access. Requesting read access here would
// incorrectly reject inputs below execute/search-only directories even though
// the input itself can be opened and captured safely.
#[cfg(any(target_os = "linux", target_os = "android"))]
const ANCESTRY_DIRECTORY_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

// Darwin exposes O_SEARCH as O_EXEC | O_DIRECTORY. rustix intentionally does
// not expose those access modes, so retain the Darwin O_EXEC bit explicitly
// while continuing to use rustix's descriptor-relative openat wrapper.
#[cfg(target_vendor = "apple")]
const ANCESTRY_DIRECTORY_FLAGS: OFlags = OFlags::from_bits_retain(0x4000_0000)
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

// The supported release platforms use the search-only variants above. Keep a
// conservative compile-time fallback for other Unix targets.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const ANCESTRY_DIRECTORY_FLAGS: OFlags = DIRECTORY_FLAGS;
const MAX_ANCESTOR_DIRECTORIES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    pub max_entries: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_entries: 200_000,
            max_files: 100_000,
            max_file_bytes: 1024 * 1024 * 1024,
            max_total_bytes: 10 * 1024 * 1024 * 1024,
            max_depth: 64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub input_kind: SnapshotInputKind,
    pub manifest: ArtifactManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotInputKind {
    File,
    Directory,
}

pub struct Snapshotter<'a> {
    workspace: &'a InvocationWorkspace,
    limits: CaptureLimits,
}

impl<'a> Snapshotter<'a> {
    pub fn new(workspace: &'a InvocationWorkspace, limits: CaptureLimits) -> Self {
        Self { workspace, limits }
    }

    /// Captures one literal regular file or directory without following a link
    /// at the input or below it. Descendants are resolved only relative to
    /// already-open directory descriptors.
    pub fn capture(&self, input: &Path) -> Result<Snapshot, CaptureError> {
        let initial = fs::statat(fs::CWD, input, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| CaptureError::InputUnavailable(error.kind()))?;
        let kind = FileType::from_raw_mode(initial.st_mode);
        if kind.is_symlink() {
            return Err(CaptureError::SymlinkRejected);
        }

        let initial_key = StatKey::from_stat(&initial)?;
        if self.workspace.contains_identity(initial_key.identity()) {
            return Err(CaptureError::WorkspaceTraversalRejected);
        }
        let mut state = CaptureState {
            workspace: self.workspace,
            limits: self.limits,
            root_device: initial_key.device,
            entries: 0,
            files: 0,
            bytes: 0,
            subjects: Vec::new(),
            artifacts: Vec::new(),
            created_objects: Vec::new(),
        };

        let result = (|| {
            if kind.is_dir() {
                let root = fs::open(input, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|error| CaptureError::InputUnavailable(error.kind()))?;
                let opened = fs::fstat(&root)
                    .map_err(|error| CaptureError::InputUnavailable(error.kind()))?;
                ensure_same_entry(&initial, &opened).map_err(|_| CaptureError::InputUnstable)?;
                reject_workspace_ancestry(self.workspace, &root)?;
                state.capture_directory(&root, &[], 0)?;
                let final_stat = fs::fstat(&root).map_err(|_| CaptureError::InputUnstable)?;
                ensure_stable(&opened, &final_stat).map_err(|_| CaptureError::InputUnstable)
            } else if kind.is_file() {
                let name = input
                    .file_name()
                    .filter(|name| !name.as_bytes().is_empty())
                    .ok_or(CaptureError::InvalidInputName)?;
                let segment =
                    PathSegment::try_from(name).map_err(|_| CaptureError::InvalidInputName)?;
                let parent_path = input
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let parent = fs::open(parent_path, ANCESTRY_DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|error| CaptureError::InputUnavailable(error.kind()))?;
                reject_workspace_ancestry(self.workspace, &parent)?;
                let parent_entry = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CaptureError::InputUnstable)?;
                ensure_same_entry(&initial, &parent_entry)
                    .map_err(|_| CaptureError::InputUnstable)?;
                let fd = fs::openat(&parent, name, FILE_FLAGS, Mode::empty())
                    .map_err(|error| CaptureError::InputUnavailable(error.kind()))?;
                let opened =
                    fs::fstat(&fd).map_err(|error| CaptureError::InputUnavailable(error.kind()))?;
                ensure_same_entry(&parent_entry, &opened)
                    .map_err(|_| CaptureError::InputUnstable)?;
                state.capture_file(fd, vec![segment], opened)?;
                validate_parent_entry(&parent, name, &initial)
            } else {
                Err(CaptureError::UnsupportedFileType)
            }?;

            validate_root_path(input, &initial)
        })();

        if let Err(error) = result {
            state.rollback_objects();
            return Err(error);
        }

        let manifest = match ArtifactManifest::new(state.subjects.clone(), state.artifacts.clone())
        {
            Ok(manifest) => manifest,
            Err(error) => {
                state.rollback_objects();
                return Err(CaptureError::Manifest(error));
            }
        };
        Ok(Snapshot {
            input_kind: if kind.is_dir() {
                SnapshotInputKind::Directory
            } else {
                SnapshotInputKind::File
            },
            manifest,
        })
    }
}

/// Proves that an opened input is not nested beneath any directory belonging
/// to this invocation. Walking `..` from descriptors avoids trusting a textual
/// path or canonicalization result that can be replaced during capture.
fn reject_workspace_ancestry(
    workspace: &InvocationWorkspace,
    start: &OwnedFd,
) -> Result<(), CaptureError> {
    let mut current = start
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| CaptureError::WorkspaceAncestryUnavailable)?;
    for _ in 0..MAX_ANCESTOR_DIRECTORIES {
        let current_stat =
            fs::fstat(&current).map_err(|_| CaptureError::WorkspaceAncestryUnavailable)?;
        let current_identity = FilesystemIdentity::from_stat(&current_stat)
            .map_err(|_| CaptureError::InvalidFileMetadata)?;
        if workspace.contains_identity(current_identity) {
            return Err(CaptureError::WorkspaceTraversalRejected);
        }

        let parent = open_ancestry_parent(&current)
            .map_err(|_| CaptureError::WorkspaceAncestryUnavailable)?;
        let parent_stat =
            fs::fstat(&parent).map_err(|_| CaptureError::WorkspaceAncestryUnavailable)?;
        let parent_identity = FilesystemIdentity::from_stat(&parent_stat)
            .map_err(|_| CaptureError::InvalidFileMetadata)?;
        if parent_identity == current_identity {
            return Ok(());
        }
        current = parent;
    }
    Err(CaptureError::WorkspaceAncestryLimitExceeded {
        limit: MAX_ANCESTOR_DIRECTORIES,
    })
}

fn open_ancestry_parent(directory: &OwnedFd) -> rustix::io::Result<OwnedFd> {
    fs::openat(directory, "..", ANCESTRY_DIRECTORY_FLAGS, Mode::empty())
}

struct CaptureState<'a> {
    workspace: &'a InvocationWorkspace,
    limits: CaptureLimits,
    root_device: u64,
    entries: u64,
    files: u64,
    bytes: u64,
    subjects: Vec<PhysicalSubject>,
    artifacts: Vec<Artifact>,
    created_objects: Vec<StoredObject>,
}

impl CaptureState<'_> {
    fn capture_directory(
        &mut self,
        directory: &OwnedFd,
        parent: &[PathSegment],
        depth: usize,
    ) -> Result<(), CaptureError> {
        if depth > self.limits.max_depth {
            return Err(CaptureError::DepthLimitExceeded {
                limit: self.limits.max_depth,
            });
        }
        let before_dir = fs::fstat(directory).map_err(|_| CaptureError::EnumerationFailure)?;
        let before_key = StatKey::from_stat(&before_dir)?;
        self.reject_workspace_identity(before_key.identity())?;
        if before_key.device != self.root_device {
            return Err(CaptureError::FilesystemCrossingRejected);
        }
        let remaining_entries = self.limits.max_entries.checked_sub(self.entries).ok_or(
            CaptureError::TraversalEntryLimitExceeded {
                limit: self.limits.max_entries,
            },
        )?;
        let entries = enumerate(directory, remaining_entries, self.limits.max_entries)?;
        self.entries = self
            .entries
            .checked_add(u64::try_from(entries.len()).map_err(|_| {
                CaptureError::TraversalEntryLimitExceeded {
                    limit: self.limits.max_entries,
                }
            })?)
            .ok_or(CaptureError::TraversalEntryLimitExceeded {
                limit: self.limits.max_entries,
            })?;
        for entry in &entries {
            let mut path = parent.to_vec();
            path.push(entry.segment.clone());
            let kind = entry.stat.file_type;
            if kind.is_symlink() {
                return Err(CaptureError::SymlinkRejected);
            }
            if entry.stat.device != self.root_device {
                return Err(CaptureError::FilesystemCrossingRejected);
            }
            self.reject_workspace_identity(entry.stat.identity())?;
            if kind.is_dir() {
                let child = fs::openat(
                    directory,
                    entry.name.as_c_str(),
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )
                .map_err(|_| CaptureError::EntryUnstable)?;
                let opened = fs::fstat(&child).map_err(|_| CaptureError::EntryUnstable)?;
                ensure_same_entry_key(entry.stat(), &opened)
                    .map_err(|_| CaptureError::EntryUnstable)?;
                self.capture_directory(&child, &path, depth + 1)?;
            } else if kind.is_file() {
                if entry.stat.link_count != 1 {
                    return Err(CaptureError::HardlinkRejected);
                }
                let child = fs::openat(directory, entry.name.as_c_str(), FILE_FLAGS, Mode::empty())
                    .map_err(|_| CaptureError::EntryUnstable)?;
                let opened = fs::fstat(&child).map_err(|_| CaptureError::EntryUnstable)?;
                ensure_same_entry_key(entry.stat(), &opened)
                    .map_err(|_| CaptureError::EntryUnstable)?;
                self.capture_file(child, path, opened)?;
            } else {
                return Err(CaptureError::UnsupportedFileType);
            }
        }

        // Re-enumeration remains independently bounded. If the directory grew
        // beyond the traversal budget after the initial enumeration, report
        // the mutation as instability rather than treating the changed tree as
        // the caller's original oversized input.
        let after_entries =
            match enumerate(directory, self.limits.max_entries, self.limits.max_entries) {
                Ok(entries) => entries,
                Err(CaptureError::TraversalEntryLimitExceeded { .. }) => {
                    return Err(CaptureError::DirectoryUnstable);
                }
                Err(error) => return Err(error),
            };
        let after_dir = fs::fstat(directory).map_err(|_| CaptureError::EnumerationFailure)?;
        if entries != after_entries || ensure_stable(&before_dir, &after_dir).is_err() {
            return Err(CaptureError::DirectoryUnstable);
        }
        Ok(())
    }

    fn capture_file(
        &mut self,
        fd: OwnedFd,
        path: Vec<PathSegment>,
        before: Stat,
    ) -> Result<(), CaptureError> {
        let before_key = StatKey::from_stat(&before)?;
        self.reject_workspace_identity(before_key.identity())?;
        if before_key.device != self.root_device {
            return Err(CaptureError::FilesystemCrossingRejected);
        }
        if before_key.link_count != 1 {
            return Err(CaptureError::HardlinkRejected);
        }
        let byte_len =
            u64::try_from(before_key.byte_len).map_err(|_| CaptureError::InvalidFileMetadata)?;
        if byte_len > self.limits.max_file_bytes {
            return Err(CaptureError::FileSizeLimitExceeded {
                limit: self.limits.max_file_bytes,
            });
        }
        if self.files >= self.limits.max_files {
            return Err(CaptureError::FileCountLimitExceeded {
                limit: self.limits.max_files,
            });
        }
        let expected_total =
            self.bytes
                .checked_add(byte_len)
                .ok_or(CaptureError::TotalSizeLimitExceeded {
                    limit: self.limits.max_total_bytes,
                })?;
        if expected_total > self.limits.max_total_bytes {
            return Err(CaptureError::TotalSizeLimitExceeded {
                limit: self.limits.max_total_bytes,
            });
        }

        let read_fd = fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| CaptureError::FileUnreadable)?;
        let mut file = File::from(read_fd);
        let stored = self
            .workspace
            .objects()
            .store(&mut file, self.limits.max_file_bytes)
            .map_err(map_store_error)?;
        let after = fs::fstat(&fd).map_err(|_| CaptureError::FileUnstable)?;
        if ensure_stable(&before, &after).is_err() || stored.byte_len != byte_len {
            self.workspace.objects().remove_if_created(&stored);
            return Err(CaptureError::FileUnstable);
        }

        self.files += 1;
        self.bytes = expected_total;
        let ordinal = self.files;
        let subject_id = SubjectId::from_suffix(format!("{ordinal:016x}"))
            .expect("ordinal is a safe identifier");
        let artifact_id = ArtifactId::from_suffix(format!("{ordinal:016x}"))
            .expect("ordinal is a safe identifier");
        let logical_path = LogicalPath::new(path).expect("enumerated segments form a path");
        let identity = source_identity(&before_key, stored.digest)?;
        let object_id: ObjectId = stored.id.clone();
        self.subjects.push(PhysicalSubject {
            id: subject_id.clone(),
            relative_path: logical_path.clone(),
            source_identity: identity,
            object_id: object_id.clone(),
            byte_len: stored.byte_len,
        });
        self.artifacts.push(Artifact {
            id: artifact_id,
            subject_id,
            object_id,
            kind: ArtifactKind::PhysicalFile,
            byte_len: stored.byte_len,
            content_digest: stored.digest,
            provenance: Provenance::Physical { logical_path },
        });
        self.created_objects.push(stored);
        Ok(())
    }

    fn rollback_objects(&self) {
        for object in &self.created_objects {
            self.workspace.objects().remove_if_created(object);
        }
    }

    fn reject_workspace_identity(&self, identity: FilesystemIdentity) -> Result<(), CaptureError> {
        if self.workspace.contains_identity(identity) {
            Err(CaptureError::WorkspaceTraversalRejected)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    name: std::ffi::CString,
    segment: PathSegment,
    stat: StatKey,
}

fn enumerate(
    directory: &OwnedFd,
    permitted_entries: u64,
    configured_limit: u64,
) -> Result<Vec<Entry>, CaptureError> {
    let mut entries = Vec::new();
    let mut stream = Dir::read_from(directory).map_err(|_| CaptureError::EnumerationFailure)?;
    for result in &mut stream {
        let entry = result.map_err(|_| CaptureError::EnumerationFailure)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if u64::try_from(entries.len()).map_or(true, |count| count >= permitted_entries) {
            return Err(CaptureError::TraversalEntryLimitExceeded {
                limit: configured_limit,
            });
        }
        let segment = PathSegment::try_from(OsStr::from_bytes(name.to_bytes()))
            .map_err(|_| CaptureError::InvalidInputName)?;
        let stat = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CaptureError::EntryUnstable)?;
        entries.push(Entry {
            name: name.to_owned(),
            segment,
            stat: StatKey::from_stat(&stat)?,
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
    fn from_stat(stat: &Stat) -> Result<Self, CaptureError> {
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

    fn identity(&self) -> FilesystemIdentity {
        FilesystemIdentity {
            device: self.device,
            inode: self.inode,
        }
    }
}

impl Entry {
    fn stat(&self) -> &StatKey {
        &self.stat
    }
}

fn ensure_same_entry(expected: &Stat, actual: &Stat) -> Result<(), ()> {
    let expected = StatKey::from_stat(expected).map_err(|_| ())?;
    let actual = StatKey::from_stat(actual).map_err(|_| ())?;
    if expected.identity() == actual.identity() && expected.file_type == actual.file_type {
        Ok(())
    } else {
        Err(())
    }
}

fn ensure_same_entry_key(expected: &StatKey, actual: &Stat) -> Result<(), ()> {
    let actual = StatKey::from_stat(actual).map_err(|_| ())?;
    if expected.identity() == actual.identity() && expected.file_type == actual.file_type {
        Ok(())
    } else {
        Err(())
    }
}

fn ensure_stable(expected: &Stat, actual: &Stat) -> Result<(), ()> {
    (StatKey::from_stat(expected).map_err(|_| ())? == StatKey::from_stat(actual).map_err(|_| ())?)
        .then_some(())
        .ok_or(())
}

fn validate_root_path(input: &Path, initial: &Stat) -> Result<(), CaptureError> {
    let final_path = fs::statat(fs::CWD, input, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CaptureError::InputUnstable)?;
    ensure_stable(initial, &final_path).map_err(|_| CaptureError::InputUnstable)
}

fn validate_parent_entry(
    parent: &OwnedFd,
    name: &OsStr,
    initial: &Stat,
) -> Result<(), CaptureError> {
    let final_entry = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CaptureError::InputUnstable)?;
    ensure_stable(initial, &final_entry).map_err(|_| CaptureError::InputUnstable)
}

fn source_identity(
    stat: &StatKey,
    digest: crate::domain::Digest,
) -> Result<SourceIdentity, CaptureError> {
    Ok(SourceIdentity {
        device: stat.device,
        inode: stat.inode,
        file_type: SourceFileType::RegularFile,
        byte_len: u64::try_from(stat.byte_len).map_err(|_| CaptureError::InvalidFileMetadata)?,
        link_count: stat.link_count,
        modified: Some(timestamp(stat.modified_seconds, stat.modified_nanoseconds)?),
        changed: Some(timestamp(stat.changed_seconds, stat.changed_nanoseconds)?),
        content_digest: digest,
    })
}

// rustix's platform Stat field aliases vary across Unix targets. This is a
// checked conversion on narrower/differently-signed targets and a no-op on
// targets whose libc already uses u64.
#[allow(clippy::useless_conversion)]
fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, CaptureError> {
    value
        .try_into()
        .map_err(|_| CaptureError::InvalidFileMetadata)
}

#[allow(clippy::useless_conversion)]
fn checked_i64<T: TryInto<i64>>(value: T) -> Result<i64, CaptureError> {
    value
        .try_into()
        .map_err(|_| CaptureError::InvalidFileMetadata)
}

fn timestamp(seconds: i64, nanoseconds: u64) -> Result<FileTimestamp, CaptureError> {
    let nanoseconds = u32::try_from(nanoseconds).map_err(|_| CaptureError::InvalidFileMetadata)?;
    FileTimestamp::new(seconds, nanoseconds).ok_or(CaptureError::InvalidFileMetadata)
}

fn map_store_error(error: WorkspaceError) -> CaptureError {
    match error {
        // The pre-read stat already rejected a file larger than the configured
        // limit. Reaching the store ceiling therefore means the open file grew
        // during capture and is an instability, not a caller size violation.
        WorkspaceError::ObjectTooLarge { .. } => CaptureError::FileUnstable,
        WorkspaceError::ReadSource(_) => CaptureError::FileUnreadable,
        other => CaptureError::Workspace(other),
    }
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("input is unavailable: {0:?}")]
    InputUnavailable(io::ErrorKind),
    #[error("input name cannot be represented safely")]
    InvalidInputName,
    #[error("input changed while it was opened")]
    InputUnstable,
    #[error("filesystem metadata cannot be represented safely")]
    InvalidFileMetadata,
    #[error("the input traverses the workspace root, invocation run directory, or fixed layout")]
    WorkspaceTraversalRejected,
    #[error("the input's directory ancestry could not be inspected safely")]
    WorkspaceAncestryUnavailable,
    #[error("the input's directory ancestry exceeds {limit} directories")]
    WorkspaceAncestryLimitExceeded { limit: usize },
    #[error("directory enumeration failed")]
    EnumerationFailure,
    #[error("an entry changed while it was opened")]
    EntryUnstable,
    #[error("a directory changed during capture")]
    DirectoryUnstable,
    #[error("a file changed during capture")]
    FileUnstable,
    #[error("a file could not be read")]
    FileUnreadable,
    #[error("symbolic links are not allowed")]
    SymlinkRejected,
    #[error("multiply-linked regular files are not allowed")]
    HardlinkRejected,
    #[error("special files are not allowed")]
    UnsupportedFileType,
    #[error("crossing onto another filesystem is not allowed")]
    FilesystemCrossingRejected,
    #[error("directory traversal entry count exceeds {limit}")]
    TraversalEntryLimitExceeded { limit: u64 },
    #[error("file count exceeds {limit}")]
    FileCountLimitExceeded { limit: u64 },
    #[error("file size exceeds {limit} bytes")]
    FileSizeLimitExceeded { limit: u64 },
    #[error("total input size exceeds {limit} bytes")]
    TotalSizeLimitExceeded { limit: u64 },
    #[error("directory depth exceeds {limit}")]
    DepthLimitExceeded { limit: usize },
    #[error("invocation workspace failed: {0}")]
    Workspace(#[from] WorkspaceError),
    #[error("captured manifest is invalid: {0}")]
    Manifest(#[from] ManifestError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RunId;
    use std::io::Read;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::{fs as stdfs, os::unix::net::UnixListener};
    use tempfile::TempDir;

    struct Fixture {
        root: TempDir,
        workspace: InvocationWorkspace,
    }

    impl Fixture {
        fn new(suffix: &str) -> Self {
            let root = TempDir::new().unwrap();
            let workspace_root = root.path().join("workspaces");
            stdfs::create_dir(&workspace_root).unwrap();
            stdfs::set_permissions(&workspace_root, stdfs::Permissions::from_mode(0o700)).unwrap();
            let workspace =
                InvocationWorkspace::create(&workspace_root, &RunId::from_suffix(suffix).unwrap())
                    .unwrap();
            Self { root, workspace }
        }

        fn input(&self) -> std::path::PathBuf {
            self.root.path().join("input")
        }

        fn capture(&self, limits: CaptureLimits) -> Result<Snapshot, CaptureError> {
            Snapshotter::new(&self.workspace, limits).capture(&self.input())
        }
    }

    #[test]
    fn captures_in_byte_path_order_without_mutating_source() {
        let fixture = Fixture::new("order");
        stdfs::create_dir(fixture.input()).unwrap();
        stdfs::write(fixture.input().join("z.txt"), b"last").unwrap();
        stdfs::write(fixture.input().join("a.txt"), b"first").unwrap();
        let before = stdfs::metadata(fixture.input().join("a.txt")).unwrap();

        let first = fixture.capture(CaptureLimits::default()).unwrap();
        let second = fixture.capture(CaptureLimits::default()).unwrap();

        assert_eq!(first.manifest, second.manifest);
        assert_eq!(
            first.manifest.subjects()[0].relative_path.to_string(),
            "a.txt"
        );
        assert_eq!(
            first.manifest.subjects()[1].relative_path.to_string(),
            "z.txt"
        );
        let after = stdfs::metadata(fixture.input().join("a.txt")).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(
            stdfs::read(fixture.input().join("a.txt")).unwrap(),
            b"first"
        );
    }

    #[test]
    fn immutable_object_survives_live_path_replacement() {
        let fixture = Fixture::new("replace");
        stdfs::create_dir(fixture.input()).unwrap();
        let live = fixture.input().join("artifact.txt");
        stdfs::write(&live, b"captured bytes").unwrap();
        let snapshot = fixture.capture(CaptureLimits::default()).unwrap();
        let object_id = &snapshot.manifest.artifacts()[0].object_id;

        stdfs::rename(&live, fixture.input().join("old.txt")).unwrap();
        stdfs::write(&live, b"replacement bytes").unwrap();

        let mut bytes = Vec::new();
        fixture
            .workspace
            .objects()
            .open(object_id)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"captured bytes");
    }

    #[test]
    fn root_path_replacement_fails_identity_revalidation() {
        let root = TempDir::new().unwrap();
        let input = root.path().join("input");
        stdfs::write(&input, b"original").unwrap();
        let initial = fs::statat(fs::CWD, &input, AtFlags::SYMLINK_NOFOLLOW).unwrap();
        stdfs::rename(&input, root.path().join("old")).unwrap();
        stdfs::write(&input, b"replacement").unwrap();
        assert!(matches!(
            validate_root_path(&input, &initial),
            Err(CaptureError::InputUnstable)
        ));
    }

    #[test]
    fn rejects_workspace_root_run_and_fixed_layout_directories_as_inputs() {
        let fixture = Fixture::new("self-capture");
        let workspace_root = fixture.root.path().join("workspaces");
        let run_path = workspace_root.join("run_self-capture");
        let snapshotter = Snapshotter::new(&fixture.workspace, CaptureLimits::default());

        assert!(matches!(
            snapshotter.capture(&workspace_root),
            Err(CaptureError::WorkspaceTraversalRejected)
        ));
        assert!(matches!(
            snapshotter.capture(&run_path),
            Err(CaptureError::WorkspaceTraversalRejected)
        ));
        for name in [
            "manifest",
            "objects",
            "analyzer-views",
            "archive-work",
            "action-journal",
            "quarantine",
            "tmp",
        ] {
            assert!(matches!(
                snapshotter.capture(&run_path.join(name)),
                Err(CaptureError::WorkspaceTraversalRejected)
            ));
        }
    }

    #[test]
    fn rejects_an_object_file_nested_beneath_the_workspace() {
        let fixture = Fixture::new("object-containment");
        stdfs::write(fixture.input(), b"captured once").unwrap();
        let first = fixture.capture(CaptureLimits::default()).unwrap();
        let object_path = fixture
            .root
            .path()
            .join("workspaces/run_object-containment/objects")
            .join(first.manifest.artifacts()[0].object_id.as_str());
        let snapshotter = Snapshotter::new(&fixture.workspace, CaptureLimits::default());

        assert!(matches!(
            snapshotter.capture(&object_path),
            Err(CaptureError::WorkspaceTraversalRejected)
        ));

        let sibling = fixture.root.path().join("sibling.txt");
        stdfs::write(&sibling, b"ordinary sibling").unwrap();
        assert!(snapshotter.capture(&sibling).is_ok());
    }

    #[test]
    fn accepts_a_literal_regular_file() {
        let fixture = Fixture::new("file");
        stdfs::write(fixture.input(), b"one file").unwrap();
        let snapshot = fixture.capture(CaptureLimits::default()).unwrap();
        assert_eq!(snapshot.manifest.subjects().len(), 1);
        assert_eq!(
            snapshot.manifest.subjects()[0].relative_path.to_string(),
            "input"
        );
    }

    #[test]
    fn captures_beneath_a_search_only_ancestor() {
        let fixture = Fixture::new("search-only-ancestor");
        let ancestor = fixture.root.path().join("search-only");
        let input = ancestor.join("leaf/input");
        let literal_file = ancestor.join("literal.txt");
        stdfs::create_dir_all(&input).unwrap();
        stdfs::write(input.join("artifact.txt"), b"capturable").unwrap();
        stdfs::write(&literal_file, b"literal file").unwrap();
        stdfs::set_permissions(&ancestor, stdfs::Permissions::from_mode(0o111)).unwrap();

        let input_fd = fs::open(&input, DIRECTORY_FLAGS, Mode::empty()).unwrap();
        let leaf_fd = open_ancestry_parent(&input_fd).unwrap();
        let ancestor_fd = open_ancestry_parent(&leaf_fd).unwrap();
        let ancestor_identity =
            FilesystemIdentity::from_stat(&fs::fstat(&ancestor_fd).unwrap()).unwrap();
        let expected_identity = FilesystemIdentity::from_stat(
            &fs::statat(fs::CWD, &ancestor, AtFlags::SYMLINK_NOFOLLOW).unwrap(),
        )
        .unwrap();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let used_search_only_flag = fs::fcntl_getfl(&ancestor_fd)
            .unwrap()
            .contains(OFlags::PATH);
        #[cfg(target_vendor = "apple")]
        let used_search_only_flag = fs::fcntl_getfl(&ancestor_fd)
            .unwrap()
            .contains(OFlags::from_bits_retain(0x4000_0000));
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        let used_search_only_flag = true;

        let capture =
            Snapshotter::new(&fixture.workspace, CaptureLimits::default()).capture(&input);
        let literal_capture =
            Snapshotter::new(&fixture.workspace, CaptureLimits::default()).capture(&literal_file);
        stdfs::set_permissions(&ancestor, stdfs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(ancestor_identity, expected_identity);
        assert!(used_search_only_flag);
        let snapshot = capture.unwrap();
        assert_eq!(snapshot.manifest.artifacts().len(), 1);
        assert_eq!(literal_capture.unwrap().manifest.artifacts().len(), 1);
    }

    #[test]
    fn rejects_symlinks_hardlinks_and_special_files() {
        let symlinks = Fixture::new("symlink");
        stdfs::create_dir(symlinks.input()).unwrap();
        stdfs::write(symlinks.root.path().join("target"), b"target").unwrap();
        symlink(
            symlinks.root.path().join("target"),
            symlinks.input().join("link"),
        )
        .unwrap();
        assert!(matches!(
            symlinks.capture(CaptureLimits::default()),
            Err(CaptureError::SymlinkRejected)
        ));

        let hardlinks = Fixture::new("hardlink");
        stdfs::create_dir(hardlinks.input()).unwrap();
        let first = hardlinks.input().join("first");
        stdfs::write(&first, b"same inode").unwrap();
        stdfs::hard_link(&first, hardlinks.input().join("second")).unwrap();
        assert!(matches!(
            hardlinks.capture(CaptureLimits::default()),
            Err(CaptureError::HardlinkRejected)
        ));

        let special = Fixture::new("special");
        stdfs::create_dir(special.input()).unwrap();
        let _listener = UnixListener::bind(special.input().join("socket")).unwrap();
        assert!(matches!(
            special.capture(CaptureLimits::default()),
            Err(CaptureError::UnsupportedFileType)
        ));
    }

    #[test]
    fn enforces_count_file_total_and_depth_limits() {
        let count = Fixture::new("count");
        stdfs::create_dir(count.input()).unwrap();
        stdfs::write(count.input().join("a"), b"a").unwrap();
        stdfs::write(count.input().join("b"), b"b").unwrap();
        assert!(matches!(
            count.capture(CaptureLimits {
                max_files: 1,
                ..CaptureLimits::default()
            }),
            Err(CaptureError::FileCountLimitExceeded { limit: 1 })
        ));

        let file_size = Fixture::new("file-size");
        stdfs::write(file_size.input(), b"large").unwrap();
        assert!(matches!(
            file_size.capture(CaptureLimits {
                max_file_bytes: 4,
                ..CaptureLimits::default()
            }),
            Err(CaptureError::FileSizeLimitExceeded { limit: 4 })
        ));

        let total = Fixture::new("total");
        stdfs::create_dir(total.input()).unwrap();
        stdfs::write(total.input().join("a"), b"abc").unwrap();
        stdfs::write(total.input().join("b"), b"def").unwrap();
        assert!(matches!(
            total.capture(CaptureLimits {
                max_total_bytes: 5,
                ..CaptureLimits::default()
            }),
            Err(CaptureError::TotalSizeLimitExceeded { limit: 5 })
        ));

        let depth = Fixture::new("depth");
        stdfs::create_dir_all(depth.input().join("nested")).unwrap();
        stdfs::write(depth.input().join("nested/file"), b"x").unwrap();
        assert!(matches!(
            depth.capture(CaptureLimits {
                max_depth: 0,
                ..CaptureLimits::default()
            }),
            Err(CaptureError::DepthLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn growth_past_the_store_ceiling_is_file_instability() {
        assert!(matches!(
            map_store_error(WorkspaceError::ObjectTooLarge { limit: 4 }),
            CaptureError::FileUnstable
        ));
    }

    #[test]
    fn bounds_wide_directory_enumeration_including_empty_directories() {
        let fixture = Fixture::new("entry-count");
        stdfs::create_dir(fixture.input()).unwrap();
        for name in ["a", "b", "c", "d", "e"] {
            stdfs::create_dir(fixture.input().join(name)).unwrap();
        }

        assert!(matches!(
            fixture.capture(CaptureLimits {
                max_entries: 4,
                max_files: 0,
                ..CaptureLimits::default()
            }),
            Err(CaptureError::TraversalEntryLimitExceeded { limit: 4 })
        ));
    }

    #[test]
    fn failed_capture_removes_objects_created_by_that_capture() {
        let fixture = Fixture::new("rollback");
        stdfs::create_dir(fixture.input()).unwrap();
        stdfs::write(fixture.input().join("a"), b"first").unwrap();
        stdfs::write(fixture.input().join("b"), b"far too large").unwrap();
        assert!(fixture
            .capture(CaptureLimits {
                max_file_bytes: 11,
                ..CaptureLimits::default()
            })
            .is_err());
        let object_path = fixture.root.path().join("workspaces/run_rollback/objects");
        assert_eq!(stdfs::read_dir(object_path).unwrap().count(), 0);
    }

    #[test]
    fn workspace_layout_is_private_and_objects_are_read_only() {
        let fixture = Fixture::new("modes");
        stdfs::write(fixture.input(), b"content").unwrap();
        let snapshot = fixture.capture(CaptureLimits::default()).unwrap();
        let run = fixture.root.path().join("workspaces/run_modes");
        assert_eq!(
            stdfs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let object = run
            .join("objects")
            .join(snapshot.manifest.artifacts()[0].object_id.as_str());
        assert_eq!(
            stdfs::metadata(object).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }
}
