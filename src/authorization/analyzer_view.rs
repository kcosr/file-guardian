use super::{InvocationWorkspace, WorkspaceError};
use crate::domain::{
    ArtifactId, ArtifactKind, ArtifactManifest, CandidateId, Digest, LogicalPath, Provenance,
};
use crate::pipeline::ArtifactAssignment;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

const RESERVED_SEGMENT_PREFIX: &str = ".__fg_";
const DERIVED_NAMESPACE: &str = ".file-guardian-derived";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalyzerViewQuota {
    pub max_files: u64,
    pub max_entries: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalyzerViewLimits {
    pub per_view: AnalyzerViewQuota,
    /// One pipeline-compiled cap shared by every analyzer in the invocation.
    /// It must not depend on the analyzer that happens to reserve first.
    pub invocation: AnalyzerViewQuota,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerViewEntry {
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
    pub logical_path: LogicalPath,
    pub view_path: String,
    pub kind: ArtifactKind,
    pub byte_len: u64,
    pub content_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalyzerViewNode<'a> {
    File(&'a AnalyzerViewEntry),
    Directory {
        recursive_file_bytes: u64,
        recursive_file_count: u64,
    },
}

#[derive(Default)]
pub(super) struct AnalyzerViewUsage {
    files: u64,
    entries: u64,
    bytes: u64,
    invocation_quota: Option<AnalyzerViewQuota>,
}

struct AnalyzerViewReservation {
    usage: Arc<Mutex<AnalyzerViewUsage>>,
    files: u64,
    entries: u64,
    bytes: u64,
    release_on_drop: bool,
}

impl Drop for AnalyzerViewReservation {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        let mut usage = self.usage.lock().unwrap_or_else(|error| error.into_inner());
        usage.files -= self.files;
        usage.entries -= self.entries;
        usage.bytes -= self.bytes;
    }
}

/// One private, assignment-scoped filesystem presentation for an analyzer.
pub struct AnalyzerView {
    host_path: PathBuf,
    directory: OwnedFd,
    entries: Vec<AnalyzerViewEntry>,
    files_by_path: BTreeMap<String, usize>,
    directories: BTreeMap<String, DirectoryUsage>,
    reservation: Option<AnalyzerViewReservation>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DirectoryUsage {
    bytes: u64,
    files: u64,
}

impl AnalyzerView {
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    pub fn entries(&self) -> &[AnalyzerViewEntry] {
        &self.entries
    }

    /// Resolves one canonical path relative to `/input`.
    ///
    /// `.` denotes the view root. Absolute paths, empty paths, traversal,
    /// repeated separators, and trailing separators are deliberately rejected.
    pub fn resolve_relative_path(&self, path: &str) -> Option<AnalyzerViewNode<'_>> {
        if path == "." {
            let usage = self.directories.get(path)?;
            return Some(AnalyzerViewNode::Directory {
                recursive_file_bytes: usage.bytes,
                recursive_file_count: usage.files,
            });
        }
        if !is_canonical_relative_path(path) {
            return None;
        }
        if let Some(index) = self.files_by_path.get(path) {
            return Some(AnalyzerViewNode::File(&self.entries[*index]));
        }
        self.directories
            .get(path)
            .map(|usage| AnalyzerViewNode::Directory {
                recursive_file_bytes: usage.bytes,
                recursive_file_count: usage.files,
            })
    }
}

impl Drop for AnalyzerView {
    fn drop(&mut self) {
        match super::workspace::remove_verified_tree(&self.host_path, &self.directory) {
            Ok(()) => {
                self.reservation.take();
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.reservation.take();
            }
            Err(_) => {
                // The bytes still occupy the invocation workspace. Keep their
                // reservation charged until the workspace itself is dropped.
                if let Some(mut reservation) = self.reservation.take() {
                    reservation.release_on_drop = false;
                }
            }
        }
    }
}

pub struct AnalyzerViewBuilder<'a> {
    workspace: &'a InvocationWorkspace,
    manifest: &'a ArtifactManifest,
    assignments: &'a [ArtifactAssignment],
    limits: AnalyzerViewLimits,
}

impl<'a> AnalyzerViewBuilder<'a> {
    pub fn new(
        workspace: &'a InvocationWorkspace,
        manifest: &'a ArtifactManifest,
        assignments: &'a [ArtifactAssignment],
        limits: AnalyzerViewLimits,
    ) -> Self {
        Self {
            workspace,
            manifest,
            assignments,
            limits,
        }
    }

    pub fn materialize(self, name: &str) -> Result<AnalyzerView, AnalyzerViewError> {
        validate_limits(self.limits)?;
        let plan = self.plan()?;
        let reservation = reserve(
            &self.workspace.analyzer_view_usage,
            plan.files,
            plan.entries,
            plan.bytes,
            self.limits.invocation,
        )?;
        let (host_path, root) = self.workspace.create_analyzer_view_directory(name)?;
        let view = AnalyzerView {
            host_path,
            directory: root,
            entries: plan.presentations,
            files_by_path: plan.files_by_path,
            directories: plan.directory_usage,
            reservation: Some(reservation),
        };

        let result = (|| {
            let mut directories = view
                .directories
                .keys()
                .filter(|path| path.as_str() != ".")
                .cloned()
                .collect::<Vec<_>>();
            directories.sort_by_key(|path| path.matches('/').count());
            for directory in directories {
                create_planned_directory(&view.directory, &directory)?;
            }
            for entry in &view.entries {
                let artifact = self
                    .manifest
                    .artifact(&entry.artifact_id)
                    .ok_or(AnalyzerViewError::UnknownArtifact)?;
                let components = entry.view_path.split('/').collect::<Vec<_>>();
                let parent = open_directory(&view.directory, &components[..components.len() - 1])?;
                copy_verified(
                    self.workspace,
                    artifact.object_id.clone(),
                    &parent,
                    components[components.len() - 1],
                    artifact.byte_len,
                    artifact.content_digest,
                )?;
            }
            seal_directories(&view.directory, view.directories.keys())
        })();

        if let Err(error) = result {
            drop(view);
            return Err(error);
        }
        Ok(view)
    }

    fn plan(&self) -> Result<ViewPlan, AnalyzerViewError> {
        let mut previous_artifact: Option<&ArtifactId> = None;
        let mut presentations = Vec::with_capacity(self.assignments.len());
        let mut original_by_view_path = BTreeMap::<String, LogicalPath>::new();
        let mut files_by_path = BTreeMap::new();
        let mut directory_usage = BTreeMap::<String, DirectoryUsage>::new();
        directory_usage.insert(".".to_owned(), DirectoryUsage::default());
        let mut bytes = 0_u64;

        for assignment in self.assignments {
            if previous_artifact.is_some_and(|previous| previous >= &assignment.artifact_id) {
                return Err(AnalyzerViewError::NonCanonicalAssignments);
            }
            previous_artifact = Some(&assignment.artifact_id);
            let artifact = self
                .manifest
                .artifact(&assignment.artifact_id)
                .ok_or(AnalyzerViewError::UnknownArtifact)?;
            let logical_path = match (&artifact.kind, &artifact.provenance) {
                (ArtifactKind::PhysicalFile, Provenance::Physical { logical_path }) => logical_path,
                _ => return Err(AnalyzerViewError::UnsupportedArtifactKind),
            };
            let components = logical_path
                .segments()
                .iter()
                .map(|segment| present_segment(segment.as_slice()))
                .collect::<Vec<_>>();
            if components.len() > self.limits.per_view.max_depth {
                return Err(AnalyzerViewError::ViewDepthLimitExceeded);
            }
            let view_path = components.join("/");
            if original_by_view_path
                .insert(view_path.clone(), logical_path.clone())
                .is_some()
            {
                return Err(AnalyzerViewError::PresentationCollision);
            }
            if directory_usage.contains_key(&view_path) {
                return Err(AnalyzerViewError::PresentationCollision);
            }
            for depth in 1..components.len() {
                let directory = components[..depth].join("/");
                if files_by_path.contains_key(&directory) {
                    return Err(AnalyzerViewError::PresentationCollision);
                }
                directory_usage.entry(directory).or_default();
            }
            let index = presentations.len();
            if files_by_path.insert(view_path.clone(), index).is_some() {
                return Err(AnalyzerViewError::PresentationCollision);
            }
            bytes = bytes
                .checked_add(artifact.byte_len)
                .ok_or(AnalyzerViewError::QuotaOverflow)?;
            presentations.push(AnalyzerViewEntry {
                candidate_id: assignment.candidate_id.clone(),
                artifact_id: artifact.id.clone(),
                logical_path: logical_path.clone(),
                view_path,
                kind: artifact.kind,
                byte_len: artifact.byte_len,
                content_digest: artifact.content_digest,
            });
        }

        for entry in &presentations {
            let components = entry.view_path.split('/').collect::<Vec<_>>();
            let root = directory_usage
                .get_mut(".")
                .expect("root directory is present");
            add_directory_usage(root, entry.byte_len)?;
            for depth in 1..components.len() {
                let key = components[..depth].join("/");
                let usage = directory_usage
                    .get_mut(&key)
                    .expect("all ancestor directories are present");
                add_directory_usage(usage, entry.byte_len)?;
            }
        }

        let files =
            u64::try_from(presentations.len()).map_err(|_| AnalyzerViewError::QuotaOverflow)?;
        let directory_count = u64::try_from(directory_usage.len().saturating_sub(1))
            .map_err(|_| AnalyzerViewError::QuotaOverflow)?;
        let entries = files
            .checked_add(directory_count)
            .ok_or(AnalyzerViewError::QuotaOverflow)?;
        enforce_quota(files, entries, bytes, self.limits.per_view, false)?;
        Ok(ViewPlan {
            presentations,
            files_by_path,
            directory_usage,
            files,
            entries,
            bytes,
        })
    }
}

struct ViewPlan {
    presentations: Vec<AnalyzerViewEntry>,
    files_by_path: BTreeMap<String, usize>,
    directory_usage: BTreeMap<String, DirectoryUsage>,
    files: u64,
    entries: u64,
    bytes: u64,
}

fn validate_limits(limits: AnalyzerViewLimits) -> Result<(), AnalyzerViewError> {
    for quota in [limits.per_view, limits.invocation] {
        if quota.max_files == 0
            || quota.max_entries == 0
            || quota.max_total_bytes == 0
            || quota.max_depth == 0
        {
            return Err(AnalyzerViewError::InvalidLimits);
        }
    }
    if limits.per_view.max_files > limits.invocation.max_files
        || limits.per_view.max_entries > limits.invocation.max_entries
        || limits.per_view.max_total_bytes > limits.invocation.max_total_bytes
        || limits.per_view.max_depth > limits.invocation.max_depth
    {
        return Err(AnalyzerViewError::InvalidLimits);
    }
    Ok(())
}

fn reserve(
    usage: &Arc<Mutex<AnalyzerViewUsage>>,
    files: u64,
    entries: u64,
    bytes: u64,
    quota: AnalyzerViewQuota,
) -> Result<AnalyzerViewReservation, AnalyzerViewError> {
    let mut current = usage.lock().unwrap_or_else(|error| error.into_inner());
    match current.invocation_quota {
        Some(configured) if configured != quota => {
            return Err(AnalyzerViewError::InconsistentInvocationQuota);
        }
        Some(_) => {}
        None => current.invocation_quota = Some(quota),
    }
    let next_files = current
        .files
        .checked_add(files)
        .ok_or(AnalyzerViewError::QuotaOverflow)?;
    let next_entries = current
        .entries
        .checked_add(entries)
        .ok_or(AnalyzerViewError::QuotaOverflow)?;
    let next_bytes = current
        .bytes
        .checked_add(bytes)
        .ok_or(AnalyzerViewError::QuotaOverflow)?;
    enforce_quota(next_files, next_entries, next_bytes, quota, true)?;
    current.files = next_files;
    current.entries = next_entries;
    current.bytes = next_bytes;
    drop(current);
    Ok(AnalyzerViewReservation {
        usage: Arc::clone(usage),
        files,
        entries,
        bytes,
        release_on_drop: true,
    })
}

fn enforce_quota(
    files: u64,
    entries: u64,
    bytes: u64,
    quota: AnalyzerViewQuota,
    invocation: bool,
) -> Result<(), AnalyzerViewError> {
    if files > quota.max_files || entries > quota.max_entries || bytes > quota.max_total_bytes {
        if invocation {
            Err(AnalyzerViewError::InvocationQuotaExceeded)
        } else {
            Err(AnalyzerViewError::ViewQuotaExceeded)
        }
    } else {
        Ok(())
    }
}

fn add_directory_usage(usage: &mut DirectoryUsage, bytes: u64) -> Result<(), AnalyzerViewError> {
    usage.bytes = usage
        .bytes
        .checked_add(bytes)
        .ok_or(AnalyzerViewError::QuotaOverflow)?;
    usage.files = usage
        .files
        .checked_add(1)
        .ok_or(AnalyzerViewError::QuotaOverflow)?;
    Ok(())
}

fn present_segment(bytes: &[u8]) -> String {
    if let Ok(value) = std::str::from_utf8(bytes) {
        if bytes.len() <= 255
            && !value.starts_with(RESERVED_SEGMENT_PREFIX)
            && value != DERIVED_NAMESPACE
            && !value.chars().any(char::is_control)
        {
            return value.to_owned();
        }
    }
    let digest = Sha256::digest(bytes);
    let mut value = String::from(RESERVED_SEGMENT_PREFIX);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

fn create_planned_directory(root: &OwnedFd, path: &str) -> Result<(), AnalyzerViewError> {
    let components = path.split('/').collect::<Vec<_>>();
    let parent = open_directory(root, &components[..components.len() - 1])?;
    match fs::mkdirat(
        &parent,
        components[components.len() - 1],
        Mode::from_raw_mode(0o700),
    ) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Err(AnalyzerViewError::PresentationCollision),
        Err(error) => Err(AnalyzerViewError::CreateDirectory(error)),
    }
}

fn copy_verified(
    workspace: &InvocationWorkspace,
    object_id: crate::domain::ObjectId,
    parent: &OwnedFd,
    name: &str,
    expected_len: u64,
    expected_digest: Digest,
) -> Result<(), AnalyzerViewError> {
    let mut source = workspace.objects().open(&object_id)?;
    let destination = fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            AnalyzerViewError::PresentationCollision
        } else {
            AnalyzerViewError::CreateFile(error)
        }
    })?;
    let mut output = File::from(destination);
    let mut buffer = [0_u8; 64 * 1024];
    let mut byte_len = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(AnalyzerViewError::ReadObject)?;
        if read == 0 {
            break;
        }
        byte_len = byte_len
            .checked_add(read as u64)
            .ok_or(AnalyzerViewError::IntegrityMismatch)?;
        if byte_len > expected_len {
            return Err(AnalyzerViewError::IntegrityMismatch);
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(AnalyzerViewError::WriteFile)?;
    }
    let digest = Digest::from_array(hasher.finalize().into());
    if byte_len != expected_len || digest != expected_digest {
        return Err(AnalyzerViewError::IntegrityMismatch);
    }
    output.sync_all().map_err(AnalyzerViewError::SyncFile)?;
    fs::fchmod(&output, Mode::from_raw_mode(0o400)).map_err(AnalyzerViewError::SealFile)?;
    let stat = fs::fstat(&output).map_err(AnalyzerViewError::InspectEntry)?;
    #[allow(clippy::unnecessary_fallible_conversions, clippy::useless_conversion)]
    let links = u64::try_from(stat.st_nlink).map_err(|_| AnalyzerViewError::InvalidEntry)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o377 != 0
        || stat.st_mode & 0o400 == 0
        || links != 1
    {
        return Err(AnalyzerViewError::InvalidEntry);
    }
    Ok(())
}

fn seal_directories<'a>(
    root: &OwnedFd,
    directories: impl Iterator<Item = &'a String>,
) -> Result<(), AnalyzerViewError> {
    let mut paths = directories
        .filter(|path| path.as_str() != ".")
        .cloned()
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    for path in paths {
        let components = path.split('/').collect::<Vec<_>>();
        let directory = open_directory(root, &components)?;
        fs::fchmod(&directory, Mode::from_raw_mode(0o500))
            .map_err(AnalyzerViewError::SealDirectory)?;
    }
    fs::fchmod(root, Mode::from_raw_mode(0o500)).map_err(AnalyzerViewError::SealDirectory)
}

fn open_directory(root: &OwnedFd, components: &[&str]) -> Result<OwnedFd, AnalyzerViewError> {
    let mut current = root
        .as_fd()
        .try_clone_to_owned()
        .map_err(AnalyzerViewError::CloneDirectory)?;
    for component in components {
        current = fs::openat(&current, *component, DIRECTORY_FLAGS, Mode::empty())
            .map_err(AnalyzerViewError::OpenDirectory)?;
    }
    Ok(current)
}

fn is_canonical_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

pub(super) fn make_tree_owner_writable(path: &Path) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                make_tree_owner_writable(&entry.path());
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum AnalyzerViewError {
    #[error(
        "analyzer-view limits must be positive and per-view limits must not exceed invocation limits"
    )]
    InvalidLimits,
    #[error("analyzer assignments are not in canonical artifact order or contain duplicates")]
    NonCanonicalAssignments,
    #[error("analyzer assignment references an unknown artifact")]
    UnknownArtifact,
    #[error("this analyzer view currently supports only physical file artifacts")]
    UnsupportedArtifactKind,
    #[error("analyzer-view presentation paths collide")]
    PresentationCollision,
    #[error("analyzer view exceeds its configured depth limit")]
    ViewDepthLimitExceeded,
    #[error("analyzer view exceeds its configured quota")]
    ViewQuotaExceeded,
    #[error("active analyzer views exceed the invocation quota")]
    InvocationQuotaExceeded,
    #[error("all analyzer views in one invocation must use the same compiled invocation quota")]
    InconsistentInvocationQuota,
    #[error("analyzer-view quota arithmetic overflowed")]
    QuotaOverflow,
    #[error("could not create analyzer view workspace: {0}")]
    Workspace(#[from] WorkspaceError),
    #[error("could not clone analyzer-view directory: {0}")]
    CloneDirectory(io::Error),
    #[error("could not create analyzer-view directory: {0}")]
    CreateDirectory(rustix::io::Errno),
    #[error("could not open analyzer-view directory: {0}")]
    OpenDirectory(rustix::io::Errno),
    #[error("could not create analyzer-view file: {0}")]
    CreateFile(rustix::io::Errno),
    #[error("could not inspect analyzer-view entry: {0}")]
    InspectEntry(rustix::io::Errno),
    #[error("analyzer-view entry is not a private regular file or directory")]
    InvalidEntry,
    #[error("could not read immutable object: {0}")]
    ReadObject(io::Error),
    #[error("could not write analyzer-view file: {0}")]
    WriteFile(io::Error),
    #[error("could not sync analyzer-view file: {0}")]
    SyncFile(io::Error),
    #[error("could not seal analyzer-view file: {0}")]
    SealFile(rustix::io::Errno),
    #[error("could not seal analyzer-view directory: {0}")]
    SealDirectory(rustix::io::Errno),
    #[error("materialized analyzer-view bytes do not match the immutable manifest")]
    IntegrityMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{CaptureLimits, Snapshotter};
    use crate::domain::{PathSegment, RunId};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        input: PathBuf,
        run_path: PathBuf,
        workspace: InvocationWorkspace,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("workspaces");
            let input = temporary.path().join("input");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(&input).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let run_id = RunId::from_suffix("view-test").unwrap();
            let run_path = root.join(run_id.as_str());
            Self {
                _temporary: temporary,
                input,
                run_path,
                workspace: InvocationWorkspace::create(&root, &run_id).unwrap(),
            }
        }

        fn capture(&self) -> ArtifactManifest {
            Snapshotter::new(&self.workspace, CaptureLimits::default())
                .capture(&self.input)
                .unwrap()
                .manifest
        }
    }

    fn quotas() -> AnalyzerViewLimits {
        let quota = AnalyzerViewQuota {
            max_files: 100,
            max_entries: 200,
            max_total_bytes: 1024 * 1024,
            max_depth: 32,
        };
        AnalyzerViewLimits {
            per_view: quota,
            invocation: quota,
        }
    }

    fn assignments(manifest: &ArtifactManifest) -> Vec<ArtifactAssignment> {
        manifest
            .artifacts()
            .iter()
            .enumerate()
            .map(|(index, artifact)| ArtifactAssignment {
                candidate_id: CandidateId::from_suffix(format!("view-{index}")).unwrap(),
                artifact_id: artifact.id.clone(),
            })
            .collect()
    }

    #[test]
    fn materializes_only_assigned_immutable_bytes_and_cleans_up() {
        let fixture = Fixture::new();
        std::fs::write(fixture.input.join("a.txt"), b"captured-a").unwrap();
        std::fs::write(fixture.input.join("b.txt"), b"captured-b").unwrap();
        let manifest = fixture.capture();
        std::fs::write(fixture.input.join("a.txt"), b"mutated-live-source").unwrap();
        let selected = vec![assignments(&manifest).remove(0)];

        let view = AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, quotas())
            .materialize("assigned")
            .unwrap();
        let host_path = view.host_path().to_owned();
        assert_eq!(view.entries().len(), 1);
        assert_eq!(
            std::fs::read(host_path.join("a.txt")).unwrap(),
            b"captured-a"
        );
        assert!(!host_path.join("b.txt").exists());
        assert_eq!(
            view.resolve_relative_path("a.txt"),
            Some(AnalyzerViewNode::File(&view.entries()[0]))
        );
        assert_eq!(
            view.resolve_relative_path("."),
            Some(AnalyzerViewNode::Directory {
                recursive_file_bytes: 10,
                recursive_file_count: 1,
            })
        );
        assert!(view.resolve_relative_path("../a.txt").is_none());
        assert!(view.resolve_relative_path("a.txt/").is_none());
        assert_eq!(
            std::fs::metadata(&host_path).unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert_eq!(
            std::fs::metadata(host_path.join("a.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        drop(view);
        assert!(!host_path.exists());
    }

    #[test]
    fn literal_file_capture_uses_its_filename_as_the_view_path() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspaces");
        let input = temporary.path().join("literal.txt");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&input, b"literal").unwrap();
        let workspace =
            InvocationWorkspace::create(&root, &RunId::from_suffix("literal-view").unwrap())
                .unwrap();
        let snapshot = Snapshotter::new(&workspace, CaptureLimits::default())
            .capture(&input)
            .unwrap();
        let selected = assignments(&snapshot.manifest);

        let view = AnalyzerViewBuilder::new(&workspace, &snapshot.manifest, &selected, quotas())
            .materialize("literal")
            .unwrap();
        assert_eq!(view.entries()[0].view_path, "literal.txt");
        assert_eq!(
            std::fs::read(view.host_path().join("literal.txt")).unwrap(),
            b"literal"
        );
    }

    #[test]
    fn aliases_non_utf8_control_and_reserved_segments() {
        let fixture = Fixture::new();
        let non_utf8 = OsString::from_vec(vec![0xff, b'x']);
        std::fs::write(fixture.input.join(non_utf8), b"opaque").unwrap();
        std::fs::write(fixture.input.join("line\nbreak"), b"control").unwrap();
        std::fs::write(fixture.input.join(DERIVED_NAMESPACE), b"reserved").unwrap();
        let manifest = fixture.capture();
        let selected = assignments(&manifest);

        let view = AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, quotas())
            .materialize("aliased")
            .unwrap();
        assert_eq!(view.entries().len(), 3);
        for entry in view.entries() {
            assert!(entry.view_path.starts_with(RESERVED_SEGMENT_PREFIX));
            assert!(entry.view_path.is_ascii());
            assert_eq!(entry.view_path.len(), RESERVED_SEGMENT_PREFIX.len() + 64);
            assert!(view.host_path().join(&entry.view_path).is_file());
        }
        assert!(view
            .entries()
            .iter()
            .any(|entry| entry.logical_path.segments()[0].as_slice() == [0xff, b'x']));
    }

    #[test]
    fn rejects_file_directory_presentation_collisions_before_creation() {
        let fixture = Fixture::new();
        let first = fixture
            .workspace
            .objects()
            .store(&mut &b"one"[..], 3)
            .unwrap();
        let second = fixture
            .workspace
            .objects()
            .store(&mut &b"two"[..], 3)
            .unwrap();
        let pair =
            |suffix: &str, path: Vec<PathSegment>, object: &crate::authorization::StoredObject| {
                let logical_path = LogicalPath::new(path).unwrap();
                let subject_id = crate::domain::SubjectId::from_suffix(suffix).unwrap();
                let subject = crate::domain::PhysicalSubject {
                    id: subject_id.clone(),
                    relative_path: logical_path.clone(),
                    source_identity: crate::domain::SourceIdentity {
                        device: 1,
                        inode: suffix.as_bytes()[0] as u64,
                        file_type: crate::domain::SourceFileType::RegularFile,
                        byte_len: object.byte_len,
                        link_count: 1,
                        modified: None,
                        changed: None,
                        content_digest: object.digest,
                    },
                    object_id: object.id.clone(),
                    byte_len: object.byte_len,
                };
                let artifact = crate::domain::Artifact {
                    id: ArtifactId::from_suffix(suffix).unwrap(),
                    subject_id,
                    object_id: object.id.clone(),
                    kind: ArtifactKind::PhysicalFile,
                    byte_len: object.byte_len,
                    content_digest: object.digest,
                    provenance: Provenance::Physical { logical_path },
                };
                (subject, artifact)
            };
        let (first_subject, first_artifact) =
            pair("a", vec![PathSegment::utf8("path").unwrap()], &first);
        let (second_subject, second_artifact) = pair(
            "b",
            vec![
                PathSegment::utf8("path").unwrap(),
                PathSegment::utf8("child").unwrap(),
            ],
            &second,
        );
        let manifest = ArtifactManifest::new(
            vec![first_subject, second_subject],
            vec![first_artifact, second_artifact],
        )
        .unwrap();
        let selected = assignments(&manifest);
        assert!(matches!(
            AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, quotas())
                .materialize("collision"),
            Err(AnalyzerViewError::PresentationCollision)
        ));
    }

    #[test]
    fn enforces_per_view_and_concurrent_invocation_quotas() {
        let fixture = Fixture::new();
        std::fs::write(fixture.input.join("one"), b"12345").unwrap();
        let manifest = fixture.capture();
        let selected = assignments(&manifest);
        let mut limits = quotas();
        limits.per_view.max_total_bytes = 4;
        assert!(matches!(
            AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, limits)
                .materialize("too-large"),
            Err(AnalyzerViewError::ViewQuotaExceeded)
        ));

        let mut limits = quotas();
        limits.per_view.max_total_bytes = 5;
        limits.invocation.max_total_bytes = 5;
        let first = AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, limits)
            .materialize("first")
            .unwrap();
        assert!(matches!(
            AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, limits)
                .materialize("second"),
            Err(AnalyzerViewError::InvocationQuotaExceeded)
        ));
        drop(first);
        AnalyzerViewBuilder::new(&fixture.workspace, &manifest, &selected, limits)
            .materialize("after-release")
            .unwrap();
    }

    #[test]
    fn shared_invocation_cap_is_independent_of_different_view_acquisition_order() {
        fn run(large_limit_first: bool) {
            let fixture = Fixture::new();
            std::fs::write(fixture.input.join("a-small"), b"12").unwrap();
            std::fs::write(fixture.input.join("b-large"), b"123456").unwrap();
            let manifest = fixture.capture();
            let selected = assignments(&manifest);
            let shared = AnalyzerViewQuota {
                max_files: 2,
                max_entries: 2,
                max_total_bytes: 10,
                max_depth: 4,
            };
            let generous = AnalyzerViewLimits {
                per_view: AnalyzerViewQuota {
                    max_files: 1,
                    max_entries: 1,
                    max_total_bytes: 10,
                    max_depth: 4,
                },
                invocation: shared,
            };
            let tight = AnalyzerViewLimits {
                per_view: AnalyzerViewQuota {
                    max_files: 1,
                    max_entries: 1,
                    max_total_bytes: 6,
                    max_depth: 4,
                },
                invocation: shared,
            };
            let (first_assignment, first_limits, second_assignment, second_limits) =
                if large_limit_first {
                    (&selected[1..2], tight, &selected[0..1], generous)
                } else {
                    (&selected[0..1], generous, &selected[1..2], tight)
                };

            let first = AnalyzerViewBuilder::new(
                &fixture.workspace,
                &manifest,
                first_assignment,
                first_limits,
            )
            .materialize("order-first")
            .unwrap();
            let second = AnalyzerViewBuilder::new(
                &fixture.workspace,
                &manifest,
                second_assignment,
                second_limits,
            )
            .materialize("order-second")
            .unwrap();
            assert_eq!(first.entries().len() + second.entries().len(), 2);
        }

        run(false);
        run(true);
    }

    #[test]
    fn different_view_limits_share_one_cap_under_parallel_reservation() {
        let fixture = Fixture::new();
        std::fs::write(fixture.input.join("a"), b"12").unwrap();
        std::fs::write(fixture.input.join("b"), b"123456").unwrap();
        let manifest = fixture.capture();
        let selected = assignments(&manifest);
        let shared = AnalyzerViewQuota {
            max_files: 2,
            max_entries: 2,
            max_total_bytes: 10,
            max_depth: 4,
        };
        let first_limits = AnalyzerViewLimits {
            per_view: AnalyzerViewQuota {
                max_files: 1,
                max_entries: 1,
                max_total_bytes: 10,
                max_depth: 4,
            },
            invocation: shared,
        };
        let second_limits = AnalyzerViewLimits {
            per_view: AnalyzerViewQuota {
                max_files: 1,
                max_entries: 1,
                max_total_bytes: 6,
                max_depth: 4,
            },
            invocation: shared,
        };
        let barrier = Arc::new(std::sync::Barrier::new(2));

        std::thread::scope(|scope| {
            let workspace = &fixture.workspace;
            let manifest = &manifest;
            let first_assignment = &selected[0..1];
            let second_assignment = &selected[1..2];
            let first_barrier = Arc::clone(&barrier);
            let first = scope.spawn(move || {
                first_barrier.wait();
                AnalyzerViewBuilder::new(workspace, manifest, first_assignment, first_limits)
                    .materialize("parallel-first")
            });
            let second_barrier = Arc::clone(&barrier);
            let second = scope.spawn(move || {
                second_barrier.wait();
                AnalyzerViewBuilder::new(workspace, manifest, second_assignment, second_limits)
                    .materialize("parallel-second")
            });
            let first = first.join().unwrap().unwrap();
            let second = second.join().unwrap().unwrap();
            assert_eq!(first.entries().len() + second.entries().len(), 2);
        });
    }

    #[test]
    fn rejects_manifest_digest_mismatch_without_leaving_a_view() {
        let fixture = Fixture::new();
        std::fs::write(fixture.input.join("file"), b"captured").unwrap();
        let manifest = fixture.capture();
        let mut subjects = manifest.subjects().to_vec();
        let mut artifacts = manifest.artifacts().to_vec();
        let wrong = Digest::sha256(b"different");
        subjects[0].source_identity.content_digest = wrong;
        artifacts[0].content_digest = wrong;
        let inconsistent = ArtifactManifest::new(subjects, artifacts).unwrap();
        let selected = assignments(&inconsistent);

        assert!(matches!(
            AnalyzerViewBuilder::new(&fixture.workspace, &inconsistent, &selected, quotas())
                .materialize("bad-digest"),
            Err(AnalyzerViewError::IntegrityMismatch)
        ));
        assert!(!fixture.run_path.join("analyzer-views/bad-digest").exists());
    }
}
