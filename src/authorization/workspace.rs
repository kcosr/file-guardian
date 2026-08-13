use crate::domain::{Digest, ObjectId, RunId};
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Mode, OFlags};
use rustix::process::geteuid;
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

/// Private state for one authorization invocation.
pub struct InvocationWorkspace {
    run_path: PathBuf,
    _run_dir: OwnedFd,
    root_identity: FilesystemIdentity,
    run_identity: FilesystemIdentity,
    objects: ObjectStore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FilesystemIdentity {
    pub device: u64,
    pub inode: u64,
}

impl InvocationWorkspace {
    /// Exclusively creates `<workspace_root>/<run_id>` and its fixed private layout.
    /// The administrator-owned workspace root must already exist and must not be a link.
    pub fn create(workspace_root: &Path, run_id: &RunId) -> Result<Self, WorkspaceError> {
        let root = fs::open(workspace_root, DIRECTORY_FLAGS, Mode::empty())
            .map_err(WorkspaceError::OpenRoot)?;
        let root_stat = fs::fstat(&root).map_err(WorkspaceError::InspectRoot)?;
        let root_identity = FilesystemIdentity::from_stat(&root_stat)?;
        if root_stat.st_uid != geteuid().as_raw() || root_stat.st_mode & 0o077 != 0 {
            return Err(WorkspaceError::InsecureRoot);
        }
        fs::mkdirat(&root, run_id.as_str(), Mode::from_raw_mode(0o700))
            .map_err(WorkspaceError::CreateRun)?;

        let run_path = workspace_root.join(run_id.as_str());
        let result = (|| {
            let run_dir = fs::openat(&root, run_id.as_str(), DIRECTORY_FLAGS, Mode::empty())
                .map_err(WorkspaceError::OpenRun)?;
            let run_stat = fs::fstat(&run_dir).map_err(WorkspaceError::InspectRun)?;
            let run_identity = FilesystemIdentity::from_stat(&run_stat)?;
            for name in [
                "manifest",
                "objects",
                "analyzer-views",
                "archive-work",
                "action-journal",
                "quarantine",
                "tmp",
            ] {
                fs::mkdirat(&run_dir, name, Mode::from_raw_mode(0o700))
                    .map_err(WorkspaceError::CreateLayout)?;
            }
            let object_dir = fs::openat(&run_dir, "objects", DIRECTORY_FLAGS, Mode::empty())
                .map_err(WorkspaceError::OpenLayout)?;
            let tmp_dir = fs::openat(&run_dir, "tmp", DIRECTORY_FLAGS, Mode::empty())
                .map_err(WorkspaceError::OpenLayout)?;
            Ok(Self {
                run_path: run_path.clone(),
                _run_dir: run_dir,
                root_identity,
                run_identity,
                objects: ObjectStore {
                    object_dir,
                    tmp_dir,
                    next_temp: AtomicU64::new(0),
                },
            })
        })();

        if result.is_err() {
            // The path was exclusively created by this call and is private to this process.
            let _ = std::fs::remove_dir_all(&run_path);
        }
        result
    }

    pub fn objects(&self) -> &ObjectStore {
        &self.objects
    }

    pub(super) fn contains_identity(&self, identity: FilesystemIdentity) -> bool {
        identity == self.root_identity || identity == self.run_identity
    }

    /// Deletes this invocation's private state. Secure erasure is not claimed.
    pub fn remove(self) -> Result<(), WorkspaceError> {
        let path = self.run_path.clone();
        drop(self);
        std::fs::remove_dir_all(path).map_err(WorkspaceError::RemoveRun)
    }
}

impl FilesystemIdentity {
    // rustix's platform Stat field aliases vary across Unix targets. The
    // conversion is checked where it can narrow and intentionally a no-op
    // where the target already exposes u64.
    #[allow(clippy::useless_conversion)]
    pub(super) fn from_stat(stat: &fs::Stat) -> Result<Self, WorkspaceError> {
        Ok(Self {
            device: u64::try_from(stat.st_dev)
                .map_err(|_| WorkspaceError::InvalidFilesystemIdentity)?,
            inode: u64::try_from(stat.st_ino)
                .map_err(|_| WorkspaceError::InvalidFilesystemIdentity)?,
        })
    }
}

/// Descriptor-rooted content-addressed object storage.
pub struct ObjectStore {
    object_dir: OwnedFd,
    tmp_dir: OwnedFd,
    next_temp: AtomicU64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredObject {
    pub id: ObjectId,
    pub digest: Digest,
    pub byte_len: u64,
    pub(crate) created: bool,
}

impl ObjectStore {
    /// Streams bytes into a private temporary object, hashes them, and atomically
    /// publishes a read-only content-addressed object.
    pub fn store<R: Read>(
        &self,
        reader: &mut R,
        max_bytes: u64,
    ) -> Result<StoredObject, WorkspaceError> {
        let sequence = self.next_temp.fetch_add(1, Ordering::Relaxed);
        let temporary = format!("capture-{sequence:016x}.part");
        let fd = fs::openat(
            &self.tmp_dir,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(WorkspaceError::CreateObject)?;
        let mut output = File::from(fd);
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut byte_len = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(WorkspaceError::ReadSource)?;
                if read == 0 {
                    break;
                }
                byte_len = byte_len
                    .checked_add(read as u64)
                    .ok_or(WorkspaceError::ObjectTooLarge { limit: max_bytes })?;
                if byte_len > max_bytes {
                    return Err(WorkspaceError::ObjectTooLarge { limit: max_bytes });
                }
                hasher.update(&buffer[..read]);
                output
                    .write_all(&buffer[..read])
                    .map_err(WorkspaceError::WriteObject)?;
            }
            output.sync_all().map_err(WorkspaceError::SyncObject)?;
            let digest = Digest::from_array(hasher.finalize().into());
            let suffix = digest.to_string();
            let suffix = suffix.strip_prefix("sha256:").expect("canonical digest");
            let id = ObjectId::from_suffix(suffix).expect("digest is a safe object identifier");

            let created = match fs::statat(&self.object_dir, id.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            {
                Ok(_) => false,
                Err(rustix::io::Errno::NOENT) => {
                    fs::fchmod(&output, Mode::from_raw_mode(0o400))
                        .map_err(WorkspaceError::SealObject)?;
                    fs::renameat(
                        &self.tmp_dir,
                        temporary.as_str(),
                        &self.object_dir,
                        id.as_str(),
                    )
                    .map_err(WorkspaceError::PublishObject)?;
                    true
                }
                Err(error) => return Err(WorkspaceError::InspectObject(error)),
            };
            Ok(StoredObject {
                id,
                digest,
                byte_len,
                created,
            })
        })();

        if result.as_ref().map_or(true, |object| !object.created) {
            drop(output);
            let _ = fs::unlinkat(&self.tmp_dir, temporary.as_str(), AtFlags::empty());
        }
        result
    }

    /// Opens immutable bytes by opaque object identity. Analyzers never need a
    /// live staging path.
    pub fn open(&self, id: &ObjectId) -> Result<File, WorkspaceError> {
        let fd = fs::openat(
            &self.object_dir,
            id.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(WorkspaceError::OpenObject)?;
        let stat = fs::fstat(&fd).map_err(WorkspaceError::InspectObject)?;
        #[allow(clippy::useless_conversion)]
        let link_count = u64::try_from(stat.st_nlink).map_err(|_| WorkspaceError::InvalidObject)?;
        if !fs::FileType::from_raw_mode(stat.st_mode).is_file() || link_count != 1 {
            return Err(WorkspaceError::InvalidObject);
        }
        Ok(File::from(fd))
    }

    pub(crate) fn remove_if_created(&self, object: &StoredObject) {
        if object.created {
            let _ = fs::unlinkat(&self.object_dir, object.id.as_str(), AtFlags::empty());
        }
    }
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("could not open workspace root: {0}")]
    OpenRoot(rustix::io::Errno),
    #[error("could not inspect workspace root: {0}")]
    InspectRoot(rustix::io::Errno),
    #[error("could not inspect invocation workspace: {0}")]
    InspectRun(rustix::io::Errno),
    #[error("filesystem identity cannot be represented safely")]
    InvalidFilesystemIdentity,
    #[error(
        "workspace root must be owned by the effective user and inaccessible to group and other"
    )]
    InsecureRoot,
    #[error("could not exclusively create invocation workspace: {0}")]
    CreateRun(rustix::io::Errno),
    #[error("could not open invocation workspace: {0}")]
    OpenRun(rustix::io::Errno),
    #[error("could not create invocation workspace layout: {0}")]
    CreateLayout(rustix::io::Errno),
    #[error("could not open invocation workspace layout: {0}")]
    OpenLayout(rustix::io::Errno),
    #[error("could not remove invocation workspace: {0}")]
    RemoveRun(io::Error),
    #[error("could not create temporary object: {0}")]
    CreateObject(rustix::io::Errno),
    #[error("could not read source file: {0}")]
    ReadSource(io::Error),
    #[error("captured object exceeds {limit} bytes")]
    ObjectTooLarge { limit: u64 },
    #[error("could not write immutable object: {0}")]
    WriteObject(io::Error),
    #[error("could not synchronize immutable object: {0}")]
    SyncObject(io::Error),
    #[error("could not seal immutable object: {0}")]
    SealObject(rustix::io::Errno),
    #[error("could not publish immutable object: {0}")]
    PublishObject(rustix::io::Errno),
    #[error("could not inspect immutable object: {0}")]
    InspectObject(rustix::io::Errno),
    #[error("could not open immutable object: {0}")]
    OpenObject(rustix::io::Errno),
    #[error("immutable object entry is not a private regular file")]
    InvalidObject,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn rejects_a_group_or_world_accessible_root() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspaces");
        stdfs::create_dir(&root).unwrap();
        stdfs::set_permissions(&root, stdfs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            InvocationWorkspace::create(&root, &RunId::from_suffix("insecure").unwrap()),
            Err(WorkspaceError::InsecureRoot)
        ));
    }

    #[test]
    fn run_identifier_is_exclusively_reserved() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspaces");
        stdfs::create_dir(&root).unwrap();
        stdfs::set_permissions(&root, stdfs::Permissions::from_mode(0o700)).unwrap();
        let run_id = RunId::from_suffix("exclusive").unwrap();
        let _first = InvocationWorkspace::create(&root, &run_id).unwrap();

        assert!(matches!(
            InvocationWorkspace::create(&root, &run_id),
            Err(WorkspaceError::CreateRun(_))
        ));
    }
}
