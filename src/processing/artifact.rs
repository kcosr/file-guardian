//! Durable operator lifecycle for files removed from a publication stage by a
//! policy `quarantine` action.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::domain::{Digest, LogicalPath, RunId, SubjectId};
use crate::processing::actions::executor::ArtifactQuarantineMetadata;
use crate::processing::domain::{ActionId, ArtifactQuarantineId};
use crate::processing::report::{ActionKind as ReportActionKind, ActionState, ProcessingReport};

const ROOT_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const MAX_PRIVATE_JSON_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct ArtifactQuarantineStore {
    root_path: PathBuf,
    root: OwnedFd,
    reports: OwnedFd,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactQuarantineRecord {
    pub run_id: RunId,
    pub quarantine_id: ArtifactQuarantineId,
    pub action_id: ActionId,
    pub subject_id: SubjectId,
    pub logical_path: LogicalPath,
    pub byte_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecoveryReceipt {
    pub artifact: ArtifactQuarantineRecord,
    pub destination: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDiscardReceipt {
    pub run_id: RunId,
    pub quarantine_id: ArtifactQuarantineId,
    pub already_absent: bool,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ArtifactQuarantineError {
    #[error("artifact quarantine store is unavailable")]
    StoreUnavailable,
    #[error("processing report is unavailable or invalid")]
    ReportUnavailable,
    #[error("the report does not bind this quarantined artifact")]
    ReportBinding,
    #[error("quarantined artifact is unavailable")]
    Unavailable,
    #[error("quarantined artifact failed its recorded integrity check")]
    Integrity,
    #[error("recovery destination is invalid")]
    DestinationInvalid,
    #[error("recovery destination parent is not trusted")]
    DestinationUntrusted,
    #[error("recovery destination already exists")]
    DestinationExists,
    #[error("artifact operation could not be made durable")]
    Durability,
}

impl ArtifactQuarantineStore {
    pub fn open(
        root: impl AsRef<Path>,
        reports_root: impl AsRef<Path>,
    ) -> Result<Self, ArtifactQuarantineError> {
        let root_path = secure_root(root.as_ref())?;
        let reports_path = secure_root(reports_root.as_ref())?;
        if root_path == reports_path
            || root_path.starts_with(&reports_path)
            || reports_path.starts_with(&root_path)
        {
            return Err(ArtifactQuarantineError::StoreUnavailable);
        }
        Ok(Self {
            root: open_root(&root_path)?,
            reports: open_root(&reports_path)?,
            root_path,
        })
    }

    pub fn inspect(
        &self,
        run_id: &RunId,
        quarantine_id: &ArtifactQuarantineId,
    ) -> Result<ArtifactQuarantineRecord, ArtifactQuarantineError> {
        let _lock = self.lock()?;
        self.inspect_unlocked(run_id, quarantine_id)
    }

    fn inspect_unlocked(
        &self,
        run_id: &RunId,
        quarantine_id: &ArtifactQuarantineId,
    ) -> Result<ArtifactQuarantineRecord, ArtifactQuarantineError> {
        let binding = self.report_binding(run_id, quarantine_id)?;
        let metadata = self.read_metadata(quarantine_id)?;
        validate_binding(&binding, &metadata)?;
        self.verify_data(&metadata)?;
        Ok(record(run_id, metadata))
    }

    pub fn recover(
        &self,
        run_id: &RunId,
        quarantine_id: &ArtifactQuarantineId,
        destination: &Path,
    ) -> Result<ArtifactRecoveryReceipt, ArtifactQuarantineError> {
        let _lock = self.lock()?;
        let artifact = self.inspect_unlocked(run_id, quarantine_id)?;
        let (parent_fd, leaf) = destination_parent(destination)?;
        if fs::statat(&parent_fd, &leaf, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
            return Err(ArtifactQuarantineError::DestinationExists);
        }
        let source_name = safe_name(quarantine_id.as_str())?;
        let mut source = File::from(
            fs::openat(&self.root, &source_name, FILE_FLAGS, Mode::empty())
                .map_err(|_| ArtifactQuarantineError::Unavailable)?,
        );
        let temporary = temporary_name(quarantine_id)?;
        let temporary_fd = fs::openat(
            &parent_fd,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ArtifactQuarantineError::DestinationInvalid)?;
        let mut output = File::from(temporary_fd);
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut byte_len = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = source
                    .read(&mut buffer)
                    .map_err(|_| ArtifactQuarantineError::Integrity)?;
                if count == 0 {
                    break;
                }
                byte_len = byte_len
                    .checked_add(count as u64)
                    .ok_or(ArtifactQuarantineError::Integrity)?;
                hasher.update(&buffer[..count]);
                output
                    .write_all(&buffer[..count])
                    .map_err(|_| ArtifactQuarantineError::Durability)?;
            }
            if byte_len != artifact.byte_len {
                return Err(ArtifactQuarantineError::Integrity);
            }
            let expected = self.read_metadata(quarantine_id)?.identity.content_digest;
            if Digest::from_array(hasher.finalize().into()) != expected {
                return Err(ArtifactQuarantineError::Integrity);
            }
            output
                .sync_all()
                .map_err(|_| ArtifactQuarantineError::Durability)?;
            fs::renameat_with(
                &parent_fd,
                &temporary,
                &parent_fd,
                &leaf,
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    ArtifactQuarantineError::DestinationExists
                } else {
                    ArtifactQuarantineError::Durability
                }
            })?;
            fs::fsync(&parent_fd).map_err(|_| ArtifactQuarantineError::Durability)
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&parent_fd, &temporary, AtFlags::empty());
        }
        result?;
        Ok(ArtifactRecoveryReceipt {
            artifact,
            destination: destination.to_path_buf(),
        })
    }

    pub fn discard(
        &self,
        run_id: &RunId,
        quarantine_id: &ArtifactQuarantineId,
    ) -> Result<ArtifactDiscardReceipt, ArtifactQuarantineError> {
        let _lock = self.lock()?;
        let binding = self.report_binding(run_id, quarantine_id)?;
        let metadata_name = metadata_name(quarantine_id)?;
        let tombstone = tombstone_name(quarantine_id)?;
        let data_name = safe_name(quarantine_id.as_str())?;
        let metadata_exists =
            fs::statat(&self.root, &metadata_name, AtFlags::SYMLINK_NOFOLLOW).is_ok();
        let tombstone_exists =
            fs::statat(&self.root, &tombstone, AtFlags::SYMLINK_NOFOLLOW).is_ok();
        let data_exists = fs::statat(&self.root, &data_name, AtFlags::SYMLINK_NOFOLLOW).is_ok();
        if !metadata_exists && !tombstone_exists && !data_exists {
            return Ok(ArtifactDiscardReceipt {
                run_id: run_id.clone(),
                quarantine_id: quarantine_id.clone(),
                already_absent: true,
            });
        }
        if metadata_exists {
            let metadata = self.read_metadata(quarantine_id)?;
            validate_binding(&binding, &metadata)?;
            self.verify_data(&metadata)?;
            fs::renameat_with(
                &self.root,
                &metadata_name,
                &self.root,
                &tombstone,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| ArtifactQuarantineError::Durability)?;
            fs::fsync(&self.root).map_err(|_| ArtifactQuarantineError::Durability)?;
        } else if !tombstone_exists {
            return Err(ArtifactQuarantineError::Integrity);
        }
        unlink_if_present(&self.root, &data_name)?;
        fs::fsync(&self.root).map_err(|_| ArtifactQuarantineError::Durability)?;
        unlink_if_present(&self.root, &tombstone)?;
        fs::fsync(&self.root).map_err(|_| ArtifactQuarantineError::Durability)?;
        Ok(ArtifactDiscardReceipt {
            run_id: run_id.clone(),
            quarantine_id: quarantine_id.clone(),
            already_absent: false,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root_path
    }

    fn lock(&self) -> Result<File, ArtifactQuarantineError> {
        let name = safe_name(".artifact-quarantine.lock")?;
        let file = File::from(
            fs::openat(
                &self.root,
                &name,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| ArtifactQuarantineError::StoreUnavailable)?,
        );
        fs::flock(&file, FlockOperation::LockExclusive)
            .map_err(|_| ArtifactQuarantineError::StoreUnavailable)?;
        Ok(file)
    }

    fn report_binding(
        &self,
        run_id: &RunId,
        quarantine_id: &ArtifactQuarantineId,
    ) -> Result<ReportBinding, ArtifactQuarantineError> {
        let name = safe_name(&format!("{}.json", run_id.as_str()))?;
        let mut file = File::from(
            fs::openat(&self.reports, &name, FILE_FLAGS, Mode::empty())
                .map_err(|_| ArtifactQuarantineError::ReportUnavailable)?,
        );
        let metadata = file
            .metadata()
            .map_err(|_| ArtifactQuarantineError::ReportUnavailable)?;
        if !metadata.is_file() || metadata.len() > MAX_PRIVATE_JSON_BYTES {
            return Err(ArtifactQuarantineError::ReportUnavailable);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| ArtifactQuarantineError::ReportUnavailable)?;
        let report: ProcessingReport = serde_json::from_slice(&bytes)
            .map_err(|_| ArtifactQuarantineError::ReportUnavailable)?;
        report
            .validate()
            .map_err(|_| ArtifactQuarantineError::ReportUnavailable)?;
        if report.run_id.as_str() != run_id.as_str() {
            return Err(ArtifactQuarantineError::ReportBinding);
        }
        let action = report
            .actions
            .iter()
            .find(|action| {
                action
                    .artifact_quarantine_id
                    .as_ref()
                    .is_some_and(|id| id.as_str() == quarantine_id.as_str())
            })
            .ok_or(ArtifactQuarantineError::ReportBinding)?;
        if action.kind != ReportActionKind::Quarantine || action.state != ActionState::Committed {
            return Err(ArtifactQuarantineError::ReportBinding);
        }
        Ok(ReportBinding {
            action_id: action.action_id.as_str().to_owned(),
            subject_id: action.subject_id.as_str().to_owned(),
        })
    }

    fn read_metadata(
        &self,
        quarantine_id: &ArtifactQuarantineId,
    ) -> Result<ArtifactQuarantineMetadata, ArtifactQuarantineError> {
        let name = metadata_name(quarantine_id)?;
        let mut file = File::from(
            fs::openat(&self.root, &name, FILE_FLAGS, Mode::empty())
                .map_err(|_| ArtifactQuarantineError::Unavailable)?,
        );
        let metadata = file
            .metadata()
            .map_err(|_| ArtifactQuarantineError::Integrity)?;
        if !metadata.is_file() || metadata.len() > MAX_PRIVATE_JSON_BYTES {
            return Err(ArtifactQuarantineError::Integrity);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| ArtifactQuarantineError::Integrity)?;
        let metadata: ArtifactQuarantineMetadata =
            serde_json::from_slice(&bytes).map_err(|_| ArtifactQuarantineError::Integrity)?;
        if metadata.quarantine_id != *quarantine_id || !metadata.validate_stored_record() {
            return Err(ArtifactQuarantineError::Integrity);
        }
        Ok(metadata)
    }

    fn verify_data(
        &self,
        metadata: &ArtifactQuarantineMetadata,
    ) -> Result<(), ArtifactQuarantineError> {
        let name = safe_name(metadata.quarantine_id.as_str())?;
        let mut file = File::from(
            fs::openat(&self.root, &name, FILE_FLAGS, Mode::empty())
                .map_err(|_| ArtifactQuarantineError::Unavailable)?,
        );
        let stat = fs::fstat(file.as_fd()).map_err(|_| ArtifactQuarantineError::Integrity)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || stat.st_nlink != 1
            || u64::try_from(stat.st_size).ok() != Some(metadata.identity.byte_len)
        {
            return Err(ArtifactQuarantineError::Integrity);
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| ArtifactQuarantineError::Integrity)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        if Digest::from_array(hasher.finalize().into()) != metadata.identity.content_digest {
            return Err(ArtifactQuarantineError::Integrity);
        }
        Ok(())
    }
}

struct ReportBinding {
    action_id: String,
    subject_id: String,
}

fn validate_binding(
    binding: &ReportBinding,
    metadata: &ArtifactQuarantineMetadata,
) -> Result<(), ArtifactQuarantineError> {
    if metadata.action_id.as_str() != binding.action_id
        || metadata.subject_id.as_str() != binding.subject_id
    {
        return Err(ArtifactQuarantineError::ReportBinding);
    }
    Ok(())
}

fn record(run_id: &RunId, metadata: ArtifactQuarantineMetadata) -> ArtifactQuarantineRecord {
    ArtifactQuarantineRecord {
        run_id: run_id.clone(),
        quarantine_id: metadata.quarantine_id,
        action_id: metadata.action_id,
        subject_id: metadata.subject_id,
        logical_path: metadata.logical_path,
        byte_len: metadata.identity.byte_len,
    }
}

fn secure_root(path: &Path) -> Result<PathBuf, ArtifactQuarantineError> {
    if !path.is_absolute() {
        return Err(ArtifactQuarantineError::StoreUnavailable);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ArtifactQuarantineError::StoreUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ArtifactQuarantineError::StoreUnavailable);
    }
    std::fs::canonicalize(path).map_err(|_| ArtifactQuarantineError::StoreUnavailable)
}

fn open_root(path: &Path) -> Result<OwnedFd, ArtifactQuarantineError> {
    fs::open(path, ROOT_FLAGS, Mode::empty()).map_err(|_| ArtifactQuarantineError::StoreUnavailable)
}

fn destination_parent(destination: &Path) -> Result<(OwnedFd, CString), ArtifactQuarantineError> {
    if !destination.is_absolute() {
        return Err(ArtifactQuarantineError::DestinationInvalid);
    }
    let leaf = destination
        .file_name()
        .filter(|value| !value.as_bytes().is_empty())
        .ok_or(ArtifactQuarantineError::DestinationInvalid)?;
    let leaf = safe_os_name(leaf)?;
    let parent = destination
        .parent()
        .ok_or(ArtifactQuarantineError::DestinationInvalid)?;
    let mut current = fs::open("/", ROOT_FLAGS, Mode::empty())
        .map_err(|_| ArtifactQuarantineError::DestinationInvalid)?;
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = fs::openat(&current, name, ROOT_FLAGS, Mode::empty())
                    .map_err(|_| ArtifactQuarantineError::DestinationInvalid)?;
            }
            _ => return Err(ArtifactQuarantineError::DestinationInvalid),
        }
    }
    let stat = fs::fstat(&current).map_err(|_| ArtifactQuarantineError::DestinationInvalid)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(ArtifactQuarantineError::DestinationUntrusted);
    }
    Ok((current, leaf))
}

fn metadata_name(id: &ArtifactQuarantineId) -> Result<CString, ArtifactQuarantineError> {
    safe_name(&format!("{}.json", id.as_str()))
}

fn tombstone_name(id: &ArtifactQuarantineId) -> Result<CString, ArtifactQuarantineError> {
    safe_name(&format!(".{}.discarding", id.as_str()))
}

fn temporary_name(id: &ArtifactQuarantineId) -> Result<CString, ArtifactQuarantineError> {
    safe_name(&format!(
        ".{}.{}.recovering",
        id.as_str(),
        std::process::id()
    ))
}

fn safe_name(value: &str) -> Result<CString, ArtifactQuarantineError> {
    safe_os_name(OsStr::new(value))
}

fn safe_os_name(value: &OsStr) -> Result<CString, ArtifactQuarantineError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(ArtifactQuarantineError::DestinationInvalid);
    }
    CString::new(bytes).map_err(|_| ArtifactQuarantineError::DestinationInvalid)
}

fn unlink_if_present(root: &OwnedFd, name: &CString) -> Result<(), ArtifactQuarantineError> {
    match fs::unlinkat(root, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(_) => Err(ArtifactQuarantineError::Durability),
    }
}
