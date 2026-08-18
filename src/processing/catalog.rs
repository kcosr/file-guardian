//! Immutable schema-3 artifact catalog construction.
//!
//! Catalog construction is the only point that reads a job-owned publication
//! stage or frozen Git bytes. Analyzer backends receive `JobArtifactReader`,
//! which resolves only content-addressed objects in the invocation workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::analyzers::{ArtifactReadError, ArtifactReader};
use crate::authorization::{CaptureLimits, InvocationWorkspace, Snapshotter};
use crate::domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactManifest, Digest, LogicalPath, ObjectId,
    PhysicalSubject, Provenance, SubjectId,
};
use crate::processing::acquisition::git::FrozenGitRepository;
use crate::processing::acquisition::local::{
    capture_owned_stage, AcquiredEntry, AcquiredEntryKind, AcquisitionCancellation,
    LocalAcquisitionResult,
};
use crate::processing::config::{AnalyzerArtifactKind, CaptureLimits as PublicationCaptureLimits};
use crate::processing::executor::{
    ProcessingArtifact, ProcessingArtifactCatalog, ProcessingArtifactSurface,
    ProcessingExecutorError,
};
use crate::processing::external_backend::{ProcessingArtifactReadError, ProcessingArtifactReader};
use crate::processing::report::PublicationType;
use crate::processing::report_builder::{ArtifactPublication, ReportArtifactMetadata};
use crate::processing::{GitHistoryScope, GitProvenance, ProcessingDomainError};

/// A verified working-tree publication staged under the job root.
#[derive(Clone, Copy)]
pub struct WorkingTreeCatalogInput<'a> {
    pub stage: &'a Path,
    pub jobs_root: &'a Path,
    pub acquisition: &'a LocalAcquisitionResult,
}

/// Frozen repository history selected for this job.
#[derive(Clone, Copy)]
pub struct GitHistoryCatalogInput<'a> {
    pub repository: &'a FrozenGitRepository,
    pub scope: GitHistoryScope,
}

/// Inputs for one immutable analyzer catalog. At least one surface is required.
#[derive(Clone, Copy)]
pub struct ProcessingCatalogCaptureRequest<'a> {
    pub working_tree: Option<WorkingTreeCatalogInput<'a>>,
    pub git_history: Option<GitHistoryCatalogInput<'a>>,
    pub capture_limits: CaptureLimits,
}

/// Captured analyzer state and the separate publication/report projections.
pub struct CapturedProcessingCatalog {
    pub artifacts: Arc<ProcessingArtifactCatalog>,
    /// Exact regular-file capture consumed by the legacy built-in analyzer.
    /// Symbolic-link targets and repository blobs remain available through the
    /// processing reader but are not misrepresented as physical source files.
    pub builtin_manifest: Arc<ArtifactManifest>,
    pub reader: Arc<JobArtifactReader>,
    pub publication_entries: Vec<AcquiredEntry>,
    pub report_metadata: Vec<ReportArtifactMetadata>,
    pub snapshot_identity: Digest,
}

/// Artifact-to-object mapping backed by one retained invocation workspace.
pub struct JobArtifactReader {
    workspace: Arc<InvocationWorkspace>,
    objects: BTreeMap<ArtifactId, ObjectId>,
}

impl std::fmt::Debug for JobArtifactReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobArtifactReader")
            .field("workspace", &"<private>")
            .field("artifact_count", &self.objects.len())
            .finish()
    }
}

impl ProcessingArtifactReader for JobArtifactReader {
    fn open(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Box<dyn Read + Send>, ProcessingArtifactReadError> {
        let object_id = self
            .objects
            .get(artifact_id)
            .ok_or(ProcessingArtifactReadError::Unavailable)?;
        self.workspace
            .objects()
            .open(object_id)
            .map(|file| Box::new(file) as Box<dyn Read + Send>)
            .map_err(|_| ProcessingArtifactReadError::Unavailable)
    }
}

impl ArtifactReader for JobArtifactReader {
    fn open_object(&self, object_id: &ObjectId) -> Result<Box<dyn Read + '_>, ArtifactReadError> {
        self.workspace
            .objects()
            .open(object_id)
            .map(|file| Box::new(file) as Box<dyn Read>)
            .map_err(|_| ArtifactReadError::Unavailable)
    }
}

#[derive(Debug, Error)]
pub enum ProcessingCatalogError {
    #[error("processing catalog must contain a working tree or Git history")]
    Empty,
    #[error("working-tree publication manifest is invalid")]
    InvalidPublication,
    #[error("job-owned working tree changed before immutable capture completed")]
    WorkingTreeChanged,
    #[error("immutable working-tree capture failed")]
    CaptureFailed,
    #[error("frozen Git catalog is inconsistent")]
    InvalidGit,
    #[error("captured object could not be stored")]
    ObjectStore,
    #[error("processing artifact identity could not be constructed")]
    Identity,
    #[error("processing artifact catalog is invalid")]
    Catalog,
    #[error("captured built-in manifest is invalid")]
    Manifest,
}

/// Captures all selected surfaces into one workspace-backed artifact reader.
pub fn capture_processing_catalog(
    workspace: Arc<InvocationWorkspace>,
    request: ProcessingCatalogCaptureRequest<'_>,
) -> Result<CapturedProcessingCatalog, ProcessingCatalogError> {
    if request.working_tree.is_none() && request.git_history.is_none() {
        return Err(ProcessingCatalogError::Empty);
    }
    let mut state = CatalogState::new(Arc::clone(&workspace));
    let mut publication_entries = Vec::new();
    let mut working_identity = None;
    if let Some(working) = request.working_tree {
        publication_entries = canonical_publication(working.acquisition)?;
        capture_working_tree(
            &mut state,
            working,
            request.capture_limits,
            &publication_entries,
        )?;
        working_identity = Some(working.acquisition.manifest_identity);
    }
    let mut git_identity = None;
    if let Some(git) = request.git_history {
        capture_git_history(&mut state, git, request.capture_limits.max_file_bytes)?;
        git_identity = Some((git.repository.repository_identity, git.scope));
    }

    state
        .artifacts
        .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let snapshot_identity = snapshot_identity(
        working_identity,
        git_identity,
        &state.artifacts,
        &publication_entries,
    );
    let artifacts = ProcessingArtifactCatalog::new(state.artifacts).map_err(map_catalog_error)?;
    let builtin_manifest = ArtifactManifest::new(state.subjects, state.builtin_artifacts)
        .map_err(|_| ProcessingCatalogError::Manifest)?;
    state
        .report_metadata
        .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(CapturedProcessingCatalog {
        artifacts: Arc::new(artifacts),
        builtin_manifest: Arc::new(builtin_manifest),
        reader: Arc::new(JobArtifactReader {
            workspace,
            objects: state.objects,
        }),
        publication_entries,
        report_metadata: state.report_metadata,
        snapshot_identity,
    })
}

struct CatalogState {
    workspace: Arc<InvocationWorkspace>,
    artifacts: Vec<ProcessingArtifact>,
    subjects: Vec<PhysicalSubject>,
    builtin_artifacts: Vec<Artifact>,
    report_metadata: Vec<ReportArtifactMetadata>,
    objects: BTreeMap<ArtifactId, ObjectId>,
}

impl CatalogState {
    fn new(workspace: Arc<InvocationWorkspace>) -> Self {
        Self {
            workspace,
            artifacts: Vec::new(),
            subjects: Vec::new(),
            builtin_artifacts: Vec::new(),
            report_metadata: Vec::new(),
            objects: BTreeMap::new(),
        }
    }

    fn add_object(
        &mut self,
        artifact: ProcessingArtifact,
        object_id: ObjectId,
        subject_id: SubjectId,
        publication: ArtifactPublication,
    ) -> Result<(), ProcessingCatalogError> {
        if self
            .objects
            .insert(artifact.artifact_id.clone(), object_id)
            .is_some()
        {
            return Err(ProcessingCatalogError::Identity);
        }
        self.report_metadata.push(ReportArtifactMetadata {
            artifact_id: artifact.artifact_id.clone(),
            subject_id,
            publication,
        });
        self.artifacts.push(artifact);
        Ok(())
    }
}

fn canonical_publication(
    acquisition: &LocalAcquisitionResult,
) -> Result<Vec<AcquiredEntry>, ProcessingCatalogError> {
    let mut entries = acquisition.entries.clone();
    entries.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    if entries
        .windows(2)
        .any(|pair| pair[0].logical_path == pair[1].logical_path)
        || publication_identity(&entries)? != acquisition.manifest_identity
    {
        return Err(ProcessingCatalogError::InvalidPublication);
    }
    Ok(entries)
}

fn capture_working_tree(
    state: &mut CatalogState,
    input: WorkingTreeCatalogInput<'_>,
    limits: CaptureLimits,
    entries: &[AcquiredEntry],
) -> Result<(), ProcessingCatalogError> {
    require_current_publication(input, limits, entries)?;
    for entry in entries {
        match entry.kind {
            AcquiredEntryKind::Directory => {}
            AcquiredEntryKind::RegularFile => {
                capture_regular(state, input.stage, entry, limits)?;
            }
            AcquiredEntryKind::SymbolicLink => capture_symlink(state, input.stage, entry, limits)?,
        }
    }
    require_current_publication(input, limits, entries)
}

fn require_current_publication(
    input: WorkingTreeCatalogInput<'_>,
    limits: CaptureLimits,
    entries: &[AcquiredEntry],
) -> Result<(), ProcessingCatalogError> {
    let recaptured = capture_owned_stage(
        input.stage,
        input.jobs_root,
        input.acquisition.input_kind,
        &PublicationCaptureLimits {
            max_entries: limits.max_entries,
            max_files: limits.max_files,
            max_file_bytes: limits.max_file_bytes,
            max_total_bytes: limits.max_total_bytes,
            max_depth: limits.max_depth,
        },
        crate::processing::config::SymlinkPolicy::Preserve,
        &AcquisitionCancellation::default(),
    )
    .map_err(|_| ProcessingCatalogError::WorkingTreeChanged)?;
    if recaptured.manifest_identity != input.acquisition.manifest_identity
        || recaptured.entries != entries
    {
        return Err(ProcessingCatalogError::WorkingTreeChanged);
    }
    Ok(())
}

fn capture_regular(
    state: &mut CatalogState,
    stage: &Path,
    entry: &AcquiredEntry,
    limits: CaptureLimits,
) -> Result<(), ProcessingCatalogError> {
    let path = stage_path(stage, &entry.logical_path);
    let snapshot = Snapshotter::new(&state.workspace, limits)
        .capture(&path)
        .map_err(|_| ProcessingCatalogError::CaptureFailed)?;
    if snapshot.manifest.artifacts().len() != 1 {
        return Err(ProcessingCatalogError::CaptureFailed);
    }
    let captured = &snapshot.manifest.artifacts()[0];
    let captured_subject = snapshot
        .manifest
        .subjects()
        .first()
        .ok_or(ProcessingCatalogError::CaptureFailed)?;
    if captured.byte_len != entry.byte_len || captured.content_digest != entry.content_digest {
        return Err(ProcessingCatalogError::WorkingTreeChanged);
    }
    let artifact_id = processing_artifact_id(
        b"working-regular",
        &entry.logical_path,
        entry.content_digest,
        &[],
    )?;
    let subject_id = processing_subject_id(&artifact_id)?;
    let subject = PhysicalSubject {
        id: subject_id.clone(),
        relative_path: entry.logical_path.clone(),
        source_identity: captured_subject.source_identity.clone(),
        object_id: captured.object_id.clone(),
        byte_len: captured.byte_len,
    };
    let artifact = Artifact {
        id: artifact_id.clone(),
        subject_id: subject_id.clone(),
        object_id: captured.object_id.clone(),
        kind: ArtifactKind::PhysicalFile,
        byte_len: captured.byte_len,
        content_digest: captured.content_digest,
        provenance: Provenance::Physical {
            logical_path: entry.logical_path.clone(),
        },
    };
    state.subjects.push(subject);
    state.builtin_artifacts.push(artifact);
    state.add_object(
        ProcessingArtifact {
            artifact_id,
            logical_path: entry.logical_path.clone(),
            kind: AnalyzerArtifactKind::PhysicalFile,
            byte_len: entry.byte_len,
            content_digest: entry.content_digest,
            surface: ProcessingArtifactSurface::WorkingTree,
        },
        captured.object_id.clone(),
        subject_id,
        ArtifactPublication {
            publication_type: PublicationType::RegularFile,
            publication_mode: Some(entry.publication_mode),
        },
    )
}

fn capture_symlink(
    state: &mut CatalogState,
    stage: &Path,
    entry: &AcquiredEntry,
    limits: CaptureLimits,
) -> Result<(), ProcessingCatalogError> {
    let path = stage_path(stage, &entry.logical_path);
    let before =
        fs::symlink_metadata(&path).map_err(|_| ProcessingCatalogError::WorkingTreeChanged)?;
    if !before.file_type().is_symlink() {
        return Err(ProcessingCatalogError::WorkingTreeChanged);
    }
    let target = fs::read_link(&path)
        .map_err(|_| ProcessingCatalogError::WorkingTreeChanged)?
        .into_os_string()
        .into_vec();
    let after =
        fs::symlink_metadata(&path).map_err(|_| ProcessingCatalogError::WorkingTreeChanged)?;
    if !same_symlink(&before, &after)
        || u64::try_from(target.len()).ok() != Some(entry.byte_len)
        || Digest::sha256(&target) != entry.content_digest
    {
        return Err(ProcessingCatalogError::WorkingTreeChanged);
    }
    let mut source = Cursor::new(target);
    let stored = state
        .workspace
        .objects()
        .store(&mut source, limits.max_file_bytes)
        .map_err(|_| ProcessingCatalogError::ObjectStore)?;
    let artifact_id = processing_artifact_id(
        b"working-symlink",
        &entry.logical_path,
        entry.content_digest,
        &[],
    )?;
    let subject_id = processing_subject_id(&artifact_id)?;
    state.add_object(
        ProcessingArtifact {
            artifact_id,
            logical_path: entry.logical_path.clone(),
            kind: AnalyzerArtifactKind::SymbolicLink,
            byte_len: entry.byte_len,
            content_digest: entry.content_digest,
            surface: ProcessingArtifactSurface::WorkingTree,
        },
        stored.id,
        subject_id,
        ArtifactPublication {
            publication_type: PublicationType::Symlink,
            publication_mode: None,
        },
    )
}

fn capture_git_history(
    state: &mut CatalogState,
    input: GitHistoryCatalogInput<'_>,
    max_file_bytes: u64,
) -> Result<(), ProcessingCatalogError> {
    if input.scope == GitHistoryScope::None {
        if input.repository.blobs.is_empty() {
            return Ok(());
        }
        return Err(ProcessingCatalogError::InvalidGit);
    }
    let selected_commits = input
        .repository
        .commits
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if selected_commits.is_empty()
        || selected_commits.len() != input.repository.commits.len()
        || (input.scope == GitHistoryScope::Head
            && (selected_commits.len() != 1
                || !selected_commits.contains(&input.repository.resolved_head)))
    {
        return Err(ProcessingCatalogError::InvalidGit);
    }
    let mut object_ids = BTreeSet::new();
    let mut provenance_occurrences = BTreeSet::new();
    for blob in &input.repository.blobs {
        let canonical = GitProvenance::new(
            blob.provenance.blob_id.clone(),
            blob.provenance.mode,
            blob.provenance.occurrences.clone(),
        )
        .map_err(map_domain_error)?;
        if canonical != blob.provenance
            || blob.object_id != blob.provenance.blob_id
            || blob.object_store_identity != Digest::sha256(&blob.bytes)
            || blob.symbolic_link
                != matches!(
                    blob.provenance.mode,
                    crate::processing::GitBlobMode::SymbolicLink
                )
            || !object_ids.insert(blob.object_id.clone())
        {
            return Err(ProcessingCatalogError::InvalidGit);
        }
        for occurrence in &blob.provenance.occurrences {
            if !selected_commits.contains(&occurrence.commit_id) {
                return Err(ProcessingCatalogError::InvalidGit);
            }
            if !provenance_occurrences
                .insert((occurrence.commit_id.clone(), occurrence.path.clone()))
            {
                return Err(ProcessingCatalogError::InvalidGit);
            }
        }
        let logical_path = blob.provenance.occurrences[0].path.clone();
        let provenance_bytes =
            serde_json::to_vec(&blob.provenance).map_err(|_| ProcessingCatalogError::InvalidGit)?;
        let artifact_id = processing_artifact_id(
            b"git-history",
            &logical_path,
            blob.object_store_identity,
            &provenance_bytes,
        )?;
        let subject_id = processing_subject_id(&artifact_id)?;
        let mut source = Cursor::new(&blob.bytes);
        let stored = state
            .workspace
            .objects()
            .store(&mut source, max_file_bytes)
            .map_err(|_| ProcessingCatalogError::ObjectStore)?;
        state.add_object(
            ProcessingArtifact {
                artifact_id,
                logical_path,
                kind: AnalyzerArtifactKind::RepositoryBlob,
                byte_len: u64::try_from(blob.bytes.len())
                    .map_err(|_| ProcessingCatalogError::InvalidGit)?,
                content_digest: blob.object_store_identity,
                surface: ProcessingArtifactSurface::GitHistory {
                    repository_identity: input.repository.repository_identity,
                    history_scope: input.scope,
                    provenance: blob.provenance.clone(),
                },
            },
            stored.id,
            subject_id,
            ArtifactPublication {
                publication_type: PublicationType::Nonphysical,
                publication_mode: None,
            },
        )?;
    }
    Ok(())
}

fn stage_path(stage: &Path, logical: &LogicalPath) -> PathBuf {
    let mut output = stage.to_path_buf();
    for segment in logical.segments() {
        output.push(OsStr::from_bytes(segment.as_slice()));
    }
    output
}

#[cfg(unix)]
fn same_symlink(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.file_type().is_symlink()
        && right.file_type().is_symlink()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn processing_artifact_id(
    kind: &[u8],
    logical_path: &LogicalPath,
    digest: Digest,
    provenance: &[u8],
) -> Result<ArtifactId, ProcessingCatalogError> {
    let mut hash = Sha256::new();
    hash_component(&mut hash, b"file-guardian/processing-artifact/1");
    hash_component(&mut hash, kind);
    for segment in logical_path.segments() {
        hash_component(&mut hash, segment.as_slice());
    }
    hash_component(&mut hash, b"end-path");
    hash_component(&mut hash, digest.as_bytes());
    hash_component(&mut hash, provenance);
    let suffix = hex_prefix(hash.finalize().as_slice(), 24);
    ArtifactId::from_suffix(format!("pc_{suffix}")).map_err(|_| ProcessingCatalogError::Identity)
}

fn processing_subject_id(artifact_id: &ArtifactId) -> Result<SubjectId, ProcessingCatalogError> {
    let suffix = artifact_id
        .as_str()
        .strip_prefix("a_")
        .ok_or(ProcessingCatalogError::Identity)?;
    SubjectId::from_suffix(suffix).map_err(|_| ProcessingCatalogError::Identity)
}

fn snapshot_identity(
    working: Option<Digest>,
    git: Option<(Digest, GitHistoryScope)>,
    artifacts: &[ProcessingArtifact],
    publication: &[AcquiredEntry],
) -> Digest {
    let mut hash = Sha256::new();
    hash_component(&mut hash, b"file-guardian/processing-snapshot/1");
    optional_digest(&mut hash, working);
    match git {
        Some((repository, scope)) => {
            hash_component(&mut hash, b"git");
            hash_component(&mut hash, repository.as_bytes());
            hash_component(&mut hash, history_scope_name(scope));
        }
        None => hash_component(&mut hash, b"no-git"),
    }
    for artifact in artifacts {
        hash_component(&mut hash, artifact.artifact_id.as_str().as_bytes());
        hash_component(&mut hash, artifact.content_digest.as_bytes());
    }
    for entry in publication {
        for segment in entry.logical_path.segments() {
            hash_component(&mut hash, segment.as_slice());
        }
        hash_component(&mut hash, b"end-publication-path");
    }
    Digest::from_array(hash.finalize().into())
}

fn optional_digest(hash: &mut Sha256, digest: Option<Digest>) {
    match digest {
        Some(digest) => {
            hash_component(hash, b"some");
            hash_component(hash, digest.as_bytes());
        }
        None => hash_component(hash, b"none"),
    }
}

fn hash_component(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes[..count]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const fn history_scope_name(scope: GitHistoryScope) -> &'static [u8] {
    match scope {
        GitHistoryScope::None => b"none",
        GitHistoryScope::Head => b"head",
        GitHistoryScope::Reachable => b"reachable",
        GitHistoryScope::AllRefs => b"all-refs",
    }
}

#[derive(Serialize)]
struct PublicationManifest<'a> {
    schema: &'static str,
    entries: &'a [AcquiredEntry],
}

fn publication_identity(entries: &[AcquiredEntry]) -> Result<Digest, ProcessingCatalogError> {
    serde_json::to_vec(&PublicationManifest {
        schema: "file-guardian-publication-manifest/2",
        entries,
    })
    .map(Digest::sha256)
    .map_err(|_| ProcessingCatalogError::InvalidPublication)
}

fn map_catalog_error(_error: ProcessingExecutorError) -> ProcessingCatalogError {
    ProcessingCatalogError::Catalog
}

fn map_domain_error(_error: ProcessingDomainError) -> ProcessingCatalogError {
    ProcessingCatalogError::InvalidGit
}
