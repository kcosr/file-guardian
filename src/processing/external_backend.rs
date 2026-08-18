//! Schema-3 bridge from immutable processing assignments to the confined
//! first-party external scanner runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::analyzers::external::{
    AssignmentDisposition as ScannerDisposition, ExternalScannerRunner, FirstPartyScannerAdapter,
    FirstPartyScannerInvocation, GitleaksAdapter, ScannerAdapterContext, ScannerAssignment,
    ScannerAssignmentSurface, ScannerCancellation, ScannerKind, ScannerRunError, TrufflehogAdapter,
};
use crate::domain::{
    ArtifactId, CandidateId, Digest, Finding, NormalizedObservation, SafeEvidence,
    ValidatedLocation,
};
use crate::processing::executor::{
    AnalyzerBackendError, AnalyzerBackendOutput, AnalyzerInvocation, AssignmentDisposition,
    AssignmentOutcome, BackendFuture, BackendObservationEvidence, ExternalProcessingBackend,
    ProcessingArtifactSurface, ProcessingAssignment,
};
use crate::processing::runtime::FrozenExternalAnalyzer;
use crate::processing::CredentialVerificationState;
use globset::{Candidate, GlobBuilder, GlobSet, GlobSetBuilder};
use sha2::{Digest as _, Sha256};

/// Opens content from the immutable acquisition snapshot, never from a live
/// caller path. Implementations must return a fresh reader positioned at zero.
pub trait ProcessingArtifactReader: Send + Sync {
    fn open(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Box<dyn Read + Send>, ProcessingArtifactReadError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProcessingArtifactReadError {
    #[error("immutable processing artifact is unavailable")]
    Unavailable,
}

/// Executes schema-3 Gitleaks and TruffleHog selections in the reviewed
/// Bubblewrap runtime. Debug output deliberately omits the private workspace
/// and content source.
pub struct ConfinedExternalProcessingBackend {
    private_root: PathBuf,
    reader: Arc<dyn ProcessingArtifactReader>,
    cancellation: ScannerCancellation,
}

impl std::fmt::Debug for ConfinedExternalProcessingBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfinedExternalProcessingBackend")
            .field("private_root", &"<private>")
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl ConfinedExternalProcessingBackend {
    pub fn new(
        private_root: impl AsRef<Path>,
        reader: Arc<dyn ProcessingArtifactReader>,
        cancellation: ScannerCancellation,
    ) -> Result<Self, ExternalProcessingBackendError> {
        let private_root = private_root.as_ref();
        if !private_root.is_absolute() {
            return Err(ExternalProcessingBackendError::PrivateWorkspace);
        }
        let metadata = fs::symlink_metadata(private_root)
            .map_err(|_| ExternalProcessingBackendError::PrivateWorkspace)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ExternalProcessingBackendError::PrivateWorkspace);
        }
        let private_root = fs::canonicalize(private_root)
            .map_err(|_| ExternalProcessingBackendError::PrivateWorkspace)?;
        Ok(Self {
            private_root,
            reader,
            cancellation,
        })
    }

    async fn execute_inner(
        &self,
        runtime: &FrozenExternalAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> Result<AnalyzerBackendOutput, AnalyzerBackendError> {
        if self.cancellation.is_cancelled() {
            return Err(AnalyzerBackendError::Cancelled);
        }
        let required_text = compile_required_text(&runtime.required_text_include)
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?;
        let material = MaterializeRequest {
            root: self.private_root.clone(),
            reader: Arc::clone(&self.reader),
            assignments: Arc::clone(&invocation.assignments),
            required_text,
            max_file_bytes: runtime.max_file_bytes,
            cancellation: self.cancellation.clone(),
        };
        let view = tokio::task::spawn_blocking(move || materialize(material))
            .await
            .map_err(|_| AnalyzerBackendError::Unavailable)?
            .map_err(map_materialization_error)?;

        let runner = ExternalScannerRunner::new(runtime.sandbox.clone());
        let requirement = runtime.scanner_version_requirement();
        let native = match runtime.kind {
            ScannerKind::Gitleaks if runtime.protected_files.len() == 2 => {
                runner
                    .run(
                        &runtime.executable,
                        requirement,
                        FirstPartyScannerInvocation::Gitleaks {
                            input_view: view.input(),
                            output_directory: view.output(),
                            config: &runtime.protected_files[0],
                            ignore: &runtime.protected_files[1],
                        },
                        runtime.limits.clone(),
                        self.cancellation.clone(),
                    )
                    .await
            }
            ScannerKind::Trufflehog if runtime.protected_files.is_empty() => {
                runner
                    .run(
                        &runtime.executable,
                        requirement,
                        FirstPartyScannerInvocation::Trufflehog {
                            input_view: view.input(),
                            output_directory: view.output(),
                        },
                        runtime.limits.clone(),
                        self.cancellation.clone(),
                    )
                    .await
            }
            _ => return Err(AnalyzerBackendError::InvalidOutput),
        }
        .map_err(map_run_error)?;
        view.revalidate()
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?;

        let adapter_context = ScannerAdapterContext {
            analyzer_id: &invocation.analyzer_id,
            phase: invocation.phase,
            assignments: view.assignments(),
            max_file_bytes: runtime.max_file_bytes,
            max_findings: runtime.max_findings,
        };
        let completion = match runtime.kind {
            ScannerKind::Gitleaks => GitleaksAdapter::with_version_requirement(requirement)
                .and_then(|adapter| adapter.normalize(adapter_context, &native)),
            ScannerKind::Trufflehog => TrufflehogAdapter::with_version_requirement(requirement)
                .and_then(|adapter| adapter.normalize(adapter_context, &native)),
        }
        .map_err(|_| AnalyzerBackendError::InvalidOutput)?;

        let evidence = completion
            .occurrences
            .iter()
            .filter_map(|occurrence| {
                occurrence.location.as_ref().map(|location| {
                    view.evidence_window(&occurrence.candidate_id, location)
                        .map(|canonical_window| BackendObservationEvidence {
                            observation_id: occurrence.occurrence_id.clone(),
                            canonical_window,
                            verification_state: CredentialVerificationState::Unverified,
                        })
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?;
        let assignments = view
            .assignments()
            .iter()
            .map(|assignment| AssignmentOutcome {
                candidate_id: assignment.candidate_id.clone(),
                disposition: match assignment.disposition {
                    ScannerDisposition::Scan => AssignmentDisposition::Completed,
                    ScannerDisposition::NotApplicable => AssignmentDisposition::NotApplicable,
                },
            })
            .collect();
        let observations = completion
            .occurrences
            .into_iter()
            .map(|occurrence| {
                NormalizedObservation::Finding(Finding {
                    id: occurrence.occurrence_id,
                    analyzer_id: invocation.analyzer_id.clone(),
                    rule_id: occurrence.rule_id,
                    artifact_id: occurrence.artifact_id,
                    category: occurrence.category,
                    severity: occurrence.severity,
                    location: occurrence.location,
                    evidence: SafeEvidence::default(),
                })
            })
            .collect();
        Ok(AnalyzerBackendOutput {
            assignments,
            observations,
            evidence,
            scanner_version: Some(native.version),
            pi_analysis: None,
        })
    }
}

impl ExternalProcessingBackend for ConfinedExternalProcessingBackend {
    fn execute<'a>(
        &'a self,
        runtime: &'a FrozenExternalAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a> {
        Box::pin(async move { self.execute_inner(runtime, invocation).await })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExternalProcessingBackendError {
    #[error("external scanner private workspace is invalid")]
    PrivateWorkspace,
}

struct MaterializeRequest {
    root: PathBuf,
    reader: Arc<dyn ProcessingArtifactReader>,
    assignments: Arc<[ProcessingAssignment]>,
    required_text: GlobSet,
    max_file_bytes: u64,
    cancellation: ScannerCancellation,
}

struct MaterializedScannerView {
    _directory: PrivateTemporaryDirectory,
    input: PathBuf,
    output: PathBuf,
    assignments: Vec<ScannerAssignment>,
    content_digests: BTreeMap<String, Digest>,
}

impl MaterializedScannerView {
    fn input(&self) -> &Path {
        &self.input
    }

    fn output(&self) -> &Path {
        &self.output
    }

    fn assignments(&self) -> &[ScannerAssignment] {
        &self.assignments
    }

    fn revalidate(&self) -> Result<(), MaterializationError> {
        let expected = self
            .assignments
            .iter()
            .filter(|assignment| assignment.disposition == ScannerDisposition::Scan)
            .map(|assignment| {
                let digest = self
                    .content_digests
                    .get(&assignment.view_path)
                    .copied()
                    .ok_or(MaterializationError::InvalidContent)?;
                Ok((assignment.view_path.as_str(), (assignment, digest)))
            })
            .collect::<Result<BTreeMap<_, _>, MaterializationError>>()?;
        let mut seen = BTreeSet::new();
        revalidate_directory(&self.input, &self.input, &expected, &mut seen)?;
        if seen.len() != expected.len() {
            return Err(MaterializationError::InvalidContent);
        }
        Ok(())
    }

    fn evidence_window(
        &self,
        candidate_id: &CandidateId,
        location: &ValidatedLocation,
    ) -> Result<Vec<u8>, MaterializationError> {
        let assignment = self
            .assignments
            .iter()
            .find(|assignment| {
                &assignment.candidate_id == candidate_id
                    && assignment.disposition == ScannerDisposition::Scan
            })
            .ok_or(MaterializationError::InvalidContent)?;
        let bytes = fs::read(self.input.join(&assignment.view_path))
            .map_err(|_| MaterializationError::InvalidContent)?;
        canonical_evidence_window(&bytes, location).ok_or(MaterializationError::InvalidContent)
    }
}

fn revalidate_directory<'a>(
    root: &Path,
    directory: &Path,
    expected: &BTreeMap<&'a str, (&'a ScannerAssignment, Digest)>,
    seen: &mut BTreeSet<String>,
) -> Result<(), MaterializationError> {
    for entry in fs::read_dir(directory).map_err(|_| MaterializationError::InvalidContent)? {
        let entry = entry.map_err(|_| MaterializationError::InvalidContent)?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| MaterializationError::InvalidContent)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(MaterializationError::InvalidContent);
        }
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(Path::to_str)
            .ok_or(MaterializationError::InvalidContent)?;
        if metadata.is_dir() {
            let prefix = format!("{relative}/");
            if !expected.keys().any(|path| path.starts_with(&prefix)) {
                return Err(MaterializationError::InvalidContent);
            }
            revalidate_directory(root, &path, expected, seen)?;
            continue;
        }
        let (assignment, content_digest) = expected
            .get(relative)
            .ok_or(MaterializationError::InvalidContent)?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o177 != 0
            || metadata.len() != assignment.byte_len
            || !seen.insert(relative.to_owned())
        {
            return Err(MaterializationError::InvalidContent);
        }
        let bytes = fs::read(&path).map_err(|_| MaterializationError::InvalidContent)?;
        if Digest::sha256(&bytes) != *content_digest {
            return Err(MaterializationError::InvalidContent);
        }
    }
    Ok(())
}

const MAX_EVIDENCE_WINDOW_BYTES: usize = 512;

pub(crate) fn canonical_evidence_window(
    bytes: &[u8],
    location: &ValidatedLocation,
) -> Option<Vec<u8>> {
    let window = match *location {
        ValidatedLocation::ByteRange {
            start,
            end_exclusive,
        } => {
            let start = usize::try_from(start).ok()?;
            let end = usize::try_from(end_exclusive).ok()?;
            if start >= end || end > bytes.len() {
                return None;
            }
            let center = start.saturating_add((end - start) / 2);
            let left = center
                .saturating_sub(MAX_EVIDENCE_WINDOW_BYTES / 2)
                .min(bytes.len().saturating_sub(MAX_EVIDENCE_WINDOW_BYTES));
            &bytes[left..bytes.len().min(left + MAX_EVIDENCE_WINDOW_BYTES)]
        }
        ValidatedLocation::Line { line } => {
            let index = usize::try_from(line.saturating_sub(1)).ok()?;
            let line = bytes.split(|byte| *byte == b'\n').nth(index)?;
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            &line[..line.len().min(MAX_EVIDENCE_WINDOW_BYTES)]
        }
        ValidatedLocation::LineColumn { line, column } => {
            let index = usize::try_from(line.saturating_sub(1)).ok()?;
            let line = bytes.split(|byte| *byte == b'\n').nth(index)?;
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let text = std::str::from_utf8(line).ok()?;
            let character = usize::try_from(column.saturating_sub(1)).ok()?;
            let character_count = text.chars().count();
            if character > character_count {
                return None;
            }
            let center = if character == character_count {
                line.len()
            } else {
                text.char_indices().nth(character)?.0
            };
            let left = center
                .saturating_sub(MAX_EVIDENCE_WINDOW_BYTES / 2)
                .min(line.len().saturating_sub(MAX_EVIDENCE_WINDOW_BYTES));
            &line[left..line.len().min(left + MAX_EVIDENCE_WINDOW_BYTES)]
        }
    };
    if window.is_empty() {
        return None;
    }
    Some(window.to_vec())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MaterializationError {
    Unavailable,
    InvalidContent,
    BudgetExceeded,
    Cancelled,
    Workspace,
}

fn materialize(
    request: MaterializeRequest,
) -> Result<MaterializedScannerView, MaterializationError> {
    let directory = PrivateTemporaryDirectory::create(&request.root)?;
    let input = directory.path.join("input");
    let output = directory.path.join("output");
    DirBuilder::new()
        .mode(0o700)
        .create(&input)
        .map_err(|_| MaterializationError::Workspace)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&output)
        .map_err(|_| MaterializationError::Workspace)?;

    let view_paths = plan_view_paths(&request.assignments)?;
    let mut scanner_assignments = Vec::with_capacity(request.assignments.len());
    let mut content_digests = BTreeMap::new();
    for (assignment, view_path) in request.assignments.iter().zip(view_paths) {
        if request.cancellation.is_cancelled() {
            return Err(MaterializationError::Cancelled);
        }
        let destination = input.join(&view_path);
        if let Some(parent) = destination.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|_| MaterializationError::Workspace)?;
        }
        let disposition = copy_and_classify(
            request.reader.as_ref(),
            assignment,
            &destination,
            request.max_file_bytes,
            request
                .required_text
                .is_match_candidate(&Candidate::from_bytes(&logical_path_bytes(
                    &assignment.logical_path,
                ))),
            &request.cancellation,
        )?;
        scanner_assignments.push(ScannerAssignment {
            candidate_id: assignment.candidate_id.clone(),
            artifact_id: assignment.artifact_id.clone(),
            view_path: view_path.clone(),
            byte_len: assignment.byte_len,
            disposition,
            surface: match &assignment.surface {
                ProcessingArtifactSurface::WorkingTree => ScannerAssignmentSurface::WorkingTree,
                ProcessingArtifactSurface::GitHistory {
                    repository_identity,
                    history_scope,
                    provenance,
                } => ScannerAssignmentSurface::GitHistory {
                    repository_id: *repository_identity,
                    scope: *history_scope,
                    provenance: provenance.clone(),
                },
            },
        });
        if disposition == ScannerDisposition::Scan {
            content_digests.insert(view_path, assignment.content_digest);
        }
    }
    fs::set_permissions(&input, fs::Permissions::from_mode(0o500))
        .map_err(|_| MaterializationError::Workspace)?;
    Ok(MaterializedScannerView {
        _directory: directory,
        input,
        output,
        assignments: scanner_assignments,
        content_digests,
    })
}

const RESERVED_VIEW_SEGMENT_PREFIX: &str = ".__fg_";
const RESERVED_DERIVED_NAMESPACE: &str = ".file-guardian-derived";

fn plan_view_paths(
    assignments: &[ProcessingAssignment],
) -> Result<Vec<String>, MaterializationError> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut paths = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        let presented = assignment
            .logical_path
            .segments()
            .iter()
            .map(|segment| present_segment(segment.as_slice()))
            .collect::<Vec<_>>()
            .join("/");
        // One Git blob is cataloged once with complete provenance. Different
        // revisions commonly share the same logical path, so repository blobs
        // need a host-owned unique view name. Scanner output is mapped back by
        // the assignment and never treats this derived path as provenance.
        let path = match &assignment.surface {
            ProcessingArtifactSurface::WorkingTree => presented,
            ProcessingArtifactSurface::GitHistory { .. } => format!(
                "{RESERVED_DERIVED_NAMESPACE}/git/{}/{presented}",
                assignment.artifact_id.as_str()
            ),
        };
        let components = path.split('/').collect::<Vec<_>>();
        if directories.contains(&path) || !files.insert(path.clone()) {
            return Err(MaterializationError::InvalidContent);
        }
        for depth in 1..components.len() {
            let directory = components[..depth].join("/");
            if files.contains(&directory) {
                return Err(MaterializationError::InvalidContent);
            }
            directories.insert(directory);
        }
        paths.push(path);
    }
    Ok(paths)
}

fn present_segment(bytes: &[u8]) -> String {
    if let Ok(value) = std::str::from_utf8(bytes) {
        if bytes.len() <= 255
            && !value.starts_with(RESERVED_VIEW_SEGMENT_PREFIX)
            && value != RESERVED_DERIVED_NAMESPACE
            && !value.chars().any(char::is_control)
        {
            return value.to_owned();
        }
    }
    let digest = Sha256::digest(bytes);
    let mut value = String::from(RESERVED_VIEW_SEGMENT_PREFIX);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PrivateTemporaryDirectory {
    path: PathBuf,
}

impl PrivateTemporaryDirectory {
    fn create(root: &Path) -> Result<Self, MaterializationError> {
        for _ in 0..64 {
            let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("external-{}-{sequence}", std::process::id()));
            let result = DirBuilder::new().mode(0o700).create(&path);
            match result {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(MaterializationError::Workspace),
            }
        }
        Err(MaterializationError::Workspace)
    }
}

impl Drop for PrivateTemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_and_classify(
    reader: &dyn ProcessingArtifactReader,
    assignment: &ProcessingAssignment,
    destination: &Path,
    max_file_bytes: u64,
    required_text: bool,
    cancellation: &ScannerCancellation,
) -> Result<ScannerDisposition, MaterializationError> {
    let mut source = reader
        .open(&assignment.artifact_id)
        .map_err(|_| MaterializationError::Unavailable)?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|_| MaterializationError::Workspace)?;
    let mut hasher = Sha256::new();
    let mut validator = StreamingTextValidator::default();
    let mut length = 0_u64;
    let mut retained = true;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if cancellation.is_cancelled() {
            return Err(MaterializationError::Cancelled);
        }
        let read = source
            .read(&mut buffer)
            .map_err(|_| MaterializationError::Unavailable)?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        let read = u64::try_from(read).map_err(|_| MaterializationError::InvalidContent)?;
        length = length
            .checked_add(read)
            .ok_or(MaterializationError::InvalidContent)?;
        hasher.update(bytes);
        validator.feed(bytes);
        retained &= length <= max_file_bytes;
        if retained {
            destination_file
                .write_all(bytes)
                .map_err(|_| MaterializationError::Workspace)?;
        }
    }
    if length != assignment.byte_len
        || Digest::from_array(hasher.finalize().into()) != assignment.content_digest
    {
        return Err(MaterializationError::InvalidContent);
    }
    if !validator.is_text() {
        fs::remove_file(destination).map_err(|_| MaterializationError::Workspace)?;
        return if required_text {
            Err(MaterializationError::InvalidContent)
        } else {
            Ok(ScannerDisposition::NotApplicable)
        };
    }
    if !retained {
        fs::remove_file(destination).map_err(|_| MaterializationError::Workspace)?;
        return Err(MaterializationError::BudgetExceeded);
    }
    destination_file
        .sync_all()
        .map_err(|_| MaterializationError::Workspace)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o400))
        .map_err(|_| MaterializationError::Workspace)?;
    Ok(ScannerDisposition::Scan)
}

fn compile_required_text(patterns: &[String]) -> Result<GlobSet, globset::Error> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            GlobBuilder::new(pattern)
                .literal_separator(true)
                .backslash_escape(true)
                .build()?,
        );
    }
    builder.build()
}

fn logical_path_bytes(path: &crate::domain::LogicalPath) -> Vec<u8> {
    let mut result = Vec::new();
    for (index, segment) in path.segments().iter().enumerate() {
        if index != 0 {
            result.push(b'/');
        }
        result.extend_from_slice(segment.as_slice());
    }
    result
}

#[derive(Default)]
struct StreamingTextValidator {
    incomplete: Vec<u8>,
    invalid: bool,
    binary_control: bool,
}

impl StreamingTextValidator {
    fn feed(&mut self, bytes: &[u8]) {
        if self.invalid {
            return;
        }
        let mut candidate = std::mem::take(&mut self.incomplete);
        candidate.extend_from_slice(bytes);
        match std::str::from_utf8(&candidate) {
            Ok(text) => self.inspect(text),
            Err(error) if error.error_len().is_some() => self.invalid = true,
            Err(error) => {
                let valid = std::str::from_utf8(&candidate[..error.valid_up_to()])
                    .expect("UTF-8 reports a valid prefix");
                self.inspect(valid);
                self.incomplete
                    .extend_from_slice(&candidate[error.valid_up_to()..]);
            }
        }
    }

    fn inspect(&mut self, text: &str) {
        self.binary_control |= text.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\t' | '\n' | '\x0c' | '\r'))
        });
    }

    fn is_text(&self) -> bool {
        !self.invalid && self.incomplete.is_empty() && !self.binary_control
    }
}

fn map_materialization_error(error: MaterializationError) -> AnalyzerBackendError {
    match error {
        MaterializationError::Unavailable | MaterializationError::Workspace => {
            AnalyzerBackendError::Unavailable
        }
        MaterializationError::InvalidContent => AnalyzerBackendError::InvalidOutput,
        MaterializationError::BudgetExceeded => AnalyzerBackendError::BudgetExceeded,
        MaterializationError::Cancelled => AnalyzerBackendError::Cancelled,
    }
}

fn map_run_error(error: ScannerRunError) -> AnalyzerBackendError {
    match error {
        ScannerRunError::Cancelled => AnalyzerBackendError::Cancelled,
        ScannerRunError::Timeout | ScannerRunError::OutputLimit => {
            AnalyzerBackendError::BudgetExceeded
        }
        ScannerRunError::Adapter(_)
        | ScannerRunError::InvalidInvocation
        | ScannerRunError::ScannerVersion
        | ScannerRunError::PrivateOutput => AnalyzerBackendError::InvalidOutput,
        ScannerRunError::Sandbox(_)
        | ScannerRunError::Spawn
        | ScannerRunError::SandboxVersion
        | ScannerRunError::Supervision => AnalyzerBackendError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use crate::domain::{CandidateId, LogicalPath, PathSegment};
    use crate::processing::config::AnalyzerArtifactKind;
    use crate::processing::domain::{
        GitBlobMode, GitBlobOccurrence, GitHistoryScope, GitObjectId, GitProvenance,
    };

    struct MemoryReader(BTreeMap<ArtifactId, Vec<u8>>);

    impl ProcessingArtifactReader for MemoryReader {
        fn open(
            &self,
            artifact_id: &ArtifactId,
        ) -> Result<Box<dyn Read + Send>, ProcessingArtifactReadError> {
            self.0
                .get(artifact_id)
                .cloned()
                .map(|bytes| Box::new(std::io::Cursor::new(bytes)) as Box<dyn Read + Send>)
                .ok_or(ProcessingArtifactReadError::Unavailable)
        }
    }

    fn logical_path(value: &str) -> LogicalPath {
        LogicalPath::new(
            value
                .split('/')
                .map(|part| PathSegment::utf8(part).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn assignment(
        suffix: &str,
        path: &str,
        bytes: &[u8],
        surface: ProcessingArtifactSurface,
    ) -> ProcessingAssignment {
        ProcessingAssignment {
            candidate_id: CandidateId::from_suffix(suffix).unwrap(),
            artifact_id: ArtifactId::from_suffix(suffix).unwrap(),
            logical_path: logical_path(path),
            kind: match surface {
                ProcessingArtifactSurface::WorkingTree => AnalyzerArtifactKind::PhysicalFile,
                ProcessingArtifactSurface::GitHistory { .. } => {
                    AnalyzerArtifactKind::RepositoryBlob
                }
            },
            byte_len: bytes.len() as u64,
            content_digest: Digest::sha256(bytes),
            surface,
        }
    }

    #[test]
    fn materialization_preserves_exact_git_provenance_and_path_semantics() {
        let bytes = b"token = \"fixture\"\n";
        let blob_id = GitObjectId::from_str(&format!("sha1:{}", "1".repeat(40))).unwrap();
        let commit_id = GitObjectId::from_str(&format!("sha1:{}", "2".repeat(40))).unwrap();
        let provenance = GitProvenance::new(
            blob_id,
            GitBlobMode::Regular,
            vec![GitBlobOccurrence {
                commit_id,
                path: logical_path("src/history.rs"),
                refs: vec![logical_path("refs/heads/main")],
            }],
        )
        .unwrap();
        let source = ProcessingArtifactSurface::GitHistory {
            repository_identity: Digest::sha256(b"repository"),
            history_scope: GitHistoryScope::Reachable,
            provenance: provenance.clone(),
        };
        let assignment = assignment("git", "src/history.rs", bytes, source);
        let reader = Arc::new(MemoryReader(BTreeMap::from([(
            assignment.artifact_id.clone(),
            bytes.to_vec(),
        )])));
        let root = tempfile::tempdir().unwrap();
        let view = materialize(MaterializeRequest {
            root: root.path().to_owned(),
            reader,
            assignments: Arc::from([assignment]),
            required_text: compile_required_text(&[]).unwrap(),
            max_file_bytes: 1024,
            cancellation: ScannerCancellation::default(),
        })
        .unwrap();

        let view_path = ".file-guardian-derived/git/a_git/src/history.rs";
        assert_eq!(view.assignments()[0].view_path, view_path);
        assert_eq!(fs::read(view.input().join(view_path)).unwrap(), bytes);
        assert_eq!(
            view.assignments()[0].surface,
            ScannerAssignmentSurface::GitHistory {
                repository_id: Digest::sha256(b"repository"),
                scope: GitHistoryScope::Reachable,
                provenance,
            }
        );
        assert_eq!(
            view.evidence_window(
                &CandidateId::from_suffix("git").unwrap(),
                &ValidatedLocation::line(1).unwrap(),
            )
            .unwrap(),
            bytes.strip_suffix(b"\n").unwrap()
        );

        fs::set_permissions(
            view.input().join(view_path),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(view.input().join(view_path), b"tampered\n").unwrap();
        assert!(matches!(
            view.revalidate(),
            Err(MaterializationError::InvalidContent)
        ));
    }

    #[test]
    fn binary_is_not_applicable_unless_its_logical_path_requires_text() {
        let bytes = b"prefix\0binary";
        let assignment = assignment(
            "binary",
            "required/config.txt",
            bytes,
            ProcessingArtifactSurface::WorkingTree,
        );
        let reader = Arc::new(MemoryReader(BTreeMap::from([(
            assignment.artifact_id.clone(),
            bytes.to_vec(),
        )])));
        let root = tempfile::tempdir().unwrap();
        let view = materialize(MaterializeRequest {
            root: root.path().to_owned(),
            reader: Arc::clone(&reader) as Arc<dyn ProcessingArtifactReader>,
            assignments: Arc::from([assignment.clone()]),
            required_text: compile_required_text(&[]).unwrap(),
            max_file_bytes: 4,
            cancellation: ScannerCancellation::default(),
        })
        .unwrap();
        assert_eq!(
            view.assignments()[0].disposition,
            ScannerDisposition::NotApplicable
        );
        assert!(!view.input().join("required/config.txt").exists());

        let required = materialize(MaterializeRequest {
            root: root.path().to_owned(),
            reader,
            assignments: Arc::from([assignment]),
            required_text: compile_required_text(&["required/**".to_owned()]).unwrap(),
            max_file_bytes: 4,
            cancellation: ScannerCancellation::default(),
        });
        assert!(matches!(
            required,
            Err(MaterializationError::InvalidContent)
        ));
    }

    #[test]
    fn line_column_evidence_window_contains_a_match_late_in_a_long_line() {
        let mut bytes = vec![b'x'; 900];
        bytes[700..706].copy_from_slice(b"secret");

        let evidence =
            canonical_evidence_window(&bytes, &ValidatedLocation::line_column(1, 701).unwrap())
                .unwrap();

        assert_eq!(evidence.len(), MAX_EVIDENCE_WINDOW_BYTES);
        assert!(evidence.windows(6).any(|window| window == b"secret"));
    }
}
