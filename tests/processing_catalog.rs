use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use file_guardian::authorization::{CaptureLimits as SnapshotLimits, InvocationWorkspace};
use file_guardian::domain::{Digest, LogicalPath, PathSegment, RunId};
use file_guardian::processing::acquisition::git::{FrozenGitBlob, FrozenGitRepository};
use file_guardian::processing::acquisition::local::{
    acquire_local, capture_owned_stage, AcquisitionCancellation, LocalAcquisitionRequest,
    LocalAcquisitionResult,
};
use file_guardian::processing::catalog::{
    capture_processing_catalog, GitHistoryCatalogInput, ProcessingCatalogCaptureRequest,
    ProcessingCatalogError, WorkingTreeCatalogInput,
};
use file_guardian::processing::config::{AnalyzerArtifactKind, CaptureLimits, SymlinkPolicy};
use file_guardian::processing::external_backend::{
    ProcessingArtifactReadError, ProcessingArtifactReader,
};
use file_guardian::processing::{
    GitBlobMode, GitBlobOccurrence, GitHistoryScope, GitObjectId, GitProvenance,
};
use tempfile::TempDir;

fn path(value: &str) -> LogicalPath {
    LogicalPath::new(
        value
            .split('/')
            .map(|part| PathSegment::utf8(part).unwrap())
            .collect(),
    )
    .unwrap()
}

fn acquisition_limits() -> CaptureLimits {
    CaptureLimits {
        max_entries: 1_000,
        max_files: 1_000,
        max_file_bytes: 1_000_000,
        max_total_bytes: 10_000_000,
        max_depth: 32,
    }
}

fn snapshot_limits() -> SnapshotLimits {
    SnapshotLimits {
        max_entries: 1_000,
        max_files: 1_000,
        max_file_bytes: 1_000_000,
        max_total_bytes: 10_000_000,
        max_depth: 32,
    }
}

struct Fixture {
    root: TempDir,
    source: PathBuf,
    jobs: PathBuf,
    stage: PathBuf,
    workspace_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let source = root.path().join("source");
        let jobs = root.path().join("jobs");
        let stage = jobs.join("run_catalog/stage");
        let workspace_root = root.path().join("workspace");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&jobs).unwrap();
        fs::create_dir(jobs.join("run_catalog")).unwrap();
        fs::create_dir(&stage).unwrap();
        fs::create_dir(&workspace_root).unwrap();
        for directory in [
            source.as_path(),
            jobs.as_path(),
            jobs.join("run_catalog").as_path(),
            stage.as_path(),
            workspace_root.as_path(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            root,
            source,
            jobs,
            stage,
            workspace_root,
        }
    }

    fn acquire(&self, symlinks: SymlinkPolicy) -> LocalAcquisitionResult {
        acquire_local(LocalAcquisitionRequest {
            source: &self.source,
            stage: &self.stage,
            jobs_root: &self.jobs,
            limits: &acquisition_limits(),
            symlinks,
            cancellation: &AcquisitionCancellation::default(),
        })
        .unwrap()
    }

    fn workspace(&self, suffix: &str) -> Arc<InvocationWorkspace> {
        Arc::new(
            InvocationWorkspace::create(&self.workspace_root, &RunId::from_suffix(suffix).unwrap())
                .unwrap(),
        )
    }
}

fn capture_working(
    fixture: &Fixture,
    acquisition: &LocalAcquisitionResult,
    run_suffix: &str,
) -> file_guardian::processing::catalog::CapturedProcessingCatalog {
    capture_processing_catalog(
        fixture.workspace(run_suffix),
        ProcessingCatalogCaptureRequest {
            working_tree: Some(WorkingTreeCatalogInput {
                stage: &fixture.stage,
                jobs_root: &fixture.jobs,
                acquisition,
            }),
            git_history: None,
            capture_limits: snapshot_limits(),
        },
    )
    .unwrap()
}

#[test]
fn analyzers_read_immutable_objects_after_the_stage_changes() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.source.join("nested")).unwrap();
    fs::write(fixture.source.join("nested/secret.txt"), b"captured bytes").unwrap();
    let acquisition = fixture.acquire(SymlinkPolicy::Reject);
    let captured = capture_working(&fixture, &acquisition, "immutable");
    let artifact = captured
        .artifacts
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind == AnalyzerArtifactKind::PhysicalFile)
        .unwrap();

    fs::write(
        fixture.stage.join("nested/secret.txt"),
        b"mutated live stage",
    )
    .unwrap();
    let mut reader =
        ProcessingArtifactReader::open(captured.reader.as_ref(), &artifact.artifact_id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();

    assert_eq!(bytes, b"captured bytes");
    assert_eq!(artifact.content_digest, Digest::sha256(b"captured bytes"));
    assert_eq!(captured.builtin_manifest.artifacts().len(), 1);
    assert_eq!(captured.report_metadata.len(), 1);
    assert_eq!(captured.publication_entries, acquisition.entries);
}

#[test]
fn working_artifact_and_snapshot_identities_are_reproducible() {
    let first = Fixture::new();
    fs::write(first.source.join("same.txt"), b"same bytes").unwrap();
    let first_acquisition = first.acquire(SymlinkPolicy::Reject);
    let first_capture = capture_working(&first, &first_acquisition, "first");

    let second = Fixture::new();
    fs::write(second.source.join("same.txt"), b"same bytes").unwrap();
    let second_acquisition = second.acquire(SymlinkPolicy::Reject);
    let second_capture = capture_working(&second, &second_acquisition, "second");

    assert_eq!(first_capture.artifacts, second_capture.artifacts);
    assert_eq!(
        first_capture.snapshot_identity,
        second_capture.snapshot_identity
    );
    assert_eq!(
        first_capture.report_metadata,
        second_capture.report_metadata
    );
}

#[test]
fn symbolic_link_target_is_analyzer_data_and_publication_stays_separate() {
    let fixture = Fixture::new();
    symlink("target/inside.txt", fixture.source.join("link")).unwrap();
    let acquisition = fixture.acquire(SymlinkPolicy::Preserve);
    let captured = capture_working(&fixture, &acquisition, "symlink");
    let artifact = &captured.artifacts.artifacts()[0];
    assert_eq!(artifact.kind, AnalyzerArtifactKind::SymbolicLink);
    assert!(captured.builtin_manifest.artifacts().is_empty());

    let mut reader =
        ProcessingArtifactReader::open(captured.reader.as_ref(), &artifact.artifact_id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"target/inside.txt");
    assert_eq!(
        captured.report_metadata[0].publication.publication_type,
        file_guardian::processing::report::PublicationType::Symlink
    );
}

fn oid(fill: char) -> GitObjectId {
    format!("sha1:{}", fill.to_string().repeat(40))
        .parse()
        .unwrap()
}

fn git_blob(
    object: GitObjectId,
    commit: GitObjectId,
    logical_path: &str,
    bytes: &[u8],
    mode: GitBlobMode,
) -> FrozenGitBlob {
    FrozenGitBlob {
        object_id: object.clone(),
        object_store_identity: Digest::sha256(bytes),
        bytes: bytes.to_vec(),
        provenance: GitProvenance::new(
            object,
            mode,
            vec![GitBlobOccurrence {
                commit_id: commit,
                path: path(logical_path),
                refs: vec![path("refs/heads/main")],
            }],
        )
        .unwrap(),
        symbolic_link: mode == GitBlobMode::SymbolicLink,
    }
}

fn repository(blobs: Vec<FrozenGitBlob>) -> FrozenGitRepository {
    let mut commits = blobs
        .iter()
        .flat_map(|blob| {
            blob.provenance
                .occurrences
                .iter()
                .map(|occurrence| occurrence.commit_id.clone())
        })
        .collect::<Vec<_>>();
    commits.sort();
    commits.dedup();
    FrozenGitRepository {
        repository_identity: Digest::sha256(b"repository"),
        git_version: "git version 2.53.0".into(),
        object_format: "sha1".into(),
        bare: true,
        resolved_head: oid('a'),
        frozen_refs: Vec::new(),
        commits,
        head_tree: Vec::new(),
        blobs,
    }
}

fn capture_git(
    fixture: &Fixture,
    repository: &FrozenGitRepository,
    scope: GitHistoryScope,
) -> Result<file_guardian::processing::catalog::CapturedProcessingCatalog, ProcessingCatalogError> {
    capture_processing_catalog(
        fixture.workspace("git"),
        ProcessingCatalogCaptureRequest {
            working_tree: None,
            git_history: Some(GitHistoryCatalogInput { repository, scope }),
            capture_limits: snapshot_limits(),
        },
    )
}

#[test]
fn history_scope_and_complete_provenance_are_preserved() {
    let fixture = Fixture::new();
    let repository = repository(vec![git_blob(
        oid('b'),
        oid('a'),
        "config/old.env",
        b"historical secret",
        GitBlobMode::Regular,
    )]);
    let captured = capture_git(&fixture, &repository, GitHistoryScope::AllRefs).unwrap();
    let artifact = &captured.artifacts.artifacts()[0];
    let file_guardian::processing::executor::ProcessingArtifactSurface::GitHistory {
        repository_identity,
        history_scope,
        provenance,
    } = &artifact.surface
    else {
        panic!("expected Git history surface")
    };
    assert_eq!(*repository_identity, repository.repository_identity);
    assert_eq!(*history_scope, GitHistoryScope::AllRefs);
    assert_eq!(provenance, &repository.blobs[0].provenance);
    assert!(captured.publication_entries.is_empty());
    assert!(captured.builtin_manifest.artifacts().is_empty());
}

#[test]
fn git_symbolic_link_blob_is_read_as_data_without_materializing_a_link() {
    let fixture = Fixture::new();
    let repository = repository(vec![git_blob(
        oid('b'),
        oid('a'),
        "link",
        b"relative/target",
        GitBlobMode::SymbolicLink,
    )]);
    let captured = capture_git(&fixture, &repository, GitHistoryScope::Head).unwrap();
    let artifact = &captured.artifacts.artifacts()[0];
    let mut reader =
        ProcessingArtifactReader::open(captured.reader.as_ref(), &artifact.artifact_id).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"relative/target");
    assert!(!fixture.stage.join("link").exists());
}

#[test]
fn rejects_duplicate_blobs_duplicate_provenance_and_scope_disagreement() {
    let duplicate = git_blob(
        oid('b'),
        oid('a'),
        "same.env",
        b"first",
        GitBlobMode::Regular,
    );
    let duplicate_repository = repository(vec![duplicate.clone(), duplicate]);
    assert!(matches!(
        capture_git(
            &Fixture::new(),
            &duplicate_repository,
            GitHistoryScope::Reachable
        ),
        Err(ProcessingCatalogError::InvalidGit)
    ));

    let first = git_blob(
        oid('b'),
        oid('a'),
        "same.env",
        b"first",
        GitBlobMode::Regular,
    );
    let second = git_blob(
        oid('c'),
        oid('a'),
        "same.env",
        b"second",
        GitBlobMode::Regular,
    );
    let duplicate_provenance = repository(vec![first, second]);
    assert!(matches!(
        capture_git(
            &Fixture::new(),
            &duplicate_provenance,
            GitHistoryScope::Reachable
        ),
        Err(ProcessingCatalogError::InvalidGit)
    ));

    let scoped = repository(vec![git_blob(
        oid('b'),
        oid('a'),
        "history.env",
        b"bytes",
        GitBlobMode::Regular,
    )]);
    assert!(matches!(
        capture_git(&Fixture::new(), &scoped, GitHistoryScope::None),
        Err(ProcessingCatalogError::InvalidGit)
    ));
}

#[test]
fn distinct_revisions_of_one_path_are_retained_in_deterministic_order() {
    let first = git_blob(
        oid('b'),
        oid('a'),
        "same.env",
        b"first revision",
        GitBlobMode::Regular,
    );
    let second = git_blob(
        oid('c'),
        oid('d'),
        "same.env",
        b"second revision",
        GitBlobMode::Regular,
    );
    let forward_repository = repository(vec![first.clone(), second.clone()]);
    let reverse_repository = repository(vec![second, first]);
    let forward = capture_git(
        &Fixture::new(),
        &forward_repository,
        GitHistoryScope::Reachable,
    )
    .unwrap();
    let reverse = capture_git(
        &Fixture::new(),
        &reverse_repository,
        GitHistoryScope::Reachable,
    )
    .unwrap();

    assert_eq!(forward.artifacts, reverse.artifacts);
    assert_eq!(forward.snapshot_identity, reverse.snapshot_identity);
    assert_eq!(forward.artifacts.artifacts().len(), 2);
    assert!(forward
        .artifacts
        .artifacts()
        .iter()
        .all(|artifact| artifact.logical_path == path("same.env")));
}

#[test]
fn reader_and_failures_do_not_disclose_workspace_or_content() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("private.txt"), b"do-not-log-this").unwrap();
    let acquisition = fixture.acquire(SymlinkPolicy::Reject);
    let captured = capture_working(&fixture, &acquisition, "privacy");
    let debug = format!("{:?}", captured.reader);
    assert!(!debug.contains(fixture.root.path().to_str().unwrap()));
    assert!(!debug.contains("do-not-log-this"));
    assert!(debug.contains("<private>"));

    let unknown = file_guardian::domain::ArtifactId::from_suffix("unknown").unwrap();
    assert!(matches!(
        ProcessingArtifactReader::open(captured.reader.as_ref(), &unknown),
        Err(ProcessingArtifactReadError::Unavailable)
    ));
    assert_eq!(
        ProcessingCatalogError::WorkingTreeChanged.to_string(),
        "job-owned working tree changed before immutable capture completed"
    );
}

#[test]
fn rejects_stage_changes_before_capture_and_empty_surface_requests() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("file.txt"), b"before").unwrap();
    let acquisition = fixture.acquire(SymlinkPolicy::Reject);
    fs::write(fixture.stage.join("file.txt"), b"after").unwrap();
    assert!(matches!(
        capture_processing_catalog(
            fixture.workspace("changed"),
            ProcessingCatalogCaptureRequest {
                working_tree: Some(WorkingTreeCatalogInput {
                    stage: &fixture.stage,
                    jobs_root: &fixture.jobs,
                    acquisition: &acquisition,
                }),
                git_history: None,
                capture_limits: snapshot_limits(),
            }
        ),
        Err(ProcessingCatalogError::WorkingTreeChanged)
    ));
    assert!(matches!(
        capture_processing_catalog(
            fixture.workspace("empty"),
            ProcessingCatalogCaptureRequest {
                working_tree: None,
                git_history: None,
                capture_limits: snapshot_limits(),
            }
        ),
        Err(ProcessingCatalogError::Empty)
    ));
}

#[test]
fn descriptor_recapture_produces_a_fresh_post_action_publication() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("remove.txt"), b"remove").unwrap();
    fs::write(fixture.source.join("keep.txt"), b"keep").unwrap();
    let initial = fixture.acquire(SymlinkPolicy::Reject);
    fs::remove_file(fixture.stage.join("remove.txt")).unwrap();

    let recaptured = capture_owned_stage(
        &fixture.stage,
        &fixture.jobs,
        &acquisition_limits(),
        SymlinkPolicy::Reject,
        &AcquisitionCancellation::default(),
    )
    .unwrap();
    assert_ne!(recaptured.manifest_identity, initial.manifest_identity);
    assert_eq!(recaptured.entries.len(), 1);
    assert_eq!(recaptured.entries[0].logical_path, path("keep.txt"));

    let verified = capture_working(&fixture, &recaptured, "recaptured");
    assert_eq!(verified.artifacts.artifacts().len(), 1);
}
