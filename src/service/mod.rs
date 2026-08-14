//! Evaluate-only one-shot authorization orchestration.
//!
//! This layer owns the lifecycle of a single invocation workspace. Analyzer
//! implementations receive only the captured manifest and immutable object
//! store; the live input path is retained here solely for capture and final
//! revalidation.

use crate::authorization::{
    CaptureError, CaptureLimits, InvocationWorkspace, Snapshot, SnapshotInputKind, Snapshotter,
};
use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactManifest, InspectionIssue, InspectionPhase, IssueCode,
    NormalizedObservation, PhaseCoverage, PhaseCoverageStatus, RunCoverage, RunId,
    SanitizedMessage,
};
use crate::pipeline::{CompiledPipeline, PipelineExecution, PipelineExecutor};
use crate::policy::{self, EvaluationDecision, PolicyBinding, PolicyResolution};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type CaptureOperation = dyn Fn(&InvocationWorkspace, CaptureLimits, &Path) -> Result<Snapshot, CaptureError>
    + Send
    + Sync
    + 'static;

/// Fully compiled inputs for one authorization invocation.
///
/// Configuration parsing, profile selection, and analyzer construction happen
/// before this boundary. The service never consults environment variables or
/// legacy scanner configuration.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub run_id: RunId,
    pub workspace_root: PathBuf,
    pub input: PathBuf,
    pub capture_limits: CaptureLimits,
    pub pipeline: CompiledPipeline,
    pub policy_bindings: Vec<PolicyBinding>,
}

impl AuthorizationRequest {
    pub fn validate(&self) -> Result<(), RequestError> {
        if !self.workspace_root.is_absolute() {
            return Err(RequestError::RelativeWorkspaceRoot);
        }
        self.pipeline
            .validate()
            .map_err(|_| RequestError::InvalidPipeline)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RequestError {
    #[error("workspace root must be absolute")]
    RelativeWorkspaceRoot,
    #[error("compiled authorization pipeline is invalid")]
    InvalidPipeline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceOutcome {
    Allow,
    Deny,
    Error,
}

impl ServiceOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Allow => 0,
            Self::Deny => 20,
            Self::Error => 30,
        }
    }
}

/// Safe, report-construction data returned after the private workspace has
/// been removed. It contains manifests, but never object bytes or live paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationResult {
    pub outcome: ServiceOutcome,
    pub input_kind: Option<SnapshotInputKind>,
    pub initial_manifest: Option<ArtifactManifest>,
    pub final_manifest: Option<ArtifactManifest>,
    pub coverage: RunCoverage,
    pub pipeline: PipelineExecution,
    pub observations: Vec<NormalizedObservation>,
    pub resolutions: Vec<PolicyResolution>,
    pub issues: Vec<InspectionIssue>,
}

pub struct AuthorizationService;

impl AuthorizationService {
    pub async fn authorize(request: AuthorizationRequest) -> AuthorizationResult {
        authorize_with_revalidation_hook(request, || {}).await
    }
}

async fn authorize_with_revalidation_hook<F>(
    request: AuthorizationRequest,
    before_revalidation: F,
) -> AuthorizationResult
where
    F: FnOnce(),
{
    authorize_with_capture_operation(
        request,
        before_revalidation,
        Arc::new(|workspace, limits, input| Snapshotter::new(workspace, limits).capture(input)),
    )
    .await
}

async fn authorize_with_capture_operation<F>(
    request: AuthorizationRequest,
    before_revalidation: F,
    capture: Arc<CaptureOperation>,
) -> AuthorizationResult
where
    F: FnOnce(),
{
    if request.validate().is_err() {
        return error_without_workspace(issue(
            IssueCode::ConfigurationFailure,
            None,
            "authorization request is invalid",
        ));
    }

    let workspace = match InvocationWorkspace::create(&request.workspace_root, &request.run_id) {
        Ok(workspace) => workspace,
        Err(_) => {
            return error_without_workspace(issue(
                IssueCode::WorkspaceFailure,
                None,
                "invocation workspace could not be created",
            ));
        }
    };

    let workspace = Arc::new(workspace);
    let mut result = execute_in_workspace(
        &request,
        Arc::clone(&workspace),
        before_revalidation,
        capture,
    )
    .await;
    match Arc::try_unwrap(workspace) {
        Ok(workspace) => match tokio::task::spawn_blocking(move || workspace.remove()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                result.outcome = ServiceOutcome::Error;
                result.issues.push(issue(
                    IssueCode::WorkspaceFailure,
                    None,
                    "invocation workspace could not be removed",
                ));
            }
            Err(_) => {
                result.outcome = ServiceOutcome::Error;
                result.issues.push(issue(
                    IssueCode::InternalFailure,
                    None,
                    "workspace cleanup task did not complete",
                ));
            }
        },
        Err(_) => {
            result.outcome = ServiceOutcome::Error;
            result.issues.push(issue(
                IssueCode::InternalFailure,
                None,
                "analyzer retained the invocation workspace after completion",
            ));
        }
    }
    result
}

async fn execute_in_workspace<F>(
    request: &AuthorizationRequest,
    workspace: Arc<InvocationWorkspace>,
    before_revalidation: F,
    capture: Arc<CaptureOperation>,
) -> AuthorizationResult
where
    F: FnOnce(),
{
    let initial = match capture_snapshot(
        Arc::clone(&workspace),
        request.capture_limits,
        request.input.clone(),
        Arc::clone(&capture),
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(CaptureTaskError::Capture(error)) => {
            return error_result(ErrorParts {
                input_kind: None,
                initial_manifest: None,
                final_manifest: None,
                observations: Vec::new(),
                resolutions: Vec::new(),
                issues: vec![capture_issue(&error, InspectionPhase::Initial)],
                coverage_rows: Vec::new(),
                initial_status: PhaseCoverageStatus::Incomplete,
                pipeline: PipelineExecution {
                    stages_completed: 0,
                    analyzers_completed: 0,
                },
            });
        }
        Err(CaptureTaskError::Join) => {
            return error_result(ErrorParts {
                input_kind: None,
                initial_manifest: None,
                final_manifest: None,
                observations: Vec::new(),
                resolutions: Vec::new(),
                issues: vec![issue(
                    IssueCode::InternalFailure,
                    None,
                    "initial capture task did not complete",
                )],
                coverage_rows: Vec::new(),
                initial_status: PhaseCoverageStatus::Incomplete,
                pipeline: PipelineExecution {
                    stages_completed: 0,
                    analyzers_completed: 0,
                },
            });
        }
    };

    let pipeline_result = PipelineExecutor::execute(
        &request.pipeline,
        Arc::new(initial.manifest.clone()),
        Arc::clone(&workspace),
    )
    .await;
    let observations = pipeline_result.observations;
    let mut issues = pipeline_result.issues;
    let coverage_rows = pipeline_result.coverage;
    let pipeline = pipeline_result.execution;
    if !pipeline_result.complete || !issues.is_empty() {
        return error_result(ErrorParts {
            input_kind: Some(initial.input_kind),
            initial_manifest: Some(initial.manifest),
            final_manifest: None,
            observations,
            resolutions: Vec::new(),
            issues,
            coverage_rows,
            initial_status: PhaseCoverageStatus::Incomplete,
            pipeline,
        });
    }

    let evaluation = match policy::evaluate(&observations, &request.policy_bindings) {
        Ok(evaluation) => evaluation,
        Err(_) => {
            issues.push(issue(
                IssueCode::PolicyResolutionFailure,
                None,
                "policy could not resolve every observation exactly once",
            ));
            return error_result(ErrorParts {
                input_kind: Some(initial.input_kind),
                initial_manifest: Some(initial.manifest),
                final_manifest: None,
                observations,
                resolutions: Vec::new(),
                issues,
                coverage_rows,
                initial_status: PhaseCoverageStatus::Complete,
                pipeline,
            });
        }
    };

    before_revalidation();
    let final_snapshot = match capture_snapshot(
        Arc::clone(&workspace),
        request.capture_limits,
        request.input.clone(),
        capture,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(CaptureTaskError::Capture(error)) => {
            issues.push(capture_issue(&error, InspectionPhase::Initial));
            return error_result(ErrorParts {
                input_kind: Some(initial.input_kind),
                initial_manifest: Some(initial.manifest),
                final_manifest: None,
                observations,
                resolutions: evaluation.resolutions,
                issues,
                coverage_rows,
                initial_status: PhaseCoverageStatus::Complete,
                pipeline,
            });
        }
        Err(CaptureTaskError::Join) => {
            issues.push(issue(
                IssueCode::InternalFailure,
                None,
                "final capture task did not complete",
            ));
            return error_result(ErrorParts {
                input_kind: Some(initial.input_kind),
                initial_manifest: Some(initial.manifest),
                final_manifest: None,
                observations,
                resolutions: evaluation.resolutions,
                issues,
                coverage_rows,
                initial_status: PhaseCoverageStatus::Complete,
                pipeline,
            });
        }
    };

    if final_snapshot.input_kind != initial.input_kind
        || final_snapshot.manifest != initial.manifest
    {
        issues.push(issue_for_phase(
            InspectionPhase::Initial,
            IssueCode::FileUnstable,
            None,
            "live input changed after immutable capture",
        ));
        return error_result(ErrorParts {
            input_kind: Some(initial.input_kind),
            initial_manifest: Some(initial.manifest),
            final_manifest: Some(final_snapshot.manifest),
            observations,
            resolutions: evaluation.resolutions,
            issues,
            coverage_rows,
            initial_status: PhaseCoverageStatus::Complete,
            pipeline,
        });
    }

    successful_result(
        initial,
        final_snapshot,
        observations,
        evaluation.resolutions,
        coverage_rows,
        pipeline,
        match evaluation.decision {
            EvaluationDecision::Allow => ServiceOutcome::Allow,
            EvaluationDecision::Deny => ServiceOutcome::Deny,
        },
    )
}

enum CaptureTaskError {
    Capture(CaptureError),
    Join,
}

async fn capture_snapshot(
    workspace: Arc<InvocationWorkspace>,
    limits: CaptureLimits,
    input: PathBuf,
    capture: Arc<CaptureOperation>,
) -> Result<Snapshot, CaptureTaskError> {
    tokio::task::spawn_blocking(move || capture(workspace.as_ref(), limits, &input))
        .await
        .map_err(|_| CaptureTaskError::Join)?
        .map_err(CaptureTaskError::Capture)
}

fn successful_result(
    initial: Snapshot,
    final_snapshot: Snapshot,
    observations: Vec<NormalizedObservation>,
    resolutions: Vec<PolicyResolution>,
    coverage_rows: Vec<AnalyzerCoverage>,
    pipeline: PipelineExecution,
    outcome: ServiceOutcome,
) -> AuthorizationResult {
    AuthorizationResult {
        outcome,
        input_kind: Some(initial.input_kind),
        initial_manifest: Some(initial.manifest),
        final_manifest: Some(final_snapshot.manifest),
        coverage: run_coverage(PhaseCoverageStatus::Complete, coverage_rows),
        pipeline,
        observations,
        resolutions,
        issues: Vec::new(),
    }
}

struct ErrorParts {
    input_kind: Option<SnapshotInputKind>,
    initial_manifest: Option<ArtifactManifest>,
    final_manifest: Option<ArtifactManifest>,
    observations: Vec<NormalizedObservation>,
    resolutions: Vec<PolicyResolution>,
    issues: Vec<InspectionIssue>,
    coverage_rows: Vec<AnalyzerCoverage>,
    initial_status: PhaseCoverageStatus,
    pipeline: PipelineExecution,
}

fn error_result(parts: ErrorParts) -> AuthorizationResult {
    AuthorizationResult {
        outcome: ServiceOutcome::Error,
        input_kind: parts.input_kind,
        initial_manifest: parts.initial_manifest,
        final_manifest: parts.final_manifest,
        coverage: run_coverage(parts.initial_status, parts.coverage_rows),
        pipeline: parts.pipeline,
        observations: parts.observations,
        resolutions: parts.resolutions,
        issues: parts.issues,
    }
}

fn error_without_workspace(issue: InspectionIssue) -> AuthorizationResult {
    error_result(ErrorParts {
        input_kind: None,
        initial_manifest: None,
        final_manifest: None,
        observations: Vec::new(),
        resolutions: Vec::new(),
        issues: vec![issue],
        coverage_rows: Vec::new(),
        initial_status: PhaseCoverageStatus::Incomplete,
        pipeline: PipelineExecution {
            stages_completed: 0,
            analyzers_completed: 0,
        },
    })
}

fn run_coverage(status: PhaseCoverageStatus, rows: Vec<AnalyzerCoverage>) -> RunCoverage {
    RunCoverage::new(
        PhaseCoverage::new(status, rows).expect("service coverage is internally consistent"),
        PhaseCoverage::new(PhaseCoverageStatus::NotRun, Vec::new())
            .expect("not-run verification coverage is valid"),
    )
    .expect("service coverage rows use their declared phase")
}

fn capture_issue(error: &CaptureError, phase: InspectionPhase) -> InspectionIssue {
    let (code, message) = match error {
        CaptureError::InputUnavailable(_) => (IssueCode::InputUnavailable, "input is unavailable"),
        CaptureError::InvalidInputName | CaptureError::InvalidFileMetadata => {
            (IssueCode::UnsupportedFileType, "input metadata is invalid")
        }
        CaptureError::InputUnstable
        | CaptureError::EntryUnstable
        | CaptureError::DirectoryUnstable
        | CaptureError::FileUnstable => (IssueCode::FileUnstable, "input changed during capture"),
        CaptureError::WorkspaceTraversalRejected
        | CaptureError::WorkspaceAncestryUnavailable
        | CaptureError::WorkspaceAncestryLimitExceeded { .. }
        | CaptureError::Workspace(_) => (IssueCode::WorkspaceFailure, "workspace isolation failed"),
        CaptureError::EnumerationFailure => {
            (IssueCode::EnumerationFailure, "input enumeration failed")
        }
        CaptureError::FileUnreadable => (IssueCode::FileUnreadable, "input file is unreadable"),
        CaptureError::SymlinkRejected => (IssueCode::SymlinkRejected, "symbolic link rejected"),
        CaptureError::HardlinkRejected => (IssueCode::HardlinkRejected, "hard link rejected"),
        CaptureError::UnsupportedFileType => (
            IssueCode::UnsupportedFileType,
            "unsupported file type rejected",
        ),
        CaptureError::FilesystemCrossingRejected => (
            IssueCode::FilesystemCrossingRejected,
            "filesystem crossing rejected",
        ),
        CaptureError::FileCountLimitExceeded { .. }
        | CaptureError::TraversalEntryLimitExceeded { .. }
        | CaptureError::FileSizeLimitExceeded { .. }
        | CaptureError::TotalSizeLimitExceeded { .. }
        | CaptureError::DepthLimitExceeded { .. } => {
            (IssueCode::SizeLimitExceeded, "capture limit exceeded")
        }
        CaptureError::Manifest(_) => (IssueCode::InternalFailure, "captured manifest is invalid"),
    };
    issue_for_phase(phase, code, None, message)
}

fn issue(
    code: IssueCode,
    analyzer_id: Option<AnalyzerId>,
    message: &'static str,
) -> InspectionIssue {
    issue_for_phase(InspectionPhase::Initial, code, analyzer_id, message)
}

fn issue_for_phase(
    phase: InspectionPhase,
    code: IssueCode,
    analyzer_id: Option<AnalyzerId>,
    message: &'static str,
) -> InspectionIssue {
    InspectionIssue {
        phase,
        code,
        analyzer_id,
        subject_id: None,
        artifact_id: None,
        message: SanitizedMessage::new(message).expect("static service diagnostic is safe"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::{
        BuiltinAnalyzerLimits, BuiltinContentApplicability, BuiltinRulesAnalyzer,
    };
    use crate::domain::{ArtifactKind, FindingCategory, RuleId};
    use crate::pipeline::{
        AnalyzerImplementation, CompiledAnalyzer, CompiledStage, EligibilitySelector,
        PriorObservationMode, ProjectionLimits, StageExecution, StageId, UnsupportedAnalyzerKind,
    };
    use crate::policy::{BindingId, ObservationSelector, PolicyDirective};
    use crate::rules::load_rule_file;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    use tempfile::TempDir;

    struct Fixture {
        root: TempDir,
        workspace_root: PathBuf,
        input: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new().unwrap();
            let workspace_root = root.path().join("workspaces");
            fs::create_dir(&workspace_root).unwrap();
            fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700)).unwrap();
            let input = root.path().join("input");
            fs::create_dir(&input).unwrap();
            Self {
                root,
                workspace_root,
                input,
            }
        }

        fn request(
            &self,
            suffix: &str,
            analyzer_id: &str,
            implementation: AnalyzerImplementation,
        ) -> AuthorizationRequest {
            let analyzer_id = AnalyzerId::new(analyzer_id).unwrap();
            let analyzer = CompiledAnalyzer::new(
                analyzer_id,
                true,
                EligibilitySelector::compile(
                    &["**".to_string()],
                    &[],
                    [ArtifactKind::PhysicalFile],
                )
                .unwrap(),
                implementation,
            );
            AuthorizationRequest {
                run_id: RunId::from_suffix(suffix).unwrap(),
                workspace_root: self.workspace_root.clone(),
                input: self.input.clone(),
                capture_limits: CaptureLimits::default(),
                pipeline: CompiledPipeline::new(vec![CompiledStage::new(
                    StageId::new("scan").unwrap(),
                    StageExecution::Serial,
                    vec![analyzer],
                    PriorObservationMode::None,
                    ProjectionLimits::new(100, 16_384).unwrap(),
                )
                .unwrap()])
                .unwrap(),
                policy_bindings: vec![PolicyBinding {
                    id: BindingId::new("deny-secret").unwrap(),
                    selector: ObservationSelector::Finding {
                        analyzer_id: Some(AnalyzerId::new("builtin").unwrap()),
                        rule_id: Some(RuleId::new("secret").unwrap()),
                        category: Some(FindingCategory::ContentPattern),
                        minimum_severity: None,
                    },
                    directive: PolicyDirective::Deny,
                }],
            }
        }
    }

    fn builtin() -> AnalyzerImplementation {
        let mut rules = tempfile::NamedTempFile::new().unwrap();
        rules
            .write_all(
                br#"schema_version = "file-guardian-rules/1"
[[rules]]
id = "secret"
content_regex = "SECRET"
"#,
            )
            .unwrap();
        AnalyzerImplementation::Builtin(
            BuiltinRulesAnalyzer::new(
                "builtin",
                load_rule_file(rules.path()).unwrap(),
                BuiltinAnalyzerLimits {
                    max_content_bytes: 1024,
                    max_findings: 100,
                    content_applicability: BuiltinContentApplicability::default(),
                },
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn complete_clean_scan_allows_and_removes_workspace() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let result =
            AuthorizationService::authorize(fixture.request("allow", "builtin", builtin())).await;
        assert_eq!(result.outcome, ServiceOutcome::Allow);
        assert_eq!(result.outcome.exit_code(), 0);
        assert_eq!(
            result.coverage.initial.status,
            PhaseCoverageStatus::Complete
        );
        assert_eq!(result.initial_manifest, result.final_manifest);
        assert!(!fixture.workspace_root.join("run_allow").exists());
        assert!(fixture.root.path().exists());
    }

    #[tokio::test]
    async fn ordinary_binary_is_complete_not_applicable_and_allows() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("upload.bin"), [0xff, 0x00, 0xfe]).unwrap();

        let result =
            AuthorizationService::authorize(fixture.request("allow-binary", "builtin", builtin()))
                .await;

        assert_eq!(result.outcome, ServiceOutcome::Allow);
        assert!(result.issues.is_empty());
        assert!(result.observations.is_empty());
        let coverage = &result.coverage.initial.analyzers[0];
        assert!(coverage.is_complete());
        assert_eq!(coverage.assigned, 1);
        assert_eq!(coverage.completed, 0);
        assert_eq!(coverage.not_applicable, 1);
        assert!(!fixture.workspace_root.join("run_allow-binary").exists());
    }

    #[tokio::test]
    async fn empty_input_with_zero_assignments_remains_valid() {
        let fixture = Fixture::new();
        let result =
            AuthorizationService::authorize(fixture.request("empty-input", "builtin", builtin()))
                .await;

        assert_eq!(result.outcome, ServiceOutcome::Allow);
        assert!(result.issues.is_empty());
        assert!(result
            .initial_manifest
            .as_ref()
            .unwrap()
            .artifacts()
            .is_empty());
        assert_eq!(result.coverage.initial.analyzers[0].assigned, 0);
        assert_eq!(result.coverage.initial.analyzers[0].completed, 0);
    }

    #[tokio::test]
    async fn nonempty_input_with_no_required_assignment_fails_closed() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("captured.txt"), "safe").unwrap();
        let mut request = fixture.request("unassigned-input", "builtin", builtin());
        request.pipeline.stages[0].analyzers[0].eligibility =
            EligibilitySelector::compile(&["*.rs".to_string()], &[], [ArtifactKind::PhysicalFile])
                .unwrap();

        let result = AuthorizationService::authorize(request).await;

        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert_eq!(result.issues[0].code, IssueCode::IncompleteCoverage);
        assert!(result.final_manifest.is_none());
        assert_eq!(result.coverage.initial.analyzers[0].assigned, 0);
        assert_eq!(result.coverage.initial.analyzers[0].completed, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_captures_do_not_stall_the_async_runtime() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let request = fixture.request("nonblocking-captures", "builtin", builtin());
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(0_usize), Condvar::new()));
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel(2);

        let watchdog_gate = Arc::clone(&gate);
        let watchdog = std::thread::spawn(move || {
            let mut runtime_progressed = true;
            for capture_index in 0..2 {
                if progress_rx.recv_timeout(Duration::from_secs(2)) != Ok(capture_index) {
                    runtime_progressed = false;
                }
                let (released, condition) = watchdog_gate.as_ref();
                *released.lock().unwrap() = capture_index + 1;
                condition.notify_all();
            }
            runtime_progressed
        });

        let capture_calls = Arc::clone(&calls);
        let capture_gate = Arc::clone(&gate);
        let capture: Arc<CaptureOperation> = Arc::new(move |workspace, limits, input| {
            let capture_index = capture_calls.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(capture_index).unwrap();
            let (released, condition) = capture_gate.as_ref();
            let released = released.lock().unwrap();
            drop(
                condition
                    .wait_while(released, |released| *released <= capture_index)
                    .unwrap(),
            );
            Snapshotter::new(workspace, limits).capture(input)
        });

        let authorization = tokio::spawn(authorize_with_capture_operation(request, || {}, capture));
        for capture_index in 0..2 {
            assert_eq!(entered_rx.recv().await, Some(capture_index));
            tokio::task::yield_now().await;
            progress_tx.send(capture_index).unwrap();
        }

        let result = authorization.await.unwrap();
        assert!(watchdog.join().unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(result.outcome, ServiceOutcome::Allow);
    }

    #[tokio::test]
    async fn cancelling_authorization_removes_workspace_after_analyzer_releases() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let started = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let request = fixture.request(
            "cancel-cleanup",
            "blocking",
            AnalyzerImplementation::blocking_test(Arc::clone(&started), Arc::clone(&release)),
        );
        let run_path = fixture.workspace_root.join("run_cancel-cleanup");
        let authorization = tokio::spawn(AuthorizationService::authorize(request));
        let started_wait = Arc::clone(&started);
        tokio::task::spawn_blocking(move || started_wait.wait())
            .await
            .unwrap();
        assert!(run_path.exists());

        authorization.abort();
        let release_wait = Arc::clone(&release);
        tokio::task::spawn_blocking(move || release_wait.wait())
            .await
            .unwrap();
        let _ = authorization.await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while run_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled authorization workspace must be removed");
    }

    #[tokio::test]
    async fn matching_observation_is_denied_without_modifying_input() {
        let fixture = Fixture::new();
        let target = fixture.input.join("secret.txt");
        fs::write(&target, "SECRET=value").unwrap();
        let before = fs::read(&target).unwrap();
        let result =
            AuthorizationService::authorize(fixture.request("deny", "builtin", builtin())).await;
        assert_eq!(result.outcome, ServiceOutcome::Deny);
        assert_eq!(result.outcome.exit_code(), 20);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(fs::read(target).unwrap(), before);
    }

    #[tokio::test]
    async fn unsupported_required_analyzer_fails_closed_with_incomplete_coverage() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let request = fixture.request(
            "unsupported",
            "pi",
            AnalyzerImplementation::Unsupported {
                kind: UnsupportedAnalyzerKind::Pi,
            },
        );
        let result = AuthorizationService::authorize(request).await;
        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert_eq!(result.outcome.exit_code(), 30);
        assert_eq!(
            result.coverage.initial.status,
            PhaseCoverageStatus::Incomplete
        );
        assert_eq!(result.coverage.initial.analyzers[0].assigned, 1);
        assert_eq!(result.coverage.initial.analyzers[0].completed, 0);
        assert_eq!(
            result.issues[0].code,
            IssueCode::RequiredAnalyzerProcessFailure
        );
    }

    #[tokio::test]
    async fn required_failure_records_every_unrun_analyzer_across_later_stages() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let mut request = fixture.request("later-unrun", "builtin", builtin());
        let first_stage = request.pipeline.stages[0].clone();
        let unsupported = |id: &str| {
            CompiledAnalyzer::new(
                AnalyzerId::new(id).unwrap(),
                true,
                EligibilitySelector::compile(
                    &["**".to_string()],
                    &[],
                    [ArtifactKind::PhysicalFile],
                )
                .unwrap(),
                AnalyzerImplementation::Unsupported {
                    kind: UnsupportedAnalyzerKind::External,
                },
            )
        };
        request.pipeline = CompiledPipeline::new(vec![
            first_stage,
            CompiledStage::new(
                StageId::new("failing").unwrap(),
                StageExecution::Serial,
                vec![unsupported("failed"), unsupported("same-stage-unrun")],
                PriorObservationMode::None,
                ProjectionLimits::new(100, 16_384).unwrap(),
            )
            .unwrap(),
            CompiledStage::new(
                StageId::new("later").unwrap(),
                StageExecution::Serial,
                vec![unsupported("later-unrun")],
                PriorObservationMode::None,
                ProjectionLimits::new(100, 16_384).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();

        let result = AuthorizationService::authorize(request).await;

        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert_eq!(result.pipeline.stages_completed, 1);
        assert_eq!(result.pipeline.analyzers_completed, 1);
        assert_eq!(result.coverage.initial.analyzers.len(), 4);
        assert!(result
            .coverage
            .initial
            .analyzers
            .iter()
            .filter(|row| row.analyzer_id.as_str() != "builtin")
            .all(|row| row.assigned == 1 && row.completed == 0));
    }

    #[tokio::test]
    async fn unbound_observation_is_an_error_not_a_deny() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("secret.txt"), "SECRET").unwrap();
        let mut request = fixture.request("unbound", "builtin", builtin());
        request.policy_bindings.clear();
        let result = AuthorizationService::authorize(request).await;
        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert!(result.resolutions.is_empty());
        assert_eq!(result.issues[0].code, IssueCode::PolicyResolutionFailure);
    }

    #[tokio::test]
    async fn invalid_pipeline_is_rejected_before_workspace_creation() {
        let fixture = Fixture::new();
        let request = AuthorizationRequest {
            run_id: RunId::from_suffix("empty").unwrap(),
            workspace_root: fixture.workspace_root.clone(),
            input: fixture.input.clone(),
            capture_limits: CaptureLimits::default(),
            pipeline: CompiledPipeline { stages: Vec::new() },
            policy_bindings: Vec::new(),
        };
        let result = AuthorizationService::authorize(request).await;
        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert_eq!(result.issues[0].code, IssueCode::ConfigurationFailure);
        assert!(fs::read_dir(&fixture.workspace_root)
            .unwrap()
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn evaluate_revalidation_failure_remains_in_initial_lifecycle_phase() {
        let fixture = Fixture::new();
        let target = fixture.input.join("changing.txt");
        fs::write(&target, "before").unwrap();
        let request = fixture.request("revalidation-change", "builtin", builtin());

        let result = authorize_with_revalidation_hook(request, || {
            fs::write(&target, "after").unwrap();
        })
        .await;

        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert_eq!(
            result.coverage.initial.status,
            PhaseCoverageStatus::Complete
        );
        assert_eq!(
            result.coverage.verification.status,
            PhaseCoverageStatus::NotRun
        );
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].phase, InspectionPhase::Initial);
        assert_eq!(result.issues[0].code, IssueCode::FileUnstable);
    }
}
