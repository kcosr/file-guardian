//! Evaluate-only one-shot authorization orchestration.
//!
//! This layer owns the lifecycle of a single invocation workspace. Analyzer
//! implementations receive only the captured manifest and immutable object
//! store; the live input path is retained here solely for capture and final
//! revalidation.

use crate::analyzers::BuiltinRulesAnalyzer;
use crate::authorization::{
    CaptureError, CaptureLimits, InvocationWorkspace, Snapshot, SnapshotInputKind, Snapshotter,
};
use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactManifest, CoverageStatus, InspectionIssue,
    InspectionPhase, IssueCode, NormalizedObservation, PhaseCoverage, PhaseCoverageStatus,
    RunCoverage, RunId, SanitizedMessage,
};
use crate::policy::{self, EvaluationDecision, PolicyBinding, PolicyResolution};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedAnalyzerKind {
    External,
    Pi,
}

#[derive(Clone, Debug)]
pub enum AuthorizationAnalyzer {
    Builtin(BuiltinRulesAnalyzer),
    /// Parse-ready analyzer configuration which this milestone deliberately
    /// refuses to execute. There is no permissive or unsandboxed fallback.
    Unsupported {
        id: AnalyzerId,
        kind: UnsupportedAnalyzerKind,
    },
}

impl AuthorizationAnalyzer {
    fn id(&self) -> &AnalyzerId {
        match self {
            Self::Builtin(analyzer) => analyzer.id(),
            Self::Unsupported { id, .. } => id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizationStage {
    pub analyzers: Vec<AuthorizationAnalyzer>,
}

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
    pub stages: Vec<AuthorizationStage>,
    pub policy_bindings: Vec<PolicyBinding>,
}

impl AuthorizationRequest {
    pub fn validate(&self) -> Result<(), RequestError> {
        if !self.workspace_root.is_absolute() {
            return Err(RequestError::RelativeWorkspaceRoot);
        }
        if self.stages.is_empty() || self.stages.iter().any(|stage| stage.analyzers.is_empty()) {
            return Err(RequestError::EmptyPipeline);
        }
        if let Some(analyzer_id) = duplicate_analyzer(&self.stages) {
            return Err(RequestError::DuplicateAnalyzer(analyzer_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RequestError {
    #[error("workspace root must be absolute")]
    RelativeWorkspaceRoot,
    #[error("authorization pipeline and each stage must contain at least one analyzer")]
    EmptyPipeline,
    #[error("authorization pipeline contains duplicate analyzer {0}")]
    DuplicateAnalyzer(AnalyzerId),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineExecution {
    pub stages_completed: u64,
    pub analyzers_completed: u64,
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
    pub fn authorize(request: AuthorizationRequest) -> AuthorizationResult {
        authorize_with_revalidation_hook(request, || {})
    }
}

fn authorize_with_revalidation_hook<F>(
    request: AuthorizationRequest,
    before_revalidation: F,
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

    let mut result = execute_in_workspace(&request, &workspace, before_revalidation);
    if workspace.remove().is_err() {
        result.outcome = ServiceOutcome::Error;
        result.issues.push(issue(
            IssueCode::WorkspaceFailure,
            None,
            "invocation workspace could not be removed",
        ));
    }
    result
}

fn execute_in_workspace<F>(
    request: &AuthorizationRequest,
    workspace: &InvocationWorkspace,
    before_revalidation: F,
) -> AuthorizationResult
where
    F: FnOnce(),
{
    let initial = match Snapshotter::new(workspace, request.capture_limits).capture(&request.input)
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
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
    };

    let mut observations = Vec::new();
    let mut issues = Vec::new();
    let mut coverage_rows = Vec::new();
    let mut pipeline = PipelineExecution {
        stages_completed: 0,
        analyzers_completed: 0,
    };
    let assigned = initial.manifest.artifacts().len() as u64;
    let mut pipeline_complete = true;

    'stages: for (stage_index, stage) in request.stages.iter().enumerate() {
        for (analyzer_index, analyzer) in stage.analyzers.iter().enumerate() {
            match analyzer {
                AuthorizationAnalyzer::Builtin(analyzer) => {
                    let analysis = analyzer.analyze(
                        InspectionPhase::Initial,
                        &initial.manifest,
                        workspace.objects(),
                    );
                    let complete = analysis.coverage.is_complete() && analysis.issues.is_empty();
                    observations.extend(analysis.observations);
                    issues.extend(analysis.issues);
                    coverage_rows.push(analysis.coverage);
                    if complete {
                        pipeline.analyzers_completed += 1;
                    } else {
                        pipeline_complete = false;
                        append_unrun_coverage(
                            request,
                            stage_index,
                            analyzer_index + 1,
                            assigned,
                            &mut coverage_rows,
                        );
                        break 'stages;
                    }
                }
                AuthorizationAnalyzer::Unsupported { id, kind } => {
                    pipeline_complete = false;
                    coverage_rows.push(incomplete_coverage(id.clone(), assigned));
                    issues.push(issue(
                        IssueCode::RequiredAnalyzerProcessFailure,
                        Some(id.clone()),
                        match kind {
                            UnsupportedAnalyzerKind::External => {
                                "selected external analyzer is not implemented"
                            }
                            UnsupportedAnalyzerKind::Pi => {
                                "selected Pi analyzer is not implemented"
                            }
                        },
                    ));
                    append_unrun_coverage(
                        request,
                        stage_index,
                        analyzer_index + 1,
                        assigned,
                        &mut coverage_rows,
                    );
                    break 'stages;
                }
            }
        }
        pipeline.stages_completed += 1;
    }

    observations.sort_by(|left, right| observation_id(left).cmp(observation_id(right)));
    if !pipeline_complete || !issues.is_empty() {
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
    let final_snapshot =
        match Snapshotter::new(workspace, request.capture_limits).capture(&request.input) {
            Ok(snapshot) => snapshot,
            Err(error) => {
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

fn append_unrun_coverage(
    request: &AuthorizationRequest,
    failed_stage: usize,
    next_analyzer: usize,
    assigned: u64,
    rows: &mut Vec<AnalyzerCoverage>,
) {
    for (stage_index, stage) in request.stages.iter().enumerate().skip(failed_stage) {
        let start = if stage_index == failed_stage {
            next_analyzer
        } else {
            0
        };
        rows.extend(
            stage
                .analyzers
                .iter()
                .skip(start)
                .map(|analyzer| incomplete_coverage(analyzer.id().clone(), assigned)),
        );
    }
}

fn incomplete_coverage(analyzer_id: AnalyzerId, assigned: u64) -> AnalyzerCoverage {
    AnalyzerCoverage::new(
        analyzer_id,
        InspectionPhase::Initial,
        assigned,
        assigned,
        0,
        0,
        CoverageStatus::Incomplete,
    )
    .expect("zero completed coverage is valid")
}

fn duplicate_analyzer(stages: &[AuthorizationStage]) -> Option<AnalyzerId> {
    let mut ids = BTreeSet::new();
    stages
        .iter()
        .flat_map(|stage| &stage.analyzers)
        .map(AuthorizationAnalyzer::id)
        .find(|id| !ids.insert((*id).clone()))
        .cloned()
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

fn observation_id(observation: &NormalizedObservation) -> &crate::domain::ObservationId {
    match observation {
        NormalizedObservation::Finding(finding) => &finding.id,
        NormalizedObservation::Classification(classification) => &classification.id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::{
        BuiltinAnalyzerLimits, BuiltinContentApplicability, UnsupportedContentPolicy,
    };
    use crate::domain::{FindingCategory, RuleId};
    use crate::policy::{BindingId, ObservationSelector, PolicyDirective};
    use crate::rules::load_rule_file;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
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

        fn request(&self, suffix: &str, analyzer: AuthorizationAnalyzer) -> AuthorizationRequest {
            AuthorizationRequest {
                run_id: RunId::from_suffix(suffix).unwrap(),
                workspace_root: self.workspace_root.clone(),
                input: self.input.clone(),
                capture_limits: CaptureLimits::default(),
                stages: vec![AuthorizationStage {
                    analyzers: vec![analyzer],
                }],
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

    fn builtin() -> AuthorizationAnalyzer {
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
        AuthorizationAnalyzer::Builtin(
            BuiltinRulesAnalyzer::new(
                "builtin",
                load_rule_file(rules.path()).unwrap(),
                BuiltinAnalyzerLimits {
                    max_content_bytes: 1024,
                    max_findings: 100,
                    content_applicability: BuiltinContentApplicability {
                        invalid_utf8: UnsupportedContentPolicy::Fail,
                        over_max_bytes: UnsupportedContentPolicy::Fail,
                    },
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn complete_clean_scan_allows_and_removes_workspace() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let result = AuthorizationService::authorize(fixture.request("allow", builtin()));
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

    #[test]
    fn matching_observation_is_denied_without_modifying_input() {
        let fixture = Fixture::new();
        let target = fixture.input.join("secret.txt");
        fs::write(&target, "SECRET=value").unwrap();
        let before = fs::read(&target).unwrap();
        let result = AuthorizationService::authorize(fixture.request("deny", builtin()));
        assert_eq!(result.outcome, ServiceOutcome::Deny);
        assert_eq!(result.outcome.exit_code(), 20);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(fs::read(target).unwrap(), before);
    }

    #[test]
    fn unsupported_required_analyzer_fails_closed_with_incomplete_coverage() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("safe.txt"), "safe").unwrap();
        let request = fixture.request(
            "unsupported",
            AuthorizationAnalyzer::Unsupported {
                id: AnalyzerId::new("pi").unwrap(),
                kind: UnsupportedAnalyzerKind::Pi,
            },
        );
        let result = AuthorizationService::authorize(request);
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

    #[test]
    fn unbound_observation_is_an_error_not_a_deny() {
        let fixture = Fixture::new();
        fs::write(fixture.input.join("secret.txt"), "SECRET").unwrap();
        let mut request = fixture.request("unbound", builtin());
        request.policy_bindings.clear();
        let result = AuthorizationService::authorize(request);
        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert!(result.resolutions.is_empty());
        assert_eq!(result.issues[0].code, IssueCode::PolicyResolutionFailure);
    }

    #[test]
    fn invalid_pipeline_is_rejected_before_workspace_creation() {
        let fixture = Fixture::new();
        let request = AuthorizationRequest {
            run_id: RunId::from_suffix("empty").unwrap(),
            workspace_root: fixture.workspace_root.clone(),
            input: fixture.input.clone(),
            capture_limits: CaptureLimits::default(),
            stages: Vec::new(),
            policy_bindings: Vec::new(),
        };
        let result = AuthorizationService::authorize(request);
        assert_eq!(result.outcome, ServiceOutcome::Error);
        assert_eq!(result.issues[0].code, IssueCode::ConfigurationFailure);
        assert!(fs::read_dir(&fixture.workspace_root)
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn evaluate_revalidation_failure_remains_in_initial_lifecycle_phase() {
        let fixture = Fixture::new();
        let target = fixture.input.join("changing.txt");
        fs::write(&target, "before").unwrap();
        let request = fixture.request("revalidation-change", builtin());

        let result = authorize_with_revalidation_hook(request, || {
            fs::write(&target, "after").unwrap();
        });

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
