//! Backend-neutral schema-3 phase orchestration.
//!
//! The executor owns selection, assignments, coverage, stage ordering, prior
//! projection, and required/advisory semantics. Native and model backends may
//! return only normalized observations and an exact disposition for each
//! host-issued assignment; they cannot assert their own coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::future::join_all;
use globset::{Candidate, GlobBuilder, GlobSet, GlobSetBuilder};

use crate::analyzers::external::ScannerVersion;
use crate::analyzers::pi::triage::{PiTriageRequest, PiTriageResult, PriorFinding};
use crate::analyzers::BuiltinRulesAnalyzer;
use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, CandidateId, CoverageStatus, Digest, InspectionPhase,
    LogicalPath, NormalizedObservation, ObservationId, RunId,
};
use crate::pipeline::{PriorObservationProjection, StageExecution};
use crate::processing::config::{AnalyzerArtifactKind, PhaseExecution};
use crate::processing::domain::{GitHistoryScope, GitProvenance};
use crate::processing::findings::{
    normalize_findings, ArtifactFindingContext, ArtifactFindingProvenance,
    FindingNormalizationContext, JobCorrelationKey, NormalizedPhaseFindings, ObservationEvidence,
};
use crate::processing::runtime::{
    FrozenAnalyzer, FrozenAnalyzerImplementation, FrozenExternalAnalyzer, FrozenPiRuntime,
    FrozenPipeline,
};
use crate::processing::{Correlation, Finding, Occurrence};

pub type BackendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AnalyzerBackendOutput, AnalyzerBackendError>> + Send + 'a>>;

pub trait BuiltinProcessingBackend: Send + Sync {
    fn execute<'a>(
        &'a self,
        runtime: &'a BuiltinRulesAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a>;
}

pub trait ExternalProcessingBackend: Send + Sync {
    fn execute<'a>(
        &'a self,
        runtime: &'a FrozenExternalAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a>;
}

pub trait PiProcessingBackend: Send + Sync {
    fn execute<'a>(
        &'a self,
        runtime: &'a FrozenPiRuntime,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a>;
}

pub struct ProcessingBackends<'a> {
    pub builtin: &'a dyn BuiltinProcessingBackend,
    pub external: &'a dyn ExternalProcessingBackend,
    pub pi: &'a dyn PiProcessingBackend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingArtifact {
    pub artifact_id: ArtifactId,
    pub logical_path: LogicalPath,
    pub kind: AnalyzerArtifactKind,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub surface: ProcessingArtifactSurface,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessingArtifactSurface {
    WorkingTree,
    GitHistory {
        repository_identity: Digest,
        history_scope: GitHistoryScope,
        provenance: GitProvenance,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingArtifactCatalog {
    artifacts: Vec<ProcessingArtifact>,
}

impl ProcessingArtifactCatalog {
    pub fn new(mut artifacts: Vec<ProcessingArtifact>) -> Result<Self, ProcessingExecutorError> {
        artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        let mut working_tree_paths = BTreeSet::new();
        for pair in artifacts.windows(2) {
            if pair[0].artifact_id == pair[1].artifact_id {
                return Err(ProcessingExecutorError::InvalidCatalog);
            }
        }
        for artifact in &artifacts {
            if (matches!(&artifact.surface, ProcessingArtifactSurface::WorkingTree)
                && !working_tree_paths.insert(artifact.logical_path.clone()))
                || (artifact.kind == AnalyzerArtifactKind::RepositoryBlob)
                    != matches!(
                        &artifact.surface,
                        ProcessingArtifactSurface::GitHistory { .. }
                    )
                || matches!(
                    &artifact.surface,
                    ProcessingArtifactSurface::GitHistory {
                        history_scope: GitHistoryScope::None,
                        ..
                    }
                )
            {
                return Err(ProcessingExecutorError::InvalidCatalog);
            }
        }
        Ok(Self { artifacts })
    }

    pub fn artifacts(&self) -> &[ProcessingArtifact] {
        &self.artifacts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingAssignment {
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
    pub logical_path: LogicalPath,
    pub kind: AnalyzerArtifactKind,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub surface: ProcessingArtifactSurface,
}

#[derive(Clone, Debug)]
pub struct ProcessingExecutionContext {
    pub run_id: RunId,
    pub snapshot_identity: Digest,
    pub pipeline_identity: Digest,
    pub policy_identity: Digest,
    pub correlation_key: JobCorrelationKey,
}

#[derive(Clone)]
pub struct AnalyzerInvocation {
    pub phase: InspectionPhase,
    pub analyzer_id: AnalyzerId,
    pub assignments: Arc<[ProcessingAssignment]>,
    pub artifacts: Arc<ProcessingArtifactCatalog>,
    pub prior: Arc<PriorObservationProjection>,
    pub prior_findings: Arc<NormalizedPhaseFindings>,
    pub prior_coverage: Arc<[AnalyzerCoverage]>,
}

impl std::fmt::Debug for AnalyzerInvocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnalyzerInvocation")
            .field("phase", &self.phase)
            .field("analyzer_id", &self.analyzer_id)
            .field("assignment_count", &self.assignments.len())
            .field("prior_identity", &self.prior.identity())
            .field("prior_finding_count", &self.prior_findings.findings.len())
            .field("prior_coverage_count", &self.prior_coverage.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentDisposition {
    Completed,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentOutcome {
    pub candidate_id: CandidateId,
    pub disposition: AssignmentDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalyzerBackendOutput {
    pub assignments: Vec<AssignmentOutcome>,
    pub observations: Vec<NormalizedObservation>,
    pub evidence: Vec<BackendObservationEvidence>,
    pub scanner_version: Option<ScannerVersion>,
    pub pi_analysis: Option<ValidatedPiAnalysis>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPiAnalysis {
    request: PiTriageRequest,
    result: PiTriageResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PiAnalysisExpectation {
    pub run_id: RunId,
    pub phase: InspectionPhase,
    pub manifest_identity: Digest,
    pub pipeline_identity: Digest,
    pub policy_identity: Digest,
    pub prompt_template_identity: Digest,
    pub prior_observations_identity: Digest,
    pub prior_coverage: Vec<AnalyzerCoverage>,
    pub assigned_artifact_count: u64,
    pub completed_artifact_count: u64,
    pub not_applicable_artifact_count: u64,
    pub findings: Vec<PriorFinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PiAnalysisBindingError {
    #[error("Pi request identity or host binding is stale")]
    RequestBinding,
    #[error("Pi result coverage or assessment binding is incomplete")]
    ResultBinding,
}

impl ValidatedPiAnalysis {
    pub fn new(
        request: PiTriageRequest,
        result: PiTriageResult,
        expected: PiAnalysisExpectation,
    ) -> Result<Self, PiAnalysisBindingError> {
        if request.validate_identity().is_err()
            || request.run_id != expected.run_id
            || request.phase != expected.phase
            || request.manifest_identity != expected.manifest_identity
            || request.pipeline_identity != expected.pipeline_identity
            || request.policy_identity != expected.policy_identity
            || request.prompt_template_identity != expected.prompt_template_identity
            || request.prior_observations_identity != expected.prior_observations_identity
            || request.prior_coverage != expected.prior_coverage
            || request.assigned_artifact_count != expected.assigned_artifact_count
            || request.findings != expected.findings
        {
            return Err(PiAnalysisBindingError::RequestBinding);
        }
        let finding_ids = request
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        let assessment_ids = result
            .assessments
            .iter()
            .map(|assessment| assessment.finding_id.clone())
            .collect::<Vec<_>>();
        if expected
            .completed_artifact_count
            .checked_add(expected.not_applicable_artifact_count)
            != Some(expected.assigned_artifact_count)
            || assessment_ids != finding_ids
            || result.coverage.assigned_artifact_count != expected.assigned_artifact_count
            || result.coverage.completed_artifact_count != expected.completed_artifact_count
            || result.coverage.not_applicable_artifact_count
                != expected.not_applicable_artifact_count
            || result.coverage.assigned_finding_count != finding_ids.len() as u64
            || result.coverage.assessed_finding_count != finding_ids.len() as u64
        {
            return Err(PiAnalysisBindingError::ResultBinding);
        }
        Ok(Self { request, result })
    }

    pub fn request(&self) -> &PiTriageRequest {
        &self.request
    }

    pub fn result(&self) -> &PiTriageResult {
        &self.result
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BackendObservationEvidence {
    pub observation_id: ObservationId,
    pub canonical_window: Vec<u8>,
    pub verification_state: crate::processing::CredentialVerificationState,
}

impl std::fmt::Debug for BackendObservationEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendObservationEvidence")
            .field("observation_id", &self.observation_id)
            .field("canonical_window", &"[REDACTED]")
            .field("window_byte_len", &self.canonical_window.len())
            .field("verification_state", &self.verification_state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalyzerBackendError {
    Unavailable,
    InvalidOutput,
    BudgetExceeded,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalyzerRunState {
    Complete,
    AdvisoryFailed,
    RequiredFailed,
    Cancelled,
    Disabled,
    Skipped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalyzerRunRecord {
    pub stage_id: String,
    pub analyzer_id: AnalyzerId,
    pub execution: PhaseExecution,
    pub state: AnalyzerRunState,
    pub assigned: u64,
    pub scanner_version: Option<ScannerVersion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessingExecutionIssueCode {
    AssignmentConstruction,
    InvalidBackendOutput,
    BackendUnavailable,
    BackendBudgetExceeded,
    Cancelled,
    PriorProjectionLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingExecutionIssue {
    pub stage_id: String,
    pub analyzer_id: Option<AnalyzerId>,
    pub code: ProcessingExecutionIssueCode,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingPhaseResult {
    pub phase: InspectionPhase,
    pub stages_completed: u64,
    pub analyzers_completed: u64,
    pub observations: Vec<NormalizedObservation>,
    pub occurrences: Vec<Occurrence>,
    pub findings: Vec<Finding>,
    pub correlations: Vec<Correlation>,
    pub observation_to_finding: BTreeMap<ObservationId, crate::processing::FindingId>,
    pub pi_results: Vec<PiAnalyzerResult>,
    pub coverage: Vec<AnalyzerCoverage>,
    pub analyzer_runs: Vec<AnalyzerRunRecord>,
    pub issues: Vec<ProcessingExecutionIssue>,
    pub required_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PiAnalyzerResult {
    pub analyzer_id: AnalyzerId,
    pub analysis: ValidatedPiAnalysis,
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ProcessingExecutorError {
    #[error("frozen processing pipeline is invalid")]
    InvalidPipeline,
    #[error("processing artifact catalog is invalid")]
    InvalidCatalog,
    #[error("analyzer selector could not be compiled")]
    InvalidSelector,
    #[error("candidate identifier could not be constructed")]
    CandidateIdentifier,
    #[error("validated analyzer observations could not be normalized")]
    FindingNormalization,
}

struct PreparedAnalyzer<'a> {
    analyzer: &'a FrozenAnalyzer,
    execution: PhaseExecution,
    assignments: Arc<[ProcessingAssignment]>,
}

struct ValidatedAnalyzerResult {
    observations: Vec<NormalizedObservation>,
    evidence: Vec<BackendObservationEvidence>,
    scanner_version: Option<ScannerVersion>,
    pi_result: Option<PiAnalyzerResult>,
    coverage: AnalyzerCoverage,
}

#[derive(Clone)]
struct PhaseAnalyzerInputs {
    phase: InspectionPhase,
    artifacts: Arc<ProcessingArtifactCatalog>,
    prior: Arc<PriorObservationProjection>,
    prior_findings: Arc<NormalizedPhaseFindings>,
    prior_coverage: Arc<[AnalyzerCoverage]>,
}

pub struct ProcessingPhaseExecutor;

impl ProcessingPhaseExecutor {
    pub async fn execute(
        pipeline: &FrozenPipeline,
        phase: InspectionPhase,
        context: &ProcessingExecutionContext,
        artifacts: Arc<ProcessingArtifactCatalog>,
        backends: ProcessingBackends<'_>,
    ) -> Result<ProcessingPhaseResult, ProcessingExecutorError> {
        validate_pipeline(pipeline)?;
        let prepared = prepare(pipeline, phase, &artifacts)?;
        let mut result = ProcessingPhaseResult {
            phase,
            stages_completed: 0,
            analyzers_completed: 0,
            observations: Vec::new(),
            occurrences: Vec::new(),
            findings: Vec::new(),
            correlations: Vec::new(),
            observation_to_finding: BTreeMap::new(),
            pi_results: Vec::new(),
            coverage: Vec::new(),
            analyzer_runs: Vec::new(),
            issues: Vec::new(),
            required_complete: true,
        };
        let mut halted = false;
        let mut evidence = Vec::new();

        for (stage_index, stage) in pipeline.stages.iter().enumerate() {
            if halted {
                append_skipped(stage, phase, &prepared[stage_index], &mut result);
                continue;
            }
            let prior = match PriorObservationProjection::build(
                stage.prior_observations,
                &result.observations,
                stage.prior_limits,
            ) {
                Ok(prior) => Arc::new(prior),
                Err(_) => {
                    result.required_complete = false;
                    result.issues.push(ProcessingExecutionIssue {
                        stage_id: stage.id.as_str().to_owned(),
                        analyzer_id: None,
                        code: ProcessingExecutionIssueCode::PriorProjectionLimit,
                        required: true,
                    });
                    append_skipped(stage, phase, &prepared[stage_index], &mut result);
                    halted = true;
                    continue;
                }
            };
            let prior_findings = Arc::new(normalize_phase(
                context, phase, &artifacts, &result, &evidence,
            )?);
            let prior_coverage: Arc<[AnalyzerCoverage]> = result.coverage.clone().into();

            let stage_results = execute_stage(
                stage.execution,
                context,
                &prepared[stage_index],
                PhaseAnalyzerInputs {
                    phase,
                    artifacts: Arc::clone(&artifacts),
                    prior,
                    prior_findings,
                    prior_coverage,
                },
                &backends,
            )
            .await;
            let mut required_failed = false;
            let returned = stage_results.len();
            for (prepared, backend_result) in prepared[stage_index]
                .iter()
                .take(returned)
                .zip(stage_results)
            {
                required_failed |=
                    absorb_result(stage, prepared, backend_result, &mut evidence, &mut result);
            }
            if returned < prepared[stage_index].len() {
                append_skipped_from(stage, &prepared[stage_index], returned, &mut result);
            }
            if required_failed {
                result.required_complete = false;
                halted = true;
            } else {
                result.stages_completed += 1;
            }
        }

        result.observations.sort();
        let normalized = normalize_phase(context, phase, &artifacts, &result, &evidence)?;
        apply_normalized(&mut result, normalized);
        result
            .pi_results
            .sort_by(|left, right| left.analyzer_id.cmp(&right.analyzer_id));
        result.coverage.sort_by(|left, right| {
            (left.analyzer_id.clone(), left.phase).cmp(&(right.analyzer_id.clone(), right.phase))
        });
        Ok(result)
    }
}

fn validate_pipeline(pipeline: &FrozenPipeline) -> Result<(), ProcessingExecutorError> {
    if pipeline.stages.is_empty() {
        return Err(ProcessingExecutorError::InvalidPipeline);
    }
    let mut stages = BTreeSet::new();
    let mut analyzers = BTreeSet::new();
    for stage in &pipeline.stages {
        if stage.analyzers.is_empty()
            || !stages.insert(stage.id.as_str())
            || matches!(
                stage.execution,
                StageExecution::Parallel { max_concurrency: 0 }
            )
            || stage
                .analyzers
                .iter()
                .any(|analyzer| !analyzers.insert(analyzer.id.clone()))
        {
            return Err(ProcessingExecutorError::InvalidPipeline);
        }
    }
    Ok(())
}

fn prepare<'a>(
    pipeline: &'a FrozenPipeline,
    phase: InspectionPhase,
    artifacts: &ProcessingArtifactCatalog,
) -> Result<Vec<Vec<PreparedAnalyzer<'a>>>, ProcessingExecutorError> {
    pipeline
        .stages
        .iter()
        .map(|stage| {
            stage
                .analyzers
                .iter()
                .map(|analyzer| {
                    let execution = phase_execution(analyzer, phase);
                    let assignments = if execution == PhaseExecution::Disabled {
                        Vec::new()
                    } else {
                        assign(analyzer, artifacts)?
                    };
                    Ok(PreparedAnalyzer {
                        analyzer,
                        execution,
                        assignments: assignments.into(),
                    })
                })
                .collect()
        })
        .collect()
}

fn phase_execution(analyzer: &FrozenAnalyzer, phase: InspectionPhase) -> PhaseExecution {
    match phase {
        InspectionPhase::Initial => analyzer.initial,
        InspectionPhase::Verification => analyzer.verification,
    }
}

fn assign(
    analyzer: &FrozenAnalyzer,
    catalog: &ProcessingArtifactCatalog,
) -> Result<Vec<ProcessingAssignment>, ProcessingExecutorError> {
    let include = compile_globs(&analyzer.selection.include)?;
    let exclude = compile_globs(&analyzer.selection.exclude)?;
    let kinds = analyzer
        .selection
        .artifact_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut assignments = catalog
        .artifacts()
        .iter()
        .filter(|artifact| kinds.contains(&artifact.kind))
        .filter(|artifact| artifact_matches(artifact, &include, &exclude))
        .map(|artifact| {
            Ok(ProcessingAssignment {
                candidate_id: candidate_id(&analyzer.id, &artifact.artifact_id)?,
                artifact_id: artifact.artifact_id.clone(),
                logical_path: artifact.logical_path.clone(),
                kind: artifact.kind,
                byte_len: artifact.byte_len,
                content_digest: artifact.content_digest,
                surface: artifact.surface.clone(),
            })
        })
        .collect::<Result<Vec<_>, ProcessingExecutorError>>()?;
    assignments.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(assignments)
}

fn artifact_matches(artifact: &ProcessingArtifact, include: &GlobSet, exclude: &GlobSet) -> bool {
    let matches = |path: &LogicalPath| {
        let bytes = logical_path_bytes(path);
        let candidate = Candidate::from_bytes(&bytes);
        include.is_match_candidate(&candidate) && !exclude.is_match_candidate(&candidate)
    };
    match &artifact.surface {
        ProcessingArtifactSurface::WorkingTree => matches(&artifact.logical_path),
        ProcessingArtifactSurface::GitHistory { provenance, .. } => provenance
            .occurrences
            .iter()
            .any(|occurrence| matches(&occurrence.path)),
    }
}

fn compile_globs(patterns: &[String]) -> Result<GlobSet, ProcessingExecutorError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            GlobBuilder::new(pattern)
                .literal_separator(true)
                .backslash_escape(true)
                .build()
                .map_err(|_| ProcessingExecutorError::InvalidSelector)?,
        );
    }
    builder
        .build()
        .map_err(|_| ProcessingExecutorError::InvalidSelector)
}

fn logical_path_bytes(path: &LogicalPath) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, segment) in path.segments().iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(segment.as_slice());
    }
    bytes
}

fn candidate_id(
    analyzer: &AnalyzerId,
    artifact: &ArtifactId,
) -> Result<CandidateId, ProcessingExecutorError> {
    let digest = Digest::sha256(
        [
            b"file-guardian-processing-candidate/1\0".as_slice(),
            analyzer.as_str().as_bytes(),
            b"\0",
            artifact.as_str().as_bytes(),
        ]
        .concat(),
    );
    let suffix = digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    CandidateId::from_suffix(suffix).map_err(|_| ProcessingExecutorError::CandidateIdentifier)
}

async fn execute_stage(
    execution: StageExecution,
    context: &ProcessingExecutionContext,
    prepared: &[PreparedAnalyzer<'_>],
    inputs: PhaseAnalyzerInputs,
    backends: &ProcessingBackends<'_>,
) -> Vec<Result<ValidatedAnalyzerResult, AnalyzerBackendError>> {
    let concurrency = match execution {
        StageExecution::Serial => 1,
        StageExecution::Parallel { max_concurrency } => max_concurrency,
    };
    let mut results = Vec::with_capacity(prepared.len());
    for batch in prepared.chunks(concurrency) {
        let futures = batch
            .iter()
            .map(|prepared| execute_analyzer(prepared, context, inputs.clone(), backends));
        let batch_results = join_all(futures).await;
        let required_failed = batch.iter().zip(&batch_results).any(|(prepared, result)| {
            prepared.execution == PhaseExecution::Required && result.is_err()
        });
        results.extend(batch_results);
        if required_failed {
            break;
        }
    }
    results
}

async fn execute_analyzer(
    prepared: &PreparedAnalyzer<'_>,
    context: &ProcessingExecutionContext,
    inputs: PhaseAnalyzerInputs,
    backends: &ProcessingBackends<'_>,
) -> Result<ValidatedAnalyzerResult, AnalyzerBackendError> {
    if prepared.execution == PhaseExecution::Disabled {
        return Ok(ValidatedAnalyzerResult {
            observations: Vec::new(),
            evidence: Vec::new(),
            scanner_version: None,
            pi_result: None,
            coverage: complete_coverage(prepared, inputs.phase, 0, 0),
        });
    }
    let prior_identity = inputs.prior.identity();
    let invocation = AnalyzerInvocation {
        phase: inputs.phase,
        analyzer_id: prepared.analyzer.id.clone(),
        assignments: Arc::clone(&prepared.assignments),
        artifacts: inputs.artifacts,
        prior: inputs.prior,
        prior_findings: Arc::clone(&inputs.prior_findings),
        prior_coverage: Arc::clone(&inputs.prior_coverage),
    };
    let phase = invocation.phase;
    let output = match &prepared.analyzer.implementation {
        FrozenAnalyzerImplementation::Builtin(runtime) => {
            backends.builtin.execute(runtime, invocation).await
        }
        FrozenAnalyzerImplementation::External(runtime) => {
            backends.external.execute(runtime, invocation).await
        }
        FrozenAnalyzerImplementation::Pi(runtime) => backends.pi.execute(runtime, invocation).await,
    }?;
    validate_backend_output(
        prepared,
        phase,
        context,
        prior_identity,
        &inputs.prior_findings,
        &inputs.prior_coverage,
        output,
    )
}

fn validate_backend_output(
    prepared: &PreparedAnalyzer<'_>,
    phase: InspectionPhase,
    context: &ProcessingExecutionContext,
    prior_identity: Digest,
    prior_findings: &NormalizedPhaseFindings,
    prior_coverage: &[AnalyzerCoverage],
    mut output: AnalyzerBackendOutput,
) -> Result<ValidatedAnalyzerResult, AnalyzerBackendError> {
    let is_external = matches!(
        &prepared.analyzer.implementation,
        FrozenAnalyzerImplementation::External(_)
    );
    if is_external != output.scanner_version.is_some() {
        return Err(AnalyzerBackendError::InvalidOutput);
    }
    let is_pi = matches!(
        &prepared.analyzer.implementation,
        FrozenAnalyzerImplementation::Pi(_)
    );
    if is_pi != output.pi_analysis.is_some() || (is_pi && !output.observations.is_empty()) {
        return Err(AnalyzerBackendError::InvalidOutput);
    }
    let known_findings = prior_findings
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();
    if let Some(analysis) = &output.pi_analysis {
        let FrozenAnalyzerImplementation::Pi(runtime) = &prepared.analyzer.implementation else {
            return Err(AnalyzerBackendError::InvalidOutput);
        };
        if analysis.request.validate_identity().is_err()
            || analysis.request.run_id != context.run_id
            || analysis.request.phase != phase
            || analysis.request.pipeline_identity != context.pipeline_identity
            || analysis.request.policy_identity != context.policy_identity
            || analysis.request.prompt_template_identity != runtime.instruction_identity
            || analysis.request.prior_observations_identity != prior_identity
            || analysis.request.prior_coverage != prior_coverage
            || analysis.request.assigned_artifact_count != prepared.assignments.len() as u64
            || analysis
                .request
                .findings
                .iter()
                .any(|finding| !known_findings.contains(&finding.finding_id))
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
    }
    let assigned = prepared
        .assignments
        .iter()
        .map(|item| (item.candidate_id.clone(), item.artifact_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut completed = 0_u64;
    let mut not_applicable = 0_u64;
    let mut seen = BTreeSet::new();
    let mut completed_artifacts = BTreeSet::new();
    for outcome in &output.assignments {
        if !assigned.contains_key(&outcome.candidate_id)
            || !seen.insert(outcome.candidate_id.clone())
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
        match outcome.disposition {
            AssignmentDisposition::Completed => {
                completed += 1;
                completed_artifacts.insert(
                    assigned
                        .get(&outcome.candidate_id)
                        .expect("candidate membership checked")
                        .clone(),
                );
            }
            AssignmentDisposition::NotApplicable => not_applicable += 1,
        }
    }
    if seen.len() != assigned.len() {
        return Err(AnalyzerBackendError::InvalidOutput);
    }
    if let Some(analysis) = &output.pi_analysis {
        let request_findings = analysis
            .request
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        let assessment_findings = analysis
            .result
            .assessments
            .iter()
            .map(|assessment| assessment.finding_id.clone())
            .collect::<Vec<_>>();
        let coverage = analysis.result.coverage;
        if request_findings != assessment_findings
            || coverage.assigned_artifact_count != assigned.len() as u64
            || coverage.completed_artifact_count != completed
            || coverage.not_applicable_artifact_count != not_applicable
            || coverage.assigned_finding_count != request_findings.len() as u64
            || coverage.assessed_finding_count != request_findings.len() as u64
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
    }
    let mut observation_ids = BTreeSet::new();
    for observation in &mut output.observations {
        let (id, analyzer_id, subjects) = match observation {
            NormalizedObservation::Finding(finding) => (
                &finding.id,
                &finding.analyzer_id,
                vec![&finding.artifact_id],
            ),
            NormalizedObservation::Classification(_) => {
                return Err(AnalyzerBackendError::InvalidOutput)
            }
        };
        if analyzer_id != &prepared.analyzer.id
            || !observation_ids.insert(id.clone())
            || subjects
                .iter()
                .any(|artifact| !completed_artifacts.contains(*artifact))
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
    }
    let mut evidence_ids = BTreeSet::new();
    if output.evidence.iter().any(|item| {
        !observation_ids.contains(&item.observation_id)
            || !evidence_ids.insert(item.observation_id.clone())
    }) {
        return Err(AnalyzerBackendError::InvalidOutput);
    }
    output.observations.sort();
    let eligible = prepared.assignments.len() as u64;
    let coverage = AnalyzerCoverage::new(
        prepared.analyzer.id.clone(),
        phase,
        eligible,
        eligible,
        completed,
        not_applicable,
        CoverageStatus::Complete,
    )
    .map_err(|_| AnalyzerBackendError::InvalidOutput)?;
    Ok(ValidatedAnalyzerResult {
        observations: output.observations,
        evidence: output.evidence,
        scanner_version: output.scanner_version,
        pi_result: output.pi_analysis.map(|analysis| PiAnalyzerResult {
            analyzer_id: prepared.analyzer.id.clone(),
            analysis,
        }),
        coverage,
    })
}

fn absorb_result(
    stage: &crate::processing::runtime::FrozenStage,
    prepared: &PreparedAnalyzer<'_>,
    backend: Result<ValidatedAnalyzerResult, AnalyzerBackendError>,
    evidence: &mut Vec<BackendObservationEvidence>,
    result: &mut ProcessingPhaseResult,
) -> bool {
    let stage_id = stage.id.as_str().to_owned();
    if prepared.execution == PhaseExecution::Disabled {
        result.analyzer_runs.push(AnalyzerRunRecord {
            stage_id,
            analyzer_id: prepared.analyzer.id.clone(),
            execution: prepared.execution,
            state: AnalyzerRunState::Disabled,
            assigned: 0,
            scanner_version: None,
        });
        return false;
    }
    match backend {
        Ok(backend) => {
            result.observations.extend(backend.observations);
            evidence.extend(backend.evidence);
            if let Some(pi_result) = backend.pi_result {
                result.pi_results.push(pi_result);
            }
            result.coverage.push(backend.coverage);
            result.analyzers_completed += 1;
            result.analyzer_runs.push(AnalyzerRunRecord {
                stage_id,
                analyzer_id: prepared.analyzer.id.clone(),
                execution: prepared.execution,
                state: AnalyzerRunState::Complete,
                assigned: prepared.assignments.len() as u64,
                scanner_version: backend.scanner_version,
            });
            false
        }
        Err(error) => {
            let cancelled = error == AnalyzerBackendError::Cancelled;
            let required = prepared.execution == PhaseExecution::Required || cancelled;
            result
                .coverage
                .push(incomplete_coverage(prepared, result.phase));
            result.issues.push(ProcessingExecutionIssue {
                stage_id: stage_id.clone(),
                analyzer_id: Some(prepared.analyzer.id.clone()),
                code: map_backend_error(error),
                required,
            });
            result.analyzer_runs.push(AnalyzerRunRecord {
                stage_id,
                analyzer_id: prepared.analyzer.id.clone(),
                execution: prepared.execution,
                state: if cancelled {
                    AnalyzerRunState::Cancelled
                } else if required {
                    AnalyzerRunState::RequiredFailed
                } else {
                    AnalyzerRunState::AdvisoryFailed
                },
                assigned: prepared.assignments.len() as u64,
                scanner_version: None,
            });
            required
        }
    }
}

fn artifact_finding_context(artifact: &ProcessingArtifact) -> ArtifactFindingContext {
    ArtifactFindingContext {
        artifact_id: artifact.artifact_id.clone(),
        content_digest: artifact.content_digest,
        provenance: match &artifact.surface {
            ProcessingArtifactSurface::WorkingTree => {
                ArtifactFindingProvenance::LogicalPath(artifact.logical_path.clone())
            }
            ProcessingArtifactSurface::GitHistory {
                repository_identity,
                provenance,
                ..
            } => ArtifactFindingProvenance::Git {
                repository_identity: *repository_identity,
                provenance: provenance.clone(),
            },
        },
    }
}

fn normalize_phase(
    context: &ProcessingExecutionContext,
    phase: InspectionPhase,
    artifacts: &ProcessingArtifactCatalog,
    result: &ProcessingPhaseResult,
    evidence: &[BackendObservationEvidence],
) -> Result<NormalizedPhaseFindings, ProcessingExecutorError> {
    if result.observations.is_empty() {
        return Ok(NormalizedPhaseFindings {
            occurrences: Vec::new(),
            findings: Vec::new(),
            correlations: Vec::new(),
            observation_to_finding: BTreeMap::new(),
        });
    }
    let finding_contexts = artifacts
        .artifacts()
        .iter()
        .map(artifact_finding_context)
        .collect::<Vec<_>>();
    let evidence = evidence
        .iter()
        .map(|value| ObservationEvidence {
            observation_id: &value.observation_id,
            canonical_window: &value.canonical_window,
            verification_state: value.verification_state,
        })
        .collect::<Vec<_>>();
    let mut analyzer_ids = result
        .analyzer_runs
        .iter()
        .filter(|run| run.state == AnalyzerRunState::Complete)
        .map(|run| run.analyzer_id.clone())
        .collect::<Vec<_>>();
    analyzer_ids.sort();
    analyzer_ids.dedup();
    normalize_findings(
        FindingNormalizationContext {
            run_id: &context.run_id,
            phase,
            analyzer_ids: &analyzer_ids,
            snapshot_identity: context.snapshot_identity,
            artifacts: &finding_contexts,
            evidence: &evidence,
            correlation_key: &context.correlation_key,
        },
        &result.observations,
    )
    .map_err(|_| ProcessingExecutorError::FindingNormalization)
}

fn apply_normalized(result: &mut ProcessingPhaseResult, normalized: NormalizedPhaseFindings) {
    result.occurrences = normalized.occurrences;
    result.findings = normalized.findings;
    result.correlations = normalized.correlations;
    result.observation_to_finding = normalized.observation_to_finding;
}

fn map_backend_error(error: AnalyzerBackendError) -> ProcessingExecutionIssueCode {
    match error {
        AnalyzerBackendError::Unavailable => ProcessingExecutionIssueCode::BackendUnavailable,
        AnalyzerBackendError::InvalidOutput => ProcessingExecutionIssueCode::InvalidBackendOutput,
        AnalyzerBackendError::BudgetExceeded => ProcessingExecutionIssueCode::BackendBudgetExceeded,
        AnalyzerBackendError::Cancelled => ProcessingExecutionIssueCode::Cancelled,
    }
}

fn append_skipped(
    stage: &crate::processing::runtime::FrozenStage,
    phase: InspectionPhase,
    prepared: &[PreparedAnalyzer<'_>],
    result: &mut ProcessingPhaseResult,
) {
    let _ = phase;
    append_skipped_from(stage, prepared, 0, result);
}

fn append_skipped_from(
    stage: &crate::processing::runtime::FrozenStage,
    prepared: &[PreparedAnalyzer<'_>],
    from: usize,
    result: &mut ProcessingPhaseResult,
) {
    for prepared in &prepared[from..] {
        result.analyzer_runs.push(AnalyzerRunRecord {
            stage_id: stage.id.as_str().to_owned(),
            analyzer_id: prepared.analyzer.id.clone(),
            execution: prepared.execution,
            state: if prepared.execution == PhaseExecution::Disabled {
                AnalyzerRunState::Disabled
            } else {
                AnalyzerRunState::Skipped
            },
            assigned: prepared.assignments.len() as u64,
            scanner_version: None,
        });
    }
}

fn incomplete_coverage(
    prepared: &PreparedAnalyzer<'_>,
    phase: InspectionPhase,
) -> AnalyzerCoverage {
    let assigned = prepared.assignments.len() as u64;
    AnalyzerCoverage::new(
        prepared.analyzer.id.clone(),
        phase,
        assigned,
        assigned,
        0,
        0,
        CoverageStatus::Incomplete,
    )
    .expect("host-owned incomplete coverage is valid")
}

fn complete_coverage(
    prepared: &PreparedAnalyzer<'_>,
    phase: InspectionPhase,
    completed: u64,
    not_applicable: u64,
) -> AnalyzerCoverage {
    let assigned = prepared.assignments.len() as u64;
    AnalyzerCoverage::new(
        prepared.analyzer.id.clone(),
        phase,
        assigned,
        assigned,
        completed,
        not_applicable,
        CoverageStatus::Complete,
    )
    .expect("host-owned complete coverage is valid")
}
