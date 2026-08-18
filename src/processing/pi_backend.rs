//! Schema-3 bridge from immutable processing assignments to Pi triage.
//!
//! The bridge reconstructs the existing descriptor-rooted analyzer workspace
//! from the processing artifact reader. Pi therefore retains the reviewed
//! sidecar, proxy, and read-only view implementation without receiving a live
//! acquisition path or the legacy classifier wire format.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::analyzers::pi::protocol::{ClassificationVocabulary, TerminalValidationLimits};
use crate::analyzers::pi::proxy::{ExpectedPiRuntime, PiProxyLimits};
use crate::analyzers::pi::runner::{PiRunError, PiRunLimits};
use crate::analyzers::pi::sandbox::{PiRuntimeSpec, PI_RUNTIME_CONTEXT_MODE};
use crate::analyzers::pi::triage::{
    PiReviewScope, PiTriageInvocationId, PiTriageLimits, PiTriageRequest, PiTriageRequestContext,
    PriorFinding, PriorOccurrence,
};
use crate::analyzers::pi::{PiClassifierAnalyzer, PiClassifierError, PiClassifierSpec};
use crate::analyzers::{assess_text_artifact, RequiredTextMatcher, TextArtifactDisposition};
use crate::authorization::{AnalyzerViewLimits, AnalyzerViewQuota, InvocationWorkspace};
use crate::domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactManifest, ClassificationCode, ConfiguredConfidence,
    CoverageStatus, Digest, PhysicalSubject, Provenance, ReasonCode, RunId, SourceFileType,
    SourceIdentity, SubjectId,
};
use crate::pipeline::ArtifactAssignment;
use crate::processing::executor::{
    AnalyzerBackendError, AnalyzerBackendOutput, AnalyzerInvocation, AssignmentDisposition,
    AssignmentOutcome, BackendFuture, PiAnalysisExpectation, PiProcessingBackend,
    ProcessingArtifactSurface, ProcessingAssignment, ValidatedPiAnalysis,
};
use crate::processing::external_backend::ProcessingArtifactReader;
use crate::processing::findings::NormalizedPhaseFindings;
use crate::processing::runtime::FrozenPiRuntime;
use crate::processing::GitHistoryScope;

/// Job-frozen identities which Pi must bind into every triage request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PiProcessingContext {
    pub run_id: RunId,
    pub pipeline_identity: Digest,
    pub policy_identity: Digest,
}

/// Executes schema-3 Pi stages through the existing confined Pi runtime.
pub struct ConfinedPiProcessingBackend {
    private_root: PathBuf,
    reader: Arc<dyn ProcessingArtifactReader>,
    context: PiProcessingContext,
    invocation_sequence: AtomicU64,
}

impl std::fmt::Debug for ConfinedPiProcessingBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfinedPiProcessingBackend")
            .field("private_root", &"<private>")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl ConfinedPiProcessingBackend {
    pub fn new(
        private_root: impl AsRef<Path>,
        reader: Arc<dyn ProcessingArtifactReader>,
        context: PiProcessingContext,
    ) -> Result<Self, PiProcessingBackendError> {
        let private_root = private_root.as_ref();
        if !private_root.is_absolute() {
            return Err(PiProcessingBackendError::PrivateWorkspace);
        }
        let metadata = fs::symlink_metadata(private_root)
            .map_err(|_| PiProcessingBackendError::PrivateWorkspace)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PiProcessingBackendError::PrivateWorkspace);
        }
        let private_root = fs::canonicalize(private_root)
            .map_err(|_| PiProcessingBackendError::PrivateWorkspace)?;
        Ok(Self {
            private_root,
            reader,
            context,
            invocation_sequence: AtomicU64::new(0),
        })
    }

    async fn execute_inner(
        &self,
        runtime: &FrozenPiRuntime,
        invocation: AnalyzerInvocation,
    ) -> Result<AnalyzerBackendOutput, AnalyzerBackendError> {
        if invocation.assignments.is_empty() {
            return Err(AnalyzerBackendError::InvalidOutput);
        }

        validate_assignment_surfaces(&invocation)?;
        let required_text = RequiredTextMatcher::compile(&runtime.required_text_include)
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?;
        let sequence = self.invocation_sequence.fetch_add(1, Ordering::Relaxed);
        let workspace_run_id = workspace_run_id(&self.context, &invocation, sequence)?;
        let material = MaterializePiRequest {
            root: self.private_root.clone(),
            run_id: workspace_run_id,
            reader: Arc::clone(&self.reader),
            assignments: Arc::clone(&invocation.assignments),
            required_text,
            max_text_bytes: runtime.limits.max_read_bytes_per_call,
        };
        let prepared = tokio::task::spawn_blocking(move || materialize_pi(material))
            .await
            .map_err(|_| AnalyzerBackendError::Unavailable)?
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?;

        let applicable_artifacts = prepared
            .outcomes
            .iter()
            .zip(invocation.assignments.iter())
            .filter_map(|(outcome, assignment)| {
                (outcome.disposition == AssignmentDisposition::Completed)
                    .then_some(assignment.artifact_id.clone())
            })
            .collect::<BTreeSet<_>>();
        let prior_findings = project_prior_findings(
            &invocation.prior_findings,
            &applicable_artifacts,
            invocation.phase,
        )?;
        let review_scope = review_scope(&invocation.assignments)?;
        let assigned_count = u64::try_from(invocation.assignments.len())
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?;
        let request = Arc::new(
            PiTriageRequest::new(
                PiTriageRequestContext {
                    run_id: self.context.run_id.clone(),
                    invocation_id: triage_invocation_id(
                        &self.context,
                        &invocation,
                        prepared.manifest.identity,
                    )?,
                    phase: invocation.phase,
                    manifest_identity: prepared.manifest.identity,
                    pipeline_identity: self.context.pipeline_identity,
                    policy_identity: self.context.policy_identity,
                    prompt_template_identity: runtime.instruction_identity,
                    prior_observations_identity: invocation.prior.identity(),
                    review_scope,
                    assigned_artifact_count: assigned_count,
                    prior_coverage: invocation.prior_coverage.to_vec(),
                },
                prior_findings,
                triage_limits(runtime)?,
            )
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?,
        );
        let analyzer = compile_analyzer(runtime, &self.context.run_id, &invocation.analyzer_id)?;
        let result = analyzer
            .analyze_triage(
                Arc::clone(&prepared.manifest),
                prepared.assignments,
                Arc::clone(&prepared.workspace),
                Arc::clone(&request),
            )
            .await
            .map_err(map_pi_error)?;

        let completed = prepared
            .outcomes
            .iter()
            .filter(|outcome| outcome.disposition == AssignmentDisposition::Completed)
            .count() as u64;
        let not_applicable = assigned_count - completed;
        if result.coverage.analyzer_id != invocation.analyzer_id
            || result.coverage.phase != invocation.phase
            || result.coverage.eligible != assigned_count
            || result.coverage.assigned != assigned_count
            || result.coverage.completed != completed
            || result.coverage.not_applicable != not_applicable
            || result.coverage.status != CoverageStatus::Complete
            || !result.observations.is_empty()
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
        Ok(AnalyzerBackendOutput {
            assignments: prepared.outcomes,
            observations: Vec::new(),
            evidence: Vec::new(),
            scanner_version: None,
            pi_analysis: Some(
                ValidatedPiAnalysis::new(
                    (*request).clone(),
                    result.triage_result,
                    PiAnalysisExpectation {
                        run_id: self.context.run_id.clone(),
                        phase: invocation.phase,
                        manifest_identity: prepared.manifest.identity,
                        pipeline_identity: self.context.pipeline_identity,
                        policy_identity: self.context.policy_identity,
                        prompt_template_identity: runtime.instruction_identity,
                        prior_observations_identity: invocation.prior.identity(),
                        prior_coverage: invocation.prior_coverage.to_vec(),
                        assigned_artifact_count: assigned_count,
                        completed_artifact_count: completed,
                        not_applicable_artifact_count: not_applicable,
                        findings: request.findings.clone(),
                    },
                )
                .map_err(|_| AnalyzerBackendError::InvalidOutput)?,
            ),
        })
    }
}

impl PiProcessingBackend for ConfinedPiProcessingBackend {
    fn execute<'a>(
        &'a self,
        runtime: &'a FrozenPiRuntime,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a> {
        Box::pin(async move { self.execute_inner(runtime, invocation).await })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PiProcessingBackendError {
    #[error("Pi private workspace is invalid")]
    PrivateWorkspace,
}

struct MaterializePiRequest {
    root: PathBuf,
    run_id: RunId,
    reader: Arc<dyn ProcessingArtifactReader>,
    assignments: Arc<[ProcessingAssignment]>,
    required_text: RequiredTextMatcher,
    max_text_bytes: u64,
}

struct MaterializedPiInvocation {
    workspace: Arc<InvocationWorkspace>,
    manifest: Arc<ArtifactManifest>,
    assignments: Vec<ArtifactAssignment>,
    outcomes: Vec<AssignmentOutcome>,
}

fn materialize_pi(
    request: MaterializePiRequest,
) -> Result<MaterializedPiInvocation, MaterializePiError> {
    let workspace = Arc::new(
        InvocationWorkspace::create(&request.root, &request.run_id)
            .map_err(|_| MaterializePiError::Workspace)?,
    );
    let mut subjects = Vec::with_capacity(request.assignments.len());
    let mut artifacts = Vec::with_capacity(request.assignments.len());
    for (index, assignment) in request.assignments.iter().enumerate() {
        let mut input = request
            .reader
            .open(&assignment.artifact_id)
            .map_err(|_| MaterializePiError::Artifact)?;
        let stored = workspace
            .objects()
            .store(&mut input, assignment.byte_len)
            .map_err(|_| MaterializePiError::Artifact)?;
        if stored.byte_len != assignment.byte_len || stored.digest != assignment.content_digest {
            return Err(MaterializePiError::Artifact);
        }
        let suffix = Digest::sha256(
            [
                assignment.artifact_id.as_str().as_bytes(),
                assignment.content_digest.as_bytes(),
            ]
            .concat(),
        )
        .to_string();
        let subject_id = SubjectId::from_suffix(&suffix["sha256:".len()..])
            .map_err(|_| MaterializePiError::Artifact)?;
        let subject = PhysicalSubject {
            id: subject_id.clone(),
            relative_path: assignment.logical_path.clone(),
            source_identity: SourceIdentity {
                device: 0,
                inode: u64::try_from(index).map_err(|_| MaterializePiError::Artifact)? + 1,
                file_type: SourceFileType::RegularFile,
                byte_len: stored.byte_len,
                link_count: 1,
                modified: None,
                changed: None,
                content_digest: stored.digest,
            },
            object_id: stored.id.clone(),
            byte_len: stored.byte_len,
        };
        artifacts.push(Artifact {
            id: assignment.artifact_id.clone(),
            subject_id,
            object_id: stored.id,
            kind: ArtifactKind::PhysicalFile,
            byte_len: stored.byte_len,
            content_digest: stored.digest,
            provenance: Provenance::Physical {
                logical_path: assignment.logical_path.clone(),
            },
        });
        subjects.push(subject);
    }
    let manifest = Arc::new(
        ArtifactManifest::new(subjects, artifacts).map_err(|_| MaterializePiError::Artifact)?,
    );
    let assignments = request
        .assignments
        .iter()
        .map(|assignment| ArtifactAssignment {
            candidate_id: assignment.candidate_id.clone(),
            artifact_id: assignment.artifact_id.clone(),
        })
        .collect::<Vec<_>>();
    let mut outcomes = Vec::with_capacity(assignments.len());
    for assignment in request.assignments.iter() {
        let artifact = manifest
            .artifact(&assignment.artifact_id)
            .ok_or(MaterializePiError::Artifact)?;
        let disposition = match assess_text_artifact(
            artifact,
            workspace.objects(),
            request.max_text_bytes,
            &request.required_text,
        )
        .map_err(|_| MaterializePiError::Artifact)?
        {
            TextArtifactDisposition::Text(_) => AssignmentDisposition::Completed,
            TextArtifactDisposition::NotApplicableBinary => AssignmentDisposition::NotApplicable,
        };
        outcomes.push(AssignmentOutcome {
            candidate_id: assignment.candidate_id.clone(),
            disposition,
        });
    }
    Ok(MaterializedPiInvocation {
        workspace,
        manifest,
        assignments,
        outcomes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MaterializePiError {
    Workspace,
    Artifact,
}

fn project_prior_findings(
    prior: &NormalizedPhaseFindings,
    assigned_artifacts: &BTreeSet<ArtifactId>,
    phase: crate::domain::InspectionPhase,
) -> Result<Vec<PriorFinding>, AnalyzerBackendError> {
    let mut occurrences = BTreeMap::new();
    for occurrence in &prior.occurrences {
        if occurrences
            .insert(occurrence.id.clone(), occurrence)
            .is_some()
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
    }
    let mut correlations = BTreeMap::new();
    for correlation in &prior.correlations {
        for finding_id in &correlation.finding_ids {
            if correlations
                .insert(finding_id.clone(), correlation.id.clone())
                .is_some()
            {
                return Err(AnalyzerBackendError::InvalidOutput);
            }
        }
    }
    prior
        .findings
        .iter()
        .filter(|finding| assigned_artifacts.contains(&finding.artifact_id))
        .map(|finding| {
            if finding.phase != phase {
                return Err(AnalyzerBackendError::InvalidOutput);
            }
            let correlation_id = correlations
                .get(&finding.id)
                .cloned()
                .ok_or(AnalyzerBackendError::InvalidOutput)?;
            let prior_occurrences = finding
                .occurrence_ids
                .iter()
                .map(|id| {
                    let occurrence = occurrences
                        .get(id)
                        .ok_or(AnalyzerBackendError::InvalidOutput)?;
                    if occurrence.phase != phase
                        || occurrence.artifact_id != finding.artifact_id
                        || occurrence.analyzer_id != finding.analyzer_id
                        || occurrence.rule_id != finding.rule_id
                    {
                        return Err(AnalyzerBackendError::InvalidOutput);
                    }
                    Ok(PriorOccurrence {
                        occurrence_id: occurrence.id.clone(),
                        analyzer_id: occurrence.analyzer_id.clone(),
                        rule_id: occurrence.rule_id.clone(),
                        verification_state: occurrence.verification_state,
                        evidence_token: occurrence.evidence_token,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            PriorFinding::new(
                finding.id.clone(),
                correlation_id,
                finding.phase,
                finding.analyzer_id.clone(),
                finding.rule_id.clone(),
                finding.artifact_id.clone(),
                finding.category,
                finding.severity,
                finding.location.clone(),
                finding.evidence_token,
                prior_occurrences,
            )
            .map_err(|_| AnalyzerBackendError::InvalidOutput)
        })
        .collect()
}

fn validate_assignment_surfaces(
    invocation: &AnalyzerInvocation,
) -> Result<(), AnalyzerBackendError> {
    let catalog = invocation
        .artifacts
        .artifacts()
        .iter()
        .map(|artifact| (artifact.artifact_id.clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    for assignment in invocation.assignments.iter() {
        let artifact = catalog
            .get(&assignment.artifact_id)
            .ok_or(AnalyzerBackendError::InvalidOutput)?;
        if artifact.logical_path != assignment.logical_path
            || artifact.kind != assignment.kind
            || artifact.byte_len != assignment.byte_len
            || artifact.content_digest != assignment.content_digest
            || artifact.surface != assignment.surface
        {
            return Err(AnalyzerBackendError::InvalidOutput);
        }
    }
    Ok(())
}

fn review_scope(
    assignments: &[ProcessingAssignment],
) -> Result<PiReviewScope, AnalyzerBackendError> {
    let working_tree = assignments
        .iter()
        .any(|assignment| assignment.surface == ProcessingArtifactSurface::WorkingTree);
    let histories = assignments
        .iter()
        .filter_map(|assignment| match &assignment.surface {
            ProcessingArtifactSurface::WorkingTree => None,
            ProcessingArtifactSurface::GitHistory { history_scope, .. } => Some(*history_scope),
        })
        .collect::<BTreeSet<_>>();
    let repositories = assignments
        .iter()
        .filter_map(|assignment| match &assignment.surface {
            ProcessingArtifactSurface::WorkingTree => None,
            ProcessingArtifactSurface::GitHistory {
                repository_identity,
                ..
            } => Some(*repository_identity),
        })
        .collect::<BTreeSet<_>>();
    if histories.len() > 1 || repositories.len() > 1 {
        return Err(AnalyzerBackendError::InvalidOutput);
    }
    PiReviewScope::new(
        working_tree,
        histories
            .into_iter()
            .next()
            .unwrap_or(GitHistoryScope::None),
    )
    .map_err(|_| AnalyzerBackendError::InvalidOutput)
}

fn workspace_run_id(
    context: &PiProcessingContext,
    invocation: &AnalyzerInvocation,
    sequence: u64,
) -> Result<RunId, AnalyzerBackendError> {
    let digest = Digest::sha256(format!(
        "pi-workspace:{}:{}:{:?}:{sequence}",
        context.run_id, invocation.analyzer_id, invocation.phase
    ));
    let value = digest.to_string();
    RunId::from_suffix(&value["sha256:".len()..]).map_err(|_| AnalyzerBackendError::InvalidOutput)
}

fn triage_invocation_id(
    context: &PiProcessingContext,
    invocation: &AnalyzerInvocation,
    manifest_identity: Digest,
) -> Result<PiTriageInvocationId, AnalyzerBackendError> {
    let digest = Digest::sha256(format!(
        "pi-triage:{}:{}:{:?}:{}:{}:{}:{}",
        context.run_id,
        invocation.analyzer_id,
        invocation.phase,
        manifest_identity,
        context.pipeline_identity,
        context.policy_identity,
        invocation.prior.identity(),
    ));
    let value = digest.to_string();
    PiTriageInvocationId::new(format!("pii_{}", &value["sha256:".len()..]))
        .map_err(|_| AnalyzerBackendError::InvalidOutput)
}

fn triage_limits(runtime: &FrozenPiRuntime) -> Result<PiTriageLimits, AnalyzerBackendError> {
    PiTriageLimits::new(
        checked_usize(runtime.limits.max_findings)?,
        1,
        checked_usize(runtime.limits.max_output_bytes)?,
        checked_usize(runtime.limits.max_output_bytes)?,
        checked_usize(runtime.limits.max_findings)?,
    )
    .map_err(|_| AnalyzerBackendError::InvalidOutput)
}

fn compile_analyzer(
    runtime: &FrozenPiRuntime,
    run_id: &RunId,
    analyzer_id: &crate::domain::AnalyzerId,
) -> Result<PiClassifierAnalyzer, AnalyzerBackendError> {
    let pi = &runtime.config.pi;
    let confidences = runtime
        .config
        .vocabulary
        .confidences
        .iter()
        .map(|value| match value.as_str() {
            "low" => Ok(ConfiguredConfidence::Low),
            "medium" => Ok(ConfiguredConfidence::Medium),
            "high" => Ok(ConfiguredConfidence::High),
            _ => Err(AnalyzerBackendError::InvalidOutput),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let vocabulary = ClassificationVocabulary::new(
        runtime
            .config
            .vocabulary
            .classifications
            .iter()
            .cloned()
            .map(ClassificationCode::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?,
        confidences,
        runtime
            .config
            .vocabulary
            .reason_codes
            .iter()
            .cloned()
            .map(ReasonCode::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?,
    )
    .map_err(|_| AnalyzerBackendError::InvalidOutput)?;
    let max_findings = checked_usize(runtime.limits.max_findings)?;
    let max_output = checked_usize(runtime.limits.max_output_bytes)?;
    let max_depth = checked_usize(runtime.limits.max_view_depth)?;
    let view_quota = AnalyzerViewQuota {
        max_files: runtime.limits.max_view_files,
        max_entries: runtime.limits.max_view_entries,
        max_total_bytes: runtime.limits.max_view_bytes,
        max_depth,
    };
    PiClassifierAnalyzer::compile(PiClassifierSpec {
        id: analyzer_id.clone(),
        run_id: run_id.clone(),
        runtime: PiRuntimeSpec {
            bubblewrap_executable: pi.bubblewrap_executable.clone(),
            expected_bubblewrap_version: pi.expected_bubblewrap_version.clone(),
            runtime_root: pi.runtime_root.clone(),
            runtime_manifest: pi.runtime_root.join(&pi.runtime_manifest),
            launcher: pi.launcher.clone(),
            pi_entrypoint: pi.pi_entrypoint.clone(),
            expected_pi_version: pi.expected_pi_version.clone(),
            instruction_file: pi.instruction_file.clone(),
            trusted_extension: pi.trusted_extension.clone(),
            tool_sidecar_runner: pi.tool_sidecar_runner.clone(),
            isolated_agent_dir: pi.isolated_agent_dir.clone(),
        },
        instruction: Arc::clone(&runtime.instruction),
        vocabulary,
        expected_runtime: ExpectedPiRuntime {
            pi_version: pi.expected_pi_version.clone(),
            provider: pi.provider.clone(),
            model: pi.model.clone(),
            thinking: pi.thinking.clone(),
            mode: PI_RUNTIME_CONTEXT_MODE.to_owned(),
        },
        terminal_limits: TerminalValidationLimits::new(max_findings, max_findings, max_findings)
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?,
        proxy_limits: PiProxyLimits {
            max_frame_bytes: max_output,
            max_response_bytes: max_output,
            max_terminal_bytes: max_output,
            max_tool_calls: runtime.limits.max_tool_calls,
            max_bytes_read: runtime.limits.max_bytes_read,
            max_read_bytes_per_call: runtime.limits.max_read_bytes_per_call,
            max_search_matches: runtime.limits.max_search_results,
            max_search_bytes_per_call: runtime.limits.max_search_bytes_per_call,
            max_search_calls: runtime.limits.max_search_calls,
            frame_read_timeout: Duration::from_secs(runtime.limits.idle_timeout_secs),
        },
        run_limits: PiRunLimits {
            startup_timeout: Duration::from_secs(runtime.limits.startup_timeout_secs),
            idle_timeout: Duration::from_secs(runtime.limits.idle_timeout_secs),
            wall_timeout: Duration::from_secs(runtime.limits.wall_timeout_secs),
            termination_grace: Duration::from_secs(runtime.limits.termination_grace_secs),
            memory_bytes: runtime.limits.memory_bytes,
            cpu_seconds: runtime.limits.cpu_time_secs,
            open_files: runtime.limits.max_open_files,
            stdout_bytes: runtime.limits.max_stdout_bytes,
            stderr_bytes: runtime.limits.max_stderr_bytes,
        },
        max_search_results: runtime.limits.max_search_results,
        required_text: RequiredTextMatcher::compile(&runtime.required_text_include)
            .map_err(|_| AnalyzerBackendError::InvalidOutput)?,
        max_text_bytes: runtime.limits.max_read_bytes_per_call,
        view_limits: AnalyzerViewLimits {
            per_view: view_quota,
            invocation: view_quota,
        },
        credential_environment: runtime.credential_environment.clone(),
        identity_material: [
            b"file-guardian-processing-pi-backend/1".as_slice(),
            context_identity(runtime).as_bytes(),
        ]
        .concat(),
    })
    .map_err(|_| AnalyzerBackendError::Unavailable)
}

fn context_identity(runtime: &FrozenPiRuntime) -> Digest {
    Digest::sha256(
        [
            runtime.instruction_identity.as_bytes(),
            runtime.config.pi.expected_pi_version.as_bytes(),
            runtime.config.pi.provider.as_bytes(),
            runtime.config.pi.model.as_bytes(),
            runtime.config.pi.thinking.as_bytes(),
        ]
        .concat(),
    )
}

fn checked_usize(value: u64) -> Result<usize, AnalyzerBackendError> {
    usize::try_from(value).map_err(|_| AnalyzerBackendError::InvalidOutput)
}

fn map_pi_error(error: PiClassifierError) -> AnalyzerBackendError {
    match error {
        PiClassifierError::Runner(PiRunError::Timeout(_) | PiRunError::OutputLimit(_))
        | PiClassifierError::Proxy(crate::analyzers::pi::proxy::PiProxyError::BudgetExceeded)
        | PiClassifierError::Proxy(crate::analyzers::pi::proxy::PiProxyError::FrameTooLarge)
        | PiClassifierError::Proxy(crate::analyzers::pi::proxy::PiProxyError::ResponseTooLarge) => {
            AnalyzerBackendError::BudgetExceeded
        }
        PiClassifierError::InvalidAssignment
        | PiClassifierError::Applicability(_)
        | PiClassifierError::PreparationTask
        | PiClassifierError::View(_) => AnalyzerBackendError::InvalidOutput,
        PiClassifierError::Runner(_) | PiClassifierError::Proxy(_) => {
            AnalyzerBackendError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    use std::os::unix::fs::PermissionsExt;

    use crate::domain::{
        AnalyzerId, ArtifactId, CandidateId, FindingCategory, InspectionPhase, LogicalPath,
        PathSegment, RuleId, Severity,
    };
    use crate::processing::config::AnalyzerArtifactKind;
    use crate::processing::domain::{CorrelationId, Finding, FindingId, Occurrence, OccurrenceId};
    use crate::processing::executor::{ProcessingArtifact, ProcessingArtifactCatalog};
    use crate::processing::findings::NormalizedPhaseFindings;

    struct MemoryReader(BTreeMap<ArtifactId, Vec<u8>>);

    impl ProcessingArtifactReader for MemoryReader {
        fn open(
            &self,
            artifact_id: &ArtifactId,
        ) -> Result<
            Box<dyn Read + Send>,
            crate::processing::external_backend::ProcessingArtifactReadError,
        > {
            self.0
                .get(artifact_id)
                .cloned()
                .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read + Send>)
                .ok_or(
                    crate::processing::external_backend::ProcessingArtifactReadError::Unavailable,
                )
        }
    }

    fn path(value: &str) -> LogicalPath {
        LogicalPath::new(vec![PathSegment::utf8(value).unwrap()]).unwrap()
    }

    fn assignment(
        id: &str,
        bytes: &[u8],
        surface: ProcessingArtifactSurface,
    ) -> ProcessingAssignment {
        ProcessingAssignment {
            candidate_id: CandidateId::from_suffix(id).unwrap(),
            artifact_id: ArtifactId::from_suffix(id).unwrap(),
            logical_path: path(&format!("{id}.txt")),
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
    fn immutable_materialization_preserves_ids_and_exact_applicability() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let text = assignment(
            "text",
            b"password = example",
            ProcessingArtifactSurface::WorkingTree,
        );
        let binary = assignment("binary", b"a\0b", ProcessingArtifactSurface::WorkingTree);
        let reader = Arc::new(MemoryReader(BTreeMap::from([
            (text.artifact_id.clone(), b"password = example".to_vec()),
            (binary.artifact_id.clone(), b"a\0b".to_vec()),
        ])));
        let prepared = materialize_pi(MaterializePiRequest {
            root: temp.path().to_path_buf(),
            run_id: RunId::from_suffix("materialize").unwrap(),
            reader,
            assignments: vec![binary.clone(), text.clone()].into(),
            required_text: RequiredTextMatcher::default(),
            max_text_bytes: 1024,
        })
        .unwrap();
        assert_eq!(prepared.manifest.artifacts().len(), 2);
        assert_eq!(prepared.assignments[0].candidate_id, binary.candidate_id);
        assert_eq!(
            prepared.outcomes[0].disposition,
            AssignmentDisposition::NotApplicable
        );
        assert_eq!(
            prepared.outcomes[1].disposition,
            AssignmentDisposition::Completed
        );
    }

    #[test]
    fn materialization_rejects_reader_bytes_that_do_not_match_frozen_digest() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let assignment = assignment(
            "changed",
            b"expected",
            ProcessingArtifactSurface::WorkingTree,
        );
        let reader = Arc::new(MemoryReader(BTreeMap::from([(
            assignment.artifact_id.clone(),
            b"different".to_vec(),
        )])));
        assert!(materialize_pi(MaterializePiRequest {
            root: temp.path().to_path_buf(),
            run_id: RunId::from_suffix("mismatch").unwrap(),
            reader,
            assignments: vec![assignment].into(),
            required_text: RequiredTextMatcher::default(),
            max_text_bytes: 1024,
        })
        .is_err());
    }

    #[test]
    fn prior_projection_excludes_findings_outside_exact_assigned_view() {
        let assigned = assignment("assigned", b"x", ProcessingArtifactSurface::WorkingTree);
        let foreign = assignment("foreign", b"x", ProcessingArtifactSurface::WorkingTree);
        let analyzer = AnalyzerId::new("gitleaks").unwrap();
        let rule = RuleId::new("generic-password").unwrap();
        let assigned_occurrence = Occurrence {
            id: OccurrenceId::from_suffix("assigned").unwrap(),
            phase: InspectionPhase::Initial,
            analyzer_id: analyzer.clone(),
            rule_id: rule.clone(),
            artifact_id: assigned.artifact_id.clone(),
            category: FindingCategory::Credential,
            severity: Severity::High,
            location: None,
            verification_state: crate::processing::CredentialVerificationState::Unverified,
            evidence_token: Some(Digest::sha256(b"assigned")),
        };
        let foreign_occurrence = Occurrence {
            id: OccurrenceId::from_suffix("foreign").unwrap(),
            artifact_id: foreign.artifact_id.clone(),
            evidence_token: Some(Digest::sha256(b"foreign")),
            ..assigned_occurrence.clone()
        };
        let assigned_finding = Finding::new(
            FindingId::from_suffix("assigned").unwrap(),
            InspectionPhase::Initial,
            analyzer.clone(),
            rule.clone(),
            assigned.artifact_id.clone(),
            FindingCategory::Credential,
            Severity::High,
            None,
            assigned_occurrence.evidence_token,
            vec![assigned_occurrence.id.clone()],
        )
        .unwrap();
        let foreign_finding = Finding::new(
            FindingId::from_suffix("foreign").unwrap(),
            InspectionPhase::Initial,
            analyzer,
            rule,
            foreign.artifact_id,
            FindingCategory::Credential,
            Severity::High,
            None,
            foreign_occurrence.evidence_token,
            vec![foreign_occurrence.id.clone()],
        )
        .unwrap();
        let prior = NormalizedPhaseFindings {
            occurrences: vec![assigned_occurrence, foreign_occurrence],
            findings: vec![assigned_finding.clone(), foreign_finding.clone()],
            correlations: vec![
                crate::processing::Correlation::new(
                    CorrelationId::from_suffix("assigned").unwrap(),
                    InspectionPhase::Initial,
                    vec![assigned_finding.id.clone()],
                    assigned_finding.occurrence_ids.clone(),
                )
                .unwrap(),
                crate::processing::Correlation::new(
                    CorrelationId::from_suffix("foreign").unwrap(),
                    InspectionPhase::Initial,
                    vec![foreign_finding.id],
                    foreign_finding.occurrence_ids,
                )
                .unwrap(),
            ],
            observation_to_finding: BTreeMap::new(),
        };
        let projected = project_prior_findings(
            &prior,
            &BTreeSet::from([assigned.artifact_id.clone()]),
            InspectionPhase::Initial,
        )
        .unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].artifact_id, assigned.artifact_id);
    }

    #[test]
    fn review_scope_is_derived_from_exact_surfaces_and_rejects_mixed_history_scope() {
        let working = assignment("working", b"x", ProcessingArtifactSurface::WorkingTree);
        let history = |id, scope| {
            assignment(
                id,
                b"x",
                ProcessingArtifactSurface::GitHistory {
                    repository_identity: Digest::sha256(b"repo"),
                    history_scope: scope,
                    provenance: crate::processing::GitProvenance::new(
                        "sha1:0123456789012345678901234567890123456789"
                            .parse()
                            .unwrap(),
                        crate::processing::GitBlobMode::Regular,
                        vec![crate::processing::GitBlobOccurrence {
                            commit_id: "sha1:abcdefabcdefabcdefabcdefabcdefabcdefabcd"
                                .parse()
                                .unwrap(),
                            path: path("history.txt"),
                            refs: Vec::new(),
                        }],
                    )
                    .unwrap(),
                },
            )
        };
        let head = history("head", GitHistoryScope::Head);
        let scope = review_scope(&[working, head]).unwrap();
        assert!(scope.working_tree);
        assert_eq!(scope.history, GitHistoryScope::Head);
        assert!(review_scope(&[
            history("reachable", GitHistoryScope::Reachable),
            history("all", GitHistoryScope::AllRefs),
        ])
        .is_err());
    }

    #[test]
    fn assignment_surface_validation_detects_catalog_substitution() {
        let assignment = assignment("one", b"x", ProcessingArtifactSurface::WorkingTree);
        let substituted = ProcessingArtifact {
            artifact_id: assignment.artifact_id.clone(),
            logical_path: assignment.logical_path.clone(),
            kind: assignment.kind,
            byte_len: assignment.byte_len,
            content_digest: Digest::sha256(b"different"),
            surface: assignment.surface.clone(),
        };
        let invocation = AnalyzerInvocation {
            phase: InspectionPhase::Initial,
            analyzer_id: AnalyzerId::new("pi").unwrap(),
            assignments: vec![assignment].into(),
            artifacts: Arc::new(ProcessingArtifactCatalog::new(vec![substituted]).unwrap()),
            prior: Arc::new(
                crate::pipeline::PriorObservationProjection::build(
                    crate::pipeline::PriorObservationMode::None,
                    &[],
                    crate::pipeline::ProjectionLimits::new(1, 1024).unwrap(),
                )
                .unwrap(),
            ),
            prior_findings: Arc::new(NormalizedPhaseFindings {
                occurrences: Vec::new(),
                findings: Vec::new(),
                correlations: Vec::new(),
                observation_to_finding: BTreeMap::new(),
            }),
            prior_coverage: Arc::from([]),
        };
        assert_eq!(
            validate_assignment_surfaces(&invocation),
            Err(AnalyzerBackendError::InvalidOutput)
        );
    }
}
