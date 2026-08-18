//! Privacy-preserving assembly of strict processing report schema 2.
//!
//! This boundary accepts typed, normalized job state only. Host paths, remote
//! locators, native scanner output, prompts, snippets, and matched bytes have
//! no fields through which they can enter the public report.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::analyzers::external::ScannerVersion;
use crate::domain::{
    AnalyzerId, CoverageStatus, Digest, FindingCategory as DomainFindingCategory,
    InspectionPhase as DomainInspectionPhase, Severity as DomainSeverity, SubjectId,
    ValidatedLocation,
};
use crate::pipeline::StageId;
use crate::processing::completion::CompletionDisposition;
use crate::processing::config::{AnalyzerArtifactKind, PhaseExecution};
use crate::processing::domain::{
    ActionKind as DomainActionKind, Adjudication, AdjudicationReason,
    AdjudicationState as DomainAdjudicationState, CredentialVerificationState, Disposition,
    GitHistoryScope, GitObjectId as DomainGitObjectId, GitTransport as DomainGitTransport,
    HandoffStatus as DomainHandoffStatus, Outcome, PiFindingClassification, ProcessSource,
};
use crate::processing::executor::{
    AnalyzerRunRecord, AnalyzerRunState, ProcessingArtifact, ProcessingArtifactCatalog,
    ProcessingArtifactSurface, ProcessingExecutionIssueCode, ProcessingPhaseResult,
};
use crate::processing::policy::{
    CompiledPolicyDirective, ProcessingFindingResolution, ProcessingPolicyEvaluation,
};
use crate::processing::report::{
    AcquisitionStatus, AcquisitionSummary, ActionKind, ActionMode, ActionState, ActionSummary,
    AdjudicationState, AdjudicationSummary, AnalyzerRunSummary, ArtifactKind, ArtifactSummary,
    ConfiguredDisposition, CorrelationSummary, CoverageSummary, DegradationSummary,
    EffectiveDisposition, ExecutionStatus, FindingCategory, FindingSummary, FrozenRefSummary,
    GitObjectAlgorithm, GitObjectId, GitProvenanceSummary, GitTransport, HandoffStatus,
    HistoryScope, InspectionPhase, IssueSummary, OmissionSummary, PersistenceStatus,
    PhaseStatistics, PhaseSummary, PhasesSummary, PiAssessment, PiInvocationSummary,
    PolicyDirective, PolicySummary, ProcessingOutcome, ProcessingReport, ProcessingReportData,
    ProcessingStatistics, PublicationType, ReportError, ResolutionState, ResolutionSummary,
    Rfc3339Timestamp, SafeId, SafeLocation, Severity, Sha256Digest, SourceSummary, StageSummary,
    VerificationState,
};
use crate::processing::runtime::{
    CompiledProcessingRuntime, EffectiveActionMode, FrozenAnalyzer, FrozenAnalyzerImplementation,
};
use crate::processing::{ActionJournalState, ActionRecord};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionReportInput {
    pub status: AcquisitionStatus,
    pub implementation_id: String,
    pub implementation_version: String,
    pub started_at: Rfc3339Timestamp,
    pub finished_at: Rfc3339Timestamp,
    pub duration_ms: u64,
    pub source_identity: Option<Digest>,
    pub issue_codes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactPublication {
    pub publication_type: PublicationType,
    pub publication_mode: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportArtifactMetadata {
    pub artifact_id: crate::domain::ArtifactId,
    pub subject_id: SubjectId,
    pub publication: ArtifactPublication,
}

pub struct PhaseReportInput<'a> {
    pub result: &'a ProcessingPhaseResult,
    pub manifest_identity: Digest,
    pub artifacts: &'a ProcessingArtifactCatalog,
    pub artifact_metadata: &'a [ReportArtifactMetadata],
    pub policy: &'a ProcessingPolicyEvaluation,
    pub analyzer_duration_ms: &'a BTreeMap<AnalyzerId, u64>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionReportInput {
    pub outcome: Outcome,
    pub configured_disposition: CompletionDisposition,
    pub effective_disposition: Disposition,
    pub handoff: DomainHandoffStatus,
    pub sealed: bool,
    pub initial_manifest_identity: Option<Digest>,
    pub final_manifest_identity: Option<Digest>,
    pub current_manifest_identity: Option<Digest>,
    pub expires_at: Option<Rfc3339Timestamp>,
    pub quarantine_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportActionState {
    Planned,
    Started,
    Committed,
    RolledBack,
    Failed,
}

pub struct ReportActionInput<'a> {
    pub action: &'a ActionRecord,
    pub state: ReportActionState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeComponentEvent {
    pub code: String,
    pub phase: Option<DomainInspectionPhase>,
    pub component_id: Option<String>,
}

pub struct ProcessingReportBuildInput<'a> {
    pub run_id: &'a crate::domain::RunId,
    pub request_id: Option<&'a str>,
    pub runtime: Option<&'a CompiledProcessingRuntime>,
    pub source: Option<&'a ProcessSource>,
    pub acquisition: Option<&'a AcquisitionReportInput>,
    pub initial: Option<PhaseReportInput<'a>>,
    pub verification: Option<PhaseReportInput<'a>>,
    pub completion: Option<&'a CompletionReportInput>,
    pub pi_invocations: Vec<PiInvocationSummary>,
    pub adjudications: &'a [Adjudication],
    pub actions: &'a [ReportActionInput<'a>],
    pub issues: &'a [SafeComponentEvent],
    pub degradations: &'a [SafeComponentEvent],
    pub started_at: Rfc3339Timestamp,
    pub finished_at: Rfc3339Timestamp,
    pub duration_ms: u64,
    pub persistence_status: PersistenceStatus,
    pub omission_reason: Option<&'a str>,
}

#[derive(Debug, Error)]
pub enum ReportBuildError {
    #[error("processing report input is internally inconsistent")]
    InvalidInput,
    #[error("processing report contains an unsafe public identifier")]
    UnsafeIdentifier,
    #[error("processing report construction violated schema 2 invariants: {0}")]
    Report(#[from] ReportError),
}

pub fn build_processing_report(
    input: ProcessingReportBuildInput<'_>,
) -> Result<ProcessingReport, ReportBuildError> {
    let run_id = safe(input.run_id.as_str())?;
    let request_id = input.request_id.map(safe).transpose()?;
    let outcome = processing_outcome(
        input
            .completion
            .map_or(Outcome::Error, |completion| completion.outcome),
    );

    if input.persistence_status == PersistenceStatus::Unavailable
        && (input.runtime.is_some()
            || input.source.is_some()
            || input.acquisition.is_some()
            || input.initial.is_some()
            || input.verification.is_some()
            || input.completion.is_some()
            || outcome != ProcessingOutcome::Error)
    {
        return Err(ReportBuildError::InvalidInput);
    }

    let source = input.source.map(source_summary).transpose()?;
    let acquisition = input.acquisition.map(acquisition_summary).transpose()?;
    let policy = input.runtime.map(policy_summary).transpose()?;
    let initial = match (&input.initial, input.runtime) {
        (Some(phase), Some(runtime)) => Some(phase_summary(runtime, phase)?),
        (None, _) => None,
        (Some(_), None) => return Err(ReportBuildError::InvalidInput),
    };
    let verification = match (&input.verification, input.runtime) {
        (Some(phase), Some(runtime)) => Some(phase_summary(runtime, phase)?),
        (None, _) => None,
        (Some(_), None) => return Err(ReportBuildError::InvalidInput),
    };
    let disposition_override = input.completion.is_some_and(|completion| {
        !matches!(
            (
                completion.configured_disposition,
                completion.effective_disposition
            ),
            (CompletionDisposition::Retain, Disposition::Retained)
                | (CompletionDisposition::Discard, Disposition::Discarded)
                | (CompletionDisposition::Quarantine, Disposition::Quarantined)
        )
    });
    let stage =
        if source.as_ref().is_some_and(SourceSummary::has_working_tree) || disposition_override {
            input
                .completion
                .map(|completion| stage_summary(&run_id, completion))
                .transpose()?
        } else {
            None
        };

    let mut pi_invocations = input.pi_invocations;
    pi_invocations.sort_by(|left, right| left.invocation_id.cmp(&right.invocation_id));
    reject_duplicate_by(&pi_invocations, |row| &row.invocation_id)?;
    let adjudications = adjudication_summaries(input.adjudications)?;
    let actions = action_summaries(input.actions)?;
    let mut issues = component_events(input.issues)?;
    let mut degradations = degradation_events(input.degradations)?;
    append_phase_events(&input.initial, &mut issues, &mut degradations)?;
    append_phase_events(&input.verification, &mut issues, &mut degradations)?;
    canonicalize_events(&mut issues)?;
    canonicalize_degradations(&mut degradations)?;

    let phases = PhasesSummary {
        initial,
        verification,
    };
    let statistics = ProcessingStatistics {
        initial_artifacts: phases
            .initial
            .as_ref()
            .map_or(0, |phase| phase.artifacts.len() as u64),
        verification_artifacts: phases
            .verification
            .as_ref()
            .map_or(0, |phase| phase.artifacts.len() as u64),
        total_findings: phases
            .initial
            .iter()
            .chain(phases.verification.iter())
            .map(|phase| phase.findings.len() as u64)
            .sum(),
        total_actions: actions.len() as u64,
        duration_ms: input.duration_ms,
    };
    let modified = actions
        .iter()
        .any(|action| action.state == ActionState::Committed);
    ProcessingReport::new(ProcessingReportData {
        run_id,
        request_id,
        outcome,
        modified,
        started_at: input.started_at,
        finished_at: input.finished_at,
        persistence_status: input.persistence_status,
        source,
        acquisition,
        stage,
        policy,
        phases,
        pi_invocations,
        adjudications,
        actions,
        issues,
        degradations,
        statistics,
        omissions: OmissionSummary {
            details_omitted: input.omission_reason.is_some(),
            reason: input.omission_reason.map(safe).transpose()?,
        },
    })
    .map_err(ReportBuildError::Report)
}

fn safe(value: impl Into<String>) -> Result<SafeId, ReportBuildError> {
    SafeId::new(value).map_err(|_| ReportBuildError::UnsafeIdentifier)
}

fn digest(value: Digest) -> Result<Sha256Digest, ReportBuildError> {
    Sha256Digest::new(value.to_string()).map_err(ReportBuildError::Report)
}

fn processing_outcome(value: Outcome) -> ProcessingOutcome {
    match value {
        Outcome::Allow => ProcessingOutcome::Allow,
        Outcome::AllowModified => ProcessingOutcome::AllowModified,
        Outcome::Deny => ProcessingOutcome::Deny,
        Outcome::Error | Outcome::Cancelled => ProcessingOutcome::Error,
    }
}

fn source_summary(source: &ProcessSource) -> Result<SourceSummary, ReportBuildError> {
    Ok(match source {
        ProcessSource::Path { repository } => SourceSummary::Path {
            repository: repository
                .as_ref()
                .map(|repository| {
                    Ok::<_, ReportBuildError>(
                        crate::processing::report::DetectedRepositorySummary {
                            repository_id: digest(repository.repository_id)?,
                            resolved_head: git_object_id(&repository.resolved_head)?,
                            history: history_scope(repository.history),
                            frozen_refs: repository
                                .frozen_refs
                                .iter()
                                .map(|reference| {
                                    Ok(FrozenRefSummary {
                                        name: reference.name.clone(),
                                        object_id: git_object_id(&reference.object_id)?,
                                        peeled_commit_id: git_object_id(
                                            &reference.peeled_commit_id,
                                        )?,
                                    })
                                })
                                .collect::<Result<Vec<_>, ReportBuildError>>()?,
                        },
                    )
                })
                .transpose()?,
        },
        ProcessSource::Git {
            transport,
            repository_id,
            resolved_head,
            working_tree,
            history,
            frozen_refs,
        } => SourceSummary::Git {
            transport: match transport {
                DomainGitTransport::Https => GitTransport::Https,
                DomainGitTransport::Ssh => GitTransport::Ssh,
            },
            repository_id: digest(*repository_id)?,
            resolved_head: git_object_id(resolved_head)?,
            working_tree: *working_tree,
            history: history_scope(*history),
            frozen_refs: frozen_refs
                .iter()
                .map(|reference| {
                    Ok(FrozenRefSummary {
                        name: reference.name.clone(),
                        object_id: git_object_id(&reference.object_id)?,
                        peeled_commit_id: git_object_id(&reference.peeled_commit_id)?,
                    })
                })
                .collect::<Result<Vec<_>, ReportBuildError>>()?,
        },
    })
}

fn history_scope(value: GitHistoryScope) -> HistoryScope {
    match value {
        GitHistoryScope::None => HistoryScope::None,
        GitHistoryScope::Head => HistoryScope::Head,
        GitHistoryScope::Reachable => HistoryScope::Reachable,
        GitHistoryScope::AllRefs => HistoryScope::AllRefs,
    }
}

fn git_object_id(value: &DomainGitObjectId) -> Result<GitObjectId, ReportBuildError> {
    let encoded = value.to_string();
    let (algorithm, value) = encoded
        .split_once(':')
        .ok_or(ReportBuildError::InvalidInput)?;
    Ok(GitObjectId {
        algorithm: match algorithm {
            "sha1" => GitObjectAlgorithm::Sha1,
            "sha256" => GitObjectAlgorithm::Sha256,
            _ => return Err(ReportBuildError::InvalidInput),
        },
        value: value.to_owned(),
    })
}

fn acquisition_summary(
    input: &AcquisitionReportInput,
) -> Result<AcquisitionSummary, ReportBuildError> {
    let mut issue_codes = input
        .issue_codes
        .iter()
        .map(|value| safe(value.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    issue_codes.sort();
    reject_duplicate_by(&issue_codes, |value| value)?;
    Ok(AcquisitionSummary {
        status: input.status,
        implementation_id: safe(input.implementation_id.clone())?,
        implementation_version: safe(input.implementation_version.clone())?,
        started_at: input.started_at.clone(),
        finished_at: input.finished_at.clone(),
        duration_ms: input.duration_ms,
        source_identity: input.source_identity.map(digest).transpose()?,
        issue_codes,
    })
}

fn policy_summary(runtime: &CompiledProcessingRuntime) -> Result<PolicySummary, ReportBuildError> {
    Ok(PolicySummary {
        profile_id: safe(runtime.profile_id.clone())?,
        policy_identity: digest(runtime.policy_identity)?,
        pipeline_id: safe(runtime.pipeline.id.clone())?,
        pipeline_identity: digest(runtime.pipeline_identity)?,
        effective_action_mode: match runtime.action_mode {
            EffectiveActionMode::Evaluate => ActionMode::Evaluate,
            EffectiveActionMode::Apply => ActionMode::Apply,
        },
    })
}

fn stage_summary(
    run_id: &SafeId,
    input: &CompletionReportInput,
) -> Result<StageSummary, ReportBuildError> {
    let handoff_available = input.handoff == DomainHandoffStatus::Available;
    if input.handoff == DomainHandoffStatus::HandedOff {
        return Err(ReportBuildError::InvalidInput);
    }
    Ok(StageSummary {
        reference: handoff_available.then(|| run_id.clone()),
        configured_disposition: match input.configured_disposition {
            CompletionDisposition::Retain => ConfiguredDisposition::Retain,
            CompletionDisposition::Discard => ConfiguredDisposition::Discard,
            CompletionDisposition::Quarantine => ConfiguredDisposition::Quarantine,
        },
        effective_disposition: match input.effective_disposition {
            Disposition::Retained => EffectiveDisposition::Retained,
            Disposition::Discarded => EffectiveDisposition::Discarded,
            Disposition::Quarantined => EffectiveDisposition::Quarantined,
            Disposition::RetainedError => EffectiveDisposition::RetainedError,
        },
        handoff_status: if handoff_available {
            HandoffStatus::Available
        } else {
            HandoffStatus::Unavailable
        },
        sealed: input.sealed,
        initial_manifest_identity: input.initial_manifest_identity.map(digest).transpose()?,
        final_manifest_identity: input.final_manifest_identity.map(digest).transpose()?,
        current_manifest_identity: input.current_manifest_identity.map(digest).transpose()?,
        expires_at: input.expires_at.clone(),
        quarantine_id: input.quarantine_id.clone().map(safe).transpose()?,
    })
}

fn phase_summary(
    runtime: &CompiledProcessingRuntime,
    input: &PhaseReportInput<'_>,
) -> Result<PhaseSummary, ReportBuildError> {
    let phase = inspection_phase(input.result.phase);
    let artifacts = artifact_summaries(input.artifacts, input.artifact_metadata)?;
    let analyzer_map = runtime
        .pipeline
        .stages
        .iter()
        .flat_map(|stage| {
            stage
                .analyzers
                .iter()
                .map(move |analyzer| (stage.id.clone(), analyzer))
        })
        .map(|(stage, analyzer)| (analyzer.id.clone(), (stage, analyzer)))
        .collect::<BTreeMap<_, _>>();
    let run_ids = input
        .result
        .analyzer_runs
        .iter()
        .map(|run| run.analyzer_id.clone())
        .collect::<BTreeSet<_>>();
    if run_ids.len() != input.result.analyzer_runs.len()
        || input
            .analyzer_duration_ms
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != run_ids
    {
        return Err(ReportBuildError::InvalidInput);
    }
    let mut analyzer_runs = input
        .result
        .analyzer_runs
        .iter()
        .map(|run| {
            let (stage, analyzer) = analyzer_map
                .get(&run.analyzer_id)
                .ok_or(ReportBuildError::InvalidInput)?;
            analyzer_run_summary(
                run,
                stage,
                analyzer,
                *input
                    .analyzer_duration_ms
                    .get(&run.analyzer_id)
                    .ok_or(ReportBuildError::InvalidInput)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    analyzer_runs.sort_by(|left, right| left.analyzer_id.cmp(&right.analyzer_id));
    reject_duplicate_by(&analyzer_runs, |row| &row.analyzer_id)?;
    let mut coverage = input
        .result
        .coverage
        .iter()
        .map(|row| {
            if row.phase != input.result.phase {
                return Err(ReportBuildError::InvalidInput);
            }
            Ok(CoverageSummary {
                analyzer_id: safe(row.analyzer_id.as_str())?,
                eligible: row.eligible,
                assigned: row.assigned,
                completed: row.completed,
                not_applicable: row.not_applicable,
                status: match row.status {
                    CoverageStatus::Complete => ExecutionStatus::Complete,
                    CoverageStatus::Incomplete => ExecutionStatus::Incomplete,
                },
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    coverage.sort_by(|left, right| left.analyzer_id.cmp(&right.analyzer_id));
    reject_duplicate_by(&coverage, |row| &row.analyzer_id)?;

    let mut occurrence_to_finding = BTreeMap::new();
    for finding in &input.result.findings {
        for occurrence in &finding.occurrence_ids {
            if occurrence_to_finding
                .insert(occurrence.clone(), finding.id.clone())
                .is_some()
            {
                return Err(ReportBuildError::InvalidInput);
            }
        }
    }
    let mut occurrences = input
        .result
        .occurrences
        .iter()
        .map(|occurrence| {
            Ok(crate::processing::report::OccurrenceSummary {
                occurrence_id: safe(occurrence.id.as_str())?,
                finding_id: safe(
                    occurrence_to_finding
                        .get(&occurrence.id)
                        .ok_or(ReportBuildError::InvalidInput)?
                        .as_str(),
                )?,
                analyzer_id: safe(occurrence.analyzer_id.as_str())?,
                rule_id: safe(occurrence.rule_id.as_str())?,
                artifact_id: safe(occurrence.artifact_id.as_str())?,
                location: safe_location(occurrence.location.as_ref()),
                verification_state: verification_state(occurrence.verification_state),
                evidence_token: occurrence.evidence_token.map(digest).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, ReportBuildError>>()?;
    occurrences.sort_by(|left, right| left.occurrence_id.cmp(&right.occurrence_id));
    reject_duplicate_by(&occurrences, |row| &row.occurrence_id)?;
    let mut findings = input
        .result
        .findings
        .iter()
        .map(|finding| {
            let mut occurrence_ids = finding
                .occurrence_ids
                .iter()
                .map(|id| safe(id.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            occurrence_ids.sort();
            Ok(FindingSummary {
                finding_id: safe(finding.id.as_str())?,
                artifact_id: safe(finding.artifact_id.as_str())?,
                category: finding_category(finding.category),
                severity: severity(finding.severity),
                occurrence_ids,
            })
        })
        .collect::<Result<Vec<_>, ReportBuildError>>()?;
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    reject_duplicate_by(&findings, |row| &row.finding_id)?;
    let mut correlations = input
        .result
        .correlations
        .iter()
        .map(|correlation| {
            let mut finding_ids = correlation
                .finding_ids
                .iter()
                .map(|id| safe(id.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            finding_ids.sort();
            Ok(CorrelationSummary {
                correlation_id: safe(correlation.id.as_str())?,
                finding_ids,
            })
        })
        .collect::<Result<Vec<_>, ReportBuildError>>()?;
    correlations.sort_by(|left, right| left.correlation_id.cmp(&right.correlation_id));
    reject_duplicate_by(&correlations, |row| &row.correlation_id)?;
    let resolutions = resolution_summaries(&input.policy.resolutions)?;
    Ok(PhaseSummary {
        phase,
        manifest_identity: digest(input.manifest_identity)?,
        source_scope_identity: digest(runtime.source_scope_identity)?,
        pipeline_identity: digest(runtime.pipeline_identity)?,
        statistics: PhaseStatistics {
            artifacts: artifacts.len() as u64,
            analyzer_runs: analyzer_runs.len() as u64,
            occurrences: occurrences.len() as u64,
            findings: findings.len() as u64,
            correlations: correlations.len() as u64,
            resolutions: resolutions.len() as u64,
            duration_ms: input.duration_ms,
        },
        artifacts,
        analyzer_runs,
        coverage,
        occurrences,
        findings,
        correlations,
        resolutions,
    })
}

fn analyzer_run_summary(
    run: &AnalyzerRunRecord,
    expected_stage: &StageId,
    analyzer: &FrozenAnalyzer,
    duration_ms: u64,
) -> Result<AnalyzerRunSummary, ReportBuildError> {
    if run.stage_id != expected_stage.as_str() {
        return Err(ReportBuildError::InvalidInput);
    }
    let (adapter_id, executable_basename, executable_identity, rules_identity) =
        match &analyzer.implementation {
            FrozenAnalyzerImplementation::Builtin(_) => (
                Some(safe("builtin_rules")?),
                None,
                None,
                Some(digest(analyzer.identity)?),
            ),
            FrozenAnalyzerImplementation::External(external) => (
                Some(safe(external.kind.executable_name())?),
                Some(safe(external.kind.executable_name())?),
                Some(digest(external.executable.identity().digest)?),
                Some(digest(analyzer.identity)?),
            ),
            FrozenAnalyzerImplementation::Pi(_) => (
                Some(safe("pi_classifier")?),
                None,
                None,
                Some(digest(analyzer.identity)?),
            ),
        };
    Ok(AnalyzerRunSummary {
        analyzer_id: safe(run.analyzer_id.as_str())?,
        adapter_id,
        executable_basename,
        version: run.scanner_version.map(scanner_version).transpose()?,
        executable_identity,
        rules_identity,
        required: run.execution == PhaseExecution::Required,
        status: match run.state {
            AnalyzerRunState::Complete => ExecutionStatus::Complete,
            AnalyzerRunState::AdvisoryFailed
            | AnalyzerRunState::RequiredFailed
            | AnalyzerRunState::Cancelled => ExecutionStatus::Incomplete,
            AnalyzerRunState::Disabled | AnalyzerRunState::Skipped => ExecutionStatus::NotRun,
        },
        duration_ms,
    })
}

fn scanner_version(value: ScannerVersion) -> Result<SafeId, ReportBuildError> {
    safe(value.to_string())
}

fn artifact_summaries(
    catalog: &ProcessingArtifactCatalog,
    metadata: &[ReportArtifactMetadata],
) -> Result<Vec<ArtifactSummary>, ReportBuildError> {
    let mut metadata_by_id = BTreeMap::new();
    for value in metadata {
        if metadata_by_id
            .insert(value.artifact_id.clone(), value)
            .is_some()
        {
            return Err(ReportBuildError::InvalidInput);
        }
    }
    if metadata_by_id.len() != catalog.artifacts().len() {
        return Err(ReportBuildError::InvalidInput);
    }
    let mut output = catalog
        .artifacts()
        .iter()
        .map(|artifact| artifact_summary(artifact, &metadata_by_id))
        .collect::<Result<Vec<_>, _>>()?;
    output.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    reject_duplicate_by(&output, |row| &row.artifact_id)?;
    Ok(output)
}

fn artifact_summary(
    artifact: &ProcessingArtifact,
    metadata: &BTreeMap<crate::domain::ArtifactId, &ReportArtifactMetadata>,
) -> Result<ArtifactSummary, ReportBuildError> {
    let metadata = metadata
        .get(&artifact.artifact_id)
        .ok_or(ReportBuildError::InvalidInput)?;
    let (kind, git) = match (&artifact.kind, &artifact.surface) {
        (AnalyzerArtifactKind::PhysicalFile, ProcessingArtifactSurface::WorkingTree) => {
            if metadata.publication.publication_type == PublicationType::Nonphysical {
                return Err(ReportBuildError::InvalidInput);
            }
            (ArtifactKind::PhysicalFile, None)
        }
        (
            AnalyzerArtifactKind::RepositoryBlob,
            ProcessingArtifactSurface::GitHistory {
                repository_identity,
                provenance,
                ..
            },
        ) => {
            if metadata.publication.publication_type != PublicationType::Nonphysical
                || metadata.publication.publication_mode.is_some()
            {
                return Err(ReportBuildError::InvalidInput);
            }
            (
                ArtifactKind::RepositoryBlob,
                Some(GitProvenanceSummary {
                    repository_id: digest(*repository_identity)?,
                    blob_id: git_object_id(&provenance.blob_id)?,
                    occurrence_count: provenance.occurrences.len() as u64,
                }),
            )
        }
        _ => return Err(ReportBuildError::InvalidInput),
    };
    Ok(ArtifactSummary {
        artifact_id: safe(artifact.artifact_id.as_str())?,
        subject_id: safe(metadata.subject_id.as_str())?,
        kind,
        logical_path: artifact.logical_path.clone(),
        byte_len: artifact.byte_len,
        publication_type: metadata.publication.publication_type,
        publication_mode: metadata.publication.publication_mode,
        git,
    })
}

fn resolution_summaries(
    resolutions: &[ProcessingFindingResolution],
) -> Result<Vec<ResolutionSummary>, ReportBuildError> {
    let mut output = resolutions
        .iter()
        .map(|resolution| {
            let action = &resolution.action_resolution;
            Ok(ResolutionSummary {
                finding_id: safe(action.finding_id.as_str())?,
                binding_id: safe(action.binding_id.as_str())?,
                directive: match action.directive {
                    crate::policy::PolicyDirective::Audit => PolicyDirective::Audit,
                    crate::policy::PolicyDirective::Deny => PolicyDirective::Deny,
                    crate::policy::PolicyDirective::Delete => PolicyDirective::Delete,
                    crate::policy::PolicyDirective::Quarantine => PolicyDirective::Quarantine,
                },
                state: match action.state {
                    crate::processing::actions::plan::ResolutionState::Active => {
                        ResolutionState::Active
                    }
                    crate::processing::actions::plan::ResolutionState::Cleared => {
                        ResolutionState::Cleared
                    }
                },
                reason_code: safe(
                    if action.state == crate::processing::actions::plan::ResolutionState::Cleared {
                        "pi_false_positive_clearance"
                    } else if resolution.matched_default {
                        "default_unbound"
                    } else if resolution.configured_directive == CompiledPolicyDirective::Adjudicate
                    {
                        "adjudication_required"
                    } else {
                        "matched_binding"
                    },
                )?,
            })
        })
        .collect::<Result<Vec<_>, ReportBuildError>>()?;
    output.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    reject_duplicate_by(&output, |row| &row.finding_id)?;
    Ok(output)
}

fn adjudication_summaries(
    values: &[Adjudication],
) -> Result<Vec<AdjudicationSummary>, ReportBuildError> {
    let mut output = values
        .iter()
        .map(|value| {
            Ok(AdjudicationSummary {
                finding_id: safe(value.finding_id.as_str())?,
                phase: inspection_phase(value.phase),
                assessment: value.assessment.as_ref().map_or(
                    PiAssessment::UnableToAssess,
                    |assessment| match assessment.classification {
                        PiFindingClassification::Confirmed => PiAssessment::Confirmed,
                        PiFindingClassification::LikelyTruePositive => {
                            PiAssessment::LikelyTruePositive
                        }
                        PiFindingClassification::LikelyFalsePositive => {
                            PiAssessment::LikelyFalsePositive
                        }
                        PiFindingClassification::FalsePositive => PiAssessment::FalsePositive,
                        PiFindingClassification::Uncertain => PiAssessment::Uncertain,
                        PiFindingClassification::UnableToAssess => PiAssessment::UnableToAssess,
                    },
                ),
                state: match value.state {
                    DomainAdjudicationState::NotRequested => AdjudicationState::NotRequested,
                    DomainAdjudicationState::Advisory => AdjudicationState::Advisory,
                    DomainAdjudicationState::Applied => AdjudicationState::Applied,
                    DomainAdjudicationState::Rejected => AdjudicationState::Rejected,
                },
                reason_code: safe(adjudication_reason(value.reason))?,
            })
        })
        .collect::<Result<Vec<_>, ReportBuildError>>()?;
    output.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    reject_duplicate_by(&output, |row| &row.finding_id)?;
    Ok(output)
}

fn adjudication_reason(value: AdjudicationReason) -> &'static str {
    match value {
        AdjudicationReason::NotConfigured => "not_configured",
        AdjudicationReason::AdvisoryOnly => "advisory_only",
        AdjudicationReason::ClearedFalsePositive => "cleared_false_positive",
        AdjudicationReason::AssessmentNotFalsePositive => "assessment_not_false_positive",
        AdjudicationReason::CorrelationNotCleared => "correlation_not_cleared",
        AdjudicationReason::IncompleteRequiredAnalysis => "incomplete_required_analysis",
    }
}

fn action_summaries(
    values: &[ReportActionInput<'_>],
) -> Result<Vec<ActionSummary>, ReportBuildError> {
    let mut output = values
        .iter()
        .map(|value| {
            if value.action.planned_state != ActionJournalState::Planned {
                return Err(ReportBuildError::InvalidInput);
            }
            let mut finding_ids = value
                .action
                .finding_ids
                .iter()
                .map(|id| safe(id.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            finding_ids.sort();
            let mut binding_ids = value
                .action
                .binding_ids
                .iter()
                .map(|id| safe(id.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            binding_ids.sort();
            Ok(ActionSummary {
                action_id: safe(value.action.id.as_str())?,
                kind: match value.action.kind {
                    DomainActionKind::Delete => ActionKind::Delete,
                    DomainActionKind::Quarantine => ActionKind::Quarantine,
                },
                subject_id: safe(value.action.subject_id.as_str())?,
                finding_ids,
                binding_ids,
                state: match value.state {
                    ReportActionState::Planned => ActionState::Planned,
                    ReportActionState::Started => ActionState::Started,
                    ReportActionState::Committed => ActionState::Committed,
                    ReportActionState::RolledBack => ActionState::RolledBack,
                    ReportActionState::Failed => ActionState::Failed,
                },
                artifact_quarantine_id: value
                    .action
                    .artifact_quarantine_id
                    .as_ref()
                    .map(|id| safe(id.as_str()))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, ReportBuildError>>()?;
    output.sort_by(|left, right| left.action_id.cmp(&right.action_id));
    reject_duplicate_by(&output, |row| &row.action_id)?;
    Ok(output)
}

fn append_phase_events(
    phase: &Option<PhaseReportInput<'_>>,
    issues: &mut Vec<IssueSummary>,
    degradations: &mut Vec<DegradationSummary>,
) -> Result<(), ReportBuildError> {
    let Some(phase) = phase else { return Ok(()) };
    for event in &phase.result.issues {
        let code = safe(execution_issue_code(event.code))?;
        let component_id = event
            .analyzer_id
            .as_ref()
            .map(|id| safe(id.as_str()))
            .transpose()?;
        if event.required {
            issues.push(IssueSummary {
                code,
                phase: Some(inspection_phase(phase.result.phase)),
                component_id,
            });
        } else {
            degradations.push(DegradationSummary {
                code,
                phase: Some(inspection_phase(phase.result.phase)),
                component_id,
            });
        }
    }
    Ok(())
}

fn execution_issue_code(value: ProcessingExecutionIssueCode) -> &'static str {
    match value {
        ProcessingExecutionIssueCode::AssignmentConstruction => "assignment_construction",
        ProcessingExecutionIssueCode::InvalidBackendOutput => "invalid_backend_output",
        ProcessingExecutionIssueCode::BackendUnavailable => "backend_unavailable",
        ProcessingExecutionIssueCode::BackendBudgetExceeded => "backend_budget_exceeded",
        ProcessingExecutionIssueCode::Cancelled => "cancelled",
        ProcessingExecutionIssueCode::PriorProjectionLimit => "prior_projection_limit",
    }
}

fn component_events(values: &[SafeComponentEvent]) -> Result<Vec<IssueSummary>, ReportBuildError> {
    values
        .iter()
        .map(|value| {
            Ok(IssueSummary {
                code: safe(value.code.clone())?,
                phase: value.phase.map(inspection_phase),
                component_id: value.component_id.clone().map(safe).transpose()?,
            })
        })
        .collect()
}

fn degradation_events(
    values: &[SafeComponentEvent],
) -> Result<Vec<DegradationSummary>, ReportBuildError> {
    values
        .iter()
        .map(|value| {
            Ok(DegradationSummary {
                code: safe(value.code.clone())?,
                phase: value.phase.map(inspection_phase),
                component_id: value.component_id.clone().map(safe).transpose()?,
            })
        })
        .collect()
}

fn canonicalize_events(values: &mut [IssueSummary]) -> Result<(), ReportBuildError> {
    values.sort_by(|left, right| left.code.cmp(&right.code));
    reject_duplicate_by(values, |row| &row.code)
}

fn canonicalize_degradations(values: &mut [DegradationSummary]) -> Result<(), ReportBuildError> {
    values.sort_by(|left, right| left.code.cmp(&right.code));
    reject_duplicate_by(values, |row| &row.code)
}

fn reject_duplicate_by<T, K: Ord + ?Sized>(
    values: &[T],
    key: impl Fn(&T) -> &K,
) -> Result<(), ReportBuildError> {
    if values.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
        Err(ReportBuildError::InvalidInput)
    } else {
        Ok(())
    }
}

fn inspection_phase(value: DomainInspectionPhase) -> InspectionPhase {
    match value {
        DomainInspectionPhase::Initial => InspectionPhase::Initial,
        DomainInspectionPhase::Verification => InspectionPhase::Verification,
    }
}

fn safe_location(value: Option<&ValidatedLocation>) -> Option<SafeLocation> {
    match value {
        Some(ValidatedLocation::Line { line }) => Some(SafeLocation {
            line: *line,
            column: None,
        }),
        Some(ValidatedLocation::LineColumn { line, column }) => Some(SafeLocation {
            line: *line,
            column: Some(*column),
        }),
        Some(ValidatedLocation::ByteRange { .. }) | None => None,
    }
}

fn verification_state(value: CredentialVerificationState) -> VerificationState {
    match value {
        CredentialVerificationState::NotApplicable => VerificationState::NotSupported,
        CredentialVerificationState::Unverified => VerificationState::Unverified,
        CredentialVerificationState::Verified => VerificationState::Verified,
        CredentialVerificationState::VerificationError => VerificationState::VerificationError,
    }
}

fn finding_category(value: DomainFindingCategory) -> FindingCategory {
    match value {
        DomainFindingCategory::Secret => FindingCategory::Secret,
        DomainFindingCategory::Credential => FindingCategory::Credential,
        DomainFindingCategory::SensitiveContent => FindingCategory::SensitiveContent,
        DomainFindingCategory::KnownSensitiveFile => FindingCategory::KnownSensitiveFile,
        DomainFindingCategory::Filename => FindingCategory::Filename,
        DomainFindingCategory::ContentPattern => FindingCategory::ContentPattern,
        DomainFindingCategory::PolicyViolation => FindingCategory::PolicyViolation,
    }
}

fn severity(value: DomainSeverity) -> Severity {
    match value {
        DomainSeverity::Informational => Severity::Informational,
        DomainSeverity::Low => Severity::Low,
        DomainSeverity::Medium => Severity::Medium,
        DomainSeverity::High => Severity::High,
        DomainSeverity::Critical => Severity::Critical,
    }
}
