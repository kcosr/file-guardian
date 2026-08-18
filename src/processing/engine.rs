//! End-state schema-3 processing engine.
//!
//! The engine owns a frozen runtime, creates the durable job lease, acquires
//! into the job-owned stage, and coordinates immutable analysis through the
//! schema-3 processing contracts. Private source paths and remote locators
//! never enter its public result.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::Arc;
use std::time::Duration;

use crate::analyzers::external::ScannerCancellation;
use crate::analyzers::pi::triage::PriorFinding;
use crate::authorization::{CaptureLimits as SnapshotCaptureLimits, InvocationWorkspace};
use crate::domain::Digest;
use crate::domain::InspectionPhase;
use crate::processing::acquisition::git::{
    acquire_remote_repository_source, enumerate_local_repository, FrozenGitRepository,
    GitAcquisitionSummary, GitCommandLimits, GitCommandRunner, GitEnumerationLimits,
    GitEnumerationRequest, RemoteLocator, SanitizedGitEnvironment,
};
use crate::processing::acquisition::local::{
    acquire_local, capture_owned_stage, AcquisitionCancellation, LocalAcquisitionRequest,
    LocalAcquisitionResult,
};
use crate::processing::actions::plan::{
    build_action_plan, ActionPlan, ActionPlanOutcome, StageSubject,
};
use crate::processing::adjudication::{
    adjudicate_pi, AdjudicationDecision, AnalysisIntegrity, PiAnalysis,
};
use crate::processing::builtin_backend::CapturedBuiltinProcessingBackend;
use crate::processing::catalog::{
    capture_processing_catalog, CapturedProcessingCatalog, GitHistoryCatalogInput,
    ProcessingCatalogCaptureRequest, WorkingTreeCatalogInput,
};
use crate::processing::completion::{
    finalize_job, revalidate_and_seal, CompletionDisposition, FinalizeRequest,
};
use crate::processing::config::CaptureLimits;
use crate::processing::domain::{
    ActionJournalState, ActionRecord, Disposition, HandoffStatus, JobExecutionState, Outcome,
    ProcessSource,
};
use crate::processing::executor::{
    ProcessingArtifactSurface, ProcessingBackends, ProcessingExecutionContext,
    ProcessingPhaseExecutor, ProcessingPhaseResult,
};
use crate::processing::external_backend::{
    ConfinedExternalProcessingBackend, ProcessingArtifactReader,
};
use crate::processing::findings::JobCorrelationKey;
use crate::processing::job::{
    system_time_unix_millis, DecisionDisposition, DecisionDispositions, JobPaths, JobStore,
    LeaseIdentity, PrivateDecisionRecord,
};
use crate::processing::pi_backend::{ConfinedPiProcessingBackend, PiProcessingContext};
use crate::processing::policy::{
    evaluate_processing_policy, FindingSurface, PolicyFindingInput, ProcessingPolicyDecision,
    ProcessingPolicyEvaluation,
};
use crate::processing::report::{
    AcquisitionStatus, PersistenceStatus, PiInvocationSummary, ProcessingReport, PublicationType,
    Rfc3339Timestamp,
};
use crate::processing::report_builder::{
    build_processing_report, AcquisitionReportInput, CompletionReportInput, PhaseReportInput,
    ProcessingReportBuildInput, ReportActionInput, ReportActionState, SafeComponentEvent,
};
use crate::processing::runtime::{CompiledProcessingRuntime, FrozenSourceRequest};
use crate::processing::FindingId;

#[derive(Debug, thiserror::Error)]
pub enum ProcessingEngineError {
    #[error("processing source acquisition failed")]
    Acquisition,
    #[error("processing source acquisition was cancelled")]
    Cancelled,
    #[error("acquired processing source was internally inconsistent")]
    InvalidAcquisition,
    #[error("immutable processing catalog capture failed")]
    Catalog,
    #[error("processing analyzer runtime could not be prepared")]
    Backend,
    #[error("required processing analysis failed")]
    Analysis,
    #[error("processing policy resolution failed")]
    Policy,
    #[error("the remediated stage failed required verification")]
    Verification,
    #[error("Pi adjudication failed closed")]
    Adjudication,
    #[error("durable processing job state failed")]
    Job,
    #[error("processing action transaction failed")]
    Action,
    #[error("processing report construction failed")]
    Report,
    #[error("processing completion failed")]
    Completion,
}

/// Owned, path-free acquisition result consumed by catalog capture. The
/// frozen runtime remains the sole owner of private source inputs.
pub struct AcquiredProcessingSource {
    pub source: ProcessSource,
    pub publication_stage: LocalAcquisitionResult,
    pub analyze_working_tree: bool,
    pub repository: Option<FrozenGitRepository>,
    pub git_summary: Option<GitAcquisitionSummary>,
    pub implementation_id: &'static str,
    pub implementation_version: String,
}

/// Replaces the working-tree acquisition proof after committed actions. Git
/// history remains the originally frozen immutable surface.
pub fn recapture_processing_source(
    runtime: &CompiledProcessingRuntime,
    paths: &JobPaths,
    mut acquired: AcquiredProcessingSource,
    cancellation: &AcquisitionCancellation,
) -> Result<AcquiredProcessingSource, ProcessingEngineError> {
    let limits = acquisition_capture_limits(runtime)?;
    let current = capture_owned_stage(
        &paths.stage(),
        &runtime.jobs.jobs_root,
        &limits,
        crate::processing::config::SymlinkPolicy::Preserve,
        cancellation,
    )
    .map_err(map_local_error)?;
    acquired.publication_stage = current;
    Ok(acquired)
}

pub struct CapturedPhase {
    pub catalog: CapturedProcessingCatalog,
    pub result: ProcessingPhaseResult,
}

pub struct ProcessingEngineRequest {
    pub request_id: Option<String>,
}

pub struct ProcessingEngine {
    runtime: Arc<CompiledProcessingRuntime>,
    store: Arc<JobStore>,
    lease_identity: LeaseIdentity,
    cancellation: AcquisitionCancellation,
}

impl ProcessingEngine {
    pub fn new(
        runtime: Arc<CompiledProcessingRuntime>,
        store: Arc<JobStore>,
        lease_identity: LeaseIdentity,
        cancellation: AcquisitionCancellation,
    ) -> Result<Self, ProcessingEngineError> {
        if store.paths().jobs_root != runtime.jobs.jobs_root
            || store.paths().reports_root != runtime.jobs.reports_root
            || store.paths().quarantine_root != runtime.jobs.quarantine_root
        {
            return Err(ProcessingEngineError::Job);
        }
        Ok(Self {
            runtime,
            store,
            lease_identity,
            cancellation,
        })
    }

    pub async fn process(
        &self,
        request: ProcessingEngineRequest,
    ) -> Result<ProcessingReport, ProcessingEngineError> {
        let request_id = request.request_id.clone();
        match self.process_transaction(request).await {
            Ok(report) => Ok(report),
            Err(error) => match self.store.try_acquire(&self.runtime.run_id) {
                Ok(lease) => self.finalize_error(lease, request_id.as_deref(), &error),
                Err(_) => Err(error),
            },
        }
    }

    async fn process_transaction(
        &self,
        request: ProcessingEngineRequest,
    ) -> Result<ProcessingReport, ProcessingEngineError> {
        let started_at = timestamp_now()?;
        let started_millis = system_time_unix_millis().map_err(|_| ProcessingEngineError::Job)?;
        let mut lease = self
            .store
            .create(
                &self.runtime.run_id,
                self.lease_identity.clone(),
                started_millis,
            )
            .map_err(|_| ProcessingEngineError::Job)?;
        transition(&mut lease, JobExecutionState::Acquiring)?;
        let acquisition_started = timestamp_now()?;
        let acquired =
            acquire_processing_source(&self.runtime, lease.paths(), &self.cancellation).await?;
        let acquisition_finished = timestamp_now()?;
        transition(&mut lease, JobExecutionState::Acquired)?;
        transition(&mut lease, JobExecutionState::BaselineCaptured)?;
        transition(&mut lease, JobExecutionState::AnalyzingInitial)?;
        let correlation_key = random_correlation_key()?;
        let initial = execute_captured_phase(
            &self.runtime,
            lease.paths(),
            &acquired,
            InspectionPhase::Initial,
            correlation_key.clone(),
        )
        .await?;
        transition(&mut lease, JobExecutionState::ResolvingInitial)?;
        let (initial_policy, initial_adjudication) = resolve_phase(&self.runtime, &initial, false)?;
        let initial_publication_identity = publication_manifest_identity(&acquired)?;

        let mut actions = Vec::new();
        let mut verification = None;
        let mut verification_policy = None;
        let mut adjudications = initial_adjudication.adjudications;
        let mut terminal_issues = Vec::new();
        let (outcome, acquired, final_manifest_identity, effective_disposition_override) =
            match initial_policy.decision {
                ProcessingPolicyDecision::Allow => {
                    let manifest = publication_manifest_identity(&acquired)?;
                    (Outcome::Allow, acquired, manifest, None)
                }
                ProcessingPolicyDecision::Deny => {
                    let manifest = publication_manifest_identity(&acquired)?;
                    (Outcome::Deny, acquired, manifest, None)
                }
                ProcessingPolicyDecision::RequiresMutation
                    if self.runtime.action_mode
                        == crate::processing::runtime::EffectiveActionMode::Evaluate =>
                {
                    let manifest = publication_manifest_identity(&acquired)?;
                    (Outcome::Deny, acquired, manifest, None)
                }
                ProcessingPolicyDecision::RequiresMutation => {
                    transition(&mut lease, JobExecutionState::PlanningActions)?;
                    let subjects = stage_subjects(&initial)?;
                    let plan = match build_action_plan(
                        initial_publication_identity,
                        &subjects,
                        &initial.result.findings,
                        &initial_policy.action_resolutions(),
                    )
                    .map_err(|_| ProcessingEngineError::Action)?
                    {
                        ActionPlanOutcome::Planned(plan) => plan,
                        ActionPlanOutcome::NoActions
                        | ActionPlanOutcome::SuppressedByDeny { .. } => {
                            return Err(ProcessingEngineError::Action)
                        }
                    };
                    transition(&mut lease, JobExecutionState::ApplyingActions)?;
                    let action_paths = prepare_action_paths(lease.paths())?;
                    let prover = OwnedStageManifestProver {
                        runtime: &self.runtime,
                        cancellation: &self.cancellation,
                    };
                    crate::processing::actions::executor::execute_actions(
                        crate::processing::actions::executor::ActionExecutionRequest {
                            stage_root: &lease.paths().stage(),
                            trash_root: &action_paths.trash,
                            artifact_quarantine_root: &self.runtime.jobs.artifact_quarantine_root,
                            journal_path: &action_paths.journal,
                            plan: &plan,
                            cancellation: &self.cancellation,
                            manifest_prover: &prover,
                            faults: &crate::processing::actions::executor::NoActionFaults,
                        },
                    )
                    .map_err(|_| ProcessingEngineError::Action)?;
                    actions = action_records(&plan)?;
                    transition(&mut lease, JobExecutionState::CapturingVerification)?;
                    let acquired = recapture_processing_source(
                        &self.runtime,
                        lease.paths(),
                        acquired,
                        &self.cancellation,
                    )?;
                    let final_manifest = publication_manifest_identity(&acquired)?;
                    append_verification_started(&action_paths.journal, final_manifest)?;
                    transition(&mut lease, JobExecutionState::AnalyzingVerification)?;
                    let verified = execute_captured_phase(
                        &self.runtime,
                        lease.paths(),
                        &acquired,
                        InspectionPhase::Verification,
                        correlation_key,
                    )
                    .await?;
                    transition(&mut lease, JobExecutionState::ResolvingVerification)?;
                    let (resolved, adjudicated) = resolve_phase(&self.runtime, &verified, true)?;
                    adjudications.extend(adjudicated.adjudications);
                    if resolved.decision != ProcessingPolicyDecision::Allow {
                        append_verification_rejected(&action_paths.journal, final_manifest)?;
                        terminal_issues.push(SafeComponentEvent {
                            code: error_code(&ProcessingEngineError::Verification).to_owned(),
                            phase: Some(InspectionPhase::Verification),
                            component_id: None,
                        });
                        verification_policy = Some(resolved);
                        verification = Some(verified);
                        (
                            Outcome::Error,
                            acquired,
                            final_manifest,
                            Some(CompletionDisposition::Quarantine),
                        )
                    } else {
                        append_action_commit(&action_paths.journal, final_manifest)?;
                        crate::processing::actions::executor::cleanup_committed_actions(
                            crate::processing::actions::executor::CommittedCleanupRequest {
                                stage_root: &lease.paths().stage(),
                                trash_root: &action_paths.trash,
                                artifact_quarantine_root: &self
                                    .runtime
                                    .jobs
                                    .artifact_quarantine_root,
                                journal_path: &action_paths.journal,
                                plan: &plan,
                                faults: &crate::processing::actions::executor::NoActionFaults,
                            },
                        )
                        .map_err(|_| ProcessingEngineError::Action)?;
                        verification_policy = Some(resolved);
                        verification = Some(verified);
                        (Outcome::AllowModified, acquired, final_manifest, None)
                    }
                }
            };

        transition(&mut lease, JobExecutionState::RevalidatingFinal)?;
        let initial_manifest_identity = initial_publication_identity;
        let has_reported_stage = acquired.analyze_working_tree;
        let sealed = if outcome.is_allowed() && has_reported_stage {
            transition(&mut lease, JobExecutionState::Sealing)?;
            Some(
                revalidate_and_seal(
                    &lease.paths().stage(),
                    &acquired.publication_stage.entries,
                    final_manifest_identity,
                    &self.cancellation,
                )
                .map_err(|_| ProcessingEngineError::Completion)?,
            )
        } else {
            None
        };
        let configured = configured_disposition(&self.runtime, outcome);
        let effective_completion = effective_disposition_override.unwrap_or(configured);
        let completion = has_reported_stage
            .then(|| {
                completion_input(
                    outcome,
                    configured,
                    effective_completion,
                    initial_manifest_identity,
                    final_manifest_identity,
                    sealed.is_some(),
                    &self.runtime,
                )
            })
            .transpose()?;
        let acquisition = acquisition_report(&acquired, acquisition_started, acquisition_finished)?;
        let finished_at = timestamp_now()?;
        let action_inputs = actions
            .iter()
            .map(|action| ReportActionInput {
                action,
                state: ReportActionState::Committed,
            })
            .collect::<Vec<_>>();
        let initial_durations = analyzer_durations(&initial);
        let verification_durations = verification.as_ref().map(analyzer_durations);
        let pi_invocations =
            pi_invocation_summaries(&self.runtime, &initial, verification.as_ref(), &finished_at)?;
        let report = build_processing_report(ProcessingReportBuildInput {
            run_id: &self.runtime.run_id,
            request_id: request.request_id.as_deref(),
            runtime: Some(&self.runtime),
            source: Some(&acquired.source),
            acquisition: Some(&acquisition),
            initial: Some(PhaseReportInput {
                result: &initial.result,
                manifest_identity: initial.catalog.snapshot_identity,
                artifacts: &initial.catalog.artifacts,
                artifact_metadata: &initial.catalog.report_metadata,
                policy: &initial_policy,
                analyzer_duration_ms: &initial_durations,
                duration_ms: 0,
            }),
            verification: verification.as_ref().map(|phase| PhaseReportInput {
                result: &phase.result,
                manifest_identity: phase.catalog.snapshot_identity,
                artifacts: &phase.catalog.artifacts,
                artifact_metadata: &phase.catalog.report_metadata,
                policy: verification_policy
                    .as_ref()
                    .expect("verification policy set"),
                analyzer_duration_ms: verification_durations
                    .as_ref()
                    .expect("verification durations set"),
                duration_ms: 0,
            }),
            completion: completion.as_ref(),
            pi_invocations,
            adjudications: &adjudications,
            actions: &action_inputs,
            issues: &terminal_issues,
            degradations: &[],
            started_at,
            finished_at,
            duration_ms: u64::try_from(
                system_time_unix_millis()
                    .map_err(|_| ProcessingEngineError::Job)?
                    .saturating_sub(started_millis),
            )
            .unwrap_or(0),
            persistence_status: PersistenceStatus::Durable,
            omission_reason: None,
        })
        .map_err(|_| ProcessingEngineError::Report)?;
        let report_bytes = report
            .to_json_line()
            .map_err(|_| ProcessingEngineError::Report)?;
        let report_identity = Digest::sha256(&report_bytes);
        let evidence_identity = Digest::sha256(
            serde_json::to_vec(&(
                initial_policy.action_resolutions(),
                verification_policy
                    .as_ref()
                    .map(ProcessingPolicyEvaluation::action_resolutions),
                &adjudications,
            ))
            .map_err(|_| ProcessingEngineError::Report)?,
        );
        let decision = PrivateDecisionRecord::new(
            self.runtime.run_id.clone(),
            outcome,
            has_reported_stage.then_some(final_manifest_identity),
            Some(evidence_identity),
            DecisionDispositions::new(
                outcome,
                decision_disposition(configured),
                decision_disposition(effective_completion),
            )
            .map_err(|_| ProcessingEngineError::Job)?,
            report_identity,
            serde_json::to_value(&report).map_err(|_| ProcessingEngineError::Report)?,
        )
        .map_err(|_| ProcessingEngineError::Job)?;
        finalize_job(
            &self.store,
            &mut lease,
            FinalizeRequest {
                decision: &decision,
                report: &report,
                configured_disposition: configured,
                effective_disposition: effective_completion,
                sealed_stage: sealed.as_ref(),
                now_unix_millis: system_time_unix_millis()
                    .map_err(|_| ProcessingEngineError::Job)?,
            },
        )
        .map_err(|_| ProcessingEngineError::Completion)?;
        Ok(report)
    }

    fn finalize_error(
        &self,
        mut lease: crate::processing::job::JobLease,
        request_id: Option<&str>,
        error: &ProcessingEngineError,
    ) -> Result<ProcessingReport, ProcessingEngineError> {
        let now = timestamp_now()?;
        let proposed = if matches!(error, ProcessingEngineError::Cancelled) {
            Outcome::Cancelled
        } else {
            Outcome::Error
        };
        let configured = configured_disposition(&self.runtime, proposed);
        let action_recovery = self.recover_error_actions(&lease);
        let force_quarantine = action_recovery.force_quarantine;
        let effective_completion = if force_quarantine {
            CompletionDisposition::Quarantine
        } else {
            configured
        };
        let effective = match effective_completion {
            CompletionDisposition::Retain => Disposition::Retained,
            CompletionDisposition::Discard => Disposition::Discarded,
            CompletionDisposition::Quarantine => Disposition::Quarantined,
        };
        let completion = CompletionReportInput {
            outcome: proposed,
            configured_disposition: configured,
            effective_disposition: effective,
            handoff: HandoffStatus::Unavailable,
            sealed: false,
            initial_manifest_identity: None,
            final_manifest_identity: None,
            current_manifest_identity: None,
            expires_at: None,
            quarantine_id: (effective_completion == CompletionDisposition::Quarantine)
                .then(|| self.runtime.run_id.as_str().to_owned()),
        };
        let issues = [SafeComponentEvent {
            code: error_code(error).to_owned(),
            phase: None,
            component_id: None,
        }];
        let action_inputs = action_recovery
            .records
            .iter()
            .zip(&action_recovery.states)
            .map(|(action, state)| ReportActionInput {
                action,
                state: *state,
            })
            .collect::<Vec<_>>();
        let report = build_processing_report(ProcessingReportBuildInput {
            run_id: &self.runtime.run_id,
            request_id,
            runtime: Some(&self.runtime),
            source: None,
            acquisition: None,
            initial: None,
            verification: None,
            completion: Some(&completion),
            pi_invocations: Vec::new(),
            adjudications: &[],
            actions: &action_inputs,
            issues: &issues,
            degradations: &[],
            started_at: now.clone(),
            finished_at: now,
            duration_ms: 0,
            persistence_status: PersistenceStatus::Durable,
            omission_reason: Some(if action_recovery.details_omitted {
                "action_failure_details_withheld"
            } else {
                "failure_details_withheld"
            }),
        })
        .map_err(|_| ProcessingEngineError::Report)?;
        let identity = Digest::sha256(
            report
                .to_json_line()
                .map_err(|_| ProcessingEngineError::Report)?,
        );
        let decision = PrivateDecisionRecord::new(
            self.runtime.run_id.clone(),
            proposed,
            None,
            None,
            DecisionDispositions::new(
                proposed,
                decision_disposition(configured),
                decision_disposition(effective_completion),
            )
            .map_err(|_| ProcessingEngineError::Job)?,
            identity,
            serde_json::to_value(&report).map_err(|_| ProcessingEngineError::Report)?,
        )
        .map_err(|_| ProcessingEngineError::Job)?;
        finalize_job(
            &self.store,
            &mut lease,
            FinalizeRequest {
                decision: &decision,
                report: &report,
                configured_disposition: configured,
                effective_disposition: effective_completion,
                sealed_stage: None,
                now_unix_millis: system_time_unix_millis()
                    .map_err(|_| ProcessingEngineError::Job)?,
            },
        )
        .map_err(|_| ProcessingEngineError::Completion)?;
        Ok(report)
    }

    fn recover_error_actions(
        &self,
        lease: &crate::processing::job::JobLease,
    ) -> ErrorActionRecovery {
        let journal = lease.paths().action_journal().join("transaction.journal");
        let in_action_state = matches!(
            lease.state().execution,
            JobExecutionState::ApplyingActions
                | JobExecutionState::CapturingVerification
                | JobExecutionState::AnalyzingVerification
                | JobExecutionState::ResolvingVerification
        );
        let after_possible_committed_action = matches!(
            lease.state().execution,
            JobExecutionState::RevalidatingFinal | JobExecutionState::Sealing
        ) && journal.exists();
        if !in_action_state && !after_possible_committed_action {
            return ErrorActionRecovery::none();
        }
        let parsed = match crate::processing::actions::journal::read_journal(&journal) {
            Ok(parsed) if !parsed.incomplete_tail => parsed,
            _ => return ErrorActionRecovery::ambiguous(),
        };
        let plan = match parsed.records.first().map(|record| &record.event) {
            Some(crate::processing::actions::journal::JournalEvent::PlanPrepared { plan }) => plan,
            _ => return ErrorActionRecovery::ambiguous(),
        };
        let records = match action_records(plan) {
            Ok(records) => records,
            Err(_) => return ErrorActionRecovery::ambiguous(),
        };
        let trash = lease.paths().temporary().join("action-trash");
        let prover = OwnedStageManifestProver {
            runtime: &self.runtime,
            cancellation: &self.cancellation,
        };
        match crate::processing::actions::executor::recover_actions(
            crate::processing::actions::executor::ActionRecoveryRequest {
                stage_root: &lease.paths().stage(),
                trash_root: &trash,
                artifact_quarantine_root: &self.runtime.jobs.artifact_quarantine_root,
                journal_path: &journal,
                plan,
                manifest_prover: &prover,
                faults: &crate::processing::actions::executor::NoActionFaults,
            },
        ) {
            Ok(
                crate::processing::actions::executor::RecoveredActionTransaction::UnchangedProven { .. }
                | crate::processing::actions::executor::RecoveredActionTransaction::RolledBackProven { .. },
            ) => ErrorActionRecovery {
                force_quarantine: false,
                states: vec![ReportActionState::RolledBack; records.len()],
                records,
                details_omitted: false,
            },
            Ok(
                crate::processing::actions::executor::RecoveredActionTransaction::AlreadyCommitted { .. }
                | crate::processing::actions::executor::RecoveredActionTransaction::VerificationStagePreserved { .. },
            ) => ErrorActionRecovery {
                force_quarantine: true,
                states: vec![ReportActionState::Committed; records.len()],
                records,
                details_omitted: false,
            },
            Err(_) => ErrorActionRecovery {
                force_quarantine: true,
                states: vec![ReportActionState::Failed; records.len()],
                records,
                details_omitted: true,
            },
        }
    }
}

struct ErrorActionRecovery {
    force_quarantine: bool,
    records: Vec<ActionRecord>,
    states: Vec<ReportActionState>,
    details_omitted: bool,
}

impl ErrorActionRecovery {
    fn none() -> Self {
        Self {
            force_quarantine: false,
            records: Vec::new(),
            states: Vec::new(),
            details_omitted: false,
        }
    }

    fn ambiguous() -> Self {
        Self {
            force_quarantine: true,
            records: Vec::new(),
            states: Vec::new(),
            details_omitted: true,
        }
    }
}

pub fn evaluate_phase_policy(
    runtime: &CompiledProcessingRuntime,
    phase: &CapturedPhase,
    cleared_finding_ids: &BTreeSet<FindingId>,
) -> Result<ProcessingPolicyEvaluation, ProcessingEngineError> {
    if !phase.result.required_complete {
        return Err(ProcessingEngineError::Analysis);
    }
    let artifacts = phase
        .catalog
        .artifacts
        .artifacts()
        .iter()
        .map(|artifact| (artifact.artifact_id.clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    let publication = phase
        .catalog
        .report_metadata
        .iter()
        .map(|metadata| {
            (
                metadata.artifact_id.clone(),
                metadata.publication.publication_type,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let occurrences = phase
        .result
        .occurrences
        .iter()
        .map(|occurrence| (occurrence.id.clone(), occurrence))
        .collect::<BTreeMap<_, _>>();
    let grouped = phase
        .result
        .findings
        .iter()
        .map(|finding| {
            finding
                .occurrence_ids
                .iter()
                .map(|id| {
                    occurrences
                        .get(id)
                        .map(|value| (*value).clone())
                        .ok_or(ProcessingEngineError::Policy)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inputs = phase
        .result
        .findings
        .iter()
        .zip(&grouped)
        .map(|(finding, occurrences)| {
            let artifact = artifacts
                .get(&finding.artifact_id)
                .ok_or(ProcessingEngineError::Policy)?;
            let surface = match &artifact.surface {
                ProcessingArtifactSurface::GitHistory { .. } => FindingSurface::RepositoryBlob,
                ProcessingArtifactSurface::WorkingTree => match publication
                    .get(&finding.artifact_id)
                    .ok_or(ProcessingEngineError::Policy)?
                {
                    PublicationType::RegularFile => FindingSurface::MutablePhysicalRegularFile,
                    PublicationType::Symlink => FindingSurface::PhysicalSymlink,
                    PublicationType::Nonphysical => return Err(ProcessingEngineError::Policy),
                },
            };
            Ok(PolicyFindingInput {
                finding,
                occurrences,
                surface,
            })
        })
        .collect::<Result<Vec<_>, ProcessingEngineError>>()?;
    evaluate_processing_policy(&runtime.policy, &inputs, cleared_finding_ids)
        .map_err(|_| ProcessingEngineError::Policy)
}

pub fn adjudicate_phase(
    runtime: &CompiledProcessingRuntime,
    phase: &CapturedPhase,
    preliminary: &ProcessingPolicyEvaluation,
    after_actions: bool,
) -> Result<AdjudicationDecision, ProcessingEngineError> {
    let analysis = match phase.result.pi_results.as_slice() {
        [] => PiAnalysis::NotRun,
        [result] => PiAnalysis::Complete(&result.analysis),
        _ => return Err(ProcessingEngineError::Adjudication),
    };
    let findings: &[PriorFinding] = match &analysis {
        PiAnalysis::Complete(analysis) => &analysis.request().findings,
        PiAnalysis::NotRun | PiAnalysis::Failed => &[],
    };
    let blocking_finding_ids = preliminary
        .resolutions
        .iter()
        .filter(|resolution| {
            resolution.action_resolution.state
                == crate::processing::actions::plan::ResolutionState::Active
                && resolution.action_resolution.directive != crate::policy::PolicyDirective::Audit
        })
        .map(|resolution| &resolution.action_resolution.finding_id)
        .collect::<BTreeSet<_>>();
    let blocking_occurrence_ids = findings
        .iter()
        .filter(|finding| blocking_finding_ids.contains(&finding.finding_id))
        .flat_map(|finding| {
            finding
                .occurrences
                .iter()
                .map(|occurrence| occurrence.occurrence_id.clone())
        })
        .collect::<BTreeSet<_>>();
    adjudicate_pi(
        runtime.pi_adjudication.as_ref(),
        phase.result.phase,
        findings,
        &blocking_occurrence_ids,
        analysis,
        if after_actions {
            AnalysisIntegrity::complete_after_actions()
        } else {
            AnalysisIntegrity::complete_unchanged()
        },
    )
    .map_err(|_| ProcessingEngineError::Adjudication)
}

pub fn resolve_phase(
    runtime: &CompiledProcessingRuntime,
    phase: &CapturedPhase,
    after_actions: bool,
) -> Result<(ProcessingPolicyEvaluation, AdjudicationDecision), ProcessingEngineError> {
    let preliminary = evaluate_phase_policy(runtime, phase, &BTreeSet::new())?;
    let adjudication = adjudicate_phase(runtime, phase, &preliminary, after_actions)?;
    let mut resolved = evaluate_phase_policy(runtime, phase, &adjudication.cleared_finding_ids)?;
    if adjudication.stage_attestation
        == Some(crate::analyzers::pi::triage::PiStageAttestation::BlockingConcernsObserved)
    {
        resolved.decision = ProcessingPolicyDecision::Deny;
    }
    Ok((resolved, adjudication))
}

pub fn stage_subjects(phase: &CapturedPhase) -> Result<Vec<StageSubject>, ProcessingEngineError> {
    let metadata = phase
        .catalog
        .report_metadata
        .iter()
        .map(|value| (value.artifact_id.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let manifest_artifacts = phase
        .catalog
        .builtin_manifest
        .artifacts()
        .iter()
        .map(|value| (value.id.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let manifest_subjects = phase
        .catalog
        .builtin_manifest
        .subjects()
        .iter()
        .map(|value| (value.id.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let mut output = phase
        .catalog
        .artifacts
        .artifacts()
        .iter()
        .map(|artifact| {
            let metadata = metadata
                .get(&artifact.artifact_id)
                .ok_or(ProcessingEngineError::Policy)?;
            match metadata.publication.publication_type {
                PublicationType::RegularFile => {
                    let manifest_artifact = manifest_artifacts
                        .get(&artifact.artifact_id)
                        .ok_or(ProcessingEngineError::Policy)?;
                    let subject = manifest_subjects
                        .get(&manifest_artifact.subject_id)
                        .ok_or(ProcessingEngineError::Policy)?;
                    StageSubject::mutable_regular_file(
                        artifact.artifact_id.clone(),
                        metadata.subject_id.clone(),
                        artifact.logical_path.clone(),
                        subject.source_identity.clone(),
                    )
                    .map_err(|_| ProcessingEngineError::Policy)
                }
                PublicationType::Symlink => Ok(StageSubject::physical_symlink(
                    artifact.artifact_id.clone(),
                    metadata.subject_id.clone(),
                    artifact.logical_path.clone(),
                    artifact.byte_len,
                    artifact.content_digest,
                )),
                PublicationType::Nonphysical => Ok(StageSubject::nonphysical(
                    artifact.artifact_id.clone(),
                    metadata.subject_id.clone(),
                    artifact.logical_path.clone(),
                    artifact.byte_len,
                    artifact.content_digest,
                )),
            }
        })
        .collect::<Result<Vec<_>, ProcessingEngineError>>()?;
    output.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(output)
}

/// Captures and executes one complete phase against only immutable objects.
/// A fresh call with a fresh workspace is required after any stage mutation.
pub async fn execute_captured_phase(
    runtime: &CompiledProcessingRuntime,
    paths: &JobPaths,
    acquired: &AcquiredProcessingSource,
    phase: InspectionPhase,
    correlation_key: JobCorrelationKey,
) -> Result<CapturedPhase, ProcessingEngineError> {
    let capture_root = private_subdirectory(
        &paths.temporary(),
        match phase {
            InspectionPhase::Initial => "initial-capture",
            InspectionPhase::Verification => "verification-capture",
        },
    )?;
    let workspace = Arc::new(
        InvocationWorkspace::create(&capture_root, &runtime.run_id)
            .map_err(|_| ProcessingEngineError::Catalog)?,
    );
    let stage = paths.stage();
    let working_tree = acquired
        .analyze_working_tree
        .then_some(WorkingTreeCatalogInput {
            stage: &stage,
            jobs_root: &runtime.jobs.jobs_root,
            acquisition: &acquired.publication_stage,
        });
    let git_history = acquired
        .repository
        .as_ref()
        .filter(|_| runtime.source_scope.history != crate::processing::GitHistoryScope::None)
        .map(|repository| GitHistoryCatalogInput {
            repository,
            scope: runtime.source_scope.history,
        });
    let catalog = capture_processing_catalog(
        workspace,
        ProcessingCatalogCaptureRequest {
            working_tree,
            git_history,
            capture_limits: snapshot_capture_limits(runtime)?,
        },
    )
    .map_err(|_| ProcessingEngineError::Catalog)?;

    let external_root = private_subdirectory(
        &paths.temporary(),
        match phase {
            InspectionPhase::Initial => "initial-external",
            InspectionPhase::Verification => "verification-external",
        },
    )?;
    let pi_root = private_subdirectory(
        &paths.temporary(),
        match phase {
            InspectionPhase::Initial => "initial-pi",
            InspectionPhase::Verification => "verification-pi",
        },
    )?;
    let builtin = CapturedBuiltinProcessingBackend::new(Arc::clone(&catalog.reader));
    let processing_reader: Arc<dyn ProcessingArtifactReader> = catalog.reader.clone();
    let external = ConfinedExternalProcessingBackend::new(
        external_root,
        Arc::clone(&processing_reader),
        ScannerCancellation::default(),
    )
    .map_err(|_| ProcessingEngineError::Backend)?;
    let pi = ConfinedPiProcessingBackend::new(
        pi_root,
        processing_reader,
        PiProcessingContext {
            run_id: runtime.run_id.clone(),
            pipeline_identity: runtime.pipeline_identity,
            policy_identity: runtime.policy_identity,
            stage_root: stage.clone(),
        },
    )
    .map_err(|_| ProcessingEngineError::Backend)?;
    let context = ProcessingExecutionContext {
        run_id: runtime.run_id.clone(),
        snapshot_identity: catalog.snapshot_identity,
        pipeline_identity: runtime.pipeline_identity,
        policy_identity: runtime.policy_identity,
        correlation_key,
    };
    let result = ProcessingPhaseExecutor::execute(
        &runtime.pipeline,
        phase,
        &context,
        Arc::clone(&catalog.artifacts),
        ProcessingBackends {
            builtin: &builtin,
            external: &external,
            pi: &pi,
        },
    )
    .await
    .map_err(|_| ProcessingEngineError::Analysis)?;
    Ok(CapturedPhase { catalog, result })
}

pub async fn acquire_processing_source(
    runtime: &CompiledProcessingRuntime,
    paths: &JobPaths,
    cancellation: &AcquisitionCancellation,
) -> Result<AcquiredProcessingSource, ProcessingEngineError> {
    check_cancelled(cancellation)?;
    let limits = acquisition_capture_limits(runtime)?;
    let acquired = match &runtime.source {
        FrozenSourceRequest::Path { path } => {
            if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
                return Err(ProcessingEngineError::InvalidAcquisition);
            }
            let result = acquire_local(LocalAcquisitionRequest {
                source: path,
                stage: &paths.stage(),
                jobs_root: &runtime.jobs.jobs_root,
                limits: &limits,
                symlinks: crate::processing::config::SymlinkPolicy::Preserve,
                cancellation,
            })
            .map_err(map_local_error)?;
            let repository = if fs::symlink_metadata(paths.stage().join(".git"))
                .is_ok_and(|metadata| metadata.is_dir())
            {
                let runner = git_runner(runtime)?;
                let request = git_enumeration_request(runtime, None);
                Some(
                    enumerate_local_repository(&runner, &paths.stage(), &request)
                        .await
                        .map_err(map_git_error)?,
                )
            } else {
                None
            };
            if repository.is_none()
                && runtime.source_scope.history != crate::processing::GitHistoryScope::None
            {
                return Err(ProcessingEngineError::InvalidAcquisition);
            }
            let source = repository
                .as_ref()
                .map_or_else(
                    || Ok(ProcessSource::path()),
                    |repository| {
                        ProcessSource::path_repository(
                            repository.repository_identity,
                            repository.resolved_head.clone(),
                            runtime.source_scope.history,
                            repository.frozen_refs.clone(),
                        )
                    },
                )
                .map_err(|_| ProcessingEngineError::InvalidAcquisition)?;
            let git_summary = repository.as_ref().map(|repository| GitAcquisitionSummary {
                transport: None,
                repository_identity: repository.repository_identity,
                object_format: repository.object_format.clone(),
                resolved_head: repository.resolved_head.clone(),
                frozen_ref_count: repository.frozen_refs.len() as u64,
                commit_count: repository.commits.len() as u64,
                history_blob_count: repository.blobs.len() as u64,
                working_tree_manifest_identity: Some(result.manifest_identity),
                working_tree_statistics: Some(result.statistics),
            });
            AcquiredProcessingSource {
                source,
                publication_stage: result,
                analyze_working_tree: true,
                repository,
                git_summary,
                implementation_id: "local_copy",
                implementation_version: "1".to_owned(),
            }
        }
        FrozenSourceRequest::Git {
            remote,
            transport,
            checkout_ref,
        } => {
            let runner = git_runner(runtime)?;
            let locator = RemoteLocator::parse(remote).map_err(map_git_error)?;
            if locator.transport() != *transport {
                return Err(ProcessingEngineError::InvalidAcquisition);
            }
            let request = git_enumeration_request(runtime, checkout_ref.clone());
            let result = acquire_remote_repository_source(
                &runner,
                &locator,
                &request,
                &paths.stage(),
                &limits,
                crate::processing::config::SymlinkPolicy::Preserve,
                cancellation,
            )
            .await
            .map_err(map_git_error)?;
            check_cancelled(cancellation)?;
            let source = ProcessSource::git(
                *transport,
                result.repository.repository_identity,
                result.repository.resolved_head.clone(),
                runtime.source_scope.working_tree,
                runtime.source_scope.history,
                result.repository.frozen_refs.clone(),
            )
            .map_err(|_| ProcessingEngineError::InvalidAcquisition)?;
            let summary = result.summary;
            AcquiredProcessingSource {
                source,
                publication_stage: result.working_tree,
                analyze_working_tree: runtime.source_scope.working_tree,
                repository: Some(result.repository),
                git_summary: Some(summary),
                implementation_id: "remote_git",
                implementation_version: runner.identity().digest.to_string(),
            }
        }
    };
    check_cancelled(cancellation)?;
    Ok(acquired)
}

fn acquisition_capture_limits(
    runtime: &CompiledProcessingRuntime,
) -> Result<CaptureLimits, ProcessingEngineError> {
    let capture = runtime.jobs.capture;
    Ok(CaptureLimits {
        max_entries: capture.max_entries,
        max_files: capture.max_files,
        max_file_bytes: capture.max_file_bytes,
        max_total_bytes: capture.max_total_bytes,
        max_depth: capture.max_depth,
    })
}

pub fn snapshot_capture_limits(
    runtime: &CompiledProcessingRuntime,
) -> Result<SnapshotCaptureLimits, ProcessingEngineError> {
    let capture = runtime.jobs.capture;
    Ok(SnapshotCaptureLimits {
        max_depth: capture.max_depth,
        max_entries: capture.max_entries,
        max_files: capture.max_files,
        max_total_bytes: capture.max_total_bytes,
        max_file_bytes: capture.max_file_bytes,
    })
}

fn git_runner(
    runtime: &CompiledProcessingRuntime,
) -> Result<GitCommandRunner, ProcessingEngineError> {
    let environment =
        SanitizedGitEnvironment::from_current_authentication().map_err(map_git_error)?;
    GitCommandRunner::new(
        runtime.acquisition.git_executable.clone(),
        GitCommandLimits {
            wall_timeout: Duration::from_secs(runtime.acquisition.git_timeout_secs),
            max_stdout_bytes: runtime.acquisition.max_stdout_bytes,
            max_stderr_bytes: runtime.acquisition.max_stderr_bytes,
        },
        environment,
    )
    .map_err(map_git_error)
}

fn git_enumeration_request(
    runtime: &CompiledProcessingRuntime,
    checkout_ref: Option<String>,
) -> GitEnumerationRequest {
    GitEnumerationRequest {
        history: runtime.source_scope.history,
        history_ref_patterns: runtime.source_scope.history_ref_patterns.clone(),
        checkout_ref,
        allowed_checkout_ref_patterns: runtime
            .git_constraints
            .allowed_checkout_ref_patterns
            .clone(),
        limits: GitEnumerationLimits {
            max_refs: runtime.acquisition.max_refs,
            max_commits: runtime.acquisition.max_commits,
            max_unique_blobs: runtime.acquisition.max_unique_blobs,
            max_provenance_occurrences: runtime.acquisition.max_provenance_occurrences,
            max_git_bytes: runtime.acquisition.max_git_bytes,
        },
    }
}

fn private_subdirectory(
    parent: &std::path::Path,
    name: &str,
) -> Result<std::path::PathBuf, ProcessingEngineError> {
    let path = parent.join(name);
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&path)
        .map_err(|_| ProcessingEngineError::Backend)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| ProcessingEngineError::Backend)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProcessingEngineError::Backend);
    }
    Ok(path)
}

struct ActionPaths {
    trash: std::path::PathBuf,
    journal: std::path::PathBuf,
}

fn prepare_action_paths(paths: &JobPaths) -> Result<ActionPaths, ProcessingEngineError> {
    let trash = private_subdirectory(&paths.temporary(), "action-trash")?;
    Ok(ActionPaths {
        trash,
        journal: paths.action_journal().join("transaction.journal"),
    })
}

struct OwnedStageManifestProver<'a> {
    runtime: &'a CompiledProcessingRuntime,
    cancellation: &'a AcquisitionCancellation,
}

impl crate::processing::actions::executor::StageManifestProver for OwnedStageManifestProver<'_> {
    fn capture_manifest(
        &self,
        stage_root: &std::path::Path,
    ) -> Result<Digest, crate::processing::actions::executor::StageManifestProofError> {
        let limits = acquisition_capture_limits(self.runtime)
            .map_err(|_| crate::processing::actions::executor::StageManifestProofError)?;
        capture_owned_stage(
            stage_root,
            &self.runtime.jobs.jobs_root,
            &limits,
            crate::processing::config::SymlinkPolicy::Preserve,
            self.cancellation,
        )
        .map(|value| value.manifest_identity)
        .map_err(|_| crate::processing::actions::executor::StageManifestProofError)
    }
}

fn action_records(plan: &ActionPlan) -> Result<Vec<ActionRecord>, ProcessingEngineError> {
    plan.actions
        .iter()
        .map(|action| {
            ActionRecord::new(
                action.id.clone(),
                action.kind,
                action.target.subject_id.clone(),
                action.finding_ids.clone(),
                action.binding_ids.clone(),
                ActionJournalState::Planned,
                Some(ActionJournalState::Fsynced),
                action.artifact_quarantine_id.clone(),
            )
            .map_err(|_| ProcessingEngineError::Action)
        })
        .collect()
}

fn append_verification_started(
    journal: &std::path::Path,
    manifest: Digest,
) -> Result<(), ProcessingEngineError> {
    let mut writer = crate::processing::actions::journal::ActionJournalWriter::open_append(journal)
        .map_err(|_| ProcessingEngineError::Action)?;
    writer
        .append_and_sync(
            &crate::processing::actions::journal::JournalEvent::VerificationStarted {
                manifest_identity: manifest,
            },
        )
        .map_err(|_| ProcessingEngineError::Action)?;
    Ok(())
}

fn append_action_commit(
    journal: &std::path::Path,
    manifest: Digest,
) -> Result<(), ProcessingEngineError> {
    use crate::processing::actions::journal::{
        ActionJournalWriter, JournalEvent, VerificationDecision,
    };
    let mut writer =
        ActionJournalWriter::open_append(journal).map_err(|_| ProcessingEngineError::Action)?;
    writer
        .append_and_sync(&JournalEvent::VerificationCompleted {
            manifest_identity: manifest,
            decision: VerificationDecision::Allow,
        })
        .map_err(|_| ProcessingEngineError::Action)?;
    writer
        .append_and_sync(&JournalEvent::DecisionPrepared {
            outcome: Outcome::AllowModified,
            current_manifest_identity: Some(manifest),
        })
        .map_err(|_| ProcessingEngineError::Action)?;
    writer
        .append_and_sync(&JournalEvent::TransactionCommitted {
            final_manifest_identity: manifest,
        })
        .map_err(|_| ProcessingEngineError::Action)?;
    Ok(())
}

fn append_verification_rejected(
    journal: &std::path::Path,
    manifest: Digest,
) -> Result<(), ProcessingEngineError> {
    use crate::processing::actions::journal::{
        ActionJournalWriter, JournalEvent, JournalFailureCode, VerificationDecision,
    };
    let mut writer =
        ActionJournalWriter::open_append(journal).map_err(|_| ProcessingEngineError::Action)?;
    writer
        .append_and_sync(&JournalEvent::VerificationCompleted {
            manifest_identity: manifest,
            decision: VerificationDecision::Reject,
        })
        .map_err(|_| ProcessingEngineError::Action)?;
    writer
        .append_and_sync(&JournalEvent::FailureRecorded {
            action_id: None,
            code: JournalFailureCode::VerificationFailed,
        })
        .map_err(|_| ProcessingEngineError::Action)?;
    Ok(())
}

fn publication_manifest_identity(
    acquired: &AcquiredProcessingSource,
) -> Result<Digest, ProcessingEngineError> {
    Ok(acquired.publication_stage.manifest_identity)
}

fn configured_disposition(
    runtime: &CompiledProcessingRuntime,
    outcome: Outcome,
) -> CompletionDisposition {
    let configured = match outcome {
        Outcome::Allow => runtime.completion.allow,
        Outcome::AllowModified => runtime.completion.allow_modified,
        Outcome::Deny => runtime.completion.deny,
        Outcome::Error => runtime.completion.error,
        Outcome::Cancelled => runtime.completion.cancelled,
    };
    match configured {
        crate::processing::config::CompletionDisposition::Retain => CompletionDisposition::Retain,
        crate::processing::config::CompletionDisposition::Discard => CompletionDisposition::Discard,
        crate::processing::config::CompletionDisposition::Quarantine => {
            CompletionDisposition::Quarantine
        }
    }
}

const fn decision_disposition(value: CompletionDisposition) -> DecisionDisposition {
    match value {
        CompletionDisposition::Retain => DecisionDisposition::Retain,
        CompletionDisposition::Discard => DecisionDisposition::Discard,
        CompletionDisposition::Quarantine => DecisionDisposition::Quarantine,
    }
}

fn completion_input(
    outcome: Outcome,
    configured: CompletionDisposition,
    effective: CompletionDisposition,
    initial: Digest,
    final_identity: Digest,
    sealed: bool,
    runtime: &CompiledProcessingRuntime,
) -> Result<CompletionReportInput, ProcessingEngineError> {
    let effective_disposition = match effective {
        CompletionDisposition::Retain => Disposition::Retained,
        CompletionDisposition::Discard => Disposition::Discarded,
        CompletionDisposition::Quarantine => Disposition::Quarantined,
    };
    let available = outcome.is_allowed() && effective == CompletionDisposition::Retain;
    Ok(CompletionReportInput {
        outcome,
        configured_disposition: configured,
        effective_disposition,
        handoff: if available {
            HandoffStatus::Available
        } else {
            HandoffStatus::Unavailable
        },
        sealed,
        initial_manifest_identity: Some(initial),
        final_manifest_identity: Some(final_identity),
        current_manifest_identity: Some(final_identity),
        expires_at: available
            .then(|| {
                let seconds = i64::try_from(runtime.jobs.retention.available_ttl_secs)
                    .map_err(|_| ProcessingEngineError::Report)?;
                timestamp_from(chrono::Utc::now() + chrono::Duration::seconds(seconds))
            })
            .transpose()?,
        quarantine_id: (effective == CompletionDisposition::Quarantine)
            .then(|| runtime.run_id.as_str().to_owned()),
    })
}

fn acquisition_report(
    acquired: &AcquiredProcessingSource,
    started_at: Rfc3339Timestamp,
    finished_at: Rfc3339Timestamp,
) -> Result<AcquisitionReportInput, ProcessingEngineError> {
    let source_identity = match &acquired.source {
        ProcessSource::Path {
            repository: Some(repository),
            ..
        } => Some(repository.repository_id),
        ProcessSource::Path {
            repository: None, ..
        } => Some(acquired.publication_stage.manifest_identity),
        ProcessSource::Git { repository_id, .. } => Some(*repository_id),
    };
    Ok(AcquisitionReportInput {
        status: AcquisitionStatus::Complete,
        implementation_id: acquired.implementation_id.to_owned(),
        implementation_version: acquired.implementation_version.clone(),
        started_at,
        finished_at,
        duration_ms: 0,
        source_identity,
        issue_codes: Vec::new(),
    })
}

fn analyzer_durations(phase: &CapturedPhase) -> BTreeMap<crate::domain::AnalyzerId, u64> {
    phase
        .result
        .analyzer_runs
        .iter()
        .map(|run| (run.analyzer_id.clone(), 0))
        .collect()
}

fn pi_invocation_summaries(
    runtime: &CompiledProcessingRuntime,
    initial: &CapturedPhase,
    verification: Option<&CapturedPhase>,
    at: &Rfc3339Timestamp,
) -> Result<Vec<PiInvocationSummary>, ProcessingEngineError> {
    initial
        .result
        .pi_results
        .iter()
        .chain(
            verification
                .into_iter()
                .flat_map(|phase| phase.result.pi_results.iter()),
        )
        .map(|result| {
            crate::processing::pi_report::pi_invocation_summary(
                runtime,
                result,
                at.clone(),
                at.clone(),
            )
            .map_err(|_| ProcessingEngineError::Report)
        })
        .collect()
}

fn timestamp_now() -> Result<Rfc3339Timestamp, ProcessingEngineError> {
    timestamp_from(chrono::Utc::now())
}

fn timestamp_from(
    value: chrono::DateTime<chrono::Utc>,
) -> Result<Rfc3339Timestamp, ProcessingEngineError> {
    Rfc3339Timestamp::new(value.to_rfc3339()).map_err(|_| ProcessingEngineError::Report)
}

fn random_correlation_key() -> Result<JobCorrelationKey, ProcessingEngineError> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| ProcessingEngineError::Job)?;
    Ok(JobCorrelationKey::from_bytes(bytes))
}

fn transition(
    lease: &mut crate::processing::job::JobLease,
    state: JobExecutionState,
) -> Result<(), ProcessingEngineError> {
    lease
        .transition(
            state,
            system_time_unix_millis().map_err(|_| ProcessingEngineError::Job)?,
        )
        .map_err(|_| ProcessingEngineError::Job)
}

fn check_cancelled(cancellation: &AcquisitionCancellation) -> Result<(), ProcessingEngineError> {
    if cancellation.is_cancelled() {
        Err(ProcessingEngineError::Cancelled)
    } else {
        Ok(())
    }
}

const fn error_code(error: &ProcessingEngineError) -> &'static str {
    match error {
        ProcessingEngineError::Acquisition => "acquisition_failed",
        ProcessingEngineError::Cancelled => "cancelled",
        ProcessingEngineError::InvalidAcquisition => "invalid_acquisition",
        ProcessingEngineError::Catalog => "catalog_capture_failed",
        ProcessingEngineError::Backend => "analyzer_backend_failed",
        ProcessingEngineError::Analysis => "required_analysis_failed",
        ProcessingEngineError::Policy => "policy_resolution_failed",
        ProcessingEngineError::Verification => "verification_failed",
        ProcessingEngineError::Adjudication => "pi_adjudication_failed",
        ProcessingEngineError::Job => "job_state_failed",
        ProcessingEngineError::Action => "action_transaction_failed",
        ProcessingEngineError::Report => "report_construction_failed",
        ProcessingEngineError::Completion => "completion_failed",
    }
}

fn map_local_error(
    error: crate::processing::acquisition::local::LocalAcquisitionError,
) -> ProcessingEngineError {
    if matches!(
        error,
        crate::processing::acquisition::local::LocalAcquisitionError::Cancelled
    ) {
        ProcessingEngineError::Cancelled
    } else {
        ProcessingEngineError::Acquisition
    }
}

fn map_git_error(
    error: crate::processing::acquisition::git::GitAcquisitionError,
) -> ProcessingEngineError {
    if error == crate::processing::acquisition::git::GitAcquisitionError::Cancelled {
        ProcessingEngineError::Cancelled
    } else {
        ProcessingEngineError::Acquisition
    }
}
