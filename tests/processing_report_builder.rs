use std::collections::BTreeMap;
use std::path::PathBuf;

use file_guardian::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, CoverageStatus, Digest, FindingCategory,
    InspectionPhase, RuleId, RunId, Severity, SubjectId,
};
use file_guardian::policy::{BindingId, PolicyDirective};
use file_guardian::processing::actions::plan::{FindingResolution, ResolutionState};
use file_guardian::processing::config::{
    AcquisitionConfig, ActionMode, AnalyzerArtifactKind, AnalyzerConfig, AnalyzerExecution,
    AnalyzerKind, AnalyzerLimits, AnalyzerSelection, BuiltinRulesConfig, CaptureLimits,
    CompletionDisposition as ConfigCompletionDisposition,
    CompletionPolicy as ConfigCompletionPolicy, ContentApplicability, DaemonConfig,
    ExternalScannerRuntimeConfig, GitPolicy, HistoryScope, JobsConfig, LfsPolicy, PhaseExecution,
    PipelineConfig, PipelineStage, PriorLimits, PriorObservations, ProcessingConfig,
    ProcessingConfigFile, ProcessingProfile, ProfilePurpose, RetentionConfig, SourceScope,
    StageExecution, SubmodulePolicy, UnboundObservation,
};
use file_guardian::processing::domain::{
    ActionId, ActionJournalState, ActionKind, ActionRecord, Disposition, Finding, FindingId,
    HandoffStatus as DomainHandoffStatus, Occurrence, OccurrenceId, Outcome, ProcessSource,
};
use file_guardian::processing::executor::{
    AnalyzerRunRecord, AnalyzerRunState, ProcessingArtifact, ProcessingArtifactCatalog,
    ProcessingArtifactSurface, ProcessingPhaseResult,
};
use file_guardian::processing::policy::{
    CompiledPolicyDirective, ProcessingFindingResolution, ProcessingPolicyDecision,
    ProcessingPolicyEvaluation,
};
use file_guardian::processing::report::{
    AcquisitionStatus, PersistenceStatus, ProcessingOutcome, PublicationType, Rfc3339Timestamp,
};
use file_guardian::processing::report_builder::{
    build_processing_report, AcquisitionReportInput, ArtifactPublication, CompletionReportInput,
    PhaseReportInput, ProcessingReportBuildInput, ReportActionInput, ReportActionState,
    ReportArtifactMetadata, SafeComponentEvent,
};
use file_guardian::processing::runtime::{
    compile_processing_runtime, ProcessingCompileRequest, ProcessingSourceRequest,
    RequestedActionMode,
};

fn runtime() -> file_guardian::processing::runtime::CompiledProcessingRuntime {
    let rule_file =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/rules.d/publication.toml");
    let config = ProcessingConfigFile {
        schema_version: "3".into(),
        processing: ProcessingConfig {
            default_profile: "handoff".into(),
            jobs: JobsConfig {
                root: "/var/lib/file-guardian-report-test/jobs".into(),
                reports_root: "/var/lib/file-guardian-report-test/reports".into(),
                quarantine_root: "/var/lib/file-guardian-report-test/quarantine".into(),
                artifact_quarantine_root: "/var/lib/file-guardian-report-test/artifacts".into(),
                stale_after_secs: 60,
                max_report_bytes: 1_000_000,
                capture: CaptureLimits {
                    max_entries: 100,
                    max_files: 50,
                    max_file_bytes: 10_000,
                    max_total_bytes: 100_000,
                    max_depth: 8,
                },
                retention: RetentionConfig {
                    available_ttl_secs: 60,
                    available_max_bytes: 100_000,
                    quarantine_ttl_secs: 120,
                    quarantine_max_bytes: 200_000,
                    artifact_quarantine_ttl_secs: 180,
                    artifact_quarantine_max_bytes: 300_000,
                },
            },
            acquisition: AcquisitionConfig {
                git_executable: "/usr/bin/git".into(),
                git_timeout_secs: 30,
                max_stdout_bytes: 10_000,
                max_stderr_bytes: 10_000,
                max_refs: 100,
                max_commits: 1_000,
                max_unique_blobs: 2_000,
                max_provenance_occurrences: 4_000,
                max_git_bytes: 1_000_000,
            },
            external_scanners: ExternalScannerRuntimeConfig {
                bubblewrap_executable: "/usr/bin/bwrap".into(),
                expected_bubblewrap_version: "0.11.1".into(),
            },
            profiles: vec![ProcessingProfile {
                id: "handoff".into(),
                pipeline: "scan".into(),
                action_mode: ActionMode::Apply,
                purpose: ProfilePurpose::Handoff,
                default_unbound_observation: UnboundObservation::Deny,
                bindings: Vec::new(),
                source_scope: SourceScope {
                    working_tree: true,
                    history: HistoryScope::None,
                    history_ref_patterns: Vec::new(),
                },
                git: GitPolicy {
                    allowed_checkout_ref_patterns: vec!["refs/heads/*".into()],
                    submodules: SubmodulePolicy::Reject,
                    lfs: LfsPolicy::RejectPointer,
                },
                completion: ConfigCompletionPolicy {
                    allow: ConfigCompletionDisposition::Retain,
                    allow_modified: ConfigCompletionDisposition::Retain,
                    deny: ConfigCompletionDisposition::Discard,
                    error: ConfigCompletionDisposition::Quarantine,
                    cancelled: ConfigCompletionDisposition::Quarantine,
                },
                pi_adjudication: None,
            }],
        },
        pipelines: vec![PipelineConfig {
            id: "scan".into(),
            stages: vec![PipelineStage {
                id: "deterministic".into(),
                analyzers: vec!["rules".into()],
                execution: StageExecution::Serial,
                max_concurrency: 1,
                prior_observations: PriorObservations::None,
                prior_limits: PriorLimits {
                    max_observations: 100,
                    max_serialized_bytes: 10_000,
                },
            }],
        }],
        analyzers: vec![AnalyzerConfig {
            id: "rules".into(),
            kind: AnalyzerKind::BuiltinRules(BuiltinRulesConfig {
                rule_files: vec![rule_file],
                max_content_bytes: 100_000,
            }),
            execution: AnalyzerExecution {
                initial: PhaseExecution::Required,
                verification: PhaseExecution::Required,
            },
            selection: AnalyzerSelection {
                include: vec!["**".into()],
                exclude: Vec::new(),
                artifact_kinds: vec![AnalyzerArtifactKind::PhysicalFile],
            },
            content_applicability: ContentApplicability::default(),
            limits: AnalyzerLimits {
                max_findings: Some(100),
                ..AnalyzerLimits::default()
            },
        }],
        daemon: DaemonConfig::default(),
    };
    compile_processing_runtime(
        &config,
        ProcessingCompileRequest {
            run_id: RunId::new("run_report_builder").unwrap(),
            profile_id: None,
            action_mode: Some(RequestedActionMode::Apply),
            source: ProcessingSourceRequest::Path {
                path: "/tmp/input".into(),
            },
        },
    )
    .unwrap()
}

struct PhaseFixture {
    result: ProcessingPhaseResult,
    snapshot_identity: Digest,
    catalog: ProcessingArtifactCatalog,
    metadata: Vec<ReportArtifactMetadata>,
    policy: ProcessingPolicyEvaluation,
    durations: BTreeMap<AnalyzerId, u64>,
}

fn phase(phase: InspectionPhase, directive: Option<PolicyDirective>) -> PhaseFixture {
    let analyzer = AnalyzerId::new("rules").unwrap();
    let artifact_id = ArtifactId::from_suffix("file").unwrap();
    let subject_id = SubjectId::from_suffix("file").unwrap();
    let path =
        serde_json::from_str(r#"{"segments":[{"encoding":"utf8","value":"safe.txt"}]}"#).unwrap();
    let catalog = ProcessingArtifactCatalog::new(vec![ProcessingArtifact {
        artifact_id: artifact_id.clone(),
        logical_path: path,
        kind: AnalyzerArtifactKind::PhysicalFile,
        byte_len: 4,
        content_digest: Digest::sha256(b"safe"),
        surface: ProcessingArtifactSurface::WorkingTree,
    }])
    .unwrap();
    let (occurrences, findings, resolutions) = if let Some(directive) = directive {
        let occurrence_id = OccurrenceId::from_suffix(match phase {
            InspectionPhase::Initial => "initial",
            InspectionPhase::Verification => "verification",
        })
        .unwrap();
        let finding_id = FindingId::from_suffix(match phase {
            InspectionPhase::Initial => "initial",
            InspectionPhase::Verification => "verification",
        })
        .unwrap();
        let occurrence = Occurrence {
            id: occurrence_id.clone(),
            phase,
            analyzer_id: analyzer.clone(),
            rule_id: RuleId::new("secret").unwrap(),
            artifact_id: artifact_id.clone(),
            category: FindingCategory::Secret,
            severity: Severity::High,
            location: None,
            verification_state:
                file_guardian::processing::domain::CredentialVerificationState::Unverified,
            evidence_token: Some(Digest::sha256(b"evidence")),
        };
        let finding = Finding::new(
            finding_id.clone(),
            phase,
            analyzer.clone(),
            RuleId::new("secret").unwrap(),
            artifact_id,
            FindingCategory::Secret,
            Severity::High,
            None,
            Some(Digest::sha256(b"evidence")),
            vec![occurrence_id],
        )
        .unwrap();
        let resolution = ProcessingFindingResolution {
            action_resolution: FindingResolution {
                finding_id,
                binding_id: BindingId::new("binding").unwrap(),
                directive,
                state: ResolutionState::Active,
            },
            configured_directive: match directive {
                PolicyDirective::Audit => CompiledPolicyDirective::Audit,
                PolicyDirective::Deny => CompiledPolicyDirective::Deny,
                PolicyDirective::Delete => CompiledPolicyDirective::Delete,
                PolicyDirective::Quarantine => CompiledPolicyDirective::Quarantine,
            },
            priority: Some(10),
            matched_default: false,
        };
        (vec![occurrence], vec![finding], vec![resolution])
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    let decision = if resolutions
        .iter()
        .any(|value| value.action_resolution.directive == PolicyDirective::Deny)
    {
        ProcessingPolicyDecision::Deny
    } else if resolutions.iter().any(|value| {
        matches!(
            value.action_resolution.directive,
            PolicyDirective::Delete | PolicyDirective::Quarantine
        )
    }) {
        ProcessingPolicyDecision::RequiresMutation
    } else {
        ProcessingPolicyDecision::Allow
    };
    PhaseFixture {
        snapshot_identity: Digest::sha256(match phase {
            InspectionPhase::Initial => b"initial composite snapshot" as &[u8],
            InspectionPhase::Verification => b"verification composite snapshot" as &[u8],
        }),
        result: ProcessingPhaseResult {
            phase,
            stages_completed: 1,
            analyzers_completed: 1,
            observations: Vec::new(),
            pi_results: Vec::new(),
            occurrences,
            findings,
            correlations: Vec::new(),
            observation_to_finding: BTreeMap::new(),
            observation_to_occurrence: BTreeMap::new(),
            evidence: Vec::new(),
            coverage: vec![AnalyzerCoverage::new(
                analyzer.clone(),
                phase,
                1,
                1,
                1,
                0,
                CoverageStatus::Complete,
            )
            .unwrap()],
            analyzer_runs: vec![AnalyzerRunRecord {
                stage_id: "deterministic".into(),
                analyzer_id: analyzer.clone(),
                execution: PhaseExecution::Required,
                state: AnalyzerRunState::Complete,
                assigned: 1,
                scanner_version: None,
            }],
            issues: Vec::new(),
            required_complete: true,
        },
        catalog,
        metadata: vec![ReportArtifactMetadata {
            artifact_id: ArtifactId::from_suffix("file").unwrap(),
            subject_id,
            publication: ArtifactPublication {
                publication_type: PublicationType::RegularFile,
                publication_mode: Some(0o644),
            },
        }],
        policy: ProcessingPolicyEvaluation {
            decision,
            resolutions,
        },
        durations: BTreeMap::from([(analyzer, 3)]),
    }
}

fn acquisition() -> AcquisitionReportInput {
    AcquisitionReportInput {
        status: AcquisitionStatus::Complete,
        implementation_id: "local_copy".into(),
        implementation_version: "1".into(),
        started_at: timestamp("2026-08-17T12:00:00+00:00"),
        finished_at: timestamp("2026-08-17T12:00:01+00:00"),
        duration_ms: 1_000,
        source_identity: Some(Digest::sha256(b"source")),
        issue_codes: Vec::new(),
    }
}

fn timestamp(value: &str) -> Rfc3339Timestamp {
    Rfc3339Timestamp::new(value).unwrap()
}

fn completion(outcome: Outcome, initial: Digest, final_id: Digest) -> CompletionReportInput {
    let (configured, effective, handoff, expires) = match outcome {
        Outcome::Allow | Outcome::AllowModified => (
            file_guardian::processing::completion::CompletionDisposition::Retain,
            Disposition::Retained,
            DomainHandoffStatus::Available,
            Some(timestamp("2026-08-17T13:00:00+00:00")),
        ),
        Outcome::Deny => (
            file_guardian::processing::completion::CompletionDisposition::Discard,
            Disposition::Discarded,
            DomainHandoffStatus::Unavailable,
            None,
        ),
        Outcome::Error | Outcome::Cancelled => (
            file_guardian::processing::completion::CompletionDisposition::Quarantine,
            Disposition::RetainedError,
            DomainHandoffStatus::Unavailable,
            None,
        ),
    };
    CompletionReportInput {
        outcome,
        configured_disposition: configured,
        effective_disposition: effective,
        handoff,
        sealed: outcome.is_allowed(),
        initial_manifest_identity: Some(initial),
        final_manifest_identity: Some(final_id),
        current_manifest_identity: Some(final_id),
        expires_at: expires,
        quarantine_id: None,
    }
}

fn build<'a>(
    runtime: &'a file_guardian::processing::runtime::CompiledProcessingRuntime,
    initial: &'a PhaseFixture,
    verification: Option<&'a PhaseFixture>,
    completion: &'a CompletionReportInput,
    acquisition: &'a AcquisitionReportInput,
    actions: &'a [ReportActionInput<'a>],
    issues: &'a [SafeComponentEvent],
) -> file_guardian::processing::report::ProcessingReport {
    try_build(
        runtime,
        initial,
        verification,
        completion,
        acquisition,
        actions,
        issues,
    )
    .unwrap()
}

fn try_build<'a>(
    runtime: &'a file_guardian::processing::runtime::CompiledProcessingRuntime,
    initial: &'a PhaseFixture,
    verification: Option<&'a PhaseFixture>,
    completion: &'a CompletionReportInput,
    acquisition: &'a AcquisitionReportInput,
    actions: &'a [ReportActionInput<'a>],
    issues: &'a [SafeComponentEvent],
) -> Result<
    file_guardian::processing::report::ProcessingReport,
    file_guardian::processing::report_builder::ReportBuildError,
> {
    let initial_phase = PhaseReportInput {
        result: &initial.result,
        manifest_identity: initial.snapshot_identity,
        artifacts: &initial.catalog,
        artifact_metadata: &initial.metadata,
        policy: &initial.policy,
        analyzer_duration_ms: &initial.durations,
        duration_ms: 3,
    };
    let verification_phase = verification.map(|phase| PhaseReportInput {
        result: &phase.result,
        manifest_identity: phase.snapshot_identity,
        artifacts: &phase.catalog,
        artifact_metadata: &phase.metadata,
        policy: &phase.policy,
        analyzer_duration_ms: &phase.durations,
        duration_ms: 3,
    });
    let source = ProcessSource::path();
    build_processing_report(ProcessingReportBuildInput {
        run_id: &runtime.run_id,
        request_id: Some("request-report"),
        runtime: Some(runtime),
        source: Some(&source),
        acquisition: Some(acquisition),
        initial: Some(initial_phase),
        verification: verification_phase,
        completion: Some(completion),
        pi_invocations: Vec::new(),
        adjudications: &[],
        actions,
        issues,
        degradations: &[],
        started_at: timestamp("2026-08-17T12:00:00+00:00"),
        finished_at: timestamp("2026-08-17T12:00:02+00:00"),
        duration_ms: 2_000,
        persistence_status: PersistenceStatus::Durable,
        omission_reason: None,
    })
}

#[test]
fn assembles_allow_and_deny_without_private_source_material() {
    let runtime = runtime();
    let acquisition = acquisition();
    let manifest = Digest::sha256(b"manifest");
    let allow = completion(Outcome::Allow, manifest, manifest);
    let allow_report = build(
        &runtime,
        &phase(InspectionPhase::Initial, None),
        None,
        &allow,
        &acquisition,
        &[],
        &[],
    );
    assert_eq!(allow_report.outcome, ProcessingOutcome::Allow);
    let json = String::from_utf8(allow_report.to_json_line().unwrap()).unwrap();
    assert!(!json.contains("/tmp/input"));
    assert!(!json.contains("source stays immutable"));

    let deny = completion(Outcome::Deny, manifest, manifest);
    let deny_report = build(
        &runtime,
        &phase(InspectionPhase::Initial, Some(PolicyDirective::Deny)),
        None,
        &deny,
        &acquisition,
        &[],
        &[],
    );
    assert_eq!(deny_report.outcome, ProcessingOutcome::Deny);
    assert_eq!(deny_report.exit_code, 20);
}

#[test]
fn assembles_allow_modified_only_with_committed_action_and_fresh_verification() {
    let runtime = runtime();
    let acquisition = acquisition();
    let initial_id = Digest::sha256(b"initial");
    let final_id = Digest::sha256(b"final");
    let completion = completion(Outcome::AllowModified, initial_id, final_id);
    let initial = phase(InspectionPhase::Initial, Some(PolicyDirective::Delete));
    let verification = phase(InspectionPhase::Verification, None);
    let action = ActionRecord::new(
        ActionId::from_suffix("delete").unwrap(),
        ActionKind::Delete,
        SubjectId::from_suffix("file").unwrap(),
        vec![FindingId::from_suffix("initial").unwrap()],
        vec![BindingId::new("binding").unwrap()],
        ActionJournalState::Planned,
        Some(ActionJournalState::Fsynced),
        None,
    )
    .unwrap();
    let actions = [ReportActionInput {
        action: &action,
        state: ReportActionState::Committed,
    }];
    let report = build(
        &runtime,
        &initial,
        Some(&verification),
        &completion,
        &acquisition,
        &actions,
        &[],
    );
    assert_eq!(report.outcome, ProcessingOutcome::AllowModified);
    assert!(report.modified);
    assert_eq!(report.exit_code, 10);

    assert!(try_build(
        &runtime,
        &initial,
        None,
        &completion,
        &acquisition,
        &actions,
        &[],
    )
    .is_err());
    assert!(try_build(
        &runtime,
        &initial,
        Some(&verification),
        &completion,
        &acquisition,
        &[],
        &[],
    )
    .is_err());
}

#[test]
fn assembles_durable_error_and_rejects_unsafe_issue_identifiers() {
    let runtime = runtime();
    let acquisition = acquisition();
    let manifest = Digest::sha256(b"manifest");
    let completion = completion(Outcome::Error, manifest, manifest);
    let issues = [SafeComponentEvent {
        code: "analysis_failed".into(),
        phase: Some(InspectionPhase::Initial),
        component_id: Some("rules".into()),
    }];
    let report = build(
        &runtime,
        &phase(InspectionPhase::Initial, None),
        None,
        &completion,
        &acquisition,
        &[],
        &issues,
    );
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert_eq!(report.exit_code, 30);

    assert!(try_build(
        &runtime,
        &phase(InspectionPhase::Initial, None),
        None,
        &completion,
        &acquisition,
        &[],
        &[],
    )
    .is_err());

    let unsafe_issues = [SafeComponentEvent {
        code: "/private/path".into(),
        phase: None,
        component_id: None,
    }];
    let initial = phase(InspectionPhase::Initial, None);
    let source = ProcessSource::path();
    let result = build_processing_report(ProcessingReportBuildInput {
        run_id: &runtime.run_id,
        request_id: None,
        runtime: Some(&runtime),
        source: Some(&source),
        acquisition: Some(&acquisition),
        initial: Some(PhaseReportInput {
            result: &initial.result,
            manifest_identity: manifest,
            artifacts: &initial.catalog,
            artifact_metadata: &initial.metadata,
            policy: &initial.policy,
            analyzer_duration_ms: &initial.durations,
            duration_ms: 1,
        }),
        verification: None,
        completion: Some(&completion),
        pi_invocations: Vec::new(),
        adjudications: &[],
        actions: &[],
        issues: &unsafe_issues,
        degradations: &[],
        started_at: timestamp("2026-08-17T12:00:00+00:00"),
        finished_at: timestamp("2026-08-17T12:00:01+00:00"),
        duration_ms: 1_000,
        persistence_status: PersistenceStatus::Durable,
        omission_reason: None,
    });
    assert!(result.is_err());
}

#[test]
fn fail_safe_quarantine_override_is_preserved_without_source_context() {
    let runtime = runtime();
    let completion = CompletionReportInput {
        outcome: Outcome::Error,
        configured_disposition:
            file_guardian::processing::completion::CompletionDisposition::Discard,
        effective_disposition: Disposition::Quarantined,
        handoff: DomainHandoffStatus::Unavailable,
        sealed: false,
        initial_manifest_identity: None,
        final_manifest_identity: None,
        current_manifest_identity: None,
        expires_at: None,
        quarantine_id: Some(runtime.run_id.as_str().to_owned()),
    };
    let issues = [SafeComponentEvent {
        code: "ambiguous_stage_mutation".into(),
        phase: None,
        component_id: None,
    }];
    let report = build_processing_report(ProcessingReportBuildInput {
        run_id: &runtime.run_id,
        request_id: None,
        runtime: Some(&runtime),
        source: None,
        acquisition: None,
        initial: None,
        verification: None,
        completion: Some(&completion),
        pi_invocations: Vec::new(),
        adjudications: &[],
        actions: &[],
        issues: &issues,
        degradations: &[],
        started_at: timestamp("2026-08-17T12:00:00+00:00"),
        finished_at: timestamp("2026-08-17T12:00:01+00:00"),
        duration_ms: 1_000,
        persistence_status: PersistenceStatus::Durable,
        omission_reason: Some("failure_details_withheld"),
    })
    .unwrap();
    let stage = report.stage.unwrap();
    assert_eq!(
        stage.configured_disposition,
        file_guardian::processing::report::ConfiguredDisposition::Discard
    );
    assert_eq!(
        stage.effective_disposition,
        file_guardian::processing::report::EffectiveDisposition::Quarantined
    );
}

#[test]
fn unavailable_persistence_error_has_no_durable_or_private_context() {
    let run_id = RunId::from_suffix("startup_error").unwrap();
    let issues = [SafeComponentEvent {
        code: "configuration_failed".into(),
        phase: None,
        component_id: None,
    }];
    let report = build_processing_report(ProcessingReportBuildInput {
        run_id: &run_id,
        request_id: None,
        runtime: None,
        source: None,
        acquisition: None,
        initial: None,
        verification: None,
        completion: None,
        pi_invocations: Vec::new(),
        adjudications: &[],
        actions: &[],
        issues: &issues,
        degradations: &[],
        started_at: timestamp("2026-08-17T12:00:00+00:00"),
        finished_at: timestamp("2026-08-17T12:00:00+00:00"),
        duration_ms: 0,
        persistence_status: PersistenceStatus::Unavailable,
        omission_reason: None,
    })
    .unwrap();
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert!(report.source.is_none());
    assert!(report.policy.is_none());
    assert!(report.persistence.report_digest.is_none());
}

#[test]
fn preserves_phase_stable_evidence_tokens_without_reusing_finding_ids() {
    let runtime = runtime();
    let acquisition = acquisition();
    let initial_manifest = Digest::sha256(b"initial");
    let final_manifest = Digest::sha256(b"final");
    let completion = completion(Outcome::Error, initial_manifest, final_manifest);
    let initial = phase(InspectionPhase::Initial, Some(PolicyDirective::Deny));
    let verification = phase(InspectionPhase::Verification, Some(PolicyDirective::Deny));
    let issues = [SafeComponentEvent {
        code: "verification_blocked".into(),
        phase: Some(InspectionPhase::Verification),
        component_id: Some("rules".into()),
    }];

    let report = build(
        &runtime,
        &initial,
        Some(&verification),
        &completion,
        &acquisition,
        &[],
        &issues,
    );
    let initial = report.phases.initial.unwrap();
    let verification = report.phases.verification.unwrap();

    assert_ne!(
        initial.findings[0].finding_id,
        verification.findings[0].finding_id
    );
    assert_eq!(
        initial.occurrences[0].evidence_token,
        verification.occurrences[0].evidence_token
    );
}
