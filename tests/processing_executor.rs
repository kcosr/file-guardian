use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use file_guardian::analyzers::{
    BuiltinAnalyzerLimits, BuiltinContentApplicability, BuiltinRulesAnalyzer,
};
use file_guardian::domain::{
    AnalyzerId, ArtifactId, Digest, Finding, FindingCategory, InspectionPhase, LogicalPath,
    NormalizedObservation, ObservationId, PathSegment, RuleId, RunId, SafeEvidence, Severity,
    ValidatedLocation,
};
use file_guardian::pipeline::{PriorObservationMode, ProjectionLimits, StageExecution, StageId};
use file_guardian::processing::config::{AnalyzerArtifactKind, PhaseExecution};
use file_guardian::processing::executor::{
    AnalyzerBackendError, AnalyzerBackendOutput, AnalyzerInvocation, AnalyzerRunState,
    AssignmentDisposition, AssignmentOutcome, BackendFuture, BuiltinProcessingBackend,
    ExternalProcessingBackend, PiProcessingBackend, ProcessingArtifact, ProcessingArtifactCatalog,
    ProcessingArtifactSurface, ProcessingBackends, ProcessingExecutionContext,
    ProcessingPhaseExecutor,
};
use file_guardian::processing::findings::JobCorrelationKey;
use file_guardian::processing::runtime::{
    FrozenAnalyzer, FrozenAnalyzerImplementation, FrozenAnalyzerSelection, FrozenExternalAnalyzer,
    FrozenPiRuntime, FrozenPipeline, FrozenStage,
};
use file_guardian::rules::load_rule_files;

#[derive(Clone)]
enum Behavior {
    Success { finding: bool },
    Error(AnalyzerBackendError),
    Incomplete,
}

struct FakeBackends {
    behaviors: BTreeMap<String, Behavior>,
    calls: Mutex<Vec<(String, InspectionPhase, usize, usize)>>,
}

impl FakeBackends {
    fn new(behaviors: impl IntoIterator<Item = (&'static str, Behavior)>) -> Self {
        Self {
            behaviors: behaviors
                .into_iter()
                .map(|(id, behavior)| (id.to_owned(), behavior))
                .collect(),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn run(
        &self,
        invocation: AnalyzerInvocation,
    ) -> Result<AnalyzerBackendOutput, AnalyzerBackendError> {
        self.calls.lock().unwrap().push((
            invocation.analyzer_id.as_str().to_owned(),
            invocation.phase,
            invocation.prior.observations().len(),
            invocation.prior_findings.findings.len(),
        ));
        match self.behaviors.get(invocation.analyzer_id.as_str()).unwrap() {
            Behavior::Error(error) => Err(*error),
            Behavior::Incomplete => Ok(AnalyzerBackendOutput {
                assignments: Vec::new(),
                observations: Vec::new(),
                evidence: Vec::new(),
                scanner_version: None,
                pi_analysis: None,
            }),
            Behavior::Success { finding } => {
                let assignments = invocation
                    .assignments
                    .iter()
                    .map(|assignment| AssignmentOutcome {
                        candidate_id: assignment.candidate_id.clone(),
                        disposition: AssignmentDisposition::Completed,
                    })
                    .collect();
                let observations = if *finding {
                    invocation
                        .assignments
                        .first()
                        .map(|assignment| {
                            NormalizedObservation::Finding(Finding {
                                id: ObservationId::from_suffix(format!(
                                    "{}_observation",
                                    invocation.analyzer_id.as_str()
                                ))
                                .unwrap(),
                                analyzer_id: invocation.analyzer_id.clone(),
                                rule_id: RuleId::new("credential.test").unwrap(),
                                artifact_id: assignment.artifact_id.clone(),
                                category: FindingCategory::Credential,
                                severity: Severity::High,
                                location: Some(ValidatedLocation::line(4).unwrap()),
                                evidence: SafeEvidence::default(),
                            })
                        })
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                };
                Ok(AnalyzerBackendOutput {
                    assignments,
                    observations,
                    evidence: Vec::new(),
                    scanner_version: None,
                    pi_analysis: None,
                })
            }
        }
    }
}

impl BuiltinProcessingBackend for FakeBackends {
    fn execute<'a>(
        &'a self,
        _runtime: &'a BuiltinRulesAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a> {
        Box::pin(async move { self.run(invocation) })
    }
}

impl ExternalProcessingBackend for FakeBackends {
    fn execute<'a>(
        &'a self,
        _runtime: &'a FrozenExternalAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a> {
        Box::pin(async move { self.run(invocation) })
    }
}

impl PiProcessingBackend for FakeBackends {
    fn execute<'a>(
        &'a self,
        _runtime: &'a FrozenPiRuntime,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a> {
        Box::pin(async move { self.run(invocation) })
    }
}

fn analyzer(id: &str, initial: PhaseExecution, verification: PhaseExecution) -> FrozenAnalyzer {
    let rule_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("config/rules.d/publication.toml");
    let runtime = BuiltinRulesAnalyzer::new(
        id,
        load_rule_files(&[rule_file]).unwrap(),
        BuiltinAnalyzerLimits {
            max_content_bytes: 100_000,
            max_findings: 100,
            content_applicability: BuiltinContentApplicability::default(),
        },
    )
    .unwrap();
    FrozenAnalyzer {
        id: AnalyzerId::new(id).unwrap(),
        initial,
        verification,
        identity: Digest::sha256(id.as_bytes()),
        selection: FrozenAnalyzerSelection {
            include: vec!["**".into()],
            exclude: Vec::new(),
            artifact_kinds: vec![AnalyzerArtifactKind::PhysicalFile],
            required_text_include: Vec::new(),
        },
        implementation: FrozenAnalyzerImplementation::Builtin(runtime),
    }
}

fn stage(id: &str, analyzers: Vec<FrozenAnalyzer>, execution: StageExecution) -> FrozenStage {
    FrozenStage {
        id: StageId::new(id).unwrap(),
        execution,
        prior_observations: PriorObservationMode::AllNormalized,
        prior_limits: ProjectionLimits::new(100, 100_000).unwrap(),
        analyzers,
    }
}

fn catalog() -> Arc<ProcessingArtifactCatalog> {
    Arc::new(
        ProcessingArtifactCatalog::new(vec![ProcessingArtifact {
            artifact_id: ArtifactId::from_suffix("one").unwrap(),
            logical_path: LogicalPath::new(vec![PathSegment::utf8("secret.txt").unwrap()]).unwrap(),
            kind: AnalyzerArtifactKind::PhysicalFile,
            byte_len: 12,
            content_digest: Digest::sha256(b"artifact"),
            surface: ProcessingArtifactSurface::WorkingTree,
        }])
        .unwrap(),
    )
}

fn context() -> ProcessingExecutionContext {
    ProcessingExecutionContext {
        run_id: RunId::new("run_executor_test").unwrap(),
        snapshot_identity: Digest::sha256(b"snapshot"),
        pipeline_identity: Digest::sha256(b"pipeline"),
        policy_identity: Digest::sha256(b"policy"),
        correlation_key: JobCorrelationKey::from_bytes([7; 32]),
    }
}

fn backends(fake: &FakeBackends) -> ProcessingBackends<'_> {
    ProcessingBackends {
        builtin: fake,
        external: fake,
        pi: fake,
    }
}

#[tokio::test]
async fn advisory_failure_and_disabled_analyzer_do_not_stop_required_work() {
    let pipeline = FrozenPipeline {
        id: "pipeline".into(),
        stages: vec![
            stage(
                "first",
                vec![
                    analyzer(
                        "advisory",
                        PhaseExecution::Advisory,
                        PhaseExecution::Disabled,
                    ),
                    analyzer(
                        "disabled",
                        PhaseExecution::Disabled,
                        PhaseExecution::Disabled,
                    ),
                    analyzer(
                        "required",
                        PhaseExecution::Required,
                        PhaseExecution::Required,
                    ),
                ],
                StageExecution::Serial,
            ),
            stage(
                "second",
                vec![analyzer(
                    "later",
                    PhaseExecution::Required,
                    PhaseExecution::Required,
                )],
                StageExecution::Serial,
            ),
        ],
    };
    let fake = FakeBackends::new([
        (
            "advisory",
            Behavior::Error(AnalyzerBackendError::Unavailable),
        ),
        ("required", Behavior::Success { finding: true }),
        ("later", Behavior::Success { finding: false }),
    ]);
    let result = ProcessingPhaseExecutor::execute(
        &pipeline,
        InspectionPhase::Initial,
        &context(),
        catalog(),
        backends(&fake),
    )
    .await
    .unwrap();

    assert!(result.required_complete);
    assert_eq!(result.stages_completed, 2);
    assert_eq!(result.analyzers_completed, 2);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.occurrences.len(), 1);
    assert_eq!(result.correlations.len(), 1);
    assert_eq!(
        result
            .analyzer_runs
            .iter()
            .map(|run| run.state)
            .collect::<Vec<_>>(),
        vec![
            AnalyzerRunState::AdvisoryFailed,
            AnalyzerRunState::Disabled,
            AnalyzerRunState::Complete,
            AnalyzerRunState::Complete,
        ]
    );
    assert!(!fake
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call.0 == "disabled"));
    assert!(fake
        .calls
        .lock()
        .unwrap()
        .contains(&("later".into(), InspectionPhase::Initial, 1, 1)));
}

#[tokio::test]
async fn required_invalid_coverage_stops_serial_and_later_stages() {
    let pipeline = FrozenPipeline {
        id: "pipeline".into(),
        stages: vec![
            stage(
                "first",
                vec![
                    analyzer("broken", PhaseExecution::Required, PhaseExecution::Required),
                    analyzer("unrun", PhaseExecution::Required, PhaseExecution::Required),
                ],
                StageExecution::Serial,
            ),
            stage(
                "later-stage",
                vec![analyzer(
                    "later",
                    PhaseExecution::Required,
                    PhaseExecution::Required,
                )],
                StageExecution::Serial,
            ),
        ],
    };
    let fake = FakeBackends::new([
        ("broken", Behavior::Incomplete),
        ("unrun", Behavior::Success { finding: false }),
        ("later", Behavior::Success { finding: false }),
    ]);
    let result = ProcessingPhaseExecutor::execute(
        &pipeline,
        InspectionPhase::Initial,
        &context(),
        catalog(),
        backends(&fake),
    )
    .await
    .unwrap();

    assert!(!result.required_complete);
    assert_eq!(result.stages_completed, 0);
    assert_eq!(
        result
            .analyzer_runs
            .iter()
            .map(|run| run.state)
            .collect::<Vec<_>>(),
        vec![
            AnalyzerRunState::RequiredFailed,
            AnalyzerRunState::Skipped,
            AnalyzerRunState::Skipped,
        ]
    );
}

#[tokio::test]
async fn prior_projection_and_phase_selection_are_explicit() {
    let pipeline = FrozenPipeline {
        id: "pipeline".into(),
        stages: vec![
            stage(
                "first",
                vec![analyzer(
                    "initial",
                    PhaseExecution::Required,
                    PhaseExecution::Disabled,
                )],
                StageExecution::Serial,
            ),
            stage(
                "second",
                vec![analyzer(
                    "verify",
                    PhaseExecution::Disabled,
                    PhaseExecution::Required,
                )],
                StageExecution::Serial,
            ),
        ],
    };
    let fake = FakeBackends::new([
        ("initial", Behavior::Success { finding: true }),
        ("verify", Behavior::Success { finding: false }),
    ]);
    let initial = ProcessingPhaseExecutor::execute(
        &pipeline,
        InspectionPhase::Initial,
        &context(),
        catalog(),
        backends(&fake),
    )
    .await
    .unwrap();
    assert_eq!(initial.analyzers_completed, 1);

    let verification = ProcessingPhaseExecutor::execute(
        &pipeline,
        InspectionPhase::Verification,
        &context(),
        catalog(),
        backends(&fake),
    )
    .await
    .unwrap();
    assert_eq!(verification.analyzers_completed, 1);
    let calls = fake.calls.lock().unwrap();
    assert!(calls.contains(&("initial".into(), InspectionPhase::Initial, 0, 0)));
    assert!(calls.contains(&("verify".into(), InspectionPhase::Verification, 0, 0)));
}

#[tokio::test]
async fn phase_wide_normalization_correlates_cross_analyzer_duplicates() {
    let pipeline = FrozenPipeline {
        id: "pipeline".into(),
        stages: vec![stage(
            "parallel",
            vec![
                analyzer(
                    "scanner_a",
                    PhaseExecution::Required,
                    PhaseExecution::Required,
                ),
                analyzer(
                    "scanner_b",
                    PhaseExecution::Required,
                    PhaseExecution::Required,
                ),
            ],
            StageExecution::Parallel { max_concurrency: 2 },
        )],
    };
    let fake = FakeBackends::new([
        ("scanner_a", Behavior::Success { finding: true }),
        ("scanner_b", Behavior::Success { finding: true }),
    ]);
    let first = ProcessingPhaseExecutor::execute(
        &pipeline,
        InspectionPhase::Initial,
        &context(),
        catalog(),
        backends(&fake),
    )
    .await
    .unwrap();
    let second = ProcessingPhaseExecutor::execute(
        &pipeline,
        InspectionPhase::Initial,
        &context(),
        catalog(),
        backends(&fake),
    )
    .await
    .unwrap();

    assert_eq!(first.findings.len(), 2);
    assert_eq!(first.occurrences.len(), 2);
    assert_eq!(first.correlations.len(), 1);
    assert_eq!(first.correlations[0].finding_ids.len(), 2);
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.correlations, second.correlations);
}

#[test]
fn repository_artifacts_require_an_explicit_nonempty_history_surface() {
    let result = ProcessingArtifactCatalog::new(vec![ProcessingArtifact {
        artifact_id: ArtifactId::from_suffix("history").unwrap(),
        logical_path: LogicalPath::new(vec![PathSegment::utf8("blob.txt").unwrap()]).unwrap(),
        kind: AnalyzerArtifactKind::RepositoryBlob,
        byte_len: 1,
        content_digest: Digest::sha256(b"blob"),
        surface: ProcessingArtifactSurface::WorkingTree,
    }]);
    assert!(result.is_err());
}
