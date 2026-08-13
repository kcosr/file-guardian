use super::{
    AnalyzerImplementation, CompiledAnalyzer, CompiledPipeline, PriorObservationProjection,
    StageExecution, UnsupportedAnalyzerKind,
};
use crate::authorization::InvocationWorkspace;
use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, ArtifactManifest, CoverageStatus, InspectionIssue,
    InspectionPhase, IssueCode, NormalizedObservation, SanitizedMessage,
};
use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestAnalyzer {
    run: Arc<dyn Fn(TestAnalyzerInput) -> TestAnalyzerOutput + Send + Sync>,
}

#[cfg(test)]
impl std::fmt::Debug for TestAnalyzer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestAnalyzer(..)")
    }
}

#[cfg(test)]
#[derive(Clone)]
struct TestAnalyzerInput {
    analyzer_id: AnalyzerId,
    assigned: u64,
    assignment: Vec<ArtifactId>,
    prior_count: usize,
}

#[cfg(test)]
struct TestAnalyzerOutput {
    observations: Vec<NormalizedObservation>,
    issues: Vec<InspectionIssue>,
    complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PipelineExecution {
    pub stages_completed: u64,
    pub analyzers_completed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineResult {
    pub execution: PipelineExecution,
    pub observations: Vec<NormalizedObservation>,
    pub issues: Vec<InspectionIssue>,
    pub coverage: Vec<AnalyzerCoverage>,
    pub complete: bool,
}

#[derive(Clone, Debug)]
struct PreparedAnalyzer {
    analyzer: CompiledAnalyzer,
    assignment: Vec<ArtifactId>,
}

#[derive(Clone, Debug)]
struct AnalyzerResult {
    observations: Vec<NormalizedObservation>,
    issues: Vec<InspectionIssue>,
    coverage: AnalyzerCoverage,
}

pub struct PipelineExecutor;

impl PipelineExecutor {
    pub async fn execute(
        pipeline: &CompiledPipeline,
        manifest: Arc<ArtifactManifest>,
        workspace: Arc<InvocationWorkspace>,
    ) -> PipelineResult {
        let prepared = match prepare(pipeline, &manifest) {
            Ok(prepared) => prepared,
            Err((analyzer_id, message)) => {
                return preparation_failure(pipeline, &manifest, analyzer_id, message)
            }
        };

        let mut aggregate = PipelineResult {
            execution: PipelineExecution::default(),
            observations: Vec::new(),
            issues: Vec::new(),
            coverage: Vec::new(),
            complete: true,
        };

        for (stage_index, stage) in pipeline.stages.iter().enumerate() {
            let projection = match PriorObservationProjection::build(
                stage.prior_observations,
                &aggregate.observations,
                stage.prior_limits,
            ) {
                Ok(projection) => Arc::new(projection),
                Err(_) => {
                    aggregate.complete = false;
                    aggregate.issues.push(issue(
                        IssueCode::RequiredAnalyzerBudgetExceeded,
                        None,
                        "prior observation projection exceeds its configured limit",
                    ));
                    append_unrun(&prepared, stage_index, 0, &mut aggregate.coverage);
                    break;
                }
            };

            let stage_results = execute_stage(
                stage.execution,
                &prepared[stage_index],
                Arc::clone(&manifest),
                Arc::clone(&workspace),
                projection,
            )
            .await;
            let returned_in_stage = stage_results.len();

            let mut failed_at = None;
            for (analyzer_index, result) in stage_results.into_iter().enumerate() {
                let Some(result) = result else {
                    failed_at.get_or_insert(analyzer_index);
                    continue;
                };
                let analyzer_complete = result.coverage.is_complete() && result.issues.is_empty();
                aggregate.observations.extend(result.observations);
                aggregate.issues.extend(result.issues);
                aggregate.coverage.push(result.coverage);
                if analyzer_complete {
                    aggregate.execution.analyzers_completed += 1;
                } else {
                    failed_at.get_or_insert(analyzer_index);
                }
            }

            if let Some(first_unrun_or_failed) = failed_at {
                aggregate.complete = false;
                // Rows already returned by failed analyzers are present. Add only
                // analyzers which were not launched after the failure became known.
                append_unrun(
                    &prepared,
                    stage_index,
                    returned_in_stage,
                    &mut aggregate.coverage,
                );
                let _ = first_unrun_or_failed;
                break;
            }
            aggregate.execution.stages_completed += 1;
        }

        canonicalize(&mut aggregate);
        if !aggregate.issues.is_empty() {
            aggregate.complete = false;
        }
        aggregate
    }
}

fn prepare(
    pipeline: &CompiledPipeline,
    manifest: &ArtifactManifest,
) -> Result<Vec<Vec<PreparedAnalyzer>>, (Option<AnalyzerId>, &'static str)> {
    pipeline
        .stages
        .iter()
        .map(|stage| {
            stage
                .analyzers
                .iter()
                .map(|analyzer| {
                    let selection = analyzer
                        .eligibility
                        .assign(&analyzer.id, manifest)
                        .map_err(|_| {
                            (
                                Some(analyzer.id.clone()),
                                "analyzer candidate assignment could not be constructed",
                            )
                        })?;
                    Ok(PreparedAnalyzer {
                        analyzer: analyzer.clone(),
                        assignment: selection
                            .assignments
                            .into_iter()
                            .map(|assignment| assignment.artifact_id)
                            .collect(),
                    })
                })
                .collect()
        })
        .collect()
}

async fn execute_stage(
    execution: StageExecution,
    analyzers: &[PreparedAnalyzer],
    manifest: Arc<ArtifactManifest>,
    workspace: Arc<InvocationWorkspace>,
    projection: Arc<PriorObservationProjection>,
) -> Vec<Option<AnalyzerResult>> {
    let concurrency = match execution {
        StageExecution::Serial => 1,
        StageExecution::Parallel { max_concurrency } => max_concurrency,
    };
    let mut results = Vec::with_capacity(analyzers.len());
    for batch in analyzers.chunks(concurrency) {
        let mut handles = Vec::with_capacity(batch.len());
        for prepared in batch {
            let prepared = prepared.clone();
            let manifest = Arc::clone(&manifest);
            let workspace = Arc::clone(&workspace);
            let projection = Arc::clone(&projection);
            handles.push((
                prepared.analyzer.id.clone(),
                tokio::task::spawn_blocking(move || {
                    execute_analyzer(prepared, manifest, workspace, projection)
                }),
            ));
        }

        let mut batch_failed = false;
        for (analyzer_id, handle) in handles {
            match handle.await {
                Ok(result) => {
                    batch_failed |= !result.coverage.is_complete() || !result.issues.is_empty();
                    results.push(Some(result));
                }
                Err(_) => {
                    batch_failed = true;
                    let assigned = analyzers
                        .iter()
                        .find(|item| item.analyzer.id == analyzer_id)
                        .map_or(0, |item| item.assignment.len() as u64);
                    results.push(Some(AnalyzerResult {
                        observations: Vec::new(),
                        issues: vec![issue(
                            IssueCode::RequiredAnalyzerProcessFailure,
                            Some(analyzer_id.clone()),
                            "required analyzer task failed",
                        )],
                        coverage: incomplete_coverage(analyzer_id, assigned),
                    }));
                }
            }
        }
        if batch_failed {
            break;
        }
    }
    results
}

fn execute_analyzer(
    prepared: PreparedAnalyzer,
    manifest: Arc<ArtifactManifest>,
    workspace: Arc<InvocationWorkspace>,
    _projection: Arc<PriorObservationProjection>,
) -> AnalyzerResult {
    let assigned = prepared.assignment.len() as u64;
    let analyzer_id = prepared.analyzer.id.clone();
    let assignment = prepared.assignment.clone();
    let result = match prepared.analyzer.implementation {
        AnalyzerImplementation::Builtin(analyzer) => match analyzer.analyze(
            InspectionPhase::Initial,
            &manifest,
            &prepared.assignment,
            workspace.objects(),
        ) {
            Ok(result) => AnalyzerResult {
                observations: result.observations,
                issues: result.issues,
                coverage: result.coverage,
            },
            Err(_) => AnalyzerResult {
                observations: Vec::new(),
                issues: vec![issue(
                    IssueCode::InvalidAnalyzerOutput,
                    Some(prepared.analyzer.id.clone()),
                    "built-in analyzer rejected its assigned candidates",
                )],
                coverage: incomplete_coverage(prepared.analyzer.id, assigned),
            },
        },
        AnalyzerImplementation::Unsupported { kind } => AnalyzerResult {
            observations: Vec::new(),
            issues: vec![issue(
                IssueCode::RequiredAnalyzerProcessFailure,
                Some(prepared.analyzer.id.clone()),
                match kind {
                    UnsupportedAnalyzerKind::External => {
                        "selected external analyzer is not implemented"
                    }
                    UnsupportedAnalyzerKind::Pi => "selected Pi analyzer is not implemented",
                },
            )],
            coverage: incomplete_coverage(prepared.analyzer.id, assigned),
        },
        #[cfg(test)]
        AnalyzerImplementation::Test(test) => {
            let output = (test.run)(TestAnalyzerInput {
                analyzer_id: prepared.analyzer.id.clone(),
                assigned,
                assignment: prepared.assignment.clone(),
                prior_count: _projection.observations().len(),
            });
            let coverage = if output.complete {
                AnalyzerCoverage::new(
                    prepared.analyzer.id,
                    InspectionPhase::Initial,
                    assigned,
                    assigned,
                    assigned,
                    0,
                    CoverageStatus::Complete,
                )
                .expect("complete test coverage is valid")
            } else {
                incomplete_coverage(prepared.analyzer.id, assigned)
            };
            AnalyzerResult {
                observations: output.observations,
                issues: output.issues,
                coverage,
            }
        }
    };
    validate_analyzer_result(analyzer_id, &assignment, result)
}

fn validate_analyzer_result(
    analyzer_id: AnalyzerId,
    assignment: &[ArtifactId],
    result: AnalyzerResult,
) -> AnalyzerResult {
    let assigned = assignment.len() as u64;
    let assignment = assignment.iter().collect::<BTreeSet<_>>();
    let invalid_coverage = result.coverage.analyzer_id != analyzer_id
        || result.coverage.eligible != assigned
        || result.coverage.assigned != assigned;
    let invalid_observation = result
        .observations
        .iter()
        .any(|observation| match observation {
            NormalizedObservation::Finding(finding) => {
                finding.analyzer_id != analyzer_id || !assignment.contains(&finding.artifact_id)
            }
            NormalizedObservation::Classification(classification) => {
                classification.analyzer_id != analyzer_id
                    || classification
                        .subject_artifacts
                        .iter()
                        .any(|artifact_id| !assignment.contains(artifact_id))
            }
        });
    if !invalid_coverage && !invalid_observation {
        return result;
    }
    AnalyzerResult {
        observations: Vec::new(),
        issues: vec![issue(
            IssueCode::InvalidAnalyzerOutput,
            Some(analyzer_id.clone()),
            "analyzer output does not match its frozen assignment",
        )],
        coverage: incomplete_coverage(analyzer_id, assigned),
    }
}

fn preparation_failure(
    pipeline: &CompiledPipeline,
    manifest: &ArtifactManifest,
    analyzer_id: Option<AnalyzerId>,
    message: &'static str,
) -> PipelineResult {
    let assigned = manifest.artifacts().len() as u64;
    PipelineResult {
        execution: PipelineExecution::default(),
        observations: Vec::new(),
        issues: vec![issue(IssueCode::InternalFailure, analyzer_id, message)],
        coverage: pipeline
            .stages
            .iter()
            .flat_map(|stage| &stage.analyzers)
            .map(|analyzer| incomplete_coverage(analyzer.id.clone(), assigned))
            .collect(),
        complete: false,
    }
}

fn append_unrun(
    prepared: &[Vec<PreparedAnalyzer>],
    failed_stage: usize,
    next_analyzer: usize,
    coverage: &mut Vec<AnalyzerCoverage>,
) {
    for (stage_index, stage) in prepared.iter().enumerate().skip(failed_stage) {
        let start = if stage_index == failed_stage {
            next_analyzer
        } else {
            0
        };
        coverage.extend(stage.iter().skip(start).map(|item| {
            incomplete_coverage(item.analyzer.id.clone(), item.assignment.len() as u64)
        }));
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

fn canonicalize(result: &mut PipelineResult) {
    result
        .observations
        .sort_by(|left, right| observation_id(left).cmp(observation_id(right)));
    let mut ids = BTreeSet::new();
    if result
        .observations
        .iter()
        .any(|observation| !ids.insert(observation_id(observation).clone()))
    {
        result.observations.clear();
        result.issues.push(issue(
            IssueCode::InvalidAnalyzerOutput,
            None,
            "analyzers returned duplicate observation identifiers",
        ));
    }
    result.issues.sort_by(|left, right| {
        left.analyzer_id
            .cmp(&right.analyzer_id)
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });
}

fn issue(
    code: IssueCode,
    analyzer_id: Option<AnalyzerId>,
    message: &'static str,
) -> InspectionIssue {
    InspectionIssue {
        phase: InspectionPhase::Initial,
        code,
        analyzer_id,
        subject_id: None,
        artifact_id: None,
        message: SanitizedMessage::new(message).expect("static pipeline diagnostic is safe"),
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
    use crate::authorization::{CaptureLimits, Snapshotter};
    use crate::domain::{
        ArtifactKind, Finding, FindingCategory, ObservationId, ReasonCode, RuleId, RunId,
        SafeEvidence, Severity,
    };
    use crate::pipeline::{
        CompiledStage, EligibilitySelector, PriorObservationMode, ProjectionLimits, StageId,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        workspace: Arc<InvocationWorkspace>,
        manifest: Arc<ArtifactManifest>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new().unwrap();
            let workspace_root = root.path().join("workspaces");
            fs::create_dir(&workspace_root).unwrap();
            fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700)).unwrap();
            let input = root.path().join("input");
            fs::create_dir(&input).unwrap();
            fs::write(input.join("artifact.txt"), "fixture").unwrap();
            let workspace = Arc::new(
                InvocationWorkspace::create(
                    &workspace_root,
                    &RunId::from_suffix("executor-test").unwrap(),
                )
                .unwrap(),
            );
            let manifest = Snapshotter::new(workspace.as_ref(), CaptureLimits::default())
                .capture(&input)
                .unwrap()
                .manifest;
            Self {
                workspace,
                manifest: Arc::new(manifest),
                _root: root,
            }
        }
    }

    fn analyzer(
        id: &str,
        run: impl Fn(TestAnalyzerInput) -> TestAnalyzerOutput + Send + Sync + 'static,
    ) -> CompiledAnalyzer {
        CompiledAnalyzer::new(
            AnalyzerId::new(id).unwrap(),
            true,
            EligibilitySelector::compile(&["**".to_string()], &[], [ArtifactKind::PhysicalFile])
                .unwrap(),
            AnalyzerImplementation::Test(TestAnalyzer { run: Arc::new(run) }),
        )
    }

    fn stage(
        id: &str,
        execution: StageExecution,
        analyzers: Vec<CompiledAnalyzer>,
        prior: PriorObservationMode,
        limits: ProjectionLimits,
    ) -> CompiledStage {
        CompiledStage::new(
            StageId::new(id).unwrap(),
            execution,
            analyzers,
            prior,
            limits,
        )
        .unwrap()
    }

    fn success(observations: Vec<NormalizedObservation>) -> TestAnalyzerOutput {
        TestAnalyzerOutput {
            observations,
            issues: Vec::new(),
            complete: true,
        }
    }

    fn finding(
        id: &str,
        analyzer_id: AnalyzerId,
        artifact_id: ArtifactId,
    ) -> NormalizedObservation {
        NormalizedObservation::Finding(Finding {
            id: ObservationId::from_suffix(id).unwrap(),
            analyzer_id,
            rule_id: RuleId::new("test-rule").unwrap(),
            artifact_id,
            category: FindingCategory::ContentPattern,
            severity: Severity::Medium,
            location: None,
            evidence: SafeEvidence {
                reason_codes: vec![ReasonCode::new("test-reason").unwrap()],
            },
        })
    }

    fn limits() -> ProjectionLimits {
        ProjectionLimits::new(100, 16_384).unwrap()
    }

    #[tokio::test]
    async fn same_stage_prior_is_frozen_and_later_stage_sees_canonical_output() {
        let fixture = Fixture::new();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observe = |expected_id: &'static str,
                       seen: Arc<std::sync::Mutex<Vec<(String, usize)>>>| {
            analyzer(expected_id, move |input| {
                seen.lock()
                    .unwrap()
                    .push((input.analyzer_id.as_str().to_string(), input.prior_count));
                success(Vec::new())
            })
        };
        let producer = analyzer("producer", |input| {
            assert_eq!(input.prior_count, 0);
            assert_eq!(input.assigned, 1);
            success(vec![finding(
                "produced",
                input.analyzer_id,
                input.assignment[0].clone(),
            )])
        });
        let pipeline = CompiledPipeline::new(vec![
            stage(
                "first",
                StageExecution::Serial,
                vec![producer, observe("peer", Arc::clone(&seen))],
                PriorObservationMode::AllNormalized,
                limits(),
            ),
            stage(
                "second",
                StageExecution::Serial,
                vec![observe("later", Arc::clone(&seen))],
                PriorObservationMode::AllNormalized,
                limits(),
            ),
        ])
        .unwrap();

        let result = PipelineExecutor::execute(
            &pipeline,
            Arc::clone(&fixture.manifest),
            Arc::clone(&fixture.workspace),
        )
        .await;

        assert!(result.complete);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![("peer".to_string(), 0), ("later".to_string(), 1)]
        );
    }

    #[tokio::test]
    async fn parallel_stage_enforces_ceiling_and_canonicalizes_completion_order() {
        let fixture = Fixture::new();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut analyzers = Vec::new();
        for (id, delay_ms, observation) in [("one", 40, "z"), ("two", 5, "a"), ("three", 5, "m")] {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            analyzers.push(analyzer(id, move |input| {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(delay_ms));
                active.fetch_sub(1, Ordering::SeqCst);
                success(vec![finding(
                    observation,
                    input.analyzer_id,
                    input.assignment[0].clone(),
                )])
            }));
        }
        let pipeline = CompiledPipeline::new(vec![stage(
            "parallel",
            StageExecution::Parallel { max_concurrency: 2 },
            analyzers,
            PriorObservationMode::None,
            limits(),
        )])
        .unwrap();

        let result = PipelineExecutor::execute(
            &pipeline,
            Arc::clone(&fixture.manifest),
            Arc::clone(&fixture.workspace),
        )
        .await;

        assert!(result.complete);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(
            result
                .observations
                .iter()
                .map(|item| observation_id(item).as_str())
                .collect::<Vec<_>>(),
            vec!["obs_a", "obs_m", "obs_z"]
        );
    }

    #[tokio::test]
    async fn required_failure_drains_launched_batch_and_marks_all_later_work_unrun() {
        let fixture = Fixture::new();
        let drained = Arc::new(AtomicUsize::new(0));
        let failed = analyzer("failed", |_| TestAnalyzerOutput {
            observations: Vec::new(),
            issues: Vec::new(),
            complete: false,
        });
        let drained_task = {
            let drained = Arc::clone(&drained);
            analyzer("drained", move |_| {
                std::thread::sleep(Duration::from_millis(20));
                drained.fetch_add(1, Ordering::SeqCst);
                success(Vec::new())
            })
        };
        let pipeline = CompiledPipeline::new(vec![
            stage(
                "failed-stage",
                StageExecution::Parallel { max_concurrency: 2 },
                vec![
                    failed,
                    drained_task,
                    analyzer("same-unrun", |_| success(Vec::new())),
                ],
                PriorObservationMode::None,
                limits(),
            ),
            stage(
                "later-stage",
                StageExecution::Serial,
                vec![analyzer("later-unrun", |_| success(Vec::new()))],
                PriorObservationMode::None,
                limits(),
            ),
        ])
        .unwrap();

        let result = PipelineExecutor::execute(
            &pipeline,
            Arc::clone(&fixture.manifest),
            Arc::clone(&fixture.workspace),
        )
        .await;

        assert!(!result.complete);
        assert_eq!(drained.load(Ordering::SeqCst), 1);
        assert_eq!(result.coverage.len(), 4);
        assert_eq!(result.execution.analyzers_completed, 1);
        assert_eq!(result.execution.stages_completed, 0);
    }

    #[tokio::test]
    async fn prior_projection_overflow_stops_stage_before_any_analyzer_runs() {
        let fixture = Fixture::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let producer = analyzer("producer", |input| {
            success(vec![finding(
                "produced",
                input.analyzer_id,
                input.assignment[0].clone(),
            )])
        });
        let consumer = {
            let ran = Arc::clone(&ran);
            analyzer("consumer", move |_| {
                ran.fetch_add(1, Ordering::SeqCst);
                success(Vec::new())
            })
        };
        let pipeline = CompiledPipeline::new(vec![
            stage(
                "producer-stage",
                StageExecution::Serial,
                vec![producer],
                PriorObservationMode::None,
                limits(),
            ),
            stage(
                "limited-stage",
                StageExecution::Serial,
                vec![consumer],
                PriorObservationMode::AllNormalized,
                ProjectionLimits::new(100, 1).unwrap(),
            ),
        ])
        .unwrap();

        let result = PipelineExecutor::execute(
            &pipeline,
            Arc::clone(&fixture.manifest),
            Arc::clone(&fixture.workspace),
        )
        .await;

        assert!(!result.complete);
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(result.execution.stages_completed, 1);
        assert_eq!(result.coverage.len(), 2);
        assert_eq!(
            result.issues[0].code,
            IssueCode::RequiredAnalyzerBudgetExceeded
        );
    }
}
