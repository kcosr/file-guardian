use super::{
    AnalyzerImplementation, ArtifactAssignment, CompiledAnalyzer, CompiledPipeline,
    PriorObservationProjection, StageExecution, UnsupportedAnalyzerKind,
};
use crate::authorization::InvocationWorkspace;
use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, ArtifactManifest, CoverageStatus, InspectionIssue,
    InspectionPhase, IssueCode, NormalizedObservation, SanitizedMessage,
};
use futures_util::future::join_all;
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
impl TestAnalyzer {
    pub(super) fn blocking(
        started: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) -> Self {
        Self {
            run: Arc::new(move |_| {
                started.wait();
                release.wait();
                TestAnalyzerOutput {
                    observations: Vec::new(),
                    issues: Vec::new(),
                    complete: true,
                }
            }),
        }
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
    assignment: Vec<ArtifactAssignment>,
}

#[derive(Clone, Debug)]
struct AnalyzerResult {
    observations: Vec<NormalizedObservation>,
    issues: Vec<InspectionIssue>,
    coverage: AnalyzerCoverage,
}

#[derive(Clone, Debug)]
struct PreparationFailure {
    analyzer_id: Option<AnalyzerId>,
    message: &'static str,
    coverage: Vec<AnalyzerCoverage>,
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
            Err(failure) => return preparation_failure(failure),
        };
        if !manifest.artifacts().is_empty()
            && prepared
                .iter()
                .flatten()
                .filter(|prepared| prepared.analyzer.required)
                .all(|prepared| prepared.assignment.is_empty())
        {
            let coverage = prepared
                .iter()
                .flatten()
                .map(|prepared| incomplete_coverage(prepared.analyzer.id.clone(), 0))
                .collect();
            return PipelineResult {
                execution: PipelineExecution::default(),
                observations: Vec::new(),
                issues: vec![issue(
                    IssueCode::IncompleteCoverage,
                    None,
                    "no required analyzer was assigned any captured artifact",
                )],
                coverage,
                complete: false,
            };
        }

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
) -> Result<Vec<Vec<PreparedAnalyzer>>, PreparationFailure> {
    prepare_with(pipeline, |analyzer| {
        analyzer
            .eligibility
            .assign(&analyzer.id, manifest)
            .map(|selection| selection.assignments)
            .map_err(|_| ())
    })
}

fn prepare_with(
    pipeline: &CompiledPipeline,
    mut assign: impl FnMut(&CompiledAnalyzer) -> Result<Vec<ArtifactAssignment>, ()>,
) -> Result<Vec<Vec<PreparedAnalyzer>>, PreparationFailure> {
    let mut prepared = Vec::with_capacity(pipeline.stages.len());
    let mut coverage = Vec::new();
    let mut first_failure = None;

    for stage in &pipeline.stages {
        let mut prepared_stage = Vec::with_capacity(stage.analyzers.len());
        for analyzer in &stage.analyzers {
            match assign(analyzer) {
                Ok(assignment) => {
                    coverage.push(incomplete_coverage(
                        analyzer.id.clone(),
                        assignment.len() as u64,
                    ));
                    prepared_stage.push(PreparedAnalyzer {
                        analyzer: analyzer.clone(),
                        assignment,
                    });
                }
                Err(()) => {
                    first_failure.get_or_insert_with(|| analyzer.id.clone());
                    // Assignment construction failed, so no eligible or assigned
                    // count is known for this analyzer. Zero is the coverage
                    // contract's representation for that unknown, not a claim
                    // that the analyzer's selector matched the whole manifest.
                    coverage.push(incomplete_coverage(analyzer.id.clone(), 0));
                }
            }
        }
        prepared.push(prepared_stage);
    }

    if let Some(analyzer_id) = first_failure {
        Err(PreparationFailure {
            analyzer_id: Some(analyzer_id),
            message: "analyzer candidate assignment could not be constructed",
            coverage,
        })
    } else {
        Ok(prepared)
    }
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
        let mut futures = Vec::with_capacity(batch.len());
        for prepared in batch {
            let prepared = prepared.clone();
            let manifest = Arc::clone(&manifest);
            let workspace = Arc::clone(&workspace);
            let projection = Arc::clone(&projection);
            futures.push((prepared.analyzer.id.clone(), async move {
                execute_analyzer(prepared, manifest, workspace, projection).await
            }));
        }

        let mut batch_failed = false;
        let batch_results = join_all(
            futures
                .into_iter()
                .map(|(analyzer_id, future)| async move { (analyzer_id, future.await) }),
        )
        .await;
        for (_analyzer_id, result) in batch_results {
            batch_failed |= !result.coverage.is_complete() || !result.issues.is_empty();
            results.push(Some(result));
        }
        if batch_failed {
            break;
        }
    }
    results
}

async fn execute_analyzer(
    prepared: PreparedAnalyzer,
    manifest: Arc<ArtifactManifest>,
    workspace: Arc<InvocationWorkspace>,
    _projection: Arc<PriorObservationProjection>,
) -> AnalyzerResult {
    let assigned = prepared.assignment.len() as u64;
    let analyzer_id = prepared.analyzer.id.clone();
    let assignment = prepared
        .assignment
        .iter()
        .map(|assignment| assignment.artifact_id.clone())
        .collect::<Vec<_>>();
    let result = match prepared.analyzer.implementation {
        AnalyzerImplementation::Builtin(analyzer) => {
            let analyzer_id = prepared.analyzer.id.clone();
            let analyzer_assignment = assignment.clone();
            let result = tokio::task::spawn_blocking(move || {
                analyzer.analyze(
                    InspectionPhase::Initial,
                    &manifest,
                    &analyzer_assignment,
                    workspace.objects(),
                )
            })
            .await;
            match result {
                Ok(Ok(result)) => AnalyzerResult {
                    observations: result.observations,
                    issues: result.issues,
                    coverage: result.coverage,
                },
                Ok(Err(_)) => AnalyzerResult {
                    observations: Vec::new(),
                    issues: vec![issue(
                        IssueCode::InvalidAnalyzerOutput,
                        Some(analyzer_id.clone()),
                        "built-in analyzer rejected its assigned candidates",
                    )],
                    coverage: incomplete_coverage(analyzer_id.clone(), assigned),
                },
                Err(_) => AnalyzerResult {
                    observations: Vec::new(),
                    issues: vec![issue(
                        IssueCode::RequiredAnalyzerProcessFailure,
                        Some(analyzer_id.clone()),
                        "built-in analyzer task did not complete",
                    )],
                    coverage: incomplete_coverage(analyzer_id.clone(), assigned),
                },
            }
        }
        AnalyzerImplementation::Pi(analyzer) => {
            match analyzer
                .analyze(
                    Arc::clone(&manifest),
                    prepared.assignment.clone(),
                    Arc::clone(&workspace),
                    Arc::clone(&_projection),
                )
                .await
            {
                Ok(observations) => AnalyzerResult {
                    observations,
                    issues: Vec::new(),
                    coverage: AnalyzerCoverage::new(
                        analyzer_id.clone(),
                        InspectionPhase::Initial,
                        assigned,
                        assigned,
                        assigned,
                        0,
                        CoverageStatus::Complete,
                    )
                    .expect("complete Pi coverage is valid"),
                },
                Err(error) => AnalyzerResult {
                    observations: Vec::new(),
                    issues: vec![issue(
                        pi_issue_code(&error),
                        Some(analyzer_id.clone()),
                        pi_issue_message(&error),
                    )],
                    coverage: incomplete_coverage(analyzer_id.clone(), assigned),
                },
            }
        }
        AnalyzerImplementation::Unsupported { kind } => AnalyzerResult {
            observations: Vec::new(),
            issues: vec![issue(
                IssueCode::RequiredAnalyzerProcessFailure,
                Some(prepared.analyzer.id.clone()),
                match kind {
                    UnsupportedAnalyzerKind::External => {
                        "selected external analyzer is not implemented"
                    }
                    #[cfg(test)]
                    UnsupportedAnalyzerKind::Pi => "selected Pi test analyzer is unsupported",
                },
            )],
            coverage: incomplete_coverage(prepared.analyzer.id, assigned),
        },
        #[cfg(test)]
        AnalyzerImplementation::Test(test) => {
            let input = TestAnalyzerInput {
                analyzer_id: prepared.analyzer.id.clone(),
                assigned,
                assignment: assignment.clone(),
                prior_count: _projection.observations().len(),
            };
            let output = match tokio::task::spawn_blocking(move || (test.run)(input)).await {
                Ok(output) => output,
                Err(_) => {
                    return AnalyzerResult {
                        observations: Vec::new(),
                        issues: vec![issue(
                            IssueCode::RequiredAnalyzerProcessFailure,
                            Some(analyzer_id.clone()),
                            "test analyzer task did not complete",
                        )],
                        coverage: incomplete_coverage(analyzer_id, assigned),
                    };
                }
            };
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

fn preparation_failure(failure: PreparationFailure) -> PipelineResult {
    PipelineResult {
        execution: PipelineExecution::default(),
        observations: Vec::new(),
        issues: vec![issue(
            IssueCode::InternalFailure,
            failure.analyzer_id,
            failure.message,
        )],
        coverage: failure.coverage,
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

fn pi_issue_code(error: &crate::analyzers::pi::PiClassifierError) -> IssueCode {
    use crate::analyzers::pi::proxy::PiProxyError;
    use crate::analyzers::pi::runner::{PiRunError, PiTimeoutKind};
    match error {
        crate::analyzers::pi::PiClassifierError::Runner(PiRunError::Timeout(
            PiTimeoutKind::Startup | PiTimeoutKind::Idle | PiTimeoutKind::Wall,
        )) => IssueCode::RequiredAnalyzerTimeout,
        crate::analyzers::pi::PiClassifierError::Runner(PiRunError::OutputLimit(_)) => {
            IssueCode::RequiredAnalyzerBudgetExceeded
        }
        crate::analyzers::pi::PiClassifierError::Proxy(
            PiProxyError::BudgetExceeded
            | PiProxyError::FrameTooLarge
            | PiProxyError::ResponseTooLarge,
        ) => IssueCode::RequiredAnalyzerBudgetExceeded,
        crate::analyzers::pi::PiClassifierError::Proxy(PiProxyError::FrameReadTimeout) => {
            IssueCode::RequiredAnalyzerTimeout
        }
        crate::analyzers::pi::PiClassifierError::Proxy(_) => {
            IssueCode::RequiredAnalyzerProtocolFailure
        }
        crate::analyzers::pi::PiClassifierError::Runner(_) => {
            IssueCode::RequiredAnalyzerProcessFailure
        }
    }
}

fn pi_issue_message(error: &crate::analyzers::pi::PiClassifierError) -> &'static str {
    match pi_issue_code(error) {
        IssueCode::RequiredAnalyzerTimeout => "required Pi analyzer exceeded a time budget",
        IssueCode::RequiredAnalyzerBudgetExceeded => {
            "required Pi analyzer exceeded an output budget"
        }
        IssueCode::RequiredAnalyzerProtocolFailure => {
            "required Pi analyzer violated its authenticated protocol"
        }
        _ => "required sandboxed Pi analyzer process failed",
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
    use std::sync::Barrier;
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
        analyzer_with_selector(id, &["**"], run)
    }

    fn analyzer_with_selector(
        id: &str,
        include: &[&str],
        run: impl Fn(TestAnalyzerInput) -> TestAnalyzerOutput + Send + Sync + 'static,
    ) -> CompiledAnalyzer {
        CompiledAnalyzer::new(
            AnalyzerId::new(id).unwrap(),
            true,
            EligibilitySelector::compile(
                &include
                    .iter()
                    .map(|pattern| (*pattern).to_string())
                    .collect::<Vec<_>>(),
                &[],
                [ArtifactKind::PhysicalFile],
            )
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
        let first_batch_started = Arc::new(Barrier::new(2));
        let mut analyzers = Vec::new();
        for (index, (id, observation)) in [("one", "z"), ("two", "a"), ("three", "m")]
            .into_iter()
            .enumerate()
        {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let first_batch_started = Arc::clone(&first_batch_started);
            analyzers.push(analyzer(id, move |input| {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                if index < 2 {
                    // Neither member of the first batch can finish until both
                    // are running, deterministically proving actual overlap.
                    first_batch_started.wait();
                }
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

    #[test]
    fn preparation_failure_reports_exact_successful_assignments_and_zero_for_unknown() {
        let fixture = Fixture::new();
        let pipeline = CompiledPipeline::new(vec![stage(
            "prepare",
            StageExecution::Serial,
            vec![
                analyzer_with_selector("selected", &["artifact.txt"], |_| success(Vec::new())),
                analyzer_with_selector("unselected", &["*.rs"], |_| success(Vec::new())),
                analyzer_with_selector("failed", &["artifact.txt"], |_| success(Vec::new())),
            ],
            PriorObservationMode::None,
            limits(),
        )])
        .unwrap();

        let failure = prepare_with(&pipeline, |analyzer| {
            if analyzer.id.as_str() == "failed" {
                return Err(());
            }
            analyzer
                .eligibility
                .assign(&analyzer.id, &fixture.manifest)
                .map(|selection| selection.assignments)
                .map_err(|_| ())
        })
        .unwrap_err();
        let result = preparation_failure(failure);

        assert_eq!(
            result
                .coverage
                .iter()
                .map(|row| (row.analyzer_id.as_str(), row.eligible, row.assigned))
                .collect::<Vec<_>>(),
            vec![("selected", 1, 1), ("unselected", 0, 0), ("failed", 0, 0)]
        );
        assert_eq!(
            result.issues[0]
                .analyzer_id
                .as_ref()
                .map(AnalyzerId::as_str),
            Some("failed")
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

    #[tokio::test]
    async fn nonempty_manifest_with_no_required_assignment_fails_closed() {
        let fixture = Fixture::new();
        let pipeline = CompiledPipeline::new(vec![stage(
            "unmatched",
            StageExecution::Serial,
            vec![
                analyzer_with_selector("first", &["*.rs"], |_| success(Vec::new())),
                analyzer_with_selector("second", &["vendor/**"], |_| success(Vec::new())),
            ],
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

        assert!(!result.complete);
        assert_eq!(result.issues[0].code, IssueCode::IncompleteCoverage);
        assert_eq!(result.coverage.len(), 2);
        assert!(result
            .coverage
            .iter()
            .all(|row| row.eligible == 0 && row.assigned == 0 && row.completed == 0));
    }

    #[tokio::test]
    async fn one_zero_eligibility_analyzer_is_valid_when_another_covers_the_manifest() {
        let fixture = Fixture::new();
        let pipeline = CompiledPipeline::new(vec![stage(
            "mixed",
            StageExecution::Serial,
            vec![
                analyzer_with_selector("unmatched", &["*.rs"], |_| success(Vec::new())),
                analyzer("matched", |_| success(Vec::new())),
            ],
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
        assert_eq!(result.coverage.len(), 2);
        assert_eq!(result.coverage[0].assigned, 0);
        assert_eq!(result.coverage[1].assigned, 1);
    }

    #[tokio::test]
    async fn empty_manifest_with_zero_assignments_remains_valid() {
        let fixture = Fixture::new();
        let empty_manifest = Arc::new(ArtifactManifest::new(Vec::new(), Vec::new()).unwrap());
        let pipeline = CompiledPipeline::new(vec![stage(
            "empty",
            StageExecution::Serial,
            vec![analyzer("required", |_| success(Vec::new()))],
            PriorObservationMode::None,
            limits(),
        )])
        .unwrap();

        let result =
            PipelineExecutor::execute(&pipeline, empty_manifest, Arc::clone(&fixture.workspace))
                .await;

        assert!(result.complete);
        assert_eq!(result.execution.stages_completed, 1);
        assert_eq!(result.execution.analyzers_completed, 1);
        assert_eq!(result.coverage[0].assigned, 0);
        assert_eq!(result.coverage[0].completed, 0);
    }
}
