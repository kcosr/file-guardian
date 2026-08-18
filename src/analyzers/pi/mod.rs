//! Sandboxed Pi prior-finding triage and attestation support.

pub mod protocol;
pub(crate) mod proxy;
pub(crate) mod runner;
pub(crate) mod sandbox;
pub mod triage;

use std::path::PathBuf;

use self::protocol::{ClassificationVocabulary, TerminalValidationLimits};
use self::proxy::{
    ExpectedPiRuntime, PiProxy, PiProxyInput, PiProxyLimits, NATIVE_SEARCH_MAX_RESULTS,
};
use self::runner::{PiInvocationSpec, PiRunError, PiRunLimits, PiRunSignals, PiRunner};
#[cfg(test)]
use self::sandbox::PI_RUNTIME_CONTEXT_MODE;
use self::sandbox::{PiRuntimeSpec, PreparedPiRuntime};
use self::triage::{
    PiReviewScope, PiStageAttestation, PiTriageCoverage, PiTriageInvocationId, PiTriageLimits,
    PiTriageRequest, PiTriageRequestContext, PiTriageResult, PiTriageVocabulary, PriorFinding,
    PriorFindingArtifact, PriorOccurrence,
};
use crate::analyzers::{
    assess_text_artifact, RequiredTextMatcher, TextApplicabilityError, TextArtifactDisposition,
};
use crate::authorization::{
    AnalyzerView, AnalyzerViewBuilder, AnalyzerViewError, AnalyzerViewLimits, InvocationWorkspace,
};
use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactManifest, CoverageStatus, Digest, InspectionPhase,
    NormalizedObservation, Provenance, RunId,
};
use crate::pipeline::{ArtifactAssignment, PriorObservationProjection};
use crate::processing::{
    CorrelationId, CredentialVerificationState, FindingId, GitHistoryScope, OccurrenceId,
};
use std::ffi::OsString;
#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{oneshot, watch};

const FIXED_TASK: &[u8] = b"Assess every deterministic finding using the exact matched evidence in triage_request and the exact staged repository or directory mounted read-only at /input. For Git-history findings, use the supplied commit/blob/ref provenance and ordinary Git commands against /input. Decide whether each deterministic result is correct or a false positive, then submit exactly one candidate-free terminal triage response.\n";

struct ProxySignalBridge {
    signals: Option<PiRunSignals>,
    runner_done: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ProxySignalBridge {
    fn start(mut progress: watch::Receiver<proxy::ProxyProgress>) -> Self {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (activity_tx, activity_rx) = watch::channel(0_u64);
        let (runner_done_tx, mut runner_done_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut ready_tx = Some(ready_tx);
            loop {
                let state = *progress.borrow_and_update();
                activity_tx.send_replace(state.authenticated_requests);
                if state.runtime_ready {
                    if let Some(sender) = ready_tx.take() {
                        let _ = sender.send(());
                    }
                }
                tokio::select! {
                    _ = &mut runner_done_rx => break,
                    changed = progress.changed() => {
                        if changed.is_err() {
                            if state.terminal_submitted {
                                let _ = runner_done_rx.await;
                            }
                            break;
                        }
                    }
                }
            }
        });
        Self {
            signals: Some(PiRunSignals {
                runtime_ready: ready_rx,
                activity: activity_rx,
            }),
            runner_done: Some(runner_done_tx),
            task,
        }
    }

    fn take_signals(&mut self) -> PiRunSignals {
        self.signals
            .take()
            .expect("proxy signals are consumed once")
    }

    async fn stop(mut self) {
        if let Some(runner_done) = self.runner_done.take() {
            let _ = runner_done.send(());
        }
        let _ = self.task.await;
    }
}

#[derive(Clone)]
pub struct PiClassifierAnalyzer {
    id: AnalyzerId,
    run_id: RunId,
    runner: PiRunnerBackend,
    instruction: Arc<str>,
    vocabulary: Arc<ClassificationVocabulary>,
    expected_runtime: ExpectedPiRuntime,
    terminal_limits: TerminalValidationLimits,
    proxy_limits: PiProxyLimits,
    run_limits: PiRunLimits,
    max_search_results: u64,
    required_text: RequiredTextMatcher,
    max_text_bytes: u64,
    view_limits: AnalyzerViewLimits,
    credential_environment: Arc<Vec<(OsString, OsString)>>,
    identity: Digest,
}

#[derive(Clone)]
enum PiRunnerBackend {
    Process(Box<PiRunner>),
    #[cfg(test)]
    Fake(Arc<dyn Fn(FakePiInvocation) -> FakePiFuture + Send + Sync>),
}

#[cfg(test)]
type FakePiFuture = Pin<Box<dyn Future<Output = Result<(), PiRunError>> + Send>>;

#[cfg(test)]
#[derive(Clone)]
struct FakePiInvocation {
    socket_path: std::path::PathBuf,
    analyzer_input_view: std::path::PathBuf,
    token: String,
    run_id: RunId,
    analyzer_id: AnalyzerId,
    manifest_identity: Digest,
}

impl std::fmt::Debug for PiClassifierAnalyzer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PiClassifierAnalyzer")
            .field("id", &self.id)
            .field("identity", &self.identity)
            .field(
                "credential_names",
                &self
                    .credential_environment
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

pub(crate) struct PiClassifierSpec {
    pub id: AnalyzerId,
    pub run_id: RunId,
    pub runtime: PiRuntimeSpec,
    pub instruction: Arc<str>,
    pub vocabulary: ClassificationVocabulary,
    pub expected_runtime: ExpectedPiRuntime,
    pub terminal_limits: TerminalValidationLimits,
    pub proxy_limits: PiProxyLimits,
    pub run_limits: PiRunLimits,
    pub max_search_results: u64,
    pub required_text: RequiredTextMatcher,
    pub max_text_bytes: u64,
    pub view_limits: AnalyzerViewLimits,
    pub credential_environment: Vec<(OsString, OsString)>,
    pub identity_material: Vec<u8>,
}

impl PiClassifierAnalyzer {
    pub(crate) fn compile(spec: PiClassifierSpec) -> Result<Self, PiClassifierCompileError> {
        if spec.max_search_results == 0
            || spec.max_search_results > NATIVE_SEARCH_MAX_RESULTS
            || spec.max_search_results != spec.proxy_limits.max_search_matches
        {
            return Err(PiClassifierCompileError::InconsistentSearchLimits);
        }
        let runtime = PreparedPiRuntime::prepare(spec.runtime)?;
        let mut identity_material = spec.identity_material;
        identity_material.extend_from_slice(&runtime.identity());
        identity_material.extend_from_slice(spec.instruction.as_bytes());
        let identity = Digest::sha256(identity_material);
        Ok(Self {
            id: spec.id,
            run_id: spec.run_id,
            runner: PiRunnerBackend::Process(Box::new(PiRunner::new(runtime))),
            instruction: spec.instruction,
            vocabulary: Arc::new(spec.vocabulary),
            expected_runtime: spec.expected_runtime,
            terminal_limits: spec.terminal_limits,
            proxy_limits: spec.proxy_limits,
            run_limits: spec.run_limits,
            max_search_results: spec.max_search_results,
            required_text: spec.required_text,
            max_text_bytes: spec.max_text_bytes,
            view_limits: spec.view_limits,
            credential_environment: Arc::new(spec.credential_environment),
            identity,
        })
    }

    pub fn identity(&self) -> Digest {
        self.identity
    }

    pub(crate) async fn analyze(
        &self,
        manifest: Arc<ArtifactManifest>,
        assignments: Vec<ArtifactAssignment>,
        workspace: Arc<InvocationWorkspace>,
        prior: Arc<PriorObservationProjection>,
    ) -> Result<PiClassifierResult, PiClassifierError> {
        self.analyze_internal(manifest, assignments, workspace, Some(prior), None, None)
            .await
    }

    pub(crate) async fn analyze_triage(
        &self,
        manifest: Arc<ArtifactManifest>,
        assignments: Vec<ArtifactAssignment>,
        workspace: Arc<InvocationWorkspace>,
        request: Arc<PiTriageRequest>,
        staged_input: Option<PathBuf>,
    ) -> Result<PiClassifierResult, PiClassifierError> {
        self.analyze_internal(
            manifest,
            assignments,
            workspace,
            None,
            Some(request),
            staged_input,
        )
        .await
    }

    async fn analyze_internal(
        &self,
        manifest: Arc<ArtifactManifest>,
        assignments: Vec<ArtifactAssignment>,
        workspace: Arc<InvocationWorkspace>,
        prior: Option<Arc<PriorObservationProjection>>,
        supplied_request: Option<Arc<PiTriageRequest>>,
        staged_input: Option<PathBuf>,
    ) -> Result<PiClassifierResult, PiClassifierError> {
        let assigned =
            u64::try_from(assignments.len()).map_err(|_| PiClassifierError::PreparationTask)?;
        let phase = supplied_request
            .as_ref()
            .map_or(InspectionPhase::Initial, |request| request.phase);
        if supplied_request.as_ref().is_some_and(|request| {
            request.run_id != self.run_id
                || request.manifest_identity != manifest.identity
                || request.assigned_artifact_count != assigned
                || request.validate_identity().is_err()
        }) {
            return Err(PiClassifierError::InvalidAssignment);
        }
        let manifest_for_preparation = Arc::clone(&manifest);
        let workspace_for_preparation = Arc::clone(&workspace);
        let required_text = self.required_text.clone();
        let max_text_bytes = self.max_text_bytes;
        let view_limits = self.view_limits;
        let view_digest = Digest::sha256(self.id.as_str()).to_string();
        let view_name = format!(
            "pi-{}",
            view_digest
                .strip_prefix("sha256:")
                .expect("Digest display has a fixed algorithm prefix")
        );
        let prepared = tokio::task::spawn_blocking(move || -> Result<_, PiClassifierError> {
            let mut applicable = Vec::with_capacity(assignments.len());
            let mut not_applicable = 0_u64;
            for assignment in assignments {
                let artifact = manifest_for_preparation
                    .artifact(&assignment.artifact_id)
                    .ok_or(PiClassifierError::InvalidAssignment)?;
                match assess_text_artifact(
                    artifact,
                    workspace_for_preparation.objects(),
                    max_text_bytes,
                    &required_text,
                )? {
                    TextArtifactDisposition::Text(_) => applicable.push(assignment),
                    TextArtifactDisposition::NotApplicableBinary => {
                        not_applicable = not_applicable
                            .checked_add(1)
                            .ok_or(PiClassifierError::PreparationTask)?;
                    }
                }
            }
            if applicable.is_empty() {
                return Ok(PreparedPiAssignments::AllNotApplicable { not_applicable });
            }
            let view = AnalyzerViewBuilder::new(
                &workspace_for_preparation,
                &manifest_for_preparation,
                &applicable,
                view_limits,
            )
            .materialize(&view_name)?;
            Ok(PreparedPiAssignments::Applicable {
                assignments: applicable,
                not_applicable,
                view: Arc::new(view),
            })
        })
        .await
        .map_err(|_| PiClassifierError::PreparationTask)??;
        let (assignments, not_applicable, view) = match prepared {
            PreparedPiAssignments::AllNotApplicable { not_applicable } => {
                return Ok(PiClassifierResult {
                    observations: Vec::new(),
                    triage_result: PiTriageResult {
                        assessments: Vec::new(),
                        stage_attestation: PiStageAttestation::UnableToAssert,
                        coverage: PiTriageCoverage {
                            assigned_artifact_count: assigned,
                            completed_artifact_count: 0,
                            not_applicable_artifact_count: not_applicable,
                            assigned_finding_count: supplied_request
                                .as_ref()
                                .map_or(0, |request| request.findings.len() as u64),
                            assessed_finding_count: 0,
                        },
                    },
                    coverage: complete_coverage(
                        self.id.clone(),
                        phase,
                        assigned,
                        0,
                        not_applicable,
                    ),
                });
            }
            PreparedPiAssignments::Applicable {
                assignments,
                not_applicable,
                view,
            } => (assignments, not_applicable, view),
        };
        let completed =
            u64::try_from(assignments.len()).map_err(|_| PiClassifierError::PreparationTask)?;
        let triage_limits = PiTriageLimits::new(
            self.terminal_limits.max_artifact_classifications,
            1,
            self.proxy_limits.max_response_bytes,
            self.proxy_limits.max_terminal_bytes,
            self.terminal_limits.max_reason_codes_per_classification,
        )
        .map_err(|_| PiClassifierError::PreparationTask)?;
        let triage_request = if let Some(request) = supplied_request {
            if request.run_id != self.run_id
                || request.manifest_identity != manifest.identity
                || request.assigned_artifact_count != assigned
            {
                return Err(PiClassifierError::InvalidAssignment);
            }
            request
        } else {
            let prior = prior.ok_or(PiClassifierError::InvalidAssignment)?;
            let findings = prior_findings(&prior, InspectionPhase::Initial, &manifest)?;
            let invocation_digest =
                Digest::sha256(format!("{}:{}:{}", self.run_id, self.id, manifest.identity));
            let invocation_suffix = invocation_digest.to_string();
            let invocation_id = PiTriageInvocationId::new(format!(
                "pii_{}",
                &invocation_suffix["sha256:".len().."sha256:".len() + 32]
            ))
            .map_err(|_| PiClassifierError::PreparationTask)?;
            Arc::new(
                PiTriageRequest::new(
                    PiTriageRequestContext {
                        run_id: self.run_id.clone(),
                        invocation_id,
                        phase: InspectionPhase::Initial,
                        manifest_identity: manifest.identity,
                        pipeline_identity: self.identity,
                        policy_identity: self.identity,
                        prompt_template_identity: Digest::sha256(self.instruction.as_bytes()),
                        prior_observations_identity: prior.identity(),
                        review_scope: PiReviewScope::new(true, GitHistoryScope::None)
                            .map_err(|_| PiClassifierError::PreparationTask)?,
                        assigned_artifact_count: assigned,
                        prior_coverage: Vec::new(),
                    },
                    findings,
                    triage_limits,
                )
                .map_err(|_| PiClassifierError::PreparationTask)?,
            )
        };
        let proxy = PiProxy::start(
            &workspace,
            PiProxyInput {
                run_id: self.run_id.clone(),
                analyzer_id: self.id.clone(),
                manifest: Arc::clone(&manifest),
                assignments,
                view: Arc::clone(&view),
                triage_request,
                instruction: Arc::clone(&self.instruction),
                expected_runtime: self.expected_runtime.clone(),
                vocabulary: Arc::new(PiTriageVocabulary::new(self.vocabulary.reason_codes())),
                triage_limits,
                limits: self.proxy_limits,
            },
        )?;

        let token = proxy.endpoint().run_token().to_owned();
        let mut bridge = ProxySignalBridge::start(proxy.progress());
        let manifest_identity = manifest.identity.to_string();
        let invocation = PiInvocationSpec {
            provider: &self.expected_runtime.provider,
            model: &self.expected_runtime.model,
            thinking: &self.expected_runtime.thinking,
            proxy_socket_path: proxy.endpoint().host_socket_path(),
            proxy_directory_fd: proxy.endpoint().directory_fd(),
            analyzer_input_view: staged_input.as_deref().unwrap_or_else(|| view.host_path()),
            proxy_token: &token,
            analyzer_id: self.id.as_str(),
            run_id: self.run_id.as_str(),
            manifest_identity: &manifest_identity,
            credential_environment: &self.credential_environment,
            fixed_task: FIXED_TASK,
            max_search_results: self.max_search_results,
            limits: self.run_limits.clone(),
            signals: bridge.take_signals(),
        };
        let run = match &self.runner {
            PiRunnerBackend::Process(runner) => runner.run(invocation).await.map(|_| ()),
            #[cfg(test)]
            PiRunnerBackend::Fake(fake) => {
                fake(FakePiInvocation {
                    socket_path: proxy.endpoint().host_socket_path().to_path_buf(),
                    analyzer_input_view: invocation.analyzer_input_view.to_path_buf(),
                    token: token.clone(),
                    run_id: self.run_id.clone(),
                    analyzer_id: self.id.clone(),
                    manifest_identity: manifest.identity,
                })
                .await
            }
        };
        bridge.stop().await;
        let proxy_result = proxy.finish().await;
        match (run, proxy_result) {
            (Ok(()), Ok(outcome)) => Ok(PiClassifierResult {
                observations: Vec::new(),
                triage_result: outcome.submission,
                coverage: complete_coverage(
                    self.id.clone(),
                    phase,
                    assigned,
                    completed,
                    not_applicable,
                ),
            }),
            (Ok(()), Err(error)) => Err(PiClassifierError::Proxy(error)),
            (Err(runner), Ok(_)) => Err(PiClassifierError::Runner(runner)),
            (Err(_runner), Err(proxy)) if proxy_failure_is_primary(&proxy) => {
                Err(PiClassifierError::Proxy(proxy))
            }
            (Err(runner), Err(_cleanup_or_missing_terminal)) => {
                Err(PiClassifierError::Runner(runner))
            }
        }
    }
}

enum PreparedPiAssignments {
    AllNotApplicable {
        not_applicable: u64,
    },
    Applicable {
        assignments: Vec<ArtifactAssignment>,
        not_applicable: u64,
        view: Arc<AnalyzerView>,
    },
}

pub(crate) struct PiClassifierResult {
    pub observations: Vec<NormalizedObservation>,
    pub triage_result: PiTriageResult,
    pub coverage: AnalyzerCoverage,
}

fn prior_findings(
    prior: &PriorObservationProjection,
    phase: InspectionPhase,
    manifest: &ArtifactManifest,
) -> Result<Vec<PriorFinding>, PiClassifierError> {
    #[derive(serde::Deserialize)]
    struct Projection {
        observations: Vec<Observation>,
    }
    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Observation {
        Finding {
            id: crate::domain::ObservationId,
            analyzer_id: AnalyzerId,
            rule_id: crate::domain::RuleId,
            artifact_id: crate::domain::ArtifactId,
            category: crate::domain::FindingCategory,
            severity: crate::domain::Severity,
            location: Option<crate::domain::ValidatedLocation>,
        },
        Classification {},
    }
    let projection: Projection = serde_json::from_slice(prior.canonical_json())
        .map_err(|_| PiClassifierError::PreparationTask)?;
    projection
        .observations
        .into_iter()
        .filter_map(|observation| match observation {
            Observation::Finding {
                id,
                analyzer_id,
                rule_id,
                artifact_id,
                category,
                severity,
                location,
            } => Some((
                id,
                analyzer_id,
                rule_id,
                artifact_id,
                category,
                severity,
                location,
            )),
            Observation::Classification {} => None,
        })
        .map(
            |(id, analyzer_id, rule_id, artifact_id, category, severity, location)| {
                let logical_path = match &manifest
                    .artifact(&artifact_id)
                    .ok_or(PiClassifierError::InvalidAssignment)?
                    .provenance
                {
                    Provenance::Physical { logical_path } => logical_path.clone(),
                    Provenance::Derived { member_path, .. } => member_path.clone(),
                };
                let finding_id = FindingId::from_suffix(id.as_str())
                    .map_err(|_| PiClassifierError::PreparationTask)?;
                PriorFinding::new(
                    finding_id,
                    CorrelationId::from_suffix(id.as_str())
                        .map_err(|_| PiClassifierError::PreparationTask)?,
                    phase,
                    analyzer_id.clone(),
                    rule_id.clone(),
                    artifact_id,
                    PriorFindingArtifact::WorkingTree { logical_path },
                    category,
                    severity,
                    location,
                    None,
                    vec![PriorOccurrence {
                        occurrence_id: OccurrenceId::from_suffix(id.as_str())
                            .map_err(|_| PiClassifierError::PreparationTask)?,
                        analyzer_id: analyzer_id.clone(),
                        rule_id: rule_id.clone(),
                        verification_state: CredentialVerificationState::NotApplicable,
                        evidence_token: None,
                        evidence: None,
                    }],
                )
                .map_err(|_| PiClassifierError::PreparationTask)
            },
        )
        .collect()
}

fn complete_coverage(
    analyzer_id: AnalyzerId,
    phase: InspectionPhase,
    assigned: u64,
    completed: u64,
    not_applicable: u64,
) -> AnalyzerCoverage {
    AnalyzerCoverage::new(
        analyzer_id,
        phase,
        assigned,
        assigned,
        completed,
        not_applicable,
        CoverageStatus::Complete,
    )
    .expect("Pi applicability counters account for every frozen assignment")
}

fn proxy_failure_is_primary(error: &proxy::PiProxyError) -> bool {
    use proxy::PiProxyError;
    matches!(
        error,
        PiProxyError::Accept(_)
            | PiProxyError::ReadEndpoint(_)
            | PiProxyError::WriteEndpoint(_)
            | PiProxyError::FrameTooLarge
            | PiProxyError::MalformedFrame
            | PiProxyError::FrameReadTimeout
            | PiProxyError::Unauthorized
            | PiProxyError::ProtocolViolation
            | PiProxyError::ConcurrentRequest
            | PiProxyError::RuntimeMismatch
            | PiProxyError::InvalidRequest
            | PiProxyError::InvalidTerminalSubmission
            | PiProxyError::BudgetExceeded
            | PiProxyError::ResponseTooLarge
            | PiProxyError::NativeToolFailed
            | PiProxyError::Internal
    )
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PiClassifierCompileError {
    #[error("Pi search-result limits are inconsistent")]
    InconsistentSearchLimits,
    #[error("Pi runtime or tool-sidecar preflight failed")]
    Runtime(#[from] sandbox::PiSandboxError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PiClassifierError {
    #[error("Pi assignment is not present in the immutable manifest")]
    InvalidAssignment,
    #[error("Pi content applicability assessment failed")]
    Applicability(#[from] TextApplicabilityError),
    #[error("Pi analyzer view materialization failed")]
    View(#[from] AnalyzerViewError),
    #[error("Pi input preparation task did not complete")]
    PreparationTask,
    #[error("Pi process or tool sidecar failed")]
    Runner(#[from] PiRunError),
    #[error("Pi proxy failed")]
    Proxy(#[from] proxy::PiProxyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{AnalyzerViewQuota, CaptureLimits, Snapshotter};
    use crate::domain::{
        ArtifactKind, ConfiguredConfidence, FindingCategory, ReasonCode, Severity,
    };
    use crate::pipeline::EligibilitySelector;
    use crate::processing::{
        CorrelationId, FindingId, OccurrenceId, PiFindingClassification, RecommendedAction,
    };
    use serde_json::{json, Value};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    struct Fixture {
        _temporary: TempDir,
        input: std::path::PathBuf,
        workspace: Arc<InvocationWorkspace>,
        manifest: Arc<ArtifactManifest>,
        run_id: RunId,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let input = temporary.path().join("input");
            let root = temporary.path().join("workspaces");
            fs::create_dir(&input).unwrap();
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(input.join("fixture.txt"), b"password = example-only").unwrap();
            fs::create_dir(input.join(".git")).unwrap();
            fs::write(input.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
            let run_id = RunId::from_suffix("pi-triage-e2e").unwrap();
            let workspace = Arc::new(InvocationWorkspace::create(&root, &run_id).unwrap());
            let manifest = Arc::new(
                Snapshotter::new(&workspace, CaptureLimits::default())
                    .capture(&input)
                    .unwrap()
                    .manifest,
            );
            Self {
                _temporary: temporary,
                input,
                workspace,
                manifest,
                run_id,
            }
        }
    }

    fn analyzer(
        fixture: &Fixture,
        fake: impl Fn(FakePiInvocation) -> FakePiFuture + Send + Sync + 'static,
    ) -> PiClassifierAnalyzer {
        PiClassifierAnalyzer {
            id: AnalyzerId::new("pi-triage").unwrap(),
            run_id: fixture.run_id.clone(),
            runner: PiRunnerBackend::Fake(Arc::new(fake)),
            instruction: Arc::from("Assess every assigned finding under the trusted policy."),
            vocabulary: Arc::new(
                ClassificationVocabulary::new(
                    [crate::domain::ClassificationCode::new("false_positive").unwrap()],
                    [ConfiguredConfidence::High],
                    [ReasonCode::new("documented_test_fixture").unwrap()],
                )
                .unwrap(),
            ),
            expected_runtime: ExpectedPiRuntime {
                pi_version: "0.83.0".to_string(),
                provider: "internal".to_string(),
                model: "triage".to_string(),
                thinking: "high".to_string(),
                mode: PI_RUNTIME_CONTEXT_MODE.to_string(),
            },
            terminal_limits: TerminalValidationLimits::new(10, 10, 10).unwrap(),
            proxy_limits: PiProxyLimits {
                max_frame_bytes: 128 * 1024,
                max_response_bytes: 128 * 1024,
                max_terminal_bytes: 128 * 1024,
                max_tool_calls: 16,
                max_bytes_read: 64 * 1024,
                max_read_bytes_per_call: 64 * 1024,
                max_search_matches: 10,
                max_search_bytes_per_call: 64 * 1024,
                max_search_calls: 2,
                frame_read_timeout: Duration::from_secs(1),
            },
            run_limits: PiRunLimits {
                startup_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(1),
                wall_timeout: Duration::from_secs(2),
                termination_grace: Duration::from_millis(50),
                cpu_seconds: 1,
                open_files: 32,
                stdout_bytes: 1024,
                stderr_bytes: 1024,
            },
            max_search_results: 10,
            required_text: RequiredTextMatcher::default(),
            max_text_bytes: 64 * 1024,
            view_limits: AnalyzerViewLimits {
                per_view: AnalyzerViewQuota {
                    max_files: 16,
                    max_entries: 64,
                    max_total_bytes: 64 * 1024,
                    max_depth: 16,
                },
                invocation: AnalyzerViewQuota {
                    max_files: 16,
                    max_entries: 64,
                    max_total_bytes: 64 * 1024,
                    max_depth: 16,
                },
            },
            credential_environment: Arc::new(Vec::new()),
            identity: Digest::sha256(b"fake-pi-triage"),
        }
    }

    fn bound(invocation: &FakePiInvocation, request_id: u64, operation: Value) -> Value {
        let mut request = json!({
            "protocol": protocol::PROTOCOL_VERSION,
            "run_token": invocation.token,
            "request_id": request_id,
            "run_id": invocation.run_id,
            "analyzer_id": invocation.analyzer_id,
            "manifest_identity": invocation.manifest_identity,
        });
        request
            .as_object_mut()
            .unwrap()
            .extend(operation.as_object().unwrap().clone());
        request
    }

    async fn exchange(path: &std::path::Path, request: Value) -> Value {
        let mut stream = UnixStream::connect(path).await.unwrap();
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        serde_json::from_slice(&response).unwrap()
    }

    fn runtime_ready() -> Value {
        json!({
            "type": "runtime_ready",
            "pi_version": "0.83.0",
            "provider": "internal",
            "model": "triage",
            "thinking": "high",
            "mode": "print",
            "model_in_catalog": true,
            "active_tools": protocol::REQUIRED_TOOLS,
        })
    }

    #[tokio::test]
    async fn fake_pi_reads_bound_evidence_and_exact_staged_repository() {
        let fixture = Fixture::new();
        let artifact_id = fixture.manifest.artifacts()[0].id.clone();
        let finding_id = FindingId::from_suffix("fixture").unwrap();
        let request = Arc::new(
            PiTriageRequest::new(
                PiTriageRequestContext {
                    run_id: fixture.run_id.clone(),
                    invocation_id: PiTriageInvocationId::new("pii_fixture").unwrap(),
                    phase: InspectionPhase::Initial,
                    manifest_identity: fixture.manifest.identity,
                    pipeline_identity: Digest::sha256(b"pipeline"),
                    policy_identity: Digest::sha256(b"policy"),
                    prompt_template_identity: Digest::sha256(b"prompt"),
                    prior_observations_identity: Digest::sha256(b"prior"),
                    review_scope: PiReviewScope::new(true, GitHistoryScope::None).unwrap(),
                    assigned_artifact_count: 1,
                    prior_coverage: Vec::new(),
                },
                vec![PriorFinding::new(
                    finding_id.clone(),
                    CorrelationId::from_suffix("fixture").unwrap(),
                    InspectionPhase::Initial,
                    AnalyzerId::new("gitleaks").unwrap(),
                    crate::domain::RuleId::new("generic-password").unwrap(),
                    artifact_id,
                    PriorFindingArtifact::WorkingTree {
                        logical_path: fixture.manifest.subjects()[0].relative_path.clone(),
                    },
                    FindingCategory::Credential,
                    Severity::Medium,
                    None,
                    Some(Digest::sha256(b"opaque-hmac")),
                    vec![PriorOccurrence {
                        occurrence_id: OccurrenceId::from_suffix("fixture").unwrap(),
                        analyzer_id: AnalyzerId::new("gitleaks").unwrap(),
                        rule_id: crate::domain::RuleId::new("generic-password").unwrap(),
                        verification_state: CredentialVerificationState::Unverified,
                        evidence_token: Some(Digest::sha256(b"opaque-hmac")),
                        evidence: crate::analyzers::pi::triage::MatchedEvidence::from_bytes(
                            b"password = example",
                        ),
                    }],
                )
                .unwrap()],
                PiTriageLimits::new(10, 1, 128 * 1024, 128 * 1024, 10).unwrap(),
            )
            .unwrap(),
        );
        let expected_request = Arc::clone(&request);
        let analyzer = analyzer(&fixture, move |invocation| {
            let expected_request = Arc::clone(&expected_request);
            Box::pin(async move {
                assert_eq!(
                    fs::read(invocation.analyzer_input_view.join(".git/HEAD")).unwrap(),
                    b"ref: refs/heads/main\n"
                );
                assert_eq!(
                    exchange(
                        &invocation.socket_path,
                        bound(&invocation, 1, runtime_ready())
                    )
                    .await["status"],
                    "ok"
                );
                let response = exchange(
                    &invocation.socket_path,
                    bound(&invocation, 2, json!({"type":"triage_request"})),
                )
                .await;
                assert_eq!(
                    response["result"]["request_identity"],
                    json!(expected_request.request_identity)
                );
                assert_eq!(
                    response["result"]["findings"][0]["finding_id"],
                    "fnd_fixture"
                );
                assert!(response["result"].get("snippet").is_none());
                let terminal = json!({
                    "type":"submit_triage",
                    "payload": {
                        "schema_version": triage::TRIAGE_TERMINAL_SCHEMA,
                        "invocation_id": expected_request.invocation_id,
                        "phase": expected_request.phase,
                        "manifest_identity": expected_request.manifest_identity,
                        "request_identity": expected_request.request_identity,
                        "prior_observations_identity": expected_request.prior_observations_identity,
                        "status":"complete",
                        "assessments":[{
                            "finding_id":"fnd_fixture",
                            "classification":"false_positive",
                            "confidence":"high",
                            "reason_codes":["documented_test_fixture"],
                            "duplicate_of":null,
                            "recommended_action":"none"
                        }],
                        "stage_attestation":"no_blocking_concerns_observed",
                        "coverage":{
                            "assigned_artifact_count":1,
                            "completed_artifact_count":1,
                            "not_applicable_artifact_count":0,
                            "assigned_finding_count":1,
                            "assessed_finding_count":1
                        }
                    }
                });
                assert_eq!(
                    exchange(&invocation.socket_path, bound(&invocation, 3, terminal)).await
                        ["status"],
                    "ok"
                );
                Ok(())
            })
        });
        let assignments = EligibilitySelector::compile(
            &["fixture.txt".to_string()],
            &[],
            [ArtifactKind::PhysicalFile],
        )
        .unwrap()
        .assign(&AnalyzerId::new("pi-triage").unwrap(), &fixture.manifest)
        .unwrap()
        .assignments;
        let before = fs::read(fixture.input.join("fixture.txt")).unwrap();
        let result = analyzer
            .analyze_triage(
                Arc::clone(&fixture.manifest),
                assignments,
                Arc::clone(&fixture.workspace),
                request,
                Some(fixture.input.clone()),
            )
            .await
            .unwrap();
        assert_eq!(result.triage_result.assessments.len(), 1);
        assert_eq!(result.triage_result.assessments[0].finding_id, finding_id);
        assert_eq!(
            result.triage_result.assessments[0]
                .assessment
                .classification,
            PiFindingClassification::FalsePositive
        );
        assert_eq!(
            result.triage_result.assessments[0]
                .assessment
                .recommended_action,
            RecommendedAction::None
        );
        assert_eq!(
            result.triage_result.stage_attestation,
            PiStageAttestation::NoBlockingConcernsObserved
        );
        assert_eq!(fs::read(fixture.input.join("fixture.txt")).unwrap(), before);
    }
}
