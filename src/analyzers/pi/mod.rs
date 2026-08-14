//! Sandboxed Pi classification protocol and execution support.

pub mod protocol;
pub(crate) mod proxy;
pub(crate) mod runner;
pub(crate) mod sandbox;

use self::protocol::{ClassificationVocabulary, TerminalValidationLimits};
use self::proxy::{ExpectedPiRuntime, PiProxy, PiProxyInput, PiProxyLimits};
use self::runner::{PiInvocationSpec, PiRunError, PiRunLimits, PiRunSignals, PiRunner};
#[cfg(test)]
use self::sandbox::PI_RUNTIME_CONTEXT_MODE;
use self::sandbox::{PiRuntimeSpec, PreparedPiRuntime};
use crate::authorization::InvocationWorkspace;
use crate::domain::{
    AnalyzerId, ArtifactManifest, Digest, InspectionPhase, NormalizedObservation, RunId,
};
use crate::pipeline::{ArtifactAssignment, PriorObservationProjection};
use std::ffi::OsString;
#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{oneshot, watch};

const FIXED_TASK: &[u8] = b"Classify the assigned immutable artifacts under the trusted system instruction. Submit exactly one terminal classification.\n";

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
    credential_environment: Arc<Vec<(OsString, OsString)>>,
    identity: Digest,
}

#[derive(Clone)]
enum PiRunnerBackend {
    Sandbox(Box<PiRunner>),
    #[cfg(test)]
    Fake(Arc<dyn Fn(FakePiInvocation) -> FakePiFuture + Send + Sync>),
}

#[cfg(test)]
type FakePiFuture = Pin<Box<dyn Future<Output = Result<(), PiRunError>> + Send>>;

#[cfg(test)]
#[derive(Clone)]
struct FakePiInvocation {
    socket_path: std::path::PathBuf,
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
    pub credential_environment: Vec<(OsString, OsString)>,
    pub identity_material: Vec<u8>,
}

impl PiClassifierAnalyzer {
    pub(crate) fn compile(spec: PiClassifierSpec) -> Result<Self, PiClassifierCompileError> {
        let runtime = PreparedPiRuntime::prepare(spec.runtime)?;
        let mut identity_material = spec.identity_material;
        identity_material.extend_from_slice(&runtime.identity());
        identity_material.extend_from_slice(spec.instruction.as_bytes());
        let identity = Digest::sha256(identity_material);
        Ok(Self {
            id: spec.id,
            run_id: spec.run_id,
            runner: PiRunnerBackend::Sandbox(Box::new(PiRunner::new(runtime))),
            instruction: spec.instruction,
            vocabulary: Arc::new(spec.vocabulary),
            expected_runtime: spec.expected_runtime,
            terminal_limits: spec.terminal_limits,
            proxy_limits: spec.proxy_limits,
            run_limits: spec.run_limits,
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
    ) -> Result<Vec<NormalizedObservation>, PiClassifierError> {
        let proxy = PiProxy::start(
            &workspace,
            PiProxyInput {
                run_id: self.run_id.clone(),
                analyzer_id: self.id.clone(),
                manifest: Arc::clone(&manifest),
                assignments,
                objects: workspace.objects_arc(),
                prior_observations: prior,
                instruction: Arc::clone(&self.instruction),
                expected_runtime: self.expected_runtime.clone(),
                vocabulary: Arc::clone(&self.vocabulary),
                terminal_limits: self.terminal_limits,
                phase: InspectionPhase::Initial,
                limits: self.proxy_limits,
            },
        )?;

        let endpoint_dir = proxy.endpoint().endpoint_dir().to_path_buf();
        let token = proxy.endpoint().run_token().to_owned();
        let mut bridge = ProxySignalBridge::start(proxy.progress());
        let manifest_identity = manifest.identity.to_string();
        let invocation = PiInvocationSpec {
            provider: &self.expected_runtime.provider,
            model: &self.expected_runtime.model,
            thinking: &self.expected_runtime.thinking,
            proxy_endpoint_dir: &endpoint_dir,
            proxy_token: &token,
            analyzer_id: self.id.as_str(),
            run_id: self.run_id.as_str(),
            manifest_identity: &manifest_identity,
            credential_environment: &self.credential_environment,
            fixed_task: FIXED_TASK,
            limits: self.run_limits.clone(),
            signals: bridge.take_signals(),
        };
        let run = match &self.runner {
            PiRunnerBackend::Sandbox(runner) => runner.run(invocation).await.map(|_| ()),
            #[cfg(test)]
            PiRunnerBackend::Fake(fake) => {
                fake(FakePiInvocation {
                    socket_path: proxy.endpoint().host_socket_path().to_path_buf(),
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
            (Ok(()), Ok(outcome)) => Ok(outcome.submission.into_observations()),
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
            | PiProxyError::ObjectRead
            | PiProxyError::Internal
    )
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PiClassifierCompileError {
    #[error("Pi sandbox preflight failed")]
    Sandbox(#[from] sandbox::PiSandboxError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PiClassifierError {
    #[error("Pi sandboxed process failed")]
    Runner(#[from] PiRunError),
    #[error("Pi proxy failed")]
    Proxy(#[from] proxy::PiProxyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{CaptureLimits, Snapshotter};
    use crate::domain::{ArtifactKind, ClassificationCode, ConfiguredConfidence, ReasonCode};
    use crate::pipeline::{
        CompiledAnalyzer, CompiledPipeline, CompiledStage, EligibilitySelector, PipelineExecutor,
        PriorObservationMode, ProjectionLimits, StageExecution, StageId,
    };
    use serde_json::{json, Value};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
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
            fs::write(input.join("artifact.txt"), b"immutable sensitive fixture").unwrap();
            let run_id = RunId::from_suffix("pi-e2e").unwrap();
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
        let vocabulary = ClassificationVocabulary::new(
            [
                ClassificationCode::new("public").unwrap(),
                ClassificationCode::new("uncertain").unwrap(),
            ],
            [ConfiguredConfidence::Low, ConfiguredConfidence::High],
            [ReasonCode::new("policy_review").unwrap()],
        )
        .unwrap();
        PiClassifierAnalyzer {
            id: AnalyzerId::new("pi-review").unwrap(),
            run_id: fixture.run_id.clone(),
            runner: PiRunnerBackend::Fake(Arc::new(fake)),
            instruction: Arc::from("Classify under the internal publication policy."),
            vocabulary: Arc::new(vocabulary),
            expected_runtime: ExpectedPiRuntime {
                pi_version: "0.83.0".to_string(),
                provider: "internal".to_string(),
                model: "classifier".to_string(),
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
                max_search_pattern_bytes: 128,
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
                memory_bytes: 64 * 1024 * 1024,
                cpu_seconds: 1,
                open_files: 32,
                processes: 4,
                stdout_bytes: 1024,
                stderr_bytes: 1024,
            },
            credential_environment: Arc::new(Vec::new()),
            identity: Digest::sha256(b"fake-pi-integration"),
        }
    }

    fn pipeline(analyzer: PiClassifierAnalyzer) -> CompiledPipeline {
        CompiledPipeline::new(vec![CompiledStage::new(
            StageId::new("classify").unwrap(),
            StageExecution::Serial,
            vec![CompiledAnalyzer::new(
                AnalyzerId::new("pi-review").unwrap(),
                true,
                EligibilitySelector::compile(
                    &["**".to_string()],
                    &[],
                    [ArtifactKind::PhysicalFile],
                )
                .unwrap(),
                crate::pipeline::AnalyzerImplementation::Pi(Box::new(analyzer)),
            )],
            PriorObservationMode::AllNormalized,
            ProjectionLimits::new(100, 64 * 1024).unwrap(),
        )
        .unwrap()])
        .unwrap()
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
            "model": "classifier",
            "thinking": "high",
            "mode": "print",
            "model_in_catalog": true,
            "active_tools": protocol::REQUIRED_TOOLS,
        })
    }

    async fn run_analyzer(
        fixture: &Fixture,
        analyzer: &PiClassifierAnalyzer,
    ) -> Result<Vec<NormalizedObservation>, PiClassifierError> {
        let analyzer_id = AnalyzerId::new("pi-review").unwrap();
        let assignments =
            EligibilitySelector::compile(&["**".to_string()], &[], [ArtifactKind::PhysicalFile])
                .unwrap()
                .assign(&analyzer_id, &fixture.manifest)
                .unwrap()
                .assignments;
        let prior = Arc::new(
            PriorObservationProjection::build(
                PriorObservationMode::AllNormalized,
                &[],
                ProjectionLimits::new(100, 64 * 1024).unwrap(),
            )
            .unwrap(),
        );
        analyzer
            .analyze(
                Arc::clone(&fixture.manifest),
                assignments,
                Arc::clone(&fixture.workspace),
                prior,
            )
            .await
    }

    #[tokio::test]
    async fn terminal_progress_close_does_not_fail_runner_activity_channel() {
        let (progress_tx, progress_rx) = watch::channel(proxy::ProxyProgress::default());
        let mut bridge = ProxySignalBridge::start(progress_rx);
        let mut signals = bridge.take_signals();
        progress_tx.send_replace(proxy::ProxyProgress {
            authenticated_requests: 6,
            runtime_ready: true,
            terminal_submitted: true,
        });
        drop(progress_tx);

        signals.runtime_ready.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while *signals.activity.borrow() != 6 {
                signals.activity.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        signals.activity.borrow_and_update();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), signals.activity.changed())
                .await
                .is_err(),
            "the analyzer must keep activity open until the runner exits"
        );
        bridge.stop().await;
        assert!(signals.activity.changed().await.is_err());
    }

    #[tokio::test]
    async fn fatal_proxy_progress_close_still_closes_runner_activity_channel() {
        let (progress_tx, progress_rx) = watch::channel(proxy::ProxyProgress::default());
        let mut bridge = ProxySignalBridge::start(progress_rx);
        let mut signals = bridge.take_signals();
        progress_tx.send_replace(proxy::ProxyProgress {
            authenticated_requests: 1,
            runtime_ready: true,
            terminal_submitted: false,
        });
        drop(progress_tx);

        signals.runtime_ready.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while *signals.activity.borrow() != 1 {
                signals.activity.changed().await.unwrap();
            }
            signals.activity.borrow_and_update();
            assert!(signals.activity.changed().await.is_err());
        })
        .await
        .expect("fatal proxy closure must promptly stop runner activity");
        bridge.stop().await;
    }

    #[tokio::test]
    async fn runner_failure_remains_primary_when_proxy_has_no_terminal() {
        let fixture = Fixture::new();
        let analyzer = analyzer(&fixture, |invocation| {
            Box::pin(async move {
                let _ = exchange(
                    &invocation.socket_path,
                    bound(&invocation, 1, runtime_ready()),
                )
                .await;
                Err(PiRunError::NonZeroExit)
            })
        });

        assert!(matches!(
            run_analyzer(&fixture, &analyzer).await,
            Err(PiClassifierError::Runner(PiRunError::NonZeroExit))
        ));
    }

    #[tokio::test]
    async fn proxy_protocol_failure_remains_primary_when_runner_also_fails() {
        let fixture = Fixture::new();
        let analyzer = analyzer(&fixture, |invocation| {
            Box::pin(async move {
                let _ = exchange(
                    &invocation.socket_path,
                    bound(&invocation, 1, runtime_ready()),
                )
                .await;
                let mut unauthorized = bound(&invocation, 2, json!({"type":"manifest_list"}));
                unauthorized["run_token"] = json!("wrong-token");
                let response = exchange(&invocation.socket_path, unauthorized).await;
                assert_eq!(response["status"], "error");
                Err(PiRunError::RuntimeHandshake)
            })
        });

        assert!(matches!(
            run_analyzer(&fixture, &analyzer).await,
            Err(PiClassifierError::Proxy(proxy::PiProxyError::Unauthorized))
        ));
    }

    #[tokio::test]
    async fn fake_pi_uses_real_proxy_and_completes_pipeline_without_mutation() {
        let fixture = Fixture::new();
        let artifact_id = fixture.manifest.artifacts()[0].id.clone();
        let analyzer = analyzer(&fixture, move |invocation| {
            let artifact_id = artifact_id.clone();
            Box::pin(async move {
                assert_eq!(
                    exchange(
                        &invocation.socket_path,
                        bound(&invocation, 1, runtime_ready())
                    )
                    .await["status"],
                    "ok"
                );
                assert_eq!(
                    exchange(
                        &invocation.socket_path,
                        bound(&invocation, 2, json!({"type":"instruction"}))
                    )
                    .await["status"],
                    "ok"
                );
                assert_eq!(
                    exchange(
                        &invocation.socket_path,
                        bound(&invocation, 3, json!({"type":"manifest_list"}))
                    )
                    .await["status"],
                    "ok"
                );
                assert_eq!(
                    exchange(
                        &invocation.socket_path,
                        bound(
                            &invocation,
                            4,
                            json!({"type":"artifact_read","artifact_id":artifact_id})
                        )
                    )
                    .await["status"],
                    "ok"
                );
                assert_eq!(
                    exchange(
                        &invocation.socket_path,
                        bound(&invocation, 5, json!({"type":"prior_observations"}))
                    )
                    .await["status"],
                    "ok"
                );
                let terminal = json!({
                    "type":"submit_classification",
                    "payload": {
                        "schema_version": protocol::OUTPUT_SCHEMA_VERSION,
                        "status":"complete",
                        "manifest_identity":invocation.manifest_identity,
                        "classification": {"code":"public","confidence":"high","reason_codes":["policy_review"],"subject_artifact_ids":[artifact_id]},
                        "artifact_classifications":[],
                        "coverage":{"assigned_artifact_count":1,"status":"complete"}
                    }
                });
                assert_eq!(
                    exchange(&invocation.socket_path, bound(&invocation, 6, terminal)).await
                        ["status"],
                    "ok"
                );
                Ok(())
            })
        });
        let before = fs::read(fixture.input.join("artifact.txt")).unwrap();
        let result = PipelineExecutor::execute(
            &pipeline(analyzer),
            Arc::clone(&fixture.manifest),
            Arc::clone(&fixture.workspace),
        )
        .await;
        assert!(result.complete, "unexpected pipeline result: {result:?}");
        assert_eq!(result.coverage[0].completed, 1);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(
            fs::read(fixture.input.join("artifact.txt")).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn zero_exit_without_terminal_returns_prompt_incomplete_coverage() {
        let fixture = Fixture::new();
        let analyzer = analyzer(&fixture, |invocation| {
            Box::pin(async move {
                let _ = exchange(
                    &invocation.socket_path,
                    bound(&invocation, 1, runtime_ready()),
                )
                .await;
                Ok(())
            })
        });
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            PipelineExecutor::execute(
                &pipeline(analyzer),
                Arc::clone(&fixture.manifest),
                Arc::clone(&fixture.workspace),
            ),
        )
        .await
        .expect("missing terminal must not hang");
        assert!(!result.complete);
        assert!(!result.coverage[0].is_complete());
        assert_eq!(
            result.issues[0].code,
            crate::domain::IssueCode::RequiredAnalyzerProtocolFailure
        );
    }

    #[tokio::test]
    async fn cancelling_pipeline_drops_in_flight_pi_future() {
        struct DropSignal(Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let fixture = Fixture::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = oneshot::channel();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let analyzer = analyzer(&fixture, {
            let dropped = Arc::clone(&dropped);
            move |_| {
                let guard = DropSignal(Arc::clone(&dropped));
                let started_tx = Arc::clone(&started_tx);
                Box::pin(async move {
                    let _guard = guard;
                    if let Some(sender) = started_tx.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    std::future::pending::<()>().await;
                    Ok(())
                })
            }
        });
        let manifest = Arc::clone(&fixture.manifest);
        let workspace = Arc::clone(&fixture.workspace);
        let pipeline = pipeline(analyzer);
        let task =
            tokio::spawn(
                async move { PipelineExecutor::execute(&pipeline, manifest, workspace).await },
            );
        started_rx.await.unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled Pi future must be dropped promptly");
    }
}
