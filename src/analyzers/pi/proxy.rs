use super::protocol::{
    ClassificationVocabulary, NativeTool, ProxyError as WireError, ProxyErrorCode, ProxyOperation,
    ProxyRequest, ProxyResponse, TerminalValidationContext, TerminalValidationLimits,
    ValidatedSubmission, PROTOCOL_VERSION, REQUIRED_TOOLS,
};
use crate::authorization::{AnalyzerView, AnalyzerViewNode, InvocationWorkspace, WorkspaceError};
use crate::domain::{
    AnalyzerId, ArtifactId, ArtifactManifest, CandidateId, ClassificationScope, InspectionPhase,
    RunId,
};
use crate::pipeline::{ArtifactAssignment, PriorObservationProjection};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, watch};

const SOCKET_NAME: &str = "proxy.sock";
pub(crate) const EXTENSION_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const NATIVE_READ_MAX_BYTES: u64 = 1024 * 1024;
pub(crate) const NATIVE_TOOL_MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub(crate) const NATIVE_SEARCH_MAX_RESULTS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiProxyLimits {
    pub max_frame_bytes: usize,
    pub max_response_bytes: usize,
    pub max_terminal_bytes: usize,
    pub max_tool_calls: u64,
    pub max_bytes_read: u64,
    pub max_read_bytes_per_call: u64,
    pub max_search_matches: u64,
    pub max_search_bytes_per_call: u64,
    pub max_search_calls: u64,
    pub frame_read_timeout: Duration,
}

impl PiProxyLimits {
    pub fn validate(self) -> Result<Self, PiProxyError> {
        if self.max_frame_bytes == 0
            || self.max_response_bytes == 0
            || self.max_terminal_bytes == 0
            || self.max_tool_calls == 0
            || self.max_bytes_read == 0
            || self.max_read_bytes_per_call == 0
            || self.max_read_bytes_per_call > NATIVE_READ_MAX_BYTES
            || self.max_read_bytes_per_call > self.max_bytes_read
            || self.max_search_matches == 0
            || self.max_search_matches > NATIVE_SEARCH_MAX_RESULTS
            || self.max_search_bytes_per_call == 0
            || self.max_search_bytes_per_call > self.max_bytes_read
            || self.max_search_calls == 0
            || self.frame_read_timeout.is_zero()
            || self.max_response_bytes > EXTENSION_MAX_RESPONSE_BYTES
        {
            return Err(PiProxyError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedPiRuntime {
    pub pi_version: String,
    pub provider: String,
    pub model: String,
    pub thinking: String,
    pub mode: String,
}

pub struct PiProxyInput {
    pub run_id: RunId,
    pub analyzer_id: AnalyzerId,
    pub manifest: Arc<ArtifactManifest>,
    pub assignments: Vec<ArtifactAssignment>,
    pub view: Arc<AnalyzerView>,
    pub prior_observations: Arc<PriorObservationProjection>,
    pub instruction: Arc<str>,
    pub expected_runtime: ExpectedPiRuntime,
    pub vocabulary: Arc<ClassificationVocabulary>,
    pub terminal_limits: TerminalValidationLimits,
    pub phase: InspectionPhase,
    pub limits: PiProxyLimits,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProxyProgress {
    pub authenticated_requests: u64,
    pub runtime_ready: bool,
    pub terminal_submitted: bool,
}

#[derive(Debug)]
pub struct PiProxyOutcome {
    pub submission: ValidatedSubmission,
}

#[derive(Clone)]
pub struct PiProxyEndpoint {
    endpoint_dir: PathBuf,
    #[cfg(test)]
    host_socket_path: PathBuf,
    run_token: Arc<str>,
}

impl std::fmt::Debug for PiProxyEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PiProxyEndpoint")
            .field("endpoint_dir", &self.endpoint_dir)
            .field("run_token", &"[REDACTED]")
            .finish()
    }
}

impl PiProxyEndpoint {
    pub fn endpoint_dir(&self) -> &Path {
        &self.endpoint_dir
    }

    /// Descriptor-short host path. This is never mounted into the sandbox or
    /// included in reports and is valid only while the proxy owns its endpoint.
    #[cfg(test)]
    pub(crate) fn host_socket_path(&self) -> &Path {
        &self.host_socket_path
    }

    /// Secret capability passed only through the scrubbed child environment.
    pub fn run_token(&self) -> &str {
        &self.run_token
    }
}

pub struct PiProxy {
    endpoint: PiProxyEndpoint,
    endpoint_directory: Option<crate::authorization::AnalyzerEndpointDirectory>,
    progress: watch::Receiver<ProxyProgress>,
    outcome: oneshot::Receiver<Result<PiProxyOutcome, PiProxyError>>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl PiProxy {
    pub fn start(
        workspace: &InvocationWorkspace,
        input: PiProxyInput,
    ) -> Result<Self, PiProxyError> {
        let limits = input.limits.validate()?;
        validate_input(&input)?;
        let token = Arc::<str>::from(random_token()?);
        let endpoint_name = format!("pi-{}", random_identifier()?);
        let endpoint_directory = workspace
            .create_analyzer_endpoint(&endpoint_name)
            .map_err(PiProxyError::Workspace)?;
        let endpoint_dir = endpoint_directory.path().to_path_buf();
        let socket_path = endpoint_directory
            .socket_path(SOCKET_NAME)
            .map_err(PiProxyError::Workspace)?;
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = endpoint_directory.remove();
                return Err(PiProxyError::CreateEndpoint(error));
            }
        };
        let (progress_tx, progress) = watch::channel(ProxyProgress::default());
        let (outcome_tx, outcome) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let endpoint = PiProxyEndpoint {
            endpoint_dir,
            #[cfg(test)]
            host_socket_path: socket_path,
            run_token: Arc::clone(&token),
        };
        let server = Server::new(input, token, limits, progress_tx)?;
        let task = tokio::spawn(async move {
            let result = server.serve(listener, stop_rx).await;
            let _ = outcome_tx.send(result);
        });
        Ok(Self {
            endpoint,
            endpoint_directory: Some(endpoint_directory),
            progress,
            outcome,
            stop: Some(stop_tx),
            task,
        })
    }

    pub fn endpoint(&self) -> &PiProxyEndpoint {
        &self.endpoint
    }

    pub fn progress(&self) -> watch::Receiver<ProxyProgress> {
        self.progress.clone()
    }

    /// Finalizes a completed child run. A run which exits without a terminal
    /// submission is stopped, reaped, cleaned, and reported as incomplete.
    pub async fn finish(mut self) -> Result<PiProxyOutcome, PiProxyError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let outcome = (&mut self.outcome).await;
        let task = (&mut self.task).await;
        let cleanup = self.cleanup_endpoint();
        cleanup?;
        task.map_err(|_| PiProxyError::ServerStopped)?;
        let outcome = outcome.map_err(|_| PiProxyError::ServerStopped)?;
        match outcome {
            Err(PiProxyError::Stopped) => Err(PiProxyError::MissingTerminalSubmission),
            outcome => outcome,
        }
    }

    fn cleanup_endpoint(&mut self) -> Result<(), PiProxyError> {
        if let Some(directory) = self.endpoint_directory.take() {
            match directory.remove_socket(SOCKET_NAME) {
                Ok(()) => {}
                Err(WorkspaceError::RemoveAnalyzerSocket(rustix::io::Errno::NOENT)) => {}
                Err(error) => return Err(PiProxyError::Workspace(error)),
            }
            directory.remove().map_err(PiProxyError::Workspace)?;
        }
        Ok(())
    }
}

impl Drop for PiProxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

struct Server {
    input: PiProxyInput,
    token: Arc<str>,
    assignments: BTreeMap<ArtifactId, CandidateId>,
    limits: PiProxyLimits,
    calls: u64,
    tool_calls: u64,
    bytes_read: u64,
    search_calls: u64,
    outstanding_native_tool: Option<OutstandingNativeTool>,
    next_request_id: u64,
    ready: bool,
    progress: watch::Sender<ProxyProgress>,
}

#[derive(Debug)]
struct OutstandingNativeTool {
    tool_call_id: String,
    tool: NativeTool,
    path: String,
}

enum OperationResult {
    Continue(Value),
    Terminal(ValidatedSubmission),
}

impl Server {
    fn new(
        input: PiProxyInput,
        token: Arc<str>,
        limits: PiProxyLimits,
        progress: watch::Sender<ProxyProgress>,
    ) -> Result<Self, PiProxyError> {
        let assignments = input
            .assignments
            .iter()
            .map(|assignment| {
                (
                    assignment.artifact_id.clone(),
                    assignment.candidate_id.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if assignments.len() != input.assignments.len() {
            return Err(PiProxyError::InvalidAssignment);
        }
        Ok(Self {
            input,
            token,
            assignments,
            limits,
            calls: 0,
            tool_calls: 0,
            bytes_read: 0,
            search_calls: 0,
            outstanding_native_tool: None,
            next_request_id: 1,
            ready: false,
            progress,
        })
    }

    async fn serve(
        mut self,
        listener: UnixListener,
        mut stop: oneshot::Receiver<()>,
    ) -> Result<PiProxyOutcome, PiProxyError> {
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted.map_err(PiProxyError::Accept)?,
                _ = &mut stop => return Err(PiProxyError::Stopped),
            };
            self.calls = self
                .calls
                .checked_add(1)
                .ok_or(PiProxyError::BudgetExceeded)?;
            // Every model-callable native operation uses a begin/end pair. The
            // runtime-ready and instruction bootstrap requests are not model
            // tools and account for the fixed allowance of two.
            let connection_limit = self
                .limits
                .max_tool_calls
                .checked_mul(2)
                .and_then(|limit| limit.checked_add(2))
                .ok_or(PiProxyError::BudgetExceeded)?;
            if self.calls > connection_limit {
                return Err(PiProxyError::BudgetExceeded);
            }
            let (mut stream, _) = accepted;
            let read = tokio::time::timeout(
                self.limits.frame_read_timeout,
                read_request(&mut stream, self.limits.max_frame_bytes),
            );
            let frame = match tokio::select! {
                frame = read => frame,
                _ = &mut stop => return Err(PiProxyError::Stopped),
                concurrent = listener.accept() => {
                    if let Ok((mut concurrent, _)) = concurrent {
                        let _ = write_error(
                            &mut concurrent,
                            0,
                            ProxyErrorCode::ProtocolViolation,
                            self.limits,
                        ).await;
                    }
                    return Err(PiProxyError::ConcurrentRequest);
                }
            } {
                Err(_) => {
                    let error = PiProxyError::FrameReadTimeout;
                    let _ = write_error(&mut stream, 0, error.code(), self.limits).await;
                    return Err(error);
                }
                Ok(request) => request,
            };
            let request = match frame {
                Ok(request) => request,
                Err(error) => {
                    let _ = write_error(&mut stream, 0, error.code(), self.limits).await;
                    return Err(error);
                }
            };
            let request_id = request.request_id;
            if let Err(error) = self.authenticate(&request) {
                let _ = write_error(&mut stream, request_id, error.code(), self.limits).await;
                return Err(error);
            }
            self.next_request_id = self
                .next_request_id
                .checked_add(1)
                .ok_or(PiProxyError::ProtocolViolation)?;
            let mut progress = *self.progress.borrow();
            progress.authenticated_requests = progress
                .authenticated_requests
                .checked_add(1)
                .ok_or(PiProxyError::BudgetExceeded)?;
            self.progress.send_replace(progress);

            match self.operation(request.operation).await {
                Ok(OperationResult::Continue(result)) => {
                    write_ok(&mut stream, request_id, result, self.limits).await?;
                }
                Ok(OperationResult::Terminal(submission)) => {
                    // Closing the listener is the atomic capability revocation point.
                    // It occurs before acknowledgement so no later request can be
                    // accepted after the terminal operation commits.
                    drop(listener);
                    write_ok(
                        &mut stream,
                        request_id,
                        json!({"accepted": true}),
                        self.limits,
                    )
                    .await?;
                    let mut progress = *self.progress.borrow();
                    progress.terminal_submitted = true;
                    self.progress.send_replace(progress);
                    return Ok(PiProxyOutcome { submission });
                }
                Err(error) if error.is_fatal() => {
                    let _ = write_error(&mut stream, request_id, error.code(), self.limits).await;
                    return Err(error);
                }
                Err(error) => {
                    write_error(&mut stream, request_id, error.code(), self.limits).await?;
                }
            }
        }
    }

    fn authenticate(&self, request: &ProxyRequest) -> Result<(), PiProxyError> {
        if request.protocol != PROTOCOL_VERSION
            || request.run_token.as_bytes() != self.token.as_bytes()
            || request.run_id != self.input.run_id
            || request.analyzer_id != self.input.analyzer_id
            || request.manifest_identity != self.input.manifest.identity
        {
            return Err(PiProxyError::Unauthorized);
        }
        if request.request_id != self.next_request_id {
            return Err(PiProxyError::ProtocolViolation);
        }
        Ok(())
    }

    async fn operation(
        &mut self,
        operation: ProxyOperation,
    ) -> Result<OperationResult, PiProxyError> {
        match operation {
            ProxyOperation::RuntimeReady {
                pi_version,
                provider,
                model,
                thinking,
                mode,
                model_in_catalog,
                mut active_tools,
            } => {
                active_tools.sort();
                let mut expected_tools = REQUIRED_TOOLS
                    .iter()
                    .map(|tool| (*tool).to_owned())
                    .collect::<Vec<_>>();
                expected_tools.sort();
                let expected = &self.input.expected_runtime;
                if self.ready
                    || pi_version != expected.pi_version
                    || provider != expected.provider
                    || model != expected.model
                    || thinking != expected.thinking
                    || mode != expected.mode
                    || !model_in_catalog
                    || active_tools != expected_tools
                {
                    return Err(PiProxyError::RuntimeMismatch);
                }
                self.ready = true;
                let mut progress = *self.progress.borrow();
                progress.runtime_ready = true;
                self.progress.send_replace(progress);
                Ok(OperationResult::Continue(json!({"accepted": true})))
            }
            ProxyOperation::Instruction {} => {
                self.require_ready()?;
                Ok(OperationResult::Continue(
                    json!({"instruction": self.input.instruction.as_ref()}),
                ))
            }
            ProxyOperation::ManifestList {} => {
                self.require_ready()?;
                self.charge_tool_call()?;
                Ok(OperationResult::Continue(manifest_list_value(&self.input)?))
            }
            ProxyOperation::NativeToolBegin {
                tool_call_id,
                tool,
                path,
            } => {
                self.require_ready()?;
                if self.outstanding_native_tool.is_some() || !valid_tool_call_id(&tool_call_id) {
                    return Err(PiProxyError::ProtocolViolation);
                }
                let node = self
                    .input
                    .view
                    .resolve_relative_path(&path)
                    .ok_or(PiProxyError::Unauthorized)?;
                let charged_bytes = match (tool, node) {
                    (NativeTool::Read, AnalyzerViewNode::File(entry)) => entry.byte_len,
                    (NativeTool::Grep, AnalyzerViewNode::File(entry)) => entry.byte_len,
                    (
                        NativeTool::Grep,
                        AnalyzerViewNode::Directory {
                            recursive_file_bytes,
                            ..
                        },
                    ) => recursive_file_bytes,
                    (NativeTool::Find | NativeTool::Ls, AnalyzerViewNode::Directory { .. }) => 0,
                    _ => return Err(PiProxyError::InvalidRequest),
                };
                self.charge_tool_call()?;
                match tool {
                    NativeTool::Read => {
                        if charged_bytes > NATIVE_READ_MAX_BYTES {
                            return Err(PiProxyError::BudgetExceeded);
                        }
                        self.reserve_read(charged_bytes, self.limits.max_read_bytes_per_call)?;
                    }
                    NativeTool::Grep => {
                        self.search_calls = self
                            .search_calls
                            .checked_add(1)
                            .filter(|calls| *calls <= self.limits.max_search_calls)
                            .ok_or(PiProxyError::BudgetExceeded)?;
                        self.reserve_read(charged_bytes, self.limits.max_search_bytes_per_call)?;
                    }
                    NativeTool::Find | NativeTool::Ls => {}
                }
                self.charge_read(charged_bytes)?;
                self.outstanding_native_tool = Some(OutstandingNativeTool {
                    tool_call_id,
                    tool,
                    path,
                });
                Ok(OperationResult::Continue(json!({"accepted": true})))
            }
            ProxyOperation::NativeToolEnd {
                tool_call_id,
                tool,
                path,
                success,
                output_bytes,
                result_count,
            } => {
                self.require_ready()?;
                let outstanding = self
                    .outstanding_native_tool
                    .take()
                    .ok_or(PiProxyError::ProtocolViolation)?;
                if outstanding.tool_call_id != tool_call_id
                    || outstanding.tool != tool
                    || outstanding.path != path
                {
                    return Err(PiProxyError::ProtocolViolation);
                }
                if !success {
                    if output_bytes != 0 || result_count != 0 {
                        return Err(PiProxyError::ProtocolViolation);
                    }
                    return Err(PiProxyError::NativeToolFailed);
                }
                if output_bytes > NATIVE_TOOL_MAX_OUTPUT_BYTES as u64
                    || result_count > self.limits.max_search_matches
                    || (tool == NativeTool::Read && result_count != 1)
                {
                    return Err(PiProxyError::BudgetExceeded);
                }
                Ok(OperationResult::Continue(json!({"accepted": true})))
            }
            ProxyOperation::PriorObservations {} => {
                self.require_ready()?;
                self.charge_tool_call()?;
                let value = serde_json::from_slice(self.input.prior_observations.canonical_json())
                    .map_err(|_| PiProxyError::Internal)?;
                Ok(OperationResult::Continue(value))
            }
            ProxyOperation::SubmitClassification { payload } => {
                self.require_ready()?;
                if self.outstanding_native_tool.is_some() {
                    return Err(PiProxyError::ProtocolViolation);
                }
                self.charge_tool_call()?;
                if serde_json::to_vec(&payload)
                    .map_err(|_| PiProxyError::InvalidTerminalSubmission)?
                    .len()
                    > self.limits.max_terminal_bytes
                {
                    return Err(PiProxyError::BudgetExceeded);
                }
                let assigned_artifact_ids = self.assignments.keys().cloned().collect::<Vec<_>>();
                let context = TerminalValidationContext {
                    manifest_identity: self.input.manifest.identity,
                    assigned_artifact_ids: &assigned_artifact_ids,
                    scope: ClassificationScope::Tree,
                    vocabulary: &self.input.vocabulary,
                    limits: self.input.terminal_limits,
                };
                let submission = payload
                    .validate(&context, &self.input.analyzer_id, self.input.phase)
                    .map_err(|_| PiProxyError::InvalidTerminalSubmission)?;
                Ok(OperationResult::Terminal(submission))
            }
        }
    }

    fn require_ready(&self) -> Result<(), PiProxyError> {
        self.ready
            .then_some(())
            .ok_or(PiProxyError::ProtocolViolation)
    }

    fn charge_tool_call(&mut self) -> Result<(), PiProxyError> {
        self.tool_calls = self
            .tool_calls
            .checked_add(1)
            .filter(|calls| *calls <= self.limits.max_tool_calls)
            .ok_or(PiProxyError::BudgetExceeded)?;
        Ok(())
    }

    fn reserve_read(&self, amount: u64, per_call: u64) -> Result<(), PiProxyError> {
        if amount > per_call
            || self
                .bytes_read
                .checked_add(amount)
                .filter(|total| *total <= self.limits.max_bytes_read)
                .is_none()
        {
            return Err(PiProxyError::BudgetExceeded);
        }
        Ok(())
    }

    fn charge_read(&mut self, amount: u64) -> Result<(), PiProxyError> {
        self.bytes_read = self
            .bytes_read
            .checked_add(amount)
            .filter(|total| *total <= self.limits.max_bytes_read)
            .ok_or(PiProxyError::BudgetExceeded)?;
        Ok(())
    }
}

fn valid_tool_call_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn validate_input(input: &PiProxyInput) -> Result<(), PiProxyError> {
    if input.instruction.is_empty()
        || !response_fits(
            json!({"instruction": input.instruction.as_ref()}),
            input.limits.max_response_bytes,
        )?
    {
        return Err(PiProxyError::InvalidInstruction);
    }
    let assignments = input
        .assignments
        .iter()
        .map(|assignment| {
            (
                assignment.artifact_id.clone(),
                assignment.candidate_id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if assignments.len() != input.assignments.len()
        || input.view.entries().len() != assignments.len()
        || input.view.entries().iter().any(|entry| {
            assignments.get(&entry.artifact_id) != Some(&entry.candidate_id)
                || input
                    .manifest
                    .artifact(&entry.artifact_id)
                    .is_none_or(|artifact| {
                        artifact.kind != entry.kind
                            || artifact.byte_len != entry.byte_len
                            || artifact.content_digest != entry.content_digest
                    })
        })
    {
        return Err(PiProxyError::InvalidAssignment);
    }
    let manifest_list = manifest_list_value(input)?;
    if !response_fits(manifest_list, input.limits.max_response_bytes)? {
        return Err(PiProxyError::ManifestResponseTooLarge);
    }
    Ok(())
}

fn manifest_list_value(input: &PiProxyInput) -> Result<Value, PiProxyError> {
    to_value(input.view.entries())
}

fn response_fits(result: Value, max_response_bytes: usize) -> Result<bool, PiProxyError> {
    let response = ProxyResponse::Ok {
        protocol: PROTOCOL_VERSION.to_owned(),
        request_id: u64::MAX,
        result,
    };
    Ok(serde_json::to_vec(&response)
        .map_err(|_| PiProxyError::Internal)?
        .len()
        .checked_add(1)
        .is_some_and(|size| size <= max_response_bytes))
}

async fn read_request(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<ProxyRequest, PiProxyError> {
    let capacity = max_frame_bytes.min(64 * 1024);
    let mut frame = Vec::with_capacity(capacity);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(PiProxyError::ReadEndpoint)?;
        if read == 0 {
            break;
        }
        if frame
            .len()
            .checked_add(read)
            .is_none_or(|len| len > max_frame_bytes)
        {
            return Err(PiProxyError::FrameTooLarge);
        }
        frame.extend_from_slice(&buffer[..read]);
    }
    if frame.last() != Some(&b'\n') || frame[..frame.len().saturating_sub(1)].contains(&b'\n') {
        return Err(PiProxyError::MalformedFrame);
    }
    frame.pop();
    serde_json::from_slice(&frame).map_err(|_| PiProxyError::MalformedFrame)
}

async fn write_ok(
    stream: &mut UnixStream,
    request_id: u64,
    result: Value,
    limits: PiProxyLimits,
) -> Result<(), PiProxyError> {
    write_response(
        stream,
        ProxyResponse::Ok {
            protocol: PROTOCOL_VERSION.to_owned(),
            request_id,
            result,
        },
        limits,
    )
    .await
}

async fn write_error(
    stream: &mut UnixStream,
    request_id: u64,
    code: ProxyErrorCode,
    limits: PiProxyLimits,
) -> Result<(), PiProxyError> {
    write_response(
        stream,
        ProxyResponse::Error {
            protocol: PROTOCOL_VERSION.to_owned(),
            request_id,
            error: WireError { code },
        },
        limits,
    )
    .await
}

async fn write_response(
    stream: &mut UnixStream,
    response: ProxyResponse,
    limits: PiProxyLimits,
) -> Result<(), PiProxyError> {
    let mut encoded = serde_json::to_vec(&response).map_err(|_| PiProxyError::Internal)?;
    if encoded.len() >= limits.max_response_bytes {
        return Err(PiProxyError::ResponseTooLarge);
    }
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .map_err(PiProxyError::WriteEndpoint)?;
    stream.shutdown().await.map_err(PiProxyError::WriteEndpoint)
}

fn to_value(value: impl Serialize) -> Result<Value, PiProxyError> {
    serde_json::to_value(value).map_err(|_| PiProxyError::Internal)
}

fn random_token() -> Result<String, PiProxyError> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(PiProxyError::Entropy)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_identifier() -> Result<String, PiProxyError> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(PiProxyError::Entropy)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Debug, Error)]
pub enum PiProxyError {
    #[error("Pi proxy limits must all be greater than zero")]
    InvalidLimits,
    #[error("Pi proxy instruction is empty or exceeds its response limit")]
    InvalidInstruction,
    #[error("Pi proxy assignment does not match the immutable manifest")]
    InvalidAssignment,
    #[error("Pi proxy assignment metadata exceeds the configured response limit")]
    ManifestResponseTooLarge,
    #[error("could not obtain a private Pi proxy capability")]
    Entropy(#[source] std::io::Error),
    #[error("could not create the private Pi proxy endpoint")]
    CreateEndpoint(#[source] std::io::Error),
    #[error("private Pi proxy workspace operation failed")]
    Workspace(#[source] WorkspaceError),
    #[error("Pi proxy endpoint accept failed")]
    Accept(#[source] std::io::Error),
    #[error("Pi proxy endpoint read failed")]
    ReadEndpoint(#[source] std::io::Error),
    #[error("Pi proxy endpoint write failed")]
    WriteEndpoint(#[source] std::io::Error),
    #[error("Pi proxy request frame exceeds its configured limit")]
    FrameTooLarge,
    #[error("Pi proxy request frame is malformed")]
    MalformedFrame,
    #[error("Pi proxy request frame did not complete before its deadline")]
    FrameReadTimeout,
    #[error("Pi proxy request is not authorized for this invocation")]
    Unauthorized,
    #[error("Pi proxy protocol ordering or state is invalid")]
    ProtocolViolation,
    #[error("Pi proxy received concurrent requests")]
    ConcurrentRequest,
    #[error("Pi runtime handshake does not match its pinned configuration")]
    RuntimeMismatch,
    #[error("Pi proxy request is invalid")]
    InvalidRequest,
    #[error("Pi terminal classification failed semantic validation")]
    InvalidTerminalSubmission,
    #[error("Pi proxy request exceeds a configured budget")]
    BudgetExceeded,
    #[error("Pi proxy response exceeds its configured limit")]
    ResponseTooLarge,
    #[error("Pi native read-only tool execution failed")]
    NativeToolFailed,
    #[error("Pi proxy internal operation failed")]
    Internal,
    #[error("Pi proxy was stopped by its owner")]
    Stopped,
    #[error("Pi proxy server stopped unexpectedly")]
    ServerStopped,
    #[error("Pi process exited without an accepted terminal classification")]
    MissingTerminalSubmission,
}

impl PiProxyError {
    fn code(&self) -> ProxyErrorCode {
        match self {
            Self::Unauthorized => ProxyErrorCode::Unauthorized,
            Self::BudgetExceeded | Self::FrameTooLarge | Self::ResponseTooLarge => {
                ProxyErrorCode::BudgetExceeded
            }
            Self::MalformedFrame
            | Self::InvalidRequest
            | Self::InvalidTerminalSubmission
            | Self::NativeToolFailed => ProxyErrorCode::InvalidRequest,
            Self::FrameReadTimeout => ProxyErrorCode::ProtocolViolation,
            Self::ProtocolViolation | Self::ConcurrentRequest | Self::RuntimeMismatch => {
                ProxyErrorCode::ProtocolViolation
            }
            _ => ProxyErrorCode::InternalError,
        }
    }

    fn is_fatal(&self) -> bool {
        // The initial Pi contract is audit-only but required. Any failed tool
        // operation invalidates its coverage; continuing would permit a model
        // to ignore a denied read and submit a superficially complete result.
        !matches!(self, Self::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{AnalyzerViewBuilder, AnalyzerViewLimits};
    use crate::domain::{
        Artifact, ArtifactKind, ClassificationCode, ConfiguredConfidence, Digest, LogicalPath,
        PathSegment, PhysicalSubject, Provenance, ReasonCode, SourceFileType, SourceIdentity,
        SubjectId,
    };
    use crate::pipeline::{PriorObservationMode, ProjectionLimits};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        workspace: InvocationWorkspace,
        manifest: Arc<ArtifactManifest>,
        assignment: ArtifactAssignment,
        run_id: RunId,
        analyzer_id: AnalyzerId,
    }

    fn fixture(bytes: &[u8]) -> Fixture {
        fixture_with_paths(bytes, 0, "artifact.bin")
    }

    fn fixture_with_workspace_padding(bytes: &[u8], padding: usize) -> Fixture {
        fixture_with_paths(bytes, padding, "artifact.bin")
    }

    fn fixture_with_paths(bytes: &[u8], padding: usize, logical_name: &str) -> Fixture {
        let temporary = TempDir::new().unwrap();
        let mut root = temporary.path().to_path_buf();
        if padding != 0 {
            root.push("w".repeat(padding));
        }
        root.push("workspaces");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let run_id = RunId::from_suffix("proxy-test").unwrap();
        let workspace = InvocationWorkspace::create(&root, &run_id).unwrap();
        let stored = workspace
            .objects()
            .store(&mut &*bytes, bytes.len() as u64)
            .unwrap();
        let subject_id = SubjectId::from_suffix("proxy-test").unwrap();
        let artifact_id = ArtifactId::from_suffix("proxy-test").unwrap();
        let logical_path =
            LogicalPath::new(vec![PathSegment::utf8(logical_name).unwrap()]).unwrap();
        let source_identity = SourceIdentity {
            device: 1,
            inode: 2,
            file_type: SourceFileType::RegularFile,
            byte_len: bytes.len() as u64,
            link_count: 1,
            modified: None,
            changed: None,
            content_digest: stored.digest,
        };
        let subject = PhysicalSubject {
            id: subject_id.clone(),
            relative_path: logical_path.clone(),
            source_identity,
            object_id: stored.id.clone(),
            byte_len: bytes.len() as u64,
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            subject_id,
            object_id: stored.id,
            kind: ArtifactKind::PhysicalFile,
            byte_len: bytes.len() as u64,
            content_digest: stored.digest,
            provenance: Provenance::Physical { logical_path },
        };
        let manifest = Arc::new(ArtifactManifest::new(vec![subject], vec![artifact]).unwrap());
        Fixture {
            _temporary: temporary,
            workspace,
            manifest,
            assignment: ArtifactAssignment {
                candidate_id: CandidateId::from_suffix("proxy-test").unwrap(),
                artifact_id,
            },
            run_id,
            analyzer_id: AnalyzerId::new("pi-classifier").unwrap(),
        }
    }

    fn limits() -> PiProxyLimits {
        PiProxyLimits {
            max_frame_bytes: 32 * 1024,
            max_response_bytes: 4096,
            max_terminal_bytes: 4096,
            max_tool_calls: 16,
            max_bytes_read: 1024,
            max_read_bytes_per_call: 1024,
            max_search_matches: 8,
            max_search_bytes_per_call: 1024,
            max_search_calls: 1,
            frame_read_timeout: Duration::from_secs(30),
        }
    }

    fn input(fixture: &Fixture) -> PiProxyInput {
        let code = ClassificationCode::new("allowed").unwrap();
        let reason = ReasonCode::new("reviewed").unwrap();
        PiProxyInput {
            run_id: fixture.run_id.clone(),
            analyzer_id: fixture.analyzer_id.clone(),
            manifest: Arc::clone(&fixture.manifest),
            assignments: vec![fixture.assignment.clone()],
            view: Arc::new(
                AnalyzerViewBuilder::new(
                    &fixture.workspace,
                    &fixture.manifest,
                    std::slice::from_ref(&fixture.assignment),
                    AnalyzerViewLimits {
                        per_view: crate::authorization::AnalyzerViewQuota {
                            max_files: 8,
                            max_entries: 16,
                            max_total_bytes: 8 * 1024,
                            max_depth: 8,
                        },
                        invocation: crate::authorization::AnalyzerViewQuota {
                            max_files: 8,
                            max_entries: 16,
                            max_total_bytes: 8 * 1024,
                            max_depth: 8,
                        },
                    },
                )
                .materialize("proxy-input")
                .unwrap(),
            ),
            prior_observations: Arc::new(
                PriorObservationProjection::build(
                    PriorObservationMode::None,
                    &[],
                    ProjectionLimits::new(8, 1024).unwrap(),
                )
                .unwrap(),
            ),
            instruction: Arc::from("Classify only under the supplied policy."),
            expected_runtime: ExpectedPiRuntime {
                pi_version: "0.83.0".to_owned(),
                provider: "internal".to_owned(),
                model: "classifier".to_owned(),
                thinking: "high".to_owned(),
                mode: super::super::sandbox::PI_RUNTIME_CONTEXT_MODE.to_owned(),
            },
            vocabulary: Arc::new(
                ClassificationVocabulary::new([code], [ConfiguredConfidence::High], [reason])
                    .unwrap(),
            ),
            terminal_limits: TerminalValidationLimits::new(8, 8, 8).unwrap(),
            phase: InspectionPhase::Initial,
            limits: limits(),
        }
    }

    fn request(proxy: &PiProxy, request_id: u64, operation: ProxyOperation) -> ProxyRequest {
        ProxyRequest {
            protocol: PROTOCOL_VERSION.to_owned(),
            run_token: proxy.endpoint().run_token().to_owned(),
            request_id,
            run_id: proxy_input_run(proxy),
            analyzer_id: AnalyzerId::new("pi-classifier").unwrap(),
            manifest_identity: proxy_manifest_identity(proxy),
            operation,
        }
    }

    // Test-only values are recovered from the authenticated envelope captured
    // at fixture creation, never from an endpoint path.
    fn proxy_input_run(_proxy: &PiProxy) -> RunId {
        RunId::from_suffix("proxy-test").unwrap()
    }

    fn proxy_manifest_identity(proxy: &PiProxy) -> Digest {
        // The digest is supplied by each caller below because it is not exposed
        // by the capability endpoint. This helper is replaced before sending.
        let _ = proxy;
        Digest::sha256(b"placeholder")
    }

    async fn exchange(path: &Path, request: &ProxyRequest) -> ProxyResponse {
        exchange_raw(path, &serde_json::to_vec(request).unwrap()).await
    }

    async fn exchange_raw(path: &Path, frame: &[u8]) -> ProxyResponse {
        let mut stream = UnixStream::connect(path).await.unwrap();
        let mut encoded = frame.to_vec();
        encoded.push(b'\n');
        stream.write_all(&encoded).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        serde_json::from_slice(&response).unwrap()
    }

    fn bound_request(
        proxy: &PiProxy,
        fixture: &Fixture,
        request_id: u64,
        operation: ProxyOperation,
    ) -> ProxyRequest {
        let mut request = request(proxy, request_id, operation);
        request.manifest_identity = fixture.manifest.identity;
        request
    }

    fn socket(proxy: &PiProxy) -> PathBuf {
        proxy.endpoint().host_socket_path().to_path_buf()
    }

    fn runtime_ready() -> ProxyOperation {
        ProxyOperation::RuntimeReady {
            pi_version: "0.83.0".to_owned(),
            provider: "internal".to_owned(),
            model: "classifier".to_owned(),
            thinking: "high".to_owned(),
            mode: super::super::sandbox::PI_RUNTIME_CONTEXT_MODE.to_owned(),
            model_in_catalog: true,
            active_tools: REQUIRED_TOOLS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    fn terminal(fixture: &Fixture, assigned_count: u64) -> ProxyOperation {
        ProxyOperation::SubmitClassification {
            payload: super::super::protocol::TerminalSubmission {
                schema_version: super::super::protocol::OUTPUT_SCHEMA_VERSION.to_owned(),
                status: super::super::protocol::SubmissionStatus::Complete,
                manifest_identity: fixture.manifest.identity,
                classification: super::super::protocol::TreeClassification {
                    code: ClassificationCode::new("allowed").unwrap(),
                    confidence: ConfiguredConfidence::High,
                    reason_codes: vec![ReasonCode::new("reviewed").unwrap()],
                    subject_artifact_ids: vec![fixture.assignment.artifact_id.clone()],
                },
                artifact_classifications: vec![],
                coverage: super::super::protocol::SubmissionCoverage {
                    assigned_artifact_count: assigned_count,
                    status: super::super::protocol::SubmissionStatus::Complete,
                },
            },
        }
    }

    fn native_begin(tool_call_id: &str, tool: NativeTool, path: &str) -> ProxyOperation {
        ProxyOperation::NativeToolBegin {
            tool_call_id: tool_call_id.to_owned(),
            tool,
            path: path.to_owned(),
        }
    }

    fn native_end(
        tool_call_id: &str,
        tool: NativeTool,
        path: &str,
        success: bool,
        output_bytes: u64,
        result_count: u64,
    ) -> ProxyOperation {
        ProxyOperation::NativeToolEnd {
            tool_call_id: tool_call_id.to_owned(),
            tool,
            path: path.to_owned(),
            success,
            output_bytes,
            result_count,
        }
    }

    #[tokio::test]
    async fn validates_terminal_before_acknowledging_and_keeps_content_private() {
        let fixture = fixture(b"private\0content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert_eq!(
            fs::read_dir(proxy.endpoint().endpoint_dir())
                .unwrap()
                .count(),
            1
        );
        assert!(!proxy
            .endpoint()
            .endpoint_dir()
            .to_string_lossy()
            .contains(proxy.endpoint().run_token()));
        assert!(!proxy
            .endpoint()
            .endpoint_dir()
            .to_string_lossy()
            .contains(&proxy.endpoint().run_token()[..24]));

        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        let instruction = exchange(
            &socket,
            &bound_request(&proxy, &fixture, 2, ProxyOperation::Instruction {}),
        )
        .await;
        assert!(matches!(instruction, ProxyResponse::Ok { .. }));

        let response = exchange(
            &socket,
            &bound_request(&proxy, &fixture, 3, terminal(&fixture, 0)),
        )
        .await;
        assert!(matches!(
            response,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::InvalidRequest
                },
                ..
            }
        ));
        let error = proxy.finish().await.unwrap_err();
        assert!(matches!(error, PiProxyError::InvalidTerminalSubmission));
        let debug = format!("{error:?}");
        assert!(!debug.contains("private"));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn exact_search_budget_can_complete_but_one_more_call_is_fatal() {
        let fixture = fixture(b"aba\0aba");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        let ready = bound_request(&proxy, &fixture, 1, runtime_ready());
        assert!(matches!(
            exchange(&socket, &ready).await,
            ProxyResponse::Ok { .. }
        ));
        let instruction = bound_request(&proxy, &fixture, 2, ProxyOperation::Instruction {});
        assert!(matches!(
            exchange(&socket, &instruction).await,
            ProxyResponse::Ok { .. }
        ));
        let response = exchange(
            &socket,
            &bound_request(
                &proxy,
                &fixture,
                3,
                native_begin("grep-1", NativeTool::Grep, "artifact.bin"),
            ),
        )
        .await;
        assert!(matches!(response, ProxyResponse::Ok { .. }));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    4,
                    native_end("grep-1", NativeTool::Grep, "artifact.bin", true, 4, 2),
                ),
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        let response = exchange(
            &socket,
            &bound_request(
                &proxy,
                &fixture,
                5,
                native_begin("grep-2", NativeTool::Grep, "artifact.bin"),
            ),
        )
        .await;
        assert!(matches!(
            response,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::BudgetExceeded
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::BudgetExceeded)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn manifest_lists_only_view_entries_with_presentation_paths() {
        let fixture = fixture(b"private-content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        let response = exchange(
            &socket,
            &bound_request(&proxy, &fixture, 2, ProxyOperation::ManifestList {}),
        )
        .await;
        let ProxyResponse::Ok { result, .. } = response else {
            panic!("manifest list must succeed");
        };
        assert_eq!(result.as_array().unwrap().len(), 1);
        assert_eq!(result[0]["view_path"], "artifact.bin");
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("private-content"));
        assert!(!encoded.contains("object_id"));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::MissingTerminalSubmission)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn valid_terminal_atomically_closes_and_returns_normalized_observations() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 2, ProxyOperation::Instruction {})
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 3, terminal(&fixture, 1))
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        let outcome = proxy.finish().await.unwrap();
        assert_eq!(outcome.submission.observations().len(), 1);
        assert!(UnixStream::connect(&socket).await.is_err());
        fixture.workspace.remove().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn descriptor_rooted_socket_supports_workspace_paths_beyond_sun_len() {
        let fixture = fixture_with_workspace_padding(b"content", 180);
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let actual_socket = proxy.endpoint().endpoint_dir().join(SOCKET_NAME);
        assert!(actual_socket.as_os_str().len() > 108);
        assert!(proxy.endpoint().host_socket_path().as_os_str().len() < 108);
        assert!(matches!(
            exchange(
                proxy.endpoint().host_socket_path(),
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(actual_socket.exists());
        let debug = format!("{:?}", proxy.endpoint());
        assert!(!debug.contains("/proc/self/fd/"));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::MissingTerminalSubmission)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[test]
    fn oversized_manifest_list_is_rejected_before_endpoint_creation() {
        let sentinel = format!("private-name-{}", "x".repeat(6_000));
        let fixture = fixture_with_paths(b"content", 0, &sentinel);
        let error = match PiProxy::start(&fixture.workspace, input(&fixture)) {
            Ok(_) => panic!("oversized manifest response must fail before launch"),
            Err(error) => error,
        };
        assert!(matches!(&error, PiProxyError::ManifestResponseTooLarge));
        let diagnostic = format!("{error:?}");
        assert!(!diagnostic.contains("private-name"));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn malformed_json_frame_is_fatal() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let response = exchange_raw(&socket(&proxy), br#"{"protocol":]"#).await;
        assert!(matches!(
            response,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::InvalidRequest
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::MalformedFrame)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn wrong_token_and_manifest_are_each_fatal() {
        for wrong_manifest in [false, true] {
            let fixture = fixture(b"content");
            let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
            let mut request = bound_request(&proxy, &fixture, 1, runtime_ready());
            if wrong_manifest {
                request.manifest_identity = Digest::sha256(b"foreign manifest");
            } else {
                request.run_token = "foreign-token".to_owned();
            }
            assert!(matches!(
                exchange(&socket(&proxy), &request).await,
                ProxyResponse::Error {
                    error: WireError {
                        code: ProxyErrorCode::Unauthorized
                    },
                    ..
                }
            ));
            assert!(matches!(
                proxy.finish().await,
                Err(PiProxyError::Unauthorized)
            ));
            fixture.workspace.remove().unwrap();
        }
    }

    #[tokio::test]
    async fn skipped_request_id_is_fatal() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let request = bound_request(&proxy, &fixture, 2, runtime_ready());
        assert!(matches!(
            exchange(&socket(&proxy), &request).await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::ProtocolViolation
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::ProtocolViolation)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn runtime_handshake_mismatch_is_fatal() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let mut operation = runtime_ready();
        let ProxyOperation::RuntimeReady { pi_version, .. } = &mut operation else {
            unreachable!();
        };
        *pi_version = "0.82.0".to_owned();
        let request = bound_request(&proxy, &fixture, 1, operation);
        assert!(matches!(
            exchange(&socket(&proxy), &request).await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::ProtocolViolation
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::RuntimeMismatch)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn absolute_or_unassigned_view_path_is_fatal() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        let ready = bound_request(&proxy, &fixture, 1, runtime_ready());
        assert!(matches!(
            exchange(&socket, &ready).await,
            ProxyResponse::Ok { .. }
        ));
        let foreign = bound_request(
            &proxy,
            &fixture,
            2,
            native_begin("read-1", NativeTool::Read, "/proc/self/environ"),
        );
        assert!(matches!(
            exchange(&socket, &foreign).await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::Unauthorized
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::Unauthorized)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn native_tool_end_must_match_the_outstanding_begin_exactly() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    2,
                    native_begin("read-1", NativeTool::Read, "artifact.bin"),
                ),
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        let mismatched = bound_request(
            &proxy,
            &fixture,
            3,
            native_end("read-1", NativeTool::Read, "other.txt", true, 7, 1),
        );
        assert!(matches!(
            exchange(&socket, &mismatched).await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::ProtocolViolation
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::ProtocolViolation)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn native_tool_output_is_bounded_independently_of_proxy_responses() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    2,
                    native_begin("read-1", NativeTool::Read, "artifact.bin"),
                ),
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    3,
                    native_end(
                        "read-1",
                        NativeTool::Read,
                        "artifact.bin",
                        true,
                        NATIVE_TOOL_MAX_OUTPUT_BYTES as u64 + 1,
                        1,
                    ),
                ),
            )
            .await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::BudgetExceeded
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::BudgetExceeded)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn failed_native_tool_permanently_prevents_terminal_submission() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    2,
                    native_begin("grep-1", NativeTool::Grep, "."),
                ),
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    3,
                    native_end("grep-1", NativeTool::Grep, ".", false, 0, 0),
                ),
            )
            .await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::InvalidRequest
                },
                ..
            }
        ));
        assert!(UnixStream::connect(&socket).await.is_err());
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::NativeToolFailed)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn terminal_is_rejected_while_a_native_tool_is_outstanding() {
        let fixture = fixture(b"content");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(
                    &proxy,
                    &fixture,
                    2,
                    native_begin("read-1", NativeTool::Read, "artifact.bin"),
                ),
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 3, terminal(&fixture, 1)),
            )
            .await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::ProtocolViolation
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::ProtocolViolation)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn oversized_assigned_artifact_is_rejected_before_native_search() {
        let fixture = fixture(b"five!");
        let mut configured = input(&fixture);
        configured.limits.max_search_bytes_per_call = 4;
        let proxy = PiProxy::start(&fixture.workspace, configured).unwrap();
        let socket = socket(&proxy);
        assert!(matches!(
            exchange(
                &socket,
                &bound_request(&proxy, &fixture, 1, runtime_ready())
            )
            .await,
            ProxyResponse::Ok { .. }
        ));
        let search = bound_request(
            &proxy,
            &fixture,
            2,
            native_begin("grep-1", NativeTool::Grep, "."),
        );
        assert!(matches!(
            exchange(&socket, &search).await,
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::BudgetExceeded
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::BudgetExceeded)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn oversized_frame_is_bounded_and_fatal() {
        let fixture = fixture(b"data");
        let mut configured = input(&fixture);
        configured.limits.max_frame_bytes = 8;
        let proxy = PiProxy::start(&fixture.workspace, configured).unwrap();
        let socket = socket(&proxy);
        let mut client = UnixStream::connect(&socket).await.unwrap();
        client.write_all(b"123456789\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(matches!(
            serde_json::from_slice::<ProxyResponse>(&response).unwrap(),
            ProxyResponse::Error {
                error: WireError {
                    code: ProxyErrorCode::BudgetExceeded
                },
                ..
            }
        ));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::FrameTooLarge)
        ));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn finish_interrupts_a_partial_frame_and_removes_the_endpoint() {
        let fixture = fixture(b"data");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        let endpoint = proxy.endpoint().endpoint_dir().to_path_buf();
        let mut client = UnixStream::connect(&socket).await.unwrap();
        client.write_all(b"{").await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), proxy.finish())
            .await
            .expect("finish must interrupt the active frame");
        assert!(matches!(
            result,
            Err(PiProxyError::MissingTerminalSubmission)
        ));
        assert!(!endpoint.exists());
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn finish_without_terminal_is_prompt_and_cleans_the_endpoint() {
        let fixture = fixture(b"data");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let endpoint = proxy.endpoint().endpoint_dir().to_path_buf();
        let result = tokio::time::timeout(Duration::from_secs(1), proxy.finish())
            .await
            .expect("finish must cancel an idle listener");
        assert!(matches!(
            result,
            Err(PiProxyError::MissingTerminalSubmission)
        ));
        assert!(!endpoint.exists());
        fixture.workspace.remove().unwrap();
    }

    #[test]
    fn extension_response_ceiling_is_checked_without_allocating_content() {
        let mut configured = limits();
        configured.max_response_bytes = EXTENSION_MAX_RESPONSE_BYTES;
        assert!(configured.validate().is_ok());
        configured.max_response_bytes += 1;
        assert!(matches!(
            configured.validate(),
            Err(PiProxyError::InvalidLimits)
        ));
    }

    #[test]
    fn error_debug_never_contains_raw_content() {
        let content = b"super-secret-value";
        let fixture = fixture(content);
        let error = PiProxyError::NativeToolFailed;
        assert!(!format!("{error:?}").contains("super-secret-value"));
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn endpoint_debug_redacts_the_capability_token() {
        let fixture = fixture(b"data");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let token = proxy.endpoint().run_token().to_owned();
        let debug = format!("{:?}", proxy.endpoint());
        assert!(!debug.contains(&token));
        assert!(debug.contains("[REDACTED]"));
        assert!(matches!(
            proxy.finish().await,
            Err(PiProxyError::MissingTerminalSubmission)
        ));
        fixture.workspace.remove().unwrap();
    }
}
