use super::protocol::{
    ClassificationVocabulary, ProxyError as WireError, ProxyErrorCode, ProxyOperation,
    ProxyRequest, ProxyResponse, TerminalValidationContext, TerminalValidationLimits,
    ValidatedSubmission, PROTOCOL_VERSION, REQUIRED_TOOLS,
};
use crate::authorization::{InvocationWorkspace, ObjectStore, WorkspaceError};
use crate::domain::{
    AnalyzerId, Artifact, ArtifactId, ArtifactKind, ArtifactManifest, CandidateId,
    ClassificationScope, Digest, InspectionPhase, LogicalPath, Provenance, RunId,
};
use crate::pipeline::{ArtifactAssignment, PriorObservationProjection};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, watch};

const SOCKET_NAME: &str = "proxy.sock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiProxyLimits {
    pub max_frame_bytes: usize,
    pub max_response_bytes: usize,
    pub max_terminal_bytes: usize,
    pub max_tool_calls: u64,
    pub max_bytes_read: u64,
    pub max_read_bytes_per_call: u64,
    pub max_search_pattern_bytes: usize,
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
            || self.max_search_pattern_bytes == 0
            || self.max_search_matches == 0
            || self.max_search_bytes_per_call == 0
            || self.max_search_calls == 0
            || self.frame_read_timeout.is_zero()
            || encoded_response_upper_bound(self.max_read_bytes_per_call)
                .is_none_or(|size| size > self.max_response_bytes as u64)
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
    pub objects: Arc<ObjectStore>,
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

    /// Stops the server and removes the only socket and its private directory.
    pub async fn shutdown(mut self) -> Result<(), PiProxyError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        (&mut self.task)
            .await
            .map_err(|_| PiProxyError::ServerStopped)?;
        self.cleanup_endpoint()
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
    bytes_read: u64,
    search_calls: u64,
    next_request_id: u64,
    ready: bool,
    progress: watch::Sender<ProxyProgress>,
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
            bytes_read: 0,
            search_calls: 0,
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
            let connection_limit = self
                .limits
                .max_tool_calls
                .checked_add(2)
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
                let entries = self
                    .assignments
                    .iter()
                    .map(|(artifact_id, candidate_id)| {
                        let artifact = self.artifact(artifact_id)?;
                        Ok(ManifestEntry {
                            candidate_id,
                            artifact_id,
                            logical_path: logical_path(artifact),
                            kind: artifact.kind,
                            byte_len: artifact.byte_len,
                            content_digest: artifact.content_digest,
                        })
                    })
                    .collect::<Result<Vec<_>, PiProxyError>>()?;
                Ok(OperationResult::Continue(to_value(entries)?))
            }
            ProxyOperation::ArtifactMetadata { artifact_id } => {
                self.require_ready()?;
                let candidate_id = self.authorize(&artifact_id)?;
                let artifact = self.artifact(&artifact_id)?;
                Ok(OperationResult::Continue(to_value(ManifestEntry {
                    candidate_id,
                    artifact_id: &artifact.id,
                    logical_path: logical_path(artifact),
                    kind: artifact.kind,
                    byte_len: artifact.byte_len,
                    content_digest: artifact.content_digest,
                })?))
            }
            ProxyOperation::ArtifactRead { artifact_id } => {
                self.require_ready()?;
                let artifact = self.authorized_artifact(&artifact_id)?;
                self.reserve_read(artifact.byte_len, self.limits.max_read_bytes_per_call)?;
                self.reserve_encoded_response(artifact.byte_len)?;
                let object_id = artifact.object_id.clone();
                let expected = artifact.byte_len;
                let objects = Arc::clone(&self.input.objects);
                let bytes = blocking(move || read_whole(&objects, &object_id, expected)).await?;
                self.charge_read(bytes.len() as u64)?;
                Ok(OperationResult::Continue(json!({
                    "encoding": "base64",
                    "bytes": STANDARD.encode(bytes),
                    "complete": true
                })))
            }
            ProxyOperation::ArtifactReadRange {
                artifact_id,
                offset,
                length,
            } => {
                self.require_ready()?;
                let artifact = self.authorized_artifact(&artifact_id)?;
                let end = offset
                    .checked_add(length)
                    .ok_or(PiProxyError::InvalidRequest)?;
                if length == 0 || end > artifact.byte_len {
                    return Err(PiProxyError::InvalidRequest);
                }
                self.reserve_read(length, self.limits.max_read_bytes_per_call)?;
                self.reserve_encoded_response(length)?;
                let object_id = artifact.object_id.clone();
                let objects = Arc::clone(&self.input.objects);
                let bytes =
                    blocking(move || read_range(&objects, &object_id, offset, length)).await?;
                self.charge_read(bytes.len() as u64)?;
                Ok(OperationResult::Continue(json!({
                    "encoding": "base64",
                    "offset": offset,
                    "bytes": STANDARD.encode(bytes),
                    "complete": true
                })))
            }
            ProxyOperation::ArtifactSearch {
                artifact_id,
                literal,
                max_matches,
            } => {
                self.require_ready()?;
                self.search_calls = self
                    .search_calls
                    .checked_add(1)
                    .ok_or(PiProxyError::BudgetExceeded)?;
                if self.search_calls > self.limits.max_search_calls {
                    return Err(PiProxyError::BudgetExceeded);
                }
                let pattern = literal.into_bytes();
                if pattern.is_empty()
                    || pattern.len() > self.limits.max_search_pattern_bytes
                    || max_matches == 0
                    || max_matches > self.limits.max_search_matches
                {
                    return Err(PiProxyError::BudgetExceeded);
                }
                let artifact = self.authorized_artifact(&artifact_id)?;
                self.reserve_read(artifact.byte_len, self.limits.max_search_bytes_per_call)?;
                let match_bytes = max_matches
                    .checked_mul(22)
                    .ok_or(PiProxyError::BudgetExceeded)?;
                if match_bytes > self.limits.max_response_bytes as u64 {
                    return Err(PiProxyError::BudgetExceeded);
                }
                let object_id = artifact.object_id.clone();
                let expected = artifact.byte_len;
                let objects = Arc::clone(&self.input.objects);
                let matches = blocking(move || {
                    literal_search(&objects, &object_id, expected, &pattern, max_matches)
                })
                .await?;
                self.charge_read(artifact.byte_len)?;
                Ok(OperationResult::Continue(json!({"offsets": matches})))
            }
            ProxyOperation::PriorObservations {} => {
                self.require_ready()?;
                let value = serde_json::from_slice(self.input.prior_observations.canonical_json())
                    .map_err(|_| PiProxyError::Internal)?;
                Ok(OperationResult::Continue(value))
            }
            ProxyOperation::SubmitClassification { payload } => {
                self.require_ready()?;
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

    fn authorize(&self, id: &ArtifactId) -> Result<&CandidateId, PiProxyError> {
        self.assignments.get(id).ok_or(PiProxyError::Unauthorized)
    }

    fn artifact(&self, id: &ArtifactId) -> Result<&Artifact, PiProxyError> {
        self.input
            .manifest
            .artifact(id)
            .ok_or(PiProxyError::Internal)
    }

    fn authorized_artifact(&self, id: &ArtifactId) -> Result<&Artifact, PiProxyError> {
        self.authorize(id)?;
        self.artifact(id)
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

    fn reserve_encoded_response(&self, raw_bytes: u64) -> Result<(), PiProxyError> {
        // Base64 expands to four bytes per three input bytes. The fixed 512-byte
        // allowance covers the response envelope and numeric metadata.
        let encoded =
            encoded_response_upper_bound(raw_bytes).ok_or(PiProxyError::BudgetExceeded)?;
        if encoded > self.limits.max_response_bytes as u64 {
            return Err(PiProxyError::BudgetExceeded);
        }
        Ok(())
    }
}

fn encoded_response_upper_bound(raw_bytes: u64) -> Option<u64> {
    raw_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| value.checked_add(512))
}

#[derive(Serialize)]
struct ManifestEntry<'a> {
    candidate_id: &'a CandidateId,
    artifact_id: &'a ArtifactId,
    logical_path: &'a LogicalPath,
    kind: ArtifactKind,
    byte_len: u64,
    content_digest: Digest,
}

fn logical_path(artifact: &Artifact) -> &LogicalPath {
    match &artifact.provenance {
        Provenance::Physical { logical_path } => logical_path,
        Provenance::Derived { member_path, .. } => member_path,
    }
}

fn validate_input(input: &PiProxyInput) -> Result<(), PiProxyError> {
    let instruction_response = ProxyResponse::Ok {
        protocol: PROTOCOL_VERSION.to_owned(),
        request_id: u64::MAX,
        result: json!({"instruction": input.instruction.as_ref()}),
    };
    if input.instruction.is_empty()
        || serde_json::to_vec(&instruction_response)
            .map_err(|_| PiProxyError::InvalidInstruction)?
            .len()
            .checked_add(1)
            .is_none_or(|size| size > input.limits.max_response_bytes)
    {
        return Err(PiProxyError::InvalidInstruction);
    }
    if input
        .assignments
        .iter()
        .any(|assignment| input.manifest.artifact(&assignment.artifact_id).is_none())
    {
        return Err(PiProxyError::InvalidAssignment);
    }
    Ok(())
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

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, PiProxyError> + Send + 'static,
) -> Result<T, PiProxyError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| PiProxyError::Internal)?
}

fn read_whole(
    objects: &ObjectStore,
    id: &crate::domain::ObjectId,
    expected: u64,
) -> Result<Vec<u8>, PiProxyError> {
    let capacity = usize::try_from(expected).map_err(|_| PiProxyError::BudgetExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    objects
        .open(id)
        .map_err(|_| PiProxyError::ObjectRead)?
        .take(expected.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PiProxyError::ObjectRead)?;
    if bytes.len() as u64 != expected {
        return Err(PiProxyError::ObjectRead);
    }
    Ok(bytes)
}

fn read_range(
    objects: &ObjectStore,
    id: &crate::domain::ObjectId,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, PiProxyError> {
    let capacity = usize::try_from(length).map_err(|_| PiProxyError::BudgetExceeded)?;
    let mut file = objects.open(id).map_err(|_| PiProxyError::ObjectRead)?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| PiProxyError::ObjectRead)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(length)
        .read_to_end(&mut bytes)
        .map_err(|_| PiProxyError::ObjectRead)?;
    if bytes.len() as u64 != length {
        return Err(PiProxyError::ObjectRead);
    }
    Ok(bytes)
}

fn literal_search(
    objects: &ObjectStore,
    id: &crate::domain::ObjectId,
    expected: u64,
    pattern: &[u8],
    max_matches: u64,
) -> Result<Vec<u64>, PiProxyError> {
    let bytes = read_whole(objects, id, expected)?;
    let mut offsets = Vec::new();
    for (offset, window) in bytes.windows(pattern.len()).enumerate() {
        if window == pattern {
            offsets.push(u64::try_from(offset).map_err(|_| PiProxyError::Internal)?);
            if offsets.len() as u64 == max_matches {
                break;
            }
        }
    }
    Ok(offsets)
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
    #[error("Pi proxy could not read an immutable object")]
    ObjectRead,
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
            Self::MalformedFrame | Self::InvalidRequest | Self::InvalidTerminalSubmission => {
                ProxyErrorCode::InvalidRequest
            }
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
    use crate::domain::{
        ClassificationCode, ConfiguredConfidence, ObjectId, PathSegment, PhysicalSubject,
        ReasonCode, SourceFileType, SourceIdentity, SubjectId,
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
        fixture_with_workspace_padding(bytes, 0)
    }

    fn fixture_with_workspace_padding(bytes: &[u8], padding: usize) -> Fixture {
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
            LogicalPath::new(vec![PathSegment::utf8("artifact.bin").unwrap()]).unwrap();
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
            max_search_pattern_bytes: 32,
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
            objects: fixture.workspace.objects_arc(),
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
                mode: "text".to_owned(),
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
        let mut stream = UnixStream::connect(path).await.unwrap();
        let mut encoded = serde_json::to_vec(request).unwrap();
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
            mode: "text".to_owned(),
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
        let search = |request_id| {
            bound_request(
                &proxy,
                &fixture,
                request_id,
                ProxyOperation::ArtifactSearch {
                    artifact_id: fixture.assignment.artifact_id.clone(),
                    literal: super::super::protocol::Base64UrlBytes::new(b"a".to_vec()),
                    max_matches: 2,
                },
            )
        };
        let response = exchange(&socket, &search(3)).await;
        match response {
            ProxyResponse::Ok { result, .. } => assert_eq!(result["offsets"], json!([0, 2])),
            _ => panic!("search at the exact call budget must succeed"),
        }
        let response = exchange(&socket, &search(4)).await;
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
        proxy.shutdown().await.unwrap();
        fixture.workspace.remove().unwrap();
    }

    #[tokio::test]
    async fn foreign_or_unassigned_artifact_is_fatal_without_opening_an_object() {
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
            ProxyOperation::ArtifactRead {
                artifact_id: ArtifactId::from_suffix("foreign").unwrap(),
            },
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
    async fn oversized_assigned_artifact_is_rejected_before_search_allocation() {
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
            ProxyOperation::ArtifactSearch {
                artifact_id: fixture.assignment.artifact_id.clone(),
                literal: super::super::protocol::Base64UrlBytes::new(b"f".to_vec()),
                max_matches: 1,
            },
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
    async fn shutdown_interrupts_a_partial_frame_and_removes_the_endpoint() {
        let fixture = fixture(b"data");
        let proxy = PiProxy::start(&fixture.workspace, input(&fixture)).unwrap();
        let socket = socket(&proxy);
        let endpoint = proxy.endpoint().endpoint_dir().to_path_buf();
        let mut client = UnixStream::connect(&socket).await.unwrap();
        client.write_all(b"{").await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), proxy.shutdown())
            .await
            .expect("shutdown must interrupt the active frame")
            .unwrap();
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
    fn encoded_response_boundary_is_checked_without_allocating_content() {
        let mut configured = limits();
        configured.max_response_bytes = encoded_response_upper_bound(1024).unwrap() as usize;
        assert!(configured.validate().is_ok());
        configured.max_response_bytes -= 1;
        assert!(matches!(
            configured.validate(),
            Err(PiProxyError::InvalidLimits)
        ));
    }

    #[test]
    fn error_debug_never_contains_raw_content() {
        let content = b"super-secret-value";
        let fixture = fixture(content);
        let missing = ObjectId::from_suffix("missing").unwrap();
        let error =
            read_whole(fixture.workspace.objects(), &missing, content.len() as u64).unwrap_err();
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
        proxy.shutdown().await.unwrap();
        fixture.workspace.remove().unwrap();
    }
}
