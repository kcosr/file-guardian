use super::protocol::{
    NativeTool, NativeToolErrorCode, NativeToolOutcome, ProxyError as WireError, ProxyErrorCode,
    ProxyOperation, ProxyRequest, ProxyResponse, PROTOCOL_VERSION, REQUIRED_TOOLS,
};
use super::triage::{
    normalize_terminal, PiTriageLimits, PiTriageRequest, PiTriageResult, PiTriageVocabulary,
};
use crate::authorization::{
    AnalyzerView, AnalyzerViewEntry, AnalyzerViewNode, InvocationWorkspace, WorkspaceError,
};
use crate::domain::{AnalyzerId, ArtifactId, ArtifactManifest, CandidateId, RunId};
use crate::pipeline::ArtifactAssignment;
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
    pub triage_request: Arc<PiTriageRequest>,
    pub instruction: Arc<str>,
    pub expected_runtime: ExpectedPiRuntime,
    pub vocabulary: Arc<PiTriageVocabulary>,
    pub triage_limits: PiTriageLimits,
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
    pub submission: PiTriageResult,
}

#[derive(Clone)]
pub struct PiProxyEndpoint {
    endpoint_dir: PathBuf,
    host_socket_path: PathBuf,
    #[cfg(target_os = "linux")]
    directory_fd: std::os::fd::RawFd,
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
    /// Descriptor-short host path. This is never mounted into the sandbox or
    /// included in reports and is valid only while the proxy owns its endpoint.
    pub(crate) fn host_socket_path(&self) -> &Path {
        &self.host_socket_path
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn directory_fd(&self) -> std::os::fd::RawFd {
        self.directory_fd
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn directory_fd(&self) -> std::os::fd::RawFd {
        // PreparedPiRuntime rejects the Pi analyzer before launch on non-Linux
        // platforms. This keeps the shared orchestration type-checkable without
        // weakening the Linux descriptor-inheritance contract.
        -1
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
            host_socket_path: socket_path,
            #[cfg(target_os = "linux")]
            directory_fd: endpoint_directory.raw_directory_fd(),
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
        let _ = self.cleanup_endpoint();
    }
}

struct Server {
    input: PiProxyInput,
    token: Arc<str>,
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
    Terminal(PiTriageResult),
}

impl Server {
    fn new(
        input: PiProxyInput,
        token: Arc<str>,
        limits: PiProxyLimits,
        progress: watch::Sender<ProxyProgress>,
    ) -> Result<Self, PiProxyError> {
        let assignments: BTreeMap<ArtifactId, CandidateId> = input
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
            || !constant_time_token_eq(&request.run_token, &self.token)
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
            ProxyOperation::ManifestList { cursor } => {
                self.require_ready()?;
                self.charge_tool_call()?;
                Ok(OperationResult::Continue(manifest_page_value(
                    &self.input,
                    cursor,
                )?))
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
                    (NativeTool::Bash, AnalyzerViewNode::Directory { .. }) if path == "." => 0,
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
                    NativeTool::Bash | NativeTool::Find | NativeTool::Ls => {}
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
                outcome,
                error_code,
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
                match (outcome, error_code) {
                    (NativeToolOutcome::Completed, None) => {
                        if output_bytes > NATIVE_TOOL_MAX_OUTPUT_BYTES as u64
                            || result_count > self.limits.max_search_matches
                            || (tool == NativeTool::Read && result_count != 1)
                        {
                            return Err(PiProxyError::BudgetExceeded);
                        }
                    }
                    (
                        NativeToolOutcome::RecoverableError,
                        Some(NativeToolErrorCode::InvalidArguments),
                    ) if output_bytes == 0 && result_count == 0 => {}
                    (NativeToolOutcome::FatalError, Some(NativeToolErrorCode::ExecutionFailed))
                        if output_bytes == 0 && result_count == 0 =>
                    {
                        return Err(PiProxyError::NativeToolFailed);
                    }
                    _ => return Err(PiProxyError::ProtocolViolation),
                }
                Ok(OperationResult::Continue(json!({"accepted": true})))
            }
            ProxyOperation::TriageRequest {} => {
                self.require_ready()?;
                self.charge_tool_call()?;
                let value = serde_json::from_slice(
                    &self
                        .input
                        .triage_request
                        .canonical_json()
                        .map_err(|_| PiProxyError::Internal)?,
                )
                .map_err(|_| PiProxyError::Internal)?;
                Ok(OperationResult::Continue(value))
            }
            ProxyOperation::SubmitTriage { payload } => {
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
                let submission = normalize_terminal(
                    payload,
                    &self.input.triage_request,
                    &self.input.vocabulary,
                    self.input.triage_limits,
                )
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

fn constant_time_token_eq(candidate: &str, expected: &str) -> bool {
    let candidate = candidate.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = candidate.len() ^ expected.len();
    for (index, expected_byte) in expected.iter().enumerate() {
        difference |= usize::from(candidate.get(index).copied().unwrap_or(0) ^ expected_byte);
    }
    difference == 0
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
    if input.triage_request.run_id != input.run_id
        || input.triage_request.manifest_identity != input.manifest.identity
        || input.triage_request.validate_identity().is_err()
        || usize::try_from(input.triage_request.assigned_artifact_count)
            .ok()
            .is_none_or(|assigned| assigned < input.assignments.len())
        || input
            .triage_request
            .findings
            .iter()
            .any(|finding| input.manifest.artifact(&finding.artifact_id).is_none())
    {
        return Err(PiProxyError::InvalidAssignment);
    }
    let triage_request = serde_json::from_slice(
        &input
            .triage_request
            .canonical_json()
            .map_err(|_| PiProxyError::Internal)?,
    )
    .map_err(|_| PiProxyError::Internal)?;
    if !response_fits(triage_request, input.limits.max_response_bytes)? {
        return Err(PiProxyError::TriageRequestResponseTooLarge);
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
    validate_manifest_entry_pages(input)?;
    Ok(())
}

const MANIFEST_PAGE_SCHEMA: &str = "file-guardian-pi-manifest-page/1";

#[derive(Serialize)]
struct ManifestPage<'a> {
    schema: &'static str,
    manifest_identity: crate::domain::Digest,
    cursor: u64,
    total_count: u64,
    entries: &'a [AnalyzerViewEntry],
    next_cursor: Option<u64>,
}

fn validate_manifest_entry_pages(input: &PiProxyInput) -> Result<(), PiProxyError> {
    let entries = input.view.entries();
    let total_count = u64::try_from(entries.len()).map_err(|_| PiProxyError::Internal)?;
    if entries.is_empty() {
        let page = manifest_page_payload(input, 0, entries, None, total_count)?;
        if !response_fits(page, input.limits.max_response_bytes)? {
            return Err(PiProxyError::ManifestEntryResponseTooLarge);
        }
        return Ok(());
    }

    // Validate only the per-entry progress invariant. Aggregate manifest
    // metadata may be arbitrarily larger than one response and is paged.
    for (index, entry) in entries.iter().enumerate() {
        let cursor = u64::try_from(index).map_err(|_| PiProxyError::Internal)?;
        let next_cursor = (index + 1 < entries.len())
            .then(|| u64::try_from(index + 1).map_err(|_| PiProxyError::Internal))
            .transpose()?;
        let page = manifest_page_payload(
            input,
            cursor,
            std::slice::from_ref(entry),
            next_cursor,
            total_count,
        )?;
        if !response_fits(page, input.limits.max_response_bytes)? {
            return Err(PiProxyError::ManifestEntryResponseTooLarge);
        }
    }
    Ok(())
}

fn manifest_page_value(input: &PiProxyInput, cursor: u64) -> Result<Value, PiProxyError> {
    let entries = input.view.entries();
    let total_count = u64::try_from(entries.len()).map_err(|_| PiProxyError::Internal)?;
    let start = usize::try_from(cursor).map_err(|_| PiProxyError::InvalidRequest)?;
    if entries.is_empty() {
        if cursor != 0 {
            return Err(PiProxyError::InvalidRequest);
        }
        return manifest_page_payload(input, cursor, entries, None, total_count);
    }
    if start > entries.len() {
        return Err(PiProxyError::ProtocolViolation);
    }
    if start == entries.len() {
        return manifest_page_payload(input, cursor, &[], None, total_count);
    }

    let base = manifest_page_payload(input, cursor, &[], Some(u64::MAX), total_count)?;
    let mut wire_size = response_wire_size(base)?;
    let mut end = start;
    while let Some(entry) = entries.get(end) {
        let entry_size = serde_json::to_vec(entry)
            .map_err(|_| PiProxyError::Internal)?
            .len();
        let separator = usize::from(end > start);
        let next_size = wire_size
            .checked_add(separator)
            .and_then(|size| size.checked_add(entry_size))
            .ok_or(PiProxyError::ResponseTooLarge)?;
        if next_size > input.limits.max_response_bytes {
            break;
        }
        wire_size = next_size;
        end += 1;
    }
    if end == start {
        // Conservative maximum-width cursor framing can leave less room than
        // this exact page needs. Preflight guarantees the single-entry page.
        end = start.checked_add(1).ok_or(PiProxyError::Internal)?;
    }
    let next_cursor = (end < entries.len())
        .then(|| u64::try_from(end).map_err(|_| PiProxyError::Internal))
        .transpose()?;
    let page = manifest_page_payload(
        input,
        cursor,
        &entries[start..end],
        next_cursor,
        total_count,
    )?;
    if !response_fits(page.clone(), input.limits.max_response_bytes)? {
        return Err(PiProxyError::Internal);
    }
    Ok(page)
}

fn manifest_page_payload(
    input: &PiProxyInput,
    cursor: u64,
    entries: &[AnalyzerViewEntry],
    next_cursor: Option<u64>,
    total_count: u64,
) -> Result<Value, PiProxyError> {
    to_value(ManifestPage {
        schema: MANIFEST_PAGE_SCHEMA,
        manifest_identity: input.manifest.identity,
        cursor,
        total_count,
        entries,
        next_cursor,
    })
}

fn response_wire_size(result: Value) -> Result<usize, PiProxyError> {
    let response = ProxyResponse::Ok {
        protocol: PROTOCOL_VERSION.to_owned(),
        request_id: u64::MAX,
        result,
    };
    serde_json::to_vec(&response)
        .map_err(|_| PiProxyError::Internal)?
        .len()
        .checked_add(1)
        .ok_or(PiProxyError::ResponseTooLarge)
}

fn response_fits(result: Value, max_response_bytes: usize) -> Result<bool, PiProxyError> {
    Ok(response_wire_size(result)? <= max_response_bytes)
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
    #[error("one Pi manifest entry cannot fit in a bounded page response")]
    ManifestEntryResponseTooLarge,
    #[error("Pi triage request cannot fit in one bounded response")]
    TriageRequestResponseTooLarge,
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
    #[error("Pi terminal triage failed semantic validation")]
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
    #[error("Pi process exited without an accepted terminal triage response")]
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
        // Any failed tool operation invalidates trusted Pi's coverage;
        // continuing would permit an incomplete review to submit a
        // superficially complete result.
        !matches!(self, Self::Stopped)
    }
}
