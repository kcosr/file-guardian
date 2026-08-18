//! Schema-3 processing runtime compilation.
//!
//! Compilation freezes a validated profile, source request, analyzer resources,
//! and policy material before a job creates or mutates a stage. It deliberately
//! does not accept schema-2 configuration or synthesize compatibility aliases.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use globset::Glob;
use serde::Serialize;
use thiserror::Error;

use crate::analyzers::external::{
    GitleaksAdapter, PreparedProtectedFile, PreparedScannerExecutable, PreparedScannerSandbox,
    ScannerKind, ScannerRunLimits, ScannerSandboxSpec, ScannerVersion, ScannerVersionRequirement,
    TrufflehogAdapter,
};
use crate::analyzers::{
    BuiltinAnalyzerLimits, BuiltinContentApplicability, BuiltinRulesAnalyzer, RequiredTextMatcher,
};
use crate::domain::{AnalyzerId, Digest, RunId};
use crate::pipeline::{PriorObservationMode, ProjectionLimits, StageExecution, StageId};
use crate::processing::config::{
    self, AnalyzerArtifactKind, AnalyzerConfig, AnalyzerKind, CompletionPolicy, HistoryScope,
    LfsPolicy, PhaseExecution, PiAdjudicationMode, ProcessingConfigFile, ProcessingProfile,
    ProfilePurpose, SubmodulePolicy,
};
use crate::processing::domain::{GitHistoryScope, GitTransport, ProcessPurpose};
use crate::processing::policy::CompiledProcessingPolicy;
use crate::rules::load_rule_files;

/// Caller-selected authority. `Apply` is accepted only when the profile grants it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedActionMode {
    Evaluate,
    Apply,
}

/// One strict source request. Paths and locators are private runtime inputs and
/// must never be copied into the processing report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessingSourceRequest {
    Path {
        path: PathBuf,
    },
    Git {
        remote: String,
        reference: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct ProcessingCompileRequest {
    pub run_id: RunId,
    pub profile_id: Option<String>,
    pub action_mode: Option<RequestedActionMode>,
    pub source: ProcessingSourceRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveActionMode {
    Evaluate,
    Apply,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenSourceScope {
    pub working_tree: bool,
    pub history: GitHistoryScope,
    pub history_ref_patterns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenGitConstraints {
    pub allowed_checkout_ref_patterns: Vec<String>,
    pub submodules: SubmodulePolicy,
    pub lfs: LfsPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrozenSourceRequest {
    Path {
        path: PathBuf,
    },
    Git {
        remote: String,
        transport: GitTransport,
        checkout_ref: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenJobLimits {
    pub jobs_root: PathBuf,
    pub reports_root: PathBuf,
    pub quarantine_root: PathBuf,
    pub artifact_quarantine_root: PathBuf,
    pub stale_after_secs: u64,
    pub max_report_bytes: u64,
    pub capture: FrozenCaptureLimits,
    pub retention: FrozenRetentionLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenCaptureLimits {
    pub max_entries: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenRetentionLimits {
    pub available_ttl_secs: u64,
    pub available_max_bytes: u64,
    pub quarantine_ttl_secs: u64,
    pub quarantine_max_bytes: u64,
    pub artifact_quarantine_ttl_secs: u64,
    pub artifact_quarantine_max_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenAcquisitionLimits {
    pub git_executable: PathBuf,
    pub git_timeout_secs: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_refs: u64,
    pub max_commits: u64,
    pub max_unique_blobs: u64,
    pub max_provenance_occurrences: u64,
    pub max_git_bytes: u64,
}

pub struct CompiledProcessingRuntime {
    pub run_id: RunId,
    pub profile_id: String,
    pub purpose: ProcessPurpose,
    pub action_mode: EffectiveActionMode,
    pub source: FrozenSourceRequest,
    pub source_scope: FrozenSourceScope,
    pub git_constraints: FrozenGitConstraints,
    pub source_scope_identity: Digest,
    pub jobs: FrozenJobLimits,
    pub acquisition: FrozenAcquisitionLimits,
    pub policy: CompiledProcessingPolicy,
    pub completion: CompletionPolicy,
    pub pipeline: FrozenPipeline,
    pub pipeline_identity: Digest,
    pub policy_identity: Digest,
    pub pi_adjudication: Option<CompiledPiAdjudication>,
}

pub struct FrozenPipeline {
    pub id: String,
    pub stages: Vec<FrozenStage>,
}

pub struct FrozenStage {
    pub id: StageId,
    pub execution: StageExecution,
    pub prior_observations: PriorObservationMode,
    pub prior_limits: ProjectionLimits,
    pub analyzers: Vec<FrozenAnalyzer>,
}

pub struct FrozenAnalyzer {
    pub id: AnalyzerId,
    pub initial: PhaseExecution,
    pub verification: PhaseExecution,
    pub identity: Digest,
    pub selection: FrozenAnalyzerSelection,
    pub implementation: FrozenAnalyzerImplementation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenAnalyzerSelection {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub artifact_kinds: Vec<AnalyzerArtifactKind>,
    pub required_text_include: Vec<String>,
}

pub enum FrozenAnalyzerImplementation {
    Builtin(BuiltinRulesAnalyzer),
    Pi(FrozenPiRuntime),
    External(FrozenExternalAnalyzer),
}

/// Frozen Pi runtime material. The existing Pi host/sidecar owns execution;
/// this value proves that its administrator files and credential mapping were
/// available when the processing pipeline identity was compiled.
pub struct FrozenPiRuntime {
    pub config: config::PiClassifierConfig,
    pub instruction: Arc<str>,
    pub instruction_identity: Digest,
    pub credential_environment: Vec<(OsString, OsString)>,
    pub required_text_include: Vec<String>,
    pub limits: FrozenPiLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenPiLimits {
    pub startup_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub wall_timeout_secs: u64,
    pub termination_grace_secs: u64,
    pub cpu_time_secs: u64,
    pub max_open_files: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_file_bytes: Option<u64>,
    pub max_output_bytes: u64,
    pub max_findings: u64,
    pub max_tool_calls: u64,
    pub max_bytes_read: u64,
    pub max_read_bytes_per_call: u64,
    pub max_search_bytes_per_call: u64,
    pub max_search_calls: u64,
    pub max_search_results: u64,
    pub max_view_files: u64,
    pub max_view_entries: u64,
    pub max_view_bytes: u64,
    pub max_view_depth: u64,
}

pub struct FrozenExternalAnalyzer {
    pub kind: ScannerKind,
    pub executable: PreparedScannerExecutable,
    pub protected_files: Vec<PreparedProtectedFile>,
    pub sandbox: PreparedScannerSandbox,
    pub version_requirement: FrozenScannerVersionRequirement,
    pub limits: ScannerRunLimits,
    pub max_file_bytes: u64,
    pub max_findings: u64,
    pub required_text_include: Vec<String>,
}

impl FrozenExternalAnalyzer {
    pub const fn scanner_version_requirement(&self) -> ScannerVersionRequirement {
        ScannerVersionRequirement::new(
            ScannerVersion::new(
                self.version_requirement.minimum_inclusive.major,
                self.version_requirement.minimum_inclusive.minor,
                self.version_requirement.minimum_inclusive.patch,
            ),
            ScannerVersion::new(
                self.version_requirement.maximum_exclusive.major,
                self.version_requirement.maximum_exclusive.minor,
                self.version_requirement.maximum_exclusive.patch,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FrozenScannerVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenScannerVersionRequirement {
    pub minimum_inclusive: FrozenScannerVersion,
    pub maximum_exclusive: FrozenScannerVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPiAdjudication {
    pub analyzer: AnalyzerId,
    pub mode: PiAdjudicationMode,
    pub required_initial: bool,
    pub required_after_actions: bool,
}

#[derive(Debug, Error)]
pub enum ProcessingRuntimeError {
    #[error("schema-3 processing configuration is invalid: {0}")]
    Configuration(String),
    #[error("processing profile '{0}' does not exist")]
    UnknownProfile(String),
    #[error("requested apply authority exceeds the selected profile")]
    AuthorityEscalation,
    #[error("checkout ref is invalid or outside the selected profile")]
    CheckoutRef,
    #[error("remote Git locator is invalid or uses a prohibited transport")]
    Remote,
    #[error("processing policy could not be compiled")]
    InvalidPolicy,
    #[error("built-in rule material could not be loaded: {0}")]
    Rules(#[from] crate::rules::RulesError),
    #[error("analyzer '{analyzer}' could not be compiled: {message}")]
    Analyzer { analyzer: String, message: String },
    #[error("required external scanner '{analyzer}' failed preflight")]
    ScannerPreflight { analyzer: String },
    #[error("processing identity serialization failed: {0}")]
    Identity(#[from] serde_json::Error),
}

pub fn compile_processing_runtime(
    config: &ProcessingConfigFile,
    request: ProcessingCompileRequest,
) -> Result<CompiledProcessingRuntime, ProcessingRuntimeError> {
    config
        .validate()
        .map_err(|error| ProcessingRuntimeError::Configuration(error.to_string()))?;
    let profile_id = request
        .profile_id
        .as_deref()
        .unwrap_or(&config.processing.default_profile);
    let profile = config
        .processing
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| ProcessingRuntimeError::UnknownProfile(profile_id.to_owned()))?;
    let action_mode = compile_action_mode(profile, request.action_mode)?;
    let source = compile_source(profile, request.source)?;
    let source_scope = FrozenSourceScope {
        working_tree: profile.source_scope.working_tree,
        history: map_history(profile.source_scope.history),
        history_ref_patterns: profile.source_scope.history_ref_patterns.clone(),
    };
    let source_scope_identity = Digest::sha256(serde_json::to_vec(&(
        "file-guardian-source-scope/1",
        profile.purpose,
        &profile.source_scope,
        &profile.git,
    ))?);
    let pipeline_config = config
        .pipelines
        .iter()
        .find(|pipeline| pipeline.id == profile.pipeline)
        .expect("schema-3 validation resolved profile pipeline");
    let (pipeline, analyzer_identities) = compile_pipeline(config, pipeline_config)?;
    let pipeline_identity = Digest::sha256(serde_json::to_vec(&(
        "file-guardian-processing-pipeline/1",
        pipeline_config,
        &analyzer_identities,
        &source_scope_identity,
    ))?);
    let pi_adjudication = profile
        .pi_adjudication
        .as_ref()
        .map(compile_pi_adjudication)
        .transpose()?;
    let policy_identity = Digest::sha256(serde_json::to_vec(&(
        "file-guardian-processing-policy/1",
        profile,
        &pipeline_identity,
    ))?);
    let policy = CompiledProcessingPolicy::compile(profile)
        .map_err(|_| ProcessingRuntimeError::InvalidPolicy)?;
    let jobs_config = &config.processing.jobs;
    let retention = &jobs_config.retention;
    let acquisition = &config.processing.acquisition;
    Ok(CompiledProcessingRuntime {
        run_id: request.run_id,
        profile_id: profile.id.clone(),
        purpose: match profile.purpose {
            ProfilePurpose::Handoff => ProcessPurpose::Handoff,
            ProfilePurpose::ReportOnly => ProcessPurpose::ReportOnly,
        },
        action_mode,
        source,
        source_scope,
        git_constraints: FrozenGitConstraints {
            allowed_checkout_ref_patterns: profile.git.allowed_checkout_ref_patterns.clone(),
            submodules: profile.git.submodules,
            lfs: profile.git.lfs,
        },
        source_scope_identity,
        jobs: FrozenJobLimits {
            jobs_root: jobs_config.root.clone(),
            reports_root: jobs_config.reports_root.clone(),
            quarantine_root: jobs_config.quarantine_root.clone(),
            artifact_quarantine_root: jobs_config.artifact_quarantine_root.clone(),
            stale_after_secs: jobs_config.stale_after_secs,
            max_report_bytes: jobs_config.max_report_bytes,
            capture: FrozenCaptureLimits {
                max_entries: jobs_config.capture.max_entries,
                max_files: jobs_config.capture.max_files,
                max_file_bytes: jobs_config.capture.max_file_bytes,
                max_total_bytes: jobs_config.capture.max_total_bytes,
                max_depth: jobs_config.capture.max_depth,
            },
            retention: FrozenRetentionLimits {
                available_ttl_secs: retention.available_ttl_secs,
                available_max_bytes: retention.available_max_bytes,
                quarantine_ttl_secs: retention.quarantine_ttl_secs,
                quarantine_max_bytes: retention.quarantine_max_bytes,
                artifact_quarantine_ttl_secs: retention.artifact_quarantine_ttl_secs,
                artifact_quarantine_max_bytes: retention.artifact_quarantine_max_bytes,
            },
        },
        acquisition: FrozenAcquisitionLimits {
            git_executable: acquisition.git_executable.clone(),
            git_timeout_secs: acquisition.git_timeout_secs,
            max_stdout_bytes: acquisition.max_stdout_bytes,
            max_stderr_bytes: acquisition.max_stderr_bytes,
            max_refs: acquisition.max_refs,
            max_commits: acquisition.max_commits,
            max_unique_blobs: acquisition.max_unique_blobs,
            max_provenance_occurrences: acquisition.max_provenance_occurrences,
            max_git_bytes: acquisition.max_git_bytes,
        },
        policy,
        completion: profile.completion.clone(),
        pipeline,
        pipeline_identity,
        policy_identity,
        pi_adjudication,
    })
}

fn compile_action_mode(
    profile: &ProcessingProfile,
    requested: Option<RequestedActionMode>,
) -> Result<EffectiveActionMode, ProcessingRuntimeError> {
    match (profile.action_mode, requested) {
        (config::ActionMode::Evaluate, Some(RequestedActionMode::Apply)) => {
            Err(ProcessingRuntimeError::AuthorityEscalation)
        }
        (_, Some(RequestedActionMode::Evaluate)) => Ok(EffectiveActionMode::Evaluate),
        (config::ActionMode::Evaluate, None) => Ok(EffectiveActionMode::Evaluate),
        (config::ActionMode::Apply, None | Some(RequestedActionMode::Apply)) => {
            Ok(EffectiveActionMode::Apply)
        }
    }
}

fn compile_source(
    profile: &ProcessingProfile,
    source: ProcessingSourceRequest,
) -> Result<FrozenSourceRequest, ProcessingRuntimeError> {
    match source {
        ProcessingSourceRequest::Path { path } => Ok(FrozenSourceRequest::Path { path }),
        ProcessingSourceRequest::Git { remote, reference } => {
            validate_checkout_ref(profile, reference.as_deref())?;
            let transport = parse_remote(&remote)?;
            Ok(FrozenSourceRequest::Git {
                remote,
                transport,
                checkout_ref: reference,
            })
        }
    }
}

fn validate_checkout_ref(
    profile: &ProcessingProfile,
    reference: Option<&str>,
) -> Result<(), ProcessingRuntimeError> {
    let Some(reference) = reference else {
        return Ok(());
    };
    if reference.is_empty()
        || reference.starts_with('-')
        || reference.len() > 256
        || reference.contains("..")
        || reference.contains("@{")
        || reference.ends_with('.')
        || reference.ends_with('/')
        || reference
            .chars()
            .any(|value| value.is_control() || value.is_whitespace())
        || !(reference.starts_with("refs/heads/") || reference.starts_with("refs/tags/"))
        || looks_like_object_id(reference)
    {
        return Err(ProcessingRuntimeError::CheckoutRef);
    }
    let matches = profile
        .git
        .allowed_checkout_ref_patterns
        .iter()
        .any(|pattern| {
            Glob::new(pattern).is_ok_and(|glob| glob.compile_matcher().is_match(reference))
        });
    matches
        .then_some(())
        .ok_or(ProcessingRuntimeError::CheckoutRef)
}

fn looks_like_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_remote(remote: &str) -> Result<GitTransport, ProcessingRuntimeError> {
    if remote.is_empty()
        || remote.len() > 4096
        || remote.starts_with('-')
        || remote.chars().any(|character| character.is_control())
        || remote.contains('?')
        || remote.contains('#')
    {
        return Err(ProcessingRuntimeError::Remote);
    }
    if let Some(rest) = remote.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/').ok_or(ProcessingRuntimeError::Remote)?;
        if authority.is_empty() || authority.contains('@') || path.is_empty() {
            return Err(ProcessingRuntimeError::Remote);
        }
        return Ok(GitTransport::Https);
    }
    if let Some(rest) = remote.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/').ok_or(ProcessingRuntimeError::Remote)?;
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if authority.is_empty() || host.is_empty() || authority.ends_with('@') || path.is_empty() {
            return Err(ProcessingRuntimeError::Remote);
        }
        return Ok(GitTransport::Ssh);
    }
    if !remote.contains("://") {
        if let Some((authority, path)) = remote.split_once(':') {
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            let invalid = authority.is_empty()
                || host.is_empty()
                || (authority.len() == 1 && authority.as_bytes()[0].is_ascii_alphabetic())
                || authority.starts_with('/')
                || authority.ends_with('@')
                || authority.contains(['/', '\\'])
                || authority.chars().any(char::is_whitespace)
                || path.is_empty()
                || path.starts_with('/')
                || path.contains(['?', '#']);
            if !invalid {
                return Ok(GitTransport::Ssh);
            }
        }
    }
    Err(ProcessingRuntimeError::Remote)
}

fn compile_pipeline(
    config: &ProcessingConfigFile,
    pipeline: &config::PipelineConfig,
) -> Result<(FrozenPipeline, Vec<(String, Digest)>), ProcessingRuntimeError> {
    let mut stages = Vec::with_capacity(pipeline.stages.len());
    let mut identities = Vec::new();
    for stage in &pipeline.stages {
        let mut analyzers = Vec::with_capacity(stage.analyzers.len());
        for id in &stage.analyzers {
            let analyzer = config
                .analyzers
                .iter()
                .find(|analyzer| analyzer.id == *id)
                .expect("schema-3 validation resolved analyzer");
            let compiled = compile_analyzer(analyzer, &config.processing.external_scanners)?;
            identities.push((id.clone(), compiled.identity));
            analyzers.push(compiled);
        }
        let max_observations = usize::try_from(stage.prior_limits.max_observations)
            .map_err(|_| analyzer_error(&stage.id, "prior observation count exceeds platform"))?;
        let max_serialized_bytes = usize::try_from(stage.prior_limits.max_serialized_bytes)
            .map_err(|_| analyzer_error(&stage.id, "prior observation bytes exceed platform"))?;
        stages.push(FrozenStage {
            id: StageId::new(stage.id.clone())
                .map_err(|error| analyzer_error(&stage.id, &error.to_string()))?,
            execution: match stage.execution {
                config::StageExecution::Serial => StageExecution::Serial,
                config::StageExecution::Parallel => StageExecution::Parallel {
                    max_concurrency: stage.max_concurrency,
                },
            },
            prior_observations: match stage.prior_observations {
                config::PriorObservations::None => PriorObservationMode::None,
                config::PriorObservations::FindingsSummary => PriorObservationMode::FindingsSummary,
                config::PriorObservations::AllNormalized => PriorObservationMode::AllNormalized,
            },
            prior_limits: ProjectionLimits::new(max_observations, max_serialized_bytes)
                .map_err(|error| analyzer_error(&stage.id, &error.to_string()))?,
            analyzers,
        });
    }
    identities.sort_by(|left, right| left.0.cmp(&right.0));
    Ok((
        FrozenPipeline {
            id: pipeline.id.clone(),
            stages,
        },
        identities,
    ))
}

fn compile_analyzer(
    analyzer: &AnalyzerConfig,
    scanner_runtime: &config::ExternalScannerRuntimeConfig,
) -> Result<FrozenAnalyzer, ProcessingRuntimeError> {
    let id = AnalyzerId::new(analyzer.id.clone())
        .map_err(|error| analyzer_error(&analyzer.id, &error.to_string()))?;
    let selection = FrozenAnalyzerSelection {
        include: analyzer.selection.include.clone(),
        exclude: analyzer.selection.exclude.clone(),
        artifact_kinds: analyzer.selection.artifact_kinds.clone(),
        required_text_include: analyzer.content_applicability.required_text_include.clone(),
    };
    let (implementation, resource_identity) = match &analyzer.kind {
        AnalyzerKind::BuiltinRules(builtin) => compile_builtin(analyzer, builtin)?,
        AnalyzerKind::PiClassifier(pi) => compile_pi(analyzer, pi)?,
        AnalyzerKind::Gitleaks(scanner) => compile_gitleaks(analyzer, scanner, scanner_runtime)?,
        AnalyzerKind::Trufflehog(scanner) => {
            compile_trufflehog(analyzer, scanner, scanner_runtime)?
        }
    };
    let identity = Digest::sha256(serde_json::to_vec(&(
        "file-guardian-processing-analyzer/1",
        analyzer,
        resource_identity,
    ))?);
    Ok(FrozenAnalyzer {
        id,
        initial: analyzer.execution.initial,
        verification: analyzer.execution.verification,
        identity,
        selection,
        implementation,
    })
}

fn compile_builtin(
    analyzer: &AnalyzerConfig,
    builtin: &config::BuiltinRulesConfig,
) -> Result<(FrozenAnalyzerImplementation, Digest), ProcessingRuntimeError> {
    let rules = load_rule_files(&builtin.rule_files)?;
    let max_findings = usize::try_from(analyzer.limits.max_findings.unwrap_or(10_000))
        .map_err(|_| analyzer_error(&analyzer.id, "max_findings exceeds platform"))?;
    let required_text =
        RequiredTextMatcher::compile(&analyzer.content_applicability.required_text_include)
            .map_err(|error| analyzer_error(&analyzer.id, &error.to_string()))?;
    let material = rules
        .iter()
        .map(|rule| {
            (
                rule.name.clone(),
                rule.filename_glob
                    .as_ref()
                    .map(|pattern| pattern.as_str().to_owned()),
                rule.content_regex
                    .as_ref()
                    .map(|pattern| pattern.as_str().to_owned()),
            )
        })
        .collect::<Vec<_>>();
    let identity = Digest::sha256(serde_json::to_vec(&material)?);
    let runtime = BuiltinRulesAnalyzer::new(
        analyzer.id.clone(),
        rules,
        BuiltinAnalyzerLimits {
            max_content_bytes: builtin.max_content_bytes,
            max_findings,
            content_applicability: BuiltinContentApplicability { required_text },
        },
    )
    .map_err(|error| analyzer_error(&analyzer.id, &error.to_string()))?;
    Ok((FrozenAnalyzerImplementation::Builtin(runtime), identity))
}

fn compile_pi(
    analyzer: &AnalyzerConfig,
    pi: &config::PiClassifierConfig,
) -> Result<(FrozenAnalyzerImplementation, Digest), ProcessingRuntimeError> {
    let required = |name, value| pi_limit(analyzer, name, value);
    let max_output = pi_limit(
        analyzer,
        "max_output_bytes",
        analyzer.limits.max_output_bytes,
    )?;
    let instruction = read_bounded_utf8(&pi.pi.instruction_file, max_output)
        .map_err(|message| analyzer_error(&analyzer.id, &message))?;
    let instruction_identity = Digest::sha256(instruction.as_bytes());
    for path in [
        &pi.pi.pi_executable,
        &pi.pi.bubblewrap_executable,
        &pi.pi.trusted_extension,
        &pi.pi.tool_sidecar_runner,
        &pi.pi.isolated_agent_dir,
    ] {
        if !path.exists() {
            return Err(analyzer_error(
                &analyzer.id,
                "Pi runtime administrator path is unavailable",
            ));
        }
    }
    let credentials = pi
        .pi
        .credentials
        .iter()
        .map(|credential| {
            std::env::var_os(&credential.source_env)
                .map(|value| (OsString::from(&credential.target_env), value))
                .ok_or_else(|| {
                    analyzer_error(
                        &analyzer.id,
                        &format!(
                            "required Pi credential '{}' is unavailable",
                            credential.label
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let identity = Digest::sha256(serde_json::to_vec(&(
        "file-guardian-processing-pi/1",
        pi,
        instruction_identity,
    ))?);
    Ok((
        FrozenAnalyzerImplementation::Pi(FrozenPiRuntime {
            config: pi.clone(),
            instruction: Arc::from(instruction),
            instruction_identity,
            credential_environment: credentials,
            required_text_include: analyzer.content_applicability.required_text_include.clone(),
            limits: FrozenPiLimits {
                startup_timeout_secs: required(
                    "startup_timeout_secs",
                    analyzer.limits.startup_timeout_secs,
                )?,
                idle_timeout_secs: required(
                    "idle_timeout_secs",
                    analyzer.limits.idle_timeout_secs,
                )?,
                wall_timeout_secs: required(
                    "wall_timeout_secs",
                    analyzer.limits.wall_timeout_secs,
                )?,
                termination_grace_secs: required(
                    "termination_grace_secs",
                    analyzer.limits.termination_grace_secs,
                )?,
                cpu_time_secs: required("cpu_time_secs", analyzer.limits.cpu_time_secs)?,
                max_open_files: required("max_open_files", analyzer.limits.max_open_files)?,
                max_stdout_bytes: required("max_stdout_bytes", analyzer.limits.max_stdout_bytes)?,
                max_stderr_bytes: required("max_stderr_bytes", analyzer.limits.max_stderr_bytes)?,
                max_file_bytes: analyzer.limits.max_file_bytes,
                max_output_bytes: max_output,
                max_findings: required("max_findings", analyzer.limits.max_findings)?,
                max_tool_calls: required("max_tool_calls", analyzer.limits.max_tool_calls)?,
                max_bytes_read: required("max_bytes_read", analyzer.limits.max_bytes_read)?,
                max_read_bytes_per_call: required(
                    "max_read_bytes_per_call",
                    analyzer.limits.max_read_bytes_per_call,
                )?,
                max_search_bytes_per_call: required(
                    "max_search_bytes_per_call",
                    analyzer.limits.max_search_bytes_per_call,
                )?,
                max_search_calls: required("max_search_calls", analyzer.limits.max_search_calls)?,
                max_search_results: required(
                    "max_search_results",
                    analyzer.limits.max_search_results,
                )?,
                max_view_files: required("max_view_files", analyzer.limits.max_view_files)?,
                max_view_entries: required("max_view_entries", analyzer.limits.max_view_entries)?,
                max_view_bytes: required("max_view_bytes", analyzer.limits.max_view_bytes)?,
                max_view_depth: required("max_view_depth", analyzer.limits.max_view_depth)?,
            },
        }),
        identity,
    ))
}

fn compile_gitleaks(
    analyzer: &AnalyzerConfig,
    scanner: &config::GitleaksConfig,
    scanner_runtime: &config::ExternalScannerRuntimeConfig,
) -> Result<(FrozenAnalyzerImplementation, Digest), ProcessingRuntimeError> {
    let version_requirement = parse_version_requirement(analyzer, &scanner.version_requirement)?;
    GitleaksAdapter::with_version_requirement(scanner_requirement(version_requirement)).map_err(
        |_| {
            analyzer_error(
                &analyzer.id,
                "scanner version requirement is outside the reviewed range",
            )
        },
    )?;
    let executable = prepare_executable(analyzer, ScannerKind::Gitleaks, &scanner.executable)?;
    let config_file = PreparedProtectedFile::open(&scanner.config_file).map_err(|_| {
        ProcessingRuntimeError::ScannerPreflight {
            analyzer: analyzer.id.clone(),
        }
    })?;
    let ignore_file = PreparedProtectedFile::open(&scanner.ignore_file).map_err(|_| {
        ProcessingRuntimeError::ScannerPreflight {
            analyzer: analyzer.id.clone(),
        }
    })?;
    let sandbox = prepare_scanner_sandbox(analyzer, scanner_runtime)?;
    let identity = external_identity(
        &executable,
        &sandbox,
        &[config_file.identity(), ignore_file.identity()],
    )?;
    let limits = scanner_limits(analyzer)?;
    Ok((
        FrozenAnalyzerImplementation::External(FrozenExternalAnalyzer {
            kind: ScannerKind::Gitleaks,
            executable,
            protected_files: vec![config_file, ignore_file],
            sandbox,
            version_requirement,
            limits,
            max_file_bytes: pi_limit(analyzer, "max_file_bytes", analyzer.limits.max_file_bytes)?,
            max_findings: pi_limit(analyzer, "max_findings", analyzer.limits.max_findings)?,
            required_text_include: analyzer.content_applicability.required_text_include.clone(),
        }),
        identity,
    ))
}

fn compile_trufflehog(
    analyzer: &AnalyzerConfig,
    scanner: &config::TrufflehogConfig,
    scanner_runtime: &config::ExternalScannerRuntimeConfig,
) -> Result<(FrozenAnalyzerImplementation, Digest), ProcessingRuntimeError> {
    let version_requirement = parse_version_requirement(analyzer, &scanner.version_requirement)?;
    TrufflehogAdapter::with_version_requirement(scanner_requirement(version_requirement)).map_err(
        |_| {
            analyzer_error(
                &analyzer.id,
                "scanner version requirement is outside the reviewed range",
            )
        },
    )?;
    let executable = prepare_executable(analyzer, ScannerKind::Trufflehog, &scanner.executable)?;
    let sandbox = prepare_scanner_sandbox(analyzer, scanner_runtime)?;
    let identity = external_identity(&executable, &sandbox, &[])?;
    let limits = scanner_limits(analyzer)?;
    Ok((
        FrozenAnalyzerImplementation::External(FrozenExternalAnalyzer {
            kind: ScannerKind::Trufflehog,
            executable,
            protected_files: Vec::new(),
            sandbox,
            version_requirement,
            limits,
            max_file_bytes: pi_limit(analyzer, "max_file_bytes", analyzer.limits.max_file_bytes)?,
            max_findings: pi_limit(analyzer, "max_findings", analyzer.limits.max_findings)?,
            required_text_include: analyzer.content_applicability.required_text_include.clone(),
        }),
        identity,
    ))
}

fn prepare_executable(
    analyzer: &AnalyzerConfig,
    kind: ScannerKind,
    executable: &str,
) -> Result<PreparedScannerExecutable, ProcessingRuntimeError> {
    PreparedScannerExecutable::discover_from_environment(kind, OsStr::new(executable)).map_err(
        |_| ProcessingRuntimeError::ScannerPreflight {
            analyzer: analyzer.id.clone(),
        },
    )
}

fn parse_version_requirement(
    analyzer: &AnalyzerConfig,
    value: &str,
) -> Result<FrozenScannerVersionRequirement, ProcessingRuntimeError> {
    let (minimum, maximum) = value
        .strip_prefix(">=")
        .and_then(|value| value.split_once(",<"))
        .ok_or_else(|| analyzer_error(&analyzer.id, "invalid scanner version requirement"))?;
    let requirement = FrozenScannerVersionRequirement {
        minimum_inclusive: parse_version(analyzer, minimum)?,
        maximum_exclusive: parse_version(analyzer, maximum)?,
    };
    if requirement.minimum_inclusive >= requirement.maximum_exclusive {
        return Err(analyzer_error(
            &analyzer.id,
            "scanner version requirement is empty",
        ));
    }
    Ok(requirement)
}

const fn scanner_requirement(
    requirement: FrozenScannerVersionRequirement,
) -> ScannerVersionRequirement {
    ScannerVersionRequirement::new(
        ScannerVersion::new(
            requirement.minimum_inclusive.major,
            requirement.minimum_inclusive.minor,
            requirement.minimum_inclusive.patch,
        ),
        ScannerVersion::new(
            requirement.maximum_exclusive.major,
            requirement.maximum_exclusive.minor,
            requirement.maximum_exclusive.patch,
        ),
    )
}

fn parse_version(
    analyzer: &AnalyzerConfig,
    value: &str,
) -> Result<FrozenScannerVersion, ProcessingRuntimeError> {
    let mut parts = value.split('.');
    let mut next = || {
        parts
            .next()
            .map_or(Ok(0), |part| {
                (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                    .then(|| part.parse::<u64>().ok())
                    .flatten()
                    .ok_or(())
            })
            .map_err(|()| analyzer_error(&analyzer.id, "invalid scanner version requirement"))
    };
    let version = FrozenScannerVersion {
        major: next()?,
        minor: next()?,
        patch: next()?,
    };
    if parts.next().is_some() {
        return Err(analyzer_error(
            &analyzer.id,
            "invalid scanner version requirement",
        ));
    }
    Ok(version)
}

fn external_identity(
    executable: &PreparedScannerExecutable,
    sandbox: &PreparedScannerSandbox,
    protected: &[&crate::analyzers::external::ExecutableIdentity],
) -> Result<Digest, ProcessingRuntimeError> {
    let executable = executable.identity();
    let protected = protected
        .iter()
        .map(|identity| {
            (
                identity.digest,
                identity.device,
                identity.inode,
                identity.byte_len,
                identity.mode,
            )
        })
        .collect::<Vec<_>>();
    let sandbox = sandbox.identity();
    Ok(Digest::sha256(serde_json::to_vec(&(
        executable.digest,
        executable.device,
        executable.inode,
        executable.byte_len,
        executable.mode,
        sandbox.digest,
        sandbox.device,
        sandbox.inode,
        sandbox.byte_len,
        sandbox.mode,
        protected,
    ))?))
}

fn prepare_scanner_sandbox(
    analyzer: &AnalyzerConfig,
    runtime: &config::ExternalScannerRuntimeConfig,
) -> Result<PreparedScannerSandbox, ProcessingRuntimeError> {
    PreparedScannerSandbox::prepare(ScannerSandboxSpec {
        bubblewrap_executable: runtime.bubblewrap_executable.clone(),
        expected_bubblewrap_version: runtime.expected_bubblewrap_version.clone(),
    })
    .map_err(|_| ProcessingRuntimeError::ScannerPreflight {
        analyzer: analyzer.id.clone(),
    })
}

fn scanner_limits(analyzer: &AnalyzerConfig) -> Result<ScannerRunLimits, ProcessingRuntimeError> {
    Ok(ScannerRunLimits {
        wall_timeout: std::time::Duration::from_secs(pi_limit(
            analyzer,
            "wall_timeout_secs",
            analyzer.limits.wall_timeout_secs,
        )?),
        termination_grace: std::time::Duration::from_secs(
            analyzer.limits.termination_grace_secs.unwrap_or(5),
        ),
        max_output_bytes: pi_limit(
            analyzer,
            "max_output_bytes",
            analyzer.limits.max_output_bytes,
        )?,
        cpu_seconds: analyzer.limits.cpu_time_secs.unwrap_or(120),
        open_files: analyzer.limits.max_open_files.unwrap_or(64),
    })
}

fn pi_limit(
    analyzer: &AnalyzerConfig,
    name: &str,
    value: Option<u64>,
) -> Result<u64, ProcessingRuntimeError> {
    value.ok_or_else(|| analyzer_error(&analyzer.id, &format!("missing required limit {name}")))
}

fn read_bounded_utf8(path: &Path, limit: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "trusted instruction is unavailable".to_owned())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "trusted instruction could not be read".to_owned())?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("trusted instruction is empty or exceeds its limit".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "trusted instruction is not UTF-8".to_owned())
}

fn compile_pi_adjudication(
    config: &config::PiAdjudication,
) -> Result<CompiledPiAdjudication, ProcessingRuntimeError> {
    Ok(CompiledPiAdjudication {
        analyzer: AnalyzerId::new(config.analyzer.clone())
            .map_err(|error| ProcessingRuntimeError::Configuration(error.to_string()))?,
        mode: config.mode,
        required_initial: config.required_initial,
        required_after_actions: config.required_after_actions,
    })
}

fn map_history(scope: HistoryScope) -> GitHistoryScope {
    match scope {
        HistoryScope::None => GitHistoryScope::None,
        HistoryScope::Head => GitHistoryScope::Head,
        HistoryScope::Reachable => GitHistoryScope::Reachable,
        HistoryScope::AllRefs => GitHistoryScope::AllRefs,
    }
}

fn analyzer_error(analyzer: &str, message: &str) -> ProcessingRuntimeError {
    ProcessingRuntimeError::Analyzer {
        analyzer: analyzer.to_owned(),
        message: message.to_owned(),
    }
}

/// Stable identity helper used by deterministic tests and later job reports.
pub fn canonical_identity<T: Serialize>(value: &T) -> Result<Digest, ProcessingRuntimeError> {
    Ok(Digest::sha256(serde_json::to_vec(value)?))
}
