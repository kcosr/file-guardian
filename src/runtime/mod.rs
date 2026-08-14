//! Process-facing authorization runtime helpers.
//!
//! This module translates the private authorization service result into the
//! stable report contract. It deliberately contains no command-line parsing
//! and performs no policy decisions of its own.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::analyzers::pi::protocol::{ClassificationVocabulary, TerminalValidationLimits};
use crate::analyzers::pi::proxy::{ExpectedPiRuntime, PiProxyLimits};
use crate::analyzers::pi::runner::PiRunLimits;
use crate::analyzers::pi::sandbox::{PiRuntimeSpec, PI_RUNTIME_CONTEXT_MODE};
use crate::analyzers::pi::{PiClassifierAnalyzer, PiClassifierSpec};
use crate::analyzers::{
    BuiltinAnalyzerLimits, BuiltinContentApplicability, BuiltinRulesAnalyzer, RequiredTextMatcher,
};
use crate::authorization::{AnalyzerViewLimits, AnalyzerViewQuota, SnapshotInputKind};
use crate::config::{
    ActionMode as ConfigActionMode, AnalyzerKind, ArtifactKindConfig, ClassifierScope, Config,
    ContentApplicabilityConfig, PriorObservations, StageExecution as ConfigStageExecution,
    UnboundObservation, SYNTHESIZED_POLICY_BINDING_PREFIX,
};
use crate::domain::{
    AnalyzerId, ArtifactKind, ArtifactManifest, ClassificationCode, ConfiguredConfidence,
    InspectionIssue, InspectionPhase, IssueCode, LogicalPath, PhaseCoverage, PhaseCoverageStatus,
    Provenance, ReasonCode, RuleId, RunCoverage, RunId, SanitizedMessage,
};
use crate::pipeline::{
    AnalyzerImplementation, CompiledAnalyzer, CompiledPipeline, CompiledStage, EligibilitySelector,
    PriorObservationMode, ProjectionLimits, StageExecution, StageId, UnsupportedAnalyzerKind,
};
use crate::policy::{BindingId, ObservationSelector, PolicyBinding, PolicyDirective};
use crate::report::{
    ArtifactSummary, AuthorizationOutcome, AuthorizationReport, InputKind, InputSummary,
    PipelineRun, PipelineRunStatus, PolicySummary, ReportData, ReportIdentifier, ReportStatistics,
};
use crate::rules::load_rule_files;
use crate::service::{AuthorizationRequest, AuthorizationResult, ServiceOutcome};

const RANDOM_RUN_ID_BYTES: usize = 24;

/// Caller-known context which is intentionally absent from the authorization
/// service's filesystem and analyzer request.
#[derive(Clone, Debug)]
pub struct ReportContext {
    pub run_id: RunId,
    pub request_id: Option<ReportIdentifier>,
    pub policy: Option<PolicySummary>,
    pub duration_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("authorization configuration is invalid: {0}")]
    Configuration(String),
    #[error("authorization rules could not be loaded: {0}")]
    Rules(#[from] crate::rules::RulesError),
    #[error("built-in analyzer could not be compiled: {0}")]
    Builtin(#[from] crate::analyzers::BuiltinAnalyzerError),
    #[error("Pi analyzer could not be compiled: {0}")]
    Pi(String),
    #[error("authorization identity could not be serialized: {0}")]
    Identity(#[from] serde_json::Error),
}

pub struct CompiledInvocation {
    pub request: AuthorizationRequest,
    pub policy: PolicySummary,
}

/// Compile the selected v2 profile into the service's closed request model.
pub fn compile_invocation(
    config: &Config,
    profile_id: Option<&str>,
    requested_mode: Option<ConfigActionMode>,
    run_id: RunId,
    input: PathBuf,
) -> Result<CompiledInvocation, RuntimeError> {
    let selection = config
        .validate_for_authorize_mode(profile_id, requested_mode)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    if selection.effective_mode != ConfigActionMode::Evaluate {
        return Err(RuntimeError::Configuration(
            "apply authorization is not implemented".to_string(),
        ));
    }
    let invocation_view_quota = compile_invocation_view_quota(config, selection.pipeline)?;

    let mut stages = Vec::with_capacity(selection.pipeline.stages.len());
    let mut known_rules = Vec::new();
    let mut compiled_rule_material = Vec::new();
    let mut selected_analyzers = Vec::new();
    let mut pi_identity_material = Vec::new();
    for stage in &selection.pipeline.stages {
        let mut analyzers = Vec::with_capacity(stage.analyzers.len());
        for id in &stage.analyzers {
            let config_analyzer = config
                .analyzers
                .iter()
                .find(|analyzer| &analyzer.id == id)
                .expect("validated analyzer reference");
            selected_analyzers.push(config_analyzer);
            let analyzer_id = AnalyzerId::new(id.clone())
                .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            let implementation = match &config_analyzer.kind {
                AnalyzerKind::BuiltinRules {
                    rule_files,
                    max_content_bytes,
                } => {
                    let rules = load_rule_files(rule_files)?;
                    known_rules.extend(rules.iter().map(|rule| (id.clone(), rule.name.clone())));
                    compiled_rule_material.extend(rules.iter().map(|rule| {
                        (
                            id.clone(),
                            rule.name.clone(),
                            rule.filename_glob
                                .as_ref()
                                .map(|pattern| pattern.as_str().to_string()),
                            rule.content_regex
                                .as_ref()
                                .map(|regex| regex.as_str().to_string()),
                        )
                    }));
                    let max_findings = config_analyzer.limits.max_findings.unwrap_or(10_000);
                    let max_findings = usize::try_from(max_findings).map_err(|_| {
                        RuntimeError::Configuration(format!(
                            "analyzer '{id}' max_findings exceeds this platform"
                        ))
                    })?;
                    AnalyzerImplementation::Builtin(BuiltinRulesAnalyzer::new(
                        id.clone(),
                        rules,
                        BuiltinAnalyzerLimits {
                            max_content_bytes: *max_content_bytes,
                            max_findings,
                            content_applicability: BuiltinContentApplicability {
                                required_text: compile_required_text(
                                    id,
                                    &config_analyzer.content_applicability,
                                )?,
                            },
                        },
                    )?)
                }
                AnalyzerKind::ExternalTool { .. } => AnalyzerImplementation::Unsupported {
                    kind: UnsupportedAnalyzerKind::External,
                },
                AnalyzerKind::PiClassifier {
                    scope,
                    pi,
                    vocabulary,
                } => {
                    if *scope != ClassifierScope::Tree {
                        return Err(RuntimeError::Configuration(format!(
                            "Pi analyzer '{id}' uses an unsupported classifier scope"
                        )));
                    }
                    let analyzer = compile_pi_analyzer(
                        analyzer_id.clone(),
                        run_id.clone(),
                        pi,
                        vocabulary,
                        &config_analyzer.content_applicability,
                        &config_analyzer.limits,
                        invocation_view_quota.expect("a selected Pi analyzer provides a quota"),
                    )?;
                    pi_identity_material.push((id.clone(), analyzer.identity()));
                    AnalyzerImplementation::Pi(Box::new(analyzer))
                }
            };
            let eligibility = EligibilitySelector::compile(
                &config_analyzer.selection.include,
                &config_analyzer.selection.exclude,
                config_analyzer
                    .selection
                    .artifact_kinds
                    .iter()
                    .map(|kind| match kind {
                        ArtifactKindConfig::PhysicalFile => ArtifactKind::PhysicalFile,
                        ArtifactKindConfig::ArchiveMember => ArtifactKind::ArchiveMember,
                    }),
            )
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            analyzers.push(CompiledAnalyzer::new(
                analyzer_id,
                config_analyzer.required,
                eligibility,
                implementation,
            ));
        }
        let execution = match stage.execution {
            ConfigStageExecution::Serial => StageExecution::Serial,
            ConfigStageExecution::Parallel => StageExecution::Parallel {
                max_concurrency: stage.max_concurrency,
            },
        };
        let prior_observations = match stage.prior_observations {
            PriorObservations::None => PriorObservationMode::None,
            PriorObservations::FindingsSummary => PriorObservationMode::FindingsSummary,
            PriorObservations::AllNormalized => PriorObservationMode::AllNormalized,
        };
        let max_observations =
            usize::try_from(stage.prior_limits.max_observations).map_err(|_| {
                RuntimeError::Configuration(format!(
                    "pipeline stage '{}' max_observations exceeds this platform",
                    stage.id
                ))
            })?;
        let max_serialized_bytes = usize::try_from(stage.prior_limits.max_serialized_bytes)
            .map_err(|_| {
                RuntimeError::Configuration(format!(
                    "pipeline stage '{}' max_serialized_bytes exceeds this platform",
                    stage.id
                ))
            })?;
        let prior_limits = ProjectionLimits::new(max_observations, max_serialized_bytes)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let stage_id = StageId::new(stage.id.clone())
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        stages.push(
            CompiledStage::new(
                stage_id,
                execution,
                analyzers,
                prior_observations,
                prior_limits,
            )
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
        );
    }
    let pipeline = CompiledPipeline::new(stages)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;

    let policy_bindings = compile_policy_bindings(
        config,
        &selection.profile.id,
        selection.profile.default_unbound_observation,
        &known_rules,
    )?;
    let policy_identity =
        crate::domain::Digest::sha256(serde_json::to_vec(&(selection.profile, &policy_bindings))?);
    let pipeline_identity = crate::domain::Digest::sha256(serde_json::to_vec(&(
        selection.pipeline,
        &selected_analyzers,
        &compiled_rule_material,
        &pi_identity_material,
    ))?);
    let policy = PolicySummary {
        profile_id: ReportIdentifier::new(selection.profile.id.clone())
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
        identity: policy_identity,
        pipeline_id: ReportIdentifier::new(selection.pipeline.id.clone())
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
        pipeline_identity,
        effective_action_mode: crate::report::EffectiveActionMode::Evaluate,
    };
    let capture = &config.authorization.workspace.capture;
    Ok(CompiledInvocation {
        request: AuthorizationRequest {
            run_id,
            workspace_root: config.authorization.workspace.root.clone(),
            input,
            capture_limits: crate::authorization::CaptureLimits {
                max_files: capture.max_files,
                max_entries: capture.max_entries,
                max_file_bytes: capture.max_file_bytes,
                max_total_bytes: capture.max_total_bytes,
                max_depth: capture.max_depth,
            },
            pipeline,
            policy_bindings,
        },
        policy,
    })
}

fn compile_required_text(
    id: &str,
    config: &ContentApplicabilityConfig,
) -> Result<RequiredTextMatcher, RuntimeError> {
    RequiredTextMatcher::compile(&config.required_text_include).map_err(|error| {
        RuntimeError::Configuration(format!(
            "analyzer '{id}' required-text policy could not be compiled: {error}"
        ))
    })
}

fn compile_invocation_view_quota(
    config: &Config,
    pipeline: &crate::config::PipelineConfig,
) -> Result<Option<AnalyzerViewQuota>, RuntimeError> {
    let mut invocation: Option<AnalyzerViewQuota> = None;
    for analyzer_id in pipeline.stages.iter().flat_map(|stage| &stage.analyzers) {
        let analyzer = config
            .analyzer(analyzer_id)
            .expect("validated analyzer reference");
        if !matches!(&analyzer.kind, AnalyzerKind::PiClassifier { .. }) {
            continue;
        }
        let quota = compile_view_quota(analyzer_id, &analyzer.limits)?;
        invocation = Some(match invocation {
            None => quota,
            Some(current) => AnalyzerViewQuota {
                max_files: current.max_files.max(quota.max_files),
                max_entries: current.max_entries.max(quota.max_entries),
                max_total_bytes: current.max_total_bytes.max(quota.max_total_bytes),
                max_depth: current.max_depth.max(quota.max_depth),
            },
        });
    }
    Ok(invocation)
}

fn compile_view_quota(
    id: &str,
    limits: &crate::config::AnalyzerLimits,
) -> Result<AnalyzerViewQuota, RuntimeError> {
    let required = |name: &str, value: Option<u64>| {
        value.ok_or_else(|| {
            RuntimeError::Configuration(format!("Pi analyzer '{id}' requires limit {name}"))
        })
    };
    Ok(AnalyzerViewQuota {
        max_files: required("max_view_files", limits.max_view_files)?,
        max_entries: required("max_view_entries", limits.max_view_entries)?,
        max_total_bytes: required("max_view_bytes", limits.max_view_bytes)?,
        max_depth: usize::try_from(required("max_view_depth", limits.max_view_depth)?).map_err(
            |_| {
                RuntimeError::Configuration(format!(
                    "Pi analyzer '{id}' max_view_depth exceeds this platform"
                ))
            },
        )?,
    })
}

fn compile_pi_analyzer(
    id: AnalyzerId,
    run_id: RunId,
    pi: &crate::config::PiConfig,
    vocabulary: &crate::config::VocabularyConfig,
    content_applicability: &ContentApplicabilityConfig,
    limits: &crate::config::AnalyzerLimits,
    invocation_view_quota: AnalyzerViewQuota,
) -> Result<PiClassifierAnalyzer, RuntimeError> {
    let required = |name: &str, value: Option<u64>| {
        value.ok_or_else(|| {
            RuntimeError::Configuration(format!(
                "Pi analyzer '{}' requires limit {name}",
                id.as_str()
            ))
        })
    };
    let checked_usize = |name: &str, value: u64| {
        usize::try_from(value).map_err(|_| {
            RuntimeError::Configuration(format!(
                "Pi analyzer '{}' {name} exceeds this platform",
                id.as_str()
            ))
        })
    };
    let max_output = required("max_output_bytes", limits.max_output_bytes)?;
    let instruction_file = File::open(&pi.instruction_file)
        .map_err(|_| RuntimeError::Pi("trusted instruction could not be read".to_string()))?;
    let mut instruction_bytes = Vec::new();
    instruction_file
        .take(max_output.saturating_add(1))
        .read_to_end(&mut instruction_bytes)
        .map_err(|_| RuntimeError::Pi("trusted instruction could not be read".to_string()))?;
    if instruction_bytes.len() as u64 > max_output {
        return Err(RuntimeError::Pi(
            "trusted instruction exceeds its configured limit".to_string(),
        ));
    }
    let instruction = String::from_utf8(instruction_bytes)
        .map_err(|_| RuntimeError::Pi("trusted instruction is not UTF-8".to_string()))?;
    if instruction.is_empty() {
        return Err(RuntimeError::Pi("trusted instruction is empty".to_string()));
    }
    let confidences = vocabulary
        .confidences
        .iter()
        .map(|value| match value.as_str() {
            "low" => Ok(ConfiguredConfidence::Low),
            "medium" => Ok(ConfiguredConfidence::Medium),
            "high" => Ok(ConfiguredConfidence::High),
            _ => Err(RuntimeError::Configuration(format!(
                "Pi analyzer '{}' contains an unsupported confidence",
                id.as_str()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let vocabulary = ClassificationVocabulary::new(
        vocabulary
            .classifications
            .iter()
            .cloned()
            .map(ClassificationCode::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
        confidences,
        vocabulary
            .reason_codes
            .iter()
            .cloned()
            .map(ReasonCode::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
    )
    .map_err(|error| RuntimeError::Configuration(error.to_string()))?;

    let max_findings = required("max_findings", limits.max_findings)?;
    let max_read_bytes_per_call =
        required("max_read_bytes_per_call", limits.max_read_bytes_per_call)?;
    let wall = required("wall_timeout_secs", limits.wall_timeout_secs)?;
    let credentials = pi
        .credentials
        .iter()
        .map(|credential| {
            let value = std::env::var_os(&credential.source_env).ok_or_else(|| {
                RuntimeError::Configuration(format!(
                    "Pi analyzer '{}' required credential '{}' is unavailable",
                    id.as_str(),
                    credential.label
                ))
            })?;
            Ok((OsString::from(&credential.target_env), value))
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    let runtime_manifest = pi.runtime_root.join(&pi.runtime_manifest);
    let identity_material = serde_json::to_vec(&(
        "file-guardian-compiled-pi/1",
        id.as_str(),
        &pi.provider,
        &pi.model,
        &pi.thinking,
        &pi.output_schema,
        &pi.tool_grant,
        &content_applicability.required_text_include,
        (
            invocation_view_quota.max_files,
            invocation_view_quota.max_entries,
            invocation_view_quota.max_total_bytes,
            invocation_view_quota.max_depth,
        ),
        limits,
        &pi.expected_pi_version,
    ))?;
    PiClassifierAnalyzer::compile(PiClassifierSpec {
        id: id.clone(),
        run_id,
        runtime: PiRuntimeSpec {
            bubblewrap_executable: pi.bubblewrap_executable.clone(),
            expected_bubblewrap_version: pi.expected_bubblewrap_version.clone(),
            runtime_root: pi.runtime_root.clone(),
            runtime_manifest,
            launcher: pi.launcher.clone(),
            pi_entrypoint: pi.pi_entrypoint.clone(),
            expected_pi_version: pi.expected_pi_version.clone(),
            instruction_file: pi.instruction_file.clone(),
            trusted_extension: pi.trusted_extension.clone(),
            tool_sidecar_runner: pi.tool_sidecar_runner.clone(),
            isolated_agent_dir: pi.isolated_agent_dir.clone(),
        },
        instruction: Arc::from(instruction),
        vocabulary,
        expected_runtime: ExpectedPiRuntime {
            pi_version: pi.expected_pi_version.clone(),
            provider: pi.provider.clone(),
            model: pi.model.clone(),
            thinking: pi.thinking.clone(),
            mode: PI_RUNTIME_CONTEXT_MODE.to_string(),
        },
        terminal_limits: TerminalValidationLimits::new(
            checked_usize("max_findings", max_findings)?,
            checked_usize("max_findings", max_findings)?,
            checked_usize("max_findings", max_findings)?,
        )
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
        max_search_results: required("max_search_results", limits.max_search_results)?,
        required_text: compile_required_text(id.as_str(), content_applicability)?,
        max_text_bytes: max_read_bytes_per_call,
        view_limits: AnalyzerViewLimits {
            per_view: compile_view_quota(id.as_str(), limits)?,
            invocation: invocation_view_quota,
        },
        proxy_limits: PiProxyLimits {
            max_frame_bytes: checked_usize("max_output_bytes", max_output)?,
            max_response_bytes: checked_usize("max_output_bytes", max_output)?,
            max_terminal_bytes: checked_usize("max_output_bytes", max_output)?,
            max_tool_calls: required("max_tool_calls", limits.max_tool_calls)?,
            max_bytes_read: required("max_bytes_read", limits.max_bytes_read)?,
            max_read_bytes_per_call,
            max_search_matches: required("max_search_results", limits.max_search_results)?,
            max_search_bytes_per_call: required(
                "max_search_bytes_per_call",
                limits.max_search_bytes_per_call,
            )?,
            max_search_calls: required("max_search_calls", limits.max_search_calls)?,
            frame_read_timeout: Duration::from_secs(required(
                "idle_timeout_secs",
                limits.idle_timeout_secs,
            )?),
        },
        run_limits: PiRunLimits {
            startup_timeout: Duration::from_secs(required(
                "startup_timeout_secs",
                limits.startup_timeout_secs,
            )?),
            idle_timeout: Duration::from_secs(required(
                "idle_timeout_secs",
                limits.idle_timeout_secs,
            )?),
            wall_timeout: Duration::from_secs(wall),
            termination_grace: Duration::from_secs(required(
                "termination_grace_secs",
                limits.termination_grace_secs,
            )?),
            memory_bytes: required("memory_bytes", limits.memory_bytes)?,
            cpu_seconds: required("cpu_time_secs", limits.cpu_time_secs)?,
            open_files: required("max_open_files", limits.max_open_files)?,
            stdout_bytes: required("max_stdout_bytes", limits.max_stdout_bytes)?,
            stderr_bytes: required("max_stderr_bytes", limits.max_stderr_bytes)?,
        },
        credential_environment: credentials,
        identity_material,
    })
    .map_err(|_| RuntimeError::Pi("Pi runtime or tool-sidecar preflight failed".to_string()))
}

fn compile_policy_bindings(
    config: &Config,
    profile_id: &str,
    unbound: UnboundObservation,
    known_rules: &[(String, String)],
) -> Result<Vec<PolicyBinding>, RuntimeError> {
    let configured = config
        .policy_bindings
        .iter()
        .filter(|binding| binding.profile == profile_id)
        .collect::<Vec<_>>();
    let known_rule_set = known_rules
        .iter()
        .map(|(analyzer, rule)| (analyzer.as_str(), rule.as_str()))
        .collect::<BTreeSet<_>>();
    let builtin_rule_analyzers = config
        .analyzers
        .iter()
        .filter_map(|analyzer| {
            matches!(&analyzer.kind, AnalyzerKind::BuiltinRules { .. })
                .then_some(analyzer.id.as_str())
        })
        .collect::<BTreeSet<_>>();
    for binding in &configured {
        let Some(rule) = binding.rule.as_deref() else {
            continue;
        };
        // Built-in selectors can be checked against the rules loaded above.
        // Delegate rule identifiers belong to the delegate's native protocol
        // namespace and are validated when its typed output is received.
        if !builtin_rule_analyzers.contains(binding.analyzer.as_str()) {
            continue;
        }
        let analyzer_has_rules = known_rule_set
            .iter()
            .any(|(analyzer, _)| *analyzer == binding.analyzer);
        if rule == "*" {
            if !analyzer_has_rules {
                return Err(RuntimeError::Configuration(format!(
                    "policy binding '{}' uses a wildcard rule selector, but analyzer '{}' loaded no rules",
                    binding.id, binding.analyzer
                )));
            }
        } else if !known_rule_set.contains(&(binding.analyzer.as_str(), rule)) {
            return Err(RuntimeError::Configuration(format!(
                "policy binding '{}' references rule '{}' which was not loaded for analyzer '{}'",
                binding.id, rule, binding.analyzer
            )));
        }
    }
    let mut bindings = configured
        .iter()
        .map(|binding| {
            let analyzer_id = Some(
                AnalyzerId::new(binding.analyzer.clone())
                    .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
            );
            let selector = if let Some(rule) = &binding.rule {
                ObservationSelector::Finding {
                    analyzer_id,
                    rule_id: (rule != "*")
                        .then(|| RuleId::new(rule.clone()))
                        .transpose()
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
                    category: None,
                    minimum_severity: None,
                }
            } else {
                ObservationSelector::Classification {
                    analyzer_id,
                    code: binding
                        .classification
                        .as_ref()
                        .map(|code| ClassificationCode::new(code.clone()))
                        .transpose()
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
                }
            };
            Ok(PolicyBinding {
                id: BindingId::new(binding.id.clone())
                    .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
                selector,
                directive: binding.directive,
            })
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;

    let fallback = match unbound {
        UnboundObservation::Error => return Ok(bindings),
        UnboundObservation::Audit => PolicyDirective::Audit,
        UnboundObservation::Deny => PolicyDirective::Deny,
    };
    let wildcards = configured
        .iter()
        .filter(|binding| binding.rule.as_deref() == Some("*"))
        .map(|binding| binding.analyzer.as_str())
        .collect::<BTreeSet<_>>();
    let exact = configured
        .iter()
        .filter_map(|binding| {
            binding
                .rule
                .as_deref()
                .filter(|rule| *rule != "*")
                .map(|rule| (binding.analyzer.as_str(), rule))
        })
        .collect::<BTreeSet<_>>();
    for (analyzer, rule) in known_rules {
        if wildcards.contains(analyzer.as_str())
            || exact.contains(&(analyzer.as_str(), rule.as_str()))
        {
            continue;
        }
        let synthesized_identity =
            crate::domain::Digest::sha256([analyzer.as_bytes(), &[0], rule.as_bytes()].concat());
        bindings.push(PolicyBinding {
            id: BindingId::new(format!(
                "{SYNTHESIZED_POLICY_BINDING_PREFIX}{synthesized_identity}"
            ))
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
            selector: ObservationSelector::Finding {
                analyzer_id: Some(
                    AnalyzerId::new(analyzer.clone())
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
                ),
                rule_id: Some(
                    RuleId::new(rule.clone())
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
                ),
                category: None,
                minimum_severity: None,
            },
            directive: fallback,
        });
    }
    Ok(bindings)
}

/// Generate an opaque run identifier using the operating system CSPRNG.
pub fn secure_run_id() -> io::Result<RunId> {
    secure_run_id_from(&mut File::open("/dev/urandom")?)
}

fn secure_run_id_from(reader: &mut impl Read) -> io::Result<RunId> {
    let mut random = [0_u8; RANDOM_RUN_ID_BYTES];
    reader.read_exact(&mut random)?;
    let suffix = random.iter().fold(
        String::with_capacity(RANDOM_RUN_ID_BYTES * 2),
        |mut out, byte| {
            use std::fmt::Write as _;
            write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
            out
        },
    );
    RunId::from_suffix(suffix).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Construct a stable machine report from one completed service invocation.
pub fn report_from_result(
    context: ReportContext,
    result: AuthorizationResult,
) -> Result<AuthorizationReport, crate::report::ReportError> {
    let outcome = match result.outcome {
        ServiceOutcome::Allow => AuthorizationOutcome::Allow,
        ServiceOutcome::Deny => AuthorizationOutcome::Deny,
        ServiceOutcome::Error => AuthorizationOutcome::Error,
    };
    let reportable_manifest = result.initial_manifest.as_ref();
    let input = reportable_manifest.and_then(|initial| {
        result.input_kind.map(|kind| InputSummary {
            kind: match kind {
                SnapshotInputKind::File => InputKind::File,
                SnapshotInputKind::Directory => InputKind::Directory,
            },
            initial_manifest_identity: initial.identity,
            final_manifest_identity: result
                .final_manifest
                .as_ref()
                .map(|manifest| manifest.identity),
        })
    });
    let artifacts = reportable_manifest
        .map(artifact_summaries)
        .unwrap_or_default();
    let observations = result.observations;
    let resolutions = result.resolutions;
    let pipeline_runs = match result.coverage.initial.status {
        PhaseCoverageStatus::NotRun => Vec::new(),
        PhaseCoverageStatus::Complete => vec![PipelineRun {
            phase: InspectionPhase::Initial,
            status: PipelineRunStatus::Complete,
            stages_completed: result.pipeline.stages_completed,
            analyzers_completed: result.pipeline.analyzers_completed,
        }],
        PhaseCoverageStatus::Incomplete => vec![PipelineRun {
            phase: InspectionPhase::Initial,
            status: PipelineRunStatus::Incomplete,
            stages_completed: result.pipeline.stages_completed,
            analyzers_completed: result.pipeline.analyzers_completed,
        }],
    };
    let statistics = ReportStatistics {
        physical_artifacts: artifacts
            .iter()
            .map(|artifact| &artifact.subject_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u64,
        logical_artifacts: artifacts.len() as u64,
        observations: observations.len() as u64,
        duration_ms: context.duration_ms,
    };

    AuthorizationReport::new(ReportData {
        run_id: context.run_id,
        request_id: context.request_id,
        outcome,
        coverage: result.coverage,
        policy: context.policy,
        input,
        artifacts,
        pipeline_runs,
        observations,
        resolutions,
        actions: Vec::new(),
        issues: result.issues,
        statistics,
    })
}

/// Convert a completed service result whose normal report could not be
/// constructed into a typed internal-failure report. The first attempt keeps
/// all safe service state; the second drops only internally inconsistent
/// observation data and impossible input context.
pub fn completed_run_internal_failure_report(
    context: ReportContext,
    result: AuthorizationResult,
) -> AuthorizationReport {
    let mut rich = result.clone();
    rich.outcome = ServiceOutcome::Error;
    rich.issues.push(InspectionIssue {
        phase: InspectionPhase::Initial,
        code: IssueCode::InternalFailure,
        analyzer_id: None,
        subject_id: None,
        artifact_id: None,
        message: SanitizedMessage::new("authorization report could not be constructed")
            .expect("static diagnostic is sanitized"),
    });
    if let Ok(report) = report_from_result(context.clone(), rich) {
        return report;
    }

    let mut sanitized = result;
    sanitized.outcome = ServiceOutcome::Error;
    if sanitized.input_kind.is_none() || sanitized.initial_manifest.is_none() {
        sanitized.input_kind = None;
        sanitized.initial_manifest = None;
        sanitized.final_manifest = None;
    }
    sanitized.observations.clear();
    sanitized.resolutions.clear();
    sanitized.issues = vec![InspectionIssue {
        phase: InspectionPhase::Initial,
        code: IssueCode::InternalFailure,
        analyzer_id: None,
        subject_id: None,
        artifact_id: None,
        message: SanitizedMessage::new("authorization report could not be constructed")
            .expect("static diagnostic is sanitized"),
    }];
    report_from_result(context.clone(), sanitized).unwrap_or_else(|_| {
        startup_error_report(
            context.run_id,
            context.request_id,
            IssueCode::InternalFailure,
            "authorization report could not be constructed",
        )
    })
}

/// Build the minimal sanitized report used when execution cannot reach the
/// authorization service after Clap accepted the `authorize` command.
pub fn startup_error_report(
    run_id: RunId,
    request_id: Option<ReportIdentifier>,
    code: IssueCode,
    message: &'static str,
) -> AuthorizationReport {
    let coverage = RunCoverage::new(
        PhaseCoverage::new(PhaseCoverageStatus::Incomplete, Vec::new())
            .expect("empty incomplete coverage is valid"),
        PhaseCoverage::new(PhaseCoverageStatus::NotRun, Vec::new())
            .expect("empty not-run coverage is valid"),
    )
    .expect("coverage phases are valid");
    AuthorizationReport::new(ReportData {
        run_id,
        request_id,
        outcome: AuthorizationOutcome::Error,
        coverage,
        policy: None,
        input: None,
        artifacts: Vec::new(),
        pipeline_runs: vec![PipelineRun {
            phase: InspectionPhase::Initial,
            status: PipelineRunStatus::Incomplete,
            stages_completed: 0,
            analyzers_completed: 0,
        }],
        observations: Vec::new(),
        resolutions: Vec::new(),
        actions: Vec::new(),
        issues: vec![InspectionIssue {
            phase: InspectionPhase::Initial,
            code,
            analyzer_id: None,
            subject_id: None,
            artifact_id: None,
            message: SanitizedMessage::new(message).expect("static diagnostic is sanitized"),
        }],
        statistics: ReportStatistics::default(),
    })
    .expect("startup error report is structurally valid")
}

fn artifact_summaries(manifest: &ArtifactManifest) -> Vec<ArtifactSummary> {
    manifest
        .artifacts()
        .iter()
        .map(|artifact| ArtifactSummary {
            artifact_id: artifact.id.clone(),
            subject_id: artifact.subject_id.clone(),
            kind: artifact.kind,
            relative_path: relative_path(&artifact.provenance).clone(),
            byte_len: artifact.byte_len,
            content_digest: artifact.content_digest,
        })
        .collect()
}

fn relative_path(provenance: &Provenance) -> &LogicalPath {
    match provenance {
        Provenance::Physical { logical_path } => logical_path,
        Provenance::Derived { member_path, .. } => member_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::{BuiltinAnalyzerLimits, BuiltinRulesAnalyzer};
    use crate::report::EffectiveActionMode;
    use crate::service::{AuthorizationRequest, AuthorizationService};
    use crate::{authorization::CaptureLimits, domain::Digest};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn config_with_rule_binding(rule: &str) -> Config {
        let raw = format!(
            r#"
schema_version = "2"

[authorization]
default_profile = "publication"

[authorization.workspace]
root = "/var/lib/file-guardian/runs"

[[authorization.profiles]]
id = "publication"
pipeline = "publication"
action_mode = "evaluate"
default_unbound_observation = "error"

[[pipelines]]
id = "publication"

[[pipelines.stages]]
id = "rules"
analyzers = ["rules"]

[[analyzers]]
id = "rules"
kind = "builtin_rules"
rule_files = ["/etc/file-guardian/rules.toml"]

[[policy_bindings]]
id = "blocked"
profile = "publication"
analyzer = "rules"
rule = "{rule}"
directive = "deny"
"#
        );
        let config: Config = toml::from_str(&raw).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn run_id_generation_uses_all_csprng_bytes() {
        let bytes = (0_u8..RANDOM_RUN_ID_BYTES as u8).collect::<Vec<_>>();
        let run_id = secure_run_id_from(&mut bytes.as_slice()).unwrap();
        assert_eq!(
            run_id.as_str(),
            "run_000102030405060708090a0b0c0d0e0f1011121314151617"
        );
    }

    #[test]
    fn startup_error_is_one_valid_json_line() {
        let report = startup_error_report(
            RunId::from_suffix("startup").unwrap(),
            Some(ReportIdentifier::new("request-1").unwrap()),
            IssueCode::ConfigurationFailure,
            "authorization configuration is invalid",
        );
        let bytes = report.to_json_line().unwrap();
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(report.exit_code, 30);
    }

    #[test]
    fn rule_bindings_reject_an_analyzer_that_loaded_no_rules() {
        for rule in ["blocked", "*"] {
            let config = config_with_rule_binding(rule);
            let error =
                compile_policy_bindings(&config, "publication", UnboundObservation::Error, &[])
                    .unwrap_err();
            assert!(
                error.to_string().contains("loaded no rules")
                    || error.to_string().contains("was not loaded"),
                "unexpected error for selector {rule:?}: {error}"
            );
        }
    }

    #[test]
    fn synthesized_bindings_use_reserved_bounded_digest_ids() {
        let mut config = config_with_rule_binding("blocked");
        config.policy_bindings.clear();
        let long_rule = "r".repeat(128);
        let bindings = compile_policy_bindings(
            &config,
            "publication",
            UnboundObservation::Audit,
            &[
                ("rules".to_string(), "blocked".to_string()),
                ("rules".to_string(), long_rule),
            ],
        )
        .unwrap();
        assert_eq!(bindings.len(), 2);
        let ids = bindings
            .iter()
            .map(|binding| binding.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 2);
        assert!(ids
            .iter()
            .all(|id| { id.starts_with(SYNTHESIZED_POLICY_BINDING_PREFIX) && id.len() <= 128 }));
    }

    #[test]
    fn invocation_view_quota_is_component_wise_maximum_for_selected_pi_analyzers() {
        let mut config: Config = toml::from_str(include_str!(
            "../../docs/examples/active-authorization-v2.toml"
        ))
        .unwrap();
        let pi_index = config
            .analyzers
            .iter()
            .position(|analyzer| matches!(&analyzer.kind, AnalyzerKind::PiClassifier { .. }))
            .unwrap();
        let mut second = config.analyzers[pi_index].clone();
        second.id = "publication-llm-secondary".to_string();

        let first = &mut config.analyzers[pi_index].limits;
        first.max_view_files = Some(10);
        first.max_view_entries = Some(200);
        first.max_view_bytes = Some(300);
        first.max_view_depth = Some(4);
        second.limits.max_view_files = Some(20);
        second.limits.max_view_entries = Some(100);
        second.limits.max_view_bytes = Some(400);
        second.limits.max_view_depth = Some(3);
        config.analyzers.push(second);
        config.pipelines[0].stages[0]
            .analyzers
            .push("publication-llm-secondary".to_string());
        let pipeline = config.pipelines[0].clone();

        assert_eq!(
            compile_invocation_view_quota(&config, &pipeline).unwrap(),
            Some(AnalyzerViewQuota {
                max_files: 20,
                max_entries: 200,
                max_total_bytes: 400,
                max_depth: 4,
            })
        );
    }

    #[tokio::test]
    async fn complete_service_result_maps_to_allow_report() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&input).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(input.join("safe.txt"), b"safe").unwrap();
        let run_id = RunId::from_suffix("report-adapter").unwrap();
        let analyzer = CompiledAnalyzer::new(
            AnalyzerId::new("builtin").unwrap(),
            true,
            EligibilitySelector::compile(&["**".to_string()], &[], [ArtifactKind::PhysicalFile])
                .unwrap(),
            AnalyzerImplementation::Builtin(
                BuiltinRulesAnalyzer::new("builtin", Vec::new(), BuiltinAnalyzerLimits::default())
                    .unwrap(),
            ),
        );
        let result = AuthorizationService::authorize(AuthorizationRequest {
            run_id: run_id.clone(),
            workspace_root: workspace,
            input,
            capture_limits: CaptureLimits::default(),
            pipeline: CompiledPipeline::new(vec![CompiledStage::new(
                StageId::new("rules").unwrap(),
                StageExecution::Serial,
                vec![analyzer],
                PriorObservationMode::None,
                ProjectionLimits::new(100, 16_384).unwrap(),
            )
            .unwrap()])
            .unwrap(),
            policy_bindings: Vec::new(),
        })
        .await;
        let context = ReportContext {
            run_id,
            request_id: None,
            policy: Some(PolicySummary {
                profile_id: ReportIdentifier::new("publication").unwrap(),
                identity: Digest::sha256(b"profile"),
                pipeline_id: ReportIdentifier::new("pipeline").unwrap(),
                pipeline_identity: Digest::sha256(b"pipeline"),
                effective_action_mode: EffectiveActionMode::Evaluate,
            }),
            duration_ms: 7,
        };
        let report = report_from_result(context.clone(), result.clone()).unwrap();
        assert_eq!(report.outcome, AuthorizationOutcome::Allow);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.statistics.duration_ms, 7);

        let mut malformed = result;
        malformed.input_kind = None;
        assert!(report_from_result(context.clone(), malformed.clone()).is_err());
        let fallback = completed_run_internal_failure_report(context, malformed);
        assert_eq!(fallback.outcome, AuthorizationOutcome::Error);
        assert_eq!(fallback.exit_code, 30);
        assert!(fallback.policy.is_some());
        assert!(fallback.issues.iter().any(|issue| {
            issue.code == IssueCode::InternalFailure
                && issue.message.as_str() == "authorization report could not be constructed"
        }));
    }
}
