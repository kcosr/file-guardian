//! Process-facing authorization runtime helpers.
//!
//! This module translates the private authorization service result into the
//! stable report contract. It deliberately contains no command-line parsing
//! and performs no policy decisions of its own.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::analyzers::{
    BuiltinAnalyzerLimits, BuiltinContentApplicability, BuiltinRulesAnalyzer,
    UnsupportedContentPolicy,
};
use crate::authorization::SnapshotInputKind;
use crate::config::{
    ActionMode as ConfigActionMode, AnalyzerKind, ApplicabilityPolicy, Config, UnboundObservation,
};
use crate::domain::{
    AnalyzerId, ArtifactManifest, ClassificationCode, InspectionIssue, InspectionPhase, IssueCode,
    LogicalPath, PhaseCoverage, PhaseCoverageStatus, Provenance, RuleId, RunCoverage, RunId,
    SanitizedMessage,
};
use crate::policy::{BindingId, ObservationSelector, PolicyBinding, PolicyDirective};
use crate::report::{
    ArtifactSummary, AuthorizationOutcome, AuthorizationReport, InputKind, InputSummary,
    PipelineRun, PipelineRunStatus, PolicySummary, ReportData, ReportIdentifier, ReportStatistics,
};
use crate::rules::load_rule_files;
use crate::service::{
    AuthorizationAnalyzer, AuthorizationRequest, AuthorizationResult, AuthorizationStage,
    ServiceOutcome, UnsupportedAnalyzerKind,
};

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

    let mut stages = Vec::with_capacity(selection.pipeline.stages.len());
    let mut known_rules = Vec::new();
    let mut compiled_rule_material = Vec::new();
    let mut selected_analyzers = Vec::new();
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
            match &config_analyzer.kind {
                AnalyzerKind::BuiltinRules {
                    rule_files,
                    max_content_bytes,
                    content_applicability,
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
                    analyzers.push(AuthorizationAnalyzer::Builtin(BuiltinRulesAnalyzer::new(
                        id.clone(),
                        rules,
                        BuiltinAnalyzerLimits {
                            max_content_bytes: *max_content_bytes,
                            max_findings,
                            content_applicability: BuiltinContentApplicability {
                                invalid_utf8: applicability(content_applicability.invalid_utf8),
                                over_max_bytes: applicability(content_applicability.over_max_bytes),
                            },
                        },
                    )?));
                }
                AnalyzerKind::ExternalTool { .. } => {
                    analyzers.push(AuthorizationAnalyzer::Unsupported {
                        id: analyzer_id,
                        kind: UnsupportedAnalyzerKind::External,
                    });
                }
                AnalyzerKind::PiClassifier { .. } => {
                    analyzers.push(AuthorizationAnalyzer::Unsupported {
                        id: analyzer_id,
                        kind: UnsupportedAnalyzerKind::Pi,
                    });
                }
            }
        }
        stages.push(AuthorizationStage { analyzers });
    }

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
                max_file_bytes: capture.max_file_bytes,
                max_total_bytes: capture.max_total_bytes,
                max_depth: capture.max_depth,
            },
            stages,
            policy_bindings,
        },
        policy,
    })
}

fn applicability(value: ApplicabilityPolicy) -> UnsupportedContentPolicy {
    match value {
        ApplicabilityPolicy::Fail => UnsupportedContentPolicy::Fail,
        ApplicabilityPolicy::Exclude => UnsupportedContentPolicy::Exclude,
    }
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
        bindings.push(PolicyBinding {
            id: BindingId::new(format!("default:{analyzer}:{rule}"))
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
    use crate::service::{
        AuthorizationAnalyzer, AuthorizationRequest, AuthorizationService, AuthorizationStage,
    };
    use crate::{authorization::CaptureLimits, domain::Digest};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

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
    fn complete_service_result_maps_to_allow_report() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&input).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(input.join("safe.txt"), b"safe").unwrap();
        let run_id = RunId::from_suffix("report-adapter").unwrap();
        let result = AuthorizationService::authorize(AuthorizationRequest {
            run_id: run_id.clone(),
            workspace_root: workspace,
            input,
            capture_limits: CaptureLimits::default(),
            stages: vec![AuthorizationStage {
                analyzers: vec![AuthorizationAnalyzer::Builtin(
                    BuiltinRulesAnalyzer::new(
                        "builtin",
                        Vec::new(),
                        BuiltinAnalyzerLimits::default(),
                    )
                    .unwrap(),
                )],
            }],
            policy_bindings: Vec::new(),
        });
        let report = report_from_result(
            ReportContext {
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
            },
            result,
        )
        .unwrap();
        assert_eq!(report.outcome, AuthorizationOutcome::Allow);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.statistics.duration_ms, 7);
    }
}
