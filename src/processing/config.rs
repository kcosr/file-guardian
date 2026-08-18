//! Strict schema-3 processing-job configuration.
//!
//! This module is intentionally independent from the schema-2 authorization
//! runtime. It defines the end-state processing contract without accepting
//! aliases or legacy shapes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use globset::Glob;
use serde::{Deserialize, Serialize};

use crate::config::{ClassifierScope, PiConfig, VocabularyConfig};

pub const PROCESSING_CONFIG_SCHEMA_VERSION: &str = "3";

#[derive(Debug, thiserror::Error)]
pub enum ProcessingConfigError {
    #[error("failed to parse processing configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid processing configuration: {0}")]
    Invalid(String),
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ProcessingConfigError> {
    Err(ProcessingConfigError::Invalid(message.into()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingConfigFile {
    pub schema_version: String,
    pub processing: ProcessingConfig,
    pub pipelines: Vec<PipelineConfig>,
    pub analyzers: Vec<AnalyzerConfig>,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

impl ProcessingConfigFile {
    pub fn parse(raw: &str) -> Result<Self, ProcessingConfigError> {
        let config: Self = toml::from_str(raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ProcessingConfigError> {
        if self.schema_version != PROCESSING_CONFIG_SCHEMA_VERSION {
            return invalid(format!(
                "unsupported schema_version '{}'; expected '{PROCESSING_CONFIG_SCHEMA_VERSION}'",
                self.schema_version
            ));
        }
        self.processing.validate()?;

        let profiles = unique("processing.profiles", &self.processing.profiles, |v| &v.id)?;
        let analyzers = unique("analyzers", &self.analyzers, |v| &v.id)?;
        let pipelines = unique("pipelines", &self.pipelines, |v| &v.id)?;
        unique("daemon.jobs", &self.daemon.jobs, |v| &v.id)?;

        if !profiles.contains_key(self.processing.default_profile.as_str()) {
            return invalid(format!(
                "processing.default_profile '{}' does not resolve",
                self.processing.default_profile
            ));
        }
        if profiles.is_empty() || pipelines.is_empty() || analyzers.is_empty() {
            return invalid("processing profiles, pipelines, and analyzers must not be empty");
        }

        for analyzer in &self.analyzers {
            analyzer.validate()?;
        }
        for pipeline in &self.pipelines {
            pipeline.validate(&analyzers)?;
        }
        for profile in &self.processing.profiles {
            profile.validate()?;
            let pipeline = pipelines
                .get(profile.pipeline.as_str())
                .map(|index| &self.pipelines[*index])
                .ok_or_else(|| {
                    ProcessingConfigError::Invalid(format!(
                        "profile '{}' references unknown pipeline '{}'",
                        profile.id, profile.pipeline
                    ))
                })?;
            if profile.source_scope.history != HistoryScope::None
                && !pipeline_has_required_repository_scanner(pipeline, &analyzers, &self.analyzers)
            {
                return invalid(format!(
                    "profile '{}' selects Git history without a required repository_blob analyzer",
                    profile.id
                ));
            }
            let pipeline_analyzers = pipeline
                .stages
                .iter()
                .flat_map(|stage| stage.analyzers.iter())
                .collect::<BTreeSet<_>>();
            for binding in &profile.bindings {
                if let Some(analyzer) = &binding.selector.analyzer {
                    if !analyzers.contains_key(analyzer.as_str())
                        || !pipeline_analyzers.contains(analyzer)
                    {
                        return invalid(format!(
                            "profile '{}' policy binding '{}' references analyzer '{}' outside its pipeline",
                            profile.id, binding.id, analyzer
                        ));
                    }
                }
            }
            if let Some(pi) = &profile.pi_adjudication {
                let analyzer_index = analyzers.get(pi.analyzer.as_str()).ok_or_else(|| {
                    ProcessingConfigError::Invalid(format!(
                        "profile '{}' Pi adjudication references unknown analyzer '{}'",
                        profile.id, pi.analyzer
                    ))
                })?;
                let analyzer = &self.analyzers[*analyzer_index];
                if !matches!(&analyzer.kind, AnalyzerKind::PiClassifier(_)) {
                    return invalid(format!(
                        "profile '{}' Pi adjudication analyzer '{}' is not a pi_classifier",
                        profile.id, pi.analyzer
                    ));
                }
                if !pipeline
                    .stages
                    .iter()
                    .any(|stage| stage.analyzers.contains(&pi.analyzer))
                {
                    return invalid(format!(
                        "profile '{}' Pi adjudication analyzer '{}' is outside its pipeline",
                        profile.id, pi.analyzer
                    ));
                }
                pi.validate_execution(profile, &analyzer.execution)?;
            }
        }
        self.daemon.validate(&profiles, &self.processing.profiles)?;
        Ok(())
    }
}

fn pipeline_has_required_repository_scanner(
    pipeline: &PipelineConfig,
    analyzers: &BTreeMap<&str, usize>,
    definitions: &[AnalyzerConfig],
) -> bool {
    pipeline
        .stages
        .iter()
        .flat_map(|stage| &stage.analyzers)
        .any(|id| {
            analyzers
                .get(id.as_str())
                .is_some_and(|index| definitions[*index].required_repository_scanner())
        })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingConfig {
    pub default_profile: String,
    pub jobs: JobsConfig,
    pub acquisition: AcquisitionConfig,
    pub external_scanners: ExternalScannerRuntimeConfig,
    pub profiles: Vec<ProcessingProfile>,
}

impl ProcessingConfig {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        validate_id("processing.default_profile", &self.default_profile)?;
        self.jobs.validate()?;
        self.acquisition.validate()?;
        self.external_scanners.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalScannerRuntimeConfig {
    pub bubblewrap_executable: PathBuf,
    pub expected_bubblewrap_version: String,
}

impl ExternalScannerRuntimeConfig {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        validate_absolute_normalized(
            "processing.external_scanners.bubblewrap_executable",
            &self.bubblewrap_executable,
        )?;
        if self.expected_bubblewrap_version.is_empty()
            || self.expected_bubblewrap_version.len() > 64
            || self
                .expected_bubblewrap_version
                .chars()
                .any(char::is_control)
        {
            return invalid("processing.external_scanners.expected_bubblewrap_version is invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobsConfig {
    pub root: PathBuf,
    pub reports_root: PathBuf,
    pub quarantine_root: PathBuf,
    pub artifact_quarantine_root: PathBuf,
    pub stale_after_secs: u64,
    pub max_report_bytes: u64,
    pub capture: CaptureLimits,
    pub retention: RetentionConfig,
}

impl JobsConfig {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        let roots = [
            ("processing.jobs.root", &self.root),
            ("processing.jobs.reports_root", &self.reports_root),
            ("processing.jobs.quarantine_root", &self.quarantine_root),
            (
                "processing.jobs.artifact_quarantine_root",
                &self.artifact_quarantine_root,
            ),
        ];
        for (name, path) in roots {
            validate_absolute_normalized(name, path)?;
        }
        for (index, (left_name, left)) in roots.iter().enumerate() {
            for (right_name, right) in roots.iter().skip(index + 1) {
                if paths_overlap(left, right) {
                    return invalid(format!("{left_name} and {right_name} must be disjoint"));
                }
            }
        }
        positive("processing.jobs.stale_after_secs", self.stale_after_secs)?;
        positive("processing.jobs.max_report_bytes", self.max_report_bytes)?;
        self.capture.validate()?;
        self.retention.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureLimits {
    pub max_entries: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

impl CaptureLimits {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        positive("capture.max_entries", self.max_entries)?;
        positive("capture.max_files", self.max_files)?;
        positive("capture.max_file_bytes", self.max_file_bytes)?;
        positive("capture.max_total_bytes", self.max_total_bytes)?;
        positive("capture.max_depth", self.max_depth as u64)?;
        if self.max_files > self.max_entries {
            return invalid("capture.max_files must not exceed max_entries");
        }
        if self.max_file_bytes > self.max_total_bytes {
            return invalid("capture.max_file_bytes must not exceed max_total_bytes");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    pub available_ttl_secs: u64,
    pub available_max_bytes: u64,
    pub quarantine_ttl_secs: u64,
    pub quarantine_max_bytes: u64,
    pub artifact_quarantine_ttl_secs: u64,
    pub artifact_quarantine_max_bytes: u64,
}

impl RetentionConfig {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        for (name, value) in [
            ("available_ttl_secs", self.available_ttl_secs),
            ("available_max_bytes", self.available_max_bytes),
            ("quarantine_ttl_secs", self.quarantine_ttl_secs),
            ("quarantine_max_bytes", self.quarantine_max_bytes),
            (
                "artifact_quarantine_ttl_secs",
                self.artifact_quarantine_ttl_secs,
            ),
            (
                "artifact_quarantine_max_bytes",
                self.artifact_quarantine_max_bytes,
            ),
        ] {
            positive(&format!("processing.jobs.retention.{name}"), value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionConfig {
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

impl AcquisitionConfig {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        validate_absolute_normalized(
            "processing.acquisition.git_executable",
            &self.git_executable,
        )?;
        for (name, value) in [
            ("git_timeout_secs", self.git_timeout_secs),
            ("max_stdout_bytes", self.max_stdout_bytes),
            ("max_stderr_bytes", self.max_stderr_bytes),
            ("max_refs", self.max_refs),
            ("max_commits", self.max_commits),
            ("max_unique_blobs", self.max_unique_blobs),
            (
                "max_provenance_occurrences",
                self.max_provenance_occurrences,
            ),
            ("max_git_bytes", self.max_git_bytes),
        ] {
            positive(&format!("processing.acquisition.{name}"), value)?;
        }
        if self.max_unique_blobs > self.max_provenance_occurrences {
            return invalid(
                "processing.acquisition.max_unique_blobs must not exceed max_provenance_occurrences",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingProfile {
    pub id: String,
    pub pipeline: String,
    pub action_mode: ActionMode,
    pub purpose: ProfilePurpose,
    pub default_unbound_observation: UnboundObservation,
    pub bindings: Vec<ProcessingPolicyBinding>,
    pub source_scope: SourceScope,
    pub git: GitPolicy,
    pub completion: CompletionPolicy,
    #[serde(default)]
    pub pi_adjudication: Option<PiAdjudication>,
}

impl ProcessingProfile {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        validate_id("processing.profiles.id", &self.id)?;
        validate_id("processing.profiles.pipeline", &self.pipeline)?;
        self.source_scope.validate(&self.id)?;
        self.git.validate(&self.id)?;
        self.completion.validate(self)?;
        validate_policy_bindings(self)?;
        if let Some(pi) = &self.pi_adjudication {
            pi.validate(self)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingPolicyBinding {
    pub id: String,
    pub priority: u32,
    pub directive: ProcessingPolicyDirective,
    pub selector: ProcessingFindingSelector,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingPolicyDirective {
    Audit,
    Deny,
    Delete,
    Quarantine,
    Adjudicate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingFindingSelector {
    #[serde(default)]
    pub analyzer: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub category: Option<crate::domain::FindingCategory>,
    #[serde(default)]
    pub severity: Option<PolicySeverity>,
    #[serde(default)]
    pub verification_state: Option<PolicyVerificationState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerificationState {
    NotApplicable,
    Unverified,
    Verified,
    VerificationError,
}

impl ProcessingFindingSelector {
    fn validate(&self, binding: &str) -> Result<(), ProcessingConfigError> {
        if let Some(analyzer) = &self.analyzer {
            validate_id(&format!("policy binding '{binding}' analyzer"), analyzer)?;
        }
        if let Some(rule) = &self.rule {
            validate_id(&format!("policy binding '{binding}' rule"), rule)?;
        }
        Ok(())
    }

    fn overlaps(&self, other: &Self) -> bool {
        optional_overlap(&self.analyzer, &other.analyzer)
            && optional_overlap(&self.rule, &other.rule)
            && optional_overlap(&self.category, &other.category)
            && optional_overlap(&self.severity, &other.severity)
            && optional_overlap(&self.verification_state, &other.verification_state)
    }
}

fn optional_overlap<T: Eq>(left: &Option<T>, right: &Option<T>) -> bool {
    left.is_none() || right.is_none() || left == right
}

fn validate_policy_bindings(profile: &ProcessingProfile) -> Result<(), ProcessingConfigError> {
    let mut ids = BTreeSet::new();
    for binding in &profile.bindings {
        validate_id("processing policy binding id", &binding.id)?;
        if binding.id == "__default_unbound__" || !ids.insert(&binding.id) {
            return invalid(format!(
                "profile '{}' has duplicate or reserved policy binding id '{}'",
                profile.id, binding.id
            ));
        }
        binding.selector.validate(&binding.id)?;
        if binding.directive == ProcessingPolicyDirective::Adjudicate
            && !profile
                .pi_adjudication
                .as_ref()
                .is_some_and(|policy| policy.mode == PiAdjudicationMode::Authoritative)
        {
            return invalid(format!(
                "profile '{}' adjudicate binding '{}' requires authoritative Pi adjudication",
                profile.id, binding.id
            ));
        }
    }
    for (index, left) in profile.bindings.iter().enumerate() {
        for right in profile.bindings.iter().skip(index + 1) {
            if left.priority == right.priority && left.selector.overlaps(&right.selector) {
                return invalid(format!(
                    "profile '{}' policy bindings '{}' and '{}' overlap at priority {}",
                    profile.id, left.id, right.id, left.priority
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMode {
    Evaluate,
    Apply,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePurpose {
    Handoff,
    ReportOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnboundObservation {
    Audit,
    Deny,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceScope {
    pub working_tree: bool,
    pub history: HistoryScope,
    pub history_ref_patterns: Vec<String>,
}

impl SourceScope {
    fn validate(&self, profile: &str) -> Result<(), ProcessingConfigError> {
        if !self.working_tree {
            return invalid(format!(
                "profile '{profile}' must select the staged working tree"
            ));
        }
        match self.history {
            HistoryScope::Reachable if self.history_ref_patterns.is_empty() => {
                return invalid(format!(
                    "profile '{profile}' reachable history requires history_ref_patterns"
                ));
            }
            HistoryScope::Reachable => {}
            _ if !self.history_ref_patterns.is_empty() => {
                return invalid(format!(
                    "profile '{profile}' history_ref_patterns must be empty unless history = 'reachable'"
                ));
            }
            _ => {}
        }
        validate_unique_globs(
            &format!("profile '{profile}' history_ref_patterns"),
            &self.history_ref_patterns,
        )?;
        for pattern in &self.history_ref_patterns {
            validate_ref_pattern(profile, pattern, true)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryScope {
    None,
    Head,
    Reachable,
    AllRefs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitPolicy {
    pub allowed_checkout_ref_patterns: Vec<String>,
    pub submodules: SubmodulePolicy,
    pub lfs: LfsPolicy,
}

impl GitPolicy {
    fn validate(&self, profile: &str) -> Result<(), ProcessingConfigError> {
        if self.allowed_checkout_ref_patterns.is_empty() {
            return invalid(format!(
                "profile '{profile}' requires allowed_checkout_ref_patterns"
            ));
        }
        validate_unique_globs(
            &format!("profile '{profile}' allowed_checkout_ref_patterns"),
            &self.allowed_checkout_ref_patterns,
        )?;
        for pattern in &self.allowed_checkout_ref_patterns {
            validate_ref_pattern(profile, pattern, false)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmodulePolicy {
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LfsPolicy {
    RejectPointer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkPolicy {
    Reject,
    Preserve,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionPolicy {
    pub allow: CompletionDisposition,
    pub allow_modified: CompletionDisposition,
    pub deny: CompletionDisposition,
    pub error: CompletionDisposition,
    pub cancelled: CompletionDisposition,
}

impl CompletionPolicy {
    fn validate(&self, profile: &ProcessingProfile) -> Result<(), ProcessingConfigError> {
        if profile.purpose == ProfilePurpose::ReportOnly
            && (self.allow == CompletionDisposition::Retain
                || self.allow_modified == CompletionDisposition::Retain)
        {
            return invalid(format!(
                "report_only profile '{}' cannot retain an allowed handoff stage",
                profile.id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDisposition {
    Retain,
    Discard,
    Quarantine,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiAdjudication {
    pub analyzer: String,
    pub mode: PiAdjudicationMode,
    #[serde(default)]
    pub required_initial: bool,
    #[serde(default)]
    pub required_after_actions: bool,
}

impl PiAdjudication {
    fn validate(&self, profile: &ProcessingProfile) -> Result<(), ProcessingConfigError> {
        validate_id("pi_adjudication.analyzer", &self.analyzer)?;
        match self.mode {
            PiAdjudicationMode::Advisory => {
                if self.required_initial || self.required_after_actions {
                    return invalid("advisory Pi adjudication cannot require phase completion");
                }
            }
            PiAdjudicationMode::Authoritative => {
                if !self.required_initial {
                    return invalid("authoritative Pi adjudication requires required_initial");
                }
                if profile.action_mode == ActionMode::Apply && !self.required_after_actions {
                    return invalid(
                        "apply profile with authoritative Pi adjudication requires required_after_actions",
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_execution(
        &self,
        profile: &ProcessingProfile,
        execution: &AnalyzerExecution,
    ) -> Result<(), ProcessingConfigError> {
        if self.required_initial != (execution.initial == PhaseExecution::Required) {
            return invalid(format!(
                "profile '{}' required_initial must agree with Pi initial execution",
                profile.id
            ));
        }
        if self.required_after_actions != (execution.verification == PhaseExecution::Required) {
            return invalid(format!(
                "profile '{}' required_after_actions must agree with Pi verification execution",
                profile.id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiAdjudicationMode {
    Advisory,
    Authoritative,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineConfig {
    pub id: String,
    pub stages: Vec<PipelineStage>,
}

impl PipelineConfig {
    fn validate(&self, analyzers: &BTreeMap<&str, usize>) -> Result<(), ProcessingConfigError> {
        validate_id("pipelines.id", &self.id)?;
        if self.stages.is_empty() {
            return invalid(format!("pipeline '{}' has no stages", self.id));
        }
        unique("pipelines.stages", &self.stages, |v| &v.id)?;
        let mut used = BTreeSet::new();
        for stage in &self.stages {
            stage.validate(&self.id)?;
            for analyzer in &stage.analyzers {
                if !analyzers.contains_key(analyzer.as_str()) {
                    return invalid(format!(
                        "pipeline '{}' references unknown analyzer '{}'",
                        self.id, analyzer
                    ));
                }
                if !used.insert(analyzer) {
                    return invalid(format!(
                        "pipeline '{}' uses analyzer '{}' more than once",
                        self.id, analyzer
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineStage {
    pub id: String,
    pub analyzers: Vec<String>,
    #[serde(default)]
    pub execution: StageExecution,
    #[serde(default = "default_one")]
    pub max_concurrency: usize,
    #[serde(default)]
    pub prior_observations: PriorObservations,
    #[serde(default)]
    pub prior_limits: PriorLimits,
}

impl PipelineStage {
    fn validate(&self, pipeline: &str) -> Result<(), ProcessingConfigError> {
        validate_id("pipelines.stages.id", &self.id)?;
        if self.analyzers.is_empty() || self.max_concurrency == 0 {
            return invalid(format!(
                "pipeline '{pipeline}' stage '{}' requires analyzers and positive max_concurrency",
                self.id
            ));
        }
        if self.execution == StageExecution::Serial && self.max_concurrency != 1 {
            return invalid(format!(
                "pipeline '{pipeline}' serial stage '{}' requires max_concurrency = 1",
                self.id
            ));
        }
        self.prior_limits.validate()
    }
}

fn default_one() -> usize {
    1
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageExecution {
    #[default]
    Serial,
    Parallel,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorObservations {
    #[default]
    None,
    FindingsSummary,
    AllNormalized,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorLimits {
    pub max_observations: u64,
    pub max_serialized_bytes: u64,
}

impl Default for PriorLimits {
    fn default() -> Self {
        Self {
            max_observations: 10_000,
            max_serialized_bytes: 1024 * 1024,
        }
    }
}

impl PriorLimits {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        positive("prior_limits.max_observations", self.max_observations)?;
        positive(
            "prior_limits.max_serialized_bytes",
            self.max_serialized_bytes,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnalyzerConfig {
    pub id: String,
    #[serde(flatten)]
    pub kind: AnalyzerKind,
    pub execution: AnalyzerExecution,
    pub selection: AnalyzerSelection,
    #[serde(default)]
    pub content_applicability: ContentApplicability,
    pub limits: AnalyzerLimits,
}

impl AnalyzerConfig {
    fn validate(&self) -> Result<(), ProcessingConfigError> {
        validate_id("analyzers.id", &self.id)?;
        self.execution.validate(&self.id)?;
        self.selection.validate(&self.id)?;
        self.content_applicability.validate(&self.id)?;
        self.limits.validate(&self.id)?;
        match &self.kind {
            AnalyzerKind::BuiltinRules(config) => {
                config.validate(&self.id)?;
                self.limits.validate_builtin(&self.id)
            }
            AnalyzerKind::PiClassifier(config) => {
                config.validate(&self.id)?;
                self.limits.validate_pi(&self.id)
            }
            AnalyzerKind::Gitleaks(config) => {
                config.validate(&self.id)?;
                self.limits.validate_scanner(&self.id)
            }
            AnalyzerKind::Trufflehog(config) => {
                config.validate(&self.id)?;
                self.limits.validate_scanner(&self.id)
            }
        }
    }

    fn required_repository_scanner(&self) -> bool {
        self.execution.initial == PhaseExecution::Required
            && self
                .selection
                .artifact_kinds
                .contains(&AnalyzerArtifactKind::RepositoryBlob)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalyzerKind {
    BuiltinRules(BuiltinRulesConfig),
    PiClassifier(PiClassifierConfig),
    Gitleaks(GitleaksConfig),
    Trufflehog(TrufflehogConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltinRulesConfig {
    pub rule_files: Vec<PathBuf>,
    pub max_content_bytes: u64,
}

impl BuiltinRulesConfig {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        if self.rule_files.is_empty() || self.max_content_bytes == 0 {
            return invalid(format!(
                "builtin_rules analyzer '{id}' requires rule files and positive max_content_bytes"
            ));
        }
        let mut unique = BTreeSet::new();
        for path in &self.rule_files {
            validate_absolute_normalized("builtin_rules.rule_files", path)?;
            if !unique.insert(path) {
                return invalid(format!("builtin_rules analyzer '{id}' repeats a rule file"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentApplicability {
    #[serde(default)]
    pub required_text_include: Vec<String>,
}

impl ContentApplicability {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        validate_unique_globs(
            &format!("analyzer '{id}' content_applicability.required_text_include"),
            &self.required_text_include,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiClassifierConfig {
    #[serde(default)]
    pub scope: ClassifierScope,
    pub pi: Box<PiConfig>,
    pub vocabulary: Box<VocabularyConfig>,
}

impl PiClassifierConfig {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        for (name, path) in [
            ("pi_executable", &self.pi.pi_executable),
            ("bubblewrap_executable", &self.pi.bubblewrap_executable),
            ("instruction_file", &self.pi.instruction_file),
            ("trusted_extension", &self.pi.trusted_extension),
            ("tool_sidecar_runner", &self.pi.tool_sidecar_runner),
            ("isolated_agent_dir", &self.pi.isolated_agent_dir),
        ] {
            validate_absolute_normalized(&format!("Pi analyzer '{id}' {name}"), path)?;
        }
        if self.pi.expected_bubblewrap_version.trim().is_empty()
            || self.pi.expected_pi_version.trim().is_empty()
            || self.pi.provider.trim().is_empty()
            || self.pi.model.trim().is_empty()
            || self.pi.credentials.is_empty()
        {
            return invalid(format!(
                "Pi analyzer '{id}' has incomplete runtime identity"
            ));
        }
        if self.pi.output_schema != "file-guardian-pi-triage/1"
            || self.pi.tool_grant != "sandboxed-shell-v1"
        {
            return invalid(format!(
                "Pi analyzer '{id}' requires triage protocol 1 and sandboxed-shell-v1"
            ));
        }
        if !matches!(
            self.pi.thinking.as_str(),
            "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
        ) {
            return invalid(format!("Pi analyzer '{id}' has an invalid thinking level"));
        }
        let mut labels = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut targets = BTreeSet::new();
        for credential in &self.pi.credentials {
            validate_id("Pi credential label", &credential.label)?;
            if !credential
                .source_env
                .starts_with("FILE_GUARDIAN_PI_CREDENTIAL_")
                || credential.source_env == "FILE_GUARDIAN_PI_CREDENTIAL_"
                || !is_environment_name(&credential.source_env)
                || !is_environment_name(&credential.target_env)
                || !(credential.target_env.ends_with("_API_KEY")
                    || credential.target_env.ends_with("_AUTH_TOKEN"))
                || !labels.insert(&credential.label)
                || !sources.insert(&credential.source_env)
                || !targets.insert(&credential.target_env)
            {
                return invalid(format!(
                    "Pi analyzer '{id}' has an invalid or duplicate credential mapping"
                ));
            }
        }
        if self.vocabulary.classifications.is_empty()
            || self.vocabulary.confidences.is_empty()
            || self.vocabulary.reason_codes.is_empty()
        {
            return invalid(format!("Pi analyzer '{id}' vocabulary must be complete"));
        }
        validate_unique_ids(
            &format!("Pi analyzer '{id}' classifications"),
            &self.vocabulary.classifications,
        )?;
        validate_unique_ids(
            &format!("Pi analyzer '{id}' confidences"),
            &self.vocabulary.confidences,
        )?;
        validate_unique_ids(
            &format!("Pi analyzer '{id}' reason_codes"),
            &self.vocabulary.reason_codes,
        )?;
        let classifications = self
            .vocabulary
            .classifications
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_classifications = [
            "confirmed",
            "likely_true_positive",
            "likely_false_positive",
            "false_positive",
            "uncertain",
            "unable_to_assess",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let confidences = self
            .vocabulary
            .confidences
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if classifications != expected_classifications
            || confidences != ["low", "medium", "high"].into_iter().collect()
        {
            return invalid(format!(
                "Pi analyzer '{id}' requires the closed triage classification and confidence vocabularies"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitleaksConfig {
    pub executable: String,
    pub version_requirement: String,
    pub config_file: PathBuf,
    pub ignore_file: PathBuf,
}

impl GitleaksConfig {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        validate_executable(id, &self.executable)?;
        validate_version_requirement(id, &self.version_requirement)?;
        validate_absolute_normalized("gitleaks.config_file", &self.config_file)?;
        validate_absolute_normalized("gitleaks.ignore_file", &self.ignore_file)?;
        if self.config_file == self.ignore_file {
            return invalid(format!(
                "Gitleaks analyzer '{id}' config and ignore files differ"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrufflehogConfig {
    pub executable: String,
    pub version_requirement: String,
    pub credential_verification: CredentialVerification,
}

impl TrufflehogConfig {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        validate_executable(id, &self.executable)?;
        validate_version_requirement(id, &self.version_requirement)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialVerification {
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerExecution {
    pub initial: PhaseExecution,
    pub verification: PhaseExecution,
}

impl AnalyzerExecution {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        if self.initial == PhaseExecution::Required && self.verification != PhaseExecution::Required
        {
            return invalid(format!(
                "required analyzer '{id}' must also be required during verification"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseExecution {
    Required,
    Advisory,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerSelection {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub artifact_kinds: Vec<AnalyzerArtifactKind>,
}

impl AnalyzerSelection {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        if self.include.is_empty() || self.artifact_kinds.is_empty() {
            return invalid(format!(
                "analyzer '{id}' requires include patterns and artifact kinds"
            ));
        }
        validate_unique_globs(&format!("analyzer '{id}' include"), &self.include)?;
        validate_unique_globs(&format!("analyzer '{id}' exclude"), &self.exclude)?;
        unique_values(
            &format!("analyzer '{id}' artifact_kinds"),
            &self.artifact_kinds,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerArtifactKind {
    PhysicalFile,
    RepositoryBlob,
    SymbolicLink,
    ArchiveMember,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerLimits {
    pub startup_timeout_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    pub wall_timeout_secs: Option<u64>,
    pub termination_grace_secs: Option<u64>,
    pub cpu_time_secs: Option<u64>,
    pub max_open_files: Option<u64>,
    pub max_stdout_bytes: Option<u64>,
    pub max_stderr_bytes: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub max_output_bytes: Option<u64>,
    pub max_findings: Option<u64>,
    pub max_tool_calls: Option<u64>,
    pub max_bytes_read: Option<u64>,
    pub max_read_bytes_per_call: Option<u64>,
    pub max_search_bytes_per_call: Option<u64>,
    pub max_search_calls: Option<u64>,
    pub max_search_results: Option<u64>,
    pub max_view_files: Option<u64>,
    pub max_view_entries: Option<u64>,
    pub max_view_bytes: Option<u64>,
    pub max_view_depth: Option<u64>,
}

impl AnalyzerLimits {
    fn validate(&self, id: &str) -> Result<(), ProcessingConfigError> {
        if self.values().into_iter().flatten().any(|value| value == 0) {
            return invalid(format!("analyzer '{id}' limits must be positive"));
        }
        Ok(())
    }

    fn validate_scanner(&self, id: &str) -> Result<(), ProcessingConfigError> {
        for (name, value) in [
            ("wall_timeout_secs", self.wall_timeout_secs),
            ("max_file_bytes", self.max_file_bytes),
            ("max_output_bytes", self.max_output_bytes),
            ("max_findings", self.max_findings),
        ] {
            if value.is_none() {
                return invalid(format!("scanner analyzer '{id}' requires limits.{name}"));
            }
        }
        if self.named_values().into_iter().any(|(name, value)| {
            !matches!(
                name,
                "wall_timeout_secs"
                    | "termination_grace_secs"
                    | "cpu_time_secs"
                    | "max_open_files"
                    | "max_file_bytes"
                    | "max_output_bytes"
                    | "max_findings"
            ) && value.is_some()
        }) {
            return invalid(format!(
                "scanner analyzer '{id}' configures a limit that is not enforced by the scanner runtime"
            ));
        }
        Ok(())
    }

    fn validate_builtin(&self, id: &str) -> Result<(), ProcessingConfigError> {
        if self
            .named_values()
            .into_iter()
            .any(|(name, value)| name != "max_findings" && value.is_some())
        {
            return invalid(format!(
                "builtin_rules analyzer '{id}' accepts only limits.max_findings"
            ));
        }
        Ok(())
    }

    fn validate_pi(&self, id: &str) -> Result<(), ProcessingConfigError> {
        let missing = self
            .named_values()
            .into_iter()
            .filter_map(|(name, value)| value.is_none().then_some(name))
            .filter(|name| *name != "max_file_bytes")
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return invalid(format!(
                "Pi analyzer '{id}' requires explicit limits: {}",
                missing.join(", ")
            ));
        }
        let wall = self.wall_timeout_secs.expect("validated");
        if self.startup_timeout_secs.expect("validated") > wall
            || self.idle_timeout_secs.expect("validated") > wall
            || self.termination_grace_secs.expect("validated") > wall
        {
            return invalid(format!(
                "Pi analyzer '{id}' child timeouts must not exceed wall_timeout_secs"
            ));
        }
        if self.max_read_bytes_per_call.expect("validated")
            > self.max_bytes_read.expect("validated")
            || self.max_search_bytes_per_call.expect("validated")
                > self.max_bytes_read.expect("validated")
        {
            return invalid(format!(
                "Pi analyzer '{id}' per-call byte limits must not exceed max_bytes_read"
            ));
        }
        Ok(())
    }

    fn values(&self) -> [Option<u64>; 21] {
        self.named_values().map(|(_, value)| value)
    }

    fn named_values(&self) -> [(&'static str, Option<u64>); 21] {
        [
            ("startup_timeout_secs", self.startup_timeout_secs),
            ("idle_timeout_secs", self.idle_timeout_secs),
            ("wall_timeout_secs", self.wall_timeout_secs),
            ("termination_grace_secs", self.termination_grace_secs),
            ("cpu_time_secs", self.cpu_time_secs),
            ("max_open_files", self.max_open_files),
            ("max_stdout_bytes", self.max_stdout_bytes),
            ("max_stderr_bytes", self.max_stderr_bytes),
            ("max_file_bytes", self.max_file_bytes),
            ("max_output_bytes", self.max_output_bytes),
            ("max_findings", self.max_findings),
            ("max_tool_calls", self.max_tool_calls),
            ("max_bytes_read", self.max_bytes_read),
            ("max_read_bytes_per_call", self.max_read_bytes_per_call),
            ("max_search_bytes_per_call", self.max_search_bytes_per_call),
            ("max_search_calls", self.max_search_calls),
            ("max_search_results", self.max_search_results),
            ("max_view_files", self.max_view_files),
            ("max_view_entries", self.max_view_entries),
            ("max_view_bytes", self.max_view_bytes),
            ("max_view_depth", self.max_view_depth),
        ]
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default)]
    pub jobs: Vec<DaemonJob>,
}

impl DaemonConfig {
    fn validate(
        &self,
        profiles: &BTreeMap<&str, usize>,
        definitions: &[ProcessingProfile],
    ) -> Result<(), ProcessingConfigError> {
        for job in &self.jobs {
            job.validate(profiles, definitions)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonJob {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub profile: String,
    pub schedule: String,
    pub run_on_start: bool,
    pub overlap: DaemonOverlap,
    pub source: DaemonSource,
}

impl DaemonJob {
    fn validate(
        &self,
        profiles: &BTreeMap<&str, usize>,
        definitions: &[ProcessingProfile],
    ) -> Result<(), ProcessingConfigError> {
        validate_id("daemon.jobs.id", &self.id)?;
        let profile = profiles
            .get(self.profile.as_str())
            .map(|index| &definitions[*index])
            .ok_or_else(|| {
                ProcessingConfigError::Invalid(format!(
                    "daemon job '{}' references unknown profile '{}'",
                    self.id, self.profile
                ))
            })?;
        if self.schedule.is_empty()
            || self.schedule.len() > 256
            || self.schedule.trim() != self.schedule
            || self.schedule.chars().any(char::is_control)
            || self.schedule.split_ascii_whitespace().count() != 6
        {
            return invalid(format!("daemon job '{}' has an invalid schedule", self.id));
        }
        cron::Schedule::from_str(&self.schedule).map_err(|_| {
            ProcessingConfigError::Invalid(format!(
                "daemon job '{}' has an invalid schedule",
                self.id
            ))
        })?;
        self.source.validate(&self.id)?;
        match &self.source {
            DaemonSource::Git {
                reference: Some(reference),
                ..
            } if !matches_any_glob(reference, &profile.git.allowed_checkout_ref_patterns) => {
                return invalid(format!(
                    "daemon job '{}' ref does not match its profile's allowed checkout refs",
                    self.id
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonOverlap {
    Reject,
    QueueOne,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonSource {
    Path {
        path: PathBuf,
    },
    Git {
        remote: String,
        #[serde(default)]
        reference: Option<String>,
    },
}

impl DaemonSource {
    fn validate(&self, job: &str) -> Result<(), ProcessingConfigError> {
        match self {
            Self::Path { path } => {
                validate_absolute_normalized(&format!("daemon job '{job}' path"), path)?;
            }
            Self::Git { remote, .. } => validate_remote(remote)?,
        }
        if let Self::Git {
            reference: Some(reference),
            ..
        } = self
        {
            validate_ref(reference)?;
        }
        Ok(())
    }
}

fn unique<'a, T, F>(
    name: &str,
    values: &'a [T],
    key: F,
) -> Result<BTreeMap<&'a str, usize>, ProcessingConfigError>
where
    F: Fn(&'a T) -> &'a String,
{
    let mut result = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        let key = key(value);
        validate_id(name, key)?;
        if result.insert(key.as_str(), index).is_some() {
            return invalid(format!("{name} contains duplicate id '{key}'"));
        }
    }
    Ok(result)
}

fn positive(name: &str, value: u64) -> Result<(), ProcessingConfigError> {
    if value == 0 {
        invalid(format!("{name} must be greater than zero"))
    } else {
        Ok(())
    }
}

fn validate_id(name: &str, value: &str) -> Result<(), ProcessingConfigError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|v| v.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'.' | b'_' | b':' | b'/' | b'-'))
    {
        return invalid(format!("{name} contains invalid identifier '{value}'"));
    }
    Ok(())
}

fn is_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_absolute_normalized(name: &str, path: &Path) -> Result<(), ProcessingConfigError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return invalid(format!("{name} must be an absolute normalized path"));
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn validate_unique_globs(name: &str, values: &[String]) -> Result<(), ProcessingConfigError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.is_empty() || value.len() > 1024 || !unique.insert(value) {
            return invalid(format!(
                "{name} contains an empty, oversized, or duplicate pattern"
            ));
        }
        Glob::new(value)
            .map_err(|error| ProcessingConfigError::Invalid(format!("{name}: {error}")))?;
    }
    Ok(())
}

fn matches_any_glob(value: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| Glob::new(pattern).is_ok_and(|glob| glob.compile_matcher().is_match(value)))
}

fn validate_ref_pattern(
    profile: &str,
    pattern: &str,
    permit_remote_tracking: bool,
) -> Result<(), ProcessingConfigError> {
    let namespace_ok = pattern.starts_with("refs/heads/")
        || pattern.starts_with("refs/tags/")
        || (permit_remote_tracking && pattern.starts_with("refs/remotes/"));
    if !namespace_ok
        || pattern.contains("..")
        || pattern.contains("@{")
        || pattern.chars().any(char::is_control)
    {
        return invalid(format!(
            "profile '{profile}' contains a ref pattern outside the supported namespaces"
        ));
    }
    Ok(())
}

fn validate_unique_ids(name: &str, values: &[String]) -> Result<(), ProcessingConfigError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_id(name, value)?;
        if !unique.insert(value) {
            return invalid(format!("{name} contains duplicate value '{value}'"));
        }
    }
    Ok(())
}

fn unique_values<T: Ord>(name: &str, values: &[T]) -> Result<(), ProcessingConfigError> {
    let mut unique = BTreeSet::new();
    if values.iter().any(|value| !unique.insert(value)) {
        return invalid(format!("{name} contains duplicate values"));
    }
    Ok(())
}

fn validate_executable(id: &str, executable: &str) -> Result<(), ProcessingConfigError> {
    if executable.is_empty()
        || executable.len() > 4096
        || executable.chars().any(char::is_control)
        || executable.starts_with('-')
    {
        return invalid(format!("analyzer '{id}' has an invalid executable"));
    }
    if executable.contains('/') {
        validate_absolute_normalized("analyzer executable", Path::new(executable))?;
    } else if executable == "." || executable == ".." {
        return invalid(format!("analyzer '{id}' has an invalid executable"));
    }
    Ok(())
}

fn validate_version_requirement(id: &str, value: &str) -> Result<(), ProcessingConfigError> {
    if value.is_empty()
        || value.len() > 128
        || value.contains(char::is_whitespace)
        || !value.starts_with(">=")
        || !value.contains(",<")
        || value.chars().any(char::is_control)
    {
        return invalid(format!(
            "analyzer '{id}' requires a bounded >=minimum,<maximum version requirement"
        ));
    }
    Ok(())
}

fn validate_ref(reference: &str) -> Result<(), ProcessingConfigError> {
    let is_oid = matches!(reference.len(), 40 | 64)
        && reference.bytes().all(|byte| byte.is_ascii_hexdigit());
    if reference.is_empty()
        || reference.len() > 256
        || reference.starts_with('-')
        || reference.contains("..")
        || reference.contains("@{")
        || reference.ends_with('.')
        || reference.ends_with('/')
        || reference
            .chars()
            .any(|value| value.is_control() || value.is_whitespace())
        || is_oid
    {
        return invalid("Git ref is malformed, option-looking, or a raw object ID");
    }
    Ok(())
}

fn validate_remote(remote: &str) -> Result<(), ProcessingConfigError> {
    if remote.is_empty()
        || remote.len() > 4096
        || remote.starts_with('-')
        || remote.chars().any(char::is_control)
    {
        return invalid("Git remote is malformed or option-looking");
    }
    if let Some(rest) = remote.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty()
            || path.is_empty()
            || authority.contains('@')
            || remote.contains('?')
            || remote.contains('#')
        {
            return invalid("HTTPS Git remote contains credentials, query, fragment, or no host");
        }
        return Ok(());
    }
    if let Some(rest) = remote.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if authority.is_empty()
            || host.is_empty()
            || path.is_empty()
            || authority.ends_with('@')
            || remote.contains('?')
            || remote.contains('#')
        {
            return invalid("SSH Git remote is malformed");
        }
        return Ok(());
    }
    if !remote.contains("://") {
        let Some((authority, path)) = remote.split_once(':') else {
            return invalid("Git remote must use HTTPS, SSH, or SCP-like syntax");
        };
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let authority_is_valid = !(authority.is_empty()
            || host.is_empty()
            || (authority.len() == 1 && authority.as_bytes()[0].is_ascii_alphabetic())
            || authority.starts_with('/')
            || authority.ends_with('@')
            || authority.contains(['/', '\\'])
            || authority.chars().any(char::is_whitespace));
        if authority_is_valid
            && !path.is_empty()
            && !path.starts_with('/')
            && !path.contains(['?', '#'])
        {
            return Ok(());
        }
    }
    invalid("Git remote transport is not permitted")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../docs/examples/processing-v3.toml");
    const PI_ANALYZER: &str = r#"
id = "pi-triage"
kind = "pi_classifier"
scope = "tree"

[pi]
platform = "linux"
sandbox = "tool-sidecar-bubblewrap-v1"
network = "pi_host_sidecar_none"
pi_executable = "/usr/local/bin/pi"
bubblewrap_executable = "/usr/bin/bwrap"
expected_bubblewrap_version = "0.11.1"
expected_pi_version = "0.83.0"
provider = "internal"
model = "triage"
thinking = "high"
instruction_file = "/etc/file-guardian/pi-triage.md"
trusted_extension = "/usr/libexec/file-guardian/pi-extension.js"
tool_sidecar_runner = "/usr/libexec/file-guardian/pi-sidecar.js"
isolated_agent_dir = "/etc/file-guardian/pi-agent"
output_schema = "file-guardian-pi-triage/1"
tool_grant = "sandboxed-shell-v1"

[[pi.credentials]]
label = "internal"
source_env = "FILE_GUARDIAN_PI_CREDENTIAL_INTERNAL"
target_env = "INTERNAL_API_KEY"

[vocabulary]
classifications = ["confirmed", "likely_true_positive", "likely_false_positive", "false_positive", "uncertain", "unable_to_assess"]
confidences = ["low", "medium", "high"]
reason_codes = ["documented_test_fixture", "example_placeholder"]

[execution]
initial = "advisory"
verification = "disabled"

[selection]
include = ["**"]
exclude = []
artifact_kinds = ["physical_file", "repository_blob"]

[content_applicability]
required_text_include = ["**/*.rs"]

[limits]
startup_timeout_secs = 20
idle_timeout_secs = 30
wall_timeout_secs = 180
termination_grace_secs = 5
cpu_time_secs = 120
max_open_files = 64
max_stdout_bytes = 1048576
max_stderr_bytes = 1048576
max_output_bytes = 2097152
max_findings = 1000
max_tool_calls = 1000
max_bytes_read = 268435456
max_read_bytes_per_call = 1048576
max_search_bytes_per_call = 67108864
max_search_calls = 100
max_search_results = 1000
max_view_files = 100000
max_view_entries = 200000
max_view_bytes = 268435456
max_view_depth = 64
"#;

    #[test]
    fn shipped_example_is_valid_and_closed() {
        let config = ProcessingConfigFile::parse(EXAMPLE).unwrap();
        assert_eq!(config.schema_version, "3");
        assert_eq!(config.processing.profiles.len(), 2);
        assert_eq!(config.analyzers.len(), 2);
        assert_eq!(config.daemon.jobs.len(), 2);
    }

    #[test]
    fn rejects_schema_two_and_unknown_fields() {
        let schema_two = EXAMPLE.replacen("schema_version = \"3\"", "schema_version = \"2\"", 1);
        assert!(matches!(
            ProcessingConfigFile::parse(&schema_two),
            Err(ProcessingConfigError::Invalid(_))
        ));

        let unknown = EXAMPLE.replacen(
            "default_profile = \"upload\"",
            "default_profile = \"upload\"\nlegacy_authorization = true",
            1,
        );
        assert!(matches!(
            ProcessingConfigFile::parse(&unknown),
            Err(ProcessingConfigError::Parse(_))
        ));
    }

    #[test]
    fn validates_history_and_ref_pattern_matrix() {
        let missing_patterns = EXAMPLE.replacen(
            "history_ref_patterns = [\"refs/heads/*\", \"refs/tags/release-*\"]",
            "history_ref_patterns = []",
            1,
        );
        assert!(ProcessingConfigFile::parse(&missing_patterns).is_err());

        let forbidden_patterns = EXAMPLE.replacen(
            "history = \"none\"\nhistory_ref_patterns = []",
            "history = \"none\"\nhistory_ref_patterns = [\"refs/heads/*\"]",
            1,
        );
        assert!(ProcessingConfigFile::parse(&forbidden_patterns).is_err());

        let no_surface = EXAMPLE.replacen("working_tree = true", "working_tree = false", 1);
        assert!(ProcessingConfigFile::parse(&no_surface).is_err());
    }

    #[test]
    fn validates_path_git_detection_purpose_completion_and_daemon_source_matrix() {
        let history_path_job = EXAMPLE.replacen(
            "\nprofile = \"upload\"\n",
            "\nprofile = \"repository-review\"\n",
            1,
        );
        assert!(ProcessingConfigFile::parse(&history_path_job).is_ok());

        let retained_report_only = EXAMPLE.replacen(
            "allow = \"discard\"\nallow_modified = \"discard\"",
            "allow = \"retain\"\nallow_modified = \"retain\"",
            1,
        );
        assert!(ProcessingConfigFile::parse(&retained_report_only).is_err());

        let cross_variant_field = EXAMPLE.replacen(
            "kind = \"path\"\npath = \"/srv/incoming/batch\"",
            "kind = \"path\"\npath = \"/srv/incoming/batch\"\nremote = \"git@example.com:x/y.git\"",
            1,
        );
        assert!(matches!(
            ProcessingConfigFile::parse(&cross_variant_field),
            Err(ProcessingConfigError::Parse(_))
        ));

        let bad_ref = EXAMPLE.replacen(
            "reference = \"refs/heads/main\"",
            "reference = \"refs/pull/1/head\"",
            1,
        );
        assert!(ProcessingConfigFile::parse(&bad_ref).is_err());
    }

    #[test]
    fn rejects_overlapping_job_roots_and_zero_limits() {
        let overlap = EXAMPLE.replacen(
            "reports_root = \"/var/lib/file-guardian/reports\"",
            "reports_root = \"/var/lib/file-guardian/jobs/reports\"",
            1,
        );
        assert!(ProcessingConfigFile::parse(&overlap).is_err());

        let zero = EXAMPLE.replacen("max_refs = 10000", "max_refs = 0", 1);
        assert!(ProcessingConfigFile::parse(&zero).is_err());
    }

    #[test]
    fn scanner_kinds_are_closed_and_required_scanners_repeat() {
        let generic = EXAMPLE.replacen("kind = \"gitleaks\"", "kind = \"external_tool\"", 1);
        assert!(matches!(
            ProcessingConfigFile::parse(&generic),
            Err(ProcessingConfigError::Parse(_))
        ));

        let arguments = EXAMPLE.replacen(
            "executable = \"gitleaks\"",
            "executable = \"gitleaks\"\nargs = [\"--unsafe\"]",
            1,
        );
        assert!(matches!(
            ProcessingConfigFile::parse(&arguments),
            Err(ProcessingConfigError::Parse(_))
        ));

        let no_verification = EXAMPLE.replacen(
            "initial = \"required\"\nverification = \"required\"",
            "initial = \"required\"\nverification = \"disabled\"",
            1,
        );
        assert!(ProcessingConfigFile::parse(&no_verification).is_err());

        let online_verification = EXAMPLE.replacen(
            "credential_verification = \"disabled\"",
            "credential_verification = \"enabled\"",
            1,
        );
        assert!(matches!(
            ProcessingConfigFile::parse(&online_verification),
            Err(ProcessingConfigError::Parse(_))
        ));

        let unenforced_memory_limit = EXAMPLE.replacen(
            "max_findings = 10000",
            "max_findings = 10000\nmemory_bytes = 536870912",
            1,
        );
        assert!(ProcessingConfigFile::parse(&unenforced_memory_limit).is_err());
    }

    #[test]
    fn retains_strict_builtin_and_pi_analyzer_contracts() {
        let builtin: AnalyzerConfig = toml::from_str(
            r#"
id = "rules"
kind = "builtin_rules"
rule_files = ["/etc/file-guardian/rules.toml"]
max_content_bytes = 16777216

[execution]
initial = "required"
verification = "required"

[selection]
include = ["**"]
exclude = []
artifact_kinds = ["physical_file", "repository_blob"]

[content_applicability]
required_text_include = ["**/*.rs"]

[limits]
"#,
        )
        .unwrap();
        assert!(matches!(&builtin.kind, AnalyzerKind::BuiltinRules(_)));
        builtin.validate().unwrap();

        let pi: AnalyzerConfig = toml::from_str(PI_ANALYZER).unwrap();
        assert!(matches!(&pi.kind, AnalyzerKind::PiClassifier(_)));
        pi.validate().unwrap();

        let obsolete = PI_ANALYZER.replace(
            "output_schema = \"file-guardian-pi-triage/1\"",
            "output_schema = \"file-guardian-pi-classifier/1\"",
        );
        let obsolete: AnalyzerConfig = toml::from_str(&obsolete).unwrap();
        assert!(obsolete.validate().is_err());
    }

    #[test]
    fn pi_adjudication_must_reference_pipeline_pi_analyzer() {
        let mut config = ProcessingConfigFile::parse(EXAMPLE).unwrap();
        config.processing.profiles[0].pi_adjudication = Some(PiAdjudication {
            analyzer: "gitleaks".into(),
            mode: PiAdjudicationMode::Advisory,
            required_initial: false,
            required_after_actions: false,
        });
        assert!(config.validate().is_err());

        config.processing.profiles[0]
            .pi_adjudication
            .as_mut()
            .unwrap()
            .analyzer = "pi-triage".into();
        config.analyzers.push(toml::from_str(PI_ANALYZER).unwrap());
        assert!(config.validate().is_err());
        config.pipelines[0].stages.push(PipelineStage {
            id: "pi-review".into(),
            analyzers: vec!["pi-triage".into()],
            execution: StageExecution::Serial,
            max_concurrency: 1,
            prior_observations: PriorObservations::FindingsSummary,
            prior_limits: PriorLimits::default(),
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validates_pi_adjudication_authority_matrix() {
        let advisory = PiAdjudication {
            analyzer: "pi-triage".into(),
            mode: PiAdjudicationMode::Advisory,
            required_initial: false,
            required_after_actions: false,
        };
        let mut profile = ProcessingConfigFile::parse(EXAMPLE)
            .unwrap()
            .processing
            .profiles
            .remove(0);
        assert!(advisory.validate(&profile).is_ok());

        let mut authoritative = advisory;
        authoritative.mode = PiAdjudicationMode::Authoritative;
        authoritative.required_initial = true;
        assert!(authoritative.validate(&profile).is_err());
        authoritative.required_after_actions = true;
        assert!(authoritative.validate(&profile).is_ok());

        profile.action_mode = ActionMode::Evaluate;
        authoritative.required_after_actions = false;
        assert!(authoritative.validate(&profile).is_ok());
    }

    #[test]
    fn validates_remote_transport_and_ref_safety() {
        for valid in [
            "https://example.com/org/repo.git",
            "ssh://git@example.com/org/repo.git",
            "git@example.com:org/repo.git",
        ] {
            assert!(validate_remote(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "http://example.com/repo.git",
            "file:///tmp/repo",
            "https://user:password@example.com/repo.git",
            "https://example.com/repo.git?token=x",
            "-uploader",
            "/tmp/repo",
        ] {
            assert!(validate_remote(invalid).is_err(), "{invalid}");
        }
        assert!(validate_ref("refs/heads/main").is_ok());
        assert!(validate_ref("0123456789012345678901234567890123456789").is_err());
        assert!(validate_ref("--upload-pack=evil").is_err());
    }
}
