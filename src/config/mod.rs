//! Strict, versioned service configuration.
//!
//! Schema 2 is an intentional replacement for the original implicit scanner
//! configuration.  It has no aliases, legacy parser, or semantic environment
//! overrides: the environment may select the configuration file and nothing
//! else.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use globset::Glob;
use serde::{Deserialize, Serialize};

use crate::logging::LoggingSettings;
use crate::policy::PolicyDirective;

pub const CONFIG_SCHEMA_VERSION: &str = "2";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/file-guardian/config.toml";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathKind {
    Explicit,
    Env,
    Default,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: String,
    pub authorization: AuthorizationConfig,
    pub pipelines: Vec<PipelineConfig>,
    pub analyzers: Vec<AnalyzerConfig>,
    #[serde(default)]
    pub policy_bindings: Vec<PolicyBindingConfig>,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load_from_sources(cli_path: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, _) = Self::resolve_path(cli_path);
        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
        let config = toml::from_str::<Self>(&raw).map_err(|source| ConfigError::ParseToml {
            path: path.clone(),
            source,
        })?;
        config.validate()?;
        let sourced_path = if path.is_absolute() {
            path.clone()
        } else {
            env::current_dir()
                .map_err(|source| ConfigError::Io {
                    path: path.clone(),
                    source,
                })?
                .join(&path)
        };
        let resolved_path = fs::canonicalize(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
        let resolved_workspace = match fs::canonicalize(&config.authorization.workspace.root) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                config.authorization.workspace.root.clone()
            }
            Err(source) => {
                return Err(ConfigError::Io {
                    path: config.authorization.workspace.root.clone(),
                    source,
                });
            }
        };
        validate_disjoint(
            "authorization.workspace.root",
            &config.authorization.workspace.root,
            "configuration source path",
            &sourced_path,
        )?;
        validate_disjoint(
            "resolved authorization.workspace.root",
            &resolved_workspace,
            "resolved configuration file path",
            &resolved_path,
        )?;
        Ok(config)
    }

    pub fn resolve_path(cli_path: Option<&Path>) -> (PathBuf, ConfigPathKind) {
        if let Some(path) = cli_path {
            (path.to_path_buf(), ConfigPathKind::Explicit)
        } else if let Some(path) = env::var_os("FILE_GUARDIAN_CONFIG") {
            (PathBuf::from(path), ConfigPathKind::Env)
        } else {
            (PathBuf::from(DEFAULT_CONFIG_PATH), ConfigPathKind::Default)
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return invalid(format!(
                "unsupported schema_version '{}'; expected '{CONFIG_SCHEMA_VERSION}'",
                self.schema_version
            ));
        }
        validate_absolute(
            "authorization.workspace.root",
            &self.authorization.workspace.root,
        )?;
        let limits = &self.authorization.workspace.capture;
        if limits.max_files == 0
            || limits.max_file_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_depth == 0
        {
            return invalid("authorization.workspace.capture limits must all be greater than zero");
        }
        if limits.max_file_bytes > limits.max_total_bytes {
            return invalid(
                "authorization.workspace.capture.max_file_bytes must not exceed max_total_bytes",
            );
        }

        let profiles = unique_by(
            "authorization.profiles",
            &self.authorization.profiles,
            |p| &p.id,
        )?;
        let pipelines = unique_by("pipelines", &self.pipelines, |p| &p.id)?;
        let analyzers = unique_by("analyzers", &self.analyzers, |a| &a.id)?;
        unique_by("policy_bindings", &self.policy_bindings, |b| &b.id)?;
        unique_by("daemon.jobs", &self.daemon.jobs, |j| &j.id)?;

        validate_id(
            "authorization.default_profile",
            &self.authorization.default_profile,
        )?;
        if !profiles.contains_key(self.authorization.default_profile.as_str()) {
            return invalid(format!(
                "authorization.default_profile '{}' does not resolve",
                self.authorization.default_profile
            ));
        }
        if profiles.is_empty() || pipelines.is_empty() || analyzers.is_empty() {
            return invalid("profiles, pipelines, and analyzers must not be empty");
        }

        for profile in &self.authorization.profiles {
            validate_id("authorization.profiles.id", &profile.id)?;
            if !pipelines.contains_key(profile.pipeline.as_str()) {
                return invalid(format!(
                    "profile '{}' references unknown pipeline '{}'",
                    profile.id, profile.pipeline
                ));
            }
        }

        let mut used_analyzers = BTreeSet::new();
        for pipeline in &self.pipelines {
            validate_id("pipelines.id", &pipeline.id)?;
            if pipeline.stages.is_empty() {
                return invalid(format!(
                    "pipeline '{}' must contain at least one stage",
                    pipeline.id
                ));
            }
            unique_by("pipelines.stages", &pipeline.stages, |stage| &stage.id)?;
            for stage in &pipeline.stages {
                validate_id("pipelines.stages.id", &stage.id)?;
                if stage.analyzers.is_empty() {
                    return invalid(format!(
                        "pipeline '{}' stage '{}' must contain at least one analyzer",
                        pipeline.id, stage.id
                    ));
                }
                if stage.max_concurrency == 0 {
                    return invalid(format!(
                        "pipeline '{}' stage '{}' max_concurrency must be greater than zero",
                        pipeline.id, stage.id
                    ));
                }
                stage.prior_limits.validate(&pipeline.id, &stage.id)?;
                for analyzer in &stage.analyzers {
                    if !analyzers.contains_key(analyzer.as_str()) {
                        return invalid(format!(
                            "pipeline '{}' stage '{}' references unknown analyzer '{}'",
                            pipeline.id, stage.id, analyzer
                        ));
                    }
                    if !used_analyzers.insert((pipeline.id.as_str(), analyzer.as_str())) {
                        return invalid(format!(
                            "pipeline '{}' uses analyzer '{}' more than once",
                            pipeline.id, analyzer
                        ));
                    }
                }
            }
        }

        for analyzer in &self.analyzers {
            analyzer.validate()?;
            let administrator_paths = analyzer.administrator_paths();
            for (_, path) in &administrator_paths {
                validate_disjoint(
                    "authorization.workspace.root",
                    &self.authorization.workspace.root,
                    "analyzer administrator path",
                    path,
                )?;
            }
            for (index, (left_name, left)) in administrator_paths.iter().enumerate() {
                for (right_name, right) in administrator_paths.iter().skip(index + 1) {
                    validate_disjoint(left_name, left, right_name, right)?;
                }
            }
        }
        for binding in &self.policy_bindings {
            binding.validate(&profiles, &analyzers)?;
            let bound_analyzer = &self.analyzers[analyzers[binding.analyzer.as_str()]];
            match (&binding.rule, &binding.classification, &bound_analyzer.kind) {
                (Some(_), None, AnalyzerKind::PiClassifier { .. }) => {
                    return invalid(format!(
                        "policy binding '{}' uses a rule selector for Pi analyzer '{}'",
                        binding.id, binding.analyzer
                    ));
                }
                (None, Some(code), AnalyzerKind::PiClassifier { vocabulary, .. }) => {
                    if !vocabulary.classifications.contains(code) {
                        return invalid(format!(
                            "policy binding '{}' classification '{}' is outside analyzer '{}' vocabulary",
                            binding.id, code, binding.analyzer
                        ));
                    }
                }
                (None, Some(_), _) => {
                    return invalid(format!(
                        "policy binding '{}' uses a classification selector for non-Pi analyzer '{}'",
                        binding.id, binding.analyzer
                    ));
                }
                _ => {}
            }
            let profile = &self.authorization.profiles[profiles[binding.profile.as_str()]];
            let pipeline = &self.pipelines[pipelines[profile.pipeline.as_str()]];
            if !pipeline
                .stages
                .iter()
                .any(|stage| stage.analyzers.contains(&binding.analyzer))
            {
                return invalid(format!(
                    "policy binding '{}' references analyzer '{}' outside profile '{}' pipeline",
                    binding.id, binding.analyzer, binding.profile
                ));
            }
        }
        validate_binding_ambiguity(&self.policy_bindings)?;
        self.validate_pi_audit_bindings(&profiles, &pipelines, &analyzers)?;
        for job in &self.daemon.jobs {
            job.validate(&profiles)?;
        }
        if let Some(directory) = &self.logging.directory {
            validate_absolute("logging.directory", directory)?;
            validate_disjoint(
                "authorization.workspace.root",
                &self.authorization.workspace.root,
                "logging.directory",
                directory,
            )?;
        }
        LoggingSettings::from_config(&self.logging)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        Ok(())
    }

    fn validate_pi_audit_bindings(
        &self,
        profiles: &BTreeMap<&str, usize>,
        pipelines: &BTreeMap<&str, usize>,
        analyzers: &BTreeMap<&str, usize>,
    ) -> Result<(), ConfigError> {
        for profile_name in profiles.keys() {
            let profile = &self.authorization.profiles[profiles[profile_name]];
            let pipeline = &self.pipelines[pipelines[profile.pipeline.as_str()]];
            for analyzer_name in pipeline.stages.iter().flat_map(|stage| &stage.analyzers) {
                let analyzer = &self.analyzers[analyzers[analyzer_name.as_str()]];
                let AnalyzerKind::PiClassifier { vocabulary, .. } = &analyzer.kind else {
                    continue;
                };
                for classification in &vocabulary.classifications {
                    let binding = self.policy_bindings.iter().find(|binding| {
                        binding.profile == profile.id
                            && binding.analyzer == analyzer.id
                            && binding.classification.as_ref() == Some(classification)
                    });
                    match binding {
                        None => {
                            return invalid(format!(
                                "profile '{}' must bind Pi analyzer '{}' classification '{}' explicitly to audit",
                                profile.id, analyzer.id, classification
                            ));
                        }
                        Some(binding) if binding.directive != PolicyDirective::Audit => {
                            return invalid(format!(
                                "policy binding '{}' for Pi analyzer '{}' must use directive = 'audit'",
                                binding.id, analyzer.id
                            ));
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        Ok(())
    }

    pub fn validate_for_authorize(
        &self,
        profile_id: Option<&str>,
    ) -> Result<AuthorizationSelection<'_>, ConfigError> {
        self.validate_for_authorize_mode(profile_id, None)
    }

    /// Validate a one-shot selection and resolve requested authority. Passing
    /// `evaluate` may downgrade an apply-capable profile; it can never upgrade
    /// an evaluate-only profile.
    pub fn validate_for_authorize_mode(
        &self,
        profile_id: Option<&str>,
        requested_mode: Option<ActionMode>,
    ) -> Result<AuthorizationSelection<'_>, ConfigError> {
        self.validate()?;
        let requested = profile_id.unwrap_or(&self.authorization.default_profile);
        let profile = self
            .authorization
            .profiles
            .iter()
            .find(|profile| profile.id == requested)
            .ok_or_else(|| {
                ConfigError::Invalid(format!("unknown authorization profile '{requested}'"))
            })?;
        let pipeline = self
            .pipelines
            .iter()
            .find(|pipeline| pipeline.id == profile.pipeline)
            .expect("validated pipeline reference");
        if profile.action_mode == ActionMode::Evaluate && requested_mode == Some(ActionMode::Apply)
        {
            return invalid(format!(
                "profile '{}' does not grant requested apply authority",
                profile.id
            ));
        }
        let effective_mode = requested_mode.unwrap_or(profile.action_mode);
        if effective_mode != ActionMode::Evaluate {
            return invalid(format!(
                "profile '{}' requires apply mode, which is unavailable in evaluate-only authorization; request evaluate explicitly to downgrade",
                profile.id
            ));
        }
        Ok(AuthorizationSelection {
            profile,
            pipeline,
            effective_mode,
        })
    }

    pub fn analyzer(&self, id: &str) -> Option<&AnalyzerConfig> {
        self.analyzers.iter().find(|analyzer| analyzer.id == id)
    }

    pub fn bindings_for_profile<'a>(
        &'a self,
        profile: &'a str,
    ) -> impl Iterator<Item = &'a PolicyBindingConfig> + 'a {
        self.policy_bindings
            .iter()
            .filter(move |binding| binding.profile == profile)
    }

    /// Select enabled daemon jobs. An empty selector means every enabled job.
    pub fn validate_for_daemon(
        &self,
        selected: &[String],
    ) -> Result<Vec<&DaemonJobConfig>, ConfigError> {
        self.validate()?;
        let wanted = selected.iter().collect::<BTreeSet<_>>();
        for id in &wanted {
            if !self.daemon.jobs.iter().any(|job| &job.id == *id) {
                return invalid(format!("unknown daemon job '{id}'"));
            }
        }
        let jobs = self
            .daemon
            .jobs
            .iter()
            .filter(|job| job.enabled && (wanted.is_empty() || wanted.contains(&job.id)))
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            return invalid("daemon selection contains no enabled jobs");
        }
        for job in &jobs {
            let DaemonJobKind::PolicyScan { profile, .. } = &job.kind;
            self.validate_for_authorize(Some(profile))?;
        }
        Ok(jobs)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizationSelection<'a> {
    pub profile: &'a AuthorizationProfile,
    pub pipeline: &'a PipelineConfig,
    pub effective_mode: ActionMode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConfig {
    pub default_profile: String,
    pub workspace: WorkspaceConfig,
    pub profiles: Vec<AuthorizationProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {
    pub root: PathBuf,
    #[serde(default)]
    pub capture: CaptureConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    #[serde(default = "default_max_files")]
    pub max_files: u64,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_files: default_max_files(),
            max_file_bytes: default_max_file_bytes(),
            max_total_bytes: default_max_total_bytes(),
            max_depth: default_max_depth(),
        }
    }
}

fn default_max_files() -> u64 {
    100_000
}
fn default_max_file_bytes() -> u64 {
    1024 * 1024 * 1024
}
fn default_max_total_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}
fn default_max_depth() -> usize {
    64
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProfile {
    pub id: String,
    pub pipeline: String,
    #[serde(default)]
    pub action_mode: ActionMode,
    #[serde(default)]
    pub default_unbound_observation: UnboundObservation,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMode {
    #[default]
    Evaluate,
    Apply,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnboundObservation {
    Audit,
    Deny,
    #[default]
    Error,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineConfig {
    pub id: String,
    pub stages: Vec<StageConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageConfig {
    pub id: String,
    #[serde(default)]
    pub execution: StageExecution,
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    pub analyzers: Vec<String>,
    #[serde(default)]
    pub prior_observations: PriorObservations,
    #[serde(default)]
    pub prior_limits: PriorObservationLimitsConfig,
}

fn default_max_concurrency() -> usize {
    1
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageExecution {
    #[default]
    Serial,
    Parallel,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorObservations {
    #[default]
    None,
    FindingsSummary,
    AllNormalized,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorObservationLimitsConfig {
    #[serde(default = "default_max_prior_observations")]
    pub max_observations: u64,
    #[serde(default = "default_max_prior_serialized_bytes")]
    pub max_serialized_bytes: u64,
}

impl Default for PriorObservationLimitsConfig {
    fn default() -> Self {
        Self {
            max_observations: default_max_prior_observations(),
            max_serialized_bytes: default_max_prior_serialized_bytes(),
        }
    }
}

impl PriorObservationLimitsConfig {
    fn validate(&self, pipeline: &str, stage: &str) -> Result<(), ConfigError> {
        if self.max_observations == 0 || self.max_serialized_bytes == 0 {
            return invalid(format!(
                "pipeline '{pipeline}' stage '{stage}' prior_limits must be greater than zero"
            ));
        }
        Ok(())
    }
}

fn default_max_prior_observations() -> u64 {
    10_000
}

fn default_max_prior_serialized_bytes() -> u64 {
    1024 * 1024
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalyzerConfig {
    pub id: String,
    #[serde(default = "default_required")]
    pub required: bool,
    #[serde(flatten)]
    pub kind: AnalyzerKind,
    #[serde(default)]
    pub selection: SelectionConfig,
    #[serde(default)]
    pub limits: AnalyzerLimits,
}

fn default_required() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalyzerKind {
    BuiltinRules {
        rule_files: Vec<PathBuf>,
        #[serde(default = "default_builtin_max_content_bytes")]
        max_content_bytes: u64,
        #[serde(default)]
        content_applicability: ContentApplicabilityConfig,
    },
    PiClassifier {
        #[serde(default)]
        scope: ClassifierScope,
        pi: Box<PiConfig>,
        vocabulary: Box<VocabularyConfig>,
    },
    ExternalTool {
        adapter: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        protocol: String,
        sandbox: String,
    },
}

fn default_builtin_max_content_bytes() -> u64 {
    16 * 1024 * 1024
}

impl AnalyzerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_id("analyzers.id", &self.id)?;
        if !self.required {
            return invalid(format!(
                "analyzer '{}' is optional, but incomplete advisory coverage is not enabled in schema 2",
                self.id
            ));
        }
        self.selection.validate(&self.id)?;
        self.limits.validate(&self.id)?;
        match &self.kind {
            AnalyzerKind::BuiltinRules {
                rule_files,
                max_content_bytes,
                ..
            } => {
                if rule_files.is_empty() || *max_content_bytes == 0 {
                    return invalid(format!("built-in analyzer '{}' requires rule files and a positive max_content_bytes", self.id));
                }
                for path in rule_files {
                    validate_absolute("analyzers.rule_files", path)?;
                }
            }
            AnalyzerKind::PiClassifier { pi, vocabulary, .. } => {
                pi.validate(&self.id)?;
                vocabulary.validate(&self.id)?;
                self.limits.validate_complete_pi(&self.id)?;
            }
            AnalyzerKind::ExternalTool {
                adapter,
                protocol,
                sandbox,
                ..
            } => {
                validate_absolute("analyzers.adapter", adapter)?;
                if protocol.trim().is_empty() || sandbox != "required" {
                    return invalid(format!(
                        "external analyzer '{}' requires a protocol and sandbox = 'required'",
                        self.id
                    ));
                }
            }
        }
        Ok(())
    }

    fn administrator_paths(&self) -> Vec<(&'static str, &Path)> {
        match &self.kind {
            AnalyzerKind::BuiltinRules { rule_files, .. } => rule_files
                .iter()
                .map(|path| ("analyzers.rule_files", path.as_path()))
                .collect(),
            AnalyzerKind::PiClassifier { pi, .. } => vec![
                ("analyzers.pi.runtime_root", pi.runtime_root.as_path()),
                (
                    "analyzers.pi.bubblewrap_executable",
                    pi.bubblewrap_executable.as_path(),
                ),
                (
                    "analyzers.pi.instruction_file",
                    pi.instruction_file.as_path(),
                ),
                (
                    "analyzers.pi.trusted_extension",
                    pi.trusted_extension.as_path(),
                ),
                (
                    "analyzers.pi.isolated_agent_dir",
                    pi.isolated_agent_dir.as_path(),
                ),
            ],
            AnalyzerKind::ExternalTool { adapter, .. } => {
                vec![("analyzers.adapter", adapter.as_path())]
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierScope {
    Artifact,
    #[default]
    Tree,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentApplicabilityConfig {
    #[serde(default)]
    pub invalid_utf8: ApplicabilityPolicy,
    #[serde(default)]
    pub over_max_bytes: ApplicabilityPolicy,
}

impl Default for ContentApplicabilityConfig {
    fn default() -> Self {
        Self {
            invalid_utf8: ApplicabilityPolicy::Fail,
            over_max_bytes: ApplicabilityPolicy::Fail,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityPolicy {
    #[default]
    Fail,
    Exclude,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiConfig {
    pub platform: PiPlatform,
    pub sandbox: PiSandbox,
    pub network: PiNetworkMode,
    pub runtime_root: PathBuf,
    pub runtime_manifest: PathBuf,
    pub launcher: PathBuf,
    pub pi_entrypoint: PathBuf,
    pub bubblewrap_executable: PathBuf,
    pub expected_bubblewrap_version: String,
    pub expected_pi_version: String,
    pub provider: String,
    pub model: String,
    pub thinking: String,
    pub instruction_file: PathBuf,
    pub trusted_extension: PathBuf,
    pub isolated_agent_dir: PathBuf,
    pub credentials: Vec<PiCredentialEnvConfig>,
    pub output_schema: String,
    pub tool_grant: String,
}

impl PiConfig {
    fn validate(&self, id: &str) -> Result<(), ConfigError> {
        for (field, path) in [
            ("analyzers.pi.runtime_root", &self.runtime_root),
            (
                "analyzers.pi.bubblewrap_executable",
                &self.bubblewrap_executable,
            ),
            ("analyzers.pi.instruction_file", &self.instruction_file),
            ("analyzers.pi.trusted_extension", &self.trusted_extension),
            ("analyzers.pi.isolated_agent_dir", &self.isolated_agent_dir),
        ] {
            validate_absolute(field, path)?;
        }
        for (field, path) in [
            ("runtime_manifest", &self.runtime_manifest),
            ("launcher", &self.launcher),
            ("pi_entrypoint", &self.pi_entrypoint),
        ] {
            validate_relative(field, path).map_err(|_| {
                ConfigError::Invalid(format!(
                    "Pi analyzer '{id}' {field} must be a normalized relative path inside runtime_root"
                ))
            })?;
        }
        if self.runtime_manifest == self.launcher
            || self.runtime_manifest == self.pi_entrypoint
            || self.launcher == self.pi_entrypoint
        {
            return invalid(format!(
                "Pi analyzer '{id}' runtime_manifest, launcher, and pi_entrypoint must be distinct"
            ));
        }
        for (field, value) in [
            (
                "expected_bubblewrap_version",
                &self.expected_bubblewrap_version,
            ),
            ("expected_pi_version", &self.expected_pi_version),
            ("provider", &self.provider),
            ("model", &self.model),
        ] {
            validate_bounded_text(id, field, value)?;
        }
        if !matches!(
            self.thinking.as_str(),
            "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
        ) {
            return invalid(format!(
                "Pi analyzer '{id}' thinking must be one of off, minimal, low, medium, high, xhigh, or max"
            ));
        }
        if self.output_schema != "file-guardian-pi-classifier/1" {
            return invalid(format!(
                "Pi analyzer '{id}' requires output_schema = 'file-guardian-pi-classifier/1'"
            ));
        }
        if self.tool_grant != "artifact-readonly-v1" {
            return invalid(format!(
                "Pi analyzer '{id}' requires tool_grant = 'artifact-readonly-v1'"
            ));
        }
        if self.credentials.is_empty() {
            return invalid(format!(
                "Pi analyzer '{id}' credentials must contain at least one explicit credential mapping"
            ));
        }
        let mut labels = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut targets = BTreeSet::new();
        for credential in &self.credentials {
            credential.validate(id)?;
            if !labels.insert(&credential.label)
                || !sources.insert(&credential.source_env)
                || !targets.insert(&credential.target_env)
            {
                return invalid(format!(
                    "Pi analyzer '{id}' credential labels, source_env values, and target_env values must each be unique"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiPlatform {
    Linux,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum PiSandbox {
    #[serde(rename = "bubblewrap-v1")]
    BubblewrapV1,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiNetworkMode {
    /// The sandbox shares the host network solely because Pi must reach the
    /// configured internal model. It does not claim network isolation.
    HostInternalModel,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiCredentialEnvConfig {
    /// Non-secret identifier used in diagnostics and identity material.
    pub label: String,
    /// Dedicated parent-process variable from which the secret is read.
    pub source_env: String,
    /// Credential variable exposed inside the otherwise cleared environment.
    pub target_env: String,
}

impl PiCredentialEnvConfig {
    fn validate(&self, id: &str) -> Result<(), ConfigError> {
        validate_id("analyzers.pi.credentials.label", &self.label)?;
        if !is_environment_name(&self.source_env)
            || !self.source_env.starts_with("FILE_GUARDIAN_PI_CREDENTIAL_")
            || self.source_env == "FILE_GUARDIAN_PI_CREDENTIAL_"
        {
            return invalid(format!(
                "Pi analyzer '{id}' credential source_env must use the dedicated FILE_GUARDIAN_PI_CREDENTIAL_* namespace"
            ));
        }
        if !is_safe_credential_target(&self.target_env) {
            return invalid(format!(
                "Pi analyzer '{id}' credential target_env '{}' is not an explicit credential variable",
                self.target_env
            ));
        }
        Ok(())
    }
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

fn is_safe_credential_target(value: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "PATH",
        "HOME",
        "NODE_PATH",
        "NODE_OPTIONS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
    ];
    is_environment_name(value)
        && !FORBIDDEN.contains(&value)
        && !value.starts_with("PI_")
        && (value.ends_with("_API_KEY") || value.ends_with("_AUTH_TOKEN"))
}

fn validate_bounded_text(id: &str, field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return invalid(format!(
            "Pi analyzer '{id}' {field} must contain 1 to 256 non-control characters without surrounding whitespace"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VocabularyConfig {
    pub classifications: Vec<String>,
    pub confidences: Vec<String>,
    pub reason_codes: Vec<String>,
}

impl VocabularyConfig {
    fn validate(&self, id: &str) -> Result<(), ConfigError> {
        for (name, values) in [
            ("classifications", &self.classifications),
            ("confidences", &self.confidences),
            ("reason_codes", &self.reason_codes),
        ] {
            if values.is_empty() {
                return invalid(format!(
                    "Pi analyzer '{id}' vocabulary.{name} must not be empty"
                ));
            }
            if values.len() > 256 {
                return invalid(format!(
                    "Pi analyzer '{id}' vocabulary.{name} must contain at most 256 values"
                ));
            }
            let mut seen = BTreeSet::new();
            for value in values {
                validate_id("vocabulary value", value)?;
                if !seen.insert(value) {
                    return invalid(format!(
                        "Pi analyzer '{id}' has duplicate vocabulary.{name} value '{value}'"
                    ));
                }
            }
        }
        if self
            .confidences
            .iter()
            .any(|value| !matches!(value.as_str(), "low" | "medium" | "high"))
        {
            return invalid(format!(
                "Pi analyzer '{id}' vocabulary.confidences may contain only low, medium, and high"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionConfig {
    #[serde(default = "default_include")]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_artifact_kinds")]
    pub artifact_kinds: Vec<ArtifactKindConfig>,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            include: default_include(),
            exclude: Vec::new(),
            artifact_kinds: default_artifact_kinds(),
        }
    }
}
fn default_include() -> Vec<String> {
    vec!["**".to_string()]
}
fn default_artifact_kinds() -> Vec<ArtifactKindConfig> {
    vec![ArtifactKindConfig::PhysicalFile]
}

impl SelectionConfig {
    fn validate(&self, id: &str) -> Result<(), ConfigError> {
        if self.include.is_empty() || self.artifact_kinds.is_empty() {
            return invalid(format!(
                "analyzer '{id}' selection include and artifact_kinds must not be empty"
            ));
        }
        for pattern in self.include.iter().chain(&self.exclude) {
            Glob::new(pattern).map_err(|error| {
                ConfigError::Invalid(format!(
                    "analyzer '{id}' has invalid selection glob '{pattern}': {error}"
                ))
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKindConfig {
    PhysicalFile,
    ArchiveMember,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerLimits {
    pub startup_timeout_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    pub wall_timeout_secs: Option<u64>,
    pub termination_grace_secs: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub cpu_time_secs: Option<u64>,
    pub max_open_files: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_stdout_bytes: Option<u64>,
    pub max_stderr_bytes: Option<u64>,
    pub max_output_bytes: Option<u64>,
    pub max_findings: Option<u64>,
    pub max_tool_calls: Option<u64>,
    pub max_bytes_read: Option<u64>,
    pub max_read_bytes_per_call: Option<u64>,
    pub max_search_calls: Option<u64>,
    pub max_search_query_bytes: Option<u64>,
    pub max_search_results: Option<u64>,
}

impl AnalyzerLimits {
    fn validate(&self, id: &str) -> Result<(), ConfigError> {
        if [
            self.startup_timeout_secs,
            self.idle_timeout_secs,
            self.wall_timeout_secs,
            self.termination_grace_secs,
            self.memory_bytes,
            self.cpu_time_secs,
            self.max_open_files,
            self.max_processes,
            self.max_stdout_bytes,
            self.max_stderr_bytes,
            self.max_output_bytes,
            self.max_findings,
            self.max_tool_calls,
            self.max_bytes_read,
            self.max_read_bytes_per_call,
            self.max_search_calls,
            self.max_search_query_bytes,
            self.max_search_results,
        ]
        .into_iter()
        .flatten()
        .any(|value| value == 0)
        {
            return invalid(format!("analyzer '{id}' limits must be greater than zero"));
        }
        Ok(())
    }

    fn validate_complete_pi(&self, id: &str) -> Result<(), ConfigError> {
        let missing = [
            ("startup_timeout_secs", self.startup_timeout_secs),
            ("idle_timeout_secs", self.idle_timeout_secs),
            ("wall_timeout_secs", self.wall_timeout_secs),
            ("termination_grace_secs", self.termination_grace_secs),
            ("memory_bytes", self.memory_bytes),
            ("cpu_time_secs", self.cpu_time_secs),
            ("max_open_files", self.max_open_files),
            ("max_processes", self.max_processes),
            ("max_stdout_bytes", self.max_stdout_bytes),
            ("max_stderr_bytes", self.max_stderr_bytes),
            ("max_output_bytes", self.max_output_bytes),
            ("max_findings", self.max_findings),
            ("max_tool_calls", self.max_tool_calls),
            ("max_bytes_read", self.max_bytes_read),
            ("max_read_bytes_per_call", self.max_read_bytes_per_call),
            ("max_search_calls", self.max_search_calls),
            ("max_search_query_bytes", self.max_search_query_bytes),
            ("max_search_results", self.max_search_results),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.is_none().then_some(name))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            return invalid(format!(
                "Pi analyzer '{id}' requires explicit limits: {}",
                missing.join(", ")
            ));
        }
        let wall = self.wall_timeout_secs.expect("checked above");
        if self.startup_timeout_secs.expect("checked above") > wall
            || self.idle_timeout_secs.expect("checked above") > wall
            || self.termination_grace_secs.expect("checked above") > wall
        {
            return invalid(format!(
                "Pi analyzer '{id}' startup, idle, and termination grace timeouts must not exceed wall_timeout_secs"
            ));
        }
        if self.max_read_bytes_per_call.expect("checked above")
            > self.max_bytes_read.expect("checked above")
        {
            return invalid(format!(
                "Pi analyzer '{id}' max_read_bytes_per_call must not exceed max_bytes_read"
            ));
        }
        let maximum_output = self.max_output_bytes.expect("checked above");
        let maximum_read = self.max_read_bytes_per_call.expect("checked above");
        let required_response = pi_encoded_response_upper_bound(maximum_read).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "Pi analyzer '{id}' max_read_bytes_per_call is too large to bound a base64 response"
            ))
        })?;
        if maximum_output < required_response {
            return invalid(format!(
                "Pi analyzer '{id}' max_output_bytes must be at least {required_response} to contain a base64 response for max_read_bytes_per_call"
            ));
        }
        const EXTENSION_MAX_PROXY_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
        if maximum_output > EXTENSION_MAX_PROXY_RESPONSE_BYTES {
            return invalid(format!(
                "Pi analyzer '{id}' max_output_bytes must not exceed the trusted extension limit of {EXTENSION_MAX_PROXY_RESPONSE_BYTES}"
            ));
        }
        Ok(())
    }
}

/// Base64 expands to four bytes per three input bytes. The fixed allowance
/// covers the versioned JSON response envelope and numeric metadata. This is
/// kept equal to the proxy's host-side reservation contract.
fn pi_encoded_response_upper_bound(raw_bytes: u64) -> Option<u64> {
    raw_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| value.checked_add(512))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBindingConfig {
    pub id: String,
    pub profile: String,
    pub analyzer: String,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub classification: Option<String>,
    pub directive: PolicyDirective,
}

impl PolicyBindingConfig {
    fn validate(
        &self,
        profiles: &BTreeMap<&str, usize>,
        analyzers: &BTreeMap<&str, usize>,
    ) -> Result<(), ConfigError> {
        validate_id("policy_bindings.id", &self.id)?;
        if !profiles.contains_key(self.profile.as_str()) {
            return invalid(format!(
                "policy binding '{}' references unknown profile '{}'",
                self.id, self.profile
            ));
        }
        if !analyzers.contains_key(self.analyzer.as_str()) {
            return invalid(format!(
                "policy binding '{}' references unknown analyzer '{}'",
                self.id, self.analyzer
            ));
        }
        if self.rule.is_some() == self.classification.is_some() {
            return invalid(format!(
                "policy binding '{}' must set exactly one of rule or classification",
                self.id
            ));
        }
        if let Some(value) = self.rule.as_deref().filter(|value| *value != "*") {
            validate_id("policy_bindings.rule", value)?;
        }
        if let Some(value) = &self.classification {
            validate_id("policy_bindings.classification", value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default)]
    pub jobs: Vec<DaemonJobConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonJobConfig {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(flatten)]
    pub kind: DaemonJobKind,
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonJobKind {
    PolicyScan {
        profile: String,
        target: DaemonTarget,
        every_secs: u64,
        #[serde(default)]
        run_on_start: bool,
    },
}

impl DaemonJobConfig {
    fn validate(&self, profiles: &BTreeMap<&str, usize>) -> Result<(), ConfigError> {
        validate_id("daemon.jobs.id", &self.id)?;
        match &self.kind {
            DaemonJobKind::PolicyScan {
                profile,
                target,
                every_secs,
                ..
            } => {
                if !profiles.contains_key(profile.as_str()) {
                    return invalid(format!(
                        "daemon job '{}' references unknown profile '{profile}'",
                        self.id
                    ));
                }
                if *every_secs == 0 {
                    return invalid(format!(
                        "daemon job '{}' every_secs must be greater than zero",
                        self.id
                    ));
                }
                target.validate(&self.id)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonTarget {
    Literal { path: PathBuf },
    Patterns { patterns: Vec<String> },
}

impl DaemonTarget {
    fn validate(&self, job: &str) -> Result<(), ConfigError> {
        match self {
            Self::Literal { path } => validate_absolute("daemon target", path),
            Self::Patterns { patterns } => {
                if patterns.is_empty() {
                    return invalid(format!("daemon job '{job}' patterns must not be empty"));
                }
                for pattern in patterns {
                    if !Path::new(pattern).is_absolute() {
                        return invalid(format!(
                            "daemon job '{job}' pattern must be absolute: {pattern}"
                        ));
                    }
                    glob::Pattern::new(pattern).map_err(|error| {
                        ConfigError::Invalid(format!(
                            "daemon job '{job}' has invalid target pattern '{pattern}': {error}"
                        ))
                    })?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub directory: Option<PathBuf>,
    #[serde(default = "default_logging_level")]
    pub level: String,
    #[serde(default = "default_logging_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_logging_max_files")]
    pub max_files: usize,
    #[serde(default = "default_logging_console")]
    pub console: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            directory: None,
            level: default_logging_level(),
            max_bytes: default_logging_max_bytes(),
            max_files: default_logging_max_files(),
            console: default_logging_console(),
        }
    }
}
fn default_logging_level() -> String {
    "info".to_string()
}
fn default_logging_max_bytes() -> u64 {
    104_857_600
}
fn default_logging_max_files() -> usize {
    5
}
fn default_logging_console() -> bool {
    true
}

fn unique_by<'a, T, F>(
    label: &str,
    values: &'a [T],
    key: F,
) -> Result<BTreeMap<&'a str, usize>, ConfigError>
where
    F: Fn(&'a T) -> &'a String,
{
    let mut found = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        let id = key(value);
        validate_id(label, id)?;
        if found.insert(id.as_str(), index).is_some() {
            return invalid(format!("duplicate {label} id '{id}'"));
        }
    }
    Ok(found)
}

fn validate_id(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return invalid(format!(
            "{field} must contain 1 to 128 safe identifier characters"
        ));
    }
    Ok(())
}

fn validate_absolute(field: &str, path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return invalid(format!("{field} must be an absolute path"));
    }
    Ok(())
}

fn validate_relative(field: &str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return invalid(format!("{field} must be a normalized relative path"));
    }
    Ok(())
}

fn validate_binding_ambiguity(bindings: &[PolicyBindingConfig]) -> Result<(), ConfigError> {
    let mut exact = BTreeSet::new();
    let mut wildcard = BTreeSet::new();
    let mut classification = BTreeSet::new();
    for binding in bindings {
        let group = (binding.profile.as_str(), binding.analyzer.as_str());
        if let Some(rule) = &binding.rule {
            if rule == "*" {
                if !wildcard.insert(group) {
                    return invalid(format!(
                        "multiple wildcard rule bindings exist for profile '{}' analyzer '{}'",
                        binding.profile, binding.analyzer
                    ));
                }
            } else if !exact.insert((group.0, group.1, rule.as_str())) {
                return invalid(format!(
                    "duplicate rule binding for profile '{}' analyzer '{}' rule '{}'",
                    binding.profile, binding.analyzer, rule
                ));
            }
        } else if let Some(code) = &binding.classification {
            if !classification.insert((group.0, group.1, code.as_str())) {
                return invalid(format!(
                    "duplicate classification binding for profile '{}' analyzer '{}' classification '{}'",
                    binding.profile, binding.analyzer, code
                ));
            }
        }
    }
    for (profile, analyzer, _) in exact {
        if wildcard.contains(&(profile, analyzer)) {
            return invalid(format!(
                "wildcard and exact rule bindings overlap for profile '{profile}' analyzer '{analyzer}'"
            ));
        }
    }
    Ok(())
}

fn validate_disjoint(
    left_name: &str,
    left: &Path,
    right_name: &str,
    right: &Path,
) -> Result<(), ConfigError> {
    if left.starts_with(right) || right.starts_with(left) {
        return invalid(format!("{left_name} and {right_name} must be disjoint"));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
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
rule_files = ["/etc/file-guardian/rules.d/publication.toml"]

[[policy_bindings]]
id = "blocked"
profile = "publication"
analyzer = "rules"
rule = "*"
directive = "deny"
"#;

    fn parse(value: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(value)
    }

    #[test]
    fn accepts_strict_minimal_v2() {
        let config = parse(MINIMAL).unwrap();
        config.validate().unwrap();
        let selected = config.validate_for_authorize(None).unwrap();
        assert_eq!(selected.pipeline.id, "publication");
    }

    #[test]
    fn rejects_v1_and_unknown_fields() {
        let v1 = MINIMAL.replacen("schema_version = \"2\"", "schema_version = \"1\"", 1);
        assert!(parse(&v1).unwrap().validate().is_err());
        assert!(parse(&MINIMAL.replace("root = \"/var", "legacy = true\nroot = \"/var")).is_err());
        let analyzer_unknown = MINIMAL.replace(
            "rule_files = [",
            "legacy_action = \"remove\"\nrule_files = [",
        );
        assert!(parse(&analyzer_unknown).is_err());
    }

    #[test]
    fn rejects_duplicate_and_dangling_references() {
        let duplicate = MINIMAL.replace(
            "[[pipelines]]",
            "[[pipelines]]\nid = \"publication\"\nstages = []\n\n[[pipelines]]",
        );
        assert!(parse(&duplicate).unwrap().validate().is_err());
        let dangling = MINIMAL.replace("analyzers = [\"rules\"]", "analyzers = [\"missing\"]");
        assert!(parse(&dangling).unwrap().validate().is_err());
    }

    #[test]
    fn config_path_precedence_is_cli_then_env_then_default() {
        let explicit = Path::new("/tmp/explicit.toml");
        assert_eq!(
            Config::resolve_path(Some(explicit)),
            (explicit.to_path_buf(), ConfigPathKind::Explicit)
        );
    }

    #[test]
    fn loaded_config_file_must_be_disjoint_from_workspace_root() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("runs");
        fs::create_dir(&workspace).unwrap();
        let config_path = workspace.join("config.toml");
        let source = MINIMAL.replace("/var/lib/file-guardian/runs", workspace.to_str().unwrap());
        fs::write(&config_path, source).unwrap();

        let error = Config::load_from_sources(Some(&config_path)).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Invalid(message)
                if message.contains("configuration source path")
        ));
    }

    #[test]
    fn loaded_config_file_outside_workspace_root_is_accepted() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("runs");
        fs::create_dir(&workspace).unwrap();
        let config_path = temporary.path().join("config.toml");
        let source = MINIMAL.replace("/var/lib/file-guardian/runs", workspace.to_str().unwrap());
        fs::write(&config_path, source).unwrap();

        Config::load_from_sources(Some(&config_path)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_symlink_located_in_workspace_is_rejected_even_when_target_is_outside() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("runs");
        fs::create_dir(&workspace).unwrap();
        let actual_config = temporary.path().join("config.toml");
        let source = MINIMAL.replace("/var/lib/file-guardian/runs", workspace.to_str().unwrap());
        fs::write(&actual_config, source).unwrap();
        let linked_config = workspace.join("config.toml");
        symlink(&actual_config, &linked_config).unwrap();

        let error = Config::load_from_sources(Some(&linked_config)).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Invalid(message) if message.contains("configuration source path")
        ));
    }

    #[test]
    fn daemon_selection_is_explicit_and_enabled_only() {
        let extra = r#"

[[daemon.jobs]]
id = "uploads"
kind = "policy_scan"
enabled = true
profile = "publication"
every_secs = 300
run_on_start = true

[daemon.jobs.target]
kind = "literal"
path = "/srv/uploads"
"#;
        let config = parse(&format!("{MINIMAL}{extra}")).unwrap();
        let jobs = config
            .validate_for_daemon(&["uploads".to_string()])
            .unwrap();
        assert_eq!(jobs[0].id, "uploads");
    }

    #[test]
    fn evaluate_can_downgrade_but_never_upgrade_authority() {
        let mut config = parse(MINIMAL).unwrap();
        config.authorization.profiles[0].action_mode = ActionMode::Apply;
        assert!(config.validate_for_authorize(None).is_err());
        assert_eq!(
            config
                .validate_for_authorize_mode(None, Some(ActionMode::Evaluate))
                .unwrap()
                .effective_mode,
            ActionMode::Evaluate
        );
        assert!(config
            .validate_for_authorize_mode(None, Some(ActionMode::Apply))
            .is_err());
        config.authorization.profiles[0].action_mode = ActionMode::Evaluate;
        assert!(config
            .validate_for_authorize_mode(None, Some(ActionMode::Apply))
            .is_err());
    }

    #[test]
    fn phase_three_accepts_parallel_execution_and_real_selectors() {
        let mut config = parse(MINIMAL).unwrap();
        config.pipelines[0].stages[0].execution = StageExecution::Parallel;
        config.pipelines[0].stages[0].max_concurrency = 2;
        config.pipelines[0].stages[0].prior_observations = PriorObservations::AllNormalized;
        config.analyzers[0]
            .selection
            .exclude
            .push("vendor/**".to_string());
        assert!(config.validate_for_authorize(None).is_ok());
    }

    #[test]
    fn authorize_selection_accepts_valid_external_analyzers_for_fail_closed_execution() {
        let mut config = parse(MINIMAL).unwrap();
        config.analyzers[0].kind = AnalyzerKind::ExternalTool {
            adapter: PathBuf::from("/usr/libexec/file-guardian/scanner"),
            args: Vec::new(),
            protocol: "file-guardian-delegate/1".to_string(),
            sandbox: "required".to_string(),
        };
        assert!(config.validate_for_authorize(None).is_ok());
    }

    #[test]
    fn rejects_zero_prior_projection_limits_and_unknown_projection_names() {
        let mut config = parse(MINIMAL).unwrap();
        config.pipelines[0].stages[0].prior_limits.max_observations = 0;
        assert!(config.validate().is_err());

        let invalid = MINIMAL.replace(
            "analyzers = [\"rules\"]",
            "analyzers = [\"rules\"]\nprior_observations = \"all_summary\"",
        );
        assert!(parse(&invalid).is_err());
    }

    #[test]
    fn rejects_ambiguous_bindings_and_non_normal_admin_paths() {
        let mut config = parse(MINIMAL).unwrap();
        config.policy_bindings.push(PolicyBindingConfig {
            id: "exact".to_string(),
            profile: "publication".to_string(),
            analyzer: "rules".to_string(),
            rule: Some("specific".to_string()),
            classification: None,
            directive: PolicyDirective::Deny,
        });
        assert!(config.validate().is_err());

        let mut config = parse(MINIMAL).unwrap();
        config.authorization.workspace.root = PathBuf::from("/var/lib/../runs");
        assert!(config.validate().is_err());
    }

    #[test]
    fn daemon_jobs_inherit_authorize_compatibility_checks() {
        let extra = r#"

[[daemon.jobs]]
id = "uploads"
kind = "policy_scan"
profile = "publication"
every_secs = 300

[daemon.jobs.target]
kind = "literal"
path = "/srv/uploads"
"#;
        let mut config = parse(&format!("{MINIMAL}{extra}")).unwrap();
        config.authorization.profiles[0].action_mode = ActionMode::Apply;
        assert!(config.validate_for_daemon(&[]).is_err());
    }

    #[test]
    fn checked_in_example_is_valid_strict_v2() {
        let config = parse(include_str!("../../config/config.toml")).unwrap();
        config.validate().unwrap();
    }

    fn pi_example() -> Config {
        parse(include_str!(
            "../../docs/examples/active-authorization-v2.toml"
        ))
        .unwrap()
    }

    #[test]
    fn accepts_strict_pi_contract_and_audit_only_bindings() {
        pi_example().validate().unwrap();
    }

    #[test]
    fn pi_requires_every_limit_and_exact_protocol_versions() {
        let mut config = pi_example();
        let pi = config
            .analyzers
            .iter_mut()
            .find(|analyzer| analyzer.id == "publication-llm")
            .unwrap();
        pi.limits.idle_timeout_secs = None;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("idle_timeout_secs"));

        let mut config = pi_example();
        let AnalyzerKind::PiClassifier { pi, .. } = &mut config
            .analyzers
            .iter_mut()
            .find(|analyzer| analyzer.id == "publication-llm")
            .unwrap()
            .kind
        else {
            panic!("expected Pi analyzer")
        };
        pi.output_schema = "untrusted/2".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn pi_output_budget_contains_maximum_base64_read_response() {
        let mut config = pi_example();
        let limits = &mut config
            .analyzers
            .iter_mut()
            .find(|analyzer| analyzer.id == "publication-llm")
            .unwrap()
            .limits;
        limits.max_output_bytes = Some(1024 * 1024);
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("max_output_bytes must be at least"));

        let mut config = pi_example();
        let limits = &mut config
            .analyzers
            .iter_mut()
            .find(|analyzer| analyzer.id == "publication-llm")
            .unwrap()
            .limits;
        limits.max_bytes_read = Some(u64::MAX);
        limits.max_read_bytes_per_call = Some(u64::MAX);
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("too large to bound a base64 response"));
    }

    #[test]
    fn pi_rejects_dangerous_credentials_and_non_audit_policy() {
        let mut config = pi_example();
        let AnalyzerKind::PiClassifier { pi, .. } = &mut config
            .analyzers
            .iter_mut()
            .find(|analyzer| analyzer.id == "publication-llm")
            .unwrap()
            .kind
        else {
            panic!("expected Pi analyzer")
        };
        pi.credentials[0].target_env = "NODE_OPTIONS".to_string();
        assert!(config.validate().is_err());

        let mut config = pi_example();
        config
            .policy_bindings
            .iter_mut()
            .find(|binding| binding.id == "llm-restricted-audit")
            .unwrap()
            .directive = PolicyDirective::Deny;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("must use directive = 'audit'"));
    }

    #[test]
    fn pi_requires_complete_vocabulary_binding_for_each_profile() {
        let mut config = pi_example();
        config
            .policy_bindings
            .retain(|binding| binding.id != "llm-uncertain-audit");
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("classification 'uncertain' explicitly to audit"));
    }

    #[test]
    fn pi_admin_paths_must_be_pairwise_disjoint() {
        let mut config = pi_example();
        let AnalyzerKind::PiClassifier { pi, .. } = &mut config
            .analyzers
            .iter_mut()
            .find(|analyzer| analyzer.id == "publication-llm")
            .unwrap()
            .kind
        else {
            panic!("expected Pi analyzer")
        };
        pi.trusted_extension = pi.runtime_root.join("extension.js");
        assert!(config.validate().is_err());
    }
}
