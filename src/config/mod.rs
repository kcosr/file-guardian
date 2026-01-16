use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logging::LoggingSettings;

const DEFAULT_CONFIG_PATH: &str = "/etc/file-guardian/config.toml";
const DEFAULT_SCHEMA_VERSION: &str = "1";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub rules: RulesConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load_from_sources(cli_path: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, _kind) = Self::resolve_path(cli_path);
        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;

        let mut config: Config = toml::from_str(&raw).map_err(|source| ConfigError::ParseToml {
            path: path.clone(),
            source,
        })?;

        config.apply_env_overrides();
        config.validate()?;

        Ok(config)
    }

    pub fn resolve_path(cli_path: Option<&Path>) -> (PathBuf, ConfigPathKind) {
        if let Some(p) = cli_path {
            (p.to_path_buf(), ConfigPathKind::Explicit)
        } else if let Ok(env_path) = env::var("FILE_GUARDIAN_CONFIG") {
            (PathBuf::from(env_path), ConfigPathKind::Env)
        } else {
            (PathBuf::from(DEFAULT_CONFIG_PATH), ConfigPathKind::Default)
        }
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(level) = env::var("FILE_GUARDIAN_LOG_LEVEL") {
            if !level.trim().is_empty() {
                self.logging.level = level;
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != DEFAULT_SCHEMA_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported schema_version {}, expected {}",
                self.schema_version, DEFAULT_SCHEMA_VERSION
            )));
        }

        if self.scan.directories.is_empty() {
            return Err(ConfigError::Invalid(
                "scan.directories must contain at least one glob pattern".to_string(),
            ));
        }

        if self.scan.interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "scan.interval_secs must be greater than zero".to_string(),
            ));
        }

        if !self.policy.recovery_dir.is_absolute() {
            return Err(ConfigError::Invalid(
                "policy.recovery_dir must be an absolute path".to_string(),
            ));
        }

        if self.scan.write_summaries && !self.scan.summary_dir.is_absolute() {
            return Err(ConfigError::Invalid(
                "scan.summary_dir must be an absolute path".to_string(),
            ));
        }

        if let Some(ref rules_d) = self.rules.rules_d {
            if !rules_d.is_absolute() {
                return Err(ConfigError::Invalid(
                    "rules.rules_d must be an absolute path".to_string(),
                ));
            }
        }

        for (i, rule) in self.rules.inline.iter().enumerate() {
            rule.validate()
                .map_err(|e| ConfigError::Invalid(format!("rules.inline[{i}]: {e}")))?;
        }

        if let Err(err) = LoggingSettings::from_config(&self.logging) {
            return Err(ConfigError::Invalid(format!("{err}")));
        }

        Ok(())
    }
}

fn default_schema_version() -> String {
    DEFAULT_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SummaryLayout {
    #[default]
    Flat,
    Daily,
    Hourly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_directories")]
    pub directories: Vec<String>,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    #[serde(default = "default_summary_dir", alias = "results_dir")]
    pub summary_dir: PathBuf,

    #[serde(default = "default_summary_layout")]
    pub summary_layout: SummaryLayout,

    #[serde(default = "default_write_summaries")]
    pub write_summaries: bool,

    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            directories: default_directories(),
            interval_secs: default_interval_secs(),
            max_file_size: default_max_file_size(),
            summary_dir: default_summary_dir(),
            summary_layout: default_summary_layout(),
            write_summaries: default_write_summaries(),
            exclude_patterns: Vec::new(),
        }
    }
}

fn default_directories() -> Vec<String> {
    vec!["/home/*".to_string()]
}

fn default_interval_secs() -> u64 {
    3600
}

fn default_max_file_size() -> u64 {
    10 * 1024 * 1024 // 10 MiB
}

fn default_summary_dir() -> PathBuf {
    PathBuf::from("/var/log/file-guardian/summaries")
}

fn default_summary_layout() -> SummaryLayout {
    SummaryLayout::Flat
}

fn default_write_summaries() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    #[default]
    Warn,
    Remove,
    Recover,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warn => write!(f, "warn"),
            Self::Remove => write!(f, "remove"),
            Self::Recover => write!(f, "recover"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacementConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_replacement_content")]
    pub content: String,

    #[serde(default)]
    pub marker: Option<String>,
}

impl Default for ReplacementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            content: default_replacement_content(),
            marker: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub default_action: PolicyAction,

    #[serde(default = "default_recovery_dir")]
    pub recovery_dir: PathBuf,

    #[serde(default)]
    pub replacement: ReplacementConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::default(),
            recovery_dir: default_recovery_dir(),
            replacement: ReplacementConfig::default(),
        }
    }
}

fn default_recovery_dir() -> PathBuf {
    PathBuf::from("/var/lib/file-guardian/recovered")
}

fn default_replacement_content() -> String {
    "This file has been removed by file-guardian due to policy violation.\n".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub rules_d: Option<PathBuf>,

    #[serde(default)]
    pub inline: Vec<InlineRule>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            rules_d: Some(PathBuf::from("/etc/file-guardian/rules.d")),
            inline: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineRule {
    pub name: String,

    #[serde(default)]
    pub filename_glob: Option<String>,

    #[serde(default)]
    pub content_regex: Option<String>,

    #[serde(default)]
    pub action: Option<PolicyAction>,
}

impl InlineRule {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("rule name must not be empty".to_string());
        }

        if self.filename_glob.is_none() && self.content_regex.is_none() {
            return Err(format!(
                "rule '{}' must have at least filename_glob or content_regex",
                self.name
            ));
        }

        if let Some(ref pattern) = self.filename_glob {
            glob::Pattern::new(pattern)
                .map_err(|e| format!("rule '{}' has invalid filename_glob: {e}", self.name))?;
        }

        if let Some(ref pattern) = self.content_regex {
            regex::Regex::new(pattern)
                .map_err(|e| format!("rule '{}' has invalid content_regex: {e}", self.name))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        Config {
            schema_version: DEFAULT_SCHEMA_VERSION.to_string(),
            scan: ScanConfig::default(),
            policy: PolicyConfig::default(),
            rules: RulesConfig {
                rules_d: None,
                inline: vec![InlineRule {
                    name: "test".to_string(),
                    filename_glob: Some("*.exe".to_string()),
                    content_regex: None,
                    action: None,
                }],
            },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn validate_accepts_minimal_config() {
        let config = minimal_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_schema_version() {
        let mut config = minimal_config();
        config.schema_version = "999".to_string();
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn validate_rejects_empty_directories() {
        let mut config = minimal_config();
        config.scan.directories.clear();
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("directories"));
    }

    #[test]
    fn validate_rejects_zero_interval() {
        let mut config = minimal_config();
        config.scan.interval_secs = 0;
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("interval_secs"));
    }

    #[test]
    fn validate_rejects_relative_recovery_dir() {
        let mut config = minimal_config();
        config.policy.recovery_dir = PathBuf::from("relative/path");
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("recovery_dir"));
    }

    #[test]
    fn validate_rejects_relative_summary_dir() {
        let mut config = minimal_config();
        config.scan.summary_dir = PathBuf::from("relative/path");
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("summary_dir"));
    }

    #[test]
    fn inline_rule_requires_pattern() {
        let rule = InlineRule {
            name: "empty".to_string(),
            filename_glob: None,
            content_regex: None,
            action: None,
        };
        let err = rule.validate().expect_err("should fail");
        assert!(err.contains("filename_glob or content_regex"));
    }

    #[test]
    fn inline_rule_validates_glob() {
        let rule = InlineRule {
            name: "bad-glob".to_string(),
            filename_glob: Some("[invalid".to_string()),
            content_regex: None,
            action: None,
        };
        let err = rule.validate().expect_err("should fail");
        assert!(err.contains("filename_glob"));
    }

    #[test]
    fn inline_rule_validates_regex() {
        let rule = InlineRule {
            name: "bad-regex".to_string(),
            filename_glob: None,
            content_regex: Some("(unclosed".to_string()),
            action: None,
        };
        let err = rule.validate().expect_err("should fail");
        assert!(err.contains("content_regex"));
    }
}
