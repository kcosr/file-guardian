use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use glob::Pattern;
use regex::Regex;
use serde::Deserialize;

pub const RULE_FILE_SCHEMA_VERSION: &str = "file-guardian-rules/1";

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("failed to read rules file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse rules file {path}: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("invalid rules file {path}: {message}")]
    InvalidFile { path: PathBuf, message: String },

    #[error("duplicate rule id '{id}' across configured rule files")]
    DuplicateRule { id: String },
}

/// A deterministic, action-free rule ready for the built-in analyzer.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub filename_glob: Option<Pattern>,
    pub content_regex: Option<Regex>,
    pub source: RuleSource,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleSource {
    path: PathBuf,
}

impl RuleSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Display for RuleSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.path.display())
    }
}

impl CompiledRule {
    pub fn matches_filename(&self, filename: &str) -> bool {
        self.filename_glob
            .as_ref()
            .is_some_and(|pattern| pattern.matches(filename))
    }

    pub fn matches_content<'a>(&self, content: &'a str) -> Option<&'a str> {
        self.content_regex
            .as_ref()
            .and_then(|regex| regex.find(content).map(|matched| matched.as_str()))
    }

    pub fn requires_content_scan(&self) -> bool {
        self.content_regex.is_some()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    schema_version: String,
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDefinition {
    id: String,
    #[serde(default)]
    filename_glob: Option<String>,
    #[serde(default)]
    content_regex: Option<String>,
}

/// Loads rule files in configured order and rejects duplicate rule IDs across
/// the entire set. Files are explicit; directories are never discovered.
pub fn load_rule_files(paths: &[PathBuf]) -> Result<Vec<CompiledRule>, RulesError> {
    if paths.is_empty() {
        return Err(RulesError::InvalidFile {
            path: PathBuf::from("<configuration>"),
            message: "at least one rule file is required".to_string(),
        });
    }

    let mut seen = BTreeSet::new();
    let mut compiled = Vec::new();
    for path in paths {
        for rule in load_rule_file(path)? {
            if !seen.insert(rule.name.clone()) {
                return Err(RulesError::DuplicateRule {
                    id: rule.name.clone(),
                });
            }
            compiled.push(rule);
        }
    }
    Ok(compiled)
}

pub fn load_rule_file(path: &Path) -> Result<Vec<CompiledRule>, RulesError> {
    let raw = fs::read_to_string(path).map_err(|source| RulesError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let file: RuleFile = toml::from_str(&raw).map_err(|source| RulesError::ParseToml {
        path: path.to_path_buf(),
        source,
    })?;

    if file.schema_version != RULE_FILE_SCHEMA_VERSION {
        return Err(invalid(
            path,
            format!(
                "unsupported schema_version '{}'; expected '{RULE_FILE_SCHEMA_VERSION}'",
                file.schema_version
            ),
        ));
    }
    if file.rules.is_empty() {
        return Err(invalid(path, "rules must not be empty"));
    }

    let mut seen = BTreeSet::new();
    file.rules
        .into_iter()
        .map(|rule| {
            validate_rule_id(&rule.id).map_err(|message| invalid(path, message))?;
            if !seen.insert(rule.id.clone()) {
                return Err(invalid(path, format!("duplicate rule id '{}'", rule.id)));
            }
            if rule.filename_glob.is_none() && rule.content_regex.is_none() {
                return Err(invalid(
                    path,
                    format!(
                        "rule '{}' must define filename_glob, content_regex, or both",
                        rule.id
                    ),
                ));
            }

            let filename_glob = rule
                .filename_glob
                .map(|value| {
                    Pattern::new(&value).map_err(|source| {
                        invalid(
                            path,
                            format!("rule '{}' has invalid filename_glob: {source}", rule.id),
                        )
                    })
                })
                .transpose()?;
            let content_regex = rule
                .content_regex
                .map(|value| {
                    Regex::new(&value).map_err(|source| {
                        invalid(
                            path,
                            format!("rule '{}' has invalid content_regex: {source}", rule.id),
                        )
                    })
                })
                .transpose()?;

            Ok(CompiledRule {
                name: rule.id,
                filename_glob,
                content_regex,
                source: RuleSource::new(path),
            })
        })
        .collect()
}

fn validate_rule_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(format!(
            "rule id '{id}' must contain 1 to 128 safe identifier characters"
        ));
    }
    Ok(())
}

fn invalid(path: &Path, message: impl Into<String>) -> RulesError {
    RulesError::InvalidFile {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn rule_file(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn loads_strict_action_free_rules() {
        let file = rule_file(
            r#"
schema_version = "file-guardian-rules/1"

[[rules]]
id = "blocked-extension"
filename_glob = "*.blocked"

[[rules]]
id = "credential-assignment"
content_regex = "(?i)password\\s*="
"#,
        );

        let rules = load_rule_file(file.path()).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].matches_filename("payload.blocked"));
        assert_eq!(
            rules[1].matches_content("PASSWORD = value"),
            Some("PASSWORD =")
        );
        assert_eq!(rules[0].source.path(), file.path());
    }

    #[test]
    fn rejects_embedded_actions_as_unknown_fields() {
        let file = rule_file(
            r#"
schema_version = "file-guardian-rules/1"
[[rules]]
id = "legacy"
filename_glob = "*.exe"
action = "delete"
"#,
        );
        assert!(matches!(
            load_rule_file(file.path()),
            Err(RulesError::ParseToml { .. })
        ));
    }

    #[test]
    fn rejects_unknown_fields_at_file_level() {
        let file = rule_file(
            r#"
schema_version = "file-guardian-rules/1"
surprise = true
[[rules]]
id = "valid"
filename_glob = "*"
"#,
        );
        assert!(matches!(
            load_rule_file(file.path()),
            Err(RulesError::ParseToml { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_ids_across_files() {
        let first = rule_file(
            r#"
schema_version = "file-guardian-rules/1"
[[rules]]
id = "same"
filename_glob = "*"
"#,
        );
        let second = rule_file(
            r#"
schema_version = "file-guardian-rules/1"
[[rules]]
id = "same"
content_regex = "x"
"#,
        );

        let error = load_rule_files(&[first.path().to_path_buf(), second.path().to_path_buf()])
            .unwrap_err();
        assert!(matches!(error, RulesError::DuplicateRule { .. }));
    }

    #[test]
    fn rejects_wrong_schema_and_empty_matcher() {
        let wrong_schema = rule_file(
            r#"
schema_version = "1"
[[rules]]
id = "valid"
filename_glob = "*"
"#,
        );
        assert!(matches!(
            load_rule_file(wrong_schema.path()),
            Err(RulesError::InvalidFile { .. })
        ));

        let empty = rule_file(
            r#"
schema_version = "file-guardian-rules/1"
[[rules]]
id = "empty"
"#,
        );
        assert!(matches!(
            load_rule_file(empty.path()),
            Err(RulesError::InvalidFile { .. })
        ));
    }
}
