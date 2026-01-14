use std::fs;
use std::path::{Path, PathBuf};

use glob::Pattern;
use regex::Regex;

use crate::config::{InlineRule, PolicyAction, RulesConfig};

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("failed to read rules directory {path}: {source}")]
    ReadDir {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read rules file {path}: {source}")]
    ReadFile {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid rule in {path} at line {line}: {message}")]
    InvalidRule {
        path: std::path::PathBuf,
        line: usize,
        message: String,
    },

    #[error("invalid inline rule '{name}': {message}")]
    InvalidInlineRule { name: String, message: String },
}

/// A compiled rule ready for matching.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub filename_glob: Option<Pattern>,
    pub content_regex: Option<Regex>,
    pub action: Option<PolicyAction>,
    pub source: RuleSource,
}

#[derive(Debug, Clone)]
pub enum RuleSource {
    Inline,
    File(std::path::PathBuf),
}

impl std::fmt::Display for RuleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline => write!(f, "inline"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

impl CompiledRule {
    /// Check if a filename matches this rule's glob pattern.
    pub fn matches_filename(&self, filename: &str) -> bool {
        self.filename_glob
            .as_ref()
            .map(|p| p.matches(filename))
            .unwrap_or(false)
    }

    /// Check if content matches this rule's regex pattern.
    /// Returns the matched substring if found.
    pub fn matches_content<'a>(&self, content: &'a str) -> Option<&'a str> {
        self.content_regex
            .as_ref()
            .and_then(|r| r.find(content).map(|m| m.as_str()))
    }

    /// Check if this rule requires content scanning.
    pub fn requires_content_scan(&self) -> bool {
        self.content_regex.is_some()
    }
}

/// Load and compile all rules from config (inline + rules.d).
pub fn load_rules(config: &RulesConfig) -> Result<Vec<CompiledRule>, RulesError> {
    let mut rules = Vec::new();

    // Load inline rules from config
    for inline in &config.inline {
        let compiled = compile_inline_rule(inline)?;
        rules.push(compiled);
    }

    // Load rules from rules.d directory if configured
    if let Some(ref rules_d) = config.rules_d {
        if rules_d.exists() {
            let file_rules = load_rules_from_directory(rules_d)?;
            rules.extend(file_rules);
        }
    }

    Ok(rules)
}

fn compile_inline_rule(rule: &InlineRule) -> Result<CompiledRule, RulesError> {
    let filename_glob = rule
        .filename_glob
        .as_ref()
        .map(|p| Pattern::new(p))
        .transpose()
        .map_err(|e| RulesError::InvalidInlineRule {
            name: rule.name.clone(),
            message: format!("invalid filename_glob: {e}"),
        })?;

    let content_regex = rule
        .content_regex
        .as_ref()
        .map(|p| Regex::new(p))
        .transpose()
        .map_err(|e| RulesError::InvalidInlineRule {
            name: rule.name.clone(),
            message: format!("invalid content_regex: {e}"),
        })?;

    Ok(CompiledRule {
        name: rule.name.clone(),
        filename_glob,
        content_regex,
        action: rule.action,
        source: RuleSource::Inline,
    })
}

fn load_rules_from_directory(dir: &Path) -> Result<Vec<CompiledRule>, RulesError> {
    let mut rules = Vec::new();

    let entries = fs::read_dir(dir).map_err(|source| RulesError::ReadDir {
        path: dir.to_path_buf(),
        source,
    })?;

    let mut rule_files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| RulesError::ReadDir {
            path: dir.to_path_buf(),
            source,
        })?;

        let path = entry.path();
        if path.extension().map(|e| e == "rules").unwrap_or(false) {
            rule_files.push(path);
        }
    }

    rule_files.sort();
    for path in rule_files {
        let file_rules = load_rules_from_file(&path)?;
        rules.extend(file_rules);
    }

    Ok(rules)
}

/// Parse rules from a .rules file.
///
/// Format: one rule per line
///   - Lines starting with # are comments
///   - Empty lines are ignored
///   - Format: `name:type:pattern[:action]`
///     - type: `glob` (filename) or `regex` (content)
///     - action: optional, one of `warn`, `remove`, `replace`, `recover`
///
/// Examples:
///   no-exe:glob:*.exe:remove
///   no-passwords:regex:password\s*=\s*["'][^"']+["']:warn
///   no-secrets:glob:*.secret
fn load_rules_from_file(path: &Path) -> Result<Vec<CompiledRule>, RulesError> {
    let content = fs::read_to_string(path).map_err(|source| RulesError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    let mut rules = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let rule = parse_rule_line(path, line_num + 1, line)?;
        rules.push(rule);
    }

    Ok(rules)
}

fn parse_rule_line(path: &Path, line_num: usize, line: &str) -> Result<CompiledRule, RulesError> {
    let parts: Vec<&str> = line.splitn(4, ':').collect();

    if parts.len() < 3 {
        return Err(RulesError::InvalidRule {
            path: path.to_path_buf(),
            line: line_num,
            message: "expected format: name:type:pattern[:action]".to_string(),
        });
    }

    let name = parts[0].trim();
    let rule_type = parts[1].trim();
    let pattern = parts[2].trim();
    let action_str = parts.get(3).map(|s| s.trim());

    if name.is_empty() {
        return Err(RulesError::InvalidRule {
            path: path.to_path_buf(),
            line: line_num,
            message: "rule name cannot be empty".to_string(),
        });
    }

    if pattern.is_empty() {
        return Err(RulesError::InvalidRule {
            path: path.to_path_buf(),
            line: line_num,
            message: "pattern cannot be empty".to_string(),
        });
    }

    let (filename_glob, content_regex) = match rule_type {
        "glob" => {
            let glob = Pattern::new(pattern).map_err(|e| RulesError::InvalidRule {
                path: path.to_path_buf(),
                line: line_num,
                message: format!("invalid glob pattern: {e}"),
            })?;
            (Some(glob), None)
        }
        "regex" => {
            let regex = Regex::new(pattern).map_err(|e| RulesError::InvalidRule {
                path: path.to_path_buf(),
                line: line_num,
                message: format!("invalid regex pattern: {e}"),
            })?;
            (None, Some(regex))
        }
        _ => {
            return Err(RulesError::InvalidRule {
                path: path.to_path_buf(),
                line: line_num,
                message: format!("unknown rule type '{rule_type}', expected 'glob' or 'regex'"),
            });
        }
    };

    let action = if let Some(action_str) = action_str {
        Some(
            parse_action(action_str).map_err(|msg| RulesError::InvalidRule {
                path: path.to_path_buf(),
                line: line_num,
                message: msg,
            })?,
        )
    } else {
        None
    };

    Ok(CompiledRule {
        name: name.to_string(),
        filename_glob,
        content_regex,
        action,
        source: RuleSource::File(path.to_path_buf()),
    })
}

fn parse_action(s: &str) -> Result<PolicyAction, String> {
    match s.to_lowercase().as_str() {
        "warn" => Ok(PolicyAction::Warn),
        "remove" => Ok(PolicyAction::Remove),
        "replace" => Ok(PolicyAction::Replace),
        "recover" => Ok(PolicyAction::Recover),
        _ => Err(format!(
            "unknown action '{s}', expected: warn, remove, replace, recover"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_glob_rule() {
        let rule = parse_rule_line(Path::new("test.rules"), 1, "no-exe:glob:*.exe:remove").unwrap();
        assert_eq!(rule.name, "no-exe");
        assert!(rule.filename_glob.is_some());
        assert!(rule.content_regex.is_none());
        assert_eq!(rule.action, Some(PolicyAction::Remove));
    }

    #[test]
    fn parse_regex_rule() {
        let rule =
            parse_rule_line(Path::new("test.rules"), 1, "passwords:regex:password\\s*=").unwrap();
        assert_eq!(rule.name, "passwords");
        assert!(rule.filename_glob.is_none());
        assert!(rule.content_regex.is_some());
        assert!(rule.action.is_none());
    }

    #[test]
    fn parse_rule_without_action() {
        let rule = parse_rule_line(Path::new("test.rules"), 1, "secrets:glob:*.secret").unwrap();
        assert!(rule.action.is_none());
    }

    #[test]
    fn reject_invalid_format() {
        let result = parse_rule_line(Path::new("test.rules"), 1, "invalid");
        assert!(result.is_err());
    }

    #[test]
    fn reject_unknown_type() {
        let result = parse_rule_line(Path::new("test.rules"), 1, "rule:unknown:pattern");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown rule type"));
    }

    #[test]
    fn load_rules_file() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("test.rules");
        fs::write(
            &rules_file,
            r#"# Comment line
no-exe:glob:*.exe:remove
passwords:regex:password\s*=:warn

# Another comment
secrets:glob:*.secret
"#,
        )
        .unwrap();

        let rules = load_rules_from_file(&rules_file).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].name, "no-exe");
        assert_eq!(rules[1].name, "passwords");
        assert_eq!(rules[2].name, "secrets");
    }

    #[test]
    fn compiled_rule_matches_filename() {
        let rule = CompiledRule {
            name: "test".to_string(),
            filename_glob: Some(Pattern::new("*.exe").unwrap()),
            content_regex: None,
            action: None,
            source: RuleSource::Inline,
        };

        assert!(rule.matches_filename("virus.exe"));
        assert!(!rule.matches_filename("safe.txt"));
    }

    #[test]
    fn compiled_rule_matches_content() {
        let rule = CompiledRule {
            name: "test".to_string(),
            filename_glob: None,
            content_regex: Some(Regex::new(r"password\s*=").unwrap()),
            action: None,
            source: RuleSource::Inline,
        };

        assert!(rule.matches_content("password = secret").is_some());
        assert!(rule.matches_content("no secrets here").is_none());
    }

    #[test]
    fn load_rules_directory_sorted_by_path() {
        let dir = tempdir().unwrap();
        let b_path = dir.path().join("b.rules");
        let a_path = dir.path().join("a.rules");
        let ignore_path = dir.path().join("ignore.txt");

        fs::write(&b_path, "b-rule:glob:*.txt\n").unwrap();
        fs::write(&a_path, "a-rule:glob:*.txt\n").unwrap();
        fs::write(&ignore_path, "ignored").unwrap();

        let config = RulesConfig {
            rules_d: Some(dir.path().to_path_buf()),
            inline: Vec::new(),
        };

        let rules = load_rules(&config).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "a-rule");
        assert_eq!(rules[1].name, "b-rule");
    }
}
