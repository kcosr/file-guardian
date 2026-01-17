use std::collections::HashSet;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Local};
use glob::glob;

use crate::config::{Config, PolicyAction};
use crate::rules::CompiledRule;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("failed to expand glob pattern {pattern}: {source}")]
    GlobPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },

    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to get metadata for {path}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to remove file {path}: {source}")]
    RemoveFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to create recovery directory {path}: {source}")]
    CreateRecoveryDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to move file to recovery: {source}")]
    RecoverFile {
        #[source]
        source: std::io::Error,
    },
}

/// Information about a matched file violation.
#[derive(Debug, Clone)]
pub struct Violation {
    pub path: PathBuf,
    pub rule_name: String,
    pub match_type: MatchType,
    pub content_snippet: Option<String>,
    pub file_info: FileInfo,
    pub action: PolicyAction,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub enum MatchType {
    Filename,
    Content,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filename => write!(f, "filename"),
            Self::Content => write!(f, "content"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime: SystemTime,
}

impl FileInfo {
    fn from_metadata(meta: &Metadata) -> Self {
        Self {
            size: meta.len(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        }
    }

    pub fn mtime_string(&self) -> String {
        DateTime::<Local>::from(self.mtime)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    pub fn owner_string(&self) -> String {
        format!("{}:{}", self.uid, self.gid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DirKey {
    dev: u64,
    ino: u64,
}

impl DirKey {
    fn from_metadata(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// Scanner context holding configuration and rules.
pub struct Scanner {
    config: Config,
    rules: Vec<CompiledRule>,
    dry_run: bool,
    exclude_patterns: Vec<glob::Pattern>,
}

impl Scanner {
    pub fn new(config: Config, rules: Vec<CompiledRule>, dry_run: bool) -> Result<Self, ScanError> {
        let exclude_patterns: Result<Vec<_>, _> = config
            .scan
            .exclude_patterns
            .iter()
            .map(|p| {
                glob::Pattern::new(p).map_err(|source| ScanError::GlobPattern {
                    pattern: p.clone(),
                    source,
                })
            })
            .collect();

        Ok(Self {
            config,
            rules,
            dry_run,
            exclude_patterns: exclude_patterns?,
        })
    }

    /// Run a full scan and return all violations found.
    pub fn scan(&self) -> Vec<Result<Violation, ScanError>> {
        self.scan_with_handler(|_| {})
    }

    /// Run a full scan, invoking a handler as results are discovered.
    pub fn scan_with_handler<F>(&self, mut handler: F) -> Vec<Result<Violation, ScanError>>
    where
        F: FnMut(&Result<Violation, ScanError>),
    {
        let mut results = Vec::new();
        let mut visited_dirs = HashSet::new();

        for dir_pattern in &self.config.scan.directories {
            if let Err(err) =
                self.scan_glob_pattern(dir_pattern, &mut visited_dirs, &mut results, &mut handler)
            {
                let entry = Err(err);
                handler(&entry);
                results.push(entry);
            }
        }

        results
    }

    fn scan_glob_pattern<F>(
        &self,
        pattern: &str,
        visited_dirs: &mut HashSet<DirKey>,
        results: &mut Vec<Result<Violation, ScanError>>,
        handler: &mut F,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Result<Violation, ScanError>),
    {
        let paths = glob(pattern).map_err(|source| ScanError::GlobPattern {
            pattern: pattern.to_string(),
            source,
        })?;

        for entry in paths {
            match entry {
                Ok(path) => {
                    if self.is_excluded(&path) {
                        tracing::debug!("excluding path: {}", path.display());
                        continue;
                    }

                    if path.is_dir() {
                        if self.should_visit_dir(&path, visited_dirs) {
                            self.scan_directory(&path, visited_dirs, results, handler);
                        }
                    } else if path.is_file() {
                        self.scan_file(&path, results, handler);
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to access path in glob {pattern}: {e}");
                }
            }
        }

        Ok(())
    }

    fn scan_directory<F>(
        &self,
        dir: &Path,
        visited_dirs: &mut HashSet<DirKey>,
        results: &mut Vec<Result<Violation, ScanError>>,
        handler: &mut F,
    ) where
        F: FnMut(&Result<Violation, ScanError>),
    {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!("cannot read directory {}: {e}", dir.display());
                return;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("error reading entry in {}: {e}", dir.display());
                    continue;
                }
            };

            let path = entry.path();

            if self.is_excluded(&path) {
                tracing::debug!("excluding path: {}", path.display());
                continue;
            }

            if path.is_dir() {
                if self.should_visit_dir(&path, visited_dirs) {
                    self.scan_directory(&path, visited_dirs, results, handler);
                }
            } else if path.is_file() {
                self.scan_file(&path, results, handler);
            }
        }
    }

    fn scan_file<F>(
        &self,
        path: &Path,
        results: &mut Vec<Result<Violation, ScanError>>,
        handler: &mut F,
    ) where
        F: FnMut(&Result<Violation, ScanError>),
    {
        if self.is_excluded(path) {
            tracing::debug!("excluding path: {}", path.display());
            return;
        }

        // Get file metadata
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("cannot stat {}: {e}", path.display());
                return;
            }
        };

        // Skip if too large
        if meta.len() > self.config.scan.max_file_size {
            tracing::debug!(
                "skipping {} (size {} > max {})",
                path.display(),
                meta.len(),
                self.config.scan.max_file_size
            );
            return;
        }

        let file_info = FileInfo::from_metadata(&meta);
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let mut content: Option<String> = None;
        let mut content_unavailable = false;

        if let Some(marker) = self.replacement_marker() {
            if self.is_likely_binary(path) {
                content_unavailable = true;
            } else {
                match self.read_file_content(path) {
                    Ok(data) => {
                        if data == marker {
                            tracing::debug!("skipping replacement marker file: {}", path.display());
                            return;
                        }
                        content = Some(data);
                    }
                    Err(err) => {
                        tracing::debug!("cannot read {}: {err}", path.display());
                        content_unavailable = true;
                    }
                }
            }
        }

        for rule in &self.rules {
            if rule.matches_filename(filename) {
                let action = rule.action.unwrap_or(self.config.policy.default_action);
                let entry = Ok(Violation {
                    path: path.to_path_buf(),
                    rule_name: rule.name.clone(),
                    match_type: MatchType::Filename,
                    content_snippet: None,
                    file_info: file_info.clone(),
                    action,
                    dry_run: self.dry_run,
                });
                handler(&entry);
                results.push(entry);
                return;
            }

            if !rule.requires_content_scan() {
                continue;
            }

            if content_unavailable {
                continue;
            }

            if content.is_none() {
                if self.is_likely_binary(path) {
                    tracing::debug!("skipping binary file: {}", path.display());
                    content_unavailable = true;
                    continue;
                }

                match self.read_file_content(path) {
                    Ok(c) => content = Some(c),
                    Err(e) => {
                        tracing::debug!("cannot read {}: {e}", path.display());
                        content_unavailable = true;
                        continue;
                    }
                }
            }

            let content = match content.as_ref() {
                Some(content) => content,
                None => continue,
            };

            if let Some(matched) = rule.matches_content(content) {
                let action = rule.action.unwrap_or(self.config.policy.default_action);
                let snippet = truncate_snippet(matched, 100);
                let entry = Ok(Violation {
                    path: path.to_path_buf(),
                    rule_name: rule.name.clone(),
                    match_type: MatchType::Content,
                    content_snippet: Some(snippet),
                    file_info: file_info.clone(),
                    action,
                    dry_run: self.dry_run,
                });
                handler(&entry);
                results.push(entry);
                return;
            }
        }
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.exclude_patterns.iter().any(|p| {
            p.matches(&path_str)
                || p.matches(path.file_name().and_then(|n| n.to_str()).unwrap_or(""))
        })
    }

    fn is_likely_binary(&self, path: &Path) -> bool {
        // Check by reading first few bytes for null bytes
        let mut file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return true, // Assume binary if can't read
        };

        let mut buffer = [0u8; 8192];
        let bytes_read = match file.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => return true,
        };

        // Check for null bytes (common in binary files)
        buffer[..bytes_read].contains(&0)
    }

    fn should_visit_dir(&self, path: &Path, visited: &mut HashSet<DirKey>) -> bool {
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(err) => {
                tracing::warn!("cannot stat directory {}: {err}", path.display());
                return false;
            }
        };

        if !meta.is_dir() {
            return false;
        }

        let key = DirKey::from_metadata(&meta);
        if !visited.insert(key) {
            tracing::debug!("skipping already visited directory: {}", path.display());
            return false;
        }

        true
    }

    fn read_file_content(&self, path: &Path) -> Result<String, ScanError> {
        fs::read_to_string(path).map_err(|source| ScanError::ReadFile {
            path: path.to_path_buf(),
            source,
        })
    }

    fn replacement_marker(&self) -> Option<&str> {
        if !self.config.policy.replacement.enabled {
            return None;
        }

        if let Some(ref marker) = self.config.policy.replacement.marker {
            Some(marker.as_str())
        } else {
            Some(self.config.policy.replacement.content.as_str())
        }
    }

    fn should_apply_replacement(&self, violation: &Violation) -> bool {
        if !self.config.policy.replacement.enabled {
            return false;
        }

        if !matches!(
            violation.action,
            PolicyAction::Remove | PolicyAction::Recover
        ) {
            return false;
        }

        if self.is_likely_binary(&violation.path) {
            return false;
        }

        true
    }

    fn write_replacement(&self, path: &Path) -> Result<(), ScanError> {
        fs::write(path, &self.config.policy.replacement.content).map_err(|source| {
            ScanError::WriteFile {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    /// Execute the action for a violation.
    pub fn execute_action(&self, violation: &Violation) -> Result<(), ScanError> {
        if self.dry_run {
            tracing::info!(
                "[DRY-RUN] would execute action '{}' on {}",
                violation.action,
                violation.path.display()
            );
            return Ok(());
        }

        let should_replace = self.should_apply_replacement(violation);

        match violation.action {
            PolicyAction::Warn => {
                // No action needed, just logging
                Ok(())
            }
            PolicyAction::Remove => {
                tracing::info!("removing file: {}", violation.path.display());
                fs::remove_file(&violation.path).map_err(|source| ScanError::RemoveFile {
                    path: violation.path.clone(),
                    source,
                })?;

                if should_replace {
                    self.write_replacement(&violation.path)?;
                }

                Ok(())
            }
            PolicyAction::Recover => {
                self.recover_file(&violation.path)?;

                if should_replace {
                    self.write_replacement(&violation.path)?;
                }

                Ok(())
            }
        }
    }

    fn recover_file(&self, path: &Path) -> Result<(), ScanError> {
        let timestamp = Local::now().format("%Y-%m-%dT%H-%M-%S").to_string();
        let recovery_dir = self.config.policy.recovery_dir.join(&timestamp);

        // Create timestamped recovery directory
        fs::create_dir_all(&recovery_dir).map_err(|source| ScanError::CreateRecoveryDir {
            path: recovery_dir.clone(),
            source,
        })?;

        // Convert path to safe filename: /home/kevin/file.txt -> --home--kevin--file.txt
        let encoded_name = encode_path_as_filename(path);
        let dest = recovery_dir.join(&encoded_name);

        tracing::info!("recovering file {} to {}", path.display(), dest.display());

        match fs::rename(path, &dest) {
            Ok(()) => Ok(()),
            Err(err) if is_cross_device_error(&err) => {
                fs::copy(path, &dest).map_err(|source| ScanError::RecoverFile { source })?;
                fs::remove_file(path).map_err(|source| ScanError::RecoverFile { source })?;
                Ok(())
            }
            Err(err) => Err(ScanError::RecoverFile { source: err }),
        }
    }
}

/// Encode a file path as a safe filename.
/// /home/kevin/sensitive.txt -> --home--kevin--sensitive.txt
fn encode_path_as_filename(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    path_str.replace('/', "--")
}

/// Truncate a string snippet for logging.
fn truncate_snippet(s: &str, max_len: usize) -> String {
    let mut iter = s.chars();
    let truncated: String = iter.by_ref().take(max_len).collect();
    if iter.next().is_none() {
        truncated
    } else {
        format!("{truncated}...")
    }
}

fn is_cross_device_error(err: &io::Error) -> bool {
    const EXDEV: i32 = 18; // POSIX EXDEV
    err.raw_os_error() == Some(EXDEV)
}

/// Format a violation for logging.
pub fn format_violation(v: &Violation) -> String {
    let mut parts = vec![
        format!("path={}", v.path.display()),
        format!("rule={}", v.rule_name),
        format!("match={}", v.match_type),
        format!("action={}", v.action),
        format!("owner={}", v.file_info.owner_string()),
        format!("size={}", v.file_info.size),
        format!("mtime={}", v.file_info.mtime_string()),
    ];

    if let Some(ref snippet) = v.content_snippet {
        // Escape for logging
        let escaped = snippet.replace('\n', "\\n").replace('\r', "\\r");
        parts.push(format!("snippet=\"{}\"", escaped));
    }

    if v.dry_run {
        parts.push("dry_run=true".to_string());
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, LoggingConfig, PolicyConfig, RulesConfig, ScanConfig};
    use crate::rules::{CompiledRule, RuleSource};
    use glob::Pattern;
    use regex::Regex;
    use std::fs;
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn encode_path_as_filename_works() {
        assert_eq!(
            encode_path_as_filename(Path::new("/home/kevin/sensitive.txt")),
            "--home--kevin--sensitive.txt"
        );
        assert_eq!(
            encode_path_as_filename(Path::new("/var/log/app.log")),
            "--var--log--app.log"
        );
    }

    #[test]
    fn truncate_snippet_short() {
        assert_eq!(truncate_snippet("short", 100), "short");
    }

    #[test]
    fn truncate_snippet_long() {
        let long = "a".repeat(150);
        let truncated = truncate_snippet(&long, 100);
        assert_eq!(truncated.len(), 103); // 100 + "..."
        assert!(truncated.ends_with("..."));
    }

    fn base_config(root: &Path) -> Config {
        let scan = ScanConfig {
            directories: vec![format!("{}/{}", root.display(), "*")],
            ..ScanConfig::default()
        };

        Config {
            schema_version: "1".to_string(),
            scan,
            policy: PolicyConfig::default(),
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
        }
    }

    fn base_config_with_recovery(root: &Path, recovery_dir: &Path) -> Config {
        let mut config = base_config(root);
        config.policy.recovery_dir = recovery_dir.to_path_buf();
        config
    }

    #[test]
    fn scanner_first_match_rule_order() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("target.txt");
        fs::write(&file_path, "password = \"secret\"").unwrap();

        let config = base_config(dir.path());
        let rules = vec![
            CompiledRule {
                name: "content-first".to_string(),
                filename_glob: None,
                content_regex: Some(Regex::new("password").unwrap()),
                action: Some(PolicyAction::Warn),
                source: RuleSource::Inline,
            },
            CompiledRule {
                name: "filename-second".to_string(),
                filename_glob: Some(Pattern::new("*.txt").unwrap()),
                content_regex: None,
                action: Some(PolicyAction::Remove),
                source: RuleSource::Inline,
            },
        ];

        let scanner = Scanner::new(config, rules, true).unwrap();
        let results = scanner.scan();
        assert_eq!(results.len(), 1);

        let violation = results[0].as_ref().expect("violation");
        assert_eq!(violation.rule_name, "content-first");
        assert!(matches!(violation.match_type, MatchType::Content));
    }

    #[test]
    fn scanner_excludes_paths() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("skip.txt"), "skip").unwrap();
        fs::write(dir.path().join("keep.txt"), "keep").unwrap();

        let mut config = base_config(dir.path());
        config.scan.exclude_patterns = vec!["skip.txt".to_string()];

        let rules = vec![CompiledRule {
            name: "all-txt".to_string(),
            filename_glob: Some(Pattern::new("*.txt").unwrap()),
            content_regex: None,
            action: Some(PolicyAction::Warn),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config, rules, true).unwrap();
        let results = scanner.scan();
        assert_eq!(results.len(), 1);

        let violation = results[0].as_ref().expect("violation");
        assert_eq!(
            violation.path.file_name().unwrap().to_str().unwrap(),
            "keep.txt"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scanner_handles_symlink_loops() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        let loop_dir = root.join("loop");
        fs::create_dir_all(&loop_dir).unwrap();

        fs::write(loop_dir.join("target.txt"), "data").unwrap();
        symlink(&loop_dir, loop_dir.join("again")).unwrap();

        let config = base_config(&root);
        let rules = vec![CompiledRule {
            name: "all-txt".to_string(),
            filename_glob: Some(Pattern::new("*.txt").unwrap()),
            content_regex: None,
            action: Some(PolicyAction::Warn),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config, rules, true).unwrap();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let results = scanner.scan();
            let _ = tx.send(results.len());
        });

        let count = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("scan timed out");
        assert_eq!(count, 1);
    }

    #[test]
    fn execute_action_remove_deletes_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("remove.txt");
        fs::write(&file_path, "remove").unwrap();

        let config = base_config(dir.path());
        let scanner = Scanner::new(config, Vec::new(), false).unwrap();
        let meta = fs::metadata(&file_path).unwrap();
        let violation = Violation {
            path: file_path.clone(),
            rule_name: "remove".to_string(),
            match_type: MatchType::Filename,
            content_snippet: None,
            file_info: FileInfo::from_metadata(&meta),
            action: PolicyAction::Remove,
            dry_run: false,
        };

        scanner.execute_action(&violation).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn execute_action_recover_moves_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("recover.txt");
        fs::write(&file_path, "recover").unwrap();

        let recovery_dir = dir.path().join("recovered");
        let config = base_config_with_recovery(dir.path(), &recovery_dir);
        let scanner = Scanner::new(config, Vec::new(), false).unwrap();
        let meta = fs::metadata(&file_path).unwrap();
        let violation = Violation {
            path: file_path.clone(),
            rule_name: "recover".to_string(),
            match_type: MatchType::Filename,
            content_snippet: None,
            file_info: FileInfo::from_metadata(&meta),
            action: PolicyAction::Recover,
            dry_run: false,
        };

        scanner.execute_action(&violation).unwrap();
        assert!(!file_path.exists());

        let dirs: Vec<_> = fs::read_dir(&recovery_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(dirs.len(), 1);

        let recovered_dir = dirs[0].path();
        let encoded = file_path.to_string_lossy().replace('/', "--");
        let recovered_path = recovered_dir.join(encoded);
        assert!(recovered_path.exists());
        let content = fs::read_to_string(recovered_path).unwrap();
        assert_eq!(content, "recover");
    }

    #[test]
    fn execute_action_remove_writes_replacement_when_enabled() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("replace.txt");
        fs::write(&file_path, "old").unwrap();

        let mut config = base_config(dir.path());
        config.policy.replacement.enabled = true;
        config.policy.replacement.content = "new".to_string();

        let scanner = Scanner::new(config, Vec::new(), false).unwrap();
        let meta = fs::metadata(&file_path).unwrap();
        let violation = Violation {
            path: file_path.clone(),
            rule_name: "remove".to_string(),
            match_type: MatchType::Filename,
            content_snippet: None,
            file_info: FileInfo::from_metadata(&meta),
            action: PolicyAction::Remove,
            dry_run: false,
        };

        scanner.execute_action(&violation).unwrap();
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "new");
    }

    #[test]
    fn execute_action_recover_writes_replacement_when_enabled() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("recover.txt");
        fs::write(&file_path, "recover").unwrap();

        let recovery_dir = dir.path().join("recovered");
        let mut config = base_config_with_recovery(dir.path(), &recovery_dir);
        config.policy.replacement.enabled = true;
        config.policy.replacement.content = "stub".to_string();

        let scanner = Scanner::new(config, Vec::new(), false).unwrap();
        let meta = fs::metadata(&file_path).unwrap();
        let violation = Violation {
            path: file_path.clone(),
            rule_name: "recover".to_string(),
            match_type: MatchType::Filename,
            content_snippet: None,
            file_info: FileInfo::from_metadata(&meta),
            action: PolicyAction::Recover,
            dry_run: false,
        };

        scanner.execute_action(&violation).unwrap();
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "stub");

        let dirs: Vec<_> = fs::read_dir(&recovery_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(dirs.len(), 1);

        let recovered_dir = dirs[0].path();
        let encoded = file_path.to_string_lossy().replace('/', "--");
        let recovered_path = recovered_dir.join(encoded);
        assert!(recovered_path.exists());
        let recovered_content = fs::read_to_string(recovered_path).unwrap();
        assert_eq!(recovered_content, "recover");
    }

    #[test]
    fn execute_action_warn_skips_replacement() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("warn.txt");
        fs::write(&file_path, "keep").unwrap();

        let mut config = base_config(dir.path());
        config.policy.replacement.enabled = true;
        config.policy.replacement.content = "stub".to_string();

        let scanner = Scanner::new(config, Vec::new(), false).unwrap();
        let meta = fs::metadata(&file_path).unwrap();
        let violation = Violation {
            path: file_path.clone(),
            rule_name: "warn".to_string(),
            match_type: MatchType::Filename,
            content_snippet: None,
            file_info: FileInfo::from_metadata(&meta),
            action: PolicyAction::Warn,
            dry_run: false,
        };

        scanner.execute_action(&violation).unwrap();
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "keep");
    }

    #[test]
    fn scanner_skips_replacement_marker() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("marker.txt");
        fs::write(&file_path, "marker").unwrap();

        let mut config = base_config(dir.path());
        config.policy.replacement.enabled = true;
        config.policy.replacement.content = "replacement".to_string();
        config.policy.replacement.marker = Some("marker".to_string());

        let rules = vec![CompiledRule {
            name: "all-txt".to_string(),
            filename_glob: Some(Pattern::new("*.txt").unwrap()),
            content_regex: None,
            action: Some(PolicyAction::Remove),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config, rules, true).unwrap();
        let results = scanner.scan();
        assert!(results.is_empty());
    }

    #[test]
    fn scanner_does_not_skip_binary_files_for_replacement_marker() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("marker.bin");
        fs::write(&file_path, b"\0marker").unwrap();

        let mut config = base_config(dir.path());
        config.policy.replacement.enabled = true;
        config.policy.replacement.content = "marker".to_string();

        let rules = vec![CompiledRule {
            name: "all-bin".to_string(),
            filename_glob: Some(Pattern::new("*.bin").unwrap()),
            content_regex: None,
            action: Some(PolicyAction::Warn),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config, rules, true).unwrap();
        let results = scanner.scan();
        assert_eq!(results.len(), 1);
    }
}
