use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use chrono::Local;
use clap::Parser;
use serde::Serialize;
use tokio::signal;
use tokio::time;

use file_guardian::config::Config;
use file_guardian::logging::LoggingSettings;
use file_guardian::rules::load_rules;
use file_guardian::scanner::{format_violation, ScanError, Scanner, Violation};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Scans directories for disallowed files based on rules"
)]
struct Args {
    /// Path to configuration file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once and exit (don't loop)
    #[arg(long)]
    once: bool,

    /// Dry-run mode: log violations but don't modify files
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Load configuration
    let config = match Config::load_from_sources(args.config.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to load config: {err}");
            return ExitCode::from(1);
        }
    };

    // Initialize logging
    let logging_settings = match LoggingSettings::from_config(&config.logging) {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("failed to validate logging config: {err}");
            return ExitCode::from(1);
        }
    };

    let _guards = match logging_settings.init_tracing() {
        Ok(guards) => guards,
        Err(err) => {
            eprintln!("failed to init logging: {err}");
            return ExitCode::from(1);
        }
    };

    tracing::info!("file-guardian starting");

    if args.dry_run {
        tracing::info!("running in dry-run mode - no files will be modified");
    }

    // Load rules
    let rules = match load_rules(&config.rules) {
        Ok(rules) => rules,
        Err(err) => {
            tracing::error!("failed to load rules: {err}");
            return ExitCode::from(1);
        }
    };

    tracing::info!("loaded {} rules", rules.len());
    for rule in &rules {
        tracing::debug!(
            "rule: name={} glob={:?} regex={} source={}",
            rule.name,
            rule.filename_glob.as_ref().map(|p| p.as_str()),
            rule.content_regex.is_some(),
            rule.source
        );
    }

    if rules.is_empty() {
        tracing::warn!("no rules configured - nothing to scan for");
    }

    // Create scanner
    let scanner = match Scanner::new(config.clone(), rules, args.dry_run) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!("failed to create scanner: {err}");
            return ExitCode::from(1);
        }
    };

    if args.once {
        // Single scan mode
        run_scan(&scanner, &config);
        tracing::info!("file-guardian scan complete");
    } else {
        // Periodic scan mode
        let interval = Duration::from_secs(config.scan.interval_secs);
        tracing::info!("scanning every {} seconds", config.scan.interval_secs);

        // Run initial scan
        run_scan(&scanner, &config);

        // Set up periodic scanning with graceful shutdown
        let mut interval_timer = time::interval(interval);
        interval_timer.tick().await; // Skip the first immediate tick (we just ran a scan)

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    run_scan(&scanner, &config);
                }
                _ = signal::ctrl_c() => {
                    tracing::info!("received shutdown signal");
                    break;
                }
            }
        }

        tracing::info!("file-guardian shutting down");
    }

    ExitCode::SUCCESS
}

fn run_scan(scanner: &Scanner, config: &Config) {
    tracing::info!("starting scan");

    let started_at = Local::now();
    let run_id = started_at.format("%Y-%m-%dT%H-%M-%S").to_string();
    let started = Instant::now();
    let mut action_errors = HashMap::new();

    let results = scanner.scan_with_handler(|result| match result {
        Ok(violation) => {
            tracing::warn!("violation: {}", format_violation(violation));

            if let Err(err) = scanner.execute_action(violation) {
                tracing::error!(
                    "failed to execute action {} on {}: {err}",
                    violation.action,
                    violation.path.display()
                );
                action_errors.insert(violation.path.clone(), err.to_string());
            }
        }
        Err(err) => {
            tracing::error!("scan error: {err}");
        }
    });

    let finished_at = Local::now();
    let duration_ms = started.elapsed().as_millis() as u64;
    let summary = build_summary(
        &run_id,
        started_at,
        finished_at,
        duration_ms,
        &results,
        &action_errors,
    );

    if config.scan.write_summaries {
        match write_summary(config, &run_id, &summary) {
            Ok(path) => {
                tracing::info!("wrote scan summary to {}", path.display());
            }
            Err(err) => {
                tracing::error!("failed to write scan summary: {err}");
            }
        }
    }

    let error_count = summary.scan_error_count + summary.action_error_count;
    tracing::info!(
        "scan complete: {} violations found, {} errors",
        summary.violation_count,
        error_count
    );
}

#[derive(Debug, Serialize)]
struct ScanSummary {
    run_id: String,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
    violation_count: usize,
    scan_error_count: usize,
    action_error_count: usize,
    violations: Vec<ViolationSummary>,
    scan_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ViolationSummary {
    path: String,
    rule: String,
    match_type: String,
    action: String,
    owner: String,
    size: u64,
    mtime: String,
    snippet: Option<String>,
    dry_run: bool,
    action_error: Option<String>,
}

impl ViolationSummary {
    fn from_violation(violation: &Violation, action_error: Option<&String>) -> Self {
        Self {
            path: violation.path.display().to_string(),
            rule: violation.rule_name.clone(),
            match_type: violation.match_type.to_string(),
            action: violation.action.to_string(),
            owner: violation.file_info.owner_string(),
            size: violation.file_info.size,
            mtime: violation.file_info.mtime_string(),
            snippet: violation.content_snippet.clone(),
            dry_run: violation.dry_run,
            action_error: action_error.cloned(),
        }
    }
}

fn build_summary(
    run_id: &str,
    started_at: chrono::DateTime<chrono::Local>,
    finished_at: chrono::DateTime<chrono::Local>,
    duration_ms: u64,
    results: &[Result<Violation, ScanError>],
    action_errors: &HashMap<PathBuf, String>,
) -> ScanSummary {
    let violations: Vec<ViolationSummary> = results
        .iter()
        .filter_map(|result| {
            result.as_ref().ok().map(|violation| {
                let action_error = action_errors.get(&violation.path);
                ViolationSummary::from_violation(violation, action_error)
            })
        })
        .collect();

    let scan_errors: Vec<String> = results
        .iter()
        .filter_map(|result| result.as_ref().err().map(|err| err.to_string()))
        .collect();

    ScanSummary {
        run_id: run_id.to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        duration_ms,
        violation_count: violations.len(),
        scan_error_count: scan_errors.len(),
        action_error_count: action_errors.len(),
        violations,
        scan_errors,
    }
}

fn write_summary(config: &Config, run_id: &str, summary: &ScanSummary) -> Result<PathBuf, String> {
    let dir = config.scan.summary_dir.join(run_id);
    fs::create_dir_all(&dir)
        .map_err(|err| format!("create results dir {}: {err}", dir.display()))?;

    let path = dir.join("summary.json");
    let payload =
        serde_json::to_string_pretty(summary).map_err(|err| format!("serialize summary: {err}"))?;
    fs::write(&path, payload).map_err(|err| format!("write summary {}: {err}", path.display()))?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use file_guardian::config::{LoggingConfig, PolicyConfig, RulesConfig, ScanConfig};
    use file_guardian::rules::{CompiledRule, RuleSource};
    use glob::Pattern;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::tempdir;

    fn test_config(root: &Path, summary_dir: &Path, write_summaries: bool) -> Config {
        let scan = ScanConfig {
            directories: vec![format!("{}/{}", root.display(), "*")],
            summary_dir: summary_dir.to_path_buf(),
            write_summaries,
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

    #[test]
    fn run_scan_writes_summary_when_enabled() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("bad.txt");
        fs::write(&file_path, "bad").unwrap();

        let summary_dir = dir.path().join("summaries");
        let config = test_config(dir.path(), &summary_dir, true);
        let rules = vec![CompiledRule {
            name: "all-txt".to_string(),
            filename_glob: Some(Pattern::new("*.txt").unwrap()),
            content_regex: None,
            action: Some(file_guardian::config::PolicyAction::Warn),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config.clone(), rules, true).unwrap();
        run_scan(&scanner, &config);

        let entries: Vec<_> = fs::read_dir(&summary_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let summary_path = entries[0].path().join("summary.json");
        assert!(summary_path.exists());

        let payload = fs::read_to_string(&summary_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["violation_count"].as_u64(), Some(1));
        assert_eq!(value["scan_error_count"].as_u64(), Some(0));
    }

    #[test]
    fn run_scan_skips_summary_when_disabled() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("bad.txt");
        fs::write(&file_path, "bad").unwrap();

        let summary_dir = dir.path().join("summaries");
        let config = test_config(dir.path(), &summary_dir, false);
        let rules = vec![CompiledRule {
            name: "all-txt".to_string(),
            filename_glob: Some(Pattern::new("*.txt").unwrap()),
            content_regex: None,
            action: Some(file_guardian::config::PolicyAction::Warn),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config.clone(), rules, true).unwrap();
        run_scan(&scanner, &config);

        assert!(!summary_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn run_scan_records_action_error() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("bad.txt");
        fs::write(&file_path, "bad").unwrap();

        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&file_path, perms).unwrap();

        let summary_dir = dir.path().join("summaries");
        let mut config = test_config(dir.path(), &summary_dir, true);
        config.policy.replace_message = "new".to_string();

        let rules = vec![CompiledRule {
            name: "replace".to_string(),
            filename_glob: Some(Pattern::new("*.txt").unwrap()),
            content_regex: None,
            action: Some(file_guardian::config::PolicyAction::Replace),
            source: RuleSource::Inline,
        }];

        let scanner = Scanner::new(config.clone(), rules, false).unwrap();
        run_scan(&scanner, &config);

        let entries: Vec<_> = fs::read_dir(&summary_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let summary_path = entries[0].path().join("summary.json");
        let payload = fs::read_to_string(&summary_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["action_error_count"].as_u64(), Some(1));
        assert!(value["violations"][0]["action_error"].as_str().is_some());
    }
}
