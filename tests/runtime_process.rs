use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use file_guardian::processing::config::ProcessingConfigFile;
use file_guardian::processing::job::{JobStore, JobStorePaths};
use file_guardian::processing::report::{
    ActionKind, ActionState, ConfiguredDisposition, EffectiveDisposition, HandoffStatus,
    PersistenceStatus, ProcessingOutcome, ProcessingReport, SourceSummary,
};
use file_guardian::processing::retention::RetentionController;
use file_guardian::processing::runtime::FrozenRetentionLimits;

struct Fixture {
    _temporary: tempfile::TempDir,
    config: PathBuf,
    input: PathBuf,
    jobs: PathBuf,
    reports: PathBuf,
    quarantine: PathBuf,
    artifact_quarantine: PathBuf,
    scanner_path: Option<OsString>,
}

impl Fixture {
    fn new(filename: &str, contents: &[u8]) -> Self {
        Self::with_profile(filename, contents, false, false)
    }

    fn applying(filename: &str, contents: &[u8]) -> Self {
        Self::with_profile(filename, contents, true, false)
    }

    fn quarantining(filename: &str, contents: &[u8]) -> Self {
        let fixture = Self::with_profile(filename, contents, true, false);
        let config = fs::read_to_string(&fixture.config)
            .unwrap()
            .replace("directive = \"delete\"", "directive = \"quarantine\"");
        ProcessingConfigFile::parse(&config).unwrap();
        fs::write(&fixture.config, config).unwrap();
        fixture
    }

    fn with_git_history(filename: &str, contents: &[u8]) -> Self {
        Self::with_profile(filename, contents, false, true)
    }

    fn with_profile(filename: &str, contents: &[u8], apply: bool, git_history: bool) -> Self {
        let temporary = private_tempdir();
        let jobs = private_dir(temporary.path(), "jobs");
        let reports = private_dir(temporary.path(), "reports");
        let quarantine = private_dir(temporary.path(), "quarantine");
        let artifact_quarantine = private_dir(temporary.path(), "artifact-quarantine");
        let input = temporary.path().join("private-input");
        fs::create_dir(&input).unwrap();
        fs::write(input.join(filename), contents).unwrap();
        let rules = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config/rules.d/publication.toml")
            .canonicalize()
            .unwrap();
        let config = temporary.path().join("config.toml");
        let config_contents = config_text(
            &jobs,
            &reports,
            &quarantine,
            &artifact_quarantine,
            AnalyzerFixture::Builtin { rules: &rules },
            apply,
            git_history,
        );
        ProcessingConfigFile::parse(&config_contents).unwrap();
        fs::write(&config, config_contents).unwrap();
        Self {
            _temporary: temporary,
            config,
            input,
            jobs,
            reports,
            quarantine,
            artifact_quarantine,
            scanner_path: None,
        }
    }

    fn failing_verification() -> Self {
        Self::verification_fixture(
            br#"#!/bin/sh
if [ "$1" = "version" ]; then
  printf '%s\n' 'gitleaks version 8.25.1'
  exit 0
fi
if [ -e /input/delete.txt ]; then
  file=delete.txt
else
  file=keep.txt
fi
printf '[{"RuleID":"generic-password","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":8,"File":"%s","SymlinkFile":"","Commit":"","Tags":["password"],"Secret":"REDACTED"}]' "$file" > /output/findings.json
exit 42
"#,
        )
    }

    fn crashing_verification() -> Self {
        Self::verification_fixture(
            br#"#!/bin/sh
if [ "$1" = "version" ]; then
  printf '%s\n' 'gitleaks version 8.25.1'
  exit 0
fi
if [ ! -e /input/delete.txt ]; then
  exit 9
fi
printf '[{"RuleID":"generic-password","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":8,"File":"delete.txt","SymlinkFile":"","Commit":"","Tags":["password"],"Secret":"REDACTED"}]' > /output/findings.json
exit 42
"#,
        )
    }

    fn verification_fixture(scanner_contents: &[u8]) -> Self {
        let temporary = private_tempdir();
        let jobs = private_dir(temporary.path(), "jobs");
        let reports = private_dir(temporary.path(), "reports");
        let quarantine = private_dir(temporary.path(), "quarantine");
        let artifact_quarantine = private_dir(temporary.path(), "artifact-quarantine");
        let input = temporary.path().join("private-input");
        fs::create_dir(&input).unwrap();
        fs::write(
            input.join("delete.txt"),
            b"password = \"FG_INITIAL_PRIVATE_PASSWORD\"\n",
        )
        .unwrap();
        fs::write(input.join("keep.txt"), b"ordinary retained fixture\n").unwrap();

        let scanner_bin = private_dir(temporary.path(), "scanner-bin");
        let scanner = scanner_bin.join("gitleaks");
        fs::write(&scanner, scanner_contents).unwrap();
        fs::set_permissions(&scanner, fs::Permissions::from_mode(0o700)).unwrap();
        let scanner_config = temporary.path().join("gitleaks.toml");
        let scanner_ignore = temporary.path().join("gitleaks.ignore");
        fs::write(&scanner_config, b"[extend]\nuseDefault = true\n").unwrap();
        fs::write(&scanner_ignore, b"# intentionally empty fixture\n").unwrap();

        let config = temporary.path().join("config.toml");
        let config_contents = config_text(
            &jobs,
            &reports,
            &quarantine,
            &artifact_quarantine,
            AnalyzerFixture::Gitleaks {
                config: &scanner_config,
                ignore: &scanner_ignore,
            },
            true,
            false,
        )
        .replacen("error = \"quarantine\"", "error = \"discard\"", 1);
        ProcessingConfigFile::parse(&config_contents).unwrap();
        fs::write(&config, config_contents).unwrap();
        let mut scanner_path = scanner_bin.into_os_string();
        scanner_path.push(OsStr::new(":"));
        scanner_path.push(std::env::var_os("PATH").unwrap_or_default());
        Self {
            _temporary: temporary,
            config,
            input,
            jobs,
            reports,
            quarantine,
            artifact_quarantine,
            scanner_path: Some(scanner_path),
        }
    }

    fn process_path(&self, request_id: Option<&str>) -> Output {
        self.process_path_operand(request_id, &self.input)
    }

    fn process_path_operand(&self, request_id: Option<&str>, path: &Path) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_file-guardian"));
        command.arg("--config").arg(&self.config).arg("process");
        if let Some(request_id) = request_id {
            command.args(["--request-id", request_id]);
        }
        if let Some(path) = &self.scanner_path {
            command.env("PATH", path);
        }
        command.arg("path").arg(path).output().unwrap()
    }

    fn handoff_copy(&self, run_id: &str, destination: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_file-guardian"))
            .arg("--config")
            .arg(&self.config)
            .args(["stage", "handoff", run_id, "--destination"])
            .arg(destination)
            .args(["--mode", "copy"])
            .output()
            .unwrap()
    }

    fn artifact_command(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_file-guardian"))
            .arg("--config")
            .arg(&self.config)
            .args(arguments)
            .output()
            .unwrap()
    }

    fn retention_controller(&self) -> (JobStore, RetentionController) {
        let config =
            ProcessingConfigFile::parse(&fs::read_to_string(&self.config).unwrap()).unwrap();
        let store = JobStore::open(JobStorePaths {
            jobs_root: config.processing.jobs.root.clone(),
            reports_root: config.processing.jobs.reports_root.clone(),
            quarantine_root: config.processing.jobs.quarantine_root.clone(),
        })
        .unwrap();
        let retention = &config.processing.jobs.retention;
        let controller = RetentionController::open(
            &store,
            &config.processing.jobs.artifact_quarantine_root,
            FrozenRetentionLimits {
                available_ttl_secs: retention.available_ttl_secs,
                available_max_bytes: retention.available_max_bytes,
                quarantine_ttl_secs: retention.quarantine_ttl_secs,
                quarantine_max_bytes: retention.quarantine_max_bytes,
                artifact_quarantine_ttl_secs: retention.artifact_quarantine_ttl_secs,
                artifact_quarantine_max_bytes: retention.artifact_quarantine_max_bytes,
            },
        )
        .unwrap();
        (store, controller)
    }

    fn initialize_git_repository(&self) {
        for arguments in [
            vec!["init", "--initial-branch=main"],
            vec!["config", "user.name", "File Guardian Test"],
            vec!["config", "user.email", "file-guardian@example.invalid"],
        ] {
            let output = Command::new("git")
                .args(arguments)
                .current_dir(&self.input)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git fixture setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        self.commit_all("fixture");
    }

    fn commit_all(&self, message: &str) {
        for arguments in [vec!["add", "--all"], vec!["commit", "-m", message]] {
            let output = Command::new("git")
                .args(arguments)
                .current_dir(&self.input)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git fixture commit failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

fn private_dir(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn config_text(
    jobs: &Path,
    reports: &Path,
    quarantine: &Path,
    artifact_quarantine: &Path,
    analyzer: AnalyzerFixture<'_>,
    apply: bool,
    git_history: bool,
) -> String {
    let action_mode = if apply { "apply" } else { "evaluate" };
    let purpose = if apply { "handoff" } else { "report_only" };
    let completion = if apply { "retain" } else { "discard" };
    let history = if git_history { "reachable" } else { "none" };
    let history_ref_patterns = if git_history {
        "[\"refs/heads/*\"]"
    } else {
        "[]"
    };
    let artifact_kinds = if git_history {
        "[\"physical_file\", \"repository_blob\"]"
    } else {
        "[\"physical_file\"]"
    };
    let inline_bindings = if apply { "" } else { "bindings = []\n" };
    let (analyzer_id, rule_id, analyzer_block) = match analyzer {
        AnalyzerFixture::Builtin { rules } => (
            "rules",
            "hardcoded-password",
            format!(
                r#"[[analyzers]]
id = "rules"
kind = "builtin_rules"
rule_files = ["{}"]
max_content_bytes = 1048576

[analyzers.execution]
initial = "required"
verification = "required"

[analyzers.selection]
include = ["**"]
exclude = []
artifact_kinds = {artifact_kinds}

[analyzers.limits]
max_findings = 100
"#,
                rules.display()
            ),
        ),
        AnalyzerFixture::Gitleaks { config, ignore } => (
            "gitleaks",
            "gitleaks:generic-password-32645174dcf4eebe",
            format!(
                r#"[[analyzers]]
id = "gitleaks"
kind = "gitleaks"
executable = "gitleaks"
version_requirement = ">=8.19,<9"
config_file = "{}"
ignore_file = "{}"

[analyzers.execution]
initial = "required"
verification = "required"

[analyzers.selection]
include = ["**"]
exclude = []
artifact_kinds = ["physical_file"]

[analyzers.limits]
wall_timeout_secs = 10
max_file_bytes = 1048576
max_output_bytes = 1048576
max_findings = 100
"#,
                config.display(),
                ignore.display()
            ),
        ),
    };
    let binding_tables = if apply {
        format!(
            r#"
[[processing.profiles.bindings]]
id = "delete-scanner-finding"
priority = 100
directive = "delete"

[processing.profiles.bindings.selector]
rule = "{rule_id}"
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"schema_version = "3"

[processing]
default_profile = "review"

[processing.jobs]
root = "{}"
reports_root = "{}"
quarantine_root = "{}"
artifact_quarantine_root = "{}"
stale_after_secs = 60
max_report_bytes = 1048576

[processing.jobs.capture]
max_entries = 100
max_files = 100
max_file_bytes = 1048576
max_total_bytes = 2097152
max_depth = 16

[processing.jobs.retention]
available_ttl_secs = 60
available_max_bytes = 2097152
quarantine_ttl_secs = 60
quarantine_max_bytes = 2097152
artifact_quarantine_ttl_secs = 60
artifact_quarantine_max_bytes = 2097152

[processing.acquisition]
git_executable = "/usr/bin/git"
git_timeout_secs = 30
max_stdout_bytes = 1048576
max_stderr_bytes = 1048576
max_refs = 100
max_commits = 1000
max_unique_blobs = 1000
max_provenance_occurrences = 1000
max_git_bytes = 2097152

[processing.external_scanners]
bubblewrap_executable = "/usr/bin/bwrap"
expected_bubblewrap_version = "0.11.1"

[[processing.profiles]]
id = "review"
pipeline = "builtins"
action_mode = "{action_mode}"
purpose = "{purpose}"
default_unbound_observation = "deny"
{inline_bindings}

[processing.profiles.source_scope]
working_tree = true
history = "{history}"
history_ref_patterns = {history_ref_patterns}

[processing.profiles.git]
allowed_checkout_ref_patterns = ["refs/heads/*", "refs/tags/*"]
submodules = "reject"
lfs = "reject_pointer"

[processing.profiles.completion]
allow = "{completion}"
allow_modified = "{completion}"
deny = "discard"
error = "quarantine"
cancelled = "quarantine"
{binding_tables}

[[pipelines]]
id = "builtins"

[[pipelines.stages]]
id = "rules"
analyzers = ["{analyzer_id}"]

{analyzer_block}
"#,
        jobs.display(),
        reports.display(),
        quarantine.display(),
        artifact_quarantine.display(),
    )
}

enum AnalyzerFixture<'a> {
    Builtin { rules: &'a Path },
    Gitleaks { config: &'a Path, ignore: &'a Path },
}

fn report(output: &Output) -> ProcessingReport {
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_private(output: &Output, fixture: &Fixture, secret: &[u8]) {
    let stdout = &output.stdout;
    for private in [&fixture.input, &fixture.config] {
        assert!(!stdout
            .windows(private.as_os_str().as_encoded_bytes().len())
            .any(|window| window == private.as_os_str().as_encoded_bytes()));
    }
    assert!(!stdout.windows(secret.len()).any(|window| window == secret));
}

#[test]
fn clean_path_allows_with_one_durable_report_and_preserves_source() {
    let contents = b"ordinary public fixture\n";
    let fixture = Fixture::new("safe.txt", contents);
    let output = fixture.process_path(Some("build-42"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, contents);
    let report = report(&output);
    assert_eq!(report.schema_version(), "2");
    assert_eq!(report.outcome, ProcessingOutcome::Allow);
    assert_eq!(report.exit_code, 0);
    assert_eq!(report.request_id.unwrap().as_str(), "build-42");
    assert_eq!(
        report.stage.unwrap().effective_disposition,
        EffectiveDisposition::Discarded
    );
    assert_eq!(fs::read(fixture.input.join("safe.txt")).unwrap(), contents);
    let persisted = fixture
        .reports
        .join(format!("{}.json", report.run_id.as_str()));
    assert_eq!(fs::read(persisted).unwrap(), output.stdout);
}

#[test]
fn matching_path_denies_without_exposing_or_mutating_secret() {
    let contents = b"password = \"FG_PRIVATE_RUNTIME_PASSWORD\"\n";
    let fixture = Fixture::new("settings.txt", contents);
    let output = fixture.process_path(None);

    assert_eq!(
        output.status.code(),
        Some(20),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, contents);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Deny);
    assert_eq!(report.exit_code, 20);
    assert!(!report.phases.initial.unwrap().findings.is_empty());
    assert_eq!(
        fs::read(fixture.input.join("settings.txt")).unwrap(),
        contents
    );
}

#[test]
fn oversized_decision_report_fails_closed_with_a_bounded_durable_error() {
    let contents = b"password = \"FG_PRIVATE_OVERSIZED_REPORT_PASSWORD\"\n";
    let fixture = Fixture::new("settings-00.txt", contents);
    for index in 1..80 {
        fs::write(
            fixture.input.join(format!("settings-{index:02}.txt")),
            contents,
        )
        .unwrap();
    }
    let config = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("max_report_bytes = 1048576", "max_report_bytes = 4096");
    ProcessingConfigFile::parse(&config).unwrap();
    fs::write(&fixture.config, config).unwrap();

    let output = fixture.process_path(Some("bounded-report"));

    assert_eq!(output.status.code(), Some(30));
    assert!(output.stdout.len() <= 4096);
    assert_private(&output, &fixture, contents);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert!(report.omissions.details_omitted);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code.as_str() == "report_construction_failed"));
    assert!(report.phases.initial.is_none());
    assert!(report.actions.is_empty());
    let persisted = fixture
        .reports
        .join(format!("{}.json", report.run_id.as_str()));
    assert_eq!(fs::read(persisted).unwrap(), output.stdout);
}

#[test]
fn missing_path_returns_one_durable_error_report() {
    let fixture = Fixture::new("placeholder.txt", b"temporary fixture\n");
    fs::remove_dir_all(&fixture.input).unwrap();

    let output = fixture.process_path(Some("missing-source"));

    assert_eq!(
        output.status.code(),
        Some(30),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert_eq!(report.exit_code, 30);
    assert_eq!(report.request_id.unwrap().as_str(), "missing-source");
    let persisted = fixture
        .reports
        .join(format!("{}.json", report.run_id.as_str()));
    assert_eq!(fs::read(persisted).unwrap(), output.stdout);
}

#[test]
fn path_source_rejects_a_single_file_instead_of_inventing_a_third_shape() {
    let fixture = Fixture::new("placeholder.txt", b"directory fixture\n");
    let standalone = fixture._temporary.path().join("standalone.txt");
    fs::write(&standalone, b"single file\n").unwrap();

    let output = fixture.process_path_operand(Some("single-file"), &standalone);

    assert_eq!(output.status.code(), Some(30));
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert_eq!(report.exit_code, 30);
    assert_eq!(fs::read(&standalone).unwrap(), b"single file\n");
}

#[test]
fn apply_delete_modifies_only_the_owned_stage_and_returns_allow_modified() {
    let contents = b"password = \"FG_PRIVATE_RUNTIME_PASSWORD\"\n";
    let fixture = Fixture::applying("settings.txt", contents);
    fs::write(fixture.input.join("keep.txt"), b"public fixture\n").unwrap();

    let output = fixture.process_path(Some("apply-delete"));

    assert_eq!(
        output.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, contents);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::AllowModified);
    assert_eq!(report.exit_code, 10);
    assert!(report.phases.initial.as_ref().unwrap().required_complete());
    assert!(report
        .phases
        .verification
        .as_ref()
        .unwrap()
        .required_complete());
    assert_eq!(report.actions.len(), 1);
    assert_eq!(report.actions[0].kind, ActionKind::Delete);
    assert_eq!(report.actions[0].state, ActionState::Committed);
    let stage = report.stage.as_ref().unwrap();
    assert_eq!(stage.configured_disposition, ConfiguredDisposition::Retain);
    assert_eq!(stage.effective_disposition, EffectiveDisposition::Retained);
    assert_eq!(stage.handoff_status, HandoffStatus::Available);
    assert_eq!(
        fs::read(fixture.input.join("settings.txt")).unwrap(),
        contents
    );

    let destination = fixture._temporary.path().join("handoff-copy");
    let handoff = fixture.handoff_copy(report.run_id.as_str(), &destination);
    assert_eq!(handoff.status.code(), Some(0));
    assert!(!destination.join("settings.txt").exists());
    assert_eq!(
        fs::read(destination.join("keep.txt")).unwrap(),
        b"public fixture\n"
    );
}

#[test]
fn retained_capacity_is_reserved_until_the_stage_is_consumed() {
    let fixture = Fixture::applying("safe.txt", b"ordinary retained fixture\n");
    let first = fixture.process_path(Some("capacity-first"));
    assert_eq!(first.status.code(), Some(0));
    let first_report = report(&first);

    let blocked = fixture.process_path(Some("capacity-blocked"));
    assert_eq!(blocked.status.code(), Some(30));
    let blocked_report = report(&blocked);
    assert_eq!(blocked_report.outcome, ProcessingOutcome::Error);
    assert_eq!(
        blocked_report.persistence.status,
        PersistenceStatus::Unavailable
    );
    assert!(blocked_report
        .issues
        .iter()
        .any(|issue| issue.code.as_str() == "retention_capacity_unavailable"));

    let destination = fixture._temporary.path().join("capacity-handoff");
    let handoff = fixture.handoff_copy(first_report.run_id.as_str(), &destination);
    assert_eq!(handoff.status.code(), Some(0));
    let admitted = fixture.process_path(Some("capacity-after-handoff"));
    assert_eq!(admitted.status.code(), Some(0));
}

#[test]
fn explicit_retention_sweep_expires_a_retained_stage_but_preserves_its_report() {
    let fixture = Fixture::applying("safe.txt", b"expiring retained fixture\n");
    let output = fixture.process_path(Some("expiry"));
    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    let expires_at = report
        .stage
        .as_ref()
        .and_then(|stage| stage.expires_at.as_ref())
        .unwrap();
    let future = chrono::DateTime::parse_from_rfc3339(expires_at.as_str())
        .unwrap()
        .timestamp_millis()
        + 1;
    let (store, controller) = fixture.retention_controller();

    let sweep = controller.sweep_expired(&store, future, 60_000).unwrap();

    assert_eq!(sweep.expired_jobs, 1);
    assert!(!fixture.jobs.join(report.run_id.as_str()).exists());
    assert!(fixture
        .reports
        .join(format!("{}.json", report.run_id.as_str()))
        .is_file());
}

#[test]
fn whole_job_quarantine_expires_without_removing_its_public_report() {
    let fixture = Fixture::failing_verification();
    let output = fixture.process_path(Some("quarantine-expiry"));
    assert_eq!(output.status.code(), Some(30));
    let report = report(&output);
    assert!(fixture.quarantine.join(report.run_id.as_str()).is_dir());
    let future = chrono::DateTime::parse_from_rfc3339(report.finished_at.as_str())
        .unwrap()
        .timestamp_millis()
        + 61_000;
    let (store, controller) = fixture.retention_controller();

    let sweep = controller.sweep_expired(&store, future, 60_000).unwrap();

    assert_eq!(sweep.expired_jobs, 1);
    assert!(!fixture.quarantine.join(report.run_id.as_str()).exists());
    assert!(fixture
        .reports
        .join(format!("{}.json", report.run_id.as_str()))
        .is_file());
}

#[test]
fn artifact_quarantine_capacity_and_ttl_are_independent_of_stage_handoff() {
    let contents = b"password = \"FG_PRIVATE_ARTIFACT_RETENTION_PASSWORD\"\n";
    let fixture = Fixture::quarantining("quarantine.txt", contents);
    let first = fixture.process_path(Some("artifact-retention"));
    assert_eq!(first.status.code(), Some(10));
    let first_report = report(&first);
    let quarantine_id = first_report.actions[0]
        .artifact_quarantine_id
        .as_ref()
        .unwrap()
        .as_str()
        .to_owned();
    let destination = fixture._temporary.path().join("artifact-retention-handoff");
    assert_eq!(
        fixture
            .handoff_copy(first_report.run_id.as_str(), &destination)
            .status
            .code(),
        Some(0)
    );

    let blocked = fixture.process_path(Some("artifact-capacity-blocked"));
    assert_eq!(blocked.status.code(), Some(30));
    assert_eq!(
        report(&blocked).persistence.status,
        PersistenceStatus::Unavailable
    );

    let future = chrono::DateTime::parse_from_rfc3339(first_report.finished_at.as_str())
        .unwrap()
        .timestamp_millis()
        + 61_000;
    let (store, controller) = fixture.retention_controller();
    let sweep = controller.sweep_expired(&store, future, 60_000).unwrap();
    assert_eq!(sweep.expired_artifacts, 1);
    assert!(!fixture.artifact_quarantine.join(&quarantine_id).exists());

    let admitted = fixture.process_path(Some("artifact-capacity-released"));
    assert_eq!(admitted.status.code(), Some(10));
}

#[test]
fn failed_second_pipeline_run_quarantines_the_modified_stage_without_handoff_or_rollback() {
    let fixture = Fixture::failing_verification();
    let original_delete = fs::read(fixture.input.join("delete.txt")).unwrap();
    let original_keep = fs::read(fixture.input.join("keep.txt")).unwrap();

    let output = fixture.process_path(Some("verification-failure"));

    assert_eq!(
        output.status.code(),
        Some(30),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, &original_delete);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert_eq!(report.exit_code, 30);
    assert!(report.modified, "{report:#?}");
    assert!(report.phases.initial.as_ref().unwrap().required_complete());
    assert!(report
        .phases
        .verification
        .as_ref()
        .unwrap()
        .required_complete());
    assert_eq!(report.actions.len(), 1);
    assert_eq!(report.actions[0].kind, ActionKind::Delete);
    assert_eq!(report.actions[0].state, ActionState::Committed);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code.as_str() == "verification_failed"));
    let stage = report.stage.as_ref().unwrap();
    assert_eq!(stage.configured_disposition, ConfiguredDisposition::Discard);
    assert_eq!(
        stage.effective_disposition,
        EffectiveDisposition::Quarantined
    );
    assert_eq!(stage.handoff_status, HandoffStatus::Unavailable);
    assert!(stage.reference.is_none());

    assert_eq!(
        fs::read(fixture.input.join("delete.txt")).unwrap(),
        original_delete
    );
    assert_eq!(
        fs::read(fixture.input.join("keep.txt")).unwrap(),
        original_keep
    );
    let quarantined_stage = fixture
        .quarantine
        .join(report.run_id.as_str())
        .join("stage");
    assert!(!quarantined_stage.join("delete.txt").exists());
    assert_eq!(
        fs::read(quarantined_stage.join("keep.txt")).unwrap(),
        original_keep
    );
}

#[test]
fn technical_failure_during_second_pipeline_quarantines_without_handoff_or_rollback() {
    let fixture = Fixture::crashing_verification();
    let original_delete = fs::read(fixture.input.join("delete.txt")).unwrap();
    let original_keep = fs::read(fixture.input.join("keep.txt")).unwrap();

    let output = fixture.process_path(Some("verification-crash"));

    assert_eq!(
        output.status.code(),
        Some(30),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, &original_delete);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert_eq!(report.exit_code, 30);
    assert!(report.modified, "{report:#?}");
    assert!(report.phases.initial.is_none());
    assert!(report.phases.verification.is_none());
    assert_eq!(report.actions.len(), 1);
    assert_eq!(report.actions[0].kind, ActionKind::Delete);
    assert_eq!(report.actions[0].state, ActionState::Committed);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code.as_str() == "required_analysis_failed"));
    let stage = report.stage.as_ref().unwrap();
    assert_eq!(stage.configured_disposition, ConfiguredDisposition::Discard);
    assert_eq!(
        stage.effective_disposition,
        EffectiveDisposition::Quarantined
    );
    assert_eq!(stage.handoff_status, HandoffStatus::Unavailable);
    assert!(stage.reference.is_none());

    assert_eq!(
        fs::read(fixture.input.join("delete.txt")).unwrap(),
        original_delete
    );
    assert_eq!(
        fs::read(fixture.input.join("keep.txt")).unwrap(),
        original_keep
    );
    let quarantined_stage = fixture
        .quarantine
        .join(report.run_id.as_str())
        .join("stage");
    assert!(!quarantined_stage.join("delete.txt").exists());
    assert_eq!(
        fs::read(quarantined_stage.join("keep.txt")).unwrap(),
        original_keep
    );
}

#[test]
fn artifact_quarantine_can_be_inspected_recovered_and_idempotently_discarded() {
    let contents = b"password = \"FG_PRIVATE_QUARANTINE_PASSWORD\"\n";
    let fixture = Fixture::quarantining("quarantine.txt", contents);
    fs::write(fixture.input.join("keep.txt"), b"retained fixture\n").unwrap();

    let output = fixture.process_path(Some("artifact-quarantine"));
    assert_eq!(output.status.code(), Some(10));
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::AllowModified);
    let quarantine_id = report.actions[0]
        .artifact_quarantine_id
        .as_ref()
        .unwrap()
        .as_str();
    assert!(fixture.artifact_quarantine.join(quarantine_id).is_file());
    assert_eq!(
        fs::read(fixture.input.join("quarantine.txt")).unwrap(),
        contents
    );

    let inspect =
        fixture.artifact_command(&["artifact", "inspect", report.run_id.as_str(), quarantine_id]);
    assert_eq!(inspect.status.code(), Some(0));
    assert!(!inspect
        .stdout
        .windows(contents.len())
        .any(|window| window == contents));

    let untrusted_parent = fixture._temporary.path().join("untrusted-recovery-parent");
    fs::create_dir(&untrusted_parent).unwrap();
    fs::set_permissions(&untrusted_parent, fs::Permissions::from_mode(0o777)).unwrap();
    let untrusted_destination = untrusted_parent.join("recovered.txt");
    let rejected_recover = fixture.artifact_command(&[
        "artifact",
        "recover",
        report.run_id.as_str(),
        quarantine_id,
        "--destination",
        untrusted_destination.to_str().unwrap(),
    ]);
    assert_eq!(rejected_recover.status.code(), Some(30));
    assert!(!untrusted_destination.exists());

    let trusted_parent = fixture._temporary.path().join("trusted-recovery-parent");
    fs::create_dir(&trusted_parent).unwrap();
    fs::set_permissions(&trusted_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let parent_link = fixture._temporary.path().join("recovery-parent-link");
    std::os::unix::fs::symlink(&trusted_parent, &parent_link).unwrap();
    let linked_destination = parent_link.join("recovered.txt");
    let linked_recover = fixture.artifact_command(&[
        "artifact",
        "recover",
        report.run_id.as_str(),
        quarantine_id,
        "--destination",
        linked_destination.to_str().unwrap(),
    ]);
    assert_eq!(linked_recover.status.code(), Some(30));
    assert!(!trusted_parent.join("recovered.txt").exists());

    let destination = fixture._temporary.path().join("recovered.txt");
    let recover = fixture.artifact_command(&[
        "artifact",
        "recover",
        report.run_id.as_str(),
        quarantine_id,
        "--destination",
        destination.to_str().unwrap(),
    ]);
    assert_eq!(
        recover.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&recover.stdout)
    );
    assert_eq!(fs::read(&destination).unwrap(), contents);
    let repeated_recover = fixture.artifact_command(&[
        "artifact",
        "recover",
        report.run_id.as_str(),
        quarantine_id,
        "--destination",
        destination.to_str().unwrap(),
    ]);
    assert_eq!(repeated_recover.status.code(), Some(20));

    let discard =
        fixture.artifact_command(&["artifact", "discard", report.run_id.as_str(), quarantine_id]);
    assert_eq!(discard.status.code(), Some(0));
    assert!(!fixture.artifact_quarantine.join(quarantine_id).exists());
    let repeated_discard =
        fixture.artifact_command(&["artifact", "discard", report.run_id.as_str(), quarantine_id]);
    assert_eq!(repeated_discard.status.code(), Some(0));
    let inspect_after =
        fixture.artifact_command(&["artifact", "inspect", report.run_id.as_str(), quarantine_id]);
    assert_eq!(inspect_after.status.code(), Some(20));
}

fn private_tempdir() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

#[test]
fn clean_local_repository_uses_the_same_pipeline_without_mutating_git_state() {
    let contents = b"repository fixture\n";
    let fixture = Fixture::new("README.md", contents);
    fixture.initialize_git_repository();
    let head_before = fs::read(fixture.input.join(".git/HEAD")).unwrap();

    let output = fixture.process_path(None);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, contents);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Allow);
    assert!(matches!(
        report.source,
        Some(SourceSummary::Path {
            repository: Some(ref repository),
            ..
        }) if repository.history == file_guardian::processing::report::HistoryScope::None
    ));
    assert_eq!(
        fs::read(fixture.input.join(".git/HEAD")).unwrap(),
        head_before
    );
    assert_eq!(fs::read(fixture.input.join("README.md")).unwrap(), contents);
}

#[test]
fn reachable_history_profile_finds_a_secret_removed_from_the_working_tree() {
    let historical_secret = b"password = \"FG_HISTORICAL_PRIVATE_PASSWORD\"\n";
    let fixture = Fixture::with_git_history("settings.txt", historical_secret);
    fixture.initialize_git_repository();
    let current = b"ordinary current contents\n";
    fs::write(fixture.input.join("settings.txt"), current).unwrap();
    fixture.commit_all("remove historical secret");
    let head_before = fs::read(fixture.input.join(".git/HEAD")).unwrap();

    let output = fixture.process_path(None);

    assert_eq!(
        output.status.code(),
        Some(20),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_private(&output, &fixture, historical_secret);
    let report = report(&output);
    assert_eq!(report.outcome, ProcessingOutcome::Deny);
    assert!(matches!(
        report.source,
        Some(SourceSummary::Path {
            repository: Some(ref repository),
            ..
        }) if repository.history == file_guardian::processing::report::HistoryScope::Reachable
    ));
    assert!(report
        .phases
        .initial
        .unwrap()
        .occurrences
        .iter()
        .any(|occurrence| occurrence.rule_id.as_str() == "hardcoded-password"));
    assert_eq!(
        fs::read(fixture.input.join("settings.txt")).unwrap(),
        current
    );
    assert_eq!(
        fs::read(fixture.input.join(".git/HEAD")).unwrap(),
        head_before
    );
}

#[test]
fn daemon_run_on_start_submits_the_same_owned_stage_workflow_and_stops_cleanly() {
    let contents = b"daemon upload fixture\n";
    let fixture = Fixture::new("upload.txt", contents);
    let mut config = fs::read_to_string(&fixture.config).unwrap();
    config.push_str(&format!(
        r#"
[[daemon.jobs]]
id = "incoming-upload"
enabled = true
profile = "review"
schedule = "0 0 0 1 1 *"
run_on_start = true
overlap = "reject"

[daemon.jobs.source]
kind = "path"
path = "{}"
"#,
        fixture.input.display()
    ));
    ProcessingConfigFile::parse(&config).unwrap();
    fs::write(&fixture.config, config).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_file-guardian"))
        .arg("--config")
        .arg(&fixture.config)
        .args(["daemon", "--job", "incoming-upload"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = line_tx.send((result, line));
    });
    let (read, line) = match line_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            panic!("daemon did not produce its run-on-start report: {error}");
        }
    };
    assert!(read.unwrap() > 0);
    let report: ProcessingReport = serde_json::from_str(&line).unwrap();
    assert_eq!(report.outcome, ProcessingOutcome::Allow);
    assert_eq!(
        report.request_id.unwrap().as_str(),
        "daemon:incoming-upload"
    );
    assert_eq!(
        fs::read(fixture.input.join("upload.txt")).unwrap(),
        contents
    );

    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let output = child.wait_with_output().unwrap();
    reader.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
