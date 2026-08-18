use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use file_guardian::processing::config::ProcessingConfigFile;
use file_guardian::processing::report::{
    ActionKind, ActionState, ConfiguredDisposition, EffectiveDisposition, HandoffStatus,
    ProcessingOutcome, ProcessingReport, SourceSummary,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    config: PathBuf,
    input: PathBuf,
    reports: PathBuf,
}

impl Fixture {
    fn new(filename: &str, contents: &[u8]) -> Self {
        Self::with_profile(filename, contents, false, false)
    }

    fn applying(filename: &str, contents: &[u8]) -> Self {
        Self::with_profile(filename, contents, true, false)
    }

    fn with_git_history(filename: &str, contents: &[u8]) -> Self {
        Self::with_profile(filename, contents, false, true)
    }

    fn with_profile(filename: &str, contents: &[u8], apply: bool, git_history: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
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
            &rules,
            apply,
            git_history,
        );
        ProcessingConfigFile::parse(&config_contents).unwrap();
        fs::write(&config, config_contents).unwrap();
        Self {
            _temporary: temporary,
            config,
            input,
            reports,
        }
    }

    fn process_path(&self, request_id: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_file-guardian"));
        command.arg("--config").arg(&self.config).arg("process");
        if let Some(request_id) = request_id {
            command.args(["--request-id", request_id]);
        }
        command.arg("path").arg(&self.input).output().unwrap()
    }

    fn process_repo(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_file-guardian"))
            .arg("--config")
            .arg(&self.config)
            .args(["process", "repo"])
            .arg(&self.input)
            .output()
            .unwrap()
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
    rules: &Path,
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
    let binding_tables = if apply {
        r#"
[[processing.profiles.bindings]]
id = "delete-hardcoded-password"
priority = 100
directive = "delete"

[processing.profiles.bindings.selector]
rule = "hardcoded-password"
"#
    } else {
        ""
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
symlinks = "preserve"

[processing.profiles.local]
symlinks = "reject"

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
analyzers = ["rules"]

[[analyzers]]
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
        jobs.display(),
        reports.display(),
        quarantine.display(),
        artifact_quarantine.display(),
        rules.display(),
    )
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
fn clean_local_repository_uses_the_same_pipeline_without_mutating_git_state() {
    let contents = b"repository fixture\n";
    let fixture = Fixture::new("README.md", contents);
    fixture.initialize_git_repository();
    let head_before = fs::read(fixture.input.join(".git/HEAD")).unwrap();

    let output = fixture.process_repo();

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
        Some(SourceSummary::Repo {
            working_tree: true,
            history: file_guardian::processing::report::HistoryScope::None,
            ..
        })
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

    let output = fixture.process_repo();

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
        Some(SourceSummary::Repo {
            working_tree: true,
            history: file_guardian::processing::report::HistoryScope::Reachable,
            ..
        })
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
