use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use file_guardian::domain::{CoverageStatus, IssueCode, PhaseCoverageStatus};
use file_guardian::report::{AuthorizationOutcome, AuthorizationReport};

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    input: PathBuf,
}

impl Fixture {
    fn new(directive: &str, input_name: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let input = temp.path().join("input");
        let rules = temp.path().join("rules.toml");
        let config = temp.path().join("config.toml");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&input).unwrap();
        fs::write(input.join(input_name), b"public test data").unwrap();
        fs::write(
            &rules,
            r#"schema_version = "file-guardian-rules/1"

[[rules]]
id = "blocked"
filename_glob = "*.blocked"
"#,
        )
        .unwrap();
        fs::write(&config, config_text(&workspace, &rules, directive, None)).unwrap();
        Self {
            _temp: temp,
            config,
            input,
        }
    }

    fn authorize(&self, extra: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_file-guardian"));
        command.arg("--config").arg(&self.config).arg("authorize");
        command.args(extra).arg(&self.input).output().unwrap()
    }

    fn set_profile_mode(&self, mode: &str) {
        let value = fs::read_to_string(&self.config).unwrap().replace(
            "action_mode = \"evaluate\"",
            &format!("action_mode = \"{mode}\""),
        );
        fs::write(&self.config, value).unwrap();
    }

    fn enable_console_logging(&self) {
        let value = fs::read_to_string(&self.config)
            .unwrap()
            .replace("console = false", "console = true");
        fs::write(&self.config, value).unwrap();
    }

    fn select_unsupported_external_analyzer(&self) -> PathBuf {
        let adapter = self._temp.path().join("delegate-scanner");
        let marker = self._temp.path().join("delegate-was-invoked");
        fs::write(&adapter, format!("#!/bin/sh\n: > '{}'\n", marker.display())).unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();

        let rules = self._temp.path().join("rules.toml");
        let builtin_and_binding = format!(
            r#"[[analyzers]]
id = "rules"
kind = "builtin_rules"
rule_files = ["{}"]

[[policy_bindings]]
id = "blocked"
profile = "publication"
analyzer = "rules"
rule = "*"
directive = "deny""#,
            rules.display()
        );
        let external = format!(
            r#"[[analyzers]]
id = "rules"
kind = "external_tool"
adapter = "{}"
protocol = "file-guardian-delegate/1"
sandbox = "required""#,
            adapter.display()
        );
        let current = fs::read_to_string(&self.config).unwrap();
        let updated = current.replace(&builtin_and_binding, &external);
        assert_ne!(
            updated, current,
            "test fixture analyzer block must be replaced"
        );
        fs::write(&self.config, updated).unwrap();
        marker
    }
}

fn config_text(
    workspace: &Path,
    rules: &Path,
    directive: &str,
    daemon: Option<(&Path, bool)>,
) -> String {
    let daemon = daemon.map_or_else(String::new, |(target, run_on_start)| {
        format!(
            r#"
[[daemon.jobs]]
id = "scan"
enabled = true
kind = "policy_scan"
profile = "publication"
every_secs = 60
run_on_start = {run_on_start}

[daemon.jobs.target]
kind = "literal"
path = "{}"
"#,
            target.display()
        )
    });
    format!(
        r#"schema_version = "2"

[authorization]
default_profile = "publication"

[authorization.workspace]
root = "{}"

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
rule_files = ["{}"]

[[policy_bindings]]
id = "blocked"
profile = "publication"
analyzer = "rules"
rule = "*"
directive = "{directive}"

[logging]
console = false
{daemon}
"#,
        workspace.display(),
        rules.display(),
    )
}

fn report(output: &Output) -> AuthorizationReport {
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn authorize_allows_with_exact_json_stdout_and_preserves_input() {
    let fixture = Fixture::new("deny", "safe.txt");
    let output = fixture.authorize(&["--request-id", "build-42"]);
    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Allow);
    assert_eq!(report.request_id.unwrap().as_str(), "build-42");
    assert_eq!(
        fs::read(fixture.input.join("safe.txt")).unwrap(),
        b"public test data"
    );
}

#[test]
fn authorize_denies_matching_input_with_exit_twenty() {
    let fixture = Fixture::new("deny", "payload.blocked");
    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(20));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Deny);
    assert_eq!(report.observations.len(), 1);
    assert!(fixture.input.join("payload.blocked").exists());
}

#[test]
fn selected_unimplemented_external_analyzer_fails_closed_with_runtime_coverage() {
    let fixture = Fixture::new("deny", "safe.txt");
    let invocation_marker = fixture.select_unsupported_external_analyzer();

    let output = fixture.authorize(&[]);

    assert_eq!(output.status.code(), Some(30));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Error);
    assert!(report.policy.is_some());
    assert!(report.input.is_some());
    assert_eq!(
        report.coverage.initial.status,
        PhaseCoverageStatus::Incomplete
    );
    assert_eq!(report.coverage.initial.analyzers.len(), 1);
    let coverage = &report.coverage.initial.analyzers[0];
    assert_eq!(coverage.analyzer_id.as_str(), "rules");
    assert_eq!(coverage.status, CoverageStatus::Incomplete);
    assert_eq!(coverage.eligible, 1);
    assert_eq!(coverage.assigned, 1);
    assert_eq!(coverage.completed, 0);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == IssueCode::RequiredAnalyzerProcessFailure));
    assert!(!invocation_marker.exists());
}

#[test]
fn analyzer_selector_excludes_artifacts_before_assignment() {
    let fixture = Fixture::new("deny", "payload.blocked");
    let value = fs::read_to_string(&fixture.config).unwrap().replace(
        &format!(
            "rule_files = [\"{}\"]",
            fixture._temp.path().join("rules.toml").display()
        ),
        &format!(
            r#"rule_files = ["{}"]

[analyzers.selection]
include = ["**"]
exclude = ["*.blocked"]
artifact_kinds = ["physical_file"]"#,
            fixture._temp.path().join("rules.toml").display()
        ),
    );
    fs::write(&fixture.config, value).unwrap();

    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Allow);
    assert!(report.observations.is_empty());
    assert_eq!(report.coverage.initial.analyzers[0].eligible, 0);
    assert_eq!(report.coverage.initial.analyzers[0].assigned, 0);
}

#[test]
fn parallel_stage_runs_every_selected_analyzer() {
    let fixture = Fixture::new("deny", "payload.blocked");
    let value = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace(
            "id = \"rules\"\nanalyzers = [\"rules\"]",
            "id = \"rules\"\nexecution = \"parallel\"\nmax_concurrency = 2\nanalyzers = [\"rules\", \"rules_two\"]",
        )
        .replace(
            "[[policy_bindings]]",
            &format!(
                r#"[[analyzers]]
id = "rules_two"
kind = "builtin_rules"
rule_files = ["{}"]

[[policy_bindings]]
id = "blocked-two"
profile = "publication"
analyzer = "rules_two"
rule = "*"
directive = "deny"

[[policy_bindings]]"#,
                fixture._temp.path().join("rules.toml").display()
            ),
        );
    fs::write(&fixture.config, value).unwrap();

    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(20));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Deny);
    assert_eq!(report.observations.len(), 2);
    assert_eq!(report.coverage.initial.analyzers.len(), 2);
    assert_eq!(report.pipeline_runs[0].analyzers_completed, 2);
}

#[test]
fn later_stage_prior_projection_is_bounded_and_fails_closed() {
    let fixture = Fixture::new("deny", "payload.blocked");
    let value = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace(
            "id = \"rules\"\nanalyzers = [\"rules\"]",
            r#"id = "rules"
analyzers = ["rules"]

[[pipelines.stages]]
id = "second"
analyzers = ["rules_two"]
prior_observations = "findings_summary"

[pipelines.stages.prior_limits]
max_observations = 100
max_serialized_bytes = 4096"#,
        )
        .replace(
            "[[policy_bindings]]",
            &format!(
                r#"[[analyzers]]
id = "rules_two"
kind = "builtin_rules"
rule_files = ["{}"]

[[policy_bindings]]
id = "blocked-two"
profile = "publication"
analyzer = "rules_two"
rule = "*"
directive = "deny"

[[policy_bindings]]"#,
                fixture._temp.path().join("rules.toml").display()
            ),
        );
    fs::write(&fixture.config, &value).unwrap();

    let complete = fixture.authorize(&[]);
    assert_eq!(complete.status.code(), Some(20));
    let complete = report(&complete);
    assert_eq!(complete.outcome, AuthorizationOutcome::Deny);
    assert_eq!(complete.pipeline_runs[0].stages_completed, 2);

    fs::write(
        &fixture.config,
        value.replace("max_serialized_bytes = 4096", "max_serialized_bytes = 1"),
    )
    .unwrap();
    let overflow = fixture.authorize(&[]);
    assert_eq!(overflow.status.code(), Some(30));
    let overflow = report(&overflow);
    assert_eq!(overflow.outcome, AuthorizationOutcome::Error);
    assert_eq!(overflow.pipeline_runs[0].stages_completed, 1);
}

#[test]
fn valid_authorize_syntax_reports_configuration_error_as_json() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_file-guardian"))
        .arg("--config")
        .arg(temp.path().join("missing.toml"))
        .arg("authorize")
        .arg("--request-id")
        .arg("request-7")
        .arg(temp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(30));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Error);
    assert_eq!(report.request_id.unwrap().as_str(), "request-7");
}

#[test]
fn apply_request_fails_closed_without_modification() {
    let fixture = Fixture::new("delete", "payload.blocked");
    let output = fixture.authorize(&["--action-mode", "apply"]);
    assert_eq!(output.status.code(), Some(30));
    assert_eq!(report(&output).outcome, AuthorizationOutcome::Error);
    assert!(fixture.input.join("payload.blocked").exists());
}

#[test]
fn explicit_evaluate_downgrades_an_apply_capable_profile() {
    let fixture = Fixture::new("deny", "safe.txt");
    fixture.set_profile_mode("apply");
    let output = fixture.authorize(&["--action-mode", "evaluate"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report(&output).outcome, AuthorizationOutcome::Allow);

    let absent_mode = fixture.authorize(&[]);
    assert_eq!(absent_mode.status.code(), Some(30));
    assert_eq!(report(&absent_mode).outcome, AuthorizationOutcome::Error);
}

#[test]
fn literal_input_with_spaces_and_glob_characters_is_not_expanded() {
    let fixture = Fixture::new("deny", "safe.txt");
    let literal = fixture._temp.path().join("literal [*] tree");
    fs::rename(&fixture.input, &literal).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_file-guardian"))
        .arg("--config")
        .arg(&fixture.config)
        .arg("authorize")
        .arg(&literal)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report(&output).outcome, AuthorizationOutcome::Allow);
}

#[test]
fn double_dash_allows_a_literal_path_starting_with_a_hyphen() {
    let fixture = Fixture::new("deny", "safe.txt");
    let literal = fixture._temp.path().join("-input");
    fs::rename(&fixture.input, &literal).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_file-guardian"))
        .current_dir(fixture._temp.path())
        .arg("--config")
        .arg(&fixture.config)
        .arg("authorize")
        .arg("--")
        .arg("-input")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report(&output).outcome, AuthorizationOutcome::Allow);
}

#[test]
fn non_utf8_filename_is_preserved_in_the_machine_report() {
    let fixture = Fixture::new("deny", "safe.txt");
    fs::write(
        fixture._temp.path().join("rules.toml"),
        r#"schema_version = "file-guardian-rules/1"

[[rules]]
id = "blocked"
content_regex = "never-matches-this-input"
"#,
    )
    .unwrap();
    let name = std::ffi::OsString::from_vec(vec![b'n', 0xff, b'm']);
    fs::write(fixture.input.join(&name), b"opaque name").unwrap();
    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_path.segments()[0].as_slice() == [b'n', 0xff, b'm'])
        .expect("non-UTF8 filename must remain byte-exact");
    let wire = serde_json::to_value(&artifact.relative_path).unwrap();
    assert_eq!(wire["segments"][0]["encoding"], "base64url");
}

#[test]
fn console_logging_never_contaminates_machine_stdout() {
    let fixture = Fixture::new("deny", "safe.txt");
    fixture.enable_console_logging();
    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report(&output).outcome, AuthorizationOutcome::Allow);
}

#[test]
fn malformed_rules_are_reported_as_json_error() {
    let fixture = Fixture::new("deny", "safe.txt");
    fs::write(fixture._temp.path().join("rules.toml"), "not = [valid").unwrap();
    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(30));
    assert_eq!(report(&output).outcome, AuthorizationOutcome::Error);
}

#[test]
fn unknown_deny_rule_binding_fails_before_scanning_instead_of_allowing() {
    let fixture = Fixture::new("deny", "payload.blocked");
    let value = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace(
            "default_unbound_observation = \"error\"",
            "default_unbound_observation = \"audit\"",
        )
        .replace("rule = \"*\"", "rule = \"blockde\"");
    fs::write(&fixture.config, value).unwrap();

    let output = fixture.authorize(&[]);
    assert_eq!(output.status.code(), Some(30));
    let report = report(&output);
    assert_eq!(report.outcome, AuthorizationOutcome::Error);
    assert!(report.input.is_none());
    assert!(report.policy.is_none());
    assert!(report.artifacts.is_empty());
    assert!(report.observations.is_empty());
    assert!(fixture.input.join("payload.blocked").exists());
}

#[test]
fn report_identities_cover_compiled_rules_and_effective_policy() {
    let fixture = Fixture::new("audit", "safe.txt");
    let first = report(&fixture.authorize(&[]));
    let first_policy = first.policy.unwrap();

    fs::write(
        fixture._temp.path().join("rules.toml"),
        r#"schema_version = "file-guardian-rules/1"

[[rules]]
id = "blocked"
filename_glob = "*.different"
"#,
    )
    .unwrap();
    let second = report(&fixture.authorize(&[]));
    let second_policy = second.policy.unwrap();
    assert_ne!(
        first_policy.pipeline_identity,
        second_policy.pipeline_identity
    );
    assert_eq!(first_policy.identity, second_policy.identity);

    let value = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("directive = \"audit\"", "directive = \"deny\"");
    fs::write(&fixture.config, value).unwrap();
    let third = report(&fixture.authorize(&[]));
    let third_policy = third.policy.unwrap();
    assert_ne!(second_policy.identity, third_policy.identity);
    assert_eq!(
        second_policy.pipeline_identity,
        third_policy.pipeline_identity
    );

    let value = fs::read_to_string(&fixture.config).unwrap().replace(
        &format!(
            "rule_files = [\"{}\"]",
            fixture._temp.path().join("rules.toml").display()
        ),
        &format!(
            r#"rule_files = ["{}"]

[analyzers.selection]
include = ["**"]
exclude = ["vendor/**"]
artifact_kinds = ["physical_file"]"#,
            fixture._temp.path().join("rules.toml").display()
        ),
    );
    fs::write(&fixture.config, &value).unwrap();
    let selector_policy = report(&fixture.authorize(&[])).policy.unwrap();
    assert_ne!(
        third_policy.pipeline_identity,
        selector_policy.pipeline_identity
    );

    let value = value.replace(
        "id = \"rules\"\nanalyzers = [\"rules\"]",
        "id = \"rules\"\nexecution = \"parallel\"\nmax_concurrency = 2\nanalyzers = [\"rules\"]",
    );
    fs::write(&fixture.config, &value).unwrap();
    let execution_policy = report(&fixture.authorize(&[])).policy.unwrap();
    assert_ne!(
        selector_policy.pipeline_identity,
        execution_policy.pipeline_identity
    );

    let value = value.replace(
        "analyzers = [\"rules\"]",
        "analyzers = [\"rules\"]\n\n[pipelines.stages.prior_limits]\nmax_observations = 77\nmax_serialized_bytes = 4096",
    );
    fs::write(&fixture.config, value).unwrap();
    let limits_policy = report(&fixture.authorize(&[])).policy.unwrap();
    assert_ne!(
        execution_policy.pipeline_identity,
        limits_policy.pipeline_identity
    );
}

#[test]
fn unhealthy_run_on_start_daemon_writes_no_stdout_and_exits_thirty() {
    let fixture = Fixture::new("deny", "safe.txt");
    let missing = fixture.input.join("missing");
    fs::write(
        &fixture.config,
        config_text(
            fixture._temp.path().join("workspace").as_path(),
            fixture._temp.path().join("rules.toml").as_path(),
            "deny",
            Some((&missing, true)),
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_file-guardian"))
        .arg("--config")
        .arg(&fixture.config)
        .arg("daemon")
        .arg("--job")
        .arg("scan")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(30));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
