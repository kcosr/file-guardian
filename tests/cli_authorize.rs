use std::path::PathBuf;
use std::process::{Command, Output};

use file_guardian::processing::report::{ProcessingOutcome, ProcessingReport};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_file-guardian"))
}

fn config() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/examples/processing-v3.toml")
}

fn report(output: &Output) -> ProcessingReport {
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn process_reports_schema_three_runtime_compilation_failure_without_private_inputs() {
    let output = binary()
        .arg("--config")
        .arg(config())
        .args([
            "process",
            "--request-id",
            "upload-42",
            "path",
            "/private/source-that-must-not-be-reported",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(30));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("source-that-must-not-be-reported"));
    let report = report(&output);
    assert_eq!(report.schema_version(), "2");
    assert_eq!(report.outcome, ProcessingOutcome::Error);
    assert_eq!(report.exit_code, 30);
    assert_eq!(report.request_id.unwrap().as_str(), "upload-42");
    assert_eq!(
        report.issues[0].code.as_str(),
        "runtime_compilation_failure"
    );
}

#[test]
fn invalid_artifact_operands_emit_one_versioned_error() {
    let cases = [
        (
            vec!["artifact", "inspect", "run_artifact", "quarantine_1"],
            "artifact_inspect",
            Some("run_artifact"),
        ),
        (
            vec![
                "artifact",
                "recover",
                "run_artifact",
                "quarantine_1",
                "--destination",
                "/recovered/item",
            ],
            "artifact_recover",
            Some("run_artifact"),
        ),
        (
            vec!["artifact", "discard", "run_artifact", "quarantine_1"],
            "artifact_discard",
            Some("run_artifact"),
        ),
    ];

    for (arguments, operation, selected_run_id) in cases {
        let output = binary()
            .arg("--config")
            .arg(config())
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(30), "{arguments:?}");
        assert_eq!(
            output.stdout.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schema_version"], "file-guardian-auxiliary-result/1");
        assert_eq!(result["operation"], operation, "{arguments:?}");
        assert_eq!(result["status"], "error", "{arguments:?}");
        assert_eq!(result["issue_code"], "invalid_artifact_identity");
        if let Some(run_id) = selected_run_id {
            assert_eq!(result["run_id"], run_id, "{arguments:?}");
        } else {
            assert!(result["run_id"].as_str().unwrap().starts_with("run_"));
        }
    }
}

#[test]
fn unsafe_auxiliary_operand_is_never_echoed() {
    let unsafe_run_id = "../../private/customer";
    let output = binary()
        .arg("--config")
        .arg(config())
        .args(["stage", "discard", unsafe_run_id])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(30));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(unsafe_run_id));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["run_id"].as_str().unwrap().starts_with("run_"));
}

#[test]
fn configuration_failure_is_a_typed_processing_report() {
    let output = binary()
        .args([
            "--config",
            "/definitely/missing/file-guardian.toml",
            "process",
            "path",
            "/private/source",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(30));
    assert_eq!(
        report(&output).issues[0].code.as_str(),
        "configuration_failure"
    );
}

#[test]
fn obsolete_authorize_is_a_clap_error_without_machine_stdout() {
    let output = binary().args(["authorize", "/tmp/input"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
