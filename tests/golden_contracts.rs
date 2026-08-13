use file_guardian::domain::{
    InspectionIssue, IssueCode, NormalizedObservation, PhaseCoverageStatus, RunCoverage,
};
use file_guardian::report::AuthorizationReport;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct GoldenReport {
    outcome: Outcome,
    exit_code: i32,
    modified: bool,
    coverage: RunCoverage,
    observations: Vec<NormalizedObservation>,
    issues: Vec<InspectionIssue>,
    actions: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Allow,
    AllowModified,
    Deny,
    Error,
}

#[test]
fn golden_reports_match_typed_domain_contracts_and_exit_invariants() {
    let reports = [
        include_str!("../docs/examples/reports/allow.json"),
        include_str!("../docs/examples/reports/deny.json"),
        include_str!("../docs/examples/reports/error.json"),
    ]
    .map(|source| serde_json::from_str::<GoldenReport>(source).expect("valid golden report"));

    for report in &reports {
        assert_exit_invariants(report);
    }

    assert!(reports[0].observations.is_empty());
    assert_eq!(reports[1].observations.len(), 1);
    assert_eq!(reports[2].issues.len(), 1);
    assert_eq!(
        reports[2].issues[0].code,
        IssueCode::RequiredAnalyzerTimeout
    );
    assert_eq!(
        reports[2].issues[0]
            .analyzer_id
            .as_ref()
            .expect("analyzer-attributed issue")
            .as_str(),
        "publication-llm"
    );
}

#[test]
fn golden_coverage_round_trips_as_the_exact_canonical_json_shape() {
    for source in [
        include_str!("../docs/examples/reports/allow.json"),
        include_str!("../docs/examples/reports/deny.json"),
        include_str!("../docs/examples/reports/error.json"),
    ] {
        let report: Value = serde_json::from_str(source).expect("valid golden report JSON");
        let expected = report.get("coverage").expect("golden coverage").clone();
        let coverage: RunCoverage =
            serde_json::from_value(expected.clone()).expect("valid typed coverage");
        assert_eq!(
            serde_json::to_value(coverage).expect("serializable coverage"),
            expected
        );
    }
}

#[test]
fn golden_reports_satisfy_the_full_machine_report_contract() {
    for source in [
        include_str!("../docs/examples/reports/allow.json"),
        include_str!("../docs/examples/reports/deny.json"),
        include_str!("../docs/examples/reports/error.json"),
    ] {
        let report: AuthorizationReport =
            serde_json::from_str(source).expect("valid authorization report");
        report.validate().expect("report invariants");
        let line = report.to_json_line().expect("serializable report");
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(!line[..line.len() - 1].contains(&b'\n'));
    }
}

#[test]
fn final_manifest_identity_is_strict_for_decisions_and_partial_for_errors() {
    let mut allow: Value =
        serde_json::from_str(include_str!("../docs/examples/reports/allow.json")).unwrap();
    allow["input"]["final_manifest_identity"] = Value::Null;
    assert!(serde_json::from_value::<AuthorizationReport>(allow).is_err());

    let mut error: Value =
        serde_json::from_str(include_str!("../docs/examples/reports/error.json")).unwrap();
    assert!(serde_json::from_value::<AuthorizationReport>(error.clone()).is_ok());
    error["input"]["final_manifest_identity"] = Value::String(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    );
    assert!(serde_json::from_value::<AuthorizationReport>(error).is_ok());
}

#[test]
fn error_report_keeps_relative_artifacts_from_a_trustworthy_initial_capture() {
    let mut error: Value =
        serde_json::from_str(include_str!("../docs/examples/reports/error.json")).unwrap();
    error["artifacts"] = serde_json::json!([{
        "artifact_id": "a_initial",
        "subject_id": "subject_initial",
        "kind": "physical_file",
        "relative_path": {
            "segments": [{"encoding": "utf8", "value": "captured.txt"}]
        },
        "byte_len": 7,
        "content_digest":
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }]);
    error["statistics"]["physical_artifacts"] = serde_json::json!(1);
    error["statistics"]["logical_artifacts"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuthorizationReport>(error).is_ok());
}

#[test]
fn checked_in_configuration_and_classifier_examples_parse() {
    let _: toml::Value = include_str!("../docs/examples/active-authorization-v2.toml")
        .parse()
        .expect("valid configuration TOML");
    let _: Value = serde_json::from_str(include_str!(
        "../docs/examples/pi-classifier/restricted.json"
    ))
    .expect("valid classifier JSON");
}

#[test]
fn run_coverage_deserialization_is_strict_and_phase_safe() {
    let unknown_field = r#"{
        "initial":{"status":"incomplete","analyzers":[]},
        "verification":{"status":"not_run","analyzers":[]},
        "extra":true
    }"#;
    assert!(serde_json::from_str::<RunCoverage>(unknown_field).is_err());

    let misplaced_phase = r#"{
        "initial":{"status":"complete","analyzers":[{
            "analyzer_id":"builtin","phase":"verification","eligible":0,
            "assigned":0,"completed":0,"excluded":0,"status":"complete"
        }]},
        "verification":{"status":"not_run","analyzers":[]}
    }"#;
    assert!(serde_json::from_str::<RunCoverage>(misplaced_phase).is_err());

    let fully_accounted_but_incomplete = r#"{
        "initial":{"status":"incomplete","analyzers":[{
            "analyzer_id":"builtin","phase":"initial","eligible":1,
            "assigned":1,"completed":1,"excluded":0,"status":"incomplete"
        }]},
        "verification":{"status":"not_run","analyzers":[]}
    }"#;
    let coverage: RunCoverage = serde_json::from_str(fully_accounted_but_incomplete)
        .expect("execution failure may make fully-accounted coverage incomplete");
    assert_eq!(coverage.initial.status, PhaseCoverageStatus::Incomplete);
}

fn assert_exit_invariants(report: &GoldenReport) {
    match report.exit_code {
        0 => {
            assert_eq!(report.outcome, Outcome::Allow);
            assert!(!report.modified);
            assert_eq!(
                report.coverage.initial.status,
                PhaseCoverageStatus::Complete
            );
        }
        10 => {
            assert_eq!(report.outcome, Outcome::AllowModified);
            assert!(report.modified);
            assert!(!report.actions.is_empty());
            assert_eq!(
                report.coverage.initial.status,
                PhaseCoverageStatus::Complete
            );
            assert_eq!(
                report.coverage.verification.status,
                PhaseCoverageStatus::Complete
            );
        }
        20 => {
            assert_eq!(report.outcome, Outcome::Deny);
            assert_eq!(
                report.coverage.initial.status,
                PhaseCoverageStatus::Complete
            );
        }
        30 => assert_eq!(report.outcome, Outcome::Error),
        code => panic!("unexpected documented exit code {code}"),
    }

    if report.outcome != Outcome::Error {
        assert!(report.issues.is_empty());
    }
}
