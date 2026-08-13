use file_guardian::domain::{
    InspectionIssue, IssueCode, NormalizedObservation, PhaseCoverageStatus, RunCoverage,
};
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
fn checked_in_configuration_and_classifier_examples_parse() {
    let _: toml::Value = include_str!("../docs/examples/active-authorization-v2.toml")
        .parse()
        .expect("valid configuration TOML");
    let _: Value = serde_json::from_str(include_str!(
        "../docs/examples/pi-classifier/restricted.json"
    ))
    .expect("valid classifier JSON");
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
