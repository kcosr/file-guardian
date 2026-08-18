use file_guardian::processing::report::{
    ActionState, EffectiveDisposition, HandoffStatus, OmissionSummary, PersistenceStatus,
    PhasesSummary, ProcessingOutcome, ProcessingReport, ProcessingReportData, ProcessingStatistics,
    ReportError, Rfc3339Timestamp, SafeId, Sha256Digest, SourceSummary,
};
use serde_json::{json, Value};

const ALLOW: &str = include_str!("../docs/examples/processing-reports/allow.json");
const ALLOW_MODIFIED: &str =
    include_str!("../docs/examples/processing-reports/allow-modified.json");
const DENY: &str = include_str!("../docs/examples/processing-reports/deny.json");
const ERROR: &str = include_str!("../docs/examples/processing-reports/error.json");

fn parse(source: &str) -> ProcessingReport {
    serde_json::from_str(source).expect("valid strict processing report")
}

fn rebuild(report: ProcessingReport) -> Result<ProcessingReport, ReportError> {
    ProcessingReport::new(ProcessingReportData {
        run_id: report.run_id,
        request_id: report.request_id,
        outcome: report.outcome,
        modified: report.modified,
        started_at: report.started_at,
        finished_at: report.finished_at,
        persistence_status: report.persistence.status,
        source: report.source,
        acquisition: report.acquisition,
        stage: report.stage,
        policy: report.policy,
        phases: report.phases,
        pi_invocations: report.pi_invocations,
        adjudications: report.adjudications,
        actions: report.actions,
        issues: report.issues,
        degradations: report.degradations,
        statistics: report.statistics,
        omissions: report.omissions,
    })
}

fn detected_repository_source() -> SourceSummary {
    serde_json::from_value(json!({
        "kind": "path",
        "input_kind": "directory",
        "repository": {
            "repository_id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "resolved_head": {"algorithm": "sha1", "value": "2222222222222222222222222222222222222222"},
            "history": "head",
            "frozen_refs": [{
                "name": {"segments": [
                    {"encoding": "utf8", "value": "refs"},
                    {"encoding": "utf8", "value": "heads"},
                    {"encoding": "utf8", "value": "main"}
                ]},
                "object_id": {"algorithm": "sha1", "value": "2222222222222222222222222222222222222222"},
                "peeled_commit_id": {"algorithm": "sha1", "value": "2222222222222222222222222222222222222222"}
            }]
        }
    }))
    .unwrap()
}

#[test]
fn all_four_goldens_validate_with_exact_exits_and_one_json_line() {
    let expected = [
        (ALLOW, ProcessingOutcome::Allow, 0, false),
        (ALLOW_MODIFIED, ProcessingOutcome::AllowModified, 10, true),
        (DENY, ProcessingOutcome::Deny, 20, false),
        (ERROR, ProcessingOutcome::Error, 30, false),
    ];
    for (source, outcome, exit, modified) in expected {
        let report = parse(source);
        assert_eq!(report.schema_version(), "2");
        assert_eq!(report.outcome, outcome);
        assert_eq!(report.exit_code, exit);
        assert_eq!(report.modified, modified);
        report.validate().expect("golden invariants");
        let line = report.to_json_line().expect("canonical report line");
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(serde_json::from_slice::<ProcessingReport>(&line).is_ok());
    }
}

#[test]
fn composite_analysis_identity_is_independent_of_publication_stage_identity() {
    let mut report = parse(ALLOW);
    report.source = Some(detected_repository_source());
    report.phases.initial.as_mut().unwrap().manifest_identity = Sha256Digest::new(
        "sha256:9999999999999999999999999999999999999999999999999999999999999999",
    )
    .unwrap();
    let report = rebuild(report).expect("working-tree plus history report");
    assert_ne!(
        report.phases.initial.as_ref().unwrap().manifest_identity,
        report
            .stage
            .as_ref()
            .unwrap()
            .final_manifest_identity
            .clone()
            .unwrap()
    );
}

#[test]
fn durable_digest_binds_the_canonical_body_and_unavailable_has_no_digest() {
    let mut allow = parse(ALLOW);
    allow.statistics.duration_ms += 1;
    assert!(matches!(
        allow.validate(),
        Err(ReportError::ReportDigestMismatch)
    ));

    let error = parse(ERROR);
    assert_eq!(error.persistence.status, PersistenceStatus::Unavailable);
    assert!(error.persistence.report_digest.is_none());

    let durable_error = ProcessingReport::new(ProcessingReportData {
        run_id: SafeId::new("run_durable_error").unwrap(),
        request_id: None,
        outcome: ProcessingOutcome::Error,
        modified: false,
        started_at: Rfc3339Timestamp::new("2026-08-17T12:00:00+00:00").unwrap(),
        finished_at: Rfc3339Timestamp::new("2026-08-17T12:00:01+00:00").unwrap(),
        persistence_status: PersistenceStatus::Durable,
        source: None,
        acquisition: None,
        stage: None,
        policy: None,
        phases: PhasesSummary {
            initial: None,
            verification: None,
        },
        pi_invocations: vec![],
        adjudications: vec![],
        actions: vec![],
        issues: vec![file_guardian::processing::report::IssueSummary {
            code: SafeId::new("job_store_failure").unwrap(),
            phase: None,
            component_id: None,
        }],
        degradations: vec![],
        statistics: ProcessingStatistics {
            initial_artifacts: 0,
            verification_artifacts: 0,
            total_findings: 0,
            total_actions: 0,
            duration_ms: 1000,
        },
        omissions: OmissionSummary {
            details_omitted: false,
            reason: None,
        },
    })
    .expect("durable errors are valid after the job store is available");
    assert!(durable_error.persistence.report_digest.is_some());
}

#[test]
fn outcome_phase_action_and_stage_invariants_reject_forgery() {
    let mut allow = parse(ALLOW);
    allow.modified = true;
    assert!(matches!(
        allow.validate(),
        Err(ReportError::ModifiedMismatch)
    ));

    let mut allow = parse(ALLOW);
    allow.phases.verification = parse(ALLOW_MODIFIED).phases.verification;
    assert!(matches!(allow.validate(), Err(ReportError::AllowInvariant)));

    let mut modified = parse(ALLOW_MODIFIED);
    modified.actions[0].state = ActionState::Planned;
    assert!(matches!(
        modified.validate(),
        Err(ReportError::ModifiedMismatch)
    ));

    let mut modified = parse(ALLOW_MODIFIED);
    modified.phases.verification = None;
    assert!(matches!(
        modified.validate(),
        Err(ReportError::AllowModifiedInvariant)
    ));

    let mut deny = parse(DENY);
    deny.actions = parse(ALLOW_MODIFIED).actions;
    deny.modified = true;
    assert!(matches!(deny.validate(), Err(ReportError::DenyInvariant)));

    let mut error = parse(ERROR);
    error.issues.clear();
    assert!(matches!(error.validate(), Err(ReportError::ErrorInvariant)));
}

#[test]
fn disposition_and_handoff_are_independent_from_policy_outcome_but_consistent() {
    let mut allow = parse(ALLOW);
    let stage = allow.stage.as_mut().unwrap();
    stage.handoff_status = HandoffStatus::Unavailable;
    assert!(matches!(
        allow.validate(),
        Err(ReportError::HandoffMismatch)
    ));

    let mut deny = parse(DENY);
    let stage = deny.stage.as_mut().unwrap();
    stage.effective_disposition = EffectiveDisposition::Retained;
    assert!(matches!(
        deny.validate(),
        Err(ReportError::DispositionMismatch)
    ));

    let mut error = parse(ERROR);
    error.stage = parse(ALLOW).stage;
    assert!(matches!(
        error.validate(),
        Err(ReportError::HandoffMismatch | ReportError::ErrorInvariant)
    ));
}

#[test]
fn only_error_may_escalate_configured_retain_or_discard_to_quarantine() {
    for configured in [
        file_guardian::processing::report::ConfiguredDisposition::Retain,
        file_guardian::processing::report::ConfiguredDisposition::Discard,
    ] {
        let mut error = parse(DENY);
        error.outcome = ProcessingOutcome::Error;
        error.exit_code = 30;
        error.issues = vec![file_guardian::processing::report::IssueSummary {
            code: SafeId::new("ambiguous_stage_mutation").unwrap(),
            phase: None,
            component_id: None,
        }];
        let stage = error.stage.as_mut().unwrap();
        stage.configured_disposition = configured;
        stage.effective_disposition = EffectiveDisposition::Quarantined;
        stage.quarantine_id = Some(SafeId::new("quarantine_override").unwrap());
        rebuild(error).expect("error fail-safe quarantine override");
    }

    let mut allow = parse(ALLOW);
    let stage = allow.stage.as_mut().unwrap();
    stage.effective_disposition = EffectiveDisposition::Quarantined;
    stage.handoff_status = HandoffStatus::Unavailable;
    stage.reference = None;
    stage.expires_at = None;
    stage.quarantine_id = Some(SafeId::new("quarantine_invalid").unwrap());
    assert!(matches!(
        rebuild(allow),
        Err(ReportError::DispositionMismatch)
    ));

    let mut error = parse(DENY);
    error.outcome = ProcessingOutcome::Error;
    error.exit_code = 30;
    error.issues = vec![file_guardian::processing::report::IssueSummary {
        code: SafeId::new("processing_failed").unwrap(),
        phase: None,
        component_id: None,
    }];
    error.stage.as_mut().unwrap().configured_disposition =
        file_guardian::processing::report::ConfiguredDisposition::Retain;
    assert!(matches!(
        rebuild(error),
        Err(ReportError::DispositionMismatch)
    ));
}

#[test]
fn unknown_fields_and_noncanonical_arrays_are_rejected_at_every_boundary() {
    let mut top: Value = serde_json::from_str(ERROR).unwrap();
    top["private_path"] = json!("/var/lib/file-guardian/jobs/run_error");
    assert!(serde_json::from_value::<ProcessingReport>(top).is_err());

    let mut nested: Value = serde_json::from_str(ALLOW).unwrap();
    nested["stage"]["content_digest"] = json!("sha256:deadbeef");
    assert!(serde_json::from_value::<ProcessingReport>(nested).is_err());

    let mut reordered = parse(ALLOW_MODIFIED);
    reordered.actions[0].finding_ids = vec![
        SafeId::new("finding_2").unwrap(),
        SafeId::new("finding_1").unwrap(),
    ];
    assert!(matches!(
        reordered.validate(),
        Err(ReportError::NonCanonicalOrder)
    ));
}

#[test]
fn error_may_omit_bounded_details_but_decisions_may_not() {
    let mut error: Value = serde_json::from_str(ERROR).unwrap();
    error["omissions"] = json!({
        "details_omitted": true,
        "reason": "report_size_limit"
    });
    assert!(serde_json::from_value::<ProcessingReport>(error).is_ok());

    let mut allow = parse(ALLOW);
    allow.omissions = OmissionSummary {
        details_omitted: true,
        reason: Some(SafeId::new("report_size_limit").unwrap()),
    };
    assert!(matches!(
        allow.validate(),
        Err(ReportError::DecisionOmittedDetails)
    ));
}

#[test]
fn public_goldens_contain_no_raw_content_digest_or_private_report_fields() {
    fn inspect(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(!matches!(
                        key.as_str(),
                        "content_digest"
                            | "absolute_path"
                            | "source_path"
                            | "remote_url"
                            | "stdout"
                            | "stderr"
                            | "snippet"
                            | "matched_value"
                            | "prompt"
                            | "transcript"
                            | "environment"
                    ));
                    inspect(value);
                }
            }
            Value::Array(values) => values.iter().for_each(inspect),
            _ => {}
        }
    }

    for source in [ALLOW, ALLOW_MODIFIED, DENY, ERROR] {
        inspect(&serde_json::from_str(source).unwrap());
    }
}
