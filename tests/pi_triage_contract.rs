use file_guardian::analyzers::pi::triage::{
    parse_and_normalize_terminal, PiReviewScope, PiStageAttestation, PiTriageAssessmentWire,
    PiTriageCoverage, PiTriageError, PiTriageInvocationId, PiTriageLimits, PiTriageRequest,
    PiTriageRequestContext, PiTriageSubmissionStatus, PiTriageTerminalSubmission,
    PiTriageVocabulary, PriorFinding, PriorOccurrence, TRIAGE_TERMINAL_SCHEMA,
};
use file_guardian::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, ConfiguredConfidence, CoverageStatus, Digest,
    FindingCategory, InspectionPhase, ReasonCode, RuleId, RunId, Severity, ValidatedLocation,
};
use file_guardian::processing::{
    CorrelationId, CredentialVerificationState, FindingId, GitHistoryScope, OccurrenceId,
    PiFindingClassification, RecommendedAction,
};
use serde_json::{json, Value};

fn limits() -> PiTriageLimits {
    PiTriageLimits::new(16, 8, 64 * 1024, 64 * 1024, 8).unwrap()
}

fn reason(value: &str) -> ReasonCode {
    ReasonCode::new(value).unwrap()
}

fn finding(suffix: &str) -> PriorFinding {
    PriorFinding::new(
        FindingId::from_suffix(suffix).unwrap(),
        CorrelationId::from_suffix(format!("group-{suffix}")).unwrap(),
        InspectionPhase::Initial,
        AnalyzerId::new("gitleaks").unwrap(),
        RuleId::new("generic-password").unwrap(),
        ArtifactId::from_suffix(format!("artifact-{suffix}")).unwrap(),
        FindingCategory::Credential,
        Severity::Medium,
        Some(ValidatedLocation::line_column(4, 12).unwrap()),
        Some(Digest::sha256(format!("opaque-token-{suffix}"))),
        vec![PriorOccurrence {
            occurrence_id: OccurrenceId::from_suffix(format!("occ-{suffix}")).unwrap(),
            analyzer_id: AnalyzerId::new("gitleaks").unwrap(),
            rule_id: RuleId::new("generic-password").unwrap(),
            verification_state: CredentialVerificationState::Unverified,
            evidence_token: Some(Digest::sha256(format!("opaque-token-{suffix}"))),
        }],
    )
    .unwrap()
}

fn context() -> PiTriageRequestContext {
    PiTriageRequestContext {
        run_id: RunId::from_suffix("triage-contract").unwrap(),
        invocation_id: PiTriageInvocationId::new("pii_initial-1").unwrap(),
        phase: InspectionPhase::Initial,
        manifest_identity: Digest::sha256(b"sealed-manifest"),
        pipeline_identity: Digest::sha256(b"pipeline"),
        policy_identity: Digest::sha256(b"policy"),
        prompt_template_identity: Digest::sha256(b"prompt-template"),
        prior_observations_identity: Digest::sha256(b"safe-prior-findings"),
        review_scope: PiReviewScope::new(true, GitHistoryScope::Head).unwrap(),
        assigned_artifact_count: 3,
        prior_coverage: vec![AnalyzerCoverage::new(
            AnalyzerId::new("gitleaks").unwrap(),
            InspectionPhase::Initial,
            3,
            3,
            3,
            0,
            CoverageStatus::Complete,
        )
        .unwrap()],
    }
}

fn request_with(findings: Vec<PriorFinding>) -> PiTriageRequest {
    PiTriageRequest::new(context(), findings, limits()).unwrap()
}

fn vocabulary() -> PiTriageVocabulary {
    PiTriageVocabulary::new([
        reason("documented_test_fixture"),
        reason("example_placeholder"),
        reason("insufficient_context"),
    ])
}

fn submission(request: &PiTriageRequest) -> PiTriageTerminalSubmission {
    PiTriageTerminalSubmission {
        schema_version: TRIAGE_TERMINAL_SCHEMA.to_string(),
        invocation_id: request.invocation_id.clone(),
        phase: request.phase,
        manifest_identity: request.manifest_identity,
        request_identity: request.request_identity,
        prior_observations_identity: request.prior_observations_identity,
        status: PiTriageSubmissionStatus::Complete,
        assessments: request
            .findings
            .iter()
            .map(|finding| PiTriageAssessmentWire {
                finding_id: finding.finding_id.clone(),
                classification: PiFindingClassification::FalsePositive,
                confidence: ConfiguredConfidence::High,
                reason_codes: vec![reason("documented_test_fixture")],
                duplicate_of: None,
                recommended_action: RecommendedAction::None,
            })
            .collect(),
        stage_attestation: PiStageAttestation::NoBlockingConcernsObserved,
        coverage: PiTriageCoverage {
            assigned_artifact_count: request.assigned_artifact_count,
            completed_artifact_count: 2,
            not_applicable_artifact_count: 1,
            assigned_finding_count: request.findings.len() as u64,
            assessed_finding_count: request.findings.len() as u64,
        },
    }
}

fn parse(
    request: &PiTriageRequest,
    terminal: &PiTriageTerminalSubmission,
) -> Result<file_guardian::analyzers::pi::triage::PiTriageResult, PiTriageError> {
    parse_and_normalize_terminal(
        &serde_json::to_vec(terminal).unwrap(),
        request,
        &vocabulary(),
        limits(),
    )
}

#[test]
fn canonical_request_is_identity_bound_and_content_free() {
    let request = request_with(vec![finding("b"), finding("a")]);
    assert_eq!(request.findings[0].finding_id.as_str(), "fnd_a");
    request.validate_identity().unwrap();
    assert_eq!(
        request.canonical_json().unwrap(),
        request.canonical_json().unwrap()
    );

    let json = String::from_utf8(request.canonical_json().unwrap()).unwrap();
    for forbidden in [
        "hunter2",
        "password =",
        "matched_value",
        "snippet",
        "stdout",
        "stderr",
        "remote_url",
        "/home/kevin",
        "SSH_AUTH_SOCK",
        "prompt_transcript",
        "rationale",
    ] {
        assert!(
            !json.contains(forbidden),
            "leaked forbidden value {forbidden}"
        );
    }
}

#[test]
fn exact_false_positive_normalizes_to_processing_assessment() {
    let request = request_with(vec![finding("one")]);
    let result = parse(&request, &submission(&request)).unwrap();
    let bound = &result.assessments[0];
    assert_eq!(bound.finding_id.as_str(), "fnd_one");
    assert_eq!(
        bound.assessment.classification,
        PiFindingClassification::FalsePositive
    );
    assert_eq!(bound.assessment.confidence, ConfiguredConfidence::High);
    assert_eq!(
        bound.assessment.reason_codes,
        vec![reason("documented_test_fixture")]
    );
    assert_eq!(bound.assessment.recommended_action, RecommendedAction::None);
    assert_eq!(
        result.stage_attestation,
        PiStageAttestation::NoBlockingConcernsObserved
    );
}

#[test]
fn stale_bindings_are_rejected() {
    let request = request_with(vec![finding("one")]);

    let mut terminal = submission(&request);
    terminal.manifest_identity = Digest::sha256(b"stale");
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::ManifestMismatch)
    ));

    let mut terminal = submission(&request);
    terminal.request_identity = Digest::sha256(b"stale");
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::RequestMismatch)
    ));

    let mut terminal = submission(&request);
    terminal.prior_observations_identity = Digest::sha256(b"stale");
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::PriorObservationsMismatch)
    ));

    let mut terminal = submission(&request);
    terminal.phase = InspectionPhase::Verification;
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::PhaseMismatch)
    ));

    let mut terminal = submission(&request);
    terminal.invocation_id = PiTriageInvocationId::new("pii_foreign").unwrap();
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::InvocationMismatch)
    ));
}

#[test]
fn foreign_duplicate_and_missing_findings_fail_closed() {
    let request = request_with(vec![finding("one"), finding("two")]);

    let mut terminal = submission(&request);
    terminal.assessments[1].finding_id = FindingId::from_suffix("foreign").unwrap();
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::ForeignFinding)
    ));

    let mut terminal = submission(&request);
    terminal.assessments[1].finding_id = terminal.assessments[0].finding_id.clone();
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::DuplicateAssessment)
    ));

    let mut terminal = submission(&request);
    terminal.assessments.pop();
    terminal.coverage.assessed_finding_count = 1;
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::MissingFinding)
    ));
}

#[test]
fn cardinality_and_closed_reason_vocabulary_are_enforced() {
    let request = request_with(vec![finding("one")]);

    let mut terminal = submission(&request);
    terminal.coverage.completed_artifact_count = 1;
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::CoverageMismatch)
    ));

    let mut terminal = submission(&request);
    terminal.coverage.assessed_finding_count = 0;
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::CoverageMismatch)
    ));

    let mut terminal = submission(&request);
    terminal.assessments[0].reason_codes = vec![reason("model_invented_reason")];
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::ForeignReasonCode)
    ));
}

#[test]
fn request_terminal_and_reason_limits_fail_before_truncation() {
    let tiny_findings = PiTriageLimits::new(1, 8, 64 * 1024, 64 * 1024, 8).unwrap();
    assert!(matches!(
        PiTriageRequest::new(
            context(),
            vec![finding("one"), finding("two")],
            tiny_findings
        ),
        Err(PiTriageError::FindingLimitExceeded { limit: 1 })
    ));

    let request = request_with(vec![finding("one")]);
    let bytes = serde_json::to_vec(&submission(&request)).unwrap();
    let tiny_terminal = PiTriageLimits::new(16, 8, 64 * 1024, bytes.len() - 1, 8).unwrap();
    assert!(matches!(
        parse_and_normalize_terminal(&bytes, &request, &vocabulary(), tiny_terminal),
        Err(PiTriageError::TerminalByteLimitExceeded { .. })
    ));

    let mut terminal = submission(&request);
    terminal.assessments[0].reason_codes = vec![
        reason("example_placeholder"),
        reason("documented_test_fixture"),
    ];
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::NonCanonicalReasonCodes)
    ));
}

#[test]
fn assessment_order_is_canonical() {
    let request = request_with(vec![finding("one"), finding("two")]);
    let mut terminal = submission(&request);
    terminal.assessments.reverse();
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::NonCanonicalAssessments)
    ));
}

#[test]
fn candidates_unknown_fields_and_model_prose_are_not_schema_v1() {
    let request = request_with(vec![finding("one")]);
    for (key, payload) in [
        ("candidates", json!([])),
        ("rationale", json!("trust me; this is clean")),
    ] {
        let mut value = serde_json::to_value(submission(&request)).unwrap();
        if key == "rationale" {
            value["assessments"][0][key] = payload;
        } else {
            value[key] = payload;
        }
        assert!(matches!(
            parse_and_normalize_terminal(
                &serde_json::to_vec(&value).unwrap(),
                &request,
                &vocabulary(),
                limits()
            ),
            Err(PiTriageError::InvalidTerminalJson)
        ));
    }

    fn inspect(value: &Value) {
        match value {
            Value::Object(fields) => {
                for forbidden in ["candidates", "rationale", "content", "snippet"] {
                    assert!(!fields.contains_key(forbidden));
                }
                fields.values().for_each(inspect);
            }
            Value::Array(values) => values.iter().for_each(inspect),
            _ => {}
        }
    }
    inspect(&serde_json::to_value(submission(&request)).unwrap());
}

#[test]
fn duplicate_links_must_be_assigned_and_acyclic() {
    let request = request_with(vec![finding("one"), finding("two")]);

    let mut terminal = submission(&request);
    terminal.assessments[0].duplicate_of = Some(FindingId::from_suffix("foreign").unwrap());
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::InvalidDuplicateReference)
    ));

    let mut terminal = submission(&request);
    terminal.assessments[0].duplicate_of = Some(terminal.assessments[1].finding_id.clone());
    terminal.assessments[1].duplicate_of = Some(terminal.assessments[0].finding_id.clone());
    assert!(matches!(
        parse(&request, &terminal),
        Err(PiTriageError::DuplicateCycle)
    ));
}
