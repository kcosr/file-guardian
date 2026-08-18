use std::collections::BTreeSet;

use file_guardian::analyzers::pi::triage::{
    BoundPiFindingAssessment, PiReviewScope, PiStageAttestation, PiTriageCoverage, PiTriageLimits,
    PiTriageRequest, PiTriageRequestContext, PiTriageResult, PriorFinding, PriorOccurrence,
};
use file_guardian::domain::{
    AnalyzerId, ArtifactId, ConfiguredConfidence, Digest, FindingCategory, InspectionPhase,
    ReasonCode, RuleId, RunId, Severity,
};
use file_guardian::processing::adjudication::{
    adjudicate_pi, AdjudicationError, AnalysisIntegrity, PiAnalysis,
};
use file_guardian::processing::config::{
    AttestationRequirement, Confidence, PiAdjudicationMode, Severity as ConfigSeverity,
    VerificationState,
};
use file_guardian::processing::domain::{
    AdjudicationReason, AdjudicationState, ClearanceRuleId, CorrelationId,
    CredentialVerificationState, FindingId, GitHistoryScope, OccurrenceId, PiFindingAssessment,
    PiFindingClassification, RecommendedAction,
};
use file_guardian::processing::executor::{
    PiAnalysisBindingError, PiAnalysisExpectation, ValidatedPiAnalysis,
};
use file_guardian::processing::runtime::{CompiledClearanceRule, CompiledPiAdjudication};

fn occurrence(
    suffix: &str,
    analyzer: &str,
    rule: &str,
    verification: CredentialVerificationState,
) -> PriorOccurrence {
    PriorOccurrence {
        occurrence_id: OccurrenceId::from_suffix(suffix).unwrap(),
        analyzer_id: AnalyzerId::new(analyzer).unwrap(),
        rule_id: RuleId::new(rule).unwrap(),
        verification_state: verification,
        evidence_token: None,
    }
}

fn finding(
    suffix: &str,
    correlation: &str,
    rule: &str,
    category: FindingCategory,
    severity: Severity,
    verification: CredentialVerificationState,
) -> PriorFinding {
    PriorFinding::new(
        FindingId::from_suffix(suffix).unwrap(),
        CorrelationId::from_suffix(correlation).unwrap(),
        InspectionPhase::Initial,
        AnalyzerId::new("gitleaks").unwrap(),
        RuleId::new(rule).unwrap(),
        ArtifactId::from_suffix(suffix).unwrap(),
        category,
        severity,
        None,
        None,
        vec![occurrence(suffix, "gitleaks", rule, verification)],
    )
    .unwrap()
}

fn assessment(
    finding: &PriorFinding,
    classification: PiFindingClassification,
    confidence: ConfiguredConfidence,
    reasons: &[&str],
) -> BoundPiFindingAssessment {
    BoundPiFindingAssessment {
        finding_id: finding.finding_id.clone(),
        assessment: PiFindingAssessment {
            classification,
            confidence,
            reason_codes: reasons
                .iter()
                .map(|reason| ReasonCode::new(*reason).unwrap())
                .collect(),
            duplicate_of: None,
            recommended_action: RecommendedAction::None,
        },
    }
}

fn complete_analysis(
    findings: Vec<PriorFinding>,
    assessments: Vec<BoundPiFindingAssessment>,
    attestation: PiStageAttestation,
) -> (PiTriageRequest, PiTriageResult) {
    let context = PiTriageRequestContext {
        run_id: RunId::from_suffix("adjudication").unwrap(),
        invocation_id: file_guardian::analyzers::pi::triage::PiTriageInvocationId::new(
            "pii_adjudication",
        )
        .unwrap(),
        phase: InspectionPhase::Initial,
        manifest_identity: Digest::sha256(b"manifest"),
        pipeline_identity: Digest::sha256(b"pipeline"),
        policy_identity: Digest::sha256(b"policy"),
        prompt_template_identity: Digest::sha256(b"prompt"),
        prior_observations_identity: Digest::sha256(b"prior"),
        review_scope: PiReviewScope::new(true, GitHistoryScope::None).unwrap(),
        assigned_artifact_count: findings.len() as u64,
        prior_coverage: Vec::new(),
    };
    let request = PiTriageRequest::new(
        context,
        findings,
        PiTriageLimits::new(64, 8, 1_000_000, 1_000_000, 8).unwrap(),
    )
    .unwrap();
    let count = assessments.len() as u64;
    let result = PiTriageResult {
        assessments,
        stage_attestation: attestation,
        coverage: PiTriageCoverage {
            assigned_artifact_count: count,
            completed_artifact_count: count,
            not_applicable_artifact_count: 0,
            assigned_finding_count: count,
            assessed_finding_count: count,
        },
    };
    (request, result)
}

fn validated_analysis(request: &PiTriageRequest, result: &PiTriageResult) -> ValidatedPiAnalysis {
    ValidatedPiAnalysis::new(
        request.clone(),
        result.clone(),
        analysis_expectation(request, result),
    )
    .unwrap()
}

fn analysis_expectation(
    request: &PiTriageRequest,
    result: &PiTriageResult,
) -> PiAnalysisExpectation {
    PiAnalysisExpectation {
        run_id: request.run_id.clone(),
        phase: request.phase,
        manifest_identity: request.manifest_identity,
        pipeline_identity: request.pipeline_identity,
        policy_identity: request.policy_identity,
        prompt_template_identity: request.prompt_template_identity,
        prior_observations_identity: request.prior_observations_identity,
        prior_coverage: request.prior_coverage.clone(),
        assigned_artifact_count: request.assigned_artifact_count,
        completed_artifact_count: result.coverage.completed_artifact_count,
        not_applicable_artifact_count: result.coverage.not_applicable_artifact_count,
        findings: request.findings.clone(),
    }
}

fn clearance_rule() -> CompiledClearanceRule {
    CompiledClearanceRule {
        id: ClearanceRuleId::from_suffix("fixture").unwrap(),
        analyzer: AnalyzerId::new("gitleaks").unwrap(),
        rules: vec![RuleId::new("generic-password").unwrap()],
        categories: vec!["credential".to_owned()],
        maximum_severity: ConfigSeverity::Medium,
        verification_states: vec![VerificationState::Unverified],
        reason_codes: vec![ReasonCode::new("documented_test_fixture").unwrap()],
    }
}

fn policy() -> CompiledPiAdjudication {
    CompiledPiAdjudication {
        analyzer: AnalyzerId::new("pi-triage").unwrap(),
        mode: PiAdjudicationMode::ClearFalsePositives,
        required_initial: true,
        required_after_actions: true,
        minimum_confidence: Some(Confidence::High),
        initial_attestation: AttestationRequirement::DenyOnBlocking,
        post_action_attestation: AttestationRequirement::RequireNoBlocking,
        non_clearable_categories: Vec::new(),
        non_clearable_minimum_severity: None,
        non_clearable_verification_states: Vec::new(),
        hard_block_rules: Vec::new(),
        clearance_rules: vec![clearance_rule()],
    }
}

fn exact_fixture() -> PriorFinding {
    finding(
        "fixture",
        "fixture",
        "generic-password",
        FindingCategory::Credential,
        Severity::Medium,
        CredentialVerificationState::Unverified,
    )
}

fn blocking(findings: &[PriorFinding]) -> BTreeSet<OccurrenceId> {
    findings
        .iter()
        .flat_map(|finding| &finding.occurrences)
        .map(|occurrence| occurrence.occurrence_id.clone())
        .collect()
}

#[test]
fn no_policy_is_advisory_even_when_pi_calls_it_false_positive() {
    let finding = exact_fixture();
    let (request, result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let decision = adjudicate_pi(
        None,
        InspectionPhase::Initial,
        std::slice::from_ref(&finding),
        &blocking(std::slice::from_ref(&finding)),
        PiAnalysis::Complete(&validated_analysis(&request, &result)),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();

    assert!(decision.cleared_finding_ids.is_empty());
    assert_eq!(decision.adjudications[0].state, AdjudicationState::Advisory);
    assert_eq!(
        decision.adjudications[0].reason,
        AdjudicationReason::AdvisoryOnly
    );
}

#[test]
fn only_an_exact_high_confidence_clearance_rule_applies() {
    let finding = exact_fixture();
    let (request, result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let decision = adjudicate_pi(
        Some(&policy()),
        InspectionPhase::Initial,
        std::slice::from_ref(&finding),
        &blocking(std::slice::from_ref(&finding)),
        PiAnalysis::Complete(&validated_analysis(&request, &result)),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();

    assert_eq!(
        decision.cleared_finding_ids,
        BTreeSet::from([finding.finding_id.clone()])
    );
    assert_eq!(decision.adjudications[0].state, AdjudicationState::Applied);
    assert_eq!(
        decision.adjudications[0].clearance_rule_id,
        Some(ClearanceRuleId::from_suffix("fixture").unwrap())
    );
}

#[test]
fn confidence_classification_and_reason_codes_are_fail_closed() {
    let cases = [
        (
            PiFindingClassification::LikelyFalsePositive,
            ConfiguredConfidence::High,
            vec!["documented_test_fixture"],
            AdjudicationReason::AssessmentNotFalsePositive,
        ),
        (
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::Medium,
            vec!["documented_test_fixture"],
            AdjudicationReason::ConfidenceTooLow,
        ),
        (
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            vec!["other_reason"],
            AdjudicationReason::ReasonCodeMismatch,
        ),
    ];
    for (classification, confidence, reasons, expected) in cases {
        let finding = exact_fixture();
        let (request, result) = complete_analysis(
            vec![finding.clone()],
            vec![assessment(&finding, classification, confidence, &reasons)],
            PiStageAttestation::NoBlockingConcernsObserved,
        );
        let decision = adjudicate_pi(
            Some(&policy()),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(std::slice::from_ref(&finding)),
            PiAnalysis::Complete(&validated_analysis(&request, &result)),
            AnalysisIntegrity::complete_unchanged(),
        )
        .unwrap();
        assert!(decision.cleared_finding_ids.is_empty());
        assert_eq!(decision.adjudications[0].reason, expected);
    }
}

#[test]
fn fixed_verified_private_key_and_critical_findings_never_clear() {
    let cases = [
        finding(
            "verified",
            "verified",
            "generic-password",
            FindingCategory::Credential,
            Severity::Medium,
            CredentialVerificationState::Verified,
        ),
        finding(
            "private",
            "private",
            "private-key",
            FindingCategory::Credential,
            Severity::Medium,
            CredentialVerificationState::Unverified,
        ),
        finding(
            "critical",
            "critical",
            "generic-password",
            FindingCategory::Credential,
            Severity::Critical,
            CredentialVerificationState::Unverified,
        ),
    ];
    for finding in cases {
        let (request, result) = complete_analysis(
            vec![finding.clone()],
            vec![assessment(
                &finding,
                PiFindingClassification::FalsePositive,
                ConfiguredConfidence::High,
                &["documented_test_fixture"],
            )],
            PiStageAttestation::NoBlockingConcernsObserved,
        );
        let decision = adjudicate_pi(
            Some(&policy()),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(std::slice::from_ref(&finding)),
            PiAnalysis::Complete(&validated_analysis(&request, &result)),
            AnalysisIntegrity::complete_unchanged(),
        )
        .unwrap();
        assert!(decision.cleared_finding_ids.is_empty());
        assert_eq!(
            decision.adjudications[0].reason,
            AdjudicationReason::NonClearable
        );
    }
}

#[test]
fn configured_non_clearable_selectors_only_make_policy_stricter() {
    let finding = exact_fixture();
    let (request, result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let mut policy = policy();
    policy.hard_block_rules = vec![RuleId::new("generic-password").unwrap()];
    let decision = adjudicate_pi(
        Some(&policy),
        InspectionPhase::Initial,
        std::slice::from_ref(&finding),
        &blocking(std::slice::from_ref(&finding)),
        PiAnalysis::Complete(&validated_analysis(&request, &result)),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();
    assert!(decision.cleared_finding_ids.is_empty());
    assert_eq!(
        decision.adjudications[0].reason,
        AdjudicationReason::NonClearable
    );
}

#[test]
fn one_ineligible_occurrence_preserves_the_entire_blocking_correlation() {
    let eligible = exact_fixture();
    let ineligible = finding(
        "other",
        "fixture",
        "unconfigured-rule",
        FindingCategory::Credential,
        Severity::Medium,
        CredentialVerificationState::Unverified,
    );
    let findings = vec![eligible.clone(), ineligible.clone()];
    let (request, result) = complete_analysis(
        findings.clone(),
        vec![
            assessment(
                &eligible,
                PiFindingClassification::FalsePositive,
                ConfiguredConfidence::High,
                &["documented_test_fixture"],
            ),
            assessment(
                &ineligible,
                PiFindingClassification::FalsePositive,
                ConfiguredConfidence::High,
                &["documented_test_fixture"],
            ),
        ],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let decision = adjudicate_pi(
        Some(&policy()),
        InspectionPhase::Initial,
        &findings,
        &blocking(&findings),
        PiAnalysis::Complete(&validated_analysis(&request, &result)),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();

    assert!(decision.cleared_finding_ids.is_empty());
    assert_eq!(
        decision.adjudications[0].reason,
        AdjudicationReason::CorrelationNotCleared
    );
    assert_eq!(decision.adjudications[1].state, AdjudicationState::Rejected);
}

#[test]
fn required_pi_absence_or_incomplete_coverage_is_an_error() {
    let finding = exact_fixture();
    assert_eq!(
        adjudicate_pi(
            Some(&policy()),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(std::slice::from_ref(&finding)),
            PiAnalysis::NotRun,
            AnalysisIntegrity::complete_unchanged(),
        ),
        Err(AdjudicationError::RequiredPiIncomplete)
    );

    let (request, mut result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    result.coverage.assessed_finding_count = 0;
    assert_eq!(
        ValidatedPiAnalysis::new(
            request.clone(),
            result.clone(),
            analysis_expectation(&request, &result),
        ),
        Err(PiAnalysisBindingError::ResultBinding)
    );
    assert_eq!(
        adjudicate_pi(
            Some(&policy()),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(std::slice::from_ref(&finding)),
            PiAnalysis::Failed,
            AnalysisIntegrity::complete_unchanged(),
        ),
        Err(AdjudicationError::RequiredPiIncomplete)
    );
}

#[test]
fn validated_pi_analysis_preserves_the_exact_host_bound_handoff() {
    let finding = exact_fixture();
    let (request, result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );

    let analysis = validated_analysis(&request, &result);
    assert_eq!(analysis.request(), &request);
    assert_eq!(analysis.result(), &result);
}

#[test]
fn validated_pi_analysis_rejects_stale_or_wrong_host_bindings() {
    let finding = exact_fixture();
    let (request, result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );

    let mut stale_request = request.clone();
    stale_request.request_identity = Digest::sha256(b"stale-request");
    assert_eq!(
        ValidatedPiAnalysis::new(
            stale_request,
            result.clone(),
            analysis_expectation(&request, &result),
        ),
        Err(PiAnalysisBindingError::RequestBinding)
    );

    let mut wrong_manifest = analysis_expectation(&request, &result);
    wrong_manifest.manifest_identity = Digest::sha256(b"wrong-manifest");
    assert_eq!(
        ValidatedPiAnalysis::new(request.clone(), result.clone(), wrong_manifest),
        Err(PiAnalysisBindingError::RequestBinding)
    );

    let mut wrong_prior = analysis_expectation(&request, &result);
    wrong_prior.prior_observations_identity = Digest::sha256(b"wrong-prior");
    assert_eq!(
        ValidatedPiAnalysis::new(request.clone(), result.clone(), wrong_prior),
        Err(PiAnalysisBindingError::RequestBinding)
    );

    let mut wrong_coverage = result.clone();
    wrong_coverage.coverage.completed_artifact_count = 0;
    wrong_coverage.coverage.not_applicable_artifact_count = 1;
    assert_eq!(
        ValidatedPiAnalysis::new(
            request.clone(),
            wrong_coverage,
            analysis_expectation(&request, &result),
        ),
        Err(PiAnalysisBindingError::ResultBinding)
    );
}

#[test]
fn every_host_integrity_gate_is_required_for_authoritative_clearance() {
    let finding = exact_fixture();
    let (request, result) = complete_analysis(
        vec![finding.clone()],
        vec![assessment(
            &finding,
            PiFindingClassification::FalsePositive,
            ConfiguredConfidence::High,
            &["documented_test_fixture"],
        )],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let base = AnalysisIntegrity::complete_unchanged();
    let incomplete = [
        AnalysisIntegrity {
            required_deterministic_analysis_complete: false,
            ..base
        },
        AnalysisIntegrity {
            sandbox_accounting_complete: false,
            ..base
        },
        AnalysisIntegrity {
            snapshot_stable: false,
            ..base
        },
        AnalysisIntegrity {
            mutation_committed: true,
            fresh_final_verification: false,
            ..base
        },
    ];
    for integrity in incomplete {
        assert_eq!(
            adjudicate_pi(
                Some(&policy()),
                InspectionPhase::Initial,
                std::slice::from_ref(&finding),
                &blocking(std::slice::from_ref(&finding)),
                PiAnalysis::Complete(&validated_analysis(&request, &result)),
                integrity,
            ),
            Err(AdjudicationError::IncompleteAnalysis)
        );
    }
}

#[test]
fn findings_and_occurrences_must_be_canonical_and_phase_bound() {
    let finding = exact_fixture();
    let duplicate = finding.clone();
    assert!(matches!(
        adjudicate_pi(
            None,
            InspectionPhase::Initial,
            &[finding, duplicate],
            &BTreeSet::new(),
            PiAnalysis::NotRun,
            AnalysisIntegrity::complete_unchanged(),
        ),
        Err(AdjudicationError::InvalidInput(_))
    ));
}
