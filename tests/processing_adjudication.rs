use std::collections::BTreeSet;

use file_guardian::analyzers::pi::triage::{
    BoundPiFindingAssessment, PiReviewScope, PiStageAttestation, PiTriageCoverage, PiTriageLimits,
    PiTriageRequest, PiTriageRequestContext, PiTriageResult, PriorFinding, PriorFindingArtifact,
    PriorOccurrence,
};
use file_guardian::domain::{
    AnalyzerId, ArtifactId, ConfiguredConfidence, Digest, FindingCategory, InspectionPhase,
    LogicalPath, PathSegment, ReasonCode, RuleId, RunId, Severity,
};
use file_guardian::processing::adjudication::{
    adjudicate_pi, AdjudicationError, AnalysisIntegrity, PiAnalysis,
};
use file_guardian::processing::config::PiAdjudicationMode;
use file_guardian::processing::domain::{
    AdjudicationReason, AdjudicationState, CorrelationId, CredentialVerificationState, FindingId,
    GitHistoryScope, OccurrenceId, PiFindingAssessment, PiFindingClassification, RecommendedAction,
};
use file_guardian::processing::executor::{PiAnalysisExpectation, ValidatedPiAnalysis};
use file_guardian::processing::runtime::CompiledPiAdjudication;

fn finding(suffix: &str, rule: &str, verification: CredentialVerificationState) -> PriorFinding {
    PriorFinding::new(
        FindingId::from_suffix(suffix).unwrap(),
        CorrelationId::from_suffix(suffix).unwrap(),
        InspectionPhase::Initial,
        AnalyzerId::new("gitleaks").unwrap(),
        RuleId::new(rule).unwrap(),
        ArtifactId::from_suffix(suffix).unwrap(),
        PriorFindingArtifact::WorkingTree {
            logical_path: LogicalPath::new(vec![
                PathSegment::utf8(format!("{suffix}.txt")).unwrap()
            ])
            .unwrap(),
        },
        FindingCategory::Credential,
        Severity::Critical,
        None,
        None,
        vec![PriorOccurrence {
            occurrence_id: OccurrenceId::from_suffix(suffix).unwrap(),
            analyzer_id: AnalyzerId::new("gitleaks").unwrap(),
            rule_id: RuleId::new(rule).unwrap(),
            verification_state: verification,
            evidence_token: None,
            evidence: None,
        }],
    )
    .unwrap()
}

fn assessment(
    finding: &PriorFinding,
    classification: PiFindingClassification,
) -> BoundPiFindingAssessment {
    BoundPiFindingAssessment {
        finding_id: finding.finding_id.clone(),
        assessment: PiFindingAssessment {
            classification,
            // Confidence and reason codes are retained as Pi's audit metadata;
            // they are not a second host veto over the trusted judgment.
            confidence: ConfiguredConfidence::Low,
            reason_codes: vec![ReasonCode::new("semantic_review").unwrap()],
            duplicate_of: None,
            recommended_action: RecommendedAction::None,
        },
    }
}

fn complete_analysis(
    findings: Vec<PriorFinding>,
    assessments: Vec<BoundPiFindingAssessment>,
    attestation: PiStageAttestation,
) -> ValidatedPiAnalysis {
    let request = PiTriageRequest::new(
        PiTriageRequestContext {
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
        },
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
    ValidatedPiAnalysis::new(
        request.clone(),
        result.clone(),
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
        },
    )
    .unwrap()
}

fn policy(mode: PiAdjudicationMode) -> CompiledPiAdjudication {
    CompiledPiAdjudication {
        analyzer: AnalyzerId::new("pi-triage").unwrap(),
        mode,
        required_initial: mode == PiAdjudicationMode::Authoritative,
        required_after_actions: mode == PiAdjudicationMode::Authoritative,
    }
}

fn blocking(finding: &PriorFinding) -> BTreeSet<OccurrenceId> {
    BTreeSet::from([finding.occurrences[0].occurrence_id.clone()])
}

#[test]
fn advisory_pi_records_but_does_not_clear() {
    let finding = finding(
        "fixture",
        "private-key",
        CredentialVerificationState::Verified,
    );
    let analysis = complete_analysis(
        vec![finding.clone()],
        vec![assessment(&finding, PiFindingClassification::FalsePositive)],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let decision = adjudicate_pi(
        Some(&policy(PiAdjudicationMode::Advisory)),
        InspectionPhase::Initial,
        std::slice::from_ref(&finding),
        &blocking(&finding),
        PiAnalysis::Complete(&analysis),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();
    assert!(decision.cleared_finding_ids.is_empty());
    assert_eq!(decision.adjudications[0].state, AdjudicationState::Advisory);
}

#[test]
fn authoritative_pi_can_override_any_routed_deterministic_finding() {
    let finding = finding(
        "fixture",
        "private-key",
        CredentialVerificationState::Verified,
    );
    let analysis = complete_analysis(
        vec![finding.clone()],
        vec![assessment(&finding, PiFindingClassification::FalsePositive)],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    let decision = adjudicate_pi(
        Some(&policy(PiAdjudicationMode::Authoritative)),
        InspectionPhase::Initial,
        std::slice::from_ref(&finding),
        &blocking(&finding),
        PiAnalysis::Complete(&analysis),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();
    assert_eq!(
        decision.cleared_finding_ids,
        BTreeSet::from([finding.finding_id])
    );
    assert_eq!(decision.adjudications[0].state, AdjudicationState::Applied);
    assert_eq!(
        decision.adjudications[0].reason,
        AdjudicationReason::ClearedFalsePositive
    );
}

#[test]
fn authoritative_pi_does_not_clear_a_finding_it_confirms() {
    let finding = finding(
        "real",
        "generic-password",
        CredentialVerificationState::Unverified,
    );
    let analysis = complete_analysis(
        vec![finding.clone()],
        vec![assessment(&finding, PiFindingClassification::Confirmed)],
        PiStageAttestation::BlockingConcernsObserved,
    );
    let decision = adjudicate_pi(
        Some(&policy(PiAdjudicationMode::Authoritative)),
        InspectionPhase::Initial,
        std::slice::from_ref(&finding),
        &blocking(&finding),
        PiAnalysis::Complete(&analysis),
        AnalysisIntegrity::complete_unchanged(),
    )
    .unwrap();
    assert!(decision.cleared_finding_ids.is_empty());
    assert_eq!(
        decision.adjudications[0].reason,
        AdjudicationReason::AssessmentNotFalsePositive
    );
    assert_eq!(
        decision.stage_attestation,
        Some(PiStageAttestation::BlockingConcernsObserved)
    );
}

#[test]
fn authoritative_pi_requires_a_complete_stage_judgment() {
    let finding = finding(
        "fixture",
        "generic-password",
        CredentialVerificationState::Unverified,
    );
    let analysis = complete_analysis(
        vec![finding.clone()],
        vec![assessment(&finding, PiFindingClassification::FalsePositive)],
        PiStageAttestation::UnableToAssert,
    );
    assert_eq!(
        adjudicate_pi(
            Some(&policy(PiAdjudicationMode::Authoritative)),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(&finding),
            PiAnalysis::Complete(&analysis),
            AnalysisIntegrity::complete_unchanged(),
        ),
        Err(AdjudicationError::RequiredPiIncomplete)
    );
}

#[test]
fn required_pi_absence_and_stale_host_state_fail_closed() {
    let finding = finding(
        "fixture",
        "generic-password",
        CredentialVerificationState::Unverified,
    );
    let authoritative = policy(PiAdjudicationMode::Authoritative);
    assert_eq!(
        adjudicate_pi(
            Some(&authoritative),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(&finding),
            PiAnalysis::NotRun,
            AnalysisIntegrity::complete_unchanged(),
        ),
        Err(AdjudicationError::RequiredPiIncomplete)
    );

    let analysis = complete_analysis(
        vec![finding.clone()],
        vec![assessment(&finding, PiFindingClassification::FalsePositive)],
        PiStageAttestation::NoBlockingConcernsObserved,
    );
    assert_eq!(
        adjudicate_pi(
            Some(&authoritative),
            InspectionPhase::Initial,
            std::slice::from_ref(&finding),
            &blocking(&finding),
            PiAnalysis::Complete(&analysis),
            AnalysisIntegrity {
                snapshot_stable: false,
                ..AnalysisIntegrity::complete_unchanged()
            },
        ),
        Err(AdjudicationError::IncompleteAnalysis)
    );
}
