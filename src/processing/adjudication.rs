//! Deterministic policy application for Pi finding assessments.
//!
//! Pi supplies normalized assessments; it never selects the job outcome. This
//! module is the sole false-positive clearance boundary. It defaults to
//! advisory behavior and applies a clearance only when every configured and
//! fixed anti-false-allow condition succeeds.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::analyzers::pi::triage::{
    PiStageAttestation, PiTriageRequest, PiTriageResult, PriorFinding, PriorOccurrence,
};
use crate::domain::{ConfiguredConfidence, Digest, FindingCategory, InspectionPhase, Severity};
use crate::processing::config::{
    AttestationRequirement, Confidence, PiAdjudicationMode, Severity as ConfigSeverity,
    VerificationState,
};
use crate::processing::domain::{
    Adjudication, AdjudicationId, AdjudicationReason, AdjudicationState, ClearanceRuleId,
    CredentialVerificationState, FindingId, OccurrenceId, PiFindingAssessment,
    PiFindingClassification,
};
use crate::processing::executor::ValidatedPiAnalysis;
use crate::processing::runtime::{CompiledClearanceRule, CompiledPiAdjudication};

/// Host-observed integrity gates that model output cannot satisfy itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisIntegrity {
    pub required_deterministic_analysis_complete: bool,
    pub sandbox_accounting_complete: bool,
    pub snapshot_stable: bool,
    pub mutation_committed: bool,
    pub fresh_final_verification: bool,
}

impl AnalysisIntegrity {
    pub const fn complete_unchanged() -> Self {
        Self {
            required_deterministic_analysis_complete: true,
            sandbox_accounting_complete: true,
            snapshot_stable: true,
            mutation_committed: false,
            fresh_final_verification: false,
        }
    }

    pub const fn complete_after_actions() -> Self {
        Self {
            required_deterministic_analysis_complete: true,
            sandbox_accounting_complete: true,
            snapshot_stable: true,
            mutation_committed: true,
            fresh_final_verification: true,
        }
    }

    fn is_complete(self, phase: InspectionPhase) -> bool {
        self.required_deterministic_analysis_complete
            && self.sandbox_accounting_complete
            && self.snapshot_stable
            && (!self.mutation_committed
                || (phase == InspectionPhase::Verification && self.fresh_final_verification))
    }
}

/// Pi execution state at the adjudication boundary.
#[derive(Clone, Copy, Debug)]
pub enum PiAnalysis<'a> {
    NotRun,
    Failed,
    Complete(&'a ValidatedPiAnalysis),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdjudicationDecision {
    pub adjudications: Vec<Adjudication>,
    pub cleared_finding_ids: BTreeSet<FindingId>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AdjudicationError {
    #[error("required Pi analysis is absent, failed, incomplete, or stale")]
    RequiredPiIncomplete,
    #[error("false-positive clearance requires complete deterministic and host integrity gates")]
    IncompleteAnalysis,
    #[error("Pi adjudication input is inconsistent: {0}")]
    InvalidInput(&'static str),
}

/// Apply Pi assessments to normalized prior findings without changing them.
///
/// `findings` must be the canonical set assigned to Pi for this phase. Candidate
/// observations are intentionally absent from this v1 contract.
pub fn adjudicate_pi(
    policy: Option<&CompiledPiAdjudication>,
    phase: InspectionPhase,
    findings: &[PriorFinding],
    blocking_occurrence_ids: &BTreeSet<OccurrenceId>,
    analysis: PiAnalysis<'_>,
    integrity: AnalysisIntegrity,
) -> Result<AdjudicationDecision, AdjudicationError> {
    validate_findings(phase, findings, blocking_occurrence_ids)?;
    let required = policy.is_some_and(|value| match phase {
        InspectionPhase::Initial => value.required_initial,
        InspectionPhase::Verification => value.required_after_actions,
    });

    let assessments = match analysis {
        PiAnalysis::Complete(analysis) => {
            match validate_complete_analysis(phase, findings, analysis.request(), analysis.result())
            {
                Ok(assessments) => Some((assessments, analysis.result().stage_attestation)),
                Err(_) if required => return Err(AdjudicationError::RequiredPiIncomplete),
                Err(_) => None,
            }
        }
        PiAnalysis::NotRun | PiAnalysis::Failed if required => {
            return Err(AdjudicationError::RequiredPiIncomplete);
        }
        PiAnalysis::NotRun | PiAnalysis::Failed => None,
    };

    let authoritative =
        policy.is_some_and(|value| value.mode == PiAdjudicationMode::ClearFalsePositives);
    if authoritative && !integrity.is_complete(phase) {
        return Err(AdjudicationError::IncompleteAnalysis);
    }

    let mut adjudications = Vec::with_capacity(findings.len());
    let mut cleared = BTreeSet::new();
    let assessment_map = assessments.as_ref().map(|(values, _)| values);

    for finding in findings {
        let is_blocking = finding
            .occurrences
            .iter()
            .any(|occurrence| blocking_occurrence_ids.contains(&occurrence.occurrence_id));
        let assessment = assessment_map
            .and_then(|values| values.get(&finding.finding_id))
            .copied();
        let (state, rule, reason) = decide_finding(
            policy,
            finding,
            assessment,
            assessments.as_ref().map(|(_, attestation)| *attestation),
            phase,
            is_blocking,
        );
        let adjudication = Adjudication::new(
            adjudication_id(phase, &finding.finding_id),
            phase,
            finding.finding_id.clone(),
            assessment.cloned(),
            state,
            rule.clone(),
            reason,
        )
        .map_err(|_| AdjudicationError::InvalidInput("invalid adjudication record"))?;
        if state == AdjudicationState::Applied {
            cleared.insert(finding.finding_id.clone());
        }
        adjudications.push(adjudication);
    }

    preserve_blocking_correlations(
        findings,
        blocking_occurrence_ids,
        &mut adjudications,
        &mut cleared,
    );
    Ok(AdjudicationDecision {
        adjudications,
        cleared_finding_ids: cleared,
    })
}

fn validate_findings(
    phase: InspectionPhase,
    findings: &[PriorFinding],
    blocking_occurrence_ids: &BTreeSet<OccurrenceId>,
) -> Result<(), AdjudicationError> {
    if findings.iter().any(|finding| finding.phase != phase) {
        return Err(AdjudicationError::InvalidInput("finding phase mismatch"));
    }
    if findings
        .windows(2)
        .any(|pair| pair[0].finding_id >= pair[1].finding_id)
    {
        return Err(AdjudicationError::InvalidInput(
            "findings must be unique and in canonical order",
        ));
    }
    let mut occurrence_ids = BTreeSet::new();
    if findings
        .iter()
        .flat_map(|finding| &finding.occurrences)
        .any(|occurrence| !occurrence_ids.insert(occurrence.occurrence_id.clone()))
    {
        return Err(AdjudicationError::InvalidInput(
            "occurrence identifiers must be globally unique",
        ));
    }
    if !blocking_occurrence_ids.is_subset(&occurrence_ids) {
        return Err(AdjudicationError::InvalidInput(
            "blocking occurrence identifiers must belong to assigned findings",
        ));
    }
    Ok(())
}

fn validate_complete_analysis<'a>(
    phase: InspectionPhase,
    findings: &[PriorFinding],
    request: &'a PiTriageRequest,
    result: &'a PiTriageResult,
) -> Result<BTreeMap<FindingId, &'a PiFindingAssessment>, AdjudicationError> {
    request
        .validate_identity()
        .map_err(|_| AdjudicationError::InvalidInput("stale Pi request identity"))?;
    if request.phase != phase || request.findings != findings {
        return Err(AdjudicationError::InvalidInput(
            "Pi request does not match adjudication findings",
        ));
    }
    let coverage = result.coverage;
    if coverage.assigned_artifact_count != request.assigned_artifact_count
        || coverage
            .completed_artifact_count
            .checked_add(coverage.not_applicable_artifact_count)
            != Some(coverage.assigned_artifact_count)
        || coverage.assigned_finding_count != findings.len() as u64
        || coverage.assessed_finding_count != coverage.assigned_finding_count
        || result.assessments.len() != findings.len()
    {
        return Err(AdjudicationError::InvalidInput("incomplete Pi coverage"));
    }
    let mut assessments = BTreeMap::new();
    for assessment in &result.assessments {
        if assessments
            .insert(assessment.finding_id.clone(), &assessment.assessment)
            .is_some()
        {
            return Err(AdjudicationError::InvalidInput(
                "duplicate Pi finding assessment",
            ));
        }
    }
    if findings
        .iter()
        .any(|finding| !assessments.contains_key(&finding.finding_id))
    {
        return Err(AdjudicationError::InvalidInput(
            "missing Pi finding assessment",
        ));
    }
    Ok(assessments)
}

fn decide_finding(
    policy: Option<&CompiledPiAdjudication>,
    finding: &PriorFinding,
    assessment: Option<&PiFindingAssessment>,
    attestation: Option<PiStageAttestation>,
    phase: InspectionPhase,
    is_blocking: bool,
) -> (
    AdjudicationState,
    Option<ClearanceRuleId>,
    AdjudicationReason,
) {
    let Some(assessment) = assessment else {
        return (
            AdjudicationState::NotRequested,
            None,
            if policy.is_some() {
                AdjudicationReason::AdvisoryOnly
            } else {
                AdjudicationReason::NotConfigured
            },
        );
    };
    let Some(policy) = policy else {
        return (
            AdjudicationState::Advisory,
            None,
            AdjudicationReason::AdvisoryOnly,
        );
    };
    if policy.mode == PiAdjudicationMode::Advisory {
        return (
            AdjudicationState::Advisory,
            None,
            AdjudicationReason::AdvisoryOnly,
        );
    }
    if !is_blocking {
        return (
            AdjudicationState::Advisory,
            None,
            AdjudicationReason::AdvisoryOnly,
        );
    }
    if assessment.classification != PiFindingClassification::FalsePositive {
        return (
            AdjudicationState::Rejected,
            None,
            AdjudicationReason::AssessmentNotFalsePositive,
        );
    }
    if !confidence_satisfies(assessment.confidence, policy.minimum_confidence) {
        return (
            AdjudicationState::Rejected,
            None,
            AdjudicationReason::ConfidenceTooLow,
        );
    }
    if !attestation_permits_clearance(policy, phase, attestation) {
        return (
            AdjudicationState::Rejected,
            None,
            AdjudicationReason::IncompleteRequiredAnalysis,
        );
    }
    if fixed_or_configured_non_clearable(policy, finding) {
        return (
            AdjudicationState::Rejected,
            None,
            AdjudicationReason::NonClearable,
        );
    }

    let matching = policy
        .clearance_rules
        .iter()
        .filter(|rule| clearance_rule_matches(rule, finding, assessment))
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [rule] => (
            AdjudicationState::Applied,
            Some(rule.id.clone()),
            AdjudicationReason::ClearedFalsePositive,
        ),
        [] => (
            AdjudicationState::Rejected,
            None,
            AdjudicationReason::ReasonCodeMismatch,
        ),
        _ => (
            AdjudicationState::Rejected,
            None,
            AdjudicationReason::AmbiguousClearanceRule,
        ),
    }
}

fn confidence_satisfies(actual: ConfiguredConfidence, required: Option<Confidence>) -> bool {
    let required = required.unwrap_or(Confidence::High);
    let actual = match actual {
        ConfiguredConfidence::Low => Confidence::Low,
        ConfiguredConfidence::Medium => Confidence::Medium,
        ConfiguredConfidence::High => Confidence::High,
    };
    actual >= required
}

fn attestation_permits_clearance(
    policy: &CompiledPiAdjudication,
    phase: InspectionPhase,
    actual: Option<PiStageAttestation>,
) -> bool {
    let requirement = match phase {
        InspectionPhase::Initial => policy.initial_attestation,
        InspectionPhase::Verification => policy.post_action_attestation,
    };
    match (requirement, actual) {
        (AttestationRequirement::Advisory, Some(_)) => true,
        (AttestationRequirement::DenyOnBlocking, Some(value)) => {
            value != PiStageAttestation::BlockingConcernsObserved
        }
        (
            AttestationRequirement::RequireNoBlocking,
            Some(PiStageAttestation::NoBlockingConcernsObserved),
        ) => true,
        _ => false,
    }
}

fn fixed_or_configured_non_clearable(
    policy: &CompiledPiAdjudication,
    finding: &PriorFinding,
) -> bool {
    if finding.severity == Severity::Critical
        || finding.occurrences.iter().any(|occurrence| {
            occurrence.verification_state == CredentialVerificationState::Verified
                || is_private_key_rule(occurrence.rule_id.as_str())
        })
    {
        return true;
    }
    let category = category_name(finding.category);
    if policy
        .non_clearable_categories
        .iter()
        .any(|value| value == category)
        || policy
            .non_clearable_minimum_severity
            .is_some_and(|minimum| severity_at_least(finding.severity, minimum))
    {
        return true;
    }
    finding.occurrences.iter().any(|occurrence| {
        policy.hard_block_rules.contains(&occurrence.rule_id)
            || policy
                .non_clearable_verification_states
                .iter()
                .any(|state| verification_matches(*state, occurrence.verification_state))
    })
}

fn clearance_rule_matches(
    rule: &CompiledClearanceRule,
    finding: &PriorFinding,
    assessment: &PiFindingAssessment,
) -> bool {
    !assessment.reason_codes.is_empty()
        && assessment
            .reason_codes
            .iter()
            .all(|reason| rule.reason_codes.contains(reason))
        && rule
            .categories
            .iter()
            .any(|value| value == category_name(finding.category))
        && severity_at_most(finding.severity, rule.maximum_severity)
        && finding
            .occurrences
            .iter()
            .all(|occurrence| occurrence_matches(rule, occurrence))
}

fn occurrence_matches(rule: &CompiledClearanceRule, occurrence: &PriorOccurrence) -> bool {
    occurrence.analyzer_id == rule.analyzer
        && rule.rules.contains(&occurrence.rule_id)
        && rule
            .verification_states
            .iter()
            .any(|state| verification_matches(*state, occurrence.verification_state))
}

fn preserve_blocking_correlations(
    findings: &[PriorFinding],
    blocking_occurrence_ids: &BTreeSet<OccurrenceId>,
    adjudications: &mut [Adjudication],
    cleared: &mut BTreeSet<FindingId>,
) {
    let states = adjudications
        .iter()
        .map(|value| (value.finding_id.clone(), value.state))
        .collect::<BTreeMap<_, _>>();
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for finding in findings {
        if finding
            .occurrences
            .iter()
            .any(|occurrence| blocking_occurrence_ids.contains(&occurrence.occurrence_id))
        {
            groups
                .entry(finding.correlation_id.clone())
                .or_default()
                .push(finding.finding_id.clone());
        }
    }
    let rejected_groups = groups
        .values()
        .filter(|ids| {
            ids.iter()
                .any(|id| states.get(id) != Some(&AdjudicationState::Applied))
        })
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    for adjudication in adjudications {
        if adjudication.state == AdjudicationState::Applied
            && rejected_groups.contains(&adjudication.finding_id)
        {
            adjudication.state = AdjudicationState::Rejected;
            adjudication.clearance_rule_id = None;
            adjudication.reason = AdjudicationReason::CorrelationNotCleared;
            cleared.remove(&adjudication.finding_id);
        }
    }
}

fn adjudication_id(phase: InspectionPhase, finding_id: &FindingId) -> AdjudicationId {
    let phase = match phase {
        InspectionPhase::Initial => b"initial:".as_slice(),
        InspectionPhase::Verification => b"verification:".as_slice(),
    };
    let mut material = phase.to_vec();
    material.extend_from_slice(finding_id.as_str().as_bytes());
    let digest = Digest::sha256(material).to_string();
    AdjudicationId::from_suffix(&digest["sha256:".len()..])
        .expect("SHA-256 hex is a valid adjudication suffix")
}

fn category_name(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Secret => "secret",
        FindingCategory::Credential => "credential",
        FindingCategory::SensitiveContent => "sensitive_content",
        FindingCategory::KnownSensitiveFile => "known_sensitive_file",
        FindingCategory::Filename => "filename",
        FindingCategory::ContentPattern => "content_pattern",
        FindingCategory::PolicyViolation => "policy_violation",
    }
}

fn is_private_key_rule(rule: &str) -> bool {
    rule == "private-key" || rule.ends_with("/private-key")
}

fn severity_at_least(actual: Severity, minimum: ConfigSeverity) -> bool {
    severity_rank(actual) >= config_severity_rank(minimum)
}

fn severity_at_most(actual: Severity, maximum: ConfigSeverity) -> bool {
    severity_rank(actual) <= config_severity_rank(maximum)
}

const fn severity_rank(value: Severity) -> u8 {
    match value {
        Severity::Informational => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

const fn config_severity_rank(value: ConfigSeverity) -> u8 {
    match value {
        ConfigSeverity::Low => 1,
        ConfigSeverity::Medium => 2,
        ConfigSeverity::High => 3,
        ConfigSeverity::Critical => 4,
    }
}

fn verification_matches(
    configured: VerificationState,
    actual: CredentialVerificationState,
) -> bool {
    matches!(
        (configured, actual),
        (
            VerificationState::Unverified,
            CredentialVerificationState::Unverified
        ) | (
            VerificationState::Verified,
            CredentialVerificationState::Verified
        ) | (
            VerificationState::VerificationError,
            CredentialVerificationState::VerificationError
        )
    )
}
