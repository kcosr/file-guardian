//! Trusted Pi adjudication of deterministic findings.
//!
//! Deterministic scanners deliberately favor recall and can be wrong. Pi sees
//! the real evidence and immutable content, and an authoritative profile may
//! clear a blocking deterministic finding when Pi classifies it as an exact
//! false positive. The original finding and assessment remain immutable audit
//! records; only File Guardian's effective policy resolution changes.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::analyzers::pi::triage::{
    PiStageAttestation, PiTriageRequest, PiTriageResult, PriorFinding,
};
use crate::domain::{Digest, InspectionPhase};
use crate::processing::config::PiAdjudicationMode;
use crate::processing::domain::{
    Adjudication, AdjudicationId, AdjudicationReason, AdjudicationState, FindingId, OccurrenceId,
    PiFindingAssessment, PiFindingClassification,
};
use crate::processing::executor::ValidatedPiAnalysis;
use crate::processing::runtime::CompiledPiAdjudication;

/// Host-observed integrity gates that model output cannot satisfy itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisIntegrity {
    pub required_deterministic_analysis_complete: bool,
    pub execution_accounting_complete: bool,
    pub snapshot_stable: bool,
    pub mutation_committed: bool,
    pub fresh_final_verification: bool,
}

impl AnalysisIntegrity {
    pub const fn complete_unchanged() -> Self {
        Self {
            required_deterministic_analysis_complete: true,
            execution_accounting_complete: true,
            snapshot_stable: true,
            mutation_committed: false,
            fresh_final_verification: false,
        }
    }

    pub const fn complete_after_actions() -> Self {
        Self {
            required_deterministic_analysis_complete: true,
            execution_accounting_complete: true,
            snapshot_stable: true,
            mutation_committed: true,
            fresh_final_verification: true,
        }
    }

    fn is_complete(self, phase: InspectionPhase) -> bool {
        self.required_deterministic_analysis_complete
            && self.execution_accounting_complete
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
    pub stage_attestation: Option<PiStageAttestation>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AdjudicationError {
    #[error("required Pi analysis is absent, failed, incomplete, or stale")]
    RequiredPiIncomplete,
    #[error("authoritative Pi adjudication requires complete host analysis")]
    IncompleteAnalysis,
    #[error("Pi adjudication input is inconsistent: {0}")]
    InvalidInput(&'static str),
}

/// Applies Pi assessments to the exact normalized findings assigned for a
/// phase. Advisory mode records assessments. Authoritative mode clears an
/// active finding exactly when Pi calls it `false_positive` and the complete
/// stage assessment reports no remaining blocking concern.
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

    let complete = match analysis {
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

    let authoritative = policy.is_some_and(|value| value.mode == PiAdjudicationMode::Authoritative);
    if authoritative && !integrity.is_complete(phase) {
        return Err(AdjudicationError::IncompleteAnalysis);
    }
    let stage_attestation = complete.as_ref().map(|(_, value)| *value);
    if authoritative && matches!(stage_attestation, Some(PiStageAttestation::UnableToAssert)) {
        return Err(AdjudicationError::RequiredPiIncomplete);
    }
    if authoritative
        && integrity.mutation_committed
        && stage_attestation != Some(PiStageAttestation::NoBlockingConcernsObserved)
    {
        return Err(AdjudicationError::RequiredPiIncomplete);
    }

    let assessment_map = complete.as_ref().map(|(values, _)| values);
    let may_clear =
        authoritative && stage_attestation == Some(PiStageAttestation::NoBlockingConcernsObserved);
    let mut adjudications = Vec::with_capacity(findings.len());
    let mut cleared = BTreeSet::new();

    for finding in findings {
        let is_blocking = finding
            .occurrences
            .iter()
            .any(|occurrence| blocking_occurrence_ids.contains(&occurrence.occurrence_id));
        let assessment = assessment_map
            .and_then(|values| values.get(&finding.finding_id))
            .copied();
        let (state, reason) = decide_finding(policy, assessment, is_blocking, may_clear);
        let adjudication = Adjudication::new(
            adjudication_id(phase, &finding.finding_id),
            phase,
            finding.finding_id.clone(),
            assessment.cloned(),
            state,
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
        stage_attestation,
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
    assessment: Option<&PiFindingAssessment>,
    is_blocking: bool,
    may_clear: bool,
) -> (AdjudicationState, AdjudicationReason) {
    let Some(assessment) = assessment else {
        return (
            AdjudicationState::NotRequested,
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
            AdjudicationReason::AdvisoryOnly,
        );
    };
    if policy.mode == PiAdjudicationMode::Advisory || !is_blocking {
        return (
            AdjudicationState::Advisory,
            AdjudicationReason::AdvisoryOnly,
        );
    }
    if assessment.classification != PiFindingClassification::FalsePositive {
        return (
            AdjudicationState::Rejected,
            AdjudicationReason::AssessmentNotFalsePositive,
        );
    }
    if !may_clear {
        return (
            AdjudicationState::Rejected,
            AdjudicationReason::IncompleteRequiredAnalysis,
        );
    }
    (
        AdjudicationState::Applied,
        AdjudicationReason::ClearedFalsePositive,
    )
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
