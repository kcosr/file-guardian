//! Strict protocol values for trusted Pi finding triage.
//!
//! The request contains normalized findings and bounded matched evidence so Pi
//! can make the semantic judgment the product asks it to make. Public reports
//! remain content-safe; this private request is not a report DTO.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, ConfiguredConfidence, Digest, FindingCategory,
    InspectionPhase, LogicalPath, ReasonCode, RuleId, RunId, Severity, ValidatedLocation,
};
use crate::processing::{
    CorrelationId, CredentialVerificationState, FindingId, GitHistoryScope, GitProvenance,
    OccurrenceId, PiFindingAssessment, PiFindingClassification, RecommendedAction,
};

pub const TRIAGE_REQUEST_SCHEMA: &str = "file-guardian-pi-triage-request/1";
pub const TRIAGE_TERMINAL_SCHEMA: &str = "file-guardian-pi-triage/1";

#[derive(Debug, Error)]
pub enum PiTriageError {
    #[error("Pi triage limit values must all be greater than zero")]
    InvalidLimits,
    #[error("Pi triage invocation id must use pii_ followed by 1 to 96 safe characters")]
    InvalidInvocationId,
    #[error("Pi triage review scope must contain a working tree or Git history")]
    EmptyReviewScope,
    #[error("Pi triage request contains more than {limit} findings")]
    FindingLimitExceeded { limit: usize },
    #[error("Pi triage request contains more than {limit} analyzer coverage entries")]
    CoverageLimitExceeded { limit: usize },
    #[error("Pi triage request serialization exceeds {limit} bytes")]
    RequestByteLimitExceeded { limit: usize },
    #[error("Pi triage terminal submission exceeds {limit} bytes")]
    TerminalByteLimitExceeded { limit: usize },
    #[error("Pi triage terminal submission is not valid strict JSON")]
    InvalidTerminalJson,
    #[error("Pi triage terminal schema is unsupported")]
    TerminalSchema,
    #[error("Pi triage terminal submission is bound to a stale invocation")]
    InvocationMismatch,
    #[error("Pi triage terminal submission is bound to the wrong inspection phase")]
    PhaseMismatch,
    #[error("Pi triage terminal submission is bound to a stale manifest")]
    ManifestMismatch,
    #[error("Pi triage terminal submission is bound to a stale request")]
    RequestMismatch,
    #[error("Pi triage terminal submission is bound to stale prior observations")]
    PriorObservationsMismatch,
    #[error("Pi triage request contains a finding from another inspection phase")]
    FindingPhaseMismatch,
    #[error("Pi triage request contains duplicate finding ids")]
    DuplicateRequestFinding,
    #[error("Pi triage request contains duplicate analyzer coverage entries")]
    DuplicateCoverage,
    #[error("Pi triage request analyzer coverage belongs to another inspection phase")]
    CoveragePhaseMismatch,
    #[error("Pi triage prior finding contains duplicate occurrence ids")]
    DuplicateOccurrence,
    #[error("Pi triage prior finding must contain at least one occurrence")]
    MissingOccurrence,
    #[error("Pi triage prior finding artifact provenance is invalid")]
    InvalidArtifact,
    #[error("Pi triage matched evidence is empty or not canonically encoded")]
    InvalidEvidence,
    #[error("Pi triage terminal submission contains too many assessments")]
    AssessmentLimitExceeded,
    #[error("Pi triage terminal submission contains duplicate finding assessments")]
    DuplicateAssessment,
    #[error("Pi triage terminal submission contains an unknown finding id")]
    ForeignFinding,
    #[error("Pi triage terminal submission omits one or more assigned findings")]
    MissingFinding,
    #[error("Pi triage terminal coverage counts do not match the assigned artifacts/findings")]
    CoverageMismatch,
    #[error("Pi triage assessment reason codes are not canonical")]
    NonCanonicalReasonCodes,
    #[error("Pi triage assessment contains a reason code outside the closed vocabulary")]
    ForeignReasonCode,
    #[error("Pi triage assessment exceeds the configured reason-code limit")]
    ReasonCodeLimitExceeded,
    #[error("Pi triage assessments are not in canonical finding-id order")]
    NonCanonicalAssessments,
    #[error("Pi triage duplicate_of references itself or an unknown finding")]
    InvalidDuplicateReference,
    #[error("Pi triage duplicate_of references contain a cycle")]
    DuplicateCycle,
    #[error("Pi triage request identity does not match its canonical body")]
    RequestIdentityMismatch,
    #[error("Pi triage request serialization failed")]
    RequestSerialization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiTriageLimits {
    pub max_findings: usize,
    pub max_coverage_entries: usize,
    pub max_request_bytes: usize,
    pub max_terminal_bytes: usize,
    pub max_reason_codes_per_assessment: usize,
}

impl PiTriageLimits {
    pub fn new(
        max_findings: usize,
        max_coverage_entries: usize,
        max_request_bytes: usize,
        max_terminal_bytes: usize,
        max_reason_codes_per_assessment: usize,
    ) -> Result<Self, PiTriageError> {
        if [
            max_findings,
            max_coverage_entries,
            max_request_bytes,
            max_terminal_bytes,
            max_reason_codes_per_assessment,
        ]
        .contains(&0)
        {
            return Err(PiTriageError::InvalidLimits);
        }
        Ok(Self {
            max_findings,
            max_coverage_entries,
            max_request_bytes,
            max_terminal_bytes,
            max_reason_codes_per_assessment,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PiTriageInvocationId(String);

impl PiTriageInvocationId {
    pub fn new(value: impl Into<String>) -> Result<Self, PiTriageError> {
        let value = value.into();
        let Some(suffix) = value.strip_prefix("pii_") else {
            return Err(PiTriageError::InvalidInvocationId);
        };
        if suffix.is_empty()
            || suffix.len() > 96
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(PiTriageError::InvalidInvocationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PiTriageInvocationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for PiTriageInvocationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PiTriageInvocationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiReviewScope {
    pub working_tree: bool,
    pub history: GitHistoryScope,
}

impl<'de> Deserialize<'de> for PiReviewScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            working_tree: bool,
            history: GitHistoryScope,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.working_tree, wire.history).map_err(serde::de::Error::custom)
    }
}

impl PiReviewScope {
    pub fn new(working_tree: bool, history: GitHistoryScope) -> Result<Self, PiTriageError> {
        if !working_tree && history == GitHistoryScope::None {
            return Err(PiTriageError::EmptyReviewScope);
        }
        Ok(Self {
            working_tree,
            history,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorOccurrence {
    pub occurrence_id: OccurrenceId,
    pub analyzer_id: AnalyzerId,
    pub rule_id: RuleId,
    pub verification_state: CredentialVerificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_token: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<MatchedEvidence>,
}

/// The exact staged artifact that Pi should inspect for one finding.
///
/// Working-tree paths are relative to the read-only stage. Git-history
/// findings additionally carry the frozen object/commit/ref provenance needed
/// to inspect the blob through the stage's own `.git` directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "surface", rename_all = "snake_case", deny_unknown_fields)]
pub enum PriorFindingArtifact {
    WorkingTree {
        logical_path: LogicalPath,
    },
    GitHistory {
        logical_path: LogicalPath,
        repository_identity: Digest,
        history_scope: GitHistoryScope,
        provenance: GitProvenance,
    },
}

impl PriorFindingArtifact {
    fn validate(&self) -> Result<(), PiTriageError> {
        match self {
            Self::WorkingTree { .. } => Ok(()),
            Self::GitHistory {
                logical_path,
                history_scope,
                provenance,
                ..
            } if *history_scope != GitHistoryScope::None
                && provenance
                    .occurrences
                    .iter()
                    .any(|occurrence| &occurrence.path == logical_path) =>
            {
                Ok(())
            }
            Self::GitHistory { .. } => Err(PiTriageError::InvalidArtifact),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "encoding", content = "value", rename_all = "snake_case")]
pub enum MatchedEvidence {
    Utf8(String),
    Base64url(String),
}

impl MatchedEvidence {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else if let Ok(value) = std::str::from_utf8(bytes) {
            Some(Self::Utf8(value.to_owned()))
        } else {
            Some(Self::Base64url(URL_SAFE_NO_PAD.encode(bytes)))
        }
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, PiTriageError> {
        match self {
            Self::Utf8(value) if !value.is_empty() => Ok(value.as_bytes().to_vec()),
            Self::Base64url(value) if !value.is_empty() => URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| PiTriageError::InvalidEvidence),
            Self::Utf8(_) | Self::Base64url(_) => Err(PiTriageError::InvalidEvidence),
        }
    }
}

impl<'de> Deserialize<'de> for MatchedEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "encoding", content = "value", rename_all = "snake_case")]
        enum Wire {
            Utf8(String),
            Base64url(String),
        }
        let value = match Wire::deserialize(deserializer)? {
            Wire::Utf8(value) => Self::Utf8(value),
            Wire::Base64url(value) => Self::Base64url(value),
        };
        let bytes = value.as_bytes().map_err(serde::de::Error::custom)?;
        if Self::from_bytes(&bytes).as_ref() != Some(&value) {
            return Err(serde::de::Error::custom(
                "evidence encoding is not canonical",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorFinding {
    pub finding_id: FindingId,
    pub correlation_id: CorrelationId,
    pub phase: InspectionPhase,
    pub analyzer_id: AnalyzerId,
    pub rule_id: RuleId,
    pub artifact_id: ArtifactId,
    pub artifact: PriorFindingArtifact,
    pub category: FindingCategory,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ValidatedLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_token: Option<Digest>,
    pub occurrences: Vec<PriorOccurrence>,
}

impl PriorFinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finding_id: FindingId,
        correlation_id: CorrelationId,
        phase: InspectionPhase,
        analyzer_id: AnalyzerId,
        rule_id: RuleId,
        artifact_id: ArtifactId,
        artifact: PriorFindingArtifact,
        category: FindingCategory,
        severity: Severity,
        location: Option<ValidatedLocation>,
        evidence_token: Option<Digest>,
        mut occurrences: Vec<PriorOccurrence>,
    ) -> Result<Self, PiTriageError> {
        artifact.validate()?;
        if occurrences.is_empty() {
            return Err(PiTriageError::MissingOccurrence);
        }
        if occurrences.iter().any(|occurrence| {
            occurrence.evidence.is_some() != occurrence.evidence_token.is_some()
                || occurrence
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.as_bytes().is_err())
        }) {
            return Err(PiTriageError::InvalidEvidence);
        }
        occurrences.sort_by(|left, right| left.occurrence_id.cmp(&right.occurrence_id));
        if occurrences
            .windows(2)
            .any(|pair| pair[0].occurrence_id == pair[1].occurrence_id)
        {
            return Err(PiTriageError::DuplicateOccurrence);
        }
        Ok(Self {
            finding_id,
            correlation_id,
            phase,
            analyzer_id,
            rule_id,
            artifact_id,
            artifact,
            category,
            severity,
            location,
            evidence_token,
            occurrences,
        })
    }
}

impl<'de> Deserialize<'de> for PriorFinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            finding_id: FindingId,
            correlation_id: CorrelationId,
            phase: InspectionPhase,
            analyzer_id: AnalyzerId,
            rule_id: RuleId,
            artifact_id: ArtifactId,
            artifact: PriorFindingArtifact,
            category: FindingCategory,
            severity: Severity,
            location: Option<ValidatedLocation>,
            evidence_token: Option<Digest>,
            occurrences: Vec<PriorOccurrence>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let original = wire.occurrences.clone();
        let finding = Self::new(
            wire.finding_id,
            wire.correlation_id,
            wire.phase,
            wire.analyzer_id,
            wire.rule_id,
            wire.artifact_id,
            wire.artifact,
            wire.category,
            wire.severity,
            wire.location,
            wire.evidence_token,
            wire.occurrences,
        )
        .map_err(serde::de::Error::custom)?;
        if finding.occurrences != original {
            return Err(serde::de::Error::custom("occurrences are not canonical"));
        }
        Ok(finding)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiTriageRequest {
    pub schema_version: &'static str,
    pub request_identity: Digest,
    pub run_id: RunId,
    pub invocation_id: PiTriageInvocationId,
    pub phase: InspectionPhase,
    pub manifest_identity: Digest,
    pub pipeline_identity: Digest,
    pub policy_identity: Digest,
    pub prompt_template_identity: Digest,
    pub prior_observations_identity: Digest,
    pub review_scope: PiReviewScope,
    pub assigned_artifact_count: u64,
    pub prior_coverage: Vec<AnalyzerCoverage>,
    pub findings: Vec<PriorFinding>,
    pub omissions: PiTriageOmissions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiTriageOmissions {
    pub findings_omitted: bool,
    pub details_omitted: bool,
}

impl PiTriageOmissions {
    pub const NONE: Self = Self {
        findings_omitted: false,
        details_omitted: false,
    };
}

#[derive(Clone, Debug)]
pub struct PiTriageRequestContext {
    pub run_id: RunId,
    pub invocation_id: PiTriageInvocationId,
    pub phase: InspectionPhase,
    pub manifest_identity: Digest,
    pub pipeline_identity: Digest,
    pub policy_identity: Digest,
    pub prompt_template_identity: Digest,
    pub prior_observations_identity: Digest,
    pub review_scope: PiReviewScope,
    pub assigned_artifact_count: u64,
    pub prior_coverage: Vec<AnalyzerCoverage>,
}

#[derive(Serialize)]
struct RequestIdentityMaterial<'a> {
    schema_version: &'static str,
    run_id: &'a RunId,
    invocation_id: &'a PiTriageInvocationId,
    phase: InspectionPhase,
    manifest_identity: Digest,
    pipeline_identity: Digest,
    policy_identity: Digest,
    prompt_template_identity: Digest,
    prior_observations_identity: Digest,
    review_scope: PiReviewScope,
    assigned_artifact_count: u64,
    prior_coverage: &'a [AnalyzerCoverage],
    findings: &'a [PriorFinding],
    omissions: PiTriageOmissions,
}

impl PiTriageRequest {
    pub fn new(
        mut context: PiTriageRequestContext,
        mut findings: Vec<PriorFinding>,
        limits: PiTriageLimits,
    ) -> Result<Self, PiTriageError> {
        if findings.len() > limits.max_findings {
            return Err(PiTriageError::FindingLimitExceeded {
                limit: limits.max_findings,
            });
        }
        if context.prior_coverage.len() > limits.max_coverage_entries {
            return Err(PiTriageError::CoverageLimitExceeded {
                limit: limits.max_coverage_entries,
            });
        }
        if findings
            .iter()
            .any(|finding| finding.phase != context.phase)
        {
            return Err(PiTriageError::FindingPhaseMismatch);
        }
        findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        if findings
            .windows(2)
            .any(|pair| pair[0].finding_id == pair[1].finding_id)
        {
            return Err(PiTriageError::DuplicateRequestFinding);
        }
        if context
            .prior_coverage
            .iter()
            .any(|coverage| coverage.phase != context.phase)
        {
            return Err(PiTriageError::CoveragePhaseMismatch);
        }
        context
            .prior_coverage
            .sort_by(|left, right| left.analyzer_id.cmp(&right.analyzer_id));
        if context
            .prior_coverage
            .windows(2)
            .any(|pair| pair[0].analyzer_id == pair[1].analyzer_id)
        {
            return Err(PiTriageError::DuplicateCoverage);
        }

        let omissions = PiTriageOmissions::NONE;
        let material = RequestIdentityMaterial {
            schema_version: TRIAGE_REQUEST_SCHEMA,
            run_id: &context.run_id,
            invocation_id: &context.invocation_id,
            phase: context.phase,
            manifest_identity: context.manifest_identity,
            pipeline_identity: context.pipeline_identity,
            policy_identity: context.policy_identity,
            prompt_template_identity: context.prompt_template_identity,
            prior_observations_identity: context.prior_observations_identity,
            review_scope: context.review_scope,
            assigned_artifact_count: context.assigned_artifact_count,
            prior_coverage: &context.prior_coverage,
            findings: &findings,
            omissions,
        };
        let identity_bytes =
            serde_json::to_vec(&material).map_err(|_| PiTriageError::RequestSerialization)?;
        let request_identity = Digest::sha256(identity_bytes);
        let request = Self {
            schema_version: TRIAGE_REQUEST_SCHEMA,
            request_identity,
            run_id: context.run_id,
            invocation_id: context.invocation_id,
            phase: context.phase,
            manifest_identity: context.manifest_identity,
            pipeline_identity: context.pipeline_identity,
            policy_identity: context.policy_identity,
            prompt_template_identity: context.prompt_template_identity,
            prior_observations_identity: context.prior_observations_identity,
            review_scope: context.review_scope,
            assigned_artifact_count: context.assigned_artifact_count,
            prior_coverage: context.prior_coverage,
            findings,
            omissions,
        };
        if request.canonical_json()?.len() > limits.max_request_bytes {
            return Err(PiTriageError::RequestByteLimitExceeded {
                limit: limits.max_request_bytes,
            });
        }
        Ok(request)
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, PiTriageError> {
        serde_json::to_vec(self).map_err(|_| PiTriageError::RequestSerialization)
    }

    pub fn validate_identity(&self) -> Result<(), PiTriageError> {
        let material = RequestIdentityMaterial {
            schema_version: self.schema_version,
            run_id: &self.run_id,
            invocation_id: &self.invocation_id,
            phase: self.phase,
            manifest_identity: self.manifest_identity,
            pipeline_identity: self.pipeline_identity,
            policy_identity: self.policy_identity,
            prompt_template_identity: self.prompt_template_identity,
            prior_observations_identity: self.prior_observations_identity,
            review_scope: self.review_scope,
            assigned_artifact_count: self.assigned_artifact_count,
            prior_coverage: &self.prior_coverage,
            findings: &self.findings,
            omissions: self.omissions,
        };
        let bytes =
            serde_json::to_vec(&material).map_err(|_| PiTriageError::RequestSerialization)?;
        if self.schema_version != TRIAGE_REQUEST_SCHEMA
            || Digest::sha256(bytes) != self.request_identity
        {
            return Err(PiTriageError::RequestIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiTriageSubmissionStatus {
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiStageAttestation {
    NoBlockingConcernsObserved,
    BlockingConcernsObserved,
    UnableToAssert,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiTriageAssessmentWire {
    pub finding_id: FindingId,
    pub classification: PiFindingClassification,
    pub confidence: ConfiguredConfidence,
    pub reason_codes: Vec<ReasonCode>,
    pub duplicate_of: Option<FindingId>,
    pub recommended_action: RecommendedAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiTriageCoverage {
    pub assigned_artifact_count: u64,
    pub completed_artifact_count: u64,
    pub not_applicable_artifact_count: u64,
    pub assigned_finding_count: u64,
    pub assessed_finding_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiTriageTerminalSubmission {
    pub schema_version: String,
    pub invocation_id: PiTriageInvocationId,
    pub phase: InspectionPhase,
    pub manifest_identity: Digest,
    pub request_identity: Digest,
    pub prior_observations_identity: Digest,
    pub status: PiTriageSubmissionStatus,
    pub assessments: Vec<PiTriageAssessmentWire>,
    pub stage_attestation: PiStageAttestation,
    pub coverage: PiTriageCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundPiFindingAssessment {
    pub finding_id: FindingId,
    pub assessment: PiFindingAssessment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PiTriageResult {
    pub assessments: Vec<BoundPiFindingAssessment>,
    pub stage_attestation: PiStageAttestation,
    pub coverage: PiTriageCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PiTriageVocabulary {
    reason_codes: BTreeSet<ReasonCode>,
}

impl PiTriageVocabulary {
    pub fn new(reason_codes: impl IntoIterator<Item = ReasonCode>) -> Self {
        Self {
            reason_codes: reason_codes.into_iter().collect(),
        }
    }
}

pub fn parse_and_normalize_terminal(
    bytes: &[u8],
    request: &PiTriageRequest,
    vocabulary: &PiTriageVocabulary,
    limits: PiTriageLimits,
) -> Result<PiTriageResult, PiTriageError> {
    if bytes.len() > limits.max_terminal_bytes {
        return Err(PiTriageError::TerminalByteLimitExceeded {
            limit: limits.max_terminal_bytes,
        });
    }
    let submission = serde_json::from_slice::<PiTriageTerminalSubmission>(bytes)
        .map_err(|_| PiTriageError::InvalidTerminalJson)?;
    normalize_terminal(submission, request, vocabulary, limits)
}

pub fn normalize_terminal(
    submission: PiTriageTerminalSubmission,
    request: &PiTriageRequest,
    vocabulary: &PiTriageVocabulary,
    limits: PiTriageLimits,
) -> Result<PiTriageResult, PiTriageError> {
    request.validate_identity()?;
    if submission.schema_version != TRIAGE_TERMINAL_SCHEMA {
        return Err(PiTriageError::TerminalSchema);
    }
    if submission.invocation_id != request.invocation_id {
        return Err(PiTriageError::InvocationMismatch);
    }
    if submission.phase != request.phase {
        return Err(PiTriageError::PhaseMismatch);
    }
    if submission.manifest_identity != request.manifest_identity {
        return Err(PiTriageError::ManifestMismatch);
    }
    if submission.request_identity != request.request_identity {
        return Err(PiTriageError::RequestMismatch);
    }
    if submission.prior_observations_identity != request.prior_observations_identity {
        return Err(PiTriageError::PriorObservationsMismatch);
    }
    if submission.assessments.len() > limits.max_findings {
        return Err(PiTriageError::AssessmentLimitExceeded);
    }

    let assigned = request
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for assessment in &submission.assessments {
        if !assigned.contains(&assessment.finding_id) {
            return Err(PiTriageError::ForeignFinding);
        }
        if !seen.insert(assessment.finding_id.clone()) {
            return Err(PiTriageError::DuplicateAssessment);
        }
        if assessment.reason_codes.len() > limits.max_reason_codes_per_assessment {
            return Err(PiTriageError::ReasonCodeLimitExceeded);
        }
        if assessment
            .reason_codes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(PiTriageError::NonCanonicalReasonCodes);
        }
        if assessment
            .reason_codes
            .iter()
            .any(|reason| !vocabulary.reason_codes.contains(reason))
        {
            return Err(PiTriageError::ForeignReasonCode);
        }
        if assessment.duplicate_of.as_ref().is_some_and(|duplicate| {
            duplicate == &assessment.finding_id || !assigned.contains(duplicate)
        }) {
            return Err(PiTriageError::InvalidDuplicateReference);
        }
    }
    if submission
        .assessments
        .windows(2)
        .any(|pair| pair[0].finding_id > pair[1].finding_id)
    {
        return Err(PiTriageError::NonCanonicalAssessments);
    }
    if seen != assigned {
        return Err(PiTriageError::MissingFinding);
    }
    validate_duplicate_graph(&submission.assessments)?;

    let assigned_count =
        u64::try_from(request.findings.len()).map_err(|_| PiTriageError::CoverageMismatch)?;
    let assessed_count =
        u64::try_from(submission.assessments.len()).map_err(|_| PiTriageError::CoverageMismatch)?;
    let artifact_accounted = submission
        .coverage
        .completed_artifact_count
        .checked_add(submission.coverage.not_applicable_artifact_count)
        .ok_or(PiTriageError::CoverageMismatch)?;
    if submission.coverage.assigned_artifact_count != request.assigned_artifact_count
        || artifact_accounted != request.assigned_artifact_count
        || submission.coverage.assigned_finding_count != assigned_count
        || submission.coverage.assessed_finding_count != assessed_count
        || assessed_count != assigned_count
    {
        return Err(PiTriageError::CoverageMismatch);
    }

    Ok(PiTriageResult {
        assessments: submission
            .assessments
            .into_iter()
            .map(|wire| BoundPiFindingAssessment {
                finding_id: wire.finding_id,
                assessment: PiFindingAssessment {
                    classification: wire.classification,
                    confidence: wire.confidence,
                    reason_codes: wire.reason_codes,
                    duplicate_of: wire.duplicate_of,
                    recommended_action: wire.recommended_action,
                },
            })
            .collect(),
        stage_attestation: submission.stage_attestation,
        coverage: submission.coverage,
    })
}

fn validate_duplicate_graph(assessments: &[PiTriageAssessmentWire]) -> Result<(), PiTriageError> {
    let edges = assessments
        .iter()
        .filter_map(|assessment| {
            assessment
                .duplicate_of
                .as_ref()
                .map(|target| (assessment.finding_id.clone(), target.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    for start in edges.keys() {
        let mut seen = BTreeSet::new();
        let mut current = start;
        while let Some(next) = edges.get(current) {
            if !seen.insert(current.clone()) {
                return Err(PiTriageError::DuplicateCycle);
            }
            current = next;
        }
    }
    Ok(())
}
