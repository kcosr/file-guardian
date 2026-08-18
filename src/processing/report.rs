//! Strict processing report schema 2.
//!
//! This module is intentionally independent from the schema-1 authorization
//! report.  It contains only report-safe data: no host paths, content digests,
//! snippets, process output, or free-form diagnostic text.

use crate::domain::LogicalPath;
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const PROCESSING_REPORT_SCHEMA_VERSION: &str = "2";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SafeId(String);

impl SafeId {
    pub fn new(value: impl Into<String>) -> Result<Self, ReportError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err(ReportError::UnsafeIdentifier);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SafeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, ReportError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(ReportError::InvalidDigest);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReportError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes);
        Self(format!("sha256:{hash:x}"))
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Rfc3339Timestamp(String);

impl Rfc3339Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ReportError> {
        let value = value.into();
        let parsed =
            DateTime::parse_from_rfc3339(&value).map_err(|_| ReportError::InvalidTimestamp)?;
        if parsed.to_rfc3339() != value {
            return Err(ReportError::NonCanonicalTimestamp);
        }
        Ok(Self(value))
    }

    fn parsed(&self) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(&self.0).expect("timestamp constructor validated value")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Rfc3339Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingOutcome {
    Allow,
    AllowModified,
    Deny,
    Error,
}

impl ProcessingOutcome {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Allow => 0,
            Self::AllowModified => 10,
            Self::Deny => 20,
            Self::Error => 30,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceStatus {
    Durable,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceSummary {
    pub status: PersistenceStatus,
    pub report_digest: Option<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitTransport {
    Https,
    Ssh,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryScope {
    None,
    Head,
    Reachable,
    AllRefs,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitObjectId {
    pub algorithm: GitObjectAlgorithm,
    pub value: String,
}

impl GitObjectId {
    fn validate(&self) -> Result<(), ReportError> {
        let expected = match self.algorithm {
            GitObjectAlgorithm::Sha1 => 40,
            GitObjectAlgorithm::Sha256 => 64,
        };
        if self.value.len() != expected
            || !self
                .value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReportError::InvalidGitObjectId);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenRefSummary {
    pub name: LogicalPath,
    pub object_id: GitObjectId,
    pub peeled_commit_id: GitObjectId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceSummary {
    Path {
        #[serde(deserialize_with = "deserialize_required_option")]
        repository: Option<DetectedRepositorySummary>,
    },
    Git {
        transport: GitTransport,
        repository_id: Sha256Digest,
        resolved_head: GitObjectId,
        working_tree: bool,
        history: HistoryScope,
        frozen_refs: Vec<FrozenRefSummary>,
    },
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectedRepositorySummary {
    pub repository_id: Sha256Digest,
    pub resolved_head: GitObjectId,
    pub history: HistoryScope,
    pub frozen_refs: Vec<FrozenRefSummary>,
}

impl SourceSummary {
    pub(crate) fn has_working_tree(&self) -> bool {
        match self {
            Self::Path { .. } => true,
            Self::Git { working_tree, .. } => *working_tree,
        }
    }

    fn validate(&self) -> Result<(), ReportError> {
        let (head, working_tree, history, refs) = match self {
            Self::Path {
                repository: None, ..
            } => return Ok(()),
            Self::Path {
                repository: Some(repository),
                ..
            } => (
                &repository.resolved_head,
                true,
                &repository.history,
                &repository.frozen_refs,
            ),
            Self::Git {
                resolved_head,
                working_tree,
                history,
                frozen_refs,
                ..
            } => (resolved_head, *working_tree, history, frozen_refs),
        };
        head.validate()?;
        if !working_tree && *history == HistoryScope::None {
            return Err(ReportError::EmptySourceScope);
        }
        validate_sorted_unique(refs, |row| &row.name)?;
        for row in refs {
            row.object_id.validate()?;
            row.peeled_commit_id.validate()?;
        }
        if *history != HistoryScope::None && refs.is_empty() {
            return Err(ReportError::HistoryWithoutRefs);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionStatus {
    Complete,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionSummary {
    pub status: AcquisitionStatus,
    pub implementation_id: SafeId,
    pub implementation_version: SafeId,
    pub started_at: Rfc3339Timestamp,
    pub finished_at: Rfc3339Timestamp,
    pub duration_ms: u64,
    pub source_identity: Option<Sha256Digest>,
    pub issue_codes: Vec<SafeId>,
}

impl AcquisitionSummary {
    fn validate(&self) -> Result<(), ReportError> {
        validate_time_range(&self.started_at, &self.finished_at)?;
        validate_sorted_unique(&self.issue_codes, |value| value)?;
        match self.status {
            AcquisitionStatus::Complete if !self.issue_codes.is_empty() => {
                Err(ReportError::AcquisitionStatusMismatch)
            }
            AcquisitionStatus::Failed if self.issue_codes.is_empty() => {
                Err(ReportError::AcquisitionStatusMismatch)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredDisposition {
    Retain,
    Discard,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveDisposition {
    Retained,
    Discarded,
    Quarantined,
    RetainedError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatus {
    Unavailable,
    Available,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageSummary {
    pub reference: Option<SafeId>,
    pub configured_disposition: ConfiguredDisposition,
    pub effective_disposition: EffectiveDisposition,
    pub handoff_status: HandoffStatus,
    pub sealed: bool,
    pub initial_manifest_identity: Option<Sha256Digest>,
    pub final_manifest_identity: Option<Sha256Digest>,
    pub current_manifest_identity: Option<Sha256Digest>,
    pub expires_at: Option<Rfc3339Timestamp>,
    pub quarantine_id: Option<SafeId>,
}

impl StageSummary {
    fn validate(&self, run_id: &SafeId, outcome: ProcessingOutcome) -> Result<(), ReportError> {
        let disposition_matches = matches!(
            (self.configured_disposition, self.effective_disposition),
            (
                ConfiguredDisposition::Retain,
                EffectiveDisposition::Retained
            ) | (
                ConfiguredDisposition::Discard,
                EffectiveDisposition::Discarded
            ) | (
                ConfiguredDisposition::Quarantine,
                EffectiveDisposition::Quarantined
            )
        );
        let fail_safe_quarantine = outcome == ProcessingOutcome::Error
            && self.effective_disposition == EffectiveDisposition::Quarantined
            && matches!(
                self.configured_disposition,
                ConfiguredDisposition::Retain | ConfiguredDisposition::Discard
            );
        if !(disposition_matches
            || fail_safe_quarantine
            || outcome == ProcessingOutcome::Error
                && self.effective_disposition == EffectiveDisposition::RetainedError)
        {
            return Err(ReportError::DispositionMismatch);
        }
        let handoff_available = matches!(
            (outcome, self.effective_disposition),
            (
                ProcessingOutcome::Allow | ProcessingOutcome::AllowModified,
                EffectiveDisposition::Retained
            )
        );
        if (self.handoff_status == HandoffStatus::Available) != handoff_available {
            return Err(ReportError::HandoffMismatch);
        }
        if handoff_available {
            if self.reference.as_ref() != Some(run_id) || self.expires_at.is_none() {
                return Err(ReportError::HandoffMismatch);
            }
        } else if self.reference.is_some() {
            return Err(ReportError::HandoffMismatch);
        }
        if (self.effective_disposition == EffectiveDisposition::Quarantined)
            != self.quarantine_id.is_some()
        {
            return Err(ReportError::QuarantineMismatch);
        }
        if matches!(
            outcome,
            ProcessingOutcome::Allow | ProcessingOutcome::AllowModified
        ) && !self.sealed
        {
            return Err(ReportError::AllowedStageUnsealed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMode {
    Evaluate,
    Apply,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    pub profile_id: SafeId,
    pub policy_identity: Sha256Digest,
    pub pipeline_id: SafeId,
    pub pipeline_identity: Sha256Digest,
    pub effective_action_mode: ActionMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionPhase {
    Initial,
    Verification,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    PhysicalFile,
    RepositoryBlob,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationType {
    RegularFile,
    Symlink,
    Nonphysical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitProvenanceSummary {
    pub repository_id: Sha256Digest,
    pub blob_id: GitObjectId,
    pub occurrence_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSummary {
    pub artifact_id: SafeId,
    pub subject_id: SafeId,
    pub kind: ArtifactKind,
    pub logical_path: LogicalPath,
    pub byte_len: u64,
    pub publication_type: PublicationType,
    pub publication_mode: Option<u32>,
    pub git: Option<GitProvenanceSummary>,
}

impl ArtifactSummary {
    fn validate(&self) -> Result<(), ReportError> {
        if self.publication_mode.is_some_and(|mode| mode > 0o7777) {
            return Err(ReportError::InvalidPublicationMode);
        }
        match (self.kind, self.publication_type, &self.git) {
            (
                ArtifactKind::PhysicalFile,
                PublicationType::RegularFile | PublicationType::Symlink,
                None,
            ) => {}
            (ArtifactKind::RepositoryBlob, PublicationType::Nonphysical, Some(git)) => {
                git.blob_id.validate()?;
                if git.occurrence_count == 0 {
                    return Err(ReportError::InvalidGitProvenance);
                }
            }
            _ => return Err(ReportError::InvalidArtifactShape),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Complete,
    Incomplete,
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerRunSummary {
    pub analyzer_id: SafeId,
    pub adapter_id: Option<SafeId>,
    pub executable_basename: Option<SafeId>,
    pub version: Option<SafeId>,
    pub executable_identity: Option<Sha256Digest>,
    pub rules_identity: Option<Sha256Digest>,
    pub required: bool,
    pub status: ExecutionStatus,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    pub analyzer_id: SafeId,
    pub eligible: u64,
    pub assigned: u64,
    pub completed: u64,
    pub not_applicable: u64,
    pub status: ExecutionStatus,
}

impl CoverageSummary {
    fn validate(&self) -> Result<(), ReportError> {
        if self.assigned > self.eligible
            || self.completed.checked_add(self.not_applicable) > Some(self.assigned)
            || (self.status == ExecutionStatus::Complete
                && self.completed.checked_add(self.not_applicable) != Some(self.assigned))
            || (self.status == ExecutionStatus::NotRun
                && (self.completed != 0 || self.not_applicable != 0))
        {
            return Err(ReportError::InvalidCoverage);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Unverified,
    VerificationError,
    NotSupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeLocation {
    pub line: u64,
    pub column: Option<u64>,
}

impl SafeLocation {
    fn validate(&self) -> Result<(), ReportError> {
        if self.line == 0 || self.column == Some(0) {
            return Err(ReportError::InvalidLocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceSummary {
    pub occurrence_id: SafeId,
    pub finding_id: SafeId,
    pub analyzer_id: SafeId,
    pub rule_id: SafeId,
    pub artifact_id: SafeId,
    pub location: Option<SafeLocation>,
    pub verification_state: VerificationState,
    pub evidence_token: Option<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Secret,
    Credential,
    SensitiveContent,
    KnownSensitiveFile,
    Filename,
    ContentPattern,
    PolicyViolation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSummary {
    pub finding_id: SafeId,
    pub artifact_id: SafeId,
    pub category: FindingCategory,
    pub severity: Severity,
    pub occurrence_ids: Vec<SafeId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationSummary {
    pub correlation_id: SafeId,
    pub finding_ids: Vec<SafeId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDirective {
    Audit,
    Deny,
    Delete,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    Active,
    Cleared,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionSummary {
    pub finding_id: SafeId,
    pub binding_id: SafeId,
    pub directive: PolicyDirective,
    pub state: ResolutionState,
    pub reason_code: SafeId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseStatistics {
    pub artifacts: u64,
    pub analyzer_runs: u64,
    pub occurrences: u64,
    pub findings: u64,
    pub correlations: u64,
    pub resolutions: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseSummary {
    pub phase: InspectionPhase,
    pub manifest_identity: Sha256Digest,
    pub source_scope_identity: Sha256Digest,
    pub pipeline_identity: Sha256Digest,
    pub artifacts: Vec<ArtifactSummary>,
    pub analyzer_runs: Vec<AnalyzerRunSummary>,
    pub coverage: Vec<CoverageSummary>,
    pub occurrences: Vec<OccurrenceSummary>,
    pub findings: Vec<FindingSummary>,
    pub correlations: Vec<CorrelationSummary>,
    pub resolutions: Vec<ResolutionSummary>,
    pub statistics: PhaseStatistics,
}

impl PhaseSummary {
    pub fn required_complete(&self) -> bool {
        self.analyzer_runs
            .iter()
            .all(|run| !run.required || run.status == ExecutionStatus::Complete)
            && self.coverage.iter().all(|row| {
                self.analyzer_runs
                    .iter()
                    .find(|run| run.analyzer_id == row.analyzer_id)
                    .is_some_and(|run| !run.required || row.status == ExecutionStatus::Complete)
            })
    }

    fn permits(&self) -> bool {
        self.resolutions.iter().all(|resolution| {
            resolution.state == ResolutionState::Cleared
                || resolution.directive == PolicyDirective::Audit
        })
    }

    fn requires_action(&self) -> bool {
        self.resolutions.iter().any(|resolution| {
            resolution.state == ResolutionState::Active
                && matches!(
                    resolution.directive,
                    PolicyDirective::Delete | PolicyDirective::Quarantine
                )
        })
    }

    fn blocks(&self) -> bool {
        self.resolutions.iter().any(|resolution| {
            resolution.state == ResolutionState::Active
                && resolution.directive == PolicyDirective::Deny
        })
    }

    fn validate(&self, expected: InspectionPhase) -> Result<(), ReportError> {
        if self.phase != expected || self.analyzer_runs.is_empty() {
            return Err(ReportError::InvalidPhase);
        }
        validate_sorted_unique(&self.artifacts, |row| &row.artifact_id)?;
        validate_sorted_unique(&self.analyzer_runs, |row| &row.analyzer_id)?;
        validate_sorted_unique(&self.coverage, |row| &row.analyzer_id)?;
        validate_sorted_unique(&self.occurrences, |row| &row.occurrence_id)?;
        validate_sorted_unique(&self.findings, |row| &row.finding_id)?;
        validate_sorted_unique(&self.correlations, |row| &row.correlation_id)?;
        validate_sorted_unique(&self.resolutions, |row| &row.finding_id)?;
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        for row in &self.coverage {
            row.validate()?;
        }
        let analyzer_by_id = self
            .analyzer_runs
            .iter()
            .map(|row| (&row.analyzer_id, row))
            .collect::<BTreeMap<_, _>>();
        if self.coverage.len() != self.analyzer_runs.len()
            || self
                .coverage
                .iter()
                .any(|row| !analyzer_by_id.contains_key(&row.analyzer_id))
        {
            return Err(ReportError::CoverageAnalyzerMismatch);
        }
        for occurrence in &self.occurrences {
            if let Some(location) = &occurrence.location {
                location.validate()?;
            }
        }
        validate_phase_references(self)?;
        if self.statistics.artifacts != self.artifacts.len() as u64
            || self.statistics.analyzer_runs != self.analyzer_runs.len() as u64
            || self.statistics.occurrences != self.occurrences.len() as u64
            || self.statistics.findings != self.findings.len() as u64
            || self.statistics.correlations != self.correlations.len() as u64
            || self.statistics.resolutions != self.resolutions.len() as u64
        {
            return Err(ReportError::StatisticsMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhasesSummary {
    pub initial: Option<PhaseSummary>,
    pub verification: Option<PhaseSummary>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attestation {
    NoBlockingConcernsObserved,
    BlockingConcernsObserved,
    UnableToAssert,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiInvocationSummary {
    pub invocation_id: SafeId,
    pub phase: InspectionPhase,
    pub analyzer_id: SafeId,
    pub model_identity: Sha256Digest,
    pub runtime_identity: Sha256Digest,
    pub prompt_identity: Sha256Digest,
    pub protocol_identity: Sha256Digest,
    pub status: ExecutionStatus,
    pub attestation: Option<Attestation>,
    pub normalized_output_digest: Option<Sha256Digest>,
    pub started_at: Rfc3339Timestamp,
    pub finished_at: Rfc3339Timestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiAssessment {
    Confirmed,
    LikelyTruePositive,
    LikelyFalsePositive,
    FalsePositive,
    Uncertain,
    UnableToAssess,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicationState {
    NotRequested,
    Advisory,
    Applied,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicationSummary {
    pub finding_id: SafeId,
    pub phase: InspectionPhase,
    pub assessment: PiAssessment,
    pub state: AdjudicationState,
    pub reason_code: SafeId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Delete,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Planned,
    Started,
    Committed,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    pub action_id: SafeId,
    pub kind: ActionKind,
    pub subject_id: SafeId,
    pub finding_ids: Vec<SafeId>,
    pub binding_ids: Vec<SafeId>,
    pub state: ActionState,
    pub artifact_quarantine_id: Option<SafeId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueSummary {
    pub code: SafeId,
    pub phase: Option<InspectionPhase>,
    pub component_id: Option<SafeId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DegradationSummary {
    pub code: SafeId,
    pub phase: Option<InspectionPhase>,
    pub component_id: Option<SafeId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingStatistics {
    pub initial_artifacts: u64,
    pub verification_artifacts: u64,
    pub total_findings: u64,
    pub total_actions: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OmissionSummary {
    pub details_omitted: bool,
    pub reason: Option<SafeId>,
}

#[derive(Clone, Debug)]
pub struct ProcessingReportData {
    pub run_id: SafeId,
    pub request_id: Option<SafeId>,
    pub outcome: ProcessingOutcome,
    pub modified: bool,
    pub started_at: Rfc3339Timestamp,
    pub finished_at: Rfc3339Timestamp,
    pub persistence_status: PersistenceStatus,
    pub source: Option<SourceSummary>,
    pub acquisition: Option<AcquisitionSummary>,
    pub stage: Option<StageSummary>,
    pub policy: Option<PolicySummary>,
    pub phases: PhasesSummary,
    pub pi_invocations: Vec<PiInvocationSummary>,
    pub adjudications: Vec<AdjudicationSummary>,
    pub actions: Vec<ActionSummary>,
    pub issues: Vec<IssueSummary>,
    pub degradations: Vec<DegradationSummary>,
    pub statistics: ProcessingStatistics,
    pub omissions: OmissionSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingReport {
    schema_version: String,
    pub run_id: SafeId,
    pub request_id: Option<SafeId>,
    pub outcome: ProcessingOutcome,
    pub exit_code: i32,
    pub modified: bool,
    pub started_at: Rfc3339Timestamp,
    pub finished_at: Rfc3339Timestamp,
    pub persistence: PersistenceSummary,
    pub source: Option<SourceSummary>,
    pub acquisition: Option<AcquisitionSummary>,
    pub stage: Option<StageSummary>,
    pub policy: Option<PolicySummary>,
    pub phases: PhasesSummary,
    pub pi_invocations: Vec<PiInvocationSummary>,
    pub adjudications: Vec<AdjudicationSummary>,
    pub actions: Vec<ActionSummary>,
    pub issues: Vec<IssueSummary>,
    pub degradations: Vec<DegradationSummary>,
    pub statistics: ProcessingStatistics,
    pub omissions: OmissionSummary,
}

impl ProcessingReport {
    pub fn new(data: ProcessingReportData) -> Result<Self, ReportError> {
        let mut report = Self {
            schema_version: PROCESSING_REPORT_SCHEMA_VERSION.to_owned(),
            run_id: data.run_id,
            request_id: data.request_id,
            outcome: data.outcome,
            exit_code: data.outcome.exit_code(),
            modified: data.modified,
            started_at: data.started_at,
            finished_at: data.finished_at,
            persistence: PersistenceSummary {
                status: data.persistence_status,
                report_digest: None,
            },
            source: data.source,
            acquisition: data.acquisition,
            stage: data.stage,
            policy: data.policy,
            phases: data.phases,
            pi_invocations: data.pi_invocations,
            adjudications: data.adjudications,
            actions: data.actions,
            issues: data.issues,
            degradations: data.degradations,
            statistics: data.statistics,
            omissions: data.omissions,
        };
        report.validate_without_digest()?;
        if report.persistence.status == PersistenceStatus::Durable {
            report.persistence.report_digest = Some(report.canonical_digest()?);
        }
        report.validate()?;
        Ok(report)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn validate(&self) -> Result<(), ReportError> {
        self.validate_without_digest()?;
        match self.persistence.status {
            PersistenceStatus::Durable => {
                if self.persistence.report_digest.as_ref() != Some(&self.canonical_digest()?) {
                    return Err(ReportError::ReportDigestMismatch);
                }
            }
            PersistenceStatus::Unavailable if self.persistence.report_digest.is_some() => {
                return Err(ReportError::PersistenceMismatch)
            }
            PersistenceStatus::Unavailable => {}
        }
        Ok(())
    }

    pub fn to_json_line(&self) -> Result<Vec<u8>, ReportError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(ReportError::Serialize)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn canonical_digest(&self) -> Result<Sha256Digest, ReportError> {
        let mut copy = self.clone();
        copy.persistence.report_digest = None;
        let bytes = serde_json::to_vec(&copy).map_err(ReportError::Serialize)?;
        Ok(Sha256Digest::from_bytes(&bytes))
    }

    fn validate_without_digest(&self) -> Result<(), ReportError> {
        if self.schema_version != PROCESSING_REPORT_SCHEMA_VERSION {
            return Err(ReportError::SchemaVersion);
        }
        if self.exit_code != self.outcome.exit_code() {
            return Err(ReportError::ExitMismatch);
        }
        validate_time_range(&self.started_at, &self.finished_at)?;
        validate_sorted_unique(&self.pi_invocations, |row| &row.invocation_id)?;
        validate_sorted_unique(&self.adjudications, |row| &row.finding_id)?;
        validate_sorted_unique(&self.actions, |row| &row.action_id)?;
        validate_sorted_unique(&self.issues, |row| &row.code)?;
        validate_sorted_unique(&self.degradations, |row| &row.code)?;
        for invocation in &self.pi_invocations {
            validate_time_range(&invocation.started_at, &invocation.finished_at)?;
            if (invocation.status == ExecutionStatus::Complete)
                != invocation.normalized_output_digest.is_some()
            {
                return Err(ReportError::PiStatusMismatch);
            }
        }
        for action in &self.actions {
            validate_sorted_unique(&action.finding_ids, |value| value)?;
            validate_sorted_unique(&action.binding_ids, |value| value)?;
            if action.finding_ids.is_empty() || action.binding_ids.is_empty() {
                return Err(ReportError::InvalidAction);
            }
            if (action.kind == ActionKind::Quarantine) != action.artifact_quarantine_id.is_some() {
                return Err(ReportError::InvalidAction);
            }
        }
        match (&self.phases.initial, &self.phases.verification) {
            (Some(initial), verification) => {
                initial.validate(InspectionPhase::Initial)?;
                if let Some(verification) = verification {
                    verification.validate(InspectionPhase::Verification)?;
                }
            }
            (None, Some(_)) => return Err(ReportError::VerificationWithoutInitial),
            (None, None) => {}
        }
        if let Some(source) = &self.source {
            source.validate()?;
        }
        if let Some(acquisition) = &self.acquisition {
            acquisition.validate()?;
        }
        if let Some(stage) = &self.stage {
            stage.validate(&self.run_id, self.outcome)?;
        }
        if self.omissions.details_omitted != self.omissions.reason.is_some() {
            return Err(ReportError::OmissionMismatch);
        }
        self.validate_outcome()?;
        let initial_artifacts = self
            .phases
            .initial
            .as_ref()
            .map_or(0, |phase| phase.artifacts.len() as u64);
        let verification_artifacts = self
            .phases
            .verification
            .as_ref()
            .map_or(0, |phase| phase.artifacts.len() as u64);
        let findings = self
            .phases
            .initial
            .iter()
            .chain(self.phases.verification.iter())
            .map(|phase| phase.findings.len() as u64)
            .sum::<u64>();
        if self.statistics.initial_artifacts != initial_artifacts
            || self.statistics.verification_artifacts != verification_artifacts
            || self.statistics.total_findings != findings
            || self.statistics.total_actions != self.actions.len() as u64
        {
            return Err(ReportError::StatisticsMismatch);
        }
        Ok(())
    }

    fn validate_outcome(&self) -> Result<(), ReportError> {
        let committed = self
            .actions
            .iter()
            .filter(|action| action.state == ActionState::Committed)
            .count();
        if self.modified != (committed > 0) {
            return Err(ReportError::ModifiedMismatch);
        }
        match self.outcome {
            ProcessingOutcome::Allow => {
                self.require_durable_decision()?;
                let initial = self.require_complete_initial()?;
                if self.phases.verification.is_some()
                    || !self.actions.is_empty()
                    || !self.issues.is_empty()
                    || !initial.permits()
                    || self.pi_blocks(InspectionPhase::Initial)
                {
                    return Err(ReportError::AllowInvariant);
                }
                self.require_stage_identity(false)?;
            }
            ProcessingOutcome::AllowModified => {
                self.require_durable_decision()?;
                let initial = self.require_complete_initial()?;
                let verification = self
                    .phases
                    .verification
                    .as_ref()
                    .ok_or(ReportError::AllowModifiedInvariant)?;
                if !verification.required_complete()
                    || !verification.permits()
                    || committed == 0
                    || !self.issues.is_empty()
                    || (!initial.requires_action() && !initial.blocks())
                {
                    return Err(ReportError::AllowModifiedInvariant);
                }
                self.require_stage_identity(true)?;
            }
            ProcessingOutcome::Deny => {
                self.require_durable_decision()?;
                let initial = self.require_complete_initial()?;
                if self.phases.verification.is_some()
                    || committed != 0
                    || !self.issues.is_empty()
                    || (!initial.blocks()
                        && !initial.requires_action()
                        && !self.pi_blocks(InspectionPhase::Initial))
                {
                    return Err(ReportError::DenyInvariant);
                }
                self.require_stage_identity(false)?;
                if self
                    .stage
                    .as_ref()
                    .is_some_and(|stage| stage.handoff_status != HandoffStatus::Unavailable)
                {
                    return Err(ReportError::DenyInvariant);
                }
            }
            ProcessingOutcome::Error => {
                if self.stage.as_ref().is_some_and(|stage| {
                    stage.handoff_status != HandoffStatus::Unavailable || stage.reference.is_some()
                }) {
                    return Err(ReportError::ErrorInvariant);
                }
                if self.issues.is_empty() {
                    return Err(ReportError::ErrorInvariant);
                }
                if self.persistence.status == PersistenceStatus::Unavailable
                    && (self.stage.is_some()
                        || self.policy.is_some()
                        || self.phases.initial.is_some()
                        || self.phases.verification.is_some())
                {
                    return Err(ReportError::UnavailablePersistenceHasDurableState);
                }
            }
        }
        if self.outcome != ProcessingOutcome::Error && self.omissions.details_omitted {
            return Err(ReportError::DecisionOmittedDetails);
        }
        Ok(())
    }

    fn require_durable_decision(&self) -> Result<(), ReportError> {
        let source = self
            .source
            .as_ref()
            .ok_or(ReportError::DecisionContextMissing)?;
        if self.persistence.status != PersistenceStatus::Durable
            || self.acquisition.as_ref().map(|value| value.status)
                != Some(AcquisitionStatus::Complete)
            || self.policy.is_none()
            || source.has_working_tree() != self.stage.is_some()
        {
            return Err(ReportError::DecisionContextMissing);
        }
        Ok(())
    }

    fn require_complete_initial(&self) -> Result<&PhaseSummary, ReportError> {
        let initial = self
            .phases
            .initial
            .as_ref()
            .ok_or(ReportError::DecisionContextMissing)?;
        if !initial.required_complete() {
            return Err(ReportError::DecisionCoverageIncomplete);
        }
        Ok(initial)
    }

    fn require_stage_identity(&self, changed: bool) -> Result<(), ReportError> {
        let Some(stage) = self.stage.as_ref() else {
            if self
                .source
                .as_ref()
                .is_some_and(|source| !source.has_working_tree() && !changed)
            {
                return Ok(());
            }
            return Err(ReportError::DecisionContextMissing);
        };
        let (Some(initial), Some(final_id), Some(current)) = (
            &stage.initial_manifest_identity,
            &stage.final_manifest_identity,
            &stage.current_manifest_identity,
        ) else {
            return Err(ReportError::StageIdentityMissing);
        };
        if final_id != current || changed != (initial != final_id) {
            return Err(ReportError::StageIdentityMismatch);
        }
        Ok(())
    }

    fn pi_blocks(&self, phase: InspectionPhase) -> bool {
        self.pi_invocations.iter().any(|invocation| {
            invocation.phase == phase
                && invocation.status == ExecutionStatus::Complete
                && invocation.attestation == Some(Attestation::BlockingConcernsObserved)
        })
    }
}

impl<'de> Deserialize<'de> for ProcessingReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            run_id: SafeId,
            request_id: Option<SafeId>,
            outcome: ProcessingOutcome,
            exit_code: i32,
            modified: bool,
            started_at: Rfc3339Timestamp,
            finished_at: Rfc3339Timestamp,
            persistence: PersistenceSummary,
            source: Option<SourceSummary>,
            acquisition: Option<AcquisitionSummary>,
            stage: Option<StageSummary>,
            policy: Option<PolicySummary>,
            phases: PhasesSummary,
            pi_invocations: Vec<PiInvocationSummary>,
            adjudications: Vec<AdjudicationSummary>,
            actions: Vec<ActionSummary>,
            issues: Vec<IssueSummary>,
            degradations: Vec<DegradationSummary>,
            statistics: ProcessingStatistics,
            omissions: OmissionSummary,
        }
        let wire = Wire::deserialize(deserializer)?;
        let report = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            request_id: wire.request_id,
            outcome: wire.outcome,
            exit_code: wire.exit_code,
            modified: wire.modified,
            started_at: wire.started_at,
            finished_at: wire.finished_at,
            persistence: wire.persistence,
            source: wire.source,
            acquisition: wire.acquisition,
            stage: wire.stage,
            policy: wire.policy,
            phases: wire.phases,
            pi_invocations: wire.pi_invocations,
            adjudications: wire.adjudications,
            actions: wire.actions,
            issues: wire.issues,
            degradations: wire.degradations,
            statistics: wire.statistics,
            omissions: wire.omissions,
        };
        report.validate().map_err(serde::de::Error::custom)?;
        Ok(report)
    }
}

fn validate_phase_references(phase: &PhaseSummary) -> Result<(), ReportError> {
    let artifacts = phase
        .artifacts
        .iter()
        .map(|row| &row.artifact_id)
        .collect::<BTreeSet<_>>();
    let analyzers = phase
        .analyzer_runs
        .iter()
        .map(|row| &row.analyzer_id)
        .collect::<BTreeSet<_>>();
    let occurrences = phase
        .occurrences
        .iter()
        .map(|row| &row.occurrence_id)
        .collect::<BTreeSet<_>>();
    let findings = phase
        .findings
        .iter()
        .map(|row| &row.finding_id)
        .collect::<BTreeSet<_>>();
    for occurrence in &phase.occurrences {
        if !artifacts.contains(&occurrence.artifact_id)
            || !analyzers.contains(&occurrence.analyzer_id)
            || !findings.contains(&occurrence.finding_id)
        {
            return Err(ReportError::UnknownReference);
        }
    }
    for finding in &phase.findings {
        if !artifacts.contains(&finding.artifact_id)
            || finding.occurrence_ids.is_empty()
            || finding
                .occurrence_ids
                .iter()
                .any(|id| !occurrences.contains(id))
        {
            return Err(ReportError::UnknownReference);
        }
        validate_sorted_unique(&finding.occurrence_ids, |value| value)?;
    }
    for correlation in &phase.correlations {
        if correlation.finding_ids.is_empty()
            || correlation
                .finding_ids
                .iter()
                .any(|id| !findings.contains(id))
        {
            return Err(ReportError::UnknownReference);
        }
        validate_sorted_unique(&correlation.finding_ids, |value| value)?;
    }
    if phase
        .resolutions
        .iter()
        .any(|resolution| !findings.contains(&resolution.finding_id))
        || phase.resolutions.len() != phase.findings.len()
    {
        return Err(ReportError::UnknownReference);
    }
    Ok(())
}

fn validate_sorted_unique<T, K: Ord + ?Sized>(
    values: &[T],
    key: impl Fn(&T) -> &K,
) -> Result<(), ReportError> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(ReportError::NonCanonicalOrder);
    }
    Ok(())
}

fn validate_time_range(
    started: &Rfc3339Timestamp,
    finished: &Rfc3339Timestamp,
) -> Result<(), ReportError> {
    if finished.parsed() < started.parsed() {
        return Err(ReportError::InvalidTimeRange);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("processing report schema version is unsupported")]
    SchemaVersion,
    #[error("processing report exit code does not match outcome")]
    ExitMismatch,
    #[error("report identifier is not safe")]
    UnsafeIdentifier,
    #[error("SHA-256 digest is invalid or noncanonical")]
    InvalidDigest,
    #[error("timestamp is invalid")]
    InvalidTimestamp,
    #[error("timestamp is not in canonical RFC 3339 form")]
    NonCanonicalTimestamp,
    #[error("finished timestamp precedes started timestamp")]
    InvalidTimeRange,
    #[error("Git object ID is invalid")]
    InvalidGitObjectId,
    #[error("repository source has no selected surface")]
    EmptySourceScope,
    #[error("history scope has no frozen refs")]
    HistoryWithoutRefs,
    #[error("acquisition status and issues disagree")]
    AcquisitionStatusMismatch,
    #[error("configured and effective dispositions disagree")]
    DispositionMismatch,
    #[error("stage handoff fields disagree")]
    HandoffMismatch,
    #[error("stage quarantine fields disagree")]
    QuarantineMismatch,
    #[error("allowed stage is not sealed")]
    AllowedStageUnsealed,
    #[error("publication mode is invalid")]
    InvalidPublicationMode,
    #[error("artifact kind, publication type, and provenance disagree")]
    InvalidArtifactShape,
    #[error("Git provenance is invalid")]
    InvalidGitProvenance,
    #[error("analyzer coverage is invalid")]
    InvalidCoverage,
    #[error("coverage and analyzer rows disagree")]
    CoverageAnalyzerMismatch,
    #[error("finding location is invalid")]
    InvalidLocation,
    #[error("phase is absent, mislabeled, or empty")]
    InvalidPhase,
    #[error("verification exists without an initial phase")]
    VerificationWithoutInitial,
    #[error("report arrays are not in canonical unique order")]
    NonCanonicalOrder,
    #[error("report contains an unknown cross-reference")]
    UnknownReference,
    #[error("statistics do not match report rows")]
    StatisticsMismatch,
    #[error("Pi execution status and output disagree")]
    PiStatusMismatch,
    #[error("action row is invalid")]
    InvalidAction,
    #[error("omission flag and reason disagree")]
    OmissionMismatch,
    #[error("modified flag and committed actions disagree")]
    ModifiedMismatch,
    #[error("allow report violates required invariants")]
    AllowInvariant,
    #[error("allow-modified report violates required invariants")]
    AllowModifiedInvariant,
    #[error("deny report violates required invariants")]
    DenyInvariant,
    #[error("error report violates required invariants")]
    ErrorInvariant,
    #[error("decision report is missing durable context")]
    DecisionContextMissing,
    #[error("decision report has incomplete required coverage")]
    DecisionCoverageIncomplete,
    #[error("stage manifest identities are missing")]
    StageIdentityMissing,
    #[error("stage manifest identities disagree")]
    StageIdentityMismatch,
    #[error("persistence status and report digest disagree")]
    PersistenceMismatch,
    #[error("report digest does not match canonical report body")]
    ReportDigestMismatch,
    #[error("unavailable report claims durable job state")]
    UnavailablePersistenceHasDurableState,
    #[error("decision report omitted required details")]
    DecisionOmittedDetails,
    #[error("failed to serialize processing report: {0}")]
    Serialize(serde_json::Error),
}
