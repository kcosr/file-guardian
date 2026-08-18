//! Source-neutral processing-job domain types.
//!
//! These types deliberately do not contain caller paths, repository locators,
//! native scanner output, or matched content. Constructors and custom
//! deserializers enforce the same invariants so persisted JSON cannot bypass
//! validation performed by Rust callers.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    domain::{
        AnalyzerId, ArtifactId, ConfiguredConfidence, Digest, FindingCategory, InspectionPhase,
        LogicalPath, ReasonCode, RuleId, Severity, SubjectId, ValidatedLocation,
    },
    policy::BindingId,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcessingDomainError {
    #[error("{kind} must start with {prefix}")]
    IdPrefix {
        kind: &'static str,
        prefix: &'static str,
    },
    #[error("processing identifier suffix must contain 1 to 96 ASCII letters, digits, '_' or '-'")]
    InvalidIdSuffix,
    #[error("git object ID must use sha1:<40 lowercase hex> or sha256:<64 lowercase hex>")]
    InvalidGitObjectId,
    #[error("git object IDs in one ref snapshot must use the same algorithm")]
    MixedGitObjectAlgorithms,
    #[error("a source scope must include a working tree or Git history")]
    EmptySourceScope,
    #[error("handoff processing requires working-tree coverage")]
    HandoffWithoutWorkingTree,
    #[error("a bare repository is valid only for report-only history processing")]
    InvalidBareRepository,
    #[error("path sources cannot carry Git repository semantics")]
    InvalidPathSource,
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("{field} contains duplicate values")]
    DuplicateCollectionValue { field: &'static str },
    #[error("terminal outcome, disposition, and handoff state are inconsistent")]
    InvalidTerminalState,
    #[error("an applied adjudication requires an exact false-positive assessment")]
    InvalidAppliedAdjudication,
    #[error("an action record is inconsistent with its action kind")]
    InvalidAction,
}

macro_rules! processing_id {
    ($name:ident, $prefix:literal, $kind:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ProcessingDomainError> {
                let value = value.into();
                let suffix =
                    value
                        .strip_prefix($prefix)
                        .ok_or(ProcessingDomainError::IdPrefix {
                            kind: $kind,
                            prefix: $prefix,
                        })?;
                if suffix.is_empty()
                    || suffix.len() > 96
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                {
                    return Err(ProcessingDomainError::InvalidIdSuffix);
                }
                Ok(Self(value))
            }

            pub fn from_suffix(suffix: impl AsRef<str>) -> Result<Self, ProcessingDomainError> {
                Self::new(format!("{}{}", $prefix, suffix.as_ref()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ProcessingDomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

processing_id!(OccurrenceId, "occ_", "occurrence identifier");
processing_id!(FindingId, "fnd_", "finding identifier");
processing_id!(CorrelationId, "cor_", "correlation identifier");
processing_id!(AdjudicationId, "adj_", "adjudication identifier");
processing_id!(ActionId, "act_", "action identifier");
processing_id!(
    ArtifactQuarantineId,
    "aq_",
    "artifact quarantine identifier"
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPurpose {
    Handoff,
    ReportOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathInputKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitTransport {
    Https,
    Ssh,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHistoryScope {
    None,
    Head,
    Reachable,
    AllRefs,
}

impl GitHistoryScope {
    pub const fn includes_history(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A canonical Git SHA-1 or SHA-256 object identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl GitObjectId {
    pub const fn algorithm(&self) -> &'static str {
        match self {
            Self::Sha1(_) => "sha1",
            Self::Sha256(_) => "sha256",
        }
    }
}

impl FromStr for GitObjectId {
    type Err = ProcessingDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (algorithm, encoded, expected) = if let Some(encoded) = value.strip_prefix("sha1:") {
            ("sha1", encoded, 40)
        } else if let Some(encoded) = value.strip_prefix("sha256:") {
            ("sha256", encoded, 64)
        } else {
            return Err(ProcessingDomainError::InvalidGitObjectId);
        };
        if encoded.len() != expected
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ProcessingDomainError::InvalidGitObjectId);
        }
        let bytes = decode_lower_hex(encoded);
        match algorithm {
            "sha1" => Ok(Self::Sha1(
                bytes.try_into().expect("validated SHA-1 length"),
            )),
            "sha256" => Ok(Self::Sha256(
                bytes.try_into().expect("validated SHA-256 length"),
            )),
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.algorithm())?;
        formatter.write_str(":")?;
        let bytes: &[u8] = match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        };
        for byte in bytes {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for GitObjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for GitObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

fn decode_lower_hex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hex input was validated"),
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitRefSnapshot {
    pub name: LogicalPath,
    pub object_id: GitObjectId,
    pub peeled_commit_id: GitObjectId,
}

impl GitRefSnapshot {
    pub fn new(
        name: LogicalPath,
        object_id: GitObjectId,
        peeled_commit_id: GitObjectId,
    ) -> Result<Self, ProcessingDomainError> {
        if object_id.algorithm() != peeled_commit_id.algorithm() {
            return Err(ProcessingDomainError::MixedGitObjectAlgorithms);
        }
        Ok(Self {
            name,
            object_id,
            peeled_commit_id,
        })
    }
}

impl<'de> Deserialize<'de> for GitRefSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            name: LogicalPath,
            object_id: GitObjectId,
            peeled_commit_id: GitObjectId,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.name, wire.object_id, wire.peeled_commit_id)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessSource {
    Path {
        input_kind: PathInputKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repository: Option<DetectedGitRepository>,
    },
    Git {
        transport: GitTransport,
        repository_id: Digest,
        resolved_head: GitObjectId,
        working_tree: bool,
        history: GitHistoryScope,
        frozen_refs: Vec<GitRefSnapshot>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectedGitRepository {
    pub repository_id: Digest,
    pub resolved_head: GitObjectId,
    pub history: GitHistoryScope,
    pub frozen_refs: Vec<GitRefSnapshot>,
}

impl ProcessSource {
    pub fn path(input_kind: PathInputKind) -> Self {
        Self::Path {
            input_kind,
            repository: None,
        }
    }

    pub fn path_repository(
        input_kind: PathInputKind,
        repository_id: Digest,
        resolved_head: GitObjectId,
        history: GitHistoryScope,
        mut frozen_refs: Vec<GitRefSnapshot>,
    ) -> Result<Self, ProcessingDomainError> {
        validate_ref_algorithms(&resolved_head, &frozen_refs)?;
        canonicalize_unique(&mut frozen_refs, "frozen_refs")?;
        Ok(Self::Path {
            input_kind,
            repository: Some(DetectedGitRepository {
                repository_id,
                resolved_head,
                history,
                frozen_refs,
            }),
        })
    }

    pub fn git(
        transport: GitTransport,
        repository_id: Digest,
        resolved_head: GitObjectId,
        working_tree: bool,
        history: GitHistoryScope,
        mut frozen_refs: Vec<GitRefSnapshot>,
    ) -> Result<Self, ProcessingDomainError> {
        validate_scope(working_tree, history)?;
        validate_ref_algorithms(&resolved_head, &frozen_refs)?;
        canonicalize_unique(&mut frozen_refs, "frozen_refs")?;
        Ok(Self::Git {
            transport,
            repository_id,
            resolved_head,
            working_tree,
            history,
            frozen_refs,
        })
    }

    pub const fn working_tree(&self) -> bool {
        match self {
            Self::Path { .. } => true,
            Self::Git { working_tree, .. } => *working_tree,
        }
    }

    pub fn history(&self) -> GitHistoryScope {
        match self {
            Self::Path { repository, .. } => repository
                .as_ref()
                .map_or(GitHistoryScope::None, |repository| repository.history),
            Self::Git { history, .. } => *history,
        }
    }
}

impl<'de> Deserialize<'de> for ProcessSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Path {
                input_kind: PathInputKind,
                #[serde(default)]
                repository: Option<DetectedGitRepository>,
            },
            Git {
                transport: GitTransport,
                repository_id: Digest,
                resolved_head: GitObjectId,
                working_tree: bool,
                history: GitHistoryScope,
                frozen_refs: Vec<GitRefSnapshot>,
            },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Path {
                input_kind,
                repository: None,
            } => Ok(Self::path(input_kind)),
            Wire::Path {
                input_kind,
                repository: Some(repository),
            } => Self::path_repository(
                input_kind,
                repository.repository_id,
                repository.resolved_head,
                repository.history,
                repository.frozen_refs,
            ),
            Wire::Git {
                transport,
                repository_id,
                resolved_head,
                working_tree,
                history,
                frozen_refs,
            } => Self::git(
                transport,
                repository_id,
                resolved_head,
                working_tree,
                history,
                frozen_refs,
            ),
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSubject {
    pub purpose: ProcessPurpose,
    pub source: ProcessSource,
}

impl ProcessSubject {
    pub fn new(
        purpose: ProcessPurpose,
        source: ProcessSource,
    ) -> Result<Self, ProcessingDomainError> {
        if purpose == ProcessPurpose::Handoff && !source.working_tree() {
            return Err(ProcessingDomainError::HandoffWithoutWorkingTree);
        }
        Ok(Self { purpose, source })
    }
}

impl<'de> Deserialize<'de> for ProcessSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            purpose: ProcessPurpose,
            source: ProcessSource,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.purpose, wire.source).map_err(serde::de::Error::custom)
    }
}

fn validate_scope(
    working_tree: bool,
    history: GitHistoryScope,
) -> Result<(), ProcessingDomainError> {
    if !working_tree && !history.includes_history() {
        return Err(ProcessingDomainError::EmptySourceScope);
    }
    Ok(())
}

fn validate_ref_algorithms(
    resolved_head: &GitObjectId,
    refs: &[GitRefSnapshot],
) -> Result<(), ProcessingDomainError> {
    if refs.iter().any(|reference| {
        reference.object_id.algorithm() != resolved_head.algorithm()
            || reference.peeled_commit_id.algorithm() != resolved_head.algorithm()
    }) {
        return Err(ProcessingDomainError::MixedGitObjectAlgorithms);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobExecutionState {
    Created,
    Acquiring,
    Acquired,
    BaselineCaptured,
    AnalyzingInitial,
    ResolvingInitial,
    PlanningActions,
    ApplyingActions,
    CapturingVerification,
    AnalyzingVerification,
    ResolvingVerification,
    RevalidatingFinal,
    Sealing,
    PreparingDecision,
    Disposing,
    PublishingReport,
    Terminal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    AllowModified,
    Deny,
    Error,
    Cancelled,
}

impl Outcome {
    pub const fn public_exit_code(self) -> i32 {
        match self {
            Self::Allow => 0,
            Self::AllowModified => 10,
            Self::Deny => 20,
            Self::Error | Self::Cancelled => 30,
        }
    }

    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow | Self::AllowModified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Retained,
    Discarded,
    Quarantined,
    RetainedError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatus {
    Unavailable,
    Available,
    HandedOff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalJobState {
    pub outcome: Outcome,
    pub disposition: Disposition,
    pub handoff: HandoffStatus,
}

impl TerminalJobState {
    pub fn new(
        outcome: Outcome,
        disposition: Disposition,
        handoff: HandoffStatus,
    ) -> Result<Self, ProcessingDomainError> {
        let valid = match handoff {
            HandoffStatus::Unavailable => true,
            HandoffStatus::Available | HandoffStatus::HandedOff => {
                outcome.is_allowed() && disposition == Disposition::Retained
            }
        } && (disposition != Disposition::RetainedError
            || matches!(outcome, Outcome::Error | Outcome::Cancelled));
        if !valid {
            return Err(ProcessingDomainError::InvalidTerminalState);
        }
        Ok(Self {
            outcome,
            disposition,
            handoff,
        })
    }
}

impl<'de> Deserialize<'de> for TerminalJobState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            outcome: Outcome,
            disposition: Disposition,
            handoff: HandoffStatus,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.outcome, wire.disposition, wire.handoff).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitBlobOccurrence {
    pub commit_id: GitObjectId,
    pub path: LogicalPath,
    #[serde(default)]
    pub refs: Vec<LogicalPath>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitProvenance {
    pub blob_id: GitObjectId,
    pub mode: GitBlobMode,
    pub occurrences: Vec<GitBlobOccurrence>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitBlobMode {
    Regular,
    Executable,
    SymbolicLink,
}

impl GitProvenance {
    pub fn new(
        blob_id: GitObjectId,
        mode: GitBlobMode,
        mut occurrences: Vec<GitBlobOccurrence>,
    ) -> Result<Self, ProcessingDomainError> {
        if occurrences.is_empty() {
            return Err(ProcessingDomainError::EmptyCollection {
                field: "git provenance occurrences",
            });
        }
        for occurrence in &mut occurrences {
            if occurrence.commit_id.algorithm() != blob_id.algorithm() {
                return Err(ProcessingDomainError::MixedGitObjectAlgorithms);
            }
            canonicalize_unique(&mut occurrence.refs, "git occurrence refs")?;
        }
        canonicalize_unique(&mut occurrences, "git provenance occurrences")?;
        Ok(Self {
            blob_id,
            mode,
            occurrences,
        })
    }
}

impl<'de> Deserialize<'de> for GitProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            blob_id: GitObjectId,
            mode: GitBlobMode,
            occurrences: Vec<GitBlobOccurrence>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.blob_id, wire.mode, wire.occurrences).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialVerificationState {
    NotApplicable,
    Unverified,
    Verified,
    VerificationError,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Occurrence {
    pub id: OccurrenceId,
    pub phase: InspectionPhase,
    pub analyzer_id: AnalyzerId,
    pub rule_id: RuleId,
    pub artifact_id: ArtifactId,
    pub category: FindingCategory,
    pub severity: Severity,
    pub location: Option<ValidatedLocation>,
    pub verification_state: CredentialVerificationState,
    pub evidence_token: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: FindingId,
    pub phase: InspectionPhase,
    pub analyzer_id: AnalyzerId,
    pub rule_id: RuleId,
    pub artifact_id: ArtifactId,
    pub category: FindingCategory,
    pub severity: Severity,
    pub location: Option<ValidatedLocation>,
    pub evidence_token: Option<Digest>,
    pub occurrence_ids: Vec<OccurrenceId>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FindingId,
        phase: InspectionPhase,
        analyzer_id: AnalyzerId,
        rule_id: RuleId,
        artifact_id: ArtifactId,
        category: FindingCategory,
        severity: Severity,
        location: Option<ValidatedLocation>,
        evidence_token: Option<Digest>,
        mut occurrence_ids: Vec<OccurrenceId>,
    ) -> Result<Self, ProcessingDomainError> {
        require_nonempty_unique(&mut occurrence_ids, "finding occurrence_ids")?;
        Ok(Self {
            id,
            phase,
            analyzer_id,
            rule_id,
            artifact_id,
            category,
            severity,
            location,
            evidence_token,
            occurrence_ids,
        })
    }
}

impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: FindingId,
            phase: InspectionPhase,
            analyzer_id: AnalyzerId,
            rule_id: RuleId,
            artifact_id: ArtifactId,
            category: FindingCategory,
            severity: Severity,
            location: Option<ValidatedLocation>,
            evidence_token: Option<Digest>,
            occurrence_ids: Vec<OccurrenceId>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.phase,
            wire.analyzer_id,
            wire.rule_id,
            wire.artifact_id,
            wire.category,
            wire.severity,
            wire.location,
            wire.evidence_token,
            wire.occurrence_ids,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    pub id: CorrelationId,
    pub phase: InspectionPhase,
    pub finding_ids: Vec<FindingId>,
    pub occurrence_ids: Vec<OccurrenceId>,
}

impl Correlation {
    pub fn new(
        id: CorrelationId,
        phase: InspectionPhase,
        mut finding_ids: Vec<FindingId>,
        mut occurrence_ids: Vec<OccurrenceId>,
    ) -> Result<Self, ProcessingDomainError> {
        require_nonempty_unique(&mut finding_ids, "correlation finding_ids")?;
        require_nonempty_unique(&mut occurrence_ids, "correlation occurrence_ids")?;
        Ok(Self {
            id,
            phase,
            finding_ids,
            occurrence_ids,
        })
    }
}

impl<'de> Deserialize<'de> for Correlation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: CorrelationId,
            phase: InspectionPhase,
            finding_ids: Vec<FindingId>,
            occurrence_ids: Vec<OccurrenceId>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.id, wire.phase, wire.finding_ids, wire.occurrence_ids)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiFindingClassification {
    Confirmed,
    LikelyTruePositive,
    LikelyFalsePositive,
    FalsePositive,
    Uncertain,
    UnableToAssess,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    None,
    Audit,
    Delete,
    Quarantine,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiFindingAssessment {
    pub classification: PiFindingClassification,
    pub confidence: ConfiguredConfidence,
    #[serde(default)]
    pub reason_codes: Vec<ReasonCode>,
    pub duplicate_of: Option<FindingId>,
    pub recommended_action: RecommendedAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicationState {
    NotRequested,
    Advisory,
    Applied,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicationReason {
    NotConfigured,
    AdvisoryOnly,
    ClearedFalsePositive,
    AssessmentNotFalsePositive,
    CorrelationNotCleared,
    IncompleteRequiredAnalysis,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Adjudication {
    pub id: AdjudicationId,
    pub phase: InspectionPhase,
    pub finding_id: FindingId,
    pub assessment: Option<PiFindingAssessment>,
    pub state: AdjudicationState,
    pub reason: AdjudicationReason,
}

impl Adjudication {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AdjudicationId,
        phase: InspectionPhase,
        finding_id: FindingId,
        assessment: Option<PiFindingAssessment>,
        state: AdjudicationState,
        reason: AdjudicationReason,
    ) -> Result<Self, ProcessingDomainError> {
        if state == AdjudicationState::Applied
            && (!assessment.as_ref().is_some_and(|value| {
                value.classification == PiFindingClassification::FalsePositive
            }) || reason != AdjudicationReason::ClearedFalsePositive)
        {
            return Err(ProcessingDomainError::InvalidAppliedAdjudication);
        }
        Ok(Self {
            id,
            phase,
            finding_id,
            assessment,
            state,
            reason,
        })
    }
}

impl<'de> Deserialize<'de> for Adjudication {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: AdjudicationId,
            phase: InspectionPhase,
            finding_id: FindingId,
            assessment: Option<PiFindingAssessment>,
            state: AdjudicationState,
            reason: AdjudicationReason,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.phase,
            wire.finding_id,
            wire.assessment,
            wire.state,
            wire.reason,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Delete,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionJournalState {
    Planned,
    Started,
    Committed,
    Fsynced,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecord {
    pub id: ActionId,
    pub kind: ActionKind,
    pub subject_id: SubjectId,
    pub finding_ids: Vec<FindingId>,
    pub binding_ids: Vec<BindingId>,
    pub planned_state: ActionJournalState,
    pub terminal_state: Option<ActionJournalState>,
    pub artifact_quarantine_id: Option<ArtifactQuarantineId>,
}

impl ActionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ActionId,
        kind: ActionKind,
        subject_id: SubjectId,
        mut finding_ids: Vec<FindingId>,
        mut binding_ids: Vec<BindingId>,
        planned_state: ActionJournalState,
        terminal_state: Option<ActionJournalState>,
        artifact_quarantine_id: Option<ArtifactQuarantineId>,
    ) -> Result<Self, ProcessingDomainError> {
        require_nonempty_unique(&mut finding_ids, "action finding_ids")?;
        require_nonempty_unique(&mut binding_ids, "action binding_ids")?;
        if planned_state != ActionJournalState::Planned
            || (kind == ActionKind::Delete && artifact_quarantine_id.is_some())
            || (kind == ActionKind::Quarantine
                && terminal_state.is_some_and(|state| {
                    matches!(
                        state,
                        ActionJournalState::Committed | ActionJournalState::Fsynced
                    )
                })
                && artifact_quarantine_id.is_none())
        {
            return Err(ProcessingDomainError::InvalidAction);
        }
        Ok(Self {
            id,
            kind,
            subject_id,
            finding_ids,
            binding_ids,
            planned_state,
            terminal_state,
            artifact_quarantine_id,
        })
    }
}

impl<'de> Deserialize<'de> for ActionRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: ActionId,
            kind: ActionKind,
            subject_id: SubjectId,
            finding_ids: Vec<FindingId>,
            binding_ids: Vec<BindingId>,
            planned_state: ActionJournalState,
            terminal_state: Option<ActionJournalState>,
            artifact_quarantine_id: Option<ArtifactQuarantineId>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.kind,
            wire.subject_id,
            wire.finding_ids,
            wire.binding_ids,
            wire.planned_state,
            wire.terminal_state,
            wire.artifact_quarantine_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn require_nonempty_unique<T: Ord>(
    values: &mut [T],
    field: &'static str,
) -> Result<(), ProcessingDomainError> {
    if values.is_empty() {
        return Err(ProcessingDomainError::EmptyCollection { field });
    }
    canonicalize_unique(values, field)
}

fn canonicalize_unique<T: Ord>(
    values: &mut [T],
    field: &'static str,
) -> Result<(), ProcessingDomainError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProcessingDomainError::DuplicateCollectionValue { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::PathSegment;

    fn path(value: &str) -> LogicalPath {
        LogicalPath::new(
            value
                .split('/')
                .map(|segment| PathSegment::utf8(segment).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn oid(byte: char) -> GitObjectId {
        format!("sha1:{}", byte.to_string().repeat(40))
            .parse()
            .unwrap()
    }

    #[test]
    fn object_ids_are_canonical_and_algorithm_typed() {
        let sha1 = oid('a');
        assert_eq!(sha1.to_string(), format!("sha1:{}", "a".repeat(40)));
        assert!(format!("sha1:{}", "A".repeat(40))
            .parse::<GitObjectId>()
            .is_err());
        assert!("sha256:00".parse::<GitObjectId>().is_err());
    }

    #[test]
    fn handoff_requires_a_working_tree() {
        let source = ProcessSource::path_repository(
            PathInputKind::Directory,
            Digest::sha256(b"repo"),
            oid('a'),
            GitHistoryScope::AllRefs,
            Vec::new(),
        )
        .unwrap();
        assert!(ProcessSubject::new(ProcessPurpose::Handoff, source).is_ok());

        let empty_scope = ProcessSource::git(
            GitTransport::Ssh,
            Digest::sha256(b"remote"),
            oid('b'),
            false,
            GitHistoryScope::None,
            Vec::new(),
        );
        assert_eq!(empty_scope, Err(ProcessingDomainError::EmptySourceScope));
    }

    #[test]
    fn source_json_is_strict_and_canonicalizes_refs() {
        let source = ProcessSource::git(
            GitTransport::Https,
            Digest::sha256(b"remote"),
            oid('a'),
            true,
            GitHistoryScope::AllRefs,
            vec![
                GitRefSnapshot::new(path("refs/tags/z"), oid('c'), oid('c')).unwrap(),
                GitRefSnapshot::new(path("refs/heads/a"), oid('b'), oid('b')).unwrap(),
            ],
        )
        .unwrap();
        let json = serde_json::to_string(&source).unwrap();
        let decoded: ProcessSource = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, source);
        assert!(json.find("refs/heads/a").is_none()); // paths are segment-structured
        let mut value = serde_json::to_value(source).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProcessSource>(value).is_err());
    }

    #[test]
    fn lifecycle_fields_are_orthogonal_but_handoff_is_gated() {
        assert!(TerminalJobState::new(
            Outcome::Deny,
            Disposition::Quarantined,
            HandoffStatus::Unavailable,
        )
        .is_ok());
        assert!(TerminalJobState::new(
            Outcome::Allow,
            Disposition::Retained,
            HandoffStatus::Available,
        )
        .is_ok());
        assert!(TerminalJobState::new(
            Outcome::Deny,
            Disposition::Retained,
            HandoffStatus::Available,
        )
        .is_err());
        assert_eq!(Outcome::Cancelled.public_exit_code(), 30);
    }

    #[test]
    fn findings_and_correlations_sort_and_reject_duplicates() {
        let finding = Finding::new(
            FindingId::from_suffix("1").unwrap(),
            InspectionPhase::Initial,
            AnalyzerId::new("gitleaks").unwrap(),
            RuleId::new("generic-password").unwrap(),
            ArtifactId::from_suffix("1").unwrap(),
            FindingCategory::Credential,
            Severity::Medium,
            None,
            Some(Digest::sha256(b"job-local-token")),
            vec![
                OccurrenceId::from_suffix("b").unwrap(),
                OccurrenceId::from_suffix("a").unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(finding.occurrence_ids[0].as_str(), "occ_a");
        assert!(Correlation::new(
            CorrelationId::from_suffix("1").unwrap(),
            InspectionPhase::Initial,
            vec![FindingId::from_suffix("1").unwrap()],
            vec![OccurrenceId::from_suffix("a").unwrap()],
        )
        .is_ok());
        assert!(Finding::new(
            FindingId::from_suffix("2").unwrap(),
            InspectionPhase::Initial,
            AnalyzerId::new("gitleaks").unwrap(),
            RuleId::new("generic-password").unwrap(),
            ArtifactId::from_suffix("2").unwrap(),
            FindingCategory::Credential,
            Severity::Low,
            None,
            None,
            vec![
                OccurrenceId::from_suffix("a").unwrap(),
                OccurrenceId::from_suffix("a").unwrap(),
            ],
        )
        .is_err());
    }

    #[test]
    fn applied_adjudication_requires_exact_false_positive_assessment() {
        let assessment = PiFindingAssessment {
            classification: PiFindingClassification::FalsePositive,
            confidence: ConfiguredConfidence::High,
            reason_codes: vec![ReasonCode::new("documented_test_fixture").unwrap()],
            duplicate_of: None,
            recommended_action: RecommendedAction::None,
        };
        assert!(Adjudication::new(
            AdjudicationId::from_suffix("1").unwrap(),
            InspectionPhase::Initial,
            FindingId::from_suffix("1").unwrap(),
            Some(assessment),
            AdjudicationState::Applied,
            AdjudicationReason::ClearedFalsePositive,
        )
        .is_ok());
        assert!(Adjudication::new(
            AdjudicationId::from_suffix("2").unwrap(),
            InspectionPhase::Initial,
            FindingId::from_suffix("1").unwrap(),
            None,
            AdjudicationState::Applied,
            AdjudicationReason::ClearedFalsePositive,
        )
        .is_err());
    }

    #[test]
    fn action_kind_controls_quarantine_identity() {
        let common = (
            ActionId::from_suffix("1").unwrap(),
            SubjectId::from_suffix("1").unwrap(),
            vec![FindingId::from_suffix("1").unwrap()],
            vec![BindingId::new("remove-fixture").unwrap()],
        );
        assert!(ActionRecord::new(
            common.0.clone(),
            ActionKind::Delete,
            common.1.clone(),
            common.2.clone(),
            common.3.clone(),
            ActionJournalState::Planned,
            Some(ActionJournalState::Committed),
            Some(ArtifactQuarantineId::from_suffix("bad").unwrap()),
        )
        .is_err());
        assert!(ActionRecord::new(
            common.0,
            ActionKind::Quarantine,
            common.1,
            common.2,
            common.3,
            ActionJournalState::Planned,
            Some(ActionJournalState::Fsynced),
            Some(ArtifactQuarantineId::from_suffix("good").unwrap()),
        )
        .is_ok());
    }

    #[test]
    fn custom_deserializers_reject_noncanonical_or_invalid_records() {
        let state = serde_json::json!({
            "outcome": "deny",
            "disposition": "retained",
            "handoff": "available"
        });
        assert!(serde_json::from_value::<TerminalJobState>(state).is_err());

        let mixed_ref = serde_json::json!({
            "name": {"segments": [{"encoding": "utf8", "value": "refs"}]},
            "object_id": format!("sha1:{}", "a".repeat(40)),
            "peeled_commit_id": format!("sha256:{}", "b".repeat(64))
        });
        assert!(serde_json::from_value::<GitRefSnapshot>(mixed_ref).is_err());
    }
}
