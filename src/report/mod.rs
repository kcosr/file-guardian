//! Stable machine-readable authorization report schema.

use crate::{
    domain::{
        ArtifactId, ArtifactKind, Digest, InspectionIssue, InspectionPhase, LogicalPath,
        NormalizedObservation, ObservationId, PhaseCoverageStatus, RunCoverage, RunId, SubjectId,
    },
    policy::{EffectiveResult, PolicyDirective, PolicyResolution},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, io::Write};
use thiserror::Error;

pub const REPORT_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOutcome {
    Allow,
    AllowModified,
    Deny,
    Error,
}

impl AuthorizationOutcome {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Allow => 0,
            Self::AllowModified => 10,
            Self::Deny => 20,
            Self::Error => 30,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReportIdentifier(String);

impl ReportIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ReportIdentifierError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err(ReportIdentifierError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReportIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for ReportIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ReportIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("report identifier must contain 1 to 128 safe identifier characters")]
pub struct ReportIdentifierError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveActionMode {
    Evaluate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    pub profile_id: ReportIdentifier,
    pub identity: Digest,
    pub pipeline_id: ReportIdentifier,
    pub pipeline_identity: Digest,
    pub effective_action_mode: EffectiveActionMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputSummary {
    pub kind: InputKind,
    pub initial_manifest_identity: Digest,
    pub final_manifest_identity: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSummary {
    pub artifact_id: ArtifactId,
    pub subject_id: SubjectId,
    pub kind: ArtifactKind,
    pub relative_path: LogicalPath,
    pub byte_len: u64,
    pub content_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineRunStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineRun {
    pub phase: InspectionPhase,
    pub status: PipelineRunStatus,
    pub stages_completed: u64,
    pub analyzers_completed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionRecord {
    Delete {
        artifact_id: ArtifactId,
    },
    Quarantine {
        artifact_id: ArtifactId,
        quarantine_id: ReportIdentifier,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportStatistics {
    pub physical_artifacts: u64,
    pub logical_artifacts: u64,
    pub observations: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ReportData {
    pub run_id: RunId,
    pub request_id: Option<ReportIdentifier>,
    pub outcome: AuthorizationOutcome,
    pub coverage: RunCoverage,
    pub policy: Option<PolicySummary>,
    pub input: Option<InputSummary>,
    pub artifacts: Vec<ArtifactSummary>,
    pub pipeline_runs: Vec<PipelineRun>,
    pub observations: Vec<NormalizedObservation>,
    pub resolutions: Vec<PolicyResolution>,
    pub actions: Vec<ActionRecord>,
    pub issues: Vec<InspectionIssue>,
    pub statistics: ReportStatistics,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationReport {
    schema_version: String,
    pub run_id: RunId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<ReportIdentifier>,
    pub outcome: AuthorizationOutcome,
    pub exit_code: i32,
    pub modified: bool,
    pub coverage: RunCoverage,
    pub policy: Option<PolicySummary>,
    pub input: Option<InputSummary>,
    pub artifacts: Vec<ArtifactSummary>,
    pub pipeline_runs: Vec<PipelineRun>,
    pub observations: Vec<NormalizedObservation>,
    pub resolutions: Vec<PolicyResolution>,
    pub actions: Vec<ActionRecord>,
    pub issues: Vec<InspectionIssue>,
    pub statistics: ReportStatistics,
}

impl AuthorizationReport {
    pub fn new(mut data: ReportData) -> Result<Self, ReportError> {
        data.artifacts
            .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        data.pipeline_runs.sort();
        data.observations.sort();
        data.resolutions
            .sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        data.issues.sort_by(|left, right| {
            (
                left.phase,
                &left.code,
                &left.analyzer_id,
                &left.subject_id,
                &left.artifact_id,
                left.message.as_str(),
            )
                .cmp(&(
                    right.phase,
                    &right.code,
                    &right.analyzer_id,
                    &right.subject_id,
                    &right.artifact_id,
                    right.message.as_str(),
                ))
        });

        let report = Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            run_id: data.run_id,
            request_id: data.request_id,
            outcome: data.outcome,
            exit_code: data.outcome.exit_code(),
            modified: false,
            coverage: data.coverage,
            policy: data.policy,
            input: data.input,
            artifacts: data.artifacts,
            pipeline_runs: data.pipeline_runs,
            observations: data.observations,
            resolutions: data.resolutions,
            actions: data.actions,
            issues: data.issues,
            statistics: data.statistics,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn validate(&self) -> Result<(), ReportError> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(ReportError::SchemaVersion);
        }
        if self.exit_code != self.outcome.exit_code() {
            return Err(ReportError::ExitMismatch);
        }
        if self.modified || !self.actions.is_empty() {
            return Err(ReportError::MutationUnsupported);
        }
        if self.outcome == AuthorizationOutcome::AllowModified {
            return Err(ReportError::AllowModifiedUnsupported);
        }
        if self.statistics.observations != self.observations.len() as u64 {
            return Err(ReportError::ObservationCount);
        }
        if self.statistics.logical_artifacts != self.artifacts.len() as u64 {
            return Err(ReportError::ArtifactCount);
        }
        let physical_subjects = self
            .artifacts
            .iter()
            .map(|artifact| &artifact.subject_id)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        if self.statistics.physical_artifacts != physical_subjects {
            return Err(ReportError::PhysicalArtifactCount);
        }

        validate_unique_artifacts(&self.artifacts)?;
        validate_unique_observations(&self.observations)?;
        validate_observation_artifacts(&self.artifacts, &self.observations)?;
        validate_pipeline_runs(&self.pipeline_runs, &self.coverage)?;
        validate_resolutions(&self.observations, &self.resolutions, self.outcome)?;

        if self.input.is_none() && !self.artifacts.is_empty() {
            return Err(ReportError::ArtifactsWithoutInput);
        }

        match self.outcome {
            AuthorizationOutcome::Allow | AuthorizationOutcome::Deny => {
                if self.coverage.initial.status != PhaseCoverageStatus::Complete {
                    return Err(ReportError::IncompleteDecisionCoverage);
                }
                if self.coverage.verification.status != PhaseCoverageStatus::NotRun {
                    return Err(ReportError::UnexpectedVerification);
                }
                if self.policy.is_none() || self.input.is_none() {
                    return Err(ReportError::DecisionContextMissing);
                }
                let input = self.input.as_ref().expect("checked above");
                if input.final_manifest_identity != Some(input.initial_manifest_identity) {
                    return Err(ReportError::EvaluateManifestChanged);
                }
                if !self.issues.is_empty() {
                    return Err(ReportError::DecisionHasIssues);
                }
                if !self.pipeline_runs.iter().any(|run| {
                    run.phase == InspectionPhase::Initial
                        && run.status == PipelineRunStatus::Complete
                }) {
                    return Err(ReportError::DecisionPipelineMissing);
                }
            }
            AuthorizationOutcome::Error => {
                if self.issues.is_empty() {
                    return Err(ReportError::ErrorWithoutIssue);
                }
            }
            AuthorizationOutcome::AllowModified => unreachable!("rejected above"),
        }
        Ok(())
    }

    /// Serialize exactly one compact JSON value followed by one newline.
    pub fn to_json_line(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut output = serde_json::to_vec(self)?;
        output.push(b'\n');
        Ok(output)
    }

    pub fn write_json_line(&self, writer: &mut impl Write) -> Result<(), ReportWriteError> {
        writer.write_all(&self.to_json_line()?)?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AuthorizationReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireReport {
            schema_version: String,
            run_id: RunId,
            request_id: Option<ReportIdentifier>,
            outcome: AuthorizationOutcome,
            exit_code: i32,
            modified: bool,
            coverage: RunCoverage,
            policy: Option<PolicySummary>,
            input: Option<InputSummary>,
            artifacts: Vec<ArtifactSummary>,
            pipeline_runs: Vec<PipelineRun>,
            observations: Vec<NormalizedObservation>,
            resolutions: Vec<PolicyResolution>,
            actions: Vec<ActionRecord>,
            issues: Vec<InspectionIssue>,
            statistics: ReportStatistics,
        }

        let wire = WireReport::deserialize(deserializer)?;
        let report = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            request_id: wire.request_id,
            outcome: wire.outcome,
            exit_code: wire.exit_code,
            modified: wire.modified,
            coverage: wire.coverage,
            policy: wire.policy,
            input: wire.input,
            artifacts: wire.artifacts,
            pipeline_runs: wire.pipeline_runs,
            observations: wire.observations,
            resolutions: wire.resolutions,
            actions: wire.actions,
            issues: wire.issues,
            statistics: wire.statistics,
        };
        report.validate().map_err(serde::de::Error::custom)?;
        Ok(report)
    }
}

fn validate_unique_artifacts(artifacts: &[ArtifactSummary]) -> Result<(), ReportError> {
    let mut ids = BTreeSet::new();
    if artifacts
        .iter()
        .any(|artifact| !ids.insert(&artifact.artifact_id))
    {
        return Err(ReportError::DuplicateArtifact);
    }
    Ok(())
}

fn validate_unique_observations(observations: &[NormalizedObservation]) -> Result<(), ReportError> {
    let mut ids = BTreeSet::new();
    if observations
        .iter()
        .any(|observation| !ids.insert(observation_id(observation)))
    {
        return Err(ReportError::DuplicateObservation);
    }
    Ok(())
}

fn validate_observation_artifacts(
    artifacts: &[ArtifactSummary],
    observations: &[NormalizedObservation],
) -> Result<(), ReportError> {
    let artifact_ids = artifacts
        .iter()
        .map(|artifact| &artifact.artifact_id)
        .collect::<BTreeSet<_>>();
    for observation in observations {
        let valid = match observation {
            NormalizedObservation::Finding(finding) => artifact_ids.contains(&finding.artifact_id),
            NormalizedObservation::Classification(classification) => classification
                .subject_artifacts
                .iter()
                .all(|artifact_id| artifact_ids.contains(artifact_id)),
        };
        if !valid {
            return Err(ReportError::ObservationUnknownArtifact);
        }
    }
    Ok(())
}

fn validate_pipeline_runs(runs: &[PipelineRun], coverage: &RunCoverage) -> Result<(), ReportError> {
    let mut phases = BTreeSet::new();
    for run in runs {
        if !phases.insert(run.phase) {
            return Err(ReportError::DuplicatePipelinePhase);
        }
        let expected = match run.phase {
            InspectionPhase::Initial => coverage.initial.status,
            InspectionPhase::Verification => coverage.verification.status,
        };
        match (run.status, expected) {
            (PipelineRunStatus::Complete, PhaseCoverageStatus::Complete)
            | (PipelineRunStatus::Incomplete, PhaseCoverageStatus::Incomplete) => {}
            _ => return Err(ReportError::PipelineCoverageMismatch),
        }
    }
    Ok(())
}

fn validate_resolutions(
    observations: &[NormalizedObservation],
    resolutions: &[PolicyResolution],
    outcome: AuthorizationOutcome,
) -> Result<(), ReportError> {
    let observation_ids = observations
        .iter()
        .map(observation_id)
        .collect::<BTreeSet<_>>();
    let mut resolved = BTreeSet::new();
    let mut any_deny = false;
    for resolution in resolutions {
        if !observation_ids.contains(&resolution.observation_id) {
            return Err(ReportError::ResolutionUnknownObservation);
        }
        if !resolved.insert(&resolution.observation_id) {
            return Err(ReportError::DuplicateResolution);
        }
        let expected = match resolution.directive {
            PolicyDirective::Audit => EffectiveResult::Audit,
            PolicyDirective::Deny | PolicyDirective::Delete | PolicyDirective::Quarantine => {
                EffectiveResult::Deny
            }
        };
        if resolution.effective_result != expected {
            return Err(ReportError::ResolutionEffectiveResult);
        }
        any_deny |= resolution.effective_result == EffectiveResult::Deny;
    }

    if outcome != AuthorizationOutcome::Error && resolved.len() != observation_ids.len() {
        return Err(ReportError::UnresolvedObservation);
    }
    match outcome {
        AuthorizationOutcome::Allow if any_deny => Err(ReportError::OutcomeResolutionMismatch),
        AuthorizationOutcome::Deny if !any_deny => Err(ReportError::OutcomeResolutionMismatch),
        _ => Ok(()),
    }
}

fn observation_id(observation: &NormalizedObservation) -> &ObservationId {
    match observation {
        NormalizedObservation::Finding(finding) => &finding.id,
        NormalizedObservation::Classification(classification) => &classification.id,
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReportError {
    #[error("unsupported report schema version")]
    SchemaVersion,
    #[error("outcome and exit code disagree")]
    ExitMismatch,
    #[error("mutation actions are not supported in evaluate-only authorization")]
    MutationUnsupported,
    #[error("allow_modified is modeled but unavailable in evaluate-only authorization")]
    AllowModifiedUnsupported,
    #[error("statistics observation count does not match report observations")]
    ObservationCount,
    #[error("statistics logical artifact count does not match report artifacts")]
    ArtifactCount,
    #[error("statistics physical artifact count does not match report subjects")]
    PhysicalArtifactCount,
    #[error("report contains duplicate artifact ids")]
    DuplicateArtifact,
    #[error("report contains duplicate observation ids")]
    DuplicateObservation,
    #[error("observation references an unknown artifact")]
    ObservationUnknownArtifact,
    #[error("report contains more than one pipeline run for a phase")]
    DuplicatePipelinePhase,
    #[error("pipeline run status disagrees with coverage")]
    PipelineCoverageMismatch,
    #[error("resolution references an unknown observation")]
    ResolutionUnknownObservation,
    #[error("report contains duplicate resolutions")]
    DuplicateResolution,
    #[error("resolution effective result disagrees with its directive")]
    ResolutionEffectiveResult,
    #[error("complete policy decision has an unresolved observation")]
    UnresolvedObservation,
    #[error("outcome disagrees with policy resolutions")]
    OutcomeResolutionMismatch,
    #[error("evaluate-only input manifest changed")]
    EvaluateManifestChanged,
    #[error("artifacts cannot be reported without input context")]
    ArtifactsWithoutInput,
    #[error("allow or deny requires complete initial coverage")]
    IncompleteDecisionCoverage,
    #[error("evaluate-only authorization must not run verification")]
    UnexpectedVerification,
    #[error("allow or deny requires policy and input context")]
    DecisionContextMissing,
    #[error("allow or deny cannot contain operational issues")]
    DecisionHasIssues,
    #[error("allow or deny requires a complete initial pipeline run")]
    DecisionPipelineMissing,
    #[error("error outcome requires at least one typed issue")]
    ErrorWithoutIssue,
}

#[derive(Debug, Error)]
pub enum ReportWriteError {
    #[error("could not serialize authorization report: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("could not write authorization report: {0}")]
    Io(#[from] std::io::Error),
}
