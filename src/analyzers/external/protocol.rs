use crate::domain::{
    AnalyzerCoverage, AnalyzerId, ArtifactId, CandidateId, CoverageStatus, Digest, FindingCategory,
    InspectionPhase, ObservationId, RuleId, Severity, ValidatedLocation,
};
use crate::processing::{GitHistoryScope, GitProvenance};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    Gitleaks,
    Trufflehog,
}

impl ScannerKind {
    pub fn executable_name(self) -> &'static str {
        match self {
            Self::Gitleaks => "gitleaks",
            Self::Trufflehog => "trufflehog",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentDisposition {
    Scan,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannerAssignment {
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
    /// Canonical UTF-8 path relative to the immutable `/input` view.
    pub view_path: String,
    pub byte_len: u64,
    pub disposition: AssignmentDisposition,
    pub surface: ScannerAssignmentSurface,
}

/// Exact source surface covered by one host assignment. A successful
/// filesystem scan therefore cannot be reported as Git-history coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScannerAssignmentSurface {
    WorkingTree,
    GitHistory {
        repository_id: Digest,
        scope: GitHistoryScope,
        provenance: GitProvenance,
    },
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScannerCoveredSurface {
    WorkingTree,
    GitHistory {
        repository_id: Digest,
        scope: GitHistoryScope,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedScannerOccurrence {
    pub occurrence_id: ObservationId,
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
    pub rule_id: RuleId,
    pub category: FindingCategory,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ValidatedLocation>,
}

/// A host-owned result. Native scanner output cannot assert coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerCompletion {
    pub kind: ScannerKind,
    pub analyzer_id: AnalyzerId,
    pub phase: InspectionPhase,
    pub surfaces: Vec<ScannerCoveredSurface>,
    pub coverage: AnalyzerCoverage,
    pub occurrences: Vec<NormalizedScannerOccurrence>,
}

impl ScannerCompletion {
    /// Completes one reviewed whole-view invocation. `assignments` is the
    /// frozen host assignment; native output contributes occurrences only.
    pub fn whole_view(
        scanner: ScannerKind,
        analyzer_id: AnalyzerId,
        phase: InspectionPhase,
        assignments: &[ScannerAssignment],
        occurrences: Vec<NormalizedScannerOccurrence>,
        max_file_bytes: u64,
        max_findings: u64,
    ) -> Result<Self, ScannerProtocolError> {
        let assigned = u64::try_from(assignments.len())
            .map_err(|_| ScannerProtocolError::AssignmentOverflow)?;
        let max_findings = usize::try_from(max_findings).unwrap_or(usize::MAX);
        if occurrences.len() > max_findings {
            return Err(ScannerProtocolError::FindingLimit);
        }

        let mut candidates = BTreeMap::new();
        let mut paths = BTreeSet::new();
        let mut surfaces = BTreeSet::new();
        let mut completed = 0_u64;
        let mut not_applicable = 0_u64;
        for assignment in assignments {
            validate_view_path(&assignment.view_path)?;
            if assignment.disposition == AssignmentDisposition::Scan
                && assignment.byte_len > max_file_bytes
            {
                return Err(ScannerProtocolError::OversizedAssignment);
            }
            if candidates
                .insert(assignment.candidate_id.clone(), assignment)
                .is_some()
                || !paths.insert(assignment.view_path.as_str())
            {
                return Err(ScannerProtocolError::DuplicateAssignment);
            }
            if matches!(
                &assignment.surface,
                ScannerAssignmentSurface::GitHistory {
                    scope: GitHistoryScope::None,
                    ..
                }
            ) {
                return Err(ScannerProtocolError::InvalidHistorySurface);
            }
            surfaces.insert(match &assignment.surface {
                ScannerAssignmentSurface::WorkingTree => ScannerCoveredSurface::WorkingTree,
                ScannerAssignmentSurface::GitHistory {
                    repository_id,
                    scope,
                    ..
                } => ScannerCoveredSurface::GitHistory {
                    repository_id: *repository_id,
                    scope: *scope,
                },
            });
            match assignment.disposition {
                AssignmentDisposition::Scan => completed += 1,
                AssignmentDisposition::NotApplicable => not_applicable += 1,
            }
        }

        let mut occurrence_ids = BTreeSet::new();
        for occurrence in &occurrences {
            if !occurrence_ids.insert(occurrence.occurrence_id.clone()) {
                return Err(ScannerProtocolError::DuplicateOccurrence);
            }
            let assignment = candidates
                .get(&occurrence.candidate_id)
                .ok_or(ScannerProtocolError::UnassignedArtifact)?;
            if assignment.artifact_id != occurrence.artifact_id {
                return Err(ScannerProtocolError::UnassignedArtifact);
            }
            if assignment.disposition != AssignmentDisposition::Scan {
                return Err(ScannerProtocolError::NotApplicableFinding);
            }
        }

        let coverage = AnalyzerCoverage::new(
            analyzer_id.clone(),
            phase,
            assigned,
            assigned,
            completed,
            not_applicable,
            CoverageStatus::Complete,
        )
        .map_err(|_| ScannerProtocolError::Coverage)?;
        Ok(Self {
            kind: scanner,
            analyzer_id,
            phase,
            surfaces: surfaces.into_iter().collect(),
            coverage,
            occurrences,
        })
    }
}

fn validate_view_path(path: &str) -> Result<(), ScannerProtocolError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.chars().any(char::is_control)
    {
        return Err(ScannerProtocolError::InvalidAssignmentPath);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScannerProtocolError {
    #[error("external scanner assignment count is unsupported")]
    AssignmentOverflow,
    #[error("external scanner assignment is duplicated")]
    DuplicateAssignment,
    #[error("external scanner Git-history assignment has no history scope")]
    InvalidHistorySurface,
    #[error("external scanner assignment path is invalid")]
    InvalidAssignmentPath,
    #[error("external scanner assignment exceeds its required-inspection limit")]
    OversizedAssignment,
    #[error("external scanner emitted too many findings")]
    FindingLimit,
    #[error("external scanner occurrence is duplicated")]
    DuplicateOccurrence,
    #[error("external scanner occurrence refers to an unassigned artifact")]
    UnassignedArtifact,
    #[error("external scanner occurrence refers to content marked not applicable")]
    NotApplicableFinding,
    #[error("external scanner completion coverage is invalid")]
    Coverage,
}

// Keep the wire boundary deliberately one-way. Native scanner schemas are
// parsed by their first-party adapters, not deserialized into this host type.
impl<'de> Deserialize<'de> for ScannerCompletion {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "scanner completion is constructed only from host-owned assignments",
        ))
    }
}
