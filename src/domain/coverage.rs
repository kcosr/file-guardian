use super::AnalyzerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionPhase {
    Initial,
    Verification,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalyzerCoverage {
    pub analyzer_id: AnalyzerId,
    pub phase: InspectionPhase,
    pub eligible: u64,
    pub assigned: u64,
    pub completed: u64,
    pub excluded: u64,
    pub status: CoverageStatus,
}

impl AnalyzerCoverage {
    pub fn new(
        analyzer_id: AnalyzerId,
        phase: InspectionPhase,
        eligible: u64,
        assigned: u64,
        completed: u64,
        excluded: u64,
        status: CoverageStatus,
    ) -> Result<Self, CoverageError> {
        if assigned > eligible {
            return Err(CoverageError::AssignedExceedsEligible);
        }
        if excluded > eligible {
            return Err(CoverageError::ExcludedExceedsEligible);
        }
        let accounted = completed
            .checked_add(excluded)
            .ok_or(CoverageError::AccountedExceedsAssigned)?;
        if accounted > assigned {
            return Err(CoverageError::AccountedExceedsAssigned);
        }
        if (status == CoverageStatus::Complete) != (accounted == assigned) {
            return Err(CoverageError::StatusMismatch);
        }
        Ok(Self {
            analyzer_id,
            phase,
            eligible,
            assigned,
            completed,
            excluded,
            status,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.status == CoverageStatus::Complete
            && self.completed.checked_add(self.excluded) == Some(self.assigned)
    }
}

impl<'de> Deserialize<'de> for AnalyzerCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            analyzer_id: AnalyzerId,
            phase: InspectionPhase,
            eligible: u64,
            assigned: u64,
            completed: u64,
            excluded: u64,
            status: CoverageStatus,
        }

        let fields = Fields::deserialize(deserializer)?;
        Self::new(
            fields.analyzer_id,
            fields.phase,
            fields.eligible,
            fields.assigned,
            fields.completed,
            fields.excluded,
            fields.status,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseCoverageStatus {
    Complete,
    Incomplete,
    NotRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PhaseCoverage {
    pub status: PhaseCoverageStatus,
    pub analyzers: Vec<AnalyzerCoverage>,
}

impl PhaseCoverage {
    pub fn new(
        status: PhaseCoverageStatus,
        mut analyzers: Vec<AnalyzerCoverage>,
    ) -> Result<Self, CoverageError> {
        analyzers.sort_by(|left, right| left.analyzer_id.cmp(&right.analyzer_id));
        let mut analyzer_ids = BTreeSet::new();
        if let Some(duplicate) = analyzers
            .iter()
            .find(|coverage| !analyzer_ids.insert(coverage.analyzer_id.clone()))
        {
            return Err(CoverageError::DuplicateAnalyzer(
                duplicate.analyzer_id.clone(),
            ));
        }
        match status {
            PhaseCoverageStatus::Complete if analyzers.iter().any(|item| !item.is_complete()) => {
                return Err(CoverageError::PhaseStatusMismatch)
            }
            PhaseCoverageStatus::Incomplete
                if !analyzers.is_empty() && analyzers.iter().all(AnalyzerCoverage::is_complete) =>
            {
                return Err(CoverageError::PhaseStatusMismatch)
            }
            PhaseCoverageStatus::NotRun if !analyzers.is_empty() => {
                return Err(CoverageError::NotRunHasAnalyzers)
            }
            _ => {}
        }
        Ok(Self { status, analyzers })
    }
}

impl<'de> Deserialize<'de> for PhaseCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            status: PhaseCoverageStatus,
            analyzers: Vec<AnalyzerCoverage>,
        }

        let fields = Fields::deserialize(deserializer)?;
        Self::new(fields.status, fields.analyzers).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunCoverage {
    pub initial: PhaseCoverage,
    pub verification: PhaseCoverage,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CoverageError {
    #[error("coverage contains duplicate analyzer {0}")]
    DuplicateAnalyzer(AnalyzerId),
    #[error("assigned artifact count exceeds eligible artifact count")]
    AssignedExceedsEligible,
    #[error("excluded artifact count exceeds eligible artifact count")]
    ExcludedExceedsEligible,
    #[error("completed plus excluded artifact count exceeds assigned artifact count")]
    AccountedExceedsAssigned,
    #[error("coverage status does not match whether all assigned artifacts are accounted for")]
    StatusMismatch,
    #[error("phase coverage status does not match its analyzer coverage")]
    PhaseStatusMismatch,
    #[error("not-run coverage cannot contain analyzer runs")]
    NotRunHasAnalyzers,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_coverage_requires_every_assignment() {
        assert_eq!(
            AnalyzerCoverage::new(
                AnalyzerId::new("builtin").unwrap(),
                InspectionPhase::Initial,
                2,
                2,
                1,
                0,
                CoverageStatus::Complete,
            ),
            Err(CoverageError::StatusMismatch)
        );
        assert!(AnalyzerCoverage::new(
            AnalyzerId::new("builtin").unwrap(),
            InspectionPhase::Initial,
            2,
            2,
            2,
            0,
            CoverageStatus::Complete,
        )
        .unwrap()
        .is_complete());
    }

    #[test]
    fn exclusions_are_accounted_work_but_not_completed_work() {
        let coverage = AnalyzerCoverage::new(
            AnalyzerId::new("builtin").unwrap(),
            InspectionPhase::Initial,
            3,
            3,
            1,
            2,
            CoverageStatus::Complete,
        )
        .unwrap();
        assert!(coverage.is_complete());
        assert_eq!(coverage.completed, 1);
        assert_eq!(coverage.excluded, 2);

        assert_eq!(
            AnalyzerCoverage::new(
                AnalyzerId::new("builtin").unwrap(),
                InspectionPhase::Initial,
                3,
                3,
                2,
                2,
                CoverageStatus::Complete,
            ),
            Err(CoverageError::AccountedExceedsAssigned)
        );
    }

    #[test]
    fn deserialization_revalidates_coverage_and_rejects_unknown_fields() {
        let false_complete = r#"{"analyzer_id":"builtin","phase":"initial","eligible":2,"assigned":2,"completed":1,"excluded":0,"status":"complete"}"#;
        assert!(serde_json::from_str::<AnalyzerCoverage>(false_complete).is_err());

        let unknown = r#"{"status":"not_run","analyzers":[],"extra":true}"#;
        assert!(serde_json::from_str::<PhaseCoverage>(unknown).is_err());

        let analyzer_unknown = r#"{"analyzer_id":"builtin","phase":"initial","eligible":1,"assigned":1,"completed":1,"excluded":0,"status":"complete","extra":true}"#;
        assert!(serde_json::from_str::<AnalyzerCoverage>(analyzer_unknown).is_err());

        let not_run_with_row = r#"{"status":"not_run","analyzers":[{"analyzer_id":"builtin","phase":"initial","eligible":0,"assigned":0,"completed":0,"excluded":0,"status":"complete"}]}"#;
        assert!(serde_json::from_str::<PhaseCoverage>(not_run_with_row).is_err());

        let false_incomplete = r#"{"status":"incomplete","analyzers":[{"analyzer_id":"builtin","phase":"initial","eligible":1,"assigned":1,"completed":1,"excluded":0,"status":"complete"}]}"#;
        assert!(serde_json::from_str::<PhaseCoverage>(false_incomplete).is_err());

        let duplicates = r#"{"status":"complete","analyzers":[{"analyzer_id":"builtin","phase":"initial","eligible":0,"assigned":0,"completed":0,"excluded":0,"status":"complete"},{"analyzer_id":"builtin","phase":"initial","eligible":0,"assigned":0,"completed":0,"excluded":0,"status":"complete"}]}"#;
        assert!(serde_json::from_str::<PhaseCoverage>(duplicates).is_err());
    }

    #[test]
    fn phase_coverage_is_canonical_by_analyzer_id() {
        let coverage = |id| {
            AnalyzerCoverage::new(
                AnalyzerId::new(id).unwrap(),
                InspectionPhase::Initial,
                1,
                1,
                1,
                0,
                CoverageStatus::Complete,
            )
            .unwrap()
        };

        let phase = PhaseCoverage::new(
            PhaseCoverageStatus::Complete,
            vec![coverage("zeta"), coverage("alpha")],
        )
        .unwrap();
        assert_eq!(phase.analyzers[0].analyzer_id.as_str(), "alpha");
        assert_eq!(phase.analyzers[1].analyzer_id.as_str(), "zeta");
    }

    #[test]
    fn phase_coverage_rejects_duplicate_analyzers() {
        let coverage = || {
            AnalyzerCoverage::new(
                AnalyzerId::new("builtin").unwrap(),
                InspectionPhase::Initial,
                1,
                1,
                1,
                0,
                CoverageStatus::Complete,
            )
            .unwrap()
        };

        assert_eq!(
            PhaseCoverage::new(PhaseCoverageStatus::Complete, vec![coverage(), coverage()]),
            Err(CoverageError::DuplicateAnalyzer(
                AnalyzerId::new("builtin").unwrap()
            ))
        );
    }
}
