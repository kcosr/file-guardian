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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
        if completed > assigned {
            return Err(CoverageError::CompletedExceedsAssigned);
        }
        if status == CoverageStatus::Complete && completed != assigned {
            return Err(CoverageError::FalseComplete);
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
        self.status == CoverageStatus::Complete && self.completed == self.assigned
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseCoverageStatus {
    Complete,
    Incomplete,
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhaseCoverage {
    pub status: PhaseCoverageStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
                return Err(CoverageError::FalseComplete)
            }
            PhaseCoverageStatus::NotRun if !analyzers.is_empty() => {
                return Err(CoverageError::NotRunHasAnalyzers)
            }
            _ => {}
        }
        Ok(Self { status, analyzers })
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
    #[error("completed artifact count exceeds assigned artifact count")]
    CompletedExceedsAssigned,
    #[error("coverage cannot be complete while assigned work is incomplete")]
    FalseComplete,
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
            Err(CoverageError::FalseComplete)
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
