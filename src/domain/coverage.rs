use serde::{Deserialize, Serialize};
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
    pub phase: InspectionPhase,
    pub eligible: u64,
    pub assigned: u64,
    pub completed: u64,
    pub excluded: u64,
    pub status: CoverageStatus,
}

impl AnalyzerCoverage {
    pub fn new(
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
        if completed > assigned {
            return Err(CoverageError::CompletedExceedsAssigned);
        }
        if status == CoverageStatus::Complete && completed != assigned {
            return Err(CoverageError::FalseComplete);
        }
        Ok(Self {
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
        analyzers.sort_by_key(|coverage| {
            (
                coverage.phase,
                coverage.eligible,
                coverage.assigned,
                coverage.completed,
                coverage.excluded,
            )
        });
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
    #[error("assigned artifact count exceeds eligible artifact count")]
    AssignedExceedsEligible,
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
}
