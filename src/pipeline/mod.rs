//! Compiled authorization pipelines and deterministic stage execution.

mod eligibility;
mod executor;
mod prior_observations;

pub use eligibility::{
    ArtifactAssignment, ArtifactSelection, EligibilityError, EligibilitySelector,
};
pub use executor::{PipelineExecution, PipelineExecutor, PipelineResult};
pub use prior_observations::{
    PriorObservationMode, PriorObservationProjection, ProjectionError, ProjectionLimits,
};

use crate::analyzers::{BuiltinRulesAnalyzer, PiClassifierAnalyzer};
use crate::domain::{AnalyzerId, IdentifierError};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Debug)]
pub enum AnalyzerImplementation {
    Builtin(BuiltinRulesAnalyzer),
    Pi(Box<PiClassifierAnalyzer>),
    /// A selected analyzer which has no secure implementation in this build.
    Unsupported {
        kind: UnsupportedAnalyzerKind,
    },
    #[cfg(test)]
    #[allow(private_interfaces)]
    Test(executor::TestAnalyzer),
}

#[cfg(test)]
impl AnalyzerImplementation {
    pub(crate) fn blocking_test(
        started: std::sync::Arc<std::sync::Barrier>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) -> Self {
        Self::Test(executor::TestAnalyzer::blocking(started, release))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedAnalyzerKind {
    External,
    #[cfg(test)]
    Pi,
}

#[derive(Clone, Debug)]
pub struct CompiledAnalyzer {
    pub id: AnalyzerId,
    pub required: bool,
    pub eligibility: EligibilitySelector,
    pub implementation: AnalyzerImplementation,
}

impl CompiledAnalyzer {
    pub fn new(
        id: AnalyzerId,
        required: bool,
        eligibility: EligibilitySelector,
        implementation: AnalyzerImplementation,
    ) -> Self {
        Self {
            id,
            required,
            eligibility,
            implementation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageExecution {
    Serial,
    Parallel { max_concurrency: usize },
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StageId(AnalyzerId);

impl StageId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        AnalyzerId::new(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for StageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct CompiledStage {
    pub id: StageId,
    pub execution: StageExecution,
    pub analyzers: Vec<CompiledAnalyzer>,
    pub prior_observations: PriorObservationMode,
    pub prior_limits: ProjectionLimits,
}

impl CompiledStage {
    pub fn new(
        id: StageId,
        execution: StageExecution,
        analyzers: Vec<CompiledAnalyzer>,
        prior_observations: PriorObservationMode,
        prior_limits: ProjectionLimits,
    ) -> Result<Self, PipelineError> {
        if analyzers.is_empty() {
            return Err(PipelineError::EmptyStage(id));
        }
        if matches!(execution, StageExecution::Parallel { max_concurrency: 0 }) {
            return Err(PipelineError::ZeroConcurrency(id));
        }
        Ok(Self {
            id,
            execution,
            analyzers,
            prior_observations,
            prior_limits,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompiledPipeline {
    pub stages: Vec<CompiledStage>,
}

impl CompiledPipeline {
    pub fn new(stages: Vec<CompiledStage>) -> Result<Self, PipelineError> {
        if stages.is_empty() {
            return Err(PipelineError::EmptyPipeline);
        }
        let mut stage_ids = BTreeSet::new();
        for stage in &stages {
            if !stage_ids.insert(stage.id.clone()) {
                return Err(PipelineError::DuplicateStage(stage.id.clone()));
            }
        }
        let mut analyzer_ids = BTreeSet::new();
        for analyzer in stages.iter().flat_map(|stage| &stage.analyzers) {
            if !analyzer_ids.insert(analyzer.id.clone()) {
                return Err(PipelineError::DuplicateAnalyzer(analyzer.id.clone()));
            }
            if !analyzer.required {
                return Err(PipelineError::OptionalAnalyzerUnsupported(
                    analyzer.id.clone(),
                ));
            }
        }
        Ok(Self { stages })
    }

    pub fn validate(&self) -> Result<(), PipelineError> {
        Self::new(self.stages.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PipelineError {
    #[error("authorization pipeline must contain at least one stage")]
    EmptyPipeline,
    #[error("authorization stage {0} must contain at least one analyzer")]
    EmptyStage(StageId),
    #[error("parallel authorization stage {0} must have positive concurrency")]
    ZeroConcurrency(StageId),
    #[error("authorization pipeline contains duplicate stage {0}")]
    DuplicateStage(StageId),
    #[error("authorization pipeline contains duplicate analyzer {0}")]
    DuplicateAnalyzer(AnalyzerId),
    #[error("optional analyzer {0} is not supported by this coverage contract")]
    OptionalAnalyzerUnsupported(AnalyzerId),
}
