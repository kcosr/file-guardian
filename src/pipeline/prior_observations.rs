use serde::Serialize;
use thiserror::Error;

use crate::domain::{
    AnalyzerId, ArtifactId, ClassificationCode, ClassificationScope, ConfiguredConfidence, Digest,
    FindingCategory, NormalizedObservation, ObservationId, ReasonCode, RuleId, Severity,
    ValidatedLocation,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorObservationMode {
    None,
    FindingsSummary,
    AllNormalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    max_observations: usize,
    max_serialized_bytes: usize,
}

impl ProjectionLimits {
    pub fn new(
        max_observations: usize,
        max_serialized_bytes: usize,
    ) -> Result<Self, ProjectionError> {
        if max_observations == 0 || max_serialized_bytes == 0 {
            return Err(ProjectionError::InvalidLimits);
        }
        Ok(Self {
            max_observations,
            max_serialized_bytes,
        })
    }
}

/// An explicitly safe projection DTO. Adding fields to the normalized domain
/// model cannot accidentally expose them to a later analyzer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectedObservation {
    Finding {
        id: ObservationId,
        analyzer_id: AnalyzerId,
        rule_id: RuleId,
        artifact_id: ArtifactId,
        category: FindingCategory,
        severity: Severity,
        #[serde(skip_serializing_if = "Option::is_none")]
        location: Option<ValidatedLocation>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reason_codes: Vec<ReasonCode>,
    },
    Classification {
        id: ObservationId,
        analyzer_id: AnalyzerId,
        code: ClassificationCode,
        scope: ClassificationScope,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        subject_artifacts: Vec<ArtifactId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<ConfiguredConfidence>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reason_codes: Vec<ReasonCode>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorObservationProjection {
    mode: PriorObservationMode,
    observations: Vec<ProjectedObservation>,
    canonical_json: Vec<u8>,
    identity: Digest,
}

impl PriorObservationProjection {
    pub fn build(
        mode: PriorObservationMode,
        prior: &[NormalizedObservation],
        limits: ProjectionLimits,
    ) -> Result<Self, ProjectionError> {
        let mut observations = prior
            .iter()
            .filter_map(|observation| project(mode, observation))
            .collect::<Vec<_>>();
        observations.sort();

        if observations.len() > limits.max_observations {
            return Err(ProjectionError::ObservationLimitExceeded {
                limit: limits.max_observations,
                actual: observations.len(),
            });
        }

        #[derive(Serialize)]
        struct WireProjection<'a> {
            schema: &'static str,
            mode: PriorObservationMode,
            observations: &'a [ProjectedObservation],
        }
        let canonical_json = serde_json::to_vec(&WireProjection {
            schema: "file-guardian-prior-observations/1",
            mode,
            observations: &observations,
        })
        .map_err(ProjectionError::Serialization)?;
        if canonical_json.len() > limits.max_serialized_bytes {
            return Err(ProjectionError::SerializedByteLimitExceeded {
                limit: limits.max_serialized_bytes,
                actual: canonical_json.len(),
            });
        }
        let identity = Digest::sha256(&canonical_json);
        Ok(Self {
            mode,
            observations,
            canonical_json,
            identity,
        })
    }

    pub fn mode(&self) -> PriorObservationMode {
        self.mode
    }

    pub fn observations(&self) -> &[ProjectedObservation] {
        &self.observations
    }

    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn identity(&self) -> Digest {
        self.identity
    }
}

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("prior-observation limits must both be greater than zero")]
    InvalidLimits,
    #[error("prior-observation count {actual} exceeds limit {limit}")]
    ObservationLimitExceeded { limit: usize, actual: usize },
    #[error("prior-observation serialization size {actual} exceeds limit {limit}")]
    SerializedByteLimitExceeded { limit: usize, actual: usize },
    #[error("could not serialize prior observations: {0}")]
    Serialization(#[source] serde_json::Error),
}

fn project(
    mode: PriorObservationMode,
    observation: &NormalizedObservation,
) -> Option<ProjectedObservation> {
    match (mode, observation) {
        (PriorObservationMode::None, _) => None,
        (
            PriorObservationMode::FindingsSummary | PriorObservationMode::AllNormalized,
            NormalizedObservation::Finding(finding),
        ) => {
            let mut reason_codes = finding.evidence.reason_codes.clone();
            reason_codes.sort();
            Some(ProjectedObservation::Finding {
                id: finding.id.clone(),
                analyzer_id: finding.analyzer_id.clone(),
                rule_id: finding.rule_id.clone(),
                artifact_id: finding.artifact_id.clone(),
                category: finding.category,
                severity: finding.severity,
                location: finding.location.clone(),
                reason_codes,
            })
        }
        (
            PriorObservationMode::AllNormalized,
            NormalizedObservation::Classification(classification),
        ) => {
            let mut subject_artifacts = classification.subject_artifacts.clone();
            subject_artifacts.sort();
            let mut reason_codes = classification.reason_codes.clone();
            reason_codes.sort();
            Some(ProjectedObservation::Classification {
                id: classification.id.clone(),
                analyzer_id: classification.analyzer_id.clone(),
                code: classification.code.clone(),
                scope: classification.scope,
                subject_artifacts,
                confidence: classification.confidence,
                reason_codes,
            })
        }
        (PriorObservationMode::FindingsSummary, NormalizedObservation::Classification(_)) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Classification, Finding, FindingCategory, SafeEvidence, ValidatedLocation,
    };

    fn finding(id: &str) -> NormalizedObservation {
        NormalizedObservation::Finding(Finding {
            id: ObservationId::from_suffix(id).unwrap(),
            analyzer_id: AnalyzerId::new("secret-scanner").unwrap(),
            rule_id: RuleId::new("credential.password").unwrap(),
            artifact_id: ArtifactId::from_suffix(id).unwrap(),
            category: FindingCategory::Credential,
            severity: Severity::High,
            location: Some(ValidatedLocation::byte_range(2, 9).unwrap()),
            evidence: SafeEvidence {
                reason_codes: vec![ReasonCode::new("password-pattern").unwrap()],
            },
        })
    }

    fn classification(id: &str) -> NormalizedObservation {
        NormalizedObservation::Classification(Classification {
            id: ObservationId::from_suffix(id).unwrap(),
            analyzer_id: AnalyzerId::new("pi").unwrap(),
            code: ClassificationCode::new("restricted").unwrap(),
            scope: ClassificationScope::Tree,
            subject_artifacts: vec![ArtifactId::from_suffix(id).unwrap()],
            confidence: Some(ConfiguredConfidence::High),
            reason_codes: vec![ReasonCode::new("project-policy").unwrap()],
        })
    }

    fn limits() -> ProjectionLimits {
        ProjectionLimits::new(10, 16_384).unwrap()
    }

    #[test]
    fn modes_project_only_explicit_safe_fields() {
        let prior = vec![classification("2"), finding("1")];
        let none = PriorObservationProjection::build(PriorObservationMode::None, &prior, limits())
            .unwrap();
        assert!(none.observations().is_empty());

        let findings = PriorObservationProjection::build(
            PriorObservationMode::FindingsSummary,
            &prior,
            limits(),
        )
        .unwrap();
        assert_eq!(findings.observations().len(), 1);
        let json = std::str::from_utf8(findings.canonical_json()).unwrap();
        assert!(json.contains("password-pattern"));
        assert!(!json.contains("matched_value"));
        assert!(!json.contains("restricted"));

        let all = PriorObservationProjection::build(
            PriorObservationMode::AllNormalized,
            &prior,
            limits(),
        )
        .unwrap();
        assert_eq!(all.observations().len(), 2);
    }

    #[test]
    fn serialization_and_digest_are_canonical_across_input_order() {
        let first = PriorObservationProjection::build(
            PriorObservationMode::AllNormalized,
            &[classification("2"), finding("1")],
            limits(),
        )
        .unwrap();
        let second = PriorObservationProjection::build(
            PriorObservationMode::AllNormalized,
            &[finding("1"), classification("2")],
            limits(),
        )
        .unwrap();
        assert_eq!(first.canonical_json(), second.canonical_json());
        assert_eq!(first.identity(), second.identity());
    }

    #[test]
    fn overflow_is_an_error_and_never_truncates() {
        let count_limited = PriorObservationProjection::build(
            PriorObservationMode::FindingsSummary,
            &[finding("1"), finding("2")],
            ProjectionLimits::new(1, 16_384).unwrap(),
        );
        assert!(matches!(
            count_limited,
            Err(ProjectionError::ObservationLimitExceeded {
                limit: 1,
                actual: 2
            })
        ));

        let byte_limited = PriorObservationProjection::build(
            PriorObservationMode::FindingsSummary,
            &[finding("1")],
            ProjectionLimits::new(10, 1).unwrap(),
        );
        assert!(matches!(
            byte_limited,
            Err(ProjectionError::SerializedByteLimitExceeded { limit: 1, .. })
        ));
    }

    #[test]
    fn limits_must_be_explicit_and_positive() {
        assert!(matches!(
            ProjectionLimits::new(0, 1),
            Err(ProjectionError::InvalidLimits)
        ));
        assert!(matches!(
            ProjectionLimits::new(1, 0),
            Err(ProjectionError::InvalidLimits)
        ));
    }
}
