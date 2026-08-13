//! Pure, evaluate-only policy resolution for normalized analyzer observations.

use crate::domain::{
    AnalyzerId, ClassificationCode, FindingCategory, NormalizedObservation, ObservationId, RuleId,
    Severity,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDirective {
    Audit,
    Deny,
    Delete,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveResult {
    Audit,
    Deny,
}

/// A bounded identifier suitable for a machine report.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BindingId(String);

impl BindingId {
    pub fn new(value: impl Into<String>) -> Result<Self, BindingIdError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err(BindingIdError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for BindingId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BindingId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("binding id must contain 1 to 128 safe identifier characters")]
pub struct BindingIdError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "observation_kind",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObservationSelector {
    Finding {
        #[serde(skip_serializing_if = "Option::is_none")]
        analyzer_id: Option<AnalyzerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule_id: Option<RuleId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<FindingCategory>,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimum_severity: Option<Severity>,
    },
    Classification {
        #[serde(skip_serializing_if = "Option::is_none")]
        analyzer_id: Option<AnalyzerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<ClassificationCode>,
    },
}

impl ObservationSelector {
    fn matches(&self, observation: &NormalizedObservation) -> bool {
        match (self, observation) {
            (
                Self::Finding {
                    analyzer_id,
                    rule_id,
                    category,
                    minimum_severity,
                },
                NormalizedObservation::Finding(finding),
            ) => {
                analyzer_id
                    .as_ref()
                    .is_none_or(|value| value == &finding.analyzer_id)
                    && rule_id
                        .as_ref()
                        .is_none_or(|value| value == &finding.rule_id)
                    && category.is_none_or(|value| value == finding.category)
                    && minimum_severity.is_none_or(|value| finding.severity >= value)
            }
            (
                Self::Classification { analyzer_id, code },
                NormalizedObservation::Classification(classification),
            ) => {
                analyzer_id
                    .as_ref()
                    .is_none_or(|value| value == &classification.analyzer_id)
                    && code
                        .as_ref()
                        .is_none_or(|value| value == &classification.code)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    pub id: BindingId,
    pub selector: ObservationSelector,
    pub directive: PolicyDirective,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResolution {
    pub observation_id: ObservationId,
    pub binding_id: BindingId,
    pub directive: PolicyDirective,
    pub effective_result: EffectiveResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evaluation {
    pub decision: EvaluationDecision,
    pub resolutions: Vec<PolicyResolution>,
}

/// Resolve every observation exactly once. Binding order cannot affect the result.
pub fn evaluate(
    observations: &[NormalizedObservation],
    bindings: &[PolicyBinding],
) -> Result<Evaluation, PolicyError> {
    let mut binding_ids = BTreeSet::new();
    for binding in bindings {
        if !binding_ids.insert(binding.id.clone()) {
            return Err(PolicyError::DuplicateBinding(binding.id.clone()));
        }
    }

    let mut observation_ids = BTreeSet::new();
    for observation in observations {
        let id = observation_id(observation);
        if !observation_ids.insert(id.clone()) {
            return Err(PolicyError::DuplicateObservation(id.clone()));
        }
    }

    let mut sorted = observations.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| observation_id(left).cmp(observation_id(right)));
    let mut resolutions = Vec::with_capacity(sorted.len());
    for observation in sorted {
        let id = observation_id(observation);
        let mut matches = bindings
            .iter()
            .filter(|binding| binding.selector.matches(observation));
        let binding = matches
            .next()
            .ok_or_else(|| PolicyError::UnboundObservation(id.clone()))?;
        if matches.next().is_some() {
            return Err(PolicyError::AmbiguousObservation(id.clone()));
        }
        let effective_result = match binding.directive {
            PolicyDirective::Audit => EffectiveResult::Audit,
            PolicyDirective::Deny | PolicyDirective::Delete | PolicyDirective::Quarantine => {
                EffectiveResult::Deny
            }
        };
        resolutions.push(PolicyResolution {
            observation_id: id.clone(),
            binding_id: binding.id.clone(),
            directive: binding.directive,
            effective_result,
        });
    }

    let decision = if resolutions
        .iter()
        .any(|resolution| resolution.effective_result == EffectiveResult::Deny)
    {
        EvaluationDecision::Deny
    } else {
        EvaluationDecision::Allow
    };
    Ok(Evaluation {
        decision,
        resolutions,
    })
}

fn observation_id(observation: &NormalizedObservation) -> &ObservationId {
    match observation {
        NormalizedObservation::Finding(finding) => &finding.id,
        NormalizedObservation::Classification(classification) => &classification.id,
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    #[error("duplicate policy binding {0}")]
    DuplicateBinding(BindingId),
    #[error("duplicate observation {0}")]
    DuplicateObservation(ObservationId),
    #[error("observation {0} has no policy binding")]
    UnboundObservation(ObservationId),
    #[error("observation {0} matches more than one policy binding")]
    AmbiguousObservation(ObservationId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ArtifactId, Finding, ObservationId, RuleId, SafeEvidence, Severity};

    fn finding(id: &str, rule: &str, severity: Severity) -> NormalizedObservation {
        NormalizedObservation::Finding(Finding {
            id: ObservationId::from_suffix(id).unwrap(),
            analyzer_id: AnalyzerId::new("builtin").unwrap(),
            rule_id: RuleId::new(rule).unwrap(),
            artifact_id: ArtifactId::from_suffix(id).unwrap(),
            category: FindingCategory::Credential,
            severity,
            location: None,
            evidence: SafeEvidence::default(),
        })
    }

    fn binding(id: &str, rule: Option<&str>, directive: PolicyDirective) -> PolicyBinding {
        PolicyBinding {
            id: BindingId::new(id).unwrap(),
            selector: ObservationSelector::Finding {
                analyzer_id: Some(AnalyzerId::new("builtin").unwrap()),
                rule_id: rule.map(|value| RuleId::new(value).unwrap()),
                category: None,
                minimum_severity: None,
            },
            directive,
        }
    }

    #[test]
    fn audit_allows_and_canonicalizes_resolution_order() {
        let observations = vec![
            finding("2", "two", Severity::High),
            finding("1", "one", Severity::Low),
        ];
        let bindings = vec![
            binding("second", Some("two"), PolicyDirective::Audit),
            binding("first", Some("one"), PolicyDirective::Audit),
        ];
        let result = evaluate(&observations, &bindings).unwrap();
        assert_eq!(result.decision, EvaluationDecision::Allow);
        assert_eq!(result.resolutions[0].observation_id.as_str(), "obs_1");
        assert_eq!(result.resolutions[1].observation_id.as_str(), "obs_2");
    }

    #[test]
    fn every_mutating_directive_denies_in_evaluate_mode() {
        for directive in [
            PolicyDirective::Deny,
            PolicyDirective::Delete,
            PolicyDirective::Quarantine,
        ] {
            let result = evaluate(
                &[finding("1", "one", Severity::Low)],
                &[binding("binding", Some("one"), directive)],
            )
            .unwrap();
            assert_eq!(result.decision, EvaluationDecision::Deny);
            assert_eq!(result.resolutions[0].directive, directive);
            assert_eq!(
                result.resolutions[0].effective_result,
                EffectiveResult::Deny
            );
        }
    }

    #[test]
    fn missing_and_overlapping_bindings_fail_closed() {
        let observation = finding("1", "one", Severity::High);
        assert_eq!(
            evaluate(std::slice::from_ref(&observation), &[]),
            Err(PolicyError::UnboundObservation(
                ObservationId::from_suffix("1").unwrap()
            ))
        );
        let broad = binding("broad", None, PolicyDirective::Audit);
        let exact = binding("exact", Some("one"), PolicyDirective::Deny);
        assert_eq!(
            evaluate(&[observation], &[broad, exact]),
            Err(PolicyError::AmbiguousObservation(
                ObservationId::from_suffix("1").unwrap()
            ))
        );
    }
}
