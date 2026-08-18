//! Strict, deterministic schema-3 policy resolution for processing findings.
//!
//! Ordinary policy and Pi adjudication remain separate. An `adjudicate`
//! binding is fail-closed as an active deny unless the host's adjudication
//! engine supplies that exact finding ID in `cleared_finding_ids`. Pi cannot
//! clear any ordinary audit, deny, delete, or quarantine directive.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::domain::{AnalyzerId, FindingCategory, RuleId, Severity};
use crate::policy::{BindingId, PolicyDirective};
use crate::processing::actions::plan::{FindingResolution, ResolutionState};
use crate::processing::config::{
    PolicySeverity, PolicyVerificationState, ProcessingFindingSelector, ProcessingPolicyBinding,
    ProcessingPolicyDirective, ProcessingProfile, UnboundObservation,
};
use crate::processing::domain::{CredentialVerificationState, Finding, FindingId, Occurrence};

const DEFAULT_BINDING_ID: &str = "__default_unbound__";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingSurface {
    MutablePhysicalRegularFile,
    PhysicalSymlink,
    RepositoryBlob,
}

impl FindingSurface {
    const fn actionable(self) -> bool {
        matches!(self, Self::MutablePhysicalRegularFile)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyFindingInput<'a> {
    pub finding: &'a Finding,
    pub occurrences: &'a [Occurrence],
    pub surface: FindingSurface,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledFindingSelector {
    pub analyzer: Option<AnalyzerId>,
    pub rule: Option<RuleId>,
    pub category: Option<FindingCategory>,
    pub severity: Option<Severity>,
    pub verification_state: Option<CredentialVerificationState>,
}

impl CompiledFindingSelector {
    fn compile(value: &ProcessingFindingSelector) -> Result<Self, ProcessingPolicyError> {
        Ok(Self {
            analyzer: value
                .analyzer
                .as_ref()
                .map(|value| AnalyzerId::new(value.clone()))
                .transpose()
                .map_err(|_| ProcessingPolicyError::InvalidConfiguration)?,
            rule: value
                .rule
                .as_ref()
                .map(|value| RuleId::new(value.clone()))
                .transpose()
                .map_err(|_| ProcessingPolicyError::InvalidConfiguration)?,
            category: value.category,
            severity: value.severity.map(domain_severity),
            verification_state: value.verification_state.map(domain_verification),
        })
    }

    fn matches(&self, input: &PolicyFindingInput<'_>) -> bool {
        self.analyzer
            .as_ref()
            .is_none_or(|value| value == &input.finding.analyzer_id)
            && self
                .rule
                .as_ref()
                .is_none_or(|value| value == &input.finding.rule_id)
            && self
                .category
                .is_none_or(|value| value == input.finding.category)
            && self
                .severity
                .is_none_or(|value| value == input.finding.severity)
            && self.verification_state.is_none_or(|expected| {
                !input.occurrences.is_empty()
                    && input
                        .occurrences
                        .iter()
                        .all(|occurrence| occurrence.verification_state == expected)
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledPolicyDirective {
    Audit,
    Deny,
    Delete,
    Quarantine,
    Adjudicate,
}

impl From<ProcessingPolicyDirective> for CompiledPolicyDirective {
    fn from(value: ProcessingPolicyDirective) -> Self {
        match value {
            ProcessingPolicyDirective::Audit => Self::Audit,
            ProcessingPolicyDirective::Deny => Self::Deny,
            ProcessingPolicyDirective::Delete => Self::Delete,
            ProcessingPolicyDirective::Quarantine => Self::Quarantine,
            ProcessingPolicyDirective::Adjudicate => Self::Adjudicate,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicyBinding {
    pub id: BindingId,
    pub priority: u32,
    pub selector: CompiledFindingSelector,
    pub directive: CompiledPolicyDirective,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledProcessingPolicy {
    pub default_unbound: UnboundObservation,
    pub bindings: Vec<CompiledPolicyBinding>,
}

impl CompiledProcessingPolicy {
    pub fn compile(profile: &ProcessingProfile) -> Result<Self, ProcessingPolicyError> {
        let mut ids = BTreeSet::new();
        let mut bindings = profile
            .bindings
            .iter()
            .map(compile_binding)
            .collect::<Result<Vec<_>, _>>()?;
        for binding in &bindings {
            if binding.id.as_str() == DEFAULT_BINDING_ID || !ids.insert(binding.id.clone()) {
                return Err(ProcessingPolicyError::InvalidConfiguration);
            }
        }
        bindings.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(Self {
            default_unbound: profile.default_unbound_observation,
            bindings,
        })
    }
}

fn compile_binding(
    value: &ProcessingPolicyBinding,
) -> Result<CompiledPolicyBinding, ProcessingPolicyError> {
    Ok(CompiledPolicyBinding {
        id: BindingId::new(value.id.clone())
            .map_err(|_| ProcessingPolicyError::InvalidConfiguration)?,
        priority: value.priority,
        selector: CompiledFindingSelector::compile(&value.selector)?,
        directive: value.directive.into(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingFindingResolution {
    pub action_resolution: FindingResolution,
    pub configured_directive: CompiledPolicyDirective,
    pub priority: Option<u32>,
    pub matched_default: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessingPolicyDecision {
    Allow,
    Deny,
    RequiresMutation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingPolicyEvaluation {
    pub decision: ProcessingPolicyDecision,
    pub resolutions: Vec<ProcessingFindingResolution>,
}

impl ProcessingPolicyEvaluation {
    pub fn action_resolutions(&self) -> Vec<FindingResolution> {
        self.resolutions
            .iter()
            .map(|resolution| resolution.action_resolution.clone())
            .collect()
    }
}

/// Resolves every finding exactly once. `cleared_finding_ids` must be the
/// trusted host adjudication output, never model-supplied data.
pub fn evaluate_processing_policy(
    policy: &CompiledProcessingPolicy,
    inputs: &[PolicyFindingInput<'_>],
    cleared_finding_ids: &BTreeSet<FindingId>,
) -> Result<ProcessingPolicyEvaluation, ProcessingPolicyError> {
    validate_inputs(inputs, cleared_finding_ids)?;
    let mut ordered = inputs.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.finding.id.cmp(&right.finding.id));
    let mut resolutions = Vec::with_capacity(ordered.len());
    for input in ordered {
        let matching = policy
            .bindings
            .iter()
            .filter(|binding| binding.selector.matches(input))
            .collect::<Vec<_>>();
        let selected = matching.first().copied();
        if let Some(selected) = selected {
            if matching
                .iter()
                .skip(1)
                .any(|other| other.priority == selected.priority)
            {
                return Err(ProcessingPolicyError::AmbiguousFinding(
                    input.finding.id.clone(),
                ));
            }
        }
        let (binding_id, configured_directive, priority, matched_default) =
            if let Some(binding) = selected {
                (
                    binding.id.clone(),
                    binding.directive,
                    Some(binding.priority),
                    false,
                )
            } else {
                let directive = match policy.default_unbound {
                    UnboundObservation::Audit => CompiledPolicyDirective::Audit,
                    UnboundObservation::Deny => CompiledPolicyDirective::Deny,
                    UnboundObservation::Error => {
                        return Err(ProcessingPolicyError::UnboundFinding(
                            input.finding.id.clone(),
                        ));
                    }
                };
                (
                    BindingId::new(DEFAULT_BINDING_ID)
                        .map_err(|_| ProcessingPolicyError::InvalidConfiguration)?,
                    directive,
                    None,
                    true,
                )
            };
        let cleared = cleared_finding_ids.contains(&input.finding.id);
        if cleared && configured_directive != CompiledPolicyDirective::Adjudicate {
            return Err(ProcessingPolicyError::UnexpectedClearance(
                input.finding.id.clone(),
            ));
        }
        if matches!(
            configured_directive,
            CompiledPolicyDirective::Delete | CompiledPolicyDirective::Quarantine
        ) && !input.surface.actionable()
        {
            return Err(ProcessingPolicyError::UnactionableFinding(
                input.finding.id.clone(),
            ));
        }
        let directive = match configured_directive {
            CompiledPolicyDirective::Audit => PolicyDirective::Audit,
            CompiledPolicyDirective::Deny | CompiledPolicyDirective::Adjudicate => {
                PolicyDirective::Deny
            }
            CompiledPolicyDirective::Delete => PolicyDirective::Delete,
            CompiledPolicyDirective::Quarantine => PolicyDirective::Quarantine,
        };
        resolutions.push(ProcessingFindingResolution {
            action_resolution: FindingResolution {
                finding_id: input.finding.id.clone(),
                binding_id,
                directive,
                state: if cleared {
                    ResolutionState::Cleared
                } else {
                    ResolutionState::Active
                },
            },
            configured_directive,
            priority,
            matched_default,
        });
    }
    let mut active = resolutions
        .iter()
        .filter(|resolution| resolution.action_resolution.state == ResolutionState::Active);
    let decision = if active
        .clone()
        .any(|resolution| resolution.action_resolution.directive == PolicyDirective::Deny)
    {
        ProcessingPolicyDecision::Deny
    } else if active.any(|resolution| {
        matches!(
            resolution.action_resolution.directive,
            PolicyDirective::Delete | PolicyDirective::Quarantine
        )
    }) {
        ProcessingPolicyDecision::RequiresMutation
    } else {
        ProcessingPolicyDecision::Allow
    };
    Ok(ProcessingPolicyEvaluation {
        decision,
        resolutions,
    })
}

fn validate_inputs(
    inputs: &[PolicyFindingInput<'_>],
    cleared: &BTreeSet<FindingId>,
) -> Result<(), ProcessingPolicyError> {
    let mut findings = BTreeSet::new();
    for input in inputs {
        if !findings.insert(input.finding.id.clone()) {
            return Err(ProcessingPolicyError::DuplicateFinding(
                input.finding.id.clone(),
            ));
        }
        let expected = input
            .finding
            .occurrence_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let actual = input
            .occurrences
            .iter()
            .map(|occurrence| occurrence.id.clone())
            .collect::<BTreeSet<_>>();
        if input.occurrences.is_empty()
            || actual.len() != input.occurrences.len()
            || actual != expected
            || input.occurrences.iter().any(|occurrence| {
                occurrence.phase != input.finding.phase
                    || occurrence.analyzer_id != input.finding.analyzer_id
                    || occurrence.rule_id != input.finding.rule_id
                    || occurrence.artifact_id != input.finding.artifact_id
                    || occurrence.category != input.finding.category
            })
        {
            return Err(ProcessingPolicyError::InvalidFinding(
                input.finding.id.clone(),
            ));
        }
    }
    if !cleared.is_subset(&findings) {
        return Err(ProcessingPolicyError::UnknownClearance);
    }
    Ok(())
}

fn domain_severity(value: PolicySeverity) -> Severity {
    match value {
        PolicySeverity::Informational => Severity::Informational,
        PolicySeverity::Low => Severity::Low,
        PolicySeverity::Medium => Severity::Medium,
        PolicySeverity::High => Severity::High,
        PolicySeverity::Critical => Severity::Critical,
    }
}

fn domain_verification(value: PolicyVerificationState) -> CredentialVerificationState {
    match value {
        PolicyVerificationState::NotApplicable => CredentialVerificationState::NotApplicable,
        PolicyVerificationState::Unverified => CredentialVerificationState::Unverified,
        PolicyVerificationState::Verified => CredentialVerificationState::Verified,
        PolicyVerificationState::VerificationError => {
            CredentialVerificationState::VerificationError
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProcessingPolicyError {
    #[error("processing policy configuration is invalid")]
    InvalidConfiguration,
    #[error("duplicate finding {0}")]
    DuplicateFinding(FindingId),
    #[error("finding {0} and its occurrences are inconsistent")]
    InvalidFinding(FindingId),
    #[error("finding {0} matches multiple bindings at the highest priority")]
    AmbiguousFinding(FindingId),
    #[error("finding {0} is unbound and the default is error")]
    UnboundFinding(FindingId),
    #[error("finding {0} cannot be cleared by its ordinary directive")]
    UnexpectedClearance(FindingId),
    #[error("a clearance references an unknown finding")]
    UnknownClearance,
    #[error("finding {0} requests mutation of a nonphysical or immutable artifact")]
    UnactionableFinding(FindingId),
}
