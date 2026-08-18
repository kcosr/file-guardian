use std::collections::BTreeSet;

use file_guardian::domain::{
    AnalyzerId, ArtifactId, FindingCategory, InspectionPhase, RuleId, Severity,
};
use file_guardian::policy::{BindingId, PolicyDirective};
use file_guardian::processing::actions::plan::ResolutionState;
use file_guardian::processing::config::{
    ProcessingConfigFile, ProcessingFindingSelector, ProcessingPolicyBinding,
    ProcessingPolicyDirective, UnboundObservation,
};
use file_guardian::processing::domain::{
    CredentialVerificationState, Finding, FindingId, Occurrence, OccurrenceId,
};
use file_guardian::processing::policy::{
    evaluate_processing_policy, CompiledFindingSelector, CompiledPolicyBinding,
    CompiledPolicyDirective, CompiledProcessingPolicy, FindingSurface, PolicyFindingInput,
    ProcessingPolicyDecision, ProcessingPolicyError,
};

struct Fixture {
    finding: Finding,
    occurrences: Vec<Occurrence>,
}

impl Fixture {
    fn input(&self, surface: FindingSurface) -> PolicyFindingInput<'_> {
        PolicyFindingInput {
            finding: &self.finding,
            occurrences: &self.occurrences,
            surface,
        }
    }
}

fn fixture(
    suffix: &str,
    analyzer: &str,
    rule: &str,
    category: FindingCategory,
    severity: Severity,
    verification: CredentialVerificationState,
) -> Fixture {
    let occurrence_id = OccurrenceId::from_suffix(format!("{suffix}-occ")).unwrap();
    let artifact_id = ArtifactId::from_suffix(format!("{suffix}-artifact")).unwrap();
    let analyzer_id = AnalyzerId::new(analyzer).unwrap();
    let rule_id = RuleId::new(rule).unwrap();
    let occurrence = Occurrence {
        id: occurrence_id.clone(),
        phase: InspectionPhase::Initial,
        analyzer_id: analyzer_id.clone(),
        rule_id: rule_id.clone(),
        artifact_id: artifact_id.clone(),
        category,
        severity,
        location: None,
        verification_state: verification,
        evidence_token: None,
    };
    let finding = Finding::new(
        FindingId::from_suffix(suffix).unwrap(),
        InspectionPhase::Initial,
        analyzer_id,
        rule_id,
        artifact_id,
        category,
        severity,
        None,
        None,
        vec![occurrence_id],
    )
    .unwrap();
    Fixture {
        finding,
        occurrences: vec![occurrence],
    }
}

fn selector(
    analyzer: Option<&str>,
    rule: Option<&str>,
    category: Option<FindingCategory>,
    severity: Option<Severity>,
    verification_state: Option<CredentialVerificationState>,
) -> CompiledFindingSelector {
    CompiledFindingSelector {
        analyzer: analyzer.map(|value| AnalyzerId::new(value).unwrap()),
        rule: rule.map(|value| RuleId::new(value).unwrap()),
        category,
        severity,
        verification_state,
    }
}

fn binding(
    id: &str,
    priority: u32,
    selector: CompiledFindingSelector,
    directive: CompiledPolicyDirective,
) -> CompiledPolicyBinding {
    CompiledPolicyBinding {
        id: BindingId::new(id).unwrap(),
        priority,
        selector,
        directive,
    }
}

fn policy(
    default_unbound: UnboundObservation,
    mut bindings: Vec<CompiledPolicyBinding>,
) -> CompiledProcessingPolicy {
    bindings.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
    CompiledProcessingPolicy {
        default_unbound,
        bindings,
    }
}

#[test]
fn exact_selectors_and_priority_resolve_deterministically() {
    let finding = fixture(
        "credential",
        "gitleaks",
        "generic-password",
        FindingCategory::Credential,
        Severity::High,
        CredentialVerificationState::Verified,
    );
    let broad = binding(
        "broad",
        10,
        selector(None, None, Some(FindingCategory::Credential), None, None),
        CompiledPolicyDirective::Audit,
    );
    let exact = binding(
        "exact",
        50,
        selector(
            Some("gitleaks"),
            Some("generic-password"),
            Some(FindingCategory::Credential),
            Some(Severity::High),
            Some(CredentialVerificationState::Verified),
        ),
        CompiledPolicyDirective::Deny,
    );
    for bindings in [vec![broad.clone(), exact.clone()], vec![exact, broad]] {
        let result = evaluate_processing_policy(
            &policy(UnboundObservation::Error, bindings),
            &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(result.decision, ProcessingPolicyDecision::Deny);
        assert_eq!(
            result.resolutions[0].action_resolution.binding_id.as_str(),
            "exact"
        );
        assert_eq!(result.resolutions[0].priority, Some(50));
    }
}

#[test]
fn equal_highest_priority_matches_are_ambiguous() {
    let finding = fixture(
        "ambiguous",
        "builtin",
        "rule",
        FindingCategory::Secret,
        Severity::Critical,
        CredentialVerificationState::Unverified,
    );
    let compiled = policy(
        UnboundObservation::Deny,
        vec![
            binding(
                "one",
                10,
                selector(Some("builtin"), None, None, None, None),
                CompiledPolicyDirective::Deny,
            ),
            binding(
                "two",
                10,
                selector(None, Some("rule"), None, None, None),
                CompiledPolicyDirective::Audit,
            ),
        ],
    );
    assert_eq!(
        evaluate_processing_policy(
            &compiled,
            &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
            &BTreeSet::new(),
        )
        .unwrap_err(),
        ProcessingPolicyError::AmbiguousFinding(finding.finding.id)
    );
}

#[test]
fn unbound_default_is_total_and_error_remains_fail_closed() {
    let finding = fixture(
        "unbound",
        "builtin",
        "rule",
        FindingCategory::Filename,
        Severity::Low,
        CredentialVerificationState::NotApplicable,
    );
    for (default, decision, directive) in [
        (
            UnboundObservation::Audit,
            ProcessingPolicyDecision::Allow,
            PolicyDirective::Audit,
        ),
        (
            UnboundObservation::Deny,
            ProcessingPolicyDecision::Deny,
            PolicyDirective::Deny,
        ),
    ] {
        let result = evaluate_processing_policy(
            &policy(default, vec![]),
            &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(result.decision, decision);
        assert_eq!(result.resolutions[0].action_resolution.directive, directive);
        assert!(result.resolutions[0].matched_default);
    }
    assert!(matches!(
        evaluate_processing_policy(
            &policy(UnboundObservation::Error, vec![]),
            &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
            &BTreeSet::new(),
        ),
        Err(ProcessingPolicyError::UnboundFinding(_))
    ));
}

#[test]
fn history_and_symlinks_can_be_denied_or_audited_but_never_mutated() {
    let finding = fixture(
        "history",
        "gitleaks",
        "generic-password",
        FindingCategory::Credential,
        Severity::High,
        CredentialVerificationState::Unverified,
    );
    for surface in [
        FindingSurface::RepositoryBlob,
        FindingSurface::PhysicalSymlink,
    ] {
        for directive in [
            CompiledPolicyDirective::Delete,
            CompiledPolicyDirective::Quarantine,
        ] {
            let result = evaluate_processing_policy(
                &policy(
                    UnboundObservation::Error,
                    vec![binding(
                        "mutation",
                        1,
                        selector(None, None, None, None, None),
                        directive,
                    )],
                ),
                &[finding.input(surface)],
                &BTreeSet::new(),
            );
            assert!(matches!(
                result,
                Err(ProcessingPolicyError::UnactionableFinding(_))
            ));
        }
    }
}

#[test]
fn a_surviving_deny_suppresses_mutation_and_outputs_action_plan_inputs() {
    let deny = fixture(
        "deny",
        "builtin",
        "private-key",
        FindingCategory::Credential,
        Severity::Critical,
        CredentialVerificationState::Verified,
    );
    let remove = fixture(
        "remove",
        "gitleaks",
        "generic-password",
        FindingCategory::Credential,
        Severity::Medium,
        CredentialVerificationState::Unverified,
    );
    let compiled = policy(
        UnboundObservation::Error,
        vec![
            binding(
                "hard-deny",
                20,
                selector(None, Some("private-key"), None, None, None),
                CompiledPolicyDirective::Deny,
            ),
            binding(
                "delete-file",
                20,
                selector(None, Some("generic-password"), None, None, None),
                CompiledPolicyDirective::Delete,
            ),
        ],
    );
    let result = evaluate_processing_policy(
        &compiled,
        &[
            remove.input(FindingSurface::MutablePhysicalRegularFile),
            deny.input(FindingSurface::MutablePhysicalRegularFile),
        ],
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(result.decision, ProcessingPolicyDecision::Deny);
    let actions = result.action_resolutions();
    assert_eq!(actions.len(), 2);
    assert!(actions
        .iter()
        .any(|value| value.directive == PolicyDirective::Deny));
    assert!(actions
        .iter()
        .any(|value| value.directive == PolicyDirective::Delete));
}

#[test]
fn only_an_exact_adjudicate_binding_can_consume_host_clearance() {
    let finding = fixture(
        "fixture-password",
        "gitleaks",
        "generic-password",
        FindingCategory::Credential,
        Severity::Medium,
        CredentialVerificationState::Unverified,
    );
    let adjudicate = policy(
        UnboundObservation::Error,
        vec![binding(
            "review-fixture",
            100,
            selector(Some("gitleaks"), Some("generic-password"), None, None, None),
            CompiledPolicyDirective::Adjudicate,
        )],
    );
    let active = evaluate_processing_policy(
        &adjudicate,
        &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(active.decision, ProcessingPolicyDecision::Deny);

    let cleared_ids = BTreeSet::from([finding.finding.id.clone()]);
    let cleared = evaluate_processing_policy(
        &adjudicate,
        &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
        &cleared_ids,
    )
    .unwrap();
    assert_eq!(cleared.decision, ProcessingPolicyDecision::Allow);
    assert_eq!(
        cleared.resolutions[0].action_resolution.state,
        ResolutionState::Cleared
    );

    let ordinary_deny = policy(
        UnboundObservation::Error,
        vec![binding(
            "ordinary-deny",
            100,
            selector(None, None, None, None, None),
            CompiledPolicyDirective::Deny,
        )],
    );
    assert!(matches!(
        evaluate_processing_policy(
            &ordinary_deny,
            &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
            &cleared_ids,
        ),
        Err(ProcessingPolicyError::UnexpectedClearance(_))
    ));
}

#[test]
fn verification_selector_requires_every_occurrence_to_match() {
    let mut finding = fixture(
        "mixed",
        "gitleaks",
        "generic-password",
        FindingCategory::Credential,
        Severity::High,
        CredentialVerificationState::Verified,
    );
    let second_id = OccurrenceId::from_suffix("mixed-second").unwrap();
    let mut second = finding.occurrences[0].clone();
    second.id = second_id.clone();
    second.verification_state = CredentialVerificationState::Unverified;
    finding.finding.occurrence_ids.push(second_id);
    finding.finding.occurrence_ids.sort();
    finding.occurrences.push(second);
    let compiled = policy(
        UnboundObservation::Audit,
        vec![binding(
            "verified",
            10,
            selector(
                None,
                None,
                None,
                None,
                Some(CredentialVerificationState::Verified),
            ),
            CompiledPolicyDirective::Deny,
        )],
    );
    let result = evaluate_processing_policy(
        &compiled,
        &[finding.input(FindingSurface::MutablePhysicalRegularFile)],
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(result.decision, ProcessingPolicyDecision::Allow);
    assert!(result.resolutions[0].matched_default);
}

#[test]
fn config_rejects_same_priority_overlap_and_adjudicate_without_authority() {
    let raw = include_str!("../docs/examples/processing-v3.toml");
    let mut config = ProcessingConfigFile::parse(raw).unwrap();
    config.processing.profiles[0].bindings = vec![
        ProcessingPolicyBinding {
            id: "broad".into(),
            priority: 10,
            directive: ProcessingPolicyDirective::Audit,
            selector: ProcessingFindingSelector {
                analyzer: None,
                rule: None,
                category: Some(FindingCategory::Credential),
                severity: None,
                verification_state: None,
            },
        },
        ProcessingPolicyBinding {
            id: "exact".into(),
            priority: 10,
            directive: ProcessingPolicyDirective::Deny,
            selector: ProcessingFindingSelector {
                analyzer: Some("gitleaks".into()),
                rule: None,
                category: Some(FindingCategory::Credential),
                severity: None,
                verification_state: None,
            },
        },
    ];
    assert!(config.validate().is_err());

    config.processing.profiles[0].bindings[1].priority = 20;
    config.processing.profiles[0].bindings[1].directive = ProcessingPolicyDirective::Adjudicate;
    assert!(config.validate().is_err());
}
