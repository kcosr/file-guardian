use file_guardian::analyzers::pi::protocol::{
    ClassificationVocabulary, NativeToolOutcome, ProxyOperation, TerminalSubmission,
    TerminalValidationContext, TerminalValidationLimits,
};
use file_guardian::domain::{
    AnalyzerId, ArtifactId, Classification, ClassificationCode, ClassificationScope,
    ConfiguredConfidence, Digest, Finding, FindingCategory, InspectionPhase, NormalizedObservation,
    ObservationId, ReasonCode, RuleId, SafeEvidence, Severity,
};
use file_guardian::policy::{
    evaluate, BindingId, EffectiveResult, EvaluationDecision, ObservationSelector, PolicyBinding,
    PolicyDirective,
};

fn fixture() -> TerminalSubmission {
    serde_json::from_str(include_str!(
        "../docs/examples/pi-classifier/restricted.json"
    ))
    .expect("strict terminal fixture")
}

#[test]
fn terminal_fixture_validates_to_only_normalized_safe_classifications() {
    let assigned = (1..=12)
        .map(|index| ArtifactId::from_suffix(format!("{index:02}")).unwrap())
        .collect::<Vec<_>>();
    let vocabulary = ClassificationVocabulary::new(
        [ClassificationCode::new("restricted").unwrap()],
        [ConfiguredConfidence::High],
        [
            ReasonCode::new("internal_project_material").unwrap(),
            ReasonCode::new("restricted_source_material").unwrap(),
        ],
    )
    .unwrap();
    let context = TerminalValidationContext {
        manifest_identity:
            "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                .parse::<Digest>()
                .unwrap(),
        assigned_artifact_ids: &assigned,
        scope: ClassificationScope::Tree,
        vocabulary: &vocabulary,
        limits: TerminalValidationLimits::new(12, 12, 8).unwrap(),
    };

    let validated = fixture()
        .validate(
            &context,
            &AnalyzerId::new("publication-llm").unwrap(),
            InspectionPhase::Initial,
        )
        .expect("canonical fixture matches its host assignment");
    assert_eq!(validated.observations().len(), 2);
    for observation in validated.observations() {
        let NormalizedObservation::Classification(classification) = observation else {
            panic!("Pi terminal output must normalize only as classifications");
        };
        let serialized = serde_json::to_string(classification).unwrap();
        for forbidden in [
            "artifact body",
            "prompt",
            "transcript",
            "stdout",
            "stderr",
            "run_token",
            "proxy.sock",
            "API_KEY",
            "/var/lib/file-guardian",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}

#[test]
fn terminal_fixture_is_strict_and_manifest_bound() {
    let source = include_str!("../docs/examples/pi-classifier/restricted.json");
    let mut extra: serde_json::Value = serde_json::from_str(source).unwrap();
    extra["model_prose"] = serde_json::json!("sensitive explanation");
    assert!(serde_json::from_value::<TerminalSubmission>(extra).is_err());

    let mut wrong_status: serde_json::Value = serde_json::from_str(source).unwrap();
    wrong_status["status"] = serde_json::json!("uncertain");
    assert!(serde_json::from_value::<TerminalSubmission>(wrong_status).is_err());
}

#[test]
fn runtime_manifest_example_is_valid_json_with_canonical_placeholder_hashes() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../docs/examples/pi-classifier/runtime-manifest.example.json"
    ))
    .expect("runtime manifest example is JSON");
    assert_eq!(manifest["schema_version"], "file-guardian-pi-runtime/1");
    assert_eq!(manifest["pi_version"], "0.83.0");
    let files = manifest["files"].as_array().expect("manifest file list");
    assert!(!files.is_empty());
    let paths = files
        .iter()
        .map(|file| file["path"].as_str().expect("string path"))
        .collect::<std::collections::BTreeSet<_>>();
    for required in ["bin/node", "bin/rg", "bin/fd", "lib/pi/dist/cli.js"] {
        assert!(
            paths.contains(required),
            "missing pinned runtime asset {required}"
        );
    }
    for file in files {
        let hash = file["sha256"].as_str().expect("string digest");
        assert_eq!(hash.len(), 64);
        assert!(hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert!(file["path"]
            .as_str()
            .is_some_and(|path| !path.starts_with('/')));
        assert!(file["executable"].is_boolean());
    }
}

#[test]
fn proxy_v2_fixture_requires_paged_manifests_and_closed_native_outcomes() {
    let page_request = serde_json::to_value(ProxyOperation::ManifestList { cursor: 65_536 })
        .expect("manifest operation serializes");
    assert_eq!(
        page_request,
        serde_json::json!({"type":"manifest_list","cursor":65536})
    );
    assert!(serde_json::from_value::<ProxyOperation>(serde_json::json!({
        "type": "manifest_list"
    }))
    .is_err());

    for (outcome, wire) in [
        (NativeToolOutcome::Completed, "completed"),
        (NativeToolOutcome::RecoverableError, "recoverable_error"),
        (NativeToolOutcome::FatalError, "fatal_error"),
    ] {
        assert_eq!(
            serde_json::to_value(outcome).unwrap(),
            serde_json::json!(wire)
        );
    }
    assert!(serde_json::from_value::<NativeToolOutcome>(serde_json::json!("retry")).is_err());
}

#[test]
fn public_pi_audit_cannot_suppress_a_deterministic_deny() {
    let observations = vec![
        NormalizedObservation::Classification(Classification {
            id: ObservationId::from_suffix("pi-public").unwrap(),
            analyzer_id: AnalyzerId::new("publication-llm").unwrap(),
            code: ClassificationCode::new("public").unwrap(),
            scope: ClassificationScope::Tree,
            subject_artifacts: vec![ArtifactId::from_suffix("01").unwrap()],
            confidence: Some(ConfiguredConfidence::High),
            reason_codes: vec![ReasonCode::new("policy_review").unwrap()],
        }),
        NormalizedObservation::Finding(Finding {
            id: ObservationId::from_suffix("deterministic-secret").unwrap(),
            analyzer_id: AnalyzerId::new("secret-scanner").unwrap(),
            rule_id: RuleId::new("secret.detected").unwrap(),
            artifact_id: ArtifactId::from_suffix("01").unwrap(),
            category: FindingCategory::Secret,
            severity: Severity::High,
            location: None,
            evidence: SafeEvidence::default(),
        }),
    ];
    let bindings = vec![
        PolicyBinding {
            id: BindingId::new("pi-public-audit").unwrap(),
            selector: ObservationSelector::Classification {
                analyzer_id: Some(AnalyzerId::new("publication-llm").unwrap()),
                code: Some(ClassificationCode::new("public").unwrap()),
            },
            directive: PolicyDirective::Audit,
        },
        PolicyBinding {
            id: BindingId::new("secret-deny").unwrap(),
            selector: ObservationSelector::Finding {
                analyzer_id: Some(AnalyzerId::new("secret-scanner").unwrap()),
                rule_id: Some(RuleId::new("secret.detected").unwrap()),
                category: None,
                minimum_severity: None,
            },
            directive: PolicyDirective::Deny,
        },
    ];

    let evaluation = evaluate(&observations, &bindings).expect("unambiguous bindings");
    assert_eq!(evaluation.decision, EvaluationDecision::Deny);
    assert_eq!(evaluation.resolutions.len(), 2);
    assert!(evaluation
        .resolutions
        .iter()
        .any(|resolution| resolution.effective_result == EffectiveResult::Audit));
    assert!(evaluation
        .resolutions
        .iter()
        .any(|resolution| resolution.effective_result == EffectiveResult::Deny));
}
