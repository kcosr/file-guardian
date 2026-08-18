use file_guardian::domain::{
    AnalyzerId, ArtifactId, Classification, ClassificationCode, ClassificationScope,
    ConfiguredConfidence, Digest, Finding as AnalyzerFinding, FindingCategory, InspectionPhase,
    LogicalPath, NormalizedObservation, ObservationId, PathSegment, ReasonCode, RuleId, RunId,
    SafeEvidence, Severity, ValidatedLocation,
};
use file_guardian::processing::findings::{
    normalize_findings, ArtifactFindingContext, ArtifactFindingProvenance,
    FindingNormalizationContext, FindingNormalizationError, JobCorrelationKey, ObservationEvidence,
};
use file_guardian::processing::{
    CredentialVerificationState, GitBlobMode, GitBlobOccurrence, GitObjectId, GitProvenance,
};

fn path(value: &str) -> LogicalPath {
    LogicalPath::new(
        value
            .split('/')
            .map(|part| PathSegment::utf8(part).unwrap())
            .collect(),
    )
    .unwrap()
}

fn artifact(suffix: &str, logical_path: &str, bytes: &[u8]) -> ArtifactFindingContext {
    ArtifactFindingContext {
        artifact_id: ArtifactId::from_suffix(suffix).unwrap(),
        content_digest: Digest::sha256(bytes),
        provenance: ArtifactFindingProvenance::LogicalPath(path(logical_path)),
    }
}

fn finding(
    observation_suffix: &str,
    analyzer: &str,
    artifact: &ArtifactId,
    rule: &str,
    location: ValidatedLocation,
) -> NormalizedObservation {
    NormalizedObservation::Finding(AnalyzerFinding {
        id: ObservationId::from_suffix(observation_suffix).unwrap(),
        analyzer_id: AnalyzerId::new(analyzer).unwrap(),
        rule_id: RuleId::new(rule).unwrap(),
        artifact_id: artifact.clone(),
        category: FindingCategory::Credential,
        severity: Severity::High,
        location: Some(location),
        evidence: SafeEvidence {
            reason_codes: vec![ReasonCode::new("password-pattern").unwrap()],
        },
    })
}

fn normalize<'a>(
    artifacts: &'a [ArtifactFindingContext],
    observations: &'a [NormalizedObservation],
    evidence: &'a [ObservationEvidence<'a>],
    key: &'a JobCorrelationKey,
    snapshot_identity: Digest,
) -> Result<file_guardian::processing::findings::NormalizedPhaseFindings, FindingNormalizationError>
{
    let run_id = RunId::from_suffix("normalizer-test").unwrap();
    let analyzer_id = AnalyzerId::new("gitleaks").unwrap();
    let analyzer_ids = [analyzer_id];
    normalize_findings(
        FindingNormalizationContext {
            run_id: &run_id,
            phase: InspectionPhase::Initial,
            analyzer_ids: &analyzer_ids,
            snapshot_identity,
            artifacts,
            evidence,
            correlation_key: key,
        },
        observations,
    )
}

#[test]
fn normalizes_in_canonical_order_independent_of_input_order() {
    let first_artifact = artifact("a", "src/a.txt", b"alpha");
    let second_artifact = artifact("b", "src/b.txt", b"bravo");
    let first = finding(
        "first",
        "gitleaks",
        &first_artifact.artifact_id,
        "generic-password",
        ValidatedLocation::line_column(3, 4).unwrap(),
    );
    let second = finding(
        "second",
        "gitleaks",
        &second_artifact.artifact_id,
        "private-key",
        ValidatedLocation::line(8).unwrap(),
    );
    let key = JobCorrelationKey::from_bytes([7; 32]);
    let snapshot = Digest::sha256(b"snapshot");
    let forward = normalize(
        &[first_artifact.clone(), second_artifact.clone()],
        &[first.clone(), second.clone()],
        &[],
        &key,
        snapshot,
    )
    .unwrap();
    let reversed = normalize(
        &[second_artifact, first_artifact],
        &[second, first],
        &[],
        &key,
        snapshot,
    )
    .unwrap();

    assert_eq!(forward, reversed);
    assert!(forward
        .occurrences
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id));
    assert!(forward
        .findings
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id));
    assert!(forward
        .correlations
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id));
}

#[test]
fn exact_duplicates_merge_without_losing_occurrence_provenance() {
    let artifact = artifact("same", "fixture.env", b"PASSWORD=example");
    let first = finding(
        "native-a",
        "gitleaks",
        &artifact.artifact_id,
        "generic-password",
        ValidatedLocation::byte_range(9, 16).unwrap(),
    );
    let second = finding(
        "native-b",
        "gitleaks",
        &artifact.artifact_id,
        "generic-password",
        ValidatedLocation::byte_range(9, 16).unwrap(),
    );
    let first_id = ObservationId::from_suffix("native-a").unwrap();
    let second_id = ObservationId::from_suffix("native-b").unwrap();
    let key = JobCorrelationKey::from_bytes([11; 32]);
    let evidence = [
        ObservationEvidence {
            observation_id: &first_id,
            canonical_window: b"example",
            verification_state: CredentialVerificationState::Unverified,
        },
        ObservationEvidence {
            observation_id: &second_id,
            canonical_window: b"example",
            verification_state: CredentialVerificationState::Unverified,
        },
    ];
    let result = normalize(
        &[artifact],
        &[first, second],
        &evidence,
        &key,
        Digest::sha256(b"snapshot"),
    )
    .unwrap();

    assert_eq!(result.occurrences.len(), 2);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.correlations.len(), 1);
    assert_eq!(result.findings[0].occurrence_ids.len(), 2);
    assert_eq!(result.correlations[0].occurrence_ids.len(), 2);
    assert_eq!(result.observation_to_finding.len(), 2);
    assert_eq!(
        result.observation_to_finding[&first_id],
        result.observation_to_finding[&second_id]
    );
}

#[test]
fn evidence_is_opaque_phase_stable_and_bound_to_key_content_and_path() {
    let secret = b"not-a-real-password";
    let base = artifact(
        "base",
        "config/example.env",
        b"PASSWORD=not-a-real-password",
    );
    let observation = finding(
        "secret",
        "gitleaks",
        &base.artifact_id,
        "generic-password",
        ValidatedLocation::byte_range(9, 28).unwrap(),
    );
    let observation_id = ObservationId::from_suffix("secret").unwrap();
    let evidence = [ObservationEvidence {
        observation_id: &observation_id,
        canonical_window: secret,
        verification_state: CredentialVerificationState::Verified,
    }];
    let first_key = JobCorrelationKey::from_bytes([21; 32]);
    let second_key = JobCorrelationKey::from_bytes([22; 32]);
    let snapshot = Digest::sha256(b"snapshot-a");
    let baseline = normalize(
        std::slice::from_ref(&base),
        std::slice::from_ref(&observation),
        &evidence,
        &first_key,
        snapshot,
    )
    .unwrap();
    let changed_key = normalize(
        std::slice::from_ref(&base),
        std::slice::from_ref(&observation),
        &evidence,
        &second_key,
        snapshot,
    )
    .unwrap();
    let mut changed_content = base.clone();
    changed_content.content_digest = Digest::sha256(b"different content");
    let changed_content = normalize(
        &[changed_content],
        std::slice::from_ref(&observation),
        &evidence,
        &first_key,
        snapshot,
    )
    .unwrap();
    let mut changed_path = base.clone();
    changed_path.provenance = ArtifactFindingProvenance::LogicalPath(path("other/example.env"));
    let changed_path = normalize(
        &[changed_path],
        std::slice::from_ref(&observation),
        &evidence,
        &first_key,
        snapshot,
    )
    .unwrap();
    let changed_snapshot = normalize(
        &[base],
        &[observation],
        &evidence,
        &first_key,
        Digest::sha256(b"snapshot-b"),
    )
    .unwrap();

    let baseline_token = baseline.occurrences[0].evidence_token.unwrap();
    for result in [changed_key, changed_content, changed_path] {
        assert_ne!(result.occurrences[0].evidence_token, Some(baseline_token));
    }
    assert_eq!(
        changed_snapshot.occurrences[0].evidence_token,
        Some(baseline_token)
    );
    assert_ne!(baseline.findings[0].id, changed_snapshot.findings[0].id);
    let wire = serde_json::to_string(&(
        &baseline.occurrences,
        &baseline.findings,
        &baseline.correlations,
    ))
    .unwrap();
    assert!(!wire.contains("not-a-real-password"));
    assert!(!wire.contains(&"15".repeat(32)));
    assert_eq!(format!("{first_key:?}"), "JobCorrelationKey([REDACTED])");
    let evidence_debug = format!("{:?}", evidence[0]);
    assert!(!evidence_debug.contains("not-a-real-password"));
    assert!(evidence_debug.contains("[REDACTED]"));
}

#[test]
fn git_provenance_is_part_of_the_evidence_identity() {
    let artifact_id = ArtifactId::from_suffix("git").unwrap();
    let observation = finding(
        "git-secret",
        "gitleaks",
        &artifact_id,
        "generic-password",
        ValidatedLocation::line(1).unwrap(),
    );
    let observation_id = ObservationId::from_suffix("git-secret").unwrap();
    let evidence = [ObservationEvidence {
        observation_id: &observation_id,
        canonical_window: b"example",
        verification_state: CredentialVerificationState::Unverified,
    }];
    let oid = format!("sha1:{}", "a".repeat(40))
        .parse::<GitObjectId>()
        .unwrap();
    let commit = format!("sha1:{}", "b".repeat(40))
        .parse::<GitObjectId>()
        .unwrap();
    let provenance = |reference: &str| {
        GitProvenance::new(
            oid.clone(),
            GitBlobMode::Regular,
            vec![GitBlobOccurrence {
                commit_id: commit.clone(),
                path: path("config.env"),
                refs: vec![path(reference)],
            }],
        )
        .unwrap()
    };
    let context = |reference: &str| ArtifactFindingContext {
        artifact_id: artifact_id.clone(),
        content_digest: Digest::sha256(b"example"),
        provenance: ArtifactFindingProvenance::Git {
            repository_identity: Digest::sha256(b"repository"),
            provenance: provenance(reference),
        },
    };
    let key = JobCorrelationKey::from_bytes([31; 32]);
    let first = normalize(
        &[context("refs/heads/main")],
        std::slice::from_ref(&observation),
        &evidence,
        &key,
        Digest::sha256(b"snapshot"),
    )
    .unwrap();
    let second = normalize(
        &[context("refs/heads/release")],
        &[observation],
        &evidence,
        &key,
        Digest::sha256(b"snapshot"),
    )
    .unwrap();
    assert_ne!(
        first.occurrences[0].evidence_token,
        second.occurrences[0].evidence_token
    );
}

#[test]
fn correlates_overlapping_safe_locations_but_retains_each_finding() {
    let artifact = artifact("overlap", "config.env", b"password=example");
    let first = finding(
        "overlap-a",
        "gitleaks",
        &artifact.artifact_id,
        "rule-a",
        ValidatedLocation::byte_range(2, 10).unwrap(),
    );
    let second = finding(
        "overlap-b",
        "gitleaks",
        &artifact.artifact_id,
        "rule-b",
        ValidatedLocation::byte_range(8, 14).unwrap(),
    );
    let result = normalize(
        &[artifact],
        &[first, second],
        &[],
        &JobCorrelationKey::from_bytes([41; 32]),
        Digest::sha256(b"snapshot"),
    )
    .unwrap();
    assert_eq!(result.findings.len(), 2);
    assert_eq!(result.correlations.len(), 1);
    assert_eq!(result.correlations[0].finding_ids.len(), 2);
    assert_eq!(result.correlations[0].occurrence_ids.len(), 2);
}

#[test]
fn phase_wide_context_correlates_findings_from_distinct_analyzers() {
    let artifact = artifact("cross-tool", "config.env", b"password=example");
    let gitleaks = finding(
        "gitleaks-native",
        "gitleaks",
        &artifact.artifact_id,
        "generic-password",
        ValidatedLocation::line_column(1, 10).unwrap(),
    );
    let trufflehog = finding(
        "trufflehog-native",
        "trufflehog",
        &artifact.artifact_id,
        "generic-unverified",
        ValidatedLocation::line(1).unwrap(),
    );
    let run_id = RunId::from_suffix("cross-tool").unwrap();
    let analyzer_ids = [
        AnalyzerId::new("trufflehog").unwrap(),
        AnalyzerId::new("gitleaks").unwrap(),
    ];
    let result = normalize_findings(
        FindingNormalizationContext {
            run_id: &run_id,
            phase: InspectionPhase::Initial,
            analyzer_ids: &analyzer_ids,
            snapshot_identity: Digest::sha256(b"snapshot"),
            artifacts: &[artifact],
            evidence: &[],
            correlation_key: &JobCorrelationKey::from_bytes([47; 32]),
        },
        &[gitleaks, trufflehog],
    )
    .unwrap();

    assert_eq!(result.findings.len(), 2);
    assert_eq!(result.correlations.len(), 1);
    assert_eq!(result.correlations[0].finding_ids.len(), 2);
    assert_eq!(result.correlations[0].occurrence_ids.len(), 2);
}

#[test]
fn rejects_duplicates_unknowns_mismatches_and_classifications() {
    let artifact = artifact("reject", "config.env", b"example");
    let observation = finding(
        "duplicate",
        "gitleaks",
        &artifact.artifact_id,
        "generic-password",
        ValidatedLocation::line(1).unwrap(),
    );
    let key = JobCorrelationKey::from_bytes([51; 32]);
    let snapshot = Digest::sha256(b"snapshot");
    assert_eq!(
        normalize(
            std::slice::from_ref(&artifact),
            &[observation.clone(), observation.clone()],
            &[],
            &key,
            snapshot,
        ),
        Err(FindingNormalizationError::DuplicateObservation)
    );
    assert_eq!(
        normalize(
            &[artifact.clone(), artifact.clone()],
            std::slice::from_ref(&observation),
            &[],
            &key,
            snapshot,
        ),
        Err(FindingNormalizationError::DuplicateArtifact)
    );
    let observation_id = ObservationId::from_suffix("duplicate").unwrap();
    let duplicated_evidence = [
        ObservationEvidence {
            observation_id: &observation_id,
            canonical_window: b"example",
            verification_state: CredentialVerificationState::Unverified,
        },
        ObservationEvidence {
            observation_id: &observation_id,
            canonical_window: b"example",
            verification_state: CredentialVerificationState::Unverified,
        },
    ];
    assert_eq!(
        normalize(
            std::slice::from_ref(&artifact),
            std::slice::from_ref(&observation),
            &duplicated_evidence,
            &key,
            snapshot,
        ),
        Err(FindingNormalizationError::DuplicateEvidence)
    );
    let empty_evidence = [ObservationEvidence {
        observation_id: &observation_id,
        canonical_window: b"",
        verification_state: CredentialVerificationState::Unverified,
    }];
    assert_eq!(
        normalize(
            std::slice::from_ref(&artifact),
            std::slice::from_ref(&observation),
            &empty_evidence,
            &key,
            snapshot,
        ),
        Err(FindingNormalizationError::InvalidEvidence)
    );
    let unknown_id = ObservationId::from_suffix("unknown").unwrap();
    let unknown_evidence = [ObservationEvidence {
        observation_id: &unknown_id,
        canonical_window: b"example",
        verification_state: CredentialVerificationState::Unverified,
    }];
    assert_eq!(
        normalize(
            std::slice::from_ref(&artifact),
            std::slice::from_ref(&observation),
            &unknown_evidence,
            &key,
            snapshot,
        ),
        Err(FindingNormalizationError::UnknownEvidence)
    );

    let mismatched = finding(
        "wrong-analyzer",
        "trufflehog",
        &artifact.artifact_id,
        "generic-password",
        ValidatedLocation::line(1).unwrap(),
    );
    assert_eq!(
        normalize(
            std::slice::from_ref(&artifact),
            &[mismatched],
            &[],
            &key,
            snapshot,
        ),
        Err(FindingNormalizationError::AnalyzerMismatch)
    );
    assert_eq!(
        normalize(&[], &[observation], &[], &key, snapshot),
        Err(FindingNormalizationError::UnknownArtifact)
    );

    let classification = NormalizedObservation::Classification(Classification {
        id: ObservationId::from_suffix("classification").unwrap(),
        analyzer_id: AnalyzerId::new("gitleaks").unwrap(),
        code: ClassificationCode::new("public").unwrap(),
        scope: ClassificationScope::Tree,
        subject_artifacts: Vec::new(),
        confidence: Some(ConfiguredConfidence::High),
        reason_codes: Vec::new(),
    });
    assert_eq!(
        normalize(&[artifact], &[classification], &[], &key, snapshot),
        Err(FindingNormalizationError::ClassificationUnsupported)
    );

    let analyzer_id = AnalyzerId::new("gitleaks").unwrap();
    let run_id = RunId::from_suffix("bad-analyzer-context").unwrap();
    assert_eq!(
        normalize_findings(
            FindingNormalizationContext {
                run_id: &run_id,
                phase: InspectionPhase::Initial,
                analyzer_ids: &[analyzer_id.clone(), analyzer_id],
                snapshot_identity: snapshot,
                artifacts: &[],
                evidence: &[],
                correlation_key: &key,
            },
            &[],
        ),
        Err(FindingNormalizationError::InvalidAnalyzerContext)
    );
}
