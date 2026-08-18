#![cfg(target_os = "linux")]

use file_guardian::analyzers::external::{
    AssignmentDisposition, FirstPartyScannerAdapter, GitleaksAdapter, NativeExit,
    ScannerAdapterContext, ScannerAdapterError, ScannerAssignment, ScannerAssignmentSurface,
    ScannerCapability, ScannerCoveredSurface, ScannerKind, ScannerVersion,
    ScannerVersionRequirement, TrufflehogAdapter,
};
use file_guardian::domain::{
    AnalyzerId, ArtifactId, CandidateId, Digest, InspectionPhase, LogicalPath, PathSegment,
    Severity, ValidatedLocation,
};
use file_guardian::processing::{
    GitBlobMode, GitBlobOccurrence, GitHistoryScope, GitObjectId, GitProvenance,
};

fn assignment(suffix: &str, path: &str) -> ScannerAssignment {
    ScannerAssignment {
        candidate_id: CandidateId::from_suffix(suffix).unwrap(),
        artifact_id: ArtifactId::from_suffix(suffix).unwrap(),
        view_path: path.to_owned(),
        byte_len: 64,
        disposition: AssignmentDisposition::Scan,
        surface: ScannerAssignmentSurface::WorkingTree,
    }
}

fn history_assignment(suffix: &str, path: &str) -> ScannerAssignment {
    let object_id = |value: char| -> GitObjectId {
        format!("sha1:{}", value.to_string().repeat(40))
            .parse()
            .unwrap()
    };
    let provenance = GitProvenance::new(
        object_id('a'),
        GitBlobMode::Regular,
        vec![GitBlobOccurrence {
            commit_id: object_id('b'),
            path: LogicalPath::new(vec![PathSegment::utf8("historical.txt").unwrap()]).unwrap(),
            refs: Vec::new(),
        }],
    )
    .unwrap();
    ScannerAssignment {
        candidate_id: CandidateId::from_suffix(suffix).unwrap(),
        artifact_id: ArtifactId::from_suffix(suffix).unwrap(),
        view_path: path.to_owned(),
        byte_len: 64,
        disposition: AssignmentDisposition::Scan,
        surface: ScannerAssignmentSurface::GitHistory {
            repository_id: Digest::sha256(b"repository"),
            scope: GitHistoryScope::Head,
            provenance,
        },
    }
}

fn context<'a>(
    analyzer_id: &'a AnalyzerId,
    assignments: &'a [ScannerAssignment],
    max_findings: u64,
) -> ScannerAdapterContext<'a> {
    ScannerAdapterContext {
        analyzer_id,
        phase: InspectionPhase::Initial,
        assignments,
        max_file_bytes: 1024,
        max_findings,
    }
}

fn exit(code: i32) -> NativeExit {
    NativeExit {
        code: Some(code),
        signal: None,
    }
}

#[test]
fn reviewed_version_ranges_are_strict_and_capabilities_are_closed() {
    let gitleaks = GitleaksAdapter::default();
    assert_eq!(
        gitleaks
            .validate_version_output(b"gitleaks version 8.25.1\n")
            .unwrap(),
        ScannerVersion::new(8, 25, 1)
    );
    assert_eq!(
        serde_json::to_string(&ScannerVersion::new(8, 25, 1)).unwrap(),
        "\"8.25.1\""
    );
    assert_eq!(
        gitleaks
            .validate_version_output(b"v8.28.0+build\n")
            .unwrap(),
        ScannerVersion::new(8, 28, 0)
    );
    assert_eq!(
        gitleaks.validate_version_output(b"8.18.9\n"),
        Err(ScannerAdapterError::UnsupportedVersion)
    );
    assert_eq!(
        gitleaks.validate_version_output(b"9.0.0\n"),
        Err(ScannerAdapterError::UnsupportedVersion)
    );
    assert_eq!(
        gitleaks.validate_version_output(b"not-a-version\n"),
        Err(ScannerAdapterError::VersionOutput)
    );
    assert_eq!(
        gitleaks.validate_version_output(b" gitleaks version 8.25.1\n"),
        Err(ScannerAdapterError::VersionOutput)
    );
    assert_eq!(
        gitleaks.validate_version_output(b"8.25.1\n\n"),
        Err(ScannerAdapterError::VersionOutput)
    );
    assert_eq!(
        gitleaks.validate_version_output(b"8.25.1+bad suffix\n"),
        Err(ScannerAdapterError::VersionOutput)
    );

    let trufflehog = TrufflehogAdapter::default();
    assert_eq!(
        trufflehog
            .validate_version_output(b"trufflehog 3.96.0\n")
            .unwrap(),
        ScannerVersion::new(3, 96, 0)
    );
    assert_eq!(
        trufflehog.validate_version_output(b"trufflehog 4.0.0\n"),
        Err(ScannerAdapterError::UnsupportedVersion)
    );
    assert_eq!(
        gitleaks.capabilities(),
        &[
            ScannerCapability::WorkingTree,
            ScannerCapability::MaterializedGitHistory,
        ]
    );
    assert_eq!(gitleaks.kind(), ScannerKind::Gitleaks);
    assert_eq!(trufflehog.kind(), ScannerKind::Trufflehog);

    let narrowed = ScannerVersionRequirement::new(
        ScannerVersion::new(8, 25, 0),
        ScannerVersion::new(8, 26, 0),
    );
    let narrowed = GitleaksAdapter::with_version_requirement(narrowed).unwrap();
    assert!(narrowed.validate_version_output(b"v8.25.1\n").is_ok());
    assert_eq!(
        narrowed.validate_version_output(b"v8.26.0\n"),
        Err(ScannerAdapterError::UnsupportedVersion)
    );
    assert_eq!(
        GitleaksAdapter::with_version_requirement(ScannerVersionRequirement::new(
            ScannerVersion::new(8, 18, 0),
            ScannerVersion::new(8, 26, 0),
        ))
        .unwrap_err(),
        ScannerAdapterError::VersionRequirement
    );
    assert_eq!(
        TrufflehogAdapter::with_version_requirement(ScannerVersionRequirement::new(
            ScannerVersion::new(3, 95, 0),
            ScannerVersion::new(3, 95, 0),
        ))
        .unwrap_err(),
        ScannerAdapterError::VersionRequirement
    );
}

#[test]
fn gitleaks_requires_exit_and_json_report_agreement() {
    let analyzer = AnalyzerId::new("gitleaks").unwrap();
    let assignments = [assignment("one", "src/main.rs")];
    let adapter = GitleaksAdapter::default();
    let empty = adapter
        .normalize_bytes(context(&analyzer, &assignments, 10), exit(0), b"[]")
        .unwrap();
    assert!(empty.coverage.is_complete());
    assert!(empty.occurrences.is_empty());
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 10), exit(42), b"[]"),
        Err(ScannerAdapterError::ExitOutputMismatch)
    );
    let report = gitleaks_finding("src/main.rs", "github-pat", 4, 7, "REDACTED", "");
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 10), exit(0), &report),
        Err(ScannerAdapterError::ExitOutputMismatch)
    );
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 10), exit(1), &report),
        Err(ScannerAdapterError::AbnormalExit)
    );
}

#[test]
fn gitleaks_maps_only_assigned_paths_and_rejects_native_git_or_secret_data() {
    let analyzer = AnalyzerId::new("gitleaks").unwrap();
    let assignments = [assignment("one", "src/main.rs")];
    let adapter = GitleaksAdapter::default();
    let report = gitleaks_finding("/input/src/main.rs", "github-pat", 4, 7, "REDACTED", "");
    let completion = adapter
        .normalize_bytes(context(&analyzer, &assignments, 10), exit(42), &report)
        .unwrap();
    assert_eq!(completion.occurrences.len(), 1);
    assert_eq!(
        completion.occurrences[0].candidate_id,
        assignments[0].candidate_id
    );
    assert_eq!(
        completion.occurrences[0].artifact_id,
        assignments[0].artifact_id
    );
    assert_eq!(
        completion.occurrences[0].location,
        Some(ValidatedLocation::line_column(4, 7).unwrap())
    );
    assert_eq!(completion.occurrences[0].severity, Severity::High);

    let foreign = gitleaks_finding("other.rs", "github-pat", 1, 1, "REDACTED", "");
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 10), exit(42), &foreign),
        Err(ScannerAdapterError::FindingPath)
    );
    let history = gitleaks_finding(
        "src/main.rs",
        "github-pat",
        1,
        1,
        "REDACTED",
        "0123456789abcdef",
    );
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 10), exit(42), &history),
        Err(ScannerAdapterError::UnexpectedGitMetadata)
    );
    let raw_marker = "raw-value-must-never-escape";
    let unredacted = gitleaks_finding("src/main.rs", "github-pat", 1, 1, raw_marker, "");
    let error = adapter
        .normalize_bytes(context(&analyzer, &assignments, 10), exit(42), &unredacted)
        .unwrap_err();
    assert_eq!(error, ScannerAdapterError::MalformedOutput);
    assert!(!format!("{error:?}").contains(raw_marker));
    assert!(!error.to_string().contains(raw_marker));
}

#[test]
fn gitleaks_results_are_deterministic_deduplicated_and_bounded() {
    let analyzer = AnalyzerId::new("gitleaks").unwrap();
    let assignments = [assignment("one", "a.txt"), assignment("two", "z.txt")];
    let adapter = GitleaksAdapter::default();
    let first: serde_json::Value = serde_json::from_slice(&gitleaks_finding(
        "z.txt",
        "generic-api-key",
        9,
        0,
        "REDACTED",
        "",
    ))
    .unwrap();
    let second: serde_json::Value = serde_json::from_slice(&gitleaks_finding(
        "a.txt",
        "generic-api-key",
        2,
        0,
        "REDACTED",
        "",
    ))
    .unwrap();
    let findings = serde_json::json!([first[0], second[0], second[0]]);
    let bytes = serde_json::to_vec(&findings).unwrap();
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 2), exit(42), &bytes),
        Err(ScannerAdapterError::FindingLimit)
    );
    let completion = adapter
        .normalize_bytes(context(&analyzer, &assignments, 3), exit(42), &bytes)
        .unwrap();
    assert_eq!(completion.occurrences.len(), 2);
    assert_eq!(
        completion.occurrences[0].artifact_id,
        assignments[0].artifact_id
    );
    assert_eq!(
        completion.occurrences[1].artifact_id,
        assignments[1].artifact_id
    );
}

#[test]
fn normalized_rule_ids_do_not_collapse_distinct_native_identifiers() {
    let analyzer = AnalyzerId::new("gitleaks").unwrap();
    let assignments = [assignment("one", "name\\with-backslash.txt")];
    let adapter = GitleaksAdapter::default();
    let first: serde_json::Value = serde_json::from_slice(&gitleaks_finding(
        "name\\with-backslash.txt",
        "Example Rule",
        1,
        0,
        "REDACTED",
        "",
    ))
    .unwrap();
    let second: serde_json::Value = serde_json::from_slice(&gitleaks_finding(
        "name\\with-backslash.txt",
        "example-rule",
        1,
        0,
        "REDACTED",
        "",
    ))
    .unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!([first[0], second[0]])).unwrap();
    let completion = adapter
        .normalize_bytes(context(&analyzer, &assignments, 2), exit(42), &bytes)
        .unwrap();
    assert_eq!(completion.occurrences.len(), 2);
    assert_ne!(
        completion.occurrences[0].rule_id,
        completion.occurrences[1].rule_id
    );
    assert_ne!(
        completion.occurrences[0].occurrence_id,
        completion.occurrences[1].occurrence_id
    );
}

#[test]
fn materialized_history_maps_to_candidate_without_accepting_native_git_mode() {
    let analyzer = AnalyzerId::new("gitleaks-history").unwrap();
    let assignments = [history_assignment("history", "blobs/historical.txt")];
    let report = gitleaks_finding(
        "/input/blobs/historical.txt",
        "generic-api-key",
        3,
        0,
        "REDACTED",
        "",
    );
    let completion = GitleaksAdapter::default()
        .normalize_bytes(context(&analyzer, &assignments, 4), exit(42), &report)
        .unwrap();
    assert_eq!(
        completion.surfaces,
        vec![ScannerCoveredSurface::GitHistory {
            repository_id: Digest::sha256(b"repository"),
            scope: GitHistoryScope::Head,
        }]
    );
    assert_eq!(
        completion.occurrences[0].candidate_id,
        assignments[0].candidate_id
    );

    let trufflehog = trufflehog_finding(
        "/input/blobs/historical.txt",
        "AWS",
        3,
        "private-native-value",
    );
    let completion = TrufflehogAdapter::default()
        .normalize_bytes(context(&analyzer, &assignments, 4), exit(183), &trufflehog)
        .unwrap();
    assert_eq!(
        completion.surfaces,
        vec![ScannerCoveredSurface::GitHistory {
            repository_id: Digest::sha256(b"repository"),
            scope: GitHistoryScope::Head,
        }]
    );
    assert_eq!(
        completion.occurrences[0].candidate_id,
        assignments[0].candidate_id
    );
}

#[test]
fn trufflehog_requires_exit_ndjson_and_path_agreement_without_leaking_raw_fields() {
    let analyzer = AnalyzerId::new("trufflehog").unwrap();
    let assignments = [assignment("one", "config/settings.ini")];
    let adapter = TrufflehogAdapter::default();
    let marker = "native-secret-must-not-escape";
    let record = trufflehog_finding("/input/config/settings.ini", "AWS", 8, marker);
    let completion = adapter
        .normalize_bytes(context(&analyzer, &assignments, 4), exit(183), &record)
        .unwrap();
    assert_eq!(completion.occurrences.len(), 1);
    assert_eq!(
        completion.occurrences[0].candidate_id,
        assignments[0].candidate_id
    );
    assert_eq!(
        completion.occurrences[0].location,
        Some(ValidatedLocation::line(8).unwrap())
    );
    let normalized = serde_json::to_string(&completion).unwrap();
    assert!(!normalized.contains(marker));
    assert!(!format!("{completion:?}").contains(marker));

    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 4), exit(0), &record),
        Err(ScannerAdapterError::ExitOutputMismatch)
    );
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 4), exit(183), b""),
        Err(ScannerAdapterError::ExitOutputMismatch)
    );
    assert_eq!(
        adapter.normalize_bytes(
            context(&analyzer, &assignments, 4),
            exit(183),
            b"{not-json}\n"
        ),
        Err(ScannerAdapterError::MalformedOutput)
    );
    let foreign = trufflehog_finding("/input/foreign", "AWS", 1, marker);
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 4), exit(183), &foreign),
        Err(ScannerAdapterError::FindingPath)
    );
}

#[test]
fn trufflehog_rejects_git_metadata_and_verification_errors_in_filesystem_mode() {
    let analyzer = AnalyzerId::new("trufflehog").unwrap();
    let assignments = [assignment("one", "one.txt")];
    let adapter = TrufflehogAdapter::default();
    let git = serde_json::json!({
        "SourceMetadata": {"Data": {"Git": {"commit": "abc", "file": "one.txt", "line": 1}}},
        "DetectorName": "AWS",
        "Verified": false,
        "Raw": "private"
    });
    let git = serde_json::to_vec(&git).unwrap();
    assert_eq!(
        adapter.normalize_bytes(context(&analyzer, &assignments, 4), exit(183), &git),
        Err(ScannerAdapterError::UnexpectedGitMetadata)
    );
    let unknown = serde_json::json!({
        "SourceMetadata": {"Data": {"Filesystem": {"file": "one.txt", "line": 1}}},
        "DetectorName": "AWS",
        "Verified": false,
        "VerificationError": "transport included private host details",
        "Raw": "private"
    });
    let unknown = serde_json::to_vec(&unknown).unwrap();
    let error = adapter
        .normalize_bytes(context(&analyzer, &assignments, 4), exit(183), &unknown)
        .unwrap_err();
    assert_eq!(error, ScannerAdapterError::MalformedOutput);
    assert!(!format!("{error:?}").contains("private"));
}

fn gitleaks_finding(
    path: &str,
    rule: &str,
    line: u64,
    column: u64,
    secret: &str,
    commit: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([{
        "RuleID": rule,
        "Description": "ignored native prose",
        "StartLine": line,
        "EndLine": line,
        "StartColumn": column,
        "EndColumn": column,
        "Match": "ignored native match",
        "Secret": secret,
        "File": path,
        "SymlinkFile": "",
        "Commit": commit,
        "Tags": ["credential"],
        "Fingerprint": "ignored"
    }]))
    .unwrap()
}

fn trufflehog_finding(path: &str, detector: &str, line: i64, raw: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": line}}},
        "SourceType": 15,
        "DetectorName": detector,
        "DetectorDescription": "ignored native prose",
        "Verified": false,
        "Raw": raw,
        "RawV2": raw,
        "Redacted": "redacted",
        "ExtraData": {"private": raw},
        "SecretParts": {"private": raw}
    }))
    .unwrap();
    bytes.push(b'\n');
    bytes
}
