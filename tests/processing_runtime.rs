use std::path::PathBuf;

use file_guardian::domain::RunId;
use file_guardian::processing::config::{
    AcquisitionConfig, ActionMode, AnalyzerArtifactKind, AnalyzerConfig, AnalyzerExecution,
    AnalyzerKind, AnalyzerLimits, AnalyzerSelection, BuiltinRulesConfig, CaptureLimits,
    CompletionDisposition, CompletionPolicy, ContentApplicability, DaemonConfig,
    ExternalScannerRuntimeConfig, GitPolicy, HistoryScope, JobsConfig, LfsPolicy, LocalPolicy,
    PhaseExecution, PipelineConfig, PipelineStage, PriorLimits, PriorObservations,
    ProcessingConfig, ProcessingConfigFile, ProcessingProfile, ProfilePurpose, RetentionConfig,
    SourceScope, StageExecution, SubmodulePolicy, SymlinkPolicy, UnboundObservation,
};
use file_guardian::processing::domain::{GitHistoryScope, GitTransport};
use file_guardian::processing::runtime::{
    compile_processing_runtime, EffectiveActionMode, FrozenAnalyzerImplementation,
    FrozenSourceRequest, ProcessingCompileRequest, ProcessingRuntimeError, ProcessingSourceRequest,
    RequestedActionMode,
};

fn fixture(history: HistoryScope, action_mode: ActionMode) -> ProcessingConfigFile {
    let repository_blob = history != HistoryScope::None;
    let rule_file =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/rules.d/publication.toml");
    let profile = ProcessingProfile {
        id: "review".into(),
        pipeline: "scan".into(),
        action_mode,
        purpose: if action_mode == ActionMode::Apply {
            ProfilePurpose::Handoff
        } else {
            ProfilePurpose::ReportOnly
        },
        default_unbound_observation: UnboundObservation::Deny,
        bindings: Vec::new(),
        source_scope: SourceScope {
            working_tree: true,
            history,
            history_ref_patterns: if history == HistoryScope::Reachable {
                vec!["refs/heads/*".into()]
            } else {
                Vec::new()
            },
        },
        git: GitPolicy {
            allowed_checkout_ref_patterns: vec![
                "refs/heads/*".into(),
                "refs/tags/release-*".into(),
            ],
            submodules: SubmodulePolicy::Reject,
            lfs: LfsPolicy::RejectPointer,
            symlinks: SymlinkPolicy::Preserve,
        },
        local: LocalPolicy {
            symlinks: SymlinkPolicy::Reject,
        },
        completion: CompletionPolicy {
            allow: if action_mode == ActionMode::Apply {
                CompletionDisposition::Retain
            } else {
                CompletionDisposition::Discard
            },
            allow_modified: if action_mode == ActionMode::Apply {
                CompletionDisposition::Retain
            } else {
                CompletionDisposition::Discard
            },
            deny: CompletionDisposition::Discard,
            error: CompletionDisposition::Quarantine,
            cancelled: CompletionDisposition::Quarantine,
        },
        pi_adjudication: None,
    };
    let mut artifact_kinds = vec![AnalyzerArtifactKind::PhysicalFile];
    if repository_blob {
        artifact_kinds.push(AnalyzerArtifactKind::RepositoryBlob);
    }
    ProcessingConfigFile {
        schema_version: "3".into(),
        processing: ProcessingConfig {
            default_profile: "review".into(),
            jobs: JobsConfig {
                root: "/var/lib/file-guardian-test/jobs".into(),
                reports_root: "/var/lib/file-guardian-test/reports".into(),
                quarantine_root: "/var/lib/file-guardian-test/quarantine".into(),
                artifact_quarantine_root: "/var/lib/file-guardian-test/artifacts".into(),
                stale_after_secs: 60,
                max_report_bytes: 1_000_000,
                capture: CaptureLimits {
                    max_entries: 100,
                    max_files: 50,
                    max_file_bytes: 10_000,
                    max_total_bytes: 100_000,
                    max_depth: 8,
                },
                retention: RetentionConfig {
                    available_ttl_secs: 60,
                    available_max_bytes: 100_000,
                    quarantine_ttl_secs: 120,
                    quarantine_max_bytes: 200_000,
                    artifact_quarantine_ttl_secs: 180,
                    artifact_quarantine_max_bytes: 300_000,
                },
            },
            acquisition: AcquisitionConfig {
                git_executable: "/usr/bin/git".into(),
                git_timeout_secs: 30,
                max_stdout_bytes: 10_000,
                max_stderr_bytes: 10_000,
                max_refs: 100,
                max_commits: 1_000,
                max_unique_blobs: 2_000,
                max_provenance_occurrences: 4_000,
                max_git_bytes: 1_000_000,
            },
            external_scanners: ExternalScannerRuntimeConfig {
                bubblewrap_executable: "/usr/bin/bwrap".into(),
                expected_bubblewrap_version: "0.11.1".into(),
            },
            profiles: vec![profile],
        },
        pipelines: vec![PipelineConfig {
            id: "scan".into(),
            stages: vec![PipelineStage {
                id: "deterministic".into(),
                analyzers: vec!["rules".into()],
                execution: StageExecution::Serial,
                max_concurrency: 1,
                prior_observations: PriorObservations::None,
                prior_limits: PriorLimits {
                    max_observations: 100,
                    max_serialized_bytes: 10_000,
                },
            }],
        }],
        analyzers: vec![AnalyzerConfig {
            id: "rules".into(),
            kind: AnalyzerKind::BuiltinRules(BuiltinRulesConfig {
                rule_files: vec![rule_file],
                max_content_bytes: 100_000,
            }),
            execution: AnalyzerExecution {
                initial: PhaseExecution::Required,
                verification: PhaseExecution::Required,
            },
            selection: AnalyzerSelection {
                include: vec!["**".into()],
                exclude: Vec::new(),
                artifact_kinds,
            },
            content_applicability: ContentApplicability::default(),
            limits: AnalyzerLimits {
                max_findings: Some(100),
                ..AnalyzerLimits::default()
            },
        }],
        daemon: DaemonConfig::default(),
    }
}

fn request(
    action_mode: Option<RequestedActionMode>,
    source: ProcessingSourceRequest,
) -> ProcessingCompileRequest {
    ProcessingCompileRequest {
        run_id: RunId::new("run_processing_fixture").unwrap(),
        profile_id: None,
        action_mode,
        source,
    }
}

#[test]
fn freezes_a_downgraded_path_runtime_and_stable_identities() {
    let config = fixture(HistoryScope::None, ActionMode::Apply);
    let source = ProcessingSourceRequest::Path {
        path: "/srv/incoming".into(),
    };
    let first = compile_processing_runtime(
        &config,
        request(Some(RequestedActionMode::Evaluate), source.clone()),
    )
    .unwrap();
    let mut second_request = request(Some(RequestedActionMode::Evaluate), source);
    second_request.run_id = RunId::new("run_processing_fixture_two").unwrap();
    let second = compile_processing_runtime(&config, second_request).unwrap();

    assert_eq!(first.action_mode, EffectiveActionMode::Evaluate);
    assert_eq!(first.source_scope.history, GitHistoryScope::None);
    assert_eq!(first.jobs.capture.max_files, 50);
    assert_eq!(first.acquisition.max_commits, 1_000);
    assert!(matches!(
        first.pipeline.stages[0].analyzers[0].implementation,
        FrozenAnalyzerImplementation::Builtin(_)
    ));
    assert_eq!(first.source_scope_identity, second.source_scope_identity);
    assert_eq!(first.pipeline_identity, second.pipeline_identity);
    assert_eq!(first.policy_identity, second.policy_identity);
}

#[test]
fn rejects_an_authority_upgrade() {
    let config = fixture(HistoryScope::None, ActionMode::Evaluate);
    let error = compile_processing_runtime(
        &config,
        request(
            Some(RequestedActionMode::Apply),
            ProcessingSourceRequest::Path {
                path: "/tmp".into(),
            },
        ),
    )
    .err()
    .unwrap();
    assert!(matches!(error, ProcessingRuntimeError::AuthorityEscalation));
}

#[test]
fn path_sources_cannot_select_git_history() {
    let config = fixture(HistoryScope::Head, ActionMode::Evaluate);
    let error = compile_processing_runtime(
        &config,
        request(
            None,
            ProcessingSourceRequest::Path {
                path: "/tmp".into(),
            },
        ),
    )
    .err()
    .unwrap();
    assert!(matches!(error, ProcessingRuntimeError::PathHistory));
}

#[test]
fn checkout_refs_are_full_symbolic_refs_within_profile_policy() {
    let config = fixture(HistoryScope::Head, ActionMode::Evaluate);
    let runtime = compile_processing_runtime(
        &config,
        request(
            None,
            ProcessingSourceRequest::Repo {
                path: "/repo".into(),
                reference: Some("refs/tags/release-1".into()),
            },
        ),
    )
    .unwrap();
    assert!(matches!(
        runtime.source,
        FrozenSourceRequest::Repo { checkout_ref: Some(ref value), .. }
            if value == "refs/tags/release-1"
    ));

    for reference in [
        "main",
        "refs/tags/private-1",
        "-refs/heads/main",
        "refs/heads/has space",
    ] {
        let error = compile_processing_runtime(
            &config,
            request(
                None,
                ProcessingSourceRequest::Repo {
                    path: "/repo".into(),
                    reference: Some(reference.into()),
                },
            ),
        )
        .err()
        .unwrap();
        assert!(matches!(error, ProcessingRuntimeError::CheckoutRef));
    }
}

#[test]
fn accepts_only_explicit_https_and_ssh_git_transports() {
    let config = fixture(HistoryScope::Head, ActionMode::Evaluate);
    for (remote, expected) in [
        ("https://example.test/org/repo.git", GitTransport::Https),
        ("ssh://git@example.test/org/repo.git", GitTransport::Ssh),
        (
            "ssh://git@example.test:2222/org/repo.git",
            GitTransport::Ssh,
        ),
        ("git@example.test:org/repo.git", GitTransport::Ssh),
    ] {
        let runtime = compile_processing_runtime(
            &config,
            request(
                None,
                ProcessingSourceRequest::Git {
                    remote: remote.into(),
                    reference: Some("refs/heads/main".into()),
                },
            ),
        )
        .unwrap();
        assert!(matches!(
            runtime.source,
            FrozenSourceRequest::Git { transport, .. } if transport == expected
        ));
    }

    for remote in [
        "http://example.test/repo.git",
        "https://user@example.test/repo.git",
        "https://example.test/repo.git?token=secret",
        "--upload-pack=evil",
    ] {
        let error = compile_processing_runtime(
            &config,
            request(
                None,
                ProcessingSourceRequest::Git {
                    remote: remote.into(),
                    reference: None,
                },
            ),
        )
        .err()
        .unwrap();
        assert!(matches!(error, ProcessingRuntimeError::Remote));
    }
}

#[test]
fn missing_required_external_scanner_fails_closed() {
    let mut config = fixture(HistoryScope::None, ActionMode::Evaluate);
    config.analyzers[0].kind =
        AnalyzerKind::Trufflehog(file_guardian::processing::config::TrufflehogConfig {
            executable: "file-guardian-definitely-missing-scanner".into(),
            version_requirement: ">=3.90,<4".into(),
            credential_verification:
                file_guardian::processing::config::CredentialVerification::Disabled,
        });
    config.analyzers[0].limits = AnalyzerLimits {
        wall_timeout_secs: Some(10),
        max_file_bytes: Some(10_000),
        max_output_bytes: Some(10_000),
        max_findings: Some(100),
        ..AnalyzerLimits::default()
    };
    let error = compile_processing_runtime(
        &config,
        request(
            None,
            ProcessingSourceRequest::Path {
                path: "/tmp".into(),
            },
        ),
    )
    .err()
    .unwrap();
    assert!(matches!(
        error,
        ProcessingRuntimeError::ScannerPreflight { ref analyzer } if analyzer == "rules"
    ));
}

#[test]
fn scanner_version_ranges_are_compiled_not_left_as_strings() {
    let mut config = fixture(HistoryScope::None, ActionMode::Evaluate);
    config.analyzers[0].kind =
        AnalyzerKind::Trufflehog(file_guardian::processing::config::TrufflehogConfig {
            executable: "file-guardian-definitely-missing-scanner".into(),
            // This passes the config's bounded-shape check, but is not a
            // semantic version and must fail before executable discovery.
            version_requirement: ">=broken,<4".into(),
            credential_verification:
                file_guardian::processing::config::CredentialVerification::Disabled,
        });
    config.analyzers[0].limits = AnalyzerLimits {
        wall_timeout_secs: Some(10),
        max_file_bytes: Some(10_000),
        max_output_bytes: Some(10_000),
        max_findings: Some(100),
        ..AnalyzerLimits::default()
    };
    let error = compile_processing_runtime(
        &config,
        request(
            None,
            ProcessingSourceRequest::Path {
                path: "/tmp".into(),
            },
        ),
    )
    .err()
    .unwrap();
    assert!(matches!(
        error,
        ProcessingRuntimeError::Analyzer { ref analyzer, .. } if analyzer == "rules"
    ));
}
