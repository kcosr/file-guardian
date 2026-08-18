use file_guardian::domain::{Digest, RunId};
use file_guardian::processing::domain::{
    Disposition, HandoffStatus, JobExecutionState, Outcome, TerminalJobState,
};
use file_guardian::processing::job::{
    DecisionDisposition, DecisionDispositions, JobStore, JobStoreError, JobStorePaths,
    LeaseIdentity, PrivateDecisionRecord, RecoveryDirective,
};
use file_guardian::processing::report::ProcessingReport;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    paths: JobStorePaths,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let paths = JobStorePaths {
            jobs_root: temporary.path().join("jobs"),
            reports_root: temporary.path().join("reports"),
            quarantine_root: temporary.path().join("quarantine"),
        };
        for root in [
            &paths.jobs_root,
            &paths.reports_root,
            &paths.quarantine_root,
        ] {
            fs::create_dir(root).unwrap();
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            _temporary: temporary,
            paths,
        }
    }

    fn store(&self) -> JobStore {
        JobStore::open(self.paths.clone()).unwrap()
    }
}

fn run(suffix: &str) -> RunId {
    RunId::from_suffix(suffix).unwrap()
}

fn lease_identity() -> LeaseIdentity {
    LeaseIdentity::new("process_nonce", "boot_nonce").unwrap()
}

fn digest(label: &str) -> Digest {
    Digest::sha256(label)
}

fn dispositions(
    outcome: Outcome,
    configured: DecisionDisposition,
    effective: DecisionDisposition,
) -> DecisionDispositions {
    DecisionDispositions::new(outcome, configured, effective).unwrap()
}

#[test]
fn creates_the_exact_private_layout_and_durable_initial_records() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let lease = store.create(&run("layout"), lease_identity(), 100).unwrap();

    let expected_directories = [
        "stage",
        "private",
        "private/initial",
        "private/initial/manifest",
        "private/initial/objects",
        "private/verification",
        "private/verification/manifest",
        "private/verification/objects",
        "private/analyzer-views",
        "private/scanner-output",
        "private/action-journal",
        "private/artifact-quarantine",
        "private/tmp",
    ];
    assert_eq!(
        lease.paths().root(),
        fixture.paths.jobs_root.join("run_layout")
    );
    for relative in expected_directories {
        let path = lease.paths().root().join(relative);
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    for relative in ["lock", "state.json", "heartbeat"] {
        let metadata = fs::symlink_metadata(lease.paths().root().join(relative)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(lease.state().execution, JobExecutionState::Created);
    assert_eq!(lease.state().revision, 0);
    assert_eq!(lease.heartbeat_record().sequence, 0);
    assert!(fs::read_dir(&fixture.paths.jobs_root)
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
}

#[test]
fn run_ids_and_job_entries_cannot_escape_the_jobs_root() {
    assert!(RunId::new("run_../outside").is_err());
    assert!(RunId::new("run_a/b").is_err());

    let fixture = Fixture::new();
    fs::write(fixture.paths.jobs_root.join("not-a-run"), b"payload").unwrap();
    assert!(matches!(
        fixture.store().list_run_ids(),
        Err(JobStoreError::UnexpectedRootEntry)
    ));
    assert!(!fixture._temporary.path().join("outside").exists());
}

#[test]
fn roots_and_run_directories_reject_aliases_links_and_excess_permissions() {
    let fixture = Fixture::new();
    let aliased = JobStorePaths {
        jobs_root: fixture.paths.jobs_root.clone(),
        reports_root: fixture.paths.jobs_root.clone(),
        quarantine_root: fixture.paths.quarantine_root.clone(),
    };
    assert!(matches!(
        JobStore::open(aliased),
        Err(JobStoreError::AliasedRoots)
    ));

    fs::set_permissions(
        &fixture.paths.reports_root,
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    assert!(matches!(
        JobStore::open(fixture.paths.clone()),
        Err(JobStoreError::InsecureRoot)
    ));

    fs::set_permissions(
        &fixture.paths.reports_root,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let outside = fixture._temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, fixture.paths.jobs_root.join("run_link")).unwrap();
    assert!(fixture.store().try_acquire(&run("link")).is_err());
}

#[test]
fn advisory_lock_excludes_concurrent_mutation_and_releases_on_drop() {
    let fixture = Fixture::new();
    let first_store = fixture.store();
    let second_store = fixture.store();
    let lease = first_store
        .create(&run("concurrent"), lease_identity(), 100)
        .unwrap();

    assert!(matches!(
        second_store.try_acquire(&run("concurrent")),
        Err(JobStoreError::Locked)
    ));
    assert!(second_store
        .try_acquire_stale(&run("concurrent"), 1_000, 1)
        .unwrap()
        .is_none());
    drop(lease);
    assert!(second_store
        .try_acquire_stale(&run("concurrent"), 101, 1)
        .unwrap()
        .is_none());
    assert!(second_store
        .try_acquire_stale(&run("concurrent"), 102, 1)
        .unwrap()
        .is_some());
}

#[test]
fn heartbeat_is_atomic_monotonic_and_staleness_uses_the_recorded_lease() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut lease = store
        .create(&run("heartbeat"), lease_identity(), 100)
        .unwrap();
    assert!(!lease.is_stale(110, 10));
    assert!(lease.is_stale(111, 10));
    lease.heartbeat(500).unwrap();
    assert_eq!(lease.heartbeat_record().sequence, 1);
    assert!(!lease.is_stale(510, 10));

    drop(lease);
    let mut reopened = store.try_acquire(&run("heartbeat")).unwrap();
    assert_eq!(reopened.heartbeat_record().sequence, 1);
    assert_eq!(reopened.heartbeat_record().unix_millis, 500);
    reopened
        .claim_lease(LeaseIdentity::new("recovery", "new_boot").unwrap(), 1_000)
        .unwrap();
    assert_eq!(reopened.heartbeat_record().sequence, 2);
    assert_eq!(reopened.heartbeat_record().lease.process_nonce, "recovery");
    assert!(fs::read_dir(reopened.paths().root())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
}

#[test]
fn normal_state_machine_rejects_skips_and_persists_revisions() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut lease = store
        .create(&run("transitions"), lease_identity(), 0)
        .unwrap();
    assert!(matches!(
        lease.transition(JobExecutionState::Acquired, 1),
        Err(JobStoreError::InvalidTransition { .. })
    ));
    for (revision, state) in [
        JobExecutionState::Acquiring,
        JobExecutionState::Acquired,
        JobExecutionState::BaselineCaptured,
        JobExecutionState::AnalyzingInitial,
        JobExecutionState::ResolvingInitial,
        JobExecutionState::RevalidatingFinal,
        JobExecutionState::Sealing,
    ]
    .into_iter()
    .enumerate()
    {
        lease.transition(state, revision as i64 + 1).unwrap();
    }
    assert_eq!(lease.state().revision, 7);
    assert!(matches!(
        lease.transition(JobExecutionState::PreparingDecision, 8),
        Err(JobStoreError::Io { .. })
    ));

    let decision = PrivateDecisionRecord::new(
        run("transitions"),
        Outcome::Allow,
        Some(digest("final")),
        Some(digest("policy")),
        dispositions(
            Outcome::Allow,
            DecisionDisposition::Retain,
            DecisionDisposition::Retain,
        ),
        digest("report"),
        json!({"safe": true}),
    )
    .unwrap();
    lease.write_decision(&decision).unwrap();
    lease
        .transition(JobExecutionState::PreparingDecision, 8)
        .unwrap();
    lease.transition(JobExecutionState::Disposing, 9).unwrap();
    lease
        .transition(JobExecutionState::PublishingReport, 10)
        .unwrap();
    lease
        .finish_terminal(
            TerminalJobState::new(
                Outcome::Allow,
                Disposition::Retained,
                HandoffStatus::Available,
            )
            .unwrap(),
            11,
        )
        .unwrap();
    assert_eq!(lease.state().revision, 11);
    assert_eq!(lease.state().execution, JobExecutionState::Terminal);
}

#[test]
fn private_decision_is_strict_bound_to_the_run_and_create_once() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let lease = store.create(&run("decision"), lease_identity(), 0).unwrap();
    assert!(PrivateDecisionRecord::new(
        run("decision"),
        Outcome::Allow,
        Some(digest("manifest")),
        None,
        dispositions(
            Outcome::Allow,
            DecisionDisposition::Retain,
            DecisionDisposition::Retain,
        ),
        digest("report"),
        json!({}),
    )
    .is_err());
    assert!(DecisionDispositions::new(
        Outcome::Allow,
        DecisionDisposition::Retain,
        DecisionDisposition::Quarantine,
    )
    .is_err());
    assert!(DecisionDispositions::new(
        Outcome::Deny,
        DecisionDisposition::Discard,
        DecisionDisposition::Quarantine,
    )
    .is_err());
    assert!(DecisionDispositions::new(
        Outcome::Error,
        DecisionDisposition::Retain,
        DecisionDisposition::Discard,
    )
    .is_err());
    assert!(DecisionDispositions::new(
        Outcome::Error,
        DecisionDisposition::Discard,
        DecisionDisposition::Quarantine,
    )
    .is_ok());

    let wrong = PrivateDecisionRecord::new(
        run("other"),
        Outcome::Error,
        None,
        None,
        dispositions(
            Outcome::Error,
            DecisionDisposition::Quarantine,
            DecisionDisposition::Quarantine,
        ),
        digest("report"),
        json!({"issues": ["acquisition_failed"]}),
    )
    .unwrap();
    assert!(matches!(
        lease.write_decision(&wrong),
        Err(JobStoreError::RunIdentityMismatch)
    ));
    let decision = PrivateDecisionRecord::new(
        run("decision"),
        Outcome::Error,
        None,
        None,
        dispositions(
            Outcome::Error,
            DecisionDisposition::Quarantine,
            DecisionDisposition::Quarantine,
        ),
        digest("report"),
        json!({"issues": ["acquisition_failed"]}),
    )
    .unwrap();
    lease.write_decision(&decision).unwrap();
    assert_eq!(lease.read_decision().unwrap(), decision);
    assert!(lease.write_decision(&decision).is_err());

    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(lease.paths().root().join("decision.json")).unwrap())
            .unwrap();
    raw.as_object_mut()
        .unwrap()
        .insert("unknown".into(), json!(true));
    assert!(serde_json::from_value::<PrivateDecisionRecord>(raw).is_err());
}

#[test]
fn corrupt_or_foreign_durable_records_fail_closed_on_reopen() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let lease = store.create(&run("corrupt"), lease_identity(), 0).unwrap();
    let root = lease.paths().root().to_owned();
    drop(lease);

    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("state.json")).unwrap()).unwrap();
    raw["run_id"] = json!("run_foreign");
    fs::write(root.join("state.json"), serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(matches!(
        store.try_acquire(&run("corrupt")),
        Err(JobStoreError::RunIdentityMismatch)
    ));
}

#[test]
fn final_report_is_published_once_and_never_replaced() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let run_id = run("allow");
    let _lease = store.create(&run_id, lease_identity(), 0).unwrap();
    let report: ProcessingReport = serde_json::from_str(include_str!(
        "../docs/examples/processing-reports/allow.json"
    ))
    .unwrap();

    let report_path = store.publish_report_once(&run_id, &report).unwrap();
    let original = fs::read(&report_path).unwrap();
    assert_eq!(original.last(), Some(&b'\n'));
    assert!(store.publish_report_once(&run_id, &report).is_err());
    assert_eq!(fs::read(&report_path).unwrap(), original);
    assert!(fs::read_dir(&fixture.paths.reports_root)
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
}

#[test]
fn recovery_classifies_every_nonterminal_state_fail_closed() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut lease = store.create(&run("recovery"), lease_identity(), 0).unwrap();
    assert_eq!(
        lease.recovery_directive(),
        RecoveryDirective::FailAcquisition
    );
    let rows = [
        (
            JobExecutionState::Acquiring,
            RecoveryDirective::FailAcquisition,
        ),
        (JobExecutionState::Acquired, RecoveryDirective::FailAnalysis),
        (
            JobExecutionState::BaselineCaptured,
            RecoveryDirective::FailAnalysis,
        ),
        (
            JobExecutionState::AnalyzingInitial,
            RecoveryDirective::FailAnalysis,
        ),
        (
            JobExecutionState::ResolvingInitial,
            RecoveryDirective::FailAnalysis,
        ),
        (
            JobExecutionState::PlanningActions,
            RecoveryDirective::RecoverActionsAndQuarantine,
        ),
        (
            JobExecutionState::ApplyingActions,
            RecoveryDirective::RecoverActionsAndQuarantine,
        ),
        (
            JobExecutionState::CapturingVerification,
            RecoveryDirective::RecoverActionsAndQuarantine,
        ),
        (
            JobExecutionState::AnalyzingVerification,
            RecoveryDirective::RecoverActionsAndQuarantine,
        ),
        (
            JobExecutionState::ResolvingVerification,
            RecoveryDirective::RecoverActionsAndQuarantine,
        ),
        (
            JobExecutionState::RevalidatingFinal,
            RecoveryDirective::ValidateResolutionAndRecapture,
        ),
        (
            JobExecutionState::Sealing,
            RecoveryDirective::ValidateResolutionAndRecapture,
        ),
    ];
    for (index, (state, expected)) in rows.into_iter().enumerate() {
        lease.transition(state, index as i64 + 1).unwrap();
        assert_eq!(lease.recovery_directive(), expected);
    }
    let decision = PrivateDecisionRecord::new(
        run("recovery"),
        Outcome::Allow,
        Some(digest("manifest")),
        Some(digest("policy")),
        dispositions(
            Outcome::Allow,
            DecisionDisposition::Retain,
            DecisionDisposition::Retain,
        ),
        digest("report"),
        json!({}),
    )
    .unwrap();
    lease.write_decision(&decision).unwrap();
    for (state, expected) in [
        (
            JobExecutionState::PreparingDecision,
            RecoveryDirective::ResumeRecordedDisposition,
        ),
        (
            JobExecutionState::Disposing,
            RecoveryDirective::ResumeDisposition,
        ),
        (
            JobExecutionState::PublishingReport,
            RecoveryDirective::ResumeReportPublication,
        ),
    ] {
        lease.transition(state, 20).unwrap();
        assert_eq!(lease.recovery_directive(), expected);
    }
}

#[test]
fn terminal_recovery_keeps_outcome_disposition_and_handoff_orthogonal() {
    let cases = [
        (
            Outcome::Allow,
            Disposition::Retained,
            HandoffStatus::Available,
            RecoveryDirective::PreserveRetained,
        ),
        (
            Outcome::AllowModified,
            Disposition::Retained,
            HandoffStatus::HandedOff,
            RecoveryDirective::GarbageCollectTombstone,
        ),
        (
            Outcome::Deny,
            Disposition::Discarded,
            HandoffStatus::Unavailable,
            RecoveryDirective::GarbageCollectTombstone,
        ),
        (
            Outcome::Deny,
            Disposition::Quarantined,
            HandoffStatus::Unavailable,
            RecoveryDirective::PreserveQuarantined,
        ),
        (
            Outcome::Error,
            Disposition::RetainedError,
            HandoffStatus::Unavailable,
            RecoveryDirective::PreserveRetainedError,
        ),
    ];
    for (index, (outcome, disposition, handoff, expected)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let suffix = format!("terminal-{index}");
        let mut lease = store.create(&run(&suffix), lease_identity(), 0).unwrap();
        let decision = PrivateDecisionRecord::new(
            run(&suffix),
            outcome,
            outcome.is_allowed().then(|| digest("manifest")),
            outcome.is_allowed().then(|| digest("policy")),
            dispositions(
                outcome,
                match disposition {
                    Disposition::Retained | Disposition::RetainedError => {
                        DecisionDisposition::Retain
                    }
                    Disposition::Discarded => DecisionDisposition::Discard,
                    Disposition::Quarantined => DecisionDisposition::Quarantine,
                },
                match disposition {
                    Disposition::Retained | Disposition::RetainedError => {
                        DecisionDisposition::Retain
                    }
                    Disposition::Discarded => DecisionDisposition::Discard,
                    Disposition::Quarantined => DecisionDisposition::Quarantine,
                },
            ),
            digest("report"),
            json!({}),
        )
        .unwrap();
        lease.write_decision(&decision).unwrap();
        lease.enter_preparing_decision(1).unwrap();
        lease.transition(JobExecutionState::Disposing, 2).unwrap();
        lease
            .transition(JobExecutionState::PublishingReport, 3)
            .unwrap();
        lease
            .finish_terminal(
                TerminalJobState::new(outcome, disposition, handoff).unwrap(),
                4,
            )
            .unwrap();
        assert_eq!(lease.recovery_directive(), expected);
    }
}

#[test]
fn all_public_paths_remain_beneath_the_validated_run() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let lease = store.create(&run("paths"), lease_identity(), 0).unwrap();
    for path in [
        lease.paths().stage(),
        lease.paths().private_root(),
        lease.paths().initial_root(),
        lease.paths().verification_root(),
        lease.paths().analyzer_views(),
        lease.paths().scanner_output(),
        lease.paths().action_journal(),
        lease.paths().artifact_quarantine(),
        lease.paths().temporary(),
    ] {
        assert!(path.starts_with(lease.paths().root()));
        assert!(!path
            .components()
            .any(|component| component.as_os_str() == ".."));
    }
}

#[test]
fn root_paths_must_be_absolute() {
    let relative = JobStorePaths {
        jobs_root: Path::new("jobs").to_owned(),
        reports_root: Path::new("reports").to_owned(),
        quarantine_root: Path::new("quarantine").to_owned(),
    };
    assert!(matches!(
        JobStore::open(relative),
        Err(JobStoreError::RootNotAbsolute)
    ));
}
