use file_guardian::domain::{Digest, RunId};
use file_guardian::processing::acquisition::local::{
    acquire_local, AcquisitionCancellation, LocalAcquisitionRequest, LocalAcquisitionResult,
};
use file_guardian::processing::completion::{
    discard_retained_stage, finalize_job, handoff_stage, inspect_job, load_sealed_stage,
    recover_job, recover_job_with_report, revalidate_and_seal, CompletionDisposition,
    CompletionError, FinalizeRequest, HandoffMode,
};
use file_guardian::processing::config::{CaptureLimits, SymlinkPolicy};
use file_guardian::processing::domain::{Disposition, HandoffStatus, JobExecutionState, Outcome};
use file_guardian::processing::job::{
    DecisionDispositions, JobLease, JobStore, JobStorePaths, LeaseIdentity, PrivateDecisionRecord,
};
use file_guardian::processing::report::{
    ConfiguredDisposition as ReportConfiguredDisposition, EffectiveDisposition,
    HandoffStatus as ReportHandoffStatus, IssueSummary, OmissionSummary, PersistenceStatus,
    PhasesSummary, ProcessingOutcome, ProcessingReport, ProcessingReportData, ProcessingStatistics,
    Rfc3339Timestamp, SafeId, Sha256Digest, StageSummary,
};
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::str::FromStr;
use tempfile::TempDir;

struct Fixture {
    temporary: TempDir,
    store: JobStore,
    source: PathBuf,
    cancellation: AcquisitionCancellation,
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
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("plain.txt"), b"safe bytes\n").unwrap();
        fs::write(source.join("program.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(source.join("program.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/value"), b"nested\n").unwrap();
        let store = JobStore::open(paths).unwrap();
        Self {
            temporary,
            store,
            source,
            cancellation: AcquisitionCancellation::default(),
        }
    }

    fn create_acquired(&self, run_id: &RunId) -> (JobLease, LocalAcquisitionResult) {
        let mut lease = self
            .store
            .create(run_id, LeaseIdentity::new("process", "boot").unwrap(), 0)
            .unwrap();
        lease.transition(JobExecutionState::Acquiring, 1).unwrap();
        let acquired = acquire_local(LocalAcquisitionRequest {
            source: &self.source,
            stage: &lease.paths().stage(),
            jobs_root: &self.store.paths().jobs_root,
            limits: &limits(),
            symlinks: SymlinkPolicy::Reject,
            cancellation: &self.cancellation,
        })
        .unwrap();
        lease.transition(JobExecutionState::Acquired, 2).unwrap();
        lease
            .transition(JobExecutionState::BaselineCaptured, 3)
            .unwrap();
        lease
            .transition(JobExecutionState::AnalyzingInitial, 4)
            .unwrap();
        lease
            .transition(JobExecutionState::ResolvingInitial, 5)
            .unwrap();
        (lease, acquired)
    }
}

fn limits() -> CaptureLimits {
    CaptureLimits {
        max_entries: 100,
        max_files: 100,
        max_file_bytes: 1024 * 1024,
        max_total_bytes: 10 * 1024 * 1024,
        max_depth: 16,
    }
}

fn run(suffix: &str) -> RunId {
    RunId::from_suffix(suffix).unwrap()
}

fn advance_to_sealing(lease: &mut JobLease) {
    lease
        .transition(JobExecutionState::RevalidatingFinal, 6)
        .unwrap();
    lease.transition(JobExecutionState::Sealing, 7).unwrap();
}

fn allow_report(run_id: &RunId, manifest: Digest) -> ProcessingReport {
    allow_report_with_request(run_id, manifest, None)
}

fn allow_report_with_request(
    run_id: &RunId,
    manifest: Digest,
    request_id: Option<SafeId>,
) -> ProcessingReport {
    let golden: ProcessingReport = serde_json::from_str(include_str!(
        "../docs/examples/processing-reports/allow.json"
    ))
    .unwrap();
    let safe_run = SafeId::new(run_id.as_str()).unwrap();
    let digest = Sha256Digest::new(manifest.to_string()).unwrap();
    let mut stage = golden.stage.unwrap();
    stage.reference = Some(safe_run.clone());
    stage.initial_manifest_identity = Some(digest.clone());
    stage.final_manifest_identity = Some(digest.clone());
    stage.current_manifest_identity = Some(digest.clone());
    let mut phases = golden.phases;
    phases.initial.as_mut().unwrap().manifest_identity =
        Sha256Digest::new(Digest::sha256(b"composite analysis snapshot").to_string()).unwrap();
    ProcessingReport::new(ProcessingReportData {
        run_id: safe_run,
        request_id,
        outcome: golden.outcome,
        modified: golden.modified,
        started_at: golden.started_at,
        finished_at: golden.finished_at,
        persistence_status: PersistenceStatus::Durable,
        source: golden.source,
        acquisition: golden.acquisition,
        stage: Some(stage),
        policy: golden.policy,
        phases,
        pi_invocations: golden.pi_invocations,
        adjudications: golden.adjudications,
        actions: golden.actions,
        issues: golden.issues,
        degradations: golden.degradations,
        statistics: golden.statistics,
        omissions: golden.omissions,
    })
    .unwrap()
}

fn deny_report() -> ProcessingReport {
    serde_json::from_str(include_str!(
        "../docs/examples/processing-reports/deny.json"
    ))
    .unwrap()
}

fn durable_error_report(run_id: &RunId) -> ProcessingReport {
    ProcessingReport::new(ProcessingReportData {
        run_id: SafeId::new(run_id.as_str()).unwrap(),
        request_id: None,
        outcome: ProcessingOutcome::Error,
        modified: false,
        started_at: Rfc3339Timestamp::new("2026-08-17T12:00:00+00:00").unwrap(),
        finished_at: Rfc3339Timestamp::new("2026-08-17T12:00:01+00:00").unwrap(),
        persistence_status: PersistenceStatus::Durable,
        source: None,
        acquisition: None,
        stage: None,
        policy: None,
        phases: PhasesSummary {
            initial: None,
            verification: None,
        },
        pi_invocations: vec![],
        adjudications: vec![],
        actions: vec![],
        issues: vec![IssueSummary {
            code: SafeId::new("processing_cancelled").unwrap(),
            phase: None,
            component_id: None,
        }],
        degradations: vec![],
        statistics: ProcessingStatistics {
            initial_artifacts: 0,
            verification_artifacts: 0,
            total_findings: 0,
            total_actions: 0,
            duration_ms: 1_000,
        },
        omissions: OmissionSummary {
            details_omitted: false,
            reason: None,
        },
    })
    .unwrap()
}

fn quarantine_override_report(
    run_id: &RunId,
    configured: ReportConfiguredDisposition,
) -> ProcessingReport {
    ProcessingReport::new(ProcessingReportData {
        run_id: SafeId::new(run_id.as_str()).unwrap(),
        request_id: None,
        outcome: ProcessingOutcome::Error,
        modified: false,
        started_at: Rfc3339Timestamp::new("2026-08-17T12:00:00+00:00").unwrap(),
        finished_at: Rfc3339Timestamp::new("2026-08-17T12:00:01+00:00").unwrap(),
        persistence_status: PersistenceStatus::Durable,
        source: None,
        acquisition: None,
        stage: Some(StageSummary {
            reference: None,
            configured_disposition: configured,
            effective_disposition: EffectiveDisposition::Quarantined,
            handoff_status: ReportHandoffStatus::Unavailable,
            sealed: false,
            initial_manifest_identity: None,
            final_manifest_identity: None,
            current_manifest_identity: None,
            expires_at: None,
            quarantine_id: Some(SafeId::new(run_id.as_str()).unwrap()),
        }),
        policy: None,
        phases: PhasesSummary {
            initial: None,
            verification: None,
        },
        pi_invocations: vec![],
        adjudications: vec![],
        actions: vec![],
        issues: vec![IssueSummary {
            code: SafeId::new("ambiguous_stage_mutation").unwrap(),
            phase: None,
            component_id: None,
        }],
        degradations: vec![],
        statistics: ProcessingStatistics {
            initial_artifacts: 0,
            verification_artifacts: 0,
            total_findings: 0,
            total_actions: 0,
            duration_ms: 1_000,
        },
        omissions: OmissionSummary {
            details_omitted: false,
            reason: None,
        },
    })
    .unwrap()
}

fn decision(
    run_id: &RunId,
    outcome: Outcome,
    manifest: Option<Digest>,
    disposition: CompletionDisposition,
    report: &ProcessingReport,
) -> PrivateDecisionRecord {
    decision_with_effective(run_id, outcome, manifest, disposition, disposition, report)
}

fn decision_with_effective(
    run_id: &RunId,
    outcome: Outcome,
    manifest: Option<Digest>,
    configured: CompletionDisposition,
    effective: CompletionDisposition,
    report: &ProcessingReport,
) -> PrivateDecisionRecord {
    PrivateDecisionRecord::new(
        run_id.clone(),
        outcome,
        manifest,
        Some(Digest::sha256(b"policy evidence")),
        DecisionDispositions::new(outcome, configured.into(), effective.into()).unwrap(),
        Digest::sha256(report.to_json_line().unwrap()),
        serde_json::to_value(report).unwrap(),
    )
    .unwrap()
}

#[test]
fn revalidation_seals_every_regular_file_and_detects_tampering() {
    let fixture = Fixture::new();
    let run_id = run("seal");
    let (lease, acquired) = fixture.create_acquired(&run_id);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    assert_eq!(sealed.manifest_identity(), acquired.manifest_identity);
    assert_eq!(sealed.entries(), acquired.entries);
    let loaded = load_sealed_stage(&fixture.store, &run_id, &fixture.cancellation).unwrap();
    assert_eq!(loaded.manifest_identity(), acquired.manifest_identity);
    assert_eq!(loaded.entries(), acquired.entries);
    assert_eq!(
        fs::metadata(lease.paths().stage()).unwrap().mode() & 0o777,
        0o500
    );
    assert_eq!(
        fs::metadata(lease.paths().stage().join("plain.txt"))
            .unwrap()
            .mode()
            & 0o777,
        0o400
    );
    assert_eq!(
        fs::metadata(lease.paths().stage().join("program.sh"))
            .unwrap()
            .mode()
            & 0o777,
        0o500
    );

    fs::set_permissions(
        lease.paths().stage().join("plain.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(lease.paths().stage().join("plain.txt"), b"tampered").unwrap();
    assert!(matches!(
        revalidate_and_seal(
            &lease.paths().stage(),
            &acquired.entries,
            acquired.manifest_identity,
            &fixture.cancellation,
        ),
        Err(CompletionError::StageMismatch)
    ));
}

#[test]
fn cancellation_before_sealing_leaves_the_stage_unapproved() {
    let fixture = Fixture::new();
    let (lease, acquired) = fixture.create_acquired(&run("cancel"));
    fixture.cancellation.cancel();
    assert!(matches!(
        revalidate_and_seal(
            &lease.paths().stage(),
            &acquired.entries,
            acquired.manifest_identity,
            &fixture.cancellation,
        ),
        Err(CompletionError::Cancelled)
    ));
    assert_eq!(
        fs::metadata(lease.paths().stage()).unwrap().mode() & 0o777,
        0o700
    );
}

#[test]
fn handoff_sealing_rejects_absolute_and_escaping_preserved_symlinks() {
    for (suffix, target) in [
        ("absolute-link", "/etc/passwd"),
        ("escape-link", "../outside"),
    ] {
        let fixture = Fixture::new();
        symlink(target, fixture.source.join("unsafe-link")).unwrap();
        let run_id = run(suffix);
        let mut lease = fixture
            .store
            .create(&run_id, LeaseIdentity::new("process", "boot").unwrap(), 0)
            .unwrap();
        lease.transition(JobExecutionState::Acquiring, 1).unwrap();
        let acquired = acquire_local(LocalAcquisitionRequest {
            source: &fixture.source,
            stage: &lease.paths().stage(),
            jobs_root: &fixture.store.paths().jobs_root,
            limits: &limits(),
            symlinks: SymlinkPolicy::Preserve,
            cancellation: &fixture.cancellation,
        })
        .unwrap();
        assert!(matches!(
            revalidate_and_seal(
                &lease.paths().stage(),
                &acquired.entries,
                acquired.manifest_identity,
                &fixture.cancellation,
            ),
            Err(CompletionError::UnsafeHandoffSymlink)
        ));
    }
}

#[test]
fn deny_discard_commits_disposition_before_publishing_report() {
    let fixture = Fixture::new();
    let run_id = run("deny");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = deny_report();
    let decision = decision(
        &run_id,
        Outcome::Deny,
        Some(
            Digest::from_str(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        ),
        CompletionDisposition::Discard,
        &report,
    );
    let status = finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Discard,
            effective_disposition: CompletionDisposition::Discard,
            sealed_stage: None,
            now_unix_millis: 10,
        },
    )
    .unwrap();
    assert_eq!(status.disposition, Disposition::Discarded);
    assert_eq!(status.handoff, HandoffStatus::Unavailable);
    assert!(!lease.paths().stage().exists());
    assert!(fixture
        .store
        .paths()
        .reports_root
        .join("run_deny.json")
        .exists());
    assert_eq!(lease.state().execution, JobExecutionState::Terminal);
}

#[test]
fn cancelled_job_is_quarantined_before_its_public_error_report_is_published() {
    let fixture = Fixture::new();
    let run_id = run("cancelled-quarantine");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = durable_error_report(&run_id);
    let decision = decision(
        &run_id,
        Outcome::Cancelled,
        None,
        CompletionDisposition::Quarantine,
        &report,
    );
    let status = finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Quarantine,
            effective_disposition: CompletionDisposition::Quarantine,
            sealed_stage: None,
            now_unix_millis: 10,
        },
    )
    .unwrap();
    assert_eq!(status.outcome, Outcome::Cancelled);
    assert_eq!(status.disposition, Disposition::Quarantined);
    assert!(!fixture
        .store
        .paths()
        .jobs_root
        .join(run_id.as_str())
        .exists());
    assert!(fixture
        .store
        .paths()
        .quarantine_root
        .join(run_id.as_str())
        .exists());
    assert!(fixture
        .store
        .paths()
        .reports_root
        .join(format!("{}.json", run_id.as_str()))
        .exists());
}

#[test]
fn error_discard_is_overridden_to_durable_whole_job_quarantine() {
    let fixture = Fixture::new();
    let run_id = run("override-quarantine");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = quarantine_override_report(&run_id, ReportConfiguredDisposition::Discard);
    let decision = decision_with_effective(
        &run_id,
        Outcome::Error,
        None,
        CompletionDisposition::Discard,
        CompletionDisposition::Quarantine,
        &report,
    );
    let status = finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Discard,
            effective_disposition: CompletionDisposition::Quarantine,
            sealed_stage: None,
            now_unix_millis: 10,
        },
    )
    .unwrap();
    assert_eq!(status.disposition, Disposition::Quarantined);
    assert!(fixture
        .store
        .paths()
        .quarantine_root
        .join(run_id.as_str())
        .join("stage")
        .exists());
}

#[test]
fn recovery_uses_effective_quarantine_not_configured_retain() {
    let fixture = Fixture::new();
    let run_id = run("recover-override");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = quarantine_override_report(&run_id, ReportConfiguredDisposition::Retain);
    let decision = decision_with_effective(
        &run_id,
        Outcome::Cancelled,
        None,
        CompletionDisposition::Retain,
        CompletionDisposition::Quarantine,
        &report,
    );
    lease.write_decision(&decision).unwrap();
    lease.enter_preparing_decision(8).unwrap();
    drop(lease);

    let status = recover_job(
        &fixture.store,
        &run_id,
        10,
        1,
        LeaseIdentity::new("recovery", "boot").unwrap(),
    )
    .unwrap();
    assert_eq!(status.outcome, Outcome::Cancelled);
    assert_eq!(status.disposition, Disposition::Quarantined);
    assert!(fixture
        .store
        .paths()
        .quarantine_root
        .join(run_id.as_str())
        .exists());
}

#[test]
fn failed_quarantine_keeps_a_private_retained_error_and_publishes_no_report() {
    let fixture = Fixture::new();
    let run_id = run("quarantine-collision");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let collision = fixture.store.paths().quarantine_root.join(run_id.as_str());
    fs::create_dir(&collision).unwrap();
    fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
    let report = durable_error_report(&run_id);
    let decision = decision(
        &run_id,
        Outcome::Error,
        None,
        CompletionDisposition::Quarantine,
        &report,
    );
    assert!(matches!(
        finalize_job(
            &fixture.store,
            &mut lease,
            FinalizeRequest {
                decision: &decision,
                report: &report,
                configured_disposition: CompletionDisposition::Quarantine,
                effective_disposition: CompletionDisposition::Quarantine,
                sealed_stage: None,
                now_unix_millis: 10,
            },
        ),
        Err(CompletionError::DispositionFailedRetainedError)
    ));
    assert_eq!(lease.state().execution, JobExecutionState::Disposing);
    assert_eq!(
        inspect_job(&fixture.store, &run_id).unwrap().disposition,
        Disposition::RetainedError
    );
    assert!(!fixture
        .store
        .paths()
        .reports_root
        .join(format!("{}.json", run_id.as_str()))
        .exists());
}

#[test]
fn recovery_resumes_from_private_decision_without_publishing_a_provisional_report() {
    let fixture = Fixture::new();
    let run_id = run("deny");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = deny_report();
    let decision = decision(
        &run_id,
        Outcome::Deny,
        Some(
            Digest::from_str(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        ),
        CompletionDisposition::Discard,
        &report,
    );
    lease.write_decision(&decision).unwrap();
    lease.enter_preparing_decision(8).unwrap();
    assert!(!fixture
        .store
        .paths()
        .reports_root
        .join("run_deny.json")
        .exists());
    drop(lease);

    let status = recover_job(
        &fixture.store,
        &run_id,
        9,
        1,
        LeaseIdentity::new("recovery", "boot").unwrap(),
    )
    .unwrap();
    assert_eq!(status.disposition, Disposition::Discarded);
    assert!(status.report_published);
    assert!(!fixture
        .store
        .paths()
        .jobs_root
        .join("run_deny/stage")
        .exists());
    assert!(fixture
        .store
        .paths()
        .reports_root
        .join("run_deny.json")
        .exists());
}

#[test]
fn recovery_relocks_a_job_after_the_atomic_quarantine_rename() {
    let fixture = Fixture::new();
    let run_id = run("restart-quarantine");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = durable_error_report(&run_id);
    let decision = decision(
        &run_id,
        Outcome::Error,
        None,
        CompletionDisposition::Quarantine,
        &report,
    );
    lease.write_decision(&decision).unwrap();
    lease.enter_preparing_decision(8).unwrap();
    lease.transition(JobExecutionState::Disposing, 9).unwrap();
    let source = fixture.store.paths().jobs_root.join(run_id.as_str());
    let quarantined = fixture.store.paths().quarantine_root.join(run_id.as_str());
    fs::rename(&source, &quarantined).unwrap();
    drop(lease);

    let status = recover_job_with_report(&fixture.store, &run_id, &report, 10).unwrap();
    assert_eq!(status.disposition, Disposition::Quarantined);
    assert!(status.report_published);
    assert_eq!(
        inspect_job(&fixture.store, &run_id).unwrap().disposition,
        Disposition::Quarantined
    );
    assert_eq!(
        fixture
            .store
            .try_acquire_quarantined(&run_id)
            .unwrap()
            .state()
            .execution,
        JobExecutionState::Terminal
    );
}

#[test]
fn retained_allow_can_move_once_without_overwrite_or_fallback() {
    let fixture = Fixture::new();
    let run_id = run("allow");
    let (mut lease, acquired) = fixture.create_acquired(&run_id);
    advance_to_sealing(&mut lease);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    let report = allow_report(&run_id, acquired.manifest_identity);
    let decision = decision(
        &run_id,
        Outcome::Allow,
        Some(acquired.manifest_identity),
        CompletionDisposition::Retain,
        &report,
    );
    let status = finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Retain,
            effective_disposition: CompletionDisposition::Retain,
            sealed_stage: Some(&sealed),
            now_unix_millis: 10,
        },
    )
    .unwrap();
    assert!(status.stage_available());
    let pre_handoff_status = status;
    let pre_handoff_state = serde_json::to_vec(lease.state()).unwrap();
    drop(lease);

    let destination_parent = fixture.temporary.path().join("handoff");
    fs::create_dir(&destination_parent).unwrap();
    fs::set_permissions(&destination_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = destination_parent.join("published");
    let receipt = handoff_stage(
        &fixture.store,
        &run_id,
        &destination,
        HandoffMode::Move,
        &fixture.cancellation,
    )
    .unwrap();
    assert_eq!(receipt.mode, HandoffMode::Move);
    assert_eq!(
        fs::read(destination.join("plain.txt")).unwrap(),
        b"safe bytes\n"
    );
    assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, 0o755);
    assert_eq!(
        inspect_job(&fixture.store, &run_id).unwrap().handoff,
        HandoffStatus::HandedOff
    );
    assert_eq!(
        fixture
            .store
            .try_acquire(&run_id)
            .unwrap()
            .state()
            .terminal
            .unwrap()
            .handoff,
        HandoffStatus::HandedOff
    );
    assert!(matches!(
        handoff_stage(
            &fixture.store,
            &run_id,
            &destination_parent.join("second"),
            HandoffMode::Move,
            &fixture.cancellation,
        ),
        Err(CompletionError::HandoffIntentMismatch)
    ));

    // Simulate a crash after destination publication but before the terminal
    // state/status/receipt. The durable intent lets the exact retry adopt the
    // already verified destination without needing the moved source stage.
    fs::write(
        fixture
            .store
            .paths()
            .jobs_root
            .join(run_id.as_str())
            .join("state.json"),
        pre_handoff_state,
    )
    .unwrap();
    fs::write(
        fixture
            .store
            .paths()
            .jobs_root
            .join(run_id.as_str())
            .join("completion-status.json"),
        serde_json::to_vec(&pre_handoff_status).unwrap(),
    )
    .unwrap();
    let adopted = handoff_stage(
        &fixture.store,
        &run_id,
        &destination,
        HandoffMode::Move,
        &fixture.cancellation,
    )
    .unwrap();
    assert_eq!(adopted, receipt);
    assert_eq!(
        inspect_job(&fixture.store, &run_id).unwrap().handoff,
        HandoffStatus::HandedOff
    );
}

#[test]
fn copy_handoff_verifies_the_copy_and_removes_the_private_stage() {
    let fixture = Fixture::new();
    let run_id = run("copy");
    let (mut lease, acquired) = fixture.create_acquired(&run_id);
    advance_to_sealing(&mut lease);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    let report = allow_report(&run_id, acquired.manifest_identity);
    let decision = decision(
        &run_id,
        Outcome::Allow,
        Some(acquired.manifest_identity),
        CompletionDisposition::Retain,
        &report,
    );
    finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Retain,
            effective_disposition: CompletionDisposition::Retain,
            sealed_stage: Some(&sealed),
            now_unix_millis: 10,
        },
    )
    .unwrap();
    drop(lease);
    let destination_parent = fixture.temporary.path().join("copies");
    fs::create_dir(&destination_parent).unwrap();
    fs::set_permissions(&destination_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = destination_parent.join("published");
    handoff_stage(
        &fixture.store,
        &run_id,
        &destination,
        HandoffMode::Copy,
        &fixture.cancellation,
    )
    .unwrap();
    assert_eq!(
        fs::read(destination.join("nested/value")).unwrap(),
        b"nested\n"
    );
    assert!(!fixture
        .store
        .paths()
        .jobs_root
        .join(run_id.as_str())
        .join("stage")
        .exists());
    assert!(fs::read_dir(&destination_parent)
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
}

#[test]
fn destination_must_be_absent_and_parent_must_be_owner_controlled() {
    let fixture = Fixture::new();
    let run_id = run("destination");
    let (mut lease, acquired) = fixture.create_acquired(&run_id);
    advance_to_sealing(&mut lease);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    let report = allow_report(&run_id, acquired.manifest_identity);
    let decision = decision(
        &run_id,
        Outcome::Allow,
        Some(acquired.manifest_identity),
        CompletionDisposition::Retain,
        &report,
    );
    finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Retain,
            effective_disposition: CompletionDisposition::Retain,
            sealed_stage: Some(&sealed),
            now_unix_millis: 10,
        },
    )
    .unwrap();
    drop(lease);

    assert!(matches!(
        handoff_stage(
            &fixture.store,
            &run_id,
            &PathBuf::from("relative-target"),
            HandoffMode::Move,
            &fixture.cancellation,
        ),
        Err(CompletionError::DestinationNotAbsolute)
    ));

    let parent = fixture.temporary.path().join("unsafe-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        handoff_stage(
            &fixture.store,
            &run_id,
            &parent.join("target"),
            HandoffMode::Move,
            &fixture.cancellation,
        ),
        Err(CompletionError::UntrustedDestinationParent)
    ));
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(parent.join("target")).unwrap();
    assert!(matches!(
        handoff_stage(
            &fixture.store,
            &run_id,
            &parent.join("target"),
            HandoffMode::Move,
            &fixture.cancellation,
        ),
        Err(CompletionError::DestinationExists)
    ));
}

#[test]
fn explicit_discard_removes_only_the_retained_stage_and_keeps_the_report() {
    let fixture = Fixture::new();
    let run_id = run("discard-later");
    let (mut lease, acquired) = fixture.create_acquired(&run_id);
    advance_to_sealing(&mut lease);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    let report = allow_report(&run_id, acquired.manifest_identity);
    let decision = decision(
        &run_id,
        Outcome::Allow,
        Some(acquired.manifest_identity),
        CompletionDisposition::Retain,
        &report,
    );
    finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Retain,
            effective_disposition: CompletionDisposition::Retain,
            sealed_stage: Some(&sealed),
            now_unix_millis: 10,
        },
    )
    .unwrap();
    drop(lease);
    discard_retained_stage(&fixture.store, &run_id).unwrap();
    let status = inspect_job(&fixture.store, &run_id).unwrap();
    assert_eq!(status.disposition, Disposition::Discarded);
    assert_eq!(status.handoff, HandoffStatus::Unavailable);
    let terminal = fixture
        .store
        .try_acquire(&run_id)
        .unwrap()
        .state()
        .terminal
        .unwrap();
    assert_eq!(terminal.disposition, Disposition::Discarded);
    assert_eq!(terminal.handoff, HandoffStatus::Unavailable);
    assert!(fixture
        .store
        .paths()
        .reports_root
        .join(format!("{}.json", run_id.as_str()))
        .exists());
}

#[test]
fn recovery_garbage_collects_a_discard_tombstone_after_eligibility_was_revoked() {
    let fixture = Fixture::new();
    let run_id = run("discard-crash");
    let (mut lease, acquired) = fixture.create_acquired(&run_id);
    advance_to_sealing(&mut lease);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    let report = allow_report(&run_id, acquired.manifest_identity);
    let decision = decision(
        &run_id,
        Outcome::Allow,
        Some(acquired.manifest_identity),
        CompletionDisposition::Retain,
        &report,
    );
    finalize_job(
        &fixture.store,
        &mut lease,
        FinalizeRequest {
            decision: &decision,
            report: &report,
            configured_disposition: CompletionDisposition::Retain,
            effective_disposition: CompletionDisposition::Retain,
            sealed_stage: Some(&sealed),
            now_unix_millis: 10,
        },
    )
    .unwrap();
    lease
        .advance_terminal_stage(Disposition::Discarded, HandoffStatus::Unavailable, 11)
        .unwrap();
    let stage = lease.paths().stage();
    assert!(stage.exists());
    drop(lease);

    let recovered = recover_job_with_report(&fixture.store, &run_id, &report, 12).unwrap();
    assert_eq!(recovered.disposition, Disposition::Discarded);
    assert!(!stage.exists());
}

#[test]
fn report_and_decision_mismatch_is_rejected_before_any_disposition() {
    let fixture = Fixture::new();
    let run_id = run("mismatch");
    let (mut lease, _) = fixture.create_acquired(&run_id);
    let report = deny_report();
    let decision = decision(
        &run_id,
        Outcome::Error,
        None,
        CompletionDisposition::Discard,
        &report,
    );
    assert!(matches!(
        finalize_job(
            &fixture.store,
            &mut lease,
            FinalizeRequest {
                decision: &decision,
                report: &report,
                configured_disposition: CompletionDisposition::Discard,
                effective_disposition: CompletionDisposition::Discard,
                sealed_stage: None,
                now_unix_millis: 10,
            },
        ),
        Err(CompletionError::DecisionMismatch)
    ));
    assert!(lease.paths().stage().exists());
    assert!(!fixture
        .store
        .paths()
        .reports_root
        .join("run_mismatch.json")
        .exists());
}

#[test]
fn decision_report_identity_rejects_a_different_valid_report() {
    let fixture = Fixture::new();
    let run_id = run("report-binding");
    let (mut lease, acquired) = fixture.create_acquired(&run_id);
    advance_to_sealing(&mut lease);
    let sealed = revalidate_and_seal(
        &lease.paths().stage(),
        &acquired.entries,
        acquired.manifest_identity,
        &fixture.cancellation,
    )
    .unwrap();
    let bound = allow_report(&run_id, acquired.manifest_identity);
    let different = allow_report_with_request(
        &run_id,
        acquired.manifest_identity,
        Some(SafeId::new("request-different").unwrap()),
    );
    let decision = decision(
        &run_id,
        Outcome::Allow,
        Some(acquired.manifest_identity),
        CompletionDisposition::Retain,
        &bound,
    );
    assert!(matches!(
        finalize_job(
            &fixture.store,
            &mut lease,
            FinalizeRequest {
                decision: &decision,
                report: &different,
                configured_disposition: CompletionDisposition::Retain,
                effective_disposition: CompletionDisposition::Retain,
                sealed_stage: Some(&sealed),
                now_unix_millis: 10,
            },
        ),
        Err(CompletionError::DecisionMismatch)
    ));
    assert_eq!(lease.state().execution, JobExecutionState::Sealing);
    assert!(!fixture
        .store
        .paths()
        .reports_root
        .join(format!("{}.json", run_id.as_str()))
        .exists());
}

#[test]
fn report_handoff_contract_remains_available_only_for_retained_allow() {
    let report = allow_report(&run("contract"), Digest::sha256(b"contract manifest"));
    let stage = report.stage.unwrap();
    assert_eq!(stage.handoff_status, ReportHandoffStatus::Available);
    assert_eq!(stage.reference.unwrap().as_str(), "run_contract");
}
