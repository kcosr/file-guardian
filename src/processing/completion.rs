//! Descriptor-anchored stage completion, disposition, and trusted handoff.

use crate::domain::{Digest, LogicalPath, PathSegment, RunId};
use crate::processing::acquisition::local::{
    AcquiredEntry, AcquiredEntryKind, AcquisitionCancellation,
};
use crate::processing::domain::{
    Disposition, HandoffStatus, JobExecutionState, Outcome, TerminalJobState,
};
use crate::processing::job::{
    DecisionDisposition, JobLease, JobLocation, JobStore, JobStoreError, LeaseIdentity,
    PrivateDecisionRecord,
};
use crate::processing::report::{
    ConfiguredDisposition as ReportConfiguredDisposition, EffectiveDisposition, PersistenceStatus,
    ProcessingOutcome, ProcessingReport,
};
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags};
use rustix::process::geteuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const CREATE_FILE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 256;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDisposition {
    Retain,
    Discard,
    Quarantine,
}

impl From<CompletionDisposition> for DecisionDisposition {
    fn from(value: CompletionDisposition) -> Self {
        match value {
            CompletionDisposition::Retain => Self::Retain,
            CompletionDisposition::Discard => Self::Discard,
            CompletionDisposition::Quarantine => Self::Quarantine,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffMode {
    Move,
    Copy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedStage {
    manifest_identity: Digest,
    entries: Vec<AcquiredEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedStageRecord {
    schema_version: String,
    run_id: RunId,
    manifest_identity: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HandoffIntent {
    schema_version: String,
    run_id: RunId,
    mode: HandoffMode,
    manifest_identity: Digest,
    destination_identity: Digest,
    temporary_name: String,
}

impl SealedStage {
    pub fn manifest_identity(&self) -> Digest {
        self.manifest_identity
    }

    pub fn entries(&self) -> &[AcquiredEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionStatus {
    pub run_id: RunId,
    pub outcome: Outcome,
    pub disposition: Disposition,
    pub handoff: HandoffStatus,
    pub sealed: bool,
    pub final_manifest_identity: Option<Digest>,
    pub report_published: bool,
}

impl CompletionStatus {
    pub fn stage_available(&self) -> bool {
        self.disposition == Disposition::Retained
            && self.handoff == HandoffStatus::Available
            && self.outcome.is_allowed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffReceipt {
    pub run_id: RunId,
    pub mode: HandoffMode,
    pub manifest_identity: Digest,
    pub destination_identity: Digest,
}

pub struct FinalizeRequest<'a> {
    pub decision: &'a PrivateDecisionRecord,
    pub report: &'a ProcessingReport,
    pub configured_disposition: CompletionDisposition,
    pub effective_disposition: CompletionDisposition,
    pub sealed_stage: Option<&'a SealedStage>,
    pub now_unix_millis: i64,
}

/// Recaptures the complete stage through held directory descriptors, compares
/// publication semantics, applies write-blocking modes, and recaptures again.
pub fn revalidate_and_seal(
    stage_path: &Path,
    expected_entries: &[AcquiredEntry],
    expected_manifest_identity: Digest,
    cancellation: &AcquisitionCancellation,
) -> Result<SealedStage, CompletionError> {
    check_cancelled(cancellation)?;
    if stage_path.file_name() != Some(OsStr::new("stage")) {
        return Err(CompletionError::UnsafePath);
    }
    let job_root = stage_path
        .parent()
        .ok_or(CompletionError::UnsafePath)?
        .to_owned();
    let run_id = job_root
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(CompletionError::UnsafePath)
        .and_then(|value| RunId::new(value).map_err(|_| CompletionError::UnsafePath))?;
    let stage = open_private_stage(stage_path)?;
    let before = capture_entries(&stage, cancellation)?;
    require_manifest(&before, expected_entries, expected_manifest_identity)?;
    seal_directory(&stage, cancellation, 0)?;
    fs::fchmod(&stage, Mode::from_raw_mode(0o500))
        .map_err(|error| io_error("seal stage root", error))?;
    fs::fsync(&stage).map_err(|error| io_error("sync sealed stage root", error))?;
    let after = capture_entries(&stage, cancellation)?;
    require_manifest(&after, expected_entries, expected_manifest_identity)?;
    let sealed = SealedStage {
        manifest_identity: expected_manifest_identity,
        entries: expected_entries.to_vec(),
    };
    write_sealed_record(&job_root, &run_id, sealed.manifest_identity())?;
    Ok(sealed)
}

/// Loads the durable sealed identity and descriptor-recaptures the current
/// stage. Mode bits alone are never accepted as evidence of a seal.
pub fn load_sealed_stage(
    store: &JobStore,
    run_id: &RunId,
    cancellation: &AcquisitionCancellation,
) -> Result<SealedStage, CompletionError> {
    let job_root = store.paths().jobs_root.join(run_id.as_str());
    load_sealed_stage_at(&job_root, run_id, cancellation)
}

/// Executes the private-decision -> disposition -> immutable-report ->
/// terminal-state protocol. On disposition failure, no public report is
/// created and the job remains private in `disposing` for recovery.
pub fn finalize_job(
    store: &JobStore,
    lease: &mut JobLease,
    request: FinalizeRequest<'_>,
) -> Result<CompletionStatus, CompletionError> {
    validate_finalize_request(lease, &request)?;
    if let Some(sealed) = request.sealed_stage {
        let stage = open_private_stage(&lease.paths().stage())?;
        let observed = capture_entries(&stage, &AcquisitionCancellation::default())?;
        require_manifest(&observed, sealed.entries(), sealed.manifest_identity())?;
    }
    lease.write_decision(request.decision)?;
    lease.enter_preparing_decision(request.now_unix_millis)?;
    lease.transition(JobExecutionState::Disposing, request.now_unix_millis)?;

    let outcome = request.decision.proposed_outcome;
    let disposition_result: Result<(Disposition, HandoffStatus), CompletionError> =
        (|| match request.effective_disposition {
            CompletionDisposition::Retain => Ok((
                Disposition::Retained,
                if outcome.is_allowed() {
                    HandoffStatus::Available
                } else {
                    HandoffStatus::Unavailable
                },
            )),
            CompletionDisposition::Discard => {
                discard_stage_path(lease.paths().root(), &lease.paths().stage())?;
                Ok((Disposition::Discarded, HandoffStatus::Unavailable))
            }
            CompletionDisposition::Quarantine => {
                quarantine_job(store, lease.run_id())?;
                Ok((Disposition::Quarantined, HandoffStatus::Unavailable))
            }
        })();
    let (disposition, handoff) = match disposition_result {
        Ok(value) => value,
        Err(_) => {
            let _ = write_status(
                lease.paths().root(),
                &CompletionStatus {
                    run_id: lease.run_id().clone(),
                    outcome: Outcome::Error,
                    disposition: Disposition::RetainedError,
                    handoff: HandoffStatus::Unavailable,
                    sealed: false,
                    final_manifest_identity: request.decision.final_manifest_identity,
                    report_published: false,
                },
            );
            return Err(CompletionError::DispositionFailedRetainedError);
        }
    };

    let status_root = if disposition == Disposition::Quarantined {
        store.paths().quarantine_root.join(lease.run_id().as_str())
    } else {
        lease.paths().root().to_owned()
    };
    write_status(
        &status_root,
        &CompletionStatus {
            run_id: lease.run_id().clone(),
            outcome,
            disposition,
            handoff,
            sealed: request.sealed_stage.is_some(),
            final_manifest_identity: request
                .sealed_stage
                .map(SealedStage::manifest_identity)
                .or(request.decision.final_manifest_identity),
            report_published: false,
        },
    )?;

    lease.transition(JobExecutionState::PublishingReport, request.now_unix_millis)?;
    store.publish_report_once(lease.run_id(), request.report)?;
    let terminal = TerminalJobState::new(outcome, disposition, handoff)
        .map_err(|_| CompletionError::InvalidTerminal)?;
    lease.finish_terminal(terminal, request.now_unix_millis)?;
    let status = CompletionStatus {
        run_id: lease.run_id().clone(),
        outcome,
        disposition,
        handoff,
        sealed: request.sealed_stage.is_some(),
        final_manifest_identity: request
            .sealed_stage
            .map(SealedStage::manifest_identity)
            .or(request.decision.final_manifest_identity),
        report_published: true,
    };
    write_status(&status_root, &status)?;
    Ok(status)
}

pub fn inspect_job(store: &JobStore, run_id: &RunId) -> Result<CompletionStatus, CompletionError> {
    for root in [&store.paths().jobs_root, &store.paths().quarantine_root] {
        let job_root = root.join(run_id.as_str());
        match read_status(&job_root, run_id) {
            Ok(status) => return Ok(status),
            Err(CompletionError::StatusUnavailable) => {}
            Err(error) => return Err(error),
        }
    }
    Err(CompletionError::StatusUnavailable)
}

/// Revalidates a retained sealed stage immediately before handing it to an
/// owner-only destination parent. Move never falls back to copy.
pub fn handoff_stage(
    store: &JobStore,
    run_id: &RunId,
    destination: &Path,
    mode: HandoffMode,
    cancellation: &AcquisitionCancellation,
) -> Result<HandoffReceipt, CompletionError> {
    let mut lease = store.try_acquire(run_id)?;
    let status = inspect_job(store, run_id)?;
    let sealed_record = read_sealed_record(lease.paths().root(), run_id)?;
    if status.final_manifest_identity != Some(sealed_record.manifest_identity) {
        return Err(CompletionError::HandoffUnavailable);
    }
    let lifecycle_now = current_unix_millis()?;
    let (parent, destination_name) = open_destination_parent(destination)?;
    let destination_identity = destination_identity(&parent, &destination_name, mode)?;
    let mut prevalidated_stage = None;
    let existing_intent: Option<HandoffIntent> =
        read_optional_private_json(lease.paths().root(), "handoff-intent.json")?;
    let intent = if let Some(intent) = existing_intent {
        if intent.schema_version != "file-guardian-handoff-intent/1"
            || &intent.run_id != run_id
            || intent.mode != mode
            || intent.manifest_identity != sealed_record.manifest_identity
            || intent.destination_identity != destination_identity
        {
            return Err(CompletionError::HandoffIntentMismatch);
        }
        intent
    } else {
        if !status.stage_available()
            || lease.state().terminal
                != TerminalJobState::new(
                    status.outcome,
                    Disposition::Retained,
                    HandoffStatus::Available,
                )
                .ok()
        {
            return Err(CompletionError::HandoffUnavailable);
        }
        require_destination_absent(&parent, &destination_name)?;
        let expected = load_sealed_stage_at(lease.paths().root(), run_id, cancellation)?;
        if mode == HandoffMode::Move {
            let stage = open_private_stage(&lease.paths().stage())?;
            let stage_stat = fs::fstat(&stage).map_err(|error| io_error("inspect stage", error))?;
            let parent_stat =
                fs::fstat(&parent).map_err(|error| io_error("inspect destination", error))?;
            if stage_stat.st_dev != parent_stat.st_dev {
                return Err(CompletionError::CrossFilesystemMove);
            }
        }
        prevalidated_stage = Some(expected);
        let temporary_name = temporary_destination_name(run_id)?
            .into_string()
            .map_err(|_| CompletionError::UnsafePath)?;
        if mode == HandoffMode::Copy {
            let temporary =
                CString::new(temporary_name.as_bytes()).map_err(|_| CompletionError::UnsafePath)?;
            require_destination_absent(&parent, temporary.as_c_str())?;
        }
        let intent = HandoffIntent {
            schema_version: "file-guardian-handoff-intent/1".to_owned(),
            run_id: run_id.clone(),
            mode,
            manifest_identity: sealed_record.manifest_identity,
            destination_identity,
            temporary_name,
        };
        create_private_json_once(lease.paths().root(), "handoff-intent.json", &intent)?;
        intent
    };

    let stage_path = lease.paths().stage();
    if destination_is_present(&parent, &destination_name)? {
        let published = fs::openat(
            &parent,
            destination_name.as_c_str(),
            DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(|error| io_error("open adopted handoff destination", error))?;
        let published_stat = fs::fstat(&published)
            .map_err(|error| io_error("inspect adopted handoff destination", error))?;
        if published_stat.st_uid != geteuid().as_raw() || published_stat.st_mode & 0o7777 != 0o755 {
            return Err(CompletionError::HandoffDestinationMismatch);
        }
        let entries = capture_entries(&published, cancellation)?;
        if manifest_identity(&entries)? != intent.manifest_identity {
            return Err(CompletionError::HandoffDestinationMismatch);
        }
    } else {
        if !status.stage_available() {
            return Err(CompletionError::HandoffUnavailable);
        }
        let expected = match prevalidated_stage {
            Some(expected) => expected,
            None => load_sealed_stage_at(lease.paths().root(), run_id, cancellation)?,
        };
        let stage = open_private_stage(&stage_path)?;
        let observed = capture_entries(&stage, cancellation)?;
        require_manifest(&observed, expected.entries(), expected.manifest_identity())?;
        match mode {
            HandoffMode::Move => move_handoff(
                lease.paths().root(),
                &stage,
                &parent,
                &destination_name,
                &expected,
                cancellation,
            )?,
            HandoffMode::Copy => copy_handoff(
                &stage,
                &parent,
                &destination_name,
                &intent,
                &expected,
                cancellation,
            )?,
        }
    }

    let completed = CompletionStatus {
        handoff: HandoffStatus::HandedOff,
        ..status
    };
    if lease.state().terminal.is_some_and(|terminal| {
        terminal.disposition == Disposition::Retained
            && terminal.handoff == HandoffStatus::Available
    }) {
        lease.advance_terminal_stage(
            Disposition::Retained,
            HandoffStatus::HandedOff,
            lifecycle_now,
        )?;
    }
    write_status(lease.paths().root(), &completed)?;
    if mode == HandoffMode::Copy {
        // The destination is already atomically committed and the handed-off
        // status is durable. Source cleanup is tombstone garbage collection;
        // failure cannot make a retry publish a second copy.
        let _ = discard_stage_path(lease.paths().root(), &stage_path);
    }
    Ok(HandoffReceipt {
        run_id: run_id.clone(),
        mode,
        manifest_identity: intent.manifest_identity,
        destination_identity,
    })
}

pub fn discard_retained_stage(store: &JobStore, run_id: &RunId) -> Result<(), CompletionError> {
    let mut lease = store.try_acquire(run_id)?;
    let status = inspect_job(store, run_id)?;
    let terminal_matches = lease.state().terminal.is_some_and(|terminal| {
        terminal.outcome == status.outcome
            && terminal.disposition == Disposition::Retained
            && terminal.handoff == status.handoff
    });
    if status.disposition != Disposition::Retained
        || status.handoff == HandoffStatus::HandedOff
        || !terminal_matches
    {
        return Err(CompletionError::HandoffUnavailable);
    }
    let lifecycle_now = current_unix_millis()?;
    // Revoke eligibility in canonical state before deleting. A crash can
    // leave only a private tombstone for recovery/GC; it can never re-expose
    // the stage for handoff.
    lease.advance_terminal_stage(
        Disposition::Discarded,
        HandoffStatus::Unavailable,
        lifecycle_now,
    )?;
    discard_stage_path(lease.paths().root(), &lease.paths().stage())?;
    write_status(
        lease.paths().root(),
        &CompletionStatus {
            disposition: Disposition::Discarded,
            handoff: HandoffStatus::Unavailable,
            ..status
        },
    )
}

/// Removes the private tombstone for a terminal job after its configured
/// retention interval. Public reports remain in the independent report root.
/// Available stages must first be revoked with `discard_retained_stage`.
pub fn purge_terminal_job(store: &JobStore, run_id: &RunId) -> Result<(), CompletionError> {
    let lease = match store.try_acquire(run_id) {
        Ok(lease) => lease,
        Err(JobStoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            store.try_acquire_quarantined(run_id)?
        }
        Err(error) => return Err(error.into()),
    };
    let status = inspect_job(store, run_id)?;
    let terminal = lease
        .state()
        .terminal
        .ok_or(CompletionError::InvalidTerminal)?;
    if lease.state().execution != JobExecutionState::Terminal
        || !status.report_published
        || terminal.outcome != status.outcome
        || terminal.disposition != status.disposition
        || terminal.handoff != status.handoff
        || status.stage_available()
    {
        return Err(CompletionError::InvalidTerminal);
    }
    let (root_path, operation) = match lease.location() {
        JobLocation::Active => (&store.paths().jobs_root, "purge terminal job"),
        JobLocation::Quarantined => (&store.paths().quarantine_root, "purge terminal quarantine"),
    };
    let root = fs::open(root_path, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error(operation, error))?;
    let name = CString::new(run_id.as_str()).map_err(|_| CompletionError::UnsafePath)?;
    remove_named_tree(&root, name.as_c_str())?;
    fs::fsync(&root).map_err(|error| io_error(operation, error))
}

/// Resumes a stale pre-terminal job from its durable decision. The caller
/// supplies the reconstructed final report; an already published byte-identical
/// report is accepted, while any mismatch fails closed.
pub fn recover_job_with_report(
    store: &JobStore,
    run_id: &RunId,
    report: &ProcessingReport,
    now_unix_millis: i64,
) -> Result<CompletionStatus, CompletionError> {
    let lease = match store.try_acquire(run_id) {
        Ok(lease) => lease,
        Err(JobStoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            store.try_acquire_quarantined(run_id)?
        }
        Err(error) => return Err(error.into()),
    };
    recover_lease_with_report(store, lease, report, now_unix_millis)
}

fn recover_lease_with_report(
    store: &JobStore,
    mut lease: JobLease,
    report: &ProcessingReport,
    now_unix_millis: i64,
) -> Result<CompletionStatus, CompletionError> {
    let run_id = lease.run_id().clone();
    let decision = lease.read_decision()?;
    if report_identity(report)? != decision.public_report_identity
        || report.run_id.as_str() != run_id.as_str()
        || (report_outcome(report.outcome) != decision.proposed_outcome
            && !(decision.proposed_outcome == Outcome::Cancelled
                && report.outcome == ProcessingOutcome::Error))
        || report.persistence.status != PersistenceStatus::Durable
    {
        return Err(CompletionError::DecisionMismatch);
    }
    validate_report_disposition_intent(&decision, report)?;

    if lease.state().execution == JobExecutionState::Terminal {
        let terminal = lease
            .state()
            .terminal
            .ok_or(CompletionError::InvalidTerminal)?;
        let mut status = inspect_job(store, &run_id)?;
        if terminal.outcome != status.outcome {
            return Err(CompletionError::DecisionMismatch);
        }
        if (terminal.disposition, terminal.handoff) != (status.disposition, status.handoff) {
            let recoverable_lifecycle_write = status.disposition == Disposition::Retained
                && matches!(
                    (status.handoff, terminal.disposition, terminal.handoff),
                    (
                        HandoffStatus::Available,
                        Disposition::Retained,
                        HandoffStatus::HandedOff
                    ) | (
                        HandoffStatus::Available | HandoffStatus::Unavailable,
                        Disposition::Discarded,
                        HandoffStatus::Unavailable
                    )
                );
            if !recoverable_lifecycle_write {
                return Err(CompletionError::DecisionMismatch);
            }
            status.disposition = terminal.disposition;
            status.handoff = terminal.handoff;
        }
        if terminal.disposition == Disposition::Discarded
            || terminal.handoff == HandoffStatus::HandedOff
        {
            match std::fs::symlink_metadata(lease.paths().stage()) {
                Ok(_) => discard_stage_path(lease.paths().root(), &lease.paths().stage())?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(CompletionError::Io {
                        operation: "inspect terminal stage tombstone",
                        source,
                    })
                }
            }
        }
        publish_report_idempotently(store, &run_id, report)?;
        status.report_published = true;
        let status_root = if lease.location() == JobLocation::Quarantined {
            lease.paths().root().to_owned()
        } else {
            store.paths().jobs_root.join(run_id.as_str())
        };
        write_status(&status_root, &status)?;
        return Ok(status);
    }

    if lease.state().execution == JobExecutionState::PreparingDecision {
        lease.transition(JobExecutionState::Disposing, now_unix_millis)?;
    }
    if lease.state().execution == JobExecutionState::Disposing {
        let existing = inspect_job(store, &run_id).ok();
        let status = if let Some(status) = existing {
            status
        } else {
            let (disposition, handoff, status_root) = match decision.dispositions.effective() {
                DecisionDisposition::Retain => {
                    if decision.proposed_outcome.is_allowed() {
                        let sealed = load_sealed_stage_at(
                            lease.paths().root(),
                            &run_id,
                            &AcquisitionCancellation::default(),
                        )?;
                        if decision.final_manifest_identity != Some(sealed.manifest_identity()) {
                            return Err(CompletionError::DecisionMismatch);
                        }
                    }
                    (
                        Disposition::Retained,
                        if decision.proposed_outcome.is_allowed() {
                            HandoffStatus::Available
                        } else {
                            HandoffStatus::Unavailable
                        },
                        lease.paths().root().to_owned(),
                    )
                }
                DecisionDisposition::Discard => {
                    match std::fs::symlink_metadata(lease.paths().stage()) {
                        Ok(_) => discard_stage_path(lease.paths().root(), &lease.paths().stage())?,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(source) => {
                            return Err(CompletionError::Io {
                                operation: "inspect stage during recovery",
                                source,
                            })
                        }
                    }
                    (
                        Disposition::Discarded,
                        HandoffStatus::Unavailable,
                        lease.paths().root().to_owned(),
                    )
                }
                DecisionDisposition::Quarantine => {
                    if lease.location() == JobLocation::Active {
                        quarantine_job(store, &run_id)?;
                    }
                    (
                        Disposition::Quarantined,
                        HandoffStatus::Unavailable,
                        if lease.location() == JobLocation::Quarantined {
                            lease.paths().root().to_owned()
                        } else {
                            store.paths().quarantine_root.join(run_id.as_str())
                        },
                    )
                }
            };
            let status = CompletionStatus {
                run_id: run_id.clone(),
                outcome: decision.proposed_outcome,
                disposition,
                handoff,
                sealed: decision.proposed_outcome.is_allowed(),
                final_manifest_identity: decision.final_manifest_identity,
                report_published: false,
            };
            write_status(&status_root, &status)?;
            status
        };
        let _ = status;
        lease.transition(JobExecutionState::PublishingReport, now_unix_millis)?;
    }
    if lease.state().execution != JobExecutionState::PublishingReport {
        return Err(CompletionError::RecoveryStateUnsupported);
    }

    let mut status = inspect_job(store, &run_id)?;
    publish_report_idempotently(store, &run_id, report)?;
    let terminal = TerminalJobState::new(status.outcome, status.disposition, status.handoff)
        .map_err(|_| CompletionError::InvalidTerminal)?;
    lease.finish_terminal(terminal, now_unix_millis)?;
    status.report_published = true;
    let status_root = if status.disposition == Disposition::Quarantined {
        store.paths().quarantine_root.join(run_id.as_str())
    } else {
        lease.paths().root().to_owned()
    };
    write_status(&status_root, &status)?;
    Ok(status)
}

/// Reconstructs the exact report body bound by the durable private decision
/// and resumes completion without accepting caller-selected report content.
pub fn recover_job(
    store: &JobStore,
    run_id: &RunId,
    now_unix_millis: i64,
    stale_after_millis: u64,
    recovery_lease: LeaseIdentity,
) -> Result<CompletionStatus, CompletionError> {
    let mut lease = match store.try_acquire_stale(run_id, now_unix_millis, stale_after_millis) {
        Ok(Some(lease)) => lease,
        Ok(None) => return Err(CompletionError::JobNotStale),
        Err(JobStoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => store
            .try_acquire_quarantined_stale(run_id, now_unix_millis, stale_after_millis)?
            .ok_or(CompletionError::JobNotStale)?,
        Err(error) => return Err(error.into()),
    };
    lease.claim_lease(recovery_lease, now_unix_millis)?;
    let decision = lease.read_decision()?;
    let report: ProcessingReport = serde_json::from_value(decision.draft_report_body.clone())
        .map_err(CompletionError::Serialize)?;
    if report_identity(&report)? != decision.public_report_identity {
        return Err(CompletionError::DecisionMismatch);
    }
    recover_lease_with_report(store, lease, &report, now_unix_millis)
}

fn publish_report_idempotently(
    store: &JobStore,
    run_id: &RunId,
    report: &ProcessingReport,
) -> Result<(), CompletionError> {
    let expected = report
        .to_json_line()
        .map_err(|error| CompletionError::Report(Box::new(error)))?;
    let path = store
        .paths()
        .reports_root
        .join(format!("{}.json", run_id.as_str()));
    match read_existing_report(&path)? {
        Some(existing) if existing == expected => Ok(()),
        Some(_) => Err(CompletionError::PublishedReportMismatch),
        None => {
            store.publish_report_once(run_id, report)?;
            Ok(())
        }
    }
}

fn read_existing_report(path: &Path) -> Result<Option<Vec<u8>>, CompletionError> {
    let parent = path.parent().ok_or(CompletionError::UnsafePath)?;
    let name = path.file_name().ok_or(CompletionError::UnsafePath)?;
    let directory = fs::open(parent, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open reports root", error))?;
    let fd = match fs::openat(&directory, name, FILE_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io_error("open published report", error)),
    };
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect published report", error))?;
    if stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > 64 * 1024 * 1024
    {
        return Err(CompletionError::UnsafePath);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(stat.st_size).unwrap_or(0));
    File::from(fd)
        .read_to_end(&mut bytes)
        .map_err(|source| CompletionError::Io {
            operation: "read published report",
            source,
        })?;
    Ok(Some(bytes))
}

fn validate_finalize_request(
    lease: &JobLease,
    request: &FinalizeRequest<'_>,
) -> Result<(), CompletionError> {
    let draft_report: ProcessingReport =
        serde_json::from_value(request.decision.draft_report_body.clone())
            .map_err(|_| CompletionError::DecisionMismatch)?;
    let public_outcome = report_outcome(request.report.outcome);
    if report_identity(request.report)? != request.decision.public_report_identity
        || report_identity(&draft_report)? != request.decision.public_report_identity
        || &request.decision.run_id != lease.run_id()
        || request.report.run_id.as_str() != lease.run_id().as_str()
        || (public_outcome != request.decision.proposed_outcome
            && !(request.decision.proposed_outcome == Outcome::Cancelled
                && public_outcome == Outcome::Error))
        || request.decision.dispositions.configured()
            != DecisionDisposition::from(request.configured_disposition)
        || request.decision.dispositions.effective()
            != DecisionDisposition::from(request.effective_disposition)
        || request.report.persistence.status != PersistenceStatus::Durable
    {
        return Err(CompletionError::DecisionMismatch);
    }
    if request.decision.proposed_outcome.is_allowed() {
        if let Some(stage) = request.report.stage.as_ref() {
            let sealed = request
                .sealed_stage
                .ok_or(CompletionError::AllowedStageUnsealed)?;
            if request.decision.final_manifest_identity != Some(sealed.manifest_identity()) {
                return Err(CompletionError::DecisionMismatch);
            }
            let report_identity = stage
                .final_manifest_identity
                .as_ref()
                .map(|identity| identity.as_str());
            let sealed_identity = sealed.manifest_identity().to_string();
            if report_identity != Some(sealed_identity.as_str()) {
                return Err(CompletionError::DecisionMismatch);
            }
        } else if request.sealed_stage.is_some()
            || request.decision.final_manifest_identity.is_some()
        {
            return Err(CompletionError::DecisionMismatch);
        }
    }
    let stage = request.report.stage.as_ref();
    if request.configured_disposition != request.effective_disposition && stage.is_none() {
        return Err(CompletionError::ReportDispositionMismatch);
    }
    let expected_configured = match request.configured_disposition {
        CompletionDisposition::Retain => ReportConfiguredDisposition::Retain,
        CompletionDisposition::Discard => ReportConfiguredDisposition::Discard,
        CompletionDisposition::Quarantine => ReportConfiguredDisposition::Quarantine,
    };
    if stage.is_some_and(|stage| stage.configured_disposition != expected_configured) {
        return Err(CompletionError::ReportDispositionMismatch);
    }
    let expected_effective = match request.effective_disposition {
        CompletionDisposition::Retain => EffectiveDisposition::Retained,
        CompletionDisposition::Discard => EffectiveDisposition::Discarded,
        CompletionDisposition::Quarantine => EffectiveDisposition::Quarantined,
    };
    if stage.is_some_and(|stage| stage.effective_disposition != expected_effective) {
        return Err(CompletionError::ReportDispositionMismatch);
    }
    Ok(())
}

fn validate_report_disposition_intent(
    decision: &PrivateDecisionRecord,
    report: &ProcessingReport,
) -> Result<(), CompletionError> {
    let stage = report.stage.as_ref();
    if decision.dispositions.configured() != decision.dispositions.effective() && stage.is_none() {
        return Err(CompletionError::ReportDispositionMismatch);
    }
    if let Some(stage) = stage {
        let configured = match decision.dispositions.configured() {
            DecisionDisposition::Retain => ReportConfiguredDisposition::Retain,
            DecisionDisposition::Discard => ReportConfiguredDisposition::Discard,
            DecisionDisposition::Quarantine => ReportConfiguredDisposition::Quarantine,
        };
        let effective = match decision.dispositions.effective() {
            DecisionDisposition::Retain => EffectiveDisposition::Retained,
            DecisionDisposition::Discard => EffectiveDisposition::Discarded,
            DecisionDisposition::Quarantine => EffectiveDisposition::Quarantined,
        };
        if stage.configured_disposition != configured || stage.effective_disposition != effective {
            return Err(CompletionError::ReportDispositionMismatch);
        }
    }
    Ok(())
}

fn report_identity(report: &ProcessingReport) -> Result<Digest, CompletionError> {
    report
        .to_json_line()
        .map(Digest::sha256)
        .map_err(|error| CompletionError::Report(Box::new(error)))
}

fn report_outcome(outcome: ProcessingOutcome) -> Outcome {
    match outcome {
        ProcessingOutcome::Allow => Outcome::Allow,
        ProcessingOutcome::AllowModified => Outcome::AllowModified,
        ProcessingOutcome::Deny => Outcome::Deny,
        ProcessingOutcome::Error => Outcome::Error,
    }
}

fn open_private_stage(path: &Path) -> Result<OwnedFd, CompletionError> {
    let stage = fs::open(path, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open private stage", error))?;
    let stat = fs::fstat(&stage).map_err(|error| io_error("inspect private stage", error))?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(CompletionError::InsecureStage);
    }
    Ok(stage)
}

fn capture_entries(
    root: &OwnedFd,
    cancellation: &AcquisitionCancellation,
) -> Result<Vec<AcquiredEntry>, CompletionError> {
    let mut entries = Vec::new();
    collect_directory(root, &[], &mut entries, cancellation, 0)?;
    entries.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok(entries)
}

fn collect_directory(
    directory: &OwnedFd,
    parent: &[PathSegment],
    output: &mut Vec<AcquiredEntry>,
    cancellation: &AcquisitionCancellation,
    depth: usize,
) -> Result<(), CompletionError> {
    check_depth(depth)?;
    for entry in enumerate(directory)? {
        check_cancelled(cancellation)?;
        let mut logical = parent.to_vec();
        logical.push(entry.segment.clone());
        if entry.kind.is_dir() {
            output.push(AcquiredEntry {
                logical_path: logical_path(logical.clone())?,
                kind: AcquiredEntryKind::Directory,
                byte_len: 0,
                content_digest: Digest::sha256([]),
                publication_mode: 0o755,
            });
            let child = fs::openat(
                directory,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|error| io_error("open stage directory", error))?;
            collect_directory(&child, &logical, output, cancellation, depth + 1)?;
        } else if entry.kind.is_file() {
            let child = fs::openat(directory, entry.name.as_c_str(), FILE_FLAGS, Mode::empty())
                .map_err(|error| io_error("open stage file", error))?;
            let (byte_len, content_digest) = hash_file(File::from(child), cancellation)?;
            output.push(AcquiredEntry {
                logical_path: logical_path(logical)?,
                kind: AcquiredEntryKind::RegularFile,
                byte_len,
                content_digest,
                publication_mode: if entry.mode & 0o111 == 0 {
                    0o644
                } else {
                    0o755
                },
            });
        } else if entry.kind.is_symlink() {
            let target = fs::readlinkat(directory, entry.name.as_c_str(), Vec::new())
                .map_err(|error| io_error("read stage symbolic link", error))?;
            output.push(AcquiredEntry {
                logical_path: logical_path(logical)?,
                kind: AcquiredEntryKind::SymbolicLink,
                byte_len: u64::try_from(target.as_bytes().len())
                    .map_err(|_| CompletionError::StageMismatch)?,
                content_digest: Digest::sha256(target.as_bytes()),
                publication_mode: 0o777,
            });
        } else {
            return Err(CompletionError::SpecialFile);
        }
    }
    Ok(())
}

fn manifest_identity(entries: &[AcquiredEntry]) -> Result<Digest, CompletionError> {
    #[derive(Serialize)]
    struct Manifest<'a> {
        schema: &'static str,
        entries: &'a [AcquiredEntry],
    }
    serde_json::to_vec(&Manifest {
        schema: "file-guardian-publication-manifest/2",
        entries,
    })
    .map(Digest::sha256)
    .map_err(|_| CompletionError::StageMismatch)
}

fn require_manifest(
    observed: &[AcquiredEntry],
    expected: &[AcquiredEntry],
    identity: Digest,
) -> Result<(), CompletionError> {
    if observed != expected || manifest_identity(observed)? != identity {
        return Err(CompletionError::StageMismatch);
    }
    Ok(())
}

fn seal_directory(
    directory: &OwnedFd,
    cancellation: &AcquisitionCancellation,
    depth: usize,
) -> Result<(), CompletionError> {
    check_depth(depth)?;
    for entry in enumerate(directory)? {
        check_cancelled(cancellation)?;
        if entry.kind.is_dir() {
            let child = fs::openat(
                directory,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|error| io_error("open directory for sealing", error))?;
            seal_directory(&child, cancellation, depth + 1)?;
            fs::fchmod(&child, Mode::from_raw_mode(0o500))
                .map_err(|error| io_error("seal directory", error))?;
            fs::fsync(&child).map_err(|error| io_error("sync sealed directory", error))?;
        } else if entry.kind.is_file() {
            let child = fs::openat(directory, entry.name.as_c_str(), FILE_FLAGS, Mode::empty())
                .map_err(|error| io_error("open file for sealing", error))?;
            fs::fchmod(
                &child,
                Mode::from_raw_mode(if entry.mode & 0o111 == 0 {
                    0o400
                } else {
                    0o500
                }),
            )
            .map_err(|error| io_error("seal file", error))?;
            fs::fsync(&child).map_err(|error| io_error("sync sealed file", error))?;
        } else if !entry.kind.is_symlink() {
            return Err(CompletionError::SpecialFile);
        }
    }
    fs::fsync(directory).map_err(|error| io_error("sync sealed directory entries", error))
}

fn restore_publication_modes(
    directory: &OwnedFd,
    cancellation: &AcquisitionCancellation,
    depth: usize,
) -> Result<(), CompletionError> {
    check_depth(depth)?;
    for entry in enumerate(directory)? {
        check_cancelled(cancellation)?;
        if entry.kind.is_dir() {
            let child = fs::openat(
                directory,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|error| io_error("open handoff directory", error))?;
            restore_publication_modes(&child, cancellation, depth + 1)?;
            fs::fchmod(&child, Mode::from_raw_mode(0o755))
                .map_err(|error| io_error("restore directory mode", error))?;
        } else if entry.kind.is_file() {
            let child = fs::openat(directory, entry.name.as_c_str(), FILE_FLAGS, Mode::empty())
                .map_err(|error| io_error("open handoff file", error))?;
            fs::fchmod(
                &child,
                Mode::from_raw_mode(if entry.mode & 0o111 == 0 {
                    0o644
                } else {
                    0o755
                }),
            )
            .map_err(|error| io_error("restore file mode", error))?;
        } else if !entry.kind.is_symlink() {
            return Err(CompletionError::SpecialFile);
        }
    }
    Ok(())
}

fn copy_directory(
    source: &OwnedFd,
    destination: &OwnedFd,
    cancellation: &AcquisitionCancellation,
    depth: usize,
) -> Result<(), CompletionError> {
    check_depth(depth)?;
    for entry in enumerate(source)? {
        check_cancelled(cancellation)?;
        if entry.kind.is_dir() {
            fs::mkdirat(
                destination,
                entry.name.as_c_str(),
                Mode::from_raw_mode(0o700),
            )
            .map_err(|error| io_error("create copied directory", error))?;
            let source_child = fs::openat(
                source,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|error| io_error("open source directory", error))?;
            let destination_child = fs::openat(
                destination,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|error| io_error("open copied directory", error))?;
            copy_directory(&source_child, &destination_child, cancellation, depth + 1)?;
            fs::fchmod(&destination_child, Mode::from_raw_mode(0o755))
                .map_err(|error| io_error("set copied directory mode", error))?;
            fs::fsync(&destination_child)
                .map_err(|error| io_error("sync copied directory", error))?;
        } else if entry.kind.is_file() {
            let source_file = fs::openat(source, entry.name.as_c_str(), FILE_FLAGS, Mode::empty())
                .map_err(|error| io_error("open source file", error))?;
            let destination_file = fs::openat(
                destination,
                entry.name.as_c_str(),
                CREATE_FILE_FLAGS,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| io_error("create copied file", error))?;
            let mut source_file = File::from(source_file);
            let mut destination_file = File::from(destination_file);
            copy_bytes(&mut source_file, &mut destination_file, cancellation)?;
            destination_file
                .sync_all()
                .map_err(|source| CompletionError::Io {
                    operation: "sync copied file",
                    source,
                })?;
            fs::fchmod(
                &destination_file,
                Mode::from_raw_mode(if entry.mode & 0o111 == 0 {
                    0o644
                } else {
                    0o755
                }),
            )
            .map_err(|error| io_error("set copied file mode", error))?;
        } else if entry.kind.is_symlink() {
            let target = fs::readlinkat(source, entry.name.as_c_str(), Vec::new())
                .map_err(|error| io_error("read source symbolic link", error))?;
            fs::symlinkat(target.as_c_str(), destination, entry.name.as_c_str())
                .map_err(|error| io_error("create copied symbolic link", error))?;
        } else {
            return Err(CompletionError::SpecialFile);
        }
    }
    fs::fsync(destination).map_err(|error| io_error("sync copied tree", error))
}

fn copy_bytes(
    source: &mut File,
    destination: &mut File,
    cancellation: &AcquisitionCancellation,
) -> Result<(), CompletionError> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        check_cancelled(cancellation)?;
        let read = source
            .read(&mut buffer)
            .map_err(|source| CompletionError::Io {
                operation: "read copied file",
                source,
            })?;
        if read == 0 {
            return Ok(());
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|source| CompletionError::Io {
                operation: "write copied file",
                source,
            })?;
    }
}

fn hash_file(
    mut file: File,
    cancellation: &AcquisitionCancellation,
) -> Result<(u64, Digest), CompletionError> {
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        check_cancelled(cancellation)?;
        let read = file
            .read(&mut buffer)
            .map_err(|source| CompletionError::Io {
                operation: "read stage file",
                source,
            })?;
        if read == 0 {
            return Ok((length, Digest::from_array(hasher.finalize().into())));
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| CompletionError::StageMismatch)?)
            .ok_or(CompletionError::StageMismatch)?;
        hasher.update(&buffer[..read]);
    }
}

struct DirectoryEntry {
    name: CString,
    segment: PathSegment,
    kind: FileType,
    mode: u32,
}

fn enumerate(directory: &OwnedFd) -> Result<Vec<DirectoryEntry>, CompletionError> {
    let mut rows = Vec::new();
    let mut names = BTreeSet::new();
    let mut stream =
        Dir::read_from(directory).map_err(|error| io_error("read directory", error))?;
    for entry in &mut stream {
        let entry = entry.map_err(|error| io_error("read directory entry", error))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = name.to_owned();
        if !names.insert(name.clone()) {
            return Err(CompletionError::StageMismatch);
        }
        let stat = fs::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error("inspect directory entry", error))?;
        #[cfg(target_os = "macos")]
        let mode = u32::from(stat.st_mode);
        #[cfg(not(target_os = "macos"))]
        let mode = stat.st_mode;
        rows.push(DirectoryEntry {
            segment: PathSegment::from_bytes(name.to_bytes())
                .map_err(|_| CompletionError::StageMismatch)?,
            name,
            kind: FileType::from_raw_mode(stat.st_mode),
            mode,
        });
    }
    rows.sort_by(|left, right| left.segment.cmp(&right.segment));
    Ok(rows)
}

fn discard_stage_path(job_root: &Path, stage_path: &Path) -> Result<(), CompletionError> {
    if stage_path.parent() != Some(job_root) || stage_path.file_name() != Some(OsStr::new("stage"))
    {
        return Err(CompletionError::UnsafePath);
    }
    let job = fs::open(job_root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open job for discard", error))?;
    remove_named_tree(&job, c"stage")?;
    fs::fsync(&job).map_err(|error| io_error("sync discarded stage", error))
}

fn remove_named_tree(parent: &OwnedFd, name: &CStr) -> Result<(), CompletionError> {
    let directory = fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open tree for removal", error))?;
    remove_directory_contents(&directory, 0)?;
    fs::unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(|error| io_error("remove tree", error))
}

fn remove_directory_contents(directory: &OwnedFd, depth: usize) -> Result<(), CompletionError> {
    check_depth(depth)?;
    fs::fchmod(directory, Mode::from_raw_mode(0o700))
        .map_err(|error| io_error("make private tree removable", error))?;
    for entry in enumerate(directory)? {
        if entry.kind.is_dir() {
            let child = fs::openat(
                directory,
                entry.name.as_c_str(),
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|error| io_error("open removal directory", error))?;
            remove_directory_contents(&child, depth + 1)?;
            fs::unlinkat(directory, entry.name.as_c_str(), AtFlags::REMOVEDIR)
                .map_err(|error| io_error("remove directory", error))?;
        } else {
            fs::unlinkat(directory, entry.name.as_c_str(), AtFlags::empty())
                .map_err(|error| io_error("remove file", error))?;
        }
    }
    fs::fsync(directory).map_err(|error| io_error("sync tree removal", error))
}

fn quarantine_job(store: &JobStore, run_id: &RunId) -> Result<(), CompletionError> {
    let jobs = fs::open(&store.paths().jobs_root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open jobs root", error))?;
    let quarantine = fs::open(
        &store.paths().quarantine_root,
        DIRECTORY_FLAGS,
        Mode::empty(),
    )
    .map_err(|error| io_error("open quarantine root", error))?;
    let jobs_stat = fs::fstat(&jobs).map_err(|error| io_error("inspect jobs root", error))?;
    let quarantine_stat =
        fs::fstat(&quarantine).map_err(|error| io_error("inspect quarantine root", error))?;
    if jobs_stat.st_dev != quarantine_stat.st_dev {
        return Err(CompletionError::QuarantineFilesystemMismatch);
    }
    fs::renameat_with(
        &jobs,
        run_id.as_str(),
        &quarantine,
        run_id.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| io_error("quarantine job", error))?;
    sync_dirs(&jobs, &quarantine)
}

fn move_handoff(
    job_root_path: &Path,
    stage: &OwnedFd,
    parent: &OwnedFd,
    destination_name: &CStr,
    expected: &SealedStage,
    cancellation: &AcquisitionCancellation,
) -> Result<(), CompletionError> {
    let stage_stat = fs::fstat(stage).map_err(|error| io_error("inspect stage", error))?;
    let parent_stat = fs::fstat(parent).map_err(|error| io_error("inspect destination", error))?;
    if stage_stat.st_dev != parent_stat.st_dev {
        return Err(CompletionError::CrossFilesystemMove);
    }
    restore_publication_modes(stage, cancellation, 0)?;
    fs::fchmod(stage, Mode::from_raw_mode(0o755))
        .map_err(|error| io_error("restore stage root mode", error))?;
    let restored = capture_entries(stage, cancellation)?;
    require_manifest(&restored, expected.entries(), expected.manifest_identity())?;
    let job_root = fs::open(job_root_path, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open job root", error))?;
    if let Err(error) = fs::renameat_with(
        &job_root,
        "stage",
        parent,
        destination_name,
        RenameFlags::NOREPLACE,
    ) {
        let uncancelled = AcquisitionCancellation::default();
        seal_directory(stage, &uncancelled, 0)?;
        fs::fchmod(stage, Mode::from_raw_mode(0o500))
            .map_err(|seal_error| io_error("reseal stage root", seal_error))?;
        fs::fsync(stage).map_err(|seal_error| io_error("sync resealed stage root", seal_error))?;
        return Err(io_error("move handoff stage", error));
    }
    sync_dirs(&job_root, parent)
}

fn copy_handoff(
    stage: &OwnedFd,
    parent: &OwnedFd,
    destination_name: &CStr,
    intent: &HandoffIntent,
    expected: &SealedStage,
    cancellation: &AcquisitionCancellation,
) -> Result<(), CompletionError> {
    let temporary_name = CString::new(intent.temporary_name.as_bytes())
        .map_err(|_| CompletionError::HandoffIntentMismatch)?;
    match fs::statat(parent, temporary_name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => remove_named_tree(parent, temporary_name.as_c_str())?,
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(io_error("inspect copy handoff temporary", error)),
    }
    fs::mkdirat(
        parent,
        temporary_name.as_c_str(),
        Mode::from_raw_mode(0o700),
    )
    .map_err(|error| io_error("create copy handoff temporary", error))?;
    let temporary = fs::openat(
        parent,
        temporary_name.as_c_str(),
        DIRECTORY_FLAGS,
        Mode::empty(),
    )
    .map_err(|error| io_error("open copy handoff temporary", error))?;
    let copy_result: Result<(), CompletionError> = (|| {
        copy_directory(stage, &temporary, cancellation, 0)?;
        let copied = capture_entries(&temporary, cancellation)?;
        require_manifest(&copied, expected.entries(), expected.manifest_identity())?;
        fs::fchmod(&temporary, Mode::from_raw_mode(0o755))
            .map_err(|error| io_error("set destination root mode", error))?;
        fs::fsync(&temporary).map_err(|error| io_error("sync copy handoff root", error))?;
        fs::renameat_with(
            parent,
            temporary_name.as_c_str(),
            parent,
            destination_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| io_error("publish copy handoff", error))?;
        fs::fsync(parent).map_err(|error| io_error("sync destination parent", error))?;
        Ok(())
    })();
    if copy_result.is_err() {
        let _ = remove_named_tree(parent, temporary_name.as_c_str());
    }
    copy_result
}

fn open_destination_parent(destination: &Path) -> Result<(OwnedFd, CString), CompletionError> {
    if !destination.is_absolute() {
        return Err(CompletionError::DestinationNotAbsolute);
    }
    let name = destination
        .file_name()
        .filter(|value| !value.as_bytes().is_empty())
        .ok_or(CompletionError::UnsafePath)?;
    let destination_name =
        CString::new(name.as_bytes()).map_err(|_| CompletionError::UnsafePath)?;
    let parent_path = destination.parent().ok_or(CompletionError::UnsafePath)?;
    let mut current = fs::open("/", DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open filesystem root", error))?;
    for component in parent_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = fs::openat(&current, name, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|error| io_error("resolve destination parent", error))?;
            }
            _ => return Err(CompletionError::UnsafePath),
        }
    }
    let stat =
        fs::fstat(&current).map_err(|error| io_error("inspect destination parent", error))?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(CompletionError::UntrustedDestinationParent);
    }
    Ok((current, destination_name))
}

fn destination_is_present(parent: &OwnedFd, name: &CStr) -> Result<bool, CompletionError> {
    match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(io_error("inspect destination", error)),
    }
}

fn require_destination_absent(parent: &OwnedFd, name: &CStr) -> Result<(), CompletionError> {
    if destination_is_present(parent, name)? {
        Err(CompletionError::DestinationExists)
    } else {
        Ok(())
    }
}

fn destination_identity(
    parent: &OwnedFd,
    name: &CStr,
    mode: HandoffMode,
) -> Result<Digest, CompletionError> {
    let stat = fs::fstat(parent).map_err(|error| io_error("inspect destination parent", error))?;
    let mut material = Vec::new();
    material.extend_from_slice(&stat.st_dev.to_le_bytes());
    material.extend_from_slice(&stat.st_ino.to_le_bytes());
    material.extend_from_slice(name.to_bytes());
    material.push(match mode {
        HandoffMode::Move => 0,
        HandoffMode::Copy => 1,
    });
    Ok(Digest::sha256(material))
}

fn temporary_destination_name(run_id: &RunId) -> Result<CString, CompletionError> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    CString::new(format!(
        ".file-guardian-{}-{}-{counter}",
        run_id.as_str(),
        std::process::id()
    ))
    .map_err(|_| CompletionError::UnsafePath)
}

fn write_status(root: &Path, status: &CompletionStatus) -> Result<(), CompletionError> {
    write_private_json(root, "completion-status.json", status)
}

fn write_sealed_record(
    root: &Path,
    run_id: &RunId,
    manifest_identity: Digest,
) -> Result<(), CompletionError> {
    write_private_json(
        root,
        "sealed-stage.json",
        &SealedStageRecord {
            schema_version: "file-guardian-sealed-stage/1".to_owned(),
            run_id: run_id.clone(),
            manifest_identity,
        },
    )
}

fn write_private_json<T: Serialize>(
    root: &Path,
    target_name: &str,
    value: &T,
) -> Result<(), CompletionError> {
    let directory = fs::open(root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open status root", error))?;
    let bytes = serde_json::to_vec(value).map_err(CompletionError::Serialize)?;
    let temporary = CString::new(format!(
        ".completion-status-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| CompletionError::UnsafePath)?;
    let fd = fs::openat(
        &directory,
        temporary.as_c_str(),
        CREATE_FILE_FLAGS,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| io_error("create status temporary", error))?;
    let mut file = File::from(fd);
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|source| CompletionError::Io {
                operation: "write completion status",
                source,
            })?;
        file.sync_all().map_err(|source| CompletionError::Io {
            operation: "sync completion status",
            source,
        })?;
        fs::renameat(&directory, temporary.as_c_str(), &directory, target_name)
            .map_err(|error| io_error("publish completion status", error))?;
        fs::fsync(&directory).map_err(|error| io_error("sync completion status", error))
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&directory, temporary.as_c_str(), AtFlags::empty());
    }
    result
}

fn create_private_json_once<T: Serialize>(
    root: &Path,
    target_name: &str,
    value: &T,
) -> Result<(), CompletionError> {
    let directory = fs::open(root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open private metadata root", error))?;
    let bytes = serde_json::to_vec(value).map_err(CompletionError::Serialize)?;
    let temporary = CString::new(format!(
        ".handoff-intent-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| CompletionError::UnsafePath)?;
    let fd = fs::openat(
        &directory,
        temporary.as_c_str(),
        CREATE_FILE_FLAGS,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| io_error("create private metadata temporary", error))?;
    let mut file = File::from(fd);
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|source| CompletionError::Io {
                operation: "write private metadata",
                source,
            })?;
        file.sync_all().map_err(|source| CompletionError::Io {
            operation: "sync private metadata",
            source,
        })?;
        fs::renameat_with(
            &directory,
            temporary.as_c_str(),
            &directory,
            target_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| io_error("publish private metadata", error))?;
        fs::fsync(&directory).map_err(|error| io_error("sync private metadata", error))
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&directory, temporary.as_c_str(), AtFlags::empty());
    }
    result
}

fn read_optional_private_json<T: DeserializeOwned>(
    root: &Path,
    name: &str,
) -> Result<Option<T>, CompletionError> {
    match read_private_json(root, name) {
        Ok(value) => Ok(Some(value)),
        Err(CompletionError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn read_sealed_record(
    job_root: &Path,
    run_id: &RunId,
) -> Result<SealedStageRecord, CompletionError> {
    let record: SealedStageRecord = read_private_json(job_root, "sealed-stage.json")?;
    if record.schema_version != "file-guardian-sealed-stage/1" || &record.run_id != run_id {
        return Err(CompletionError::DecisionMismatch);
    }
    Ok(record)
}

fn load_sealed_stage_at(
    job_root: &Path,
    run_id: &RunId,
    cancellation: &AcquisitionCancellation,
) -> Result<SealedStage, CompletionError> {
    let record = read_sealed_record(job_root, run_id)?;
    let stage = open_private_stage(&job_root.join("stage"))?;
    let entries = capture_entries(&stage, cancellation)?;
    if manifest_identity(&entries)? != record.manifest_identity {
        return Err(CompletionError::StageMismatch);
    }
    Ok(SealedStage {
        manifest_identity: record.manifest_identity,
        entries,
    })
}

fn read_private_json<T: DeserializeOwned>(root: &Path, name: &str) -> Result<T, CompletionError> {
    let directory = fs::open(root, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open private metadata root", error))?;
    let fd = fs::openat(&directory, name, FILE_FLAGS, Mode::empty())
        .map_err(|error| io_error("open private metadata", error))?;
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect private metadata", error))?;
    if stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > 64 * 1024 * 1024
    {
        return Err(CompletionError::UnsafePath);
    }
    serde_json::from_reader(File::from(fd)).map_err(CompletionError::Serialize)
}

fn read_status(job_root: &Path, run_id: &RunId) -> Result<CompletionStatus, CompletionError> {
    let directory = match fs::open(job_root, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(directory) => directory,
        Err(rustix::io::Errno::NOENT) => return Err(CompletionError::StatusUnavailable),
        Err(error) => return Err(io_error("open completion status root", error)),
    };
    let fd = match fs::openat(
        &directory,
        "completion-status.json",
        FILE_FLAGS,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Err(CompletionError::StatusUnavailable),
        Err(error) => return Err(io_error("open completion status", error)),
    };
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect completion status", error))?;
    if stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > 1024 * 1024
    {
        return Err(CompletionError::UnsafePath);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(stat.st_size).unwrap_or(0));
    File::from(fd)
        .read_to_end(&mut bytes)
        .map_err(|source| CompletionError::Io {
            operation: "read completion status",
            source,
        })?;
    let status: CompletionStatus =
        serde_json::from_slice(&bytes).map_err(CompletionError::Serialize)?;
    if &status.run_id != run_id {
        return Err(CompletionError::DecisionMismatch);
    }
    Ok(status)
}

fn logical_path(segments: Vec<PathSegment>) -> Result<LogicalPath, CompletionError> {
    LogicalPath::new(segments).map_err(|_| CompletionError::StageMismatch)
}

fn check_cancelled(cancellation: &AcquisitionCancellation) -> Result<(), CompletionError> {
    if cancellation.is_cancelled() {
        Err(CompletionError::Cancelled)
    } else {
        Ok(())
    }
}

fn check_depth(depth: usize) -> Result<(), CompletionError> {
    if depth > MAX_DEPTH {
        Err(CompletionError::StageMismatch)
    } else {
        Ok(())
    }
}

fn current_unix_millis() -> Result<i64, CompletionError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| CompletionError::Io {
            operation: "read system clock",
            source: io::Error::other(source),
        })?;
    i64::try_from(duration.as_millis()).map_err(|_| CompletionError::UnsafePath)
}

fn sync_dirs(left: &OwnedFd, right: &OwnedFd) -> Result<(), CompletionError> {
    fs::fsync(left).map_err(|error| io_error("sync source parent", error))?;
    fs::fsync(right).map_err(|error| io_error("sync destination parent", error))
}

fn io_error(operation: &'static str, error: rustix::io::Errno) -> CompletionError {
    CompletionError::Io {
        operation,
        source: io::Error::from_raw_os_error(error.raw_os_error()),
    }
}

#[derive(Debug, Error)]
pub enum CompletionError {
    #[error("completion operation was cancelled")]
    Cancelled,
    #[error("the live stage no longer matches the sealed manifest")]
    StageMismatch,
    #[error("the stage contains an unsupported special file")]
    SpecialFile,
    #[error("the private stage is insecure")]
    InsecureStage,
    #[error("the private decision, report, and job identity do not agree")]
    DecisionMismatch,
    #[error("the report disposition does not match the requested disposition")]
    ReportDispositionMismatch,
    #[error("an allowed stage has not been sealed")]
    AllowedStageUnsealed,
    #[error("the terminal outcome/disposition/handoff tuple is invalid")]
    InvalidTerminal,
    #[error("disposition failed; the job remains private as retained_error")]
    DispositionFailedRetainedError,
    #[error("the requested stage is unavailable for handoff")]
    HandoffUnavailable,
    #[error("handoff destination must be absolute")]
    DestinationNotAbsolute,
    #[error("handoff destination parent is not trusted")]
    UntrustedDestinationParent,
    #[error("handoff destination already exists")]
    DestinationExists,
    #[error("the durable handoff intent does not match this exact retry")]
    HandoffIntentMismatch,
    #[error("the handoff destination does not match the durable intent manifest")]
    HandoffDestinationMismatch,
    #[error("move handoff requires the same filesystem")]
    CrossFilesystemMove,
    #[error("jobs and quarantine roots are not on the same filesystem")]
    QuarantineFilesystemMismatch,
    #[error("completion status is unavailable")]
    StatusUnavailable,
    #[error("the durable recovery state is not resumable by this operation")]
    RecoveryStateUnsupported,
    #[error("the job is locked or its heartbeat is not stale")]
    JobNotStale,
    #[error("an immutable published report differs from the recovery report")]
    PublishedReportMismatch,
    #[error("unsafe filesystem path")]
    UnsafePath,
    #[error("completion metadata serialization failed")]
    Serialize(#[source] serde_json::Error),
    #[error("processing report validation failed")]
    Report(#[source] Box<crate::processing::report::ReportError>),
    #[error(transparent)]
    JobStore(#[from] JobStoreError),
    #[error("{operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}
