//! Descriptor-relative execution of a previously compiled whole-file plan.
//!
//! The executor owns no policy decisions.  It validates every target and
//! destination before the first mutation, moves files only beneath held stage
//! and private destination descriptors, and journals every durable boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::domain::{Digest, FileTimestamp, LogicalPath, SourceFileType, SourceIdentity};
use crate::processing::acquisition::local::AcquisitionCancellation;
use crate::processing::domain::{ActionId, ActionKind, ArtifactQuarantineId};

use super::journal::{
    read_journal, ActionJournalWriter, CleanupKind, JournalEvent, JournalFailureCode,
};
use super::plan::{ActionPlan, PlannedAction};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const PRIVATE_FILE_MODE: Mode = Mode::from_raw_mode(0o600);
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const QUARANTINE_METADATA_SCHEMA: &str = "1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionFaultPoint {
    AfterPreflight,
    BeforeAction,
    AfterActionStarted,
    BeforeRename,
    AfterRename,
    AfterActionFsynced,
    BeforeRollback,
    BeforeRollbackAction,
    AfterRollbackAction,
    BeforeCleanup,
    AfterCleanupMutation,
}

/// Test seam for deterministic boundary failures. Production uses
/// [`NoActionFaults`]. Returning true injects a safe internal failure.
pub trait ActionFaultInjector: Send + Sync {
    fn fail(&self, point: ActionFaultPoint, action_id: Option<&ActionId>) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoActionFaults;

impl ActionFaultInjector for NoActionFaults {
    fn fail(&self, _point: ActionFaultPoint, _action_id: Option<&ActionId>) -> bool {
        false
    }
}

/// Trusted immutable-capture seam used to prove an exact baseline after a
/// rollback. The implementation must perform the normal descriptor-safe stage
/// capture and return its canonical manifest identity.
pub trait StageManifestProver: Send + Sync {
    fn capture_manifest(&self, stage_root: &Path) -> Result<Digest, StageManifestProofError>;
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("stage manifest capture failed")]
pub struct StageManifestProofError;

#[derive(Clone, Copy)]
/// The caller must retain the job store's exclusive lease for the entire call
/// and must not expose the private stage to another writer. The executor also
/// performs an exact descriptor-relative identity check at the rename
/// boundary and verifies the moved object afterward.
pub struct ActionExecutionRequest<'a> {
    pub stage_root: &'a Path,
    pub trash_root: &'a Path,
    pub artifact_quarantine_root: &'a Path,
    pub journal_path: &'a Path,
    pub plan: &'a ActionPlan,
    pub cancellation: &'a AcquisitionCancellation,
    pub manifest_prover: &'a dyn StageManifestProver,
    pub faults: &'a dyn ActionFaultInjector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedActionTransaction {
    pub action_ids: Vec<ActionId>,
}

pub struct ActionRecoveryRequest<'a> {
    pub stage_root: &'a Path,
    pub trash_root: &'a Path,
    pub artifact_quarantine_root: &'a Path,
    pub journal_path: &'a Path,
    pub plan: &'a ActionPlan,
    pub manifest_prover: &'a dyn StageManifestProver,
    pub faults: &'a dyn ActionFaultInjector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveredActionTransaction {
    AlreadyCommitted {
        final_manifest_identity: Digest,
    },
    /// Every planned mutation was durably applied and the fresh publication
    /// manifest was recorded before verification began. A verification
    /// failure preserves this modified stage for whole-job quarantine.
    VerificationStagePreserved {
        manifest_identity: Digest,
    },
    UnchangedProven {
        manifest_identity: Digest,
    },
    RolledBackProven {
        action_ids: Vec<ActionId>,
        manifest_identity: Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionFailureKind {
    Cancelled,
    InvalidPrivateRoot,
    RootOverlap,
    CrossFilesystem,
    DestinationExists,
    PreconditionMismatch,
    MutationFailed,
    DurabilityFailed,
    JournalFailed,
    QuarantineMetadataFailed,
    ManifestProofFailed,
    FaultInjected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackStatus {
    UnchangedProven { manifest_identity: Digest },
    RestoredProven { manifest_identity: Digest },
    Failed,
}

#[derive(Debug, Error)]
#[error("action execution failed safely")]
pub struct ActionExecutionFailure {
    pub kind: ActionFailureKind,
    pub applied_action_ids: Vec<ActionId>,
    pub rollback: RollbackStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupFailureKind {
    InvalidPrivateRoot,
    JournalFailed,
    TransactionNotCommitted,
    ArtifactMissingOrChanged,
    DurabilityFailed,
    FaultInjected,
}

#[derive(Debug, Error)]
#[error("committed action cleanup is incomplete and retryable")]
pub struct CommittedCleanupFailure {
    pub kind: CleanupFailureKind,
    pub action_id: Option<ActionId>,
}

pub struct CommittedCleanupRequest<'a> {
    pub stage_root: &'a Path,
    pub trash_root: &'a Path,
    pub artifact_quarantine_root: &'a Path,
    pub journal_path: &'a Path,
    pub plan: &'a ActionPlan,
    pub faults: &'a dyn ActionFaultInjector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedCleanup {
    pub cleaned_action_ids: Vec<ActionId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactQuarantineMetadata {
    schema_version: String,
    pub quarantine_id: ArtifactQuarantineId,
    pub action_id: ActionId,
    pub subject_id: crate::domain::SubjectId,
    pub logical_path: LogicalPath,
    pub identity: SourceIdentity,
}

impl ArtifactQuarantineMetadata {
    fn new(action: &PlannedAction) -> Result<Self, ActionFailureKind> {
        let quarantine_id = action
            .artifact_quarantine_id
            .clone()
            .ok_or(ActionFailureKind::QuarantineMetadataFailed)?;
        Ok(Self {
            schema_version: QUARANTINE_METADATA_SCHEMA.to_owned(),
            quarantine_id,
            action_id: action.id.clone(),
            subject_id: action.target.subject_id.clone(),
            logical_path: action.target.logical_path.clone(),
            identity: action.target.expected_identity.clone(),
        })
    }

    fn validate(&self, action: &PlannedAction) -> bool {
        self.schema_version == QUARANTINE_METADATA_SCHEMA
            && action.kind == ActionKind::Quarantine
            && action.artifact_quarantine_id.as_ref() == Some(&self.quarantine_id)
            && self.action_id == action.id
            && self.subject_id == action.target.subject_id
            && self.logical_path == action.target.logical_path
            && same_content(&self.identity, &action.target.expected_identity)
    }

    pub fn validate_stored_record(&self) -> bool {
        self.schema_version == QUARANTINE_METADATA_SCHEMA
            && self.identity.file_type == SourceFileType::RegularFile
            && self.identity.link_count == 1
    }
}

struct Roots {
    stage: OwnedFd,
    trash: OwnedFd,
    quarantine: OwnedFd,
}

#[derive(Clone)]
struct AppliedMove<'a> {
    action: &'a PlannedAction,
    metadata_created: bool,
}

struct RollbackContext<'a> {
    stage_root: &'a Path,
    plan: &'a ActionPlan,
    manifest_prover: &'a dyn StageManifestProver,
    faults: &'a dyn ActionFaultInjector,
    already_started: bool,
}

/// Apply a whole-file plan. Success means mutations are durable but not yet
/// authorized for handoff; verification, decision, commit, and cleanup remain
/// separate mandatory phases.
pub fn execute_actions(
    request: ActionExecutionRequest<'_>,
) -> Result<AppliedActionTransaction, ActionExecutionFailure> {
    let roots = open_roots(
        request.stage_root,
        request.trash_root,
        request.artifact_quarantine_root,
    )
    .map_err(|kind| setup_failure(kind, &request))?;
    preflight_destinations(&roots, request.plan).map_err(|kind| setup_failure(kind, &request))?;

    let mut journal = ActionJournalWriter::create(request.journal_path)
        .map_err(|_| setup_failure(ActionFailureKind::JournalFailed, &request))?;
    if journal
        .append_and_sync(&JournalEvent::PlanPrepared {
            plan: request.plan.clone(),
        })
        .is_err()
    {
        return Err(setup_failure(ActionFailureKind::JournalFailed, &request));
    }

    for action in &request.plan.actions {
        if request.cancellation.is_cancelled() {
            return Err(fail_and_rollback(
                ActionFailureKind::Cancelled,
                None,
                &roots,
                &mut journal,
                &[],
                &request,
            ));
        }
        let identity = match inspect_stage_target(&roots.stage, action) {
            Ok(identity) if identity == action.target.expected_identity => identity,
            _ => {
                return Err(fail_and_rollback(
                    ActionFailureKind::PreconditionMismatch,
                    Some(&action.id),
                    &roots,
                    &mut journal,
                    &[],
                    &request,
                ))
            }
        };
        if journal
            .append_and_sync(&JournalEvent::PreconditionValidated {
                action_id: action.id.clone(),
                observed_identity: identity,
            })
            .is_err()
        {
            return Err(fail_and_rollback(
                ActionFailureKind::JournalFailed,
                Some(&action.id),
                &roots,
                &mut journal,
                &[],
                &request,
            ));
        }
    }

    if request.faults.fail(ActionFaultPoint::AfterPreflight, None) {
        return Err(fail_and_rollback(
            ActionFailureKind::FaultInjected,
            None,
            &roots,
            &mut journal,
            &[],
            &request,
        ));
    }

    let mut applied = Vec::new();
    for action in &request.plan.actions {
        let failure = apply_one(action, &roots, &mut journal, &request, &mut applied);
        if let Err((kind, action_id)) = failure {
            return Err(fail_and_rollback(
                kind,
                action_id.as_ref(),
                &roots,
                &mut journal,
                &applied,
                &request,
            ));
        }
    }

    Ok(AppliedActionTransaction {
        action_ids: applied
            .iter()
            .map(|entry| entry.action.id.clone())
            .collect(),
    })
}

/// Recover an interrupted, uncommitted action transaction from its durable
/// journal and the two job-owned move destinations. Recovery repairs only a
/// structurally valid incomplete final journal frame, never corrupt interior
/// data. A committed transaction is never rolled back.
pub fn recover_actions(
    request: ActionRecoveryRequest<'_>,
) -> Result<RecoveredActionTransaction, ActionExecutionFailure> {
    let roots = open_roots(
        request.stage_root,
        request.trash_root,
        request.artifact_quarantine_root,
    )
    .map_err(|kind| recovery_setup_failure(kind, &request))?;
    let parsed = read_journal(request.journal_path)
        .map_err(|_| recovery_setup_failure(ActionFailureKind::JournalFailed, &request))?;
    if !matches!(
        parsed.records.first().map(|record| &record.event),
        Some(JournalEvent::PlanPrepared { plan }) if plan == request.plan
    ) {
        return Err(recovery_setup_failure(
            ActionFailureKind::JournalFailed,
            &request,
        ));
    }
    let committed_manifest = parsed.records.iter().find_map(|record| match record.event {
        JournalEvent::TransactionCommitted {
            final_manifest_identity,
        } => Some(final_manifest_identity),
        _ => None,
    });
    let mut journal = ActionJournalWriter::open_repair_tail(request.journal_path)
        .map_err(|_| recovery_setup_failure(ActionFailureKind::JournalFailed, &request))?;
    if let Some(final_manifest_identity) = committed_manifest {
        return Ok(RecoveredActionTransaction::AlreadyCommitted {
            final_manifest_identity,
        });
    }
    let verification_manifest = parsed.records.iter().find_map(|record| match record.event {
        JournalEvent::VerificationStarted { manifest_identity } => Some(manifest_identity),
        _ => None,
    });
    if let Some(manifest_identity) = verification_manifest {
        let observed = request
            .manifest_prover
            .capture_manifest(request.stage_root)
            .map_err(|_| {
                recovery_setup_failure(ActionFailureKind::ManifestProofFailed, &request)
            })?;
        if observed != manifest_identity {
            return Err(recovery_setup_failure(
                ActionFailureKind::ManifestProofFailed,
                &request,
            ));
        }
        return Ok(RecoveredActionTransaction::VerificationStagePreserved { manifest_identity });
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum RecordedProgress {
        Planned,
        Preconditioned,
        Started,
        Applied,
        Fsynced,
        RolledBack,
    }

    let mut progress = request
        .plan
        .actions
        .iter()
        .map(|action| (action.id.clone(), RecordedProgress::Planned))
        .collect::<BTreeMap<_, _>>();
    let mut rollback_started = false;
    for record in &parsed.records {
        match &record.event {
            JournalEvent::PreconditionValidated { action_id, .. } => {
                progress.insert(action_id.clone(), RecordedProgress::Preconditioned);
            }
            JournalEvent::ActionStarted { action_id } => {
                progress.insert(action_id.clone(), RecordedProgress::Started);
            }
            JournalEvent::ActionApplied { action_id, .. } => {
                progress.insert(action_id.clone(), RecordedProgress::Applied);
            }
            JournalEvent::ActionFsynced { action_id } => {
                progress.insert(action_id.clone(), RecordedProgress::Fsynced);
            }
            JournalEvent::RollbackStarted => rollback_started = true,
            JournalEvent::ActionRolledBack { action_id, .. } => {
                progress.insert(action_id.clone(), RecordedProgress::RolledBack);
            }
            _ => {}
        }
    }

    let mut moved = Vec::new();
    for action in &request.plan.actions {
        let stage_identity = inspect_stage_target_optional(&roots.stage, action)
            .map_err(|kind| recovery_setup_failure(kind, &request))?;
        let (destination, name) =
            destination(&roots, action).map_err(|kind| recovery_setup_failure(kind, &request))?;
        let destination_identity = inspect_named_file_optional(destination, name.as_c_str())
            .map_err(|kind| recovery_setup_failure(kind, &request))?;
        match (stage_identity, destination_identity) {
            (Some(stage), None) if stage == action.target.expected_identity => {}
            (None, Some(destination_identity))
                if same_content(&destination_identity, &action.target.expected_identity) =>
            {
                if progress.get(&action.id) == Some(&RecordedProgress::Started) && !rollback_started
                {
                    journal
                        .append_and_sync(&JournalEvent::ActionApplied {
                            action_id: action.id.clone(),
                            result_identity: destination_identity,
                            artifact_quarantine_id: action.artifact_quarantine_id.clone(),
                        })
                        .map_err(|_| {
                            recovery_setup_failure(ActionFailureKind::JournalFailed, &request)
                        })?;
                    progress.insert(action.id.clone(), RecordedProgress::Applied);
                } else if !matches!(
                    progress.get(&action.id),
                    Some(RecordedProgress::Applied | RecordedProgress::Fsynced)
                ) {
                    return Err(recovery_setup_failure(
                        ActionFailureKind::PreconditionMismatch,
                        &request,
                    ));
                }
                moved.push(AppliedMove {
                    action,
                    metadata_created: quarantine_metadata_exists(&roots.quarantine, action),
                });
            }
            _ => {
                return Err(recovery_setup_failure(
                    ActionFailureKind::PreconditionMismatch,
                    &request,
                ))
            }
        }
    }

    if moved.is_empty() {
        return match request.manifest_prover.capture_manifest(request.stage_root) {
            Ok(identity) if identity == request.plan.initial_manifest_identity => {
                Ok(RecoveredActionTransaction::UnchangedProven {
                    manifest_identity: identity,
                })
            }
            _ => Err(recovery_setup_failure(
                ActionFailureKind::ManifestProofFailed,
                &request,
            )),
        };
    }
    let _ = journal.append_and_sync(&JournalEvent::FailureRecorded {
        action_id: None,
        code: JournalFailureCode::InternalFailure,
    });
    let moved_ids = moved
        .iter()
        .map(|entry| entry.action.id.clone())
        .collect::<Vec<_>>();
    match rollback(
        &roots,
        &mut journal,
        &moved,
        RollbackContext {
            stage_root: request.stage_root,
            plan: request.plan,
            manifest_prover: request.manifest_prover,
            faults: request.faults,
            already_started: rollback_started,
        },
    ) {
        RollbackStatus::RestoredProven { manifest_identity } => {
            Ok(RecoveredActionTransaction::RolledBackProven {
                action_ids: moved_ids,
                manifest_identity,
            })
        }
        _ => Err(ActionExecutionFailure {
            kind: ActionFailureKind::ManifestProofFailed,
            applied_action_ids: moved_ids,
            rollback: RollbackStatus::Failed,
        }),
    }
}

fn apply_one<'a>(
    action: &'a PlannedAction,
    roots: &Roots,
    journal: &mut ActionJournalWriter,
    request: &ActionExecutionRequest<'_>,
    applied: &mut Vec<AppliedMove<'a>>,
) -> Result<(), (ActionFailureKind, Option<ActionId>)> {
    let id = Some(action.id.clone());
    if request.cancellation.is_cancelled() {
        return Err((ActionFailureKind::Cancelled, id));
    }
    if request
        .faults
        .fail(ActionFaultPoint::BeforeAction, Some(&action.id))
    {
        return Err((ActionFailureKind::FaultInjected, id));
    }
    match inspect_stage_target(&roots.stage, action) {
        Ok(identity) if identity == action.target.expected_identity => {}
        _ => return Err((ActionFailureKind::PreconditionMismatch, id)),
    }
    journal
        .append_and_sync(&JournalEvent::ActionStarted {
            action_id: action.id.clone(),
        })
        .map_err(|_| (ActionFailureKind::JournalFailed, id.clone()))?;
    if request
        .faults
        .fail(ActionFaultPoint::AfterActionStarted, Some(&action.id))
    {
        return Err((ActionFailureKind::FaultInjected, id));
    }

    let (source_parent, source_name) = resolve_parent(&roots.stage, &action.target.logical_path)
        .map_err(|_| (ActionFailureKind::PreconditionMismatch, id.clone()))?;
    let (destination, destination_name) =
        destination(roots, action).map_err(|kind| (kind, id.clone()))?;
    if request
        .faults
        .fail(ActionFaultPoint::BeforeRename, Some(&action.id))
    {
        return Err((ActionFailureKind::FaultInjected, id));
    }
    if request.cancellation.is_cancelled() {
        return Err((ActionFailureKind::Cancelled, id));
    }
    match inspect_named_file(&source_parent, source_name.as_c_str()) {
        Ok(identity) if identity == action.target.expected_identity => {}
        _ => return Err((ActionFailureKind::PreconditionMismatch, id)),
    }
    if request.cancellation.is_cancelled() {
        return Err((ActionFailureKind::Cancelled, id));
    }
    fs::renameat_with(
        &source_parent,
        source_name.as_c_str(),
        destination,
        destination_name.as_c_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| (ActionFailureKind::MutationFailed, id.clone()))?;
    applied.push(AppliedMove {
        action,
        metadata_created: false,
    });

    if request
        .faults
        .fail(ActionFaultPoint::AfterRename, Some(&action.id))
    {
        // Recovery now knows the rename occurred even though the injected
        // failure interrupted the normal post-mutation path.
        if let Ok(result_identity) = inspect_destination(roots, action) {
            let _ = journal.append_and_sync(&JournalEvent::ActionApplied {
                action_id: action.id.clone(),
                result_identity,
                artifact_quarantine_id: action.artifact_quarantine_id.clone(),
            });
        }
        return Err((ActionFailureKind::FaultInjected, id));
    }

    let result_identity = inspect_destination(roots, action)
        .map_err(|_| (ActionFailureKind::MutationFailed, id.clone()))?;
    if !same_content(&result_identity, &action.target.expected_identity) {
        return Err((ActionFailureKind::MutationFailed, id));
    }
    if action.kind == ActionKind::Quarantine {
        write_quarantine_metadata(&roots.quarantine, action)
            .map_err(|kind| (kind, Some(action.id.clone())))?;
        applied
            .last_mut()
            .expect("move was recorded")
            .metadata_created = true;
    }
    journal
        .append_and_sync(&JournalEvent::ActionApplied {
            action_id: action.id.clone(),
            result_identity,
            artifact_quarantine_id: action.artifact_quarantine_id.clone(),
        })
        .map_err(|_| (ActionFailureKind::JournalFailed, Some(action.id.clone())))?;
    sync_dir(&source_parent)
        .and_then(|_| sync_dir(destination))
        .map_err(|_| (ActionFailureKind::DurabilityFailed, Some(action.id.clone())))?;
    journal
        .append_and_sync(&JournalEvent::ActionFsynced {
            action_id: action.id.clone(),
        })
        .map_err(|_| (ActionFailureKind::JournalFailed, Some(action.id.clone())))?;
    if request
        .faults
        .fail(ActionFaultPoint::AfterActionFsynced, Some(&action.id))
    {
        return Err((ActionFailureKind::FaultInjected, Some(action.id.clone())));
    }
    Ok(())
}

fn fail_and_rollback(
    kind: ActionFailureKind,
    action_id: Option<&ActionId>,
    roots: &Roots,
    journal: &mut ActionJournalWriter,
    applied: &[AppliedMove<'_>],
    request: &ActionExecutionRequest<'_>,
) -> ActionExecutionFailure {
    let code = match kind {
        ActionFailureKind::Cancelled => JournalFailureCode::InternalFailure,
        ActionFailureKind::PreconditionMismatch => JournalFailureCode::PreconditionMismatch,
        ActionFailureKind::DurabilityFailed => JournalFailureCode::SyncFailed,
        ActionFailureKind::QuarantineMetadataFailed => JournalFailureCode::MutationFailed,
        ActionFailureKind::ManifestProofFailed => JournalFailureCode::RollbackFailed,
        ActionFailureKind::JournalFailed => JournalFailureCode::InternalFailure,
        _ => JournalFailureCode::MutationFailed,
    };
    let _ = journal.append_and_sync(&JournalEvent::FailureRecorded {
        action_id: action_id.cloned(),
        code,
    });
    let rollback = rollback(
        roots,
        journal,
        applied,
        RollbackContext {
            stage_root: request.stage_root,
            plan: request.plan,
            manifest_prover: request.manifest_prover,
            faults: request.faults,
            already_started: false,
        },
    );
    ActionExecutionFailure {
        kind,
        applied_action_ids: applied
            .iter()
            .map(|entry| entry.action.id.clone())
            .collect(),
        rollback,
    }
}

fn rollback(
    roots: &Roots,
    journal: &mut ActionJournalWriter,
    applied: &[AppliedMove<'_>],
    context: RollbackContext<'_>,
) -> RollbackStatus {
    let had_moves = !applied.is_empty();
    if had_moves {
        if context.faults.fail(ActionFaultPoint::BeforeRollback, None) {
            return RollbackStatus::Failed;
        }
        // Once mutation has begun, restoring the stage is more important than
        // journal availability. A poisoned journal must never prevent the
        // physical rollback; the exact manifest proof below remains the
        // authoritative indication that restoration succeeded.
        let mut journal_available = context.already_started
            || journal
                .append_and_sync(&JournalEvent::RollbackStarted)
                .is_ok();
        for moved in applied.iter().rev() {
            if context.faults.fail(
                ActionFaultPoint::BeforeRollbackAction,
                Some(&moved.action.id),
            ) || restore_one(roots, moved).is_err()
            {
                let _ = journal.append_and_sync(&JournalEvent::FailureRecorded {
                    action_id: Some(moved.action.id.clone()),
                    code: JournalFailureCode::RollbackFailed,
                });
                return RollbackStatus::Failed;
            }
            let restored = match inspect_stage_target(&roots.stage, moved.action) {
                Ok(identity) if same_content(&identity, &moved.action.target.expected_identity) => {
                    identity
                }
                _ => return RollbackStatus::Failed,
            };
            if journal_available
                && journal
                    .append_and_sync(&JournalEvent::ActionRolledBack {
                        action_id: moved.action.id.clone(),
                        restored_identity: restored,
                    })
                    .is_err()
            {
                journal_available = false;
            }
            if context.faults.fail(
                ActionFaultPoint::AfterRollbackAction,
                Some(&moved.action.id),
            ) {
                return RollbackStatus::Failed;
            }
        }
    }
    match context.manifest_prover.capture_manifest(context.stage_root) {
        Ok(identity) if identity == context.plan.initial_manifest_identity => {
            if had_moves {
                RollbackStatus::RestoredProven {
                    manifest_identity: identity,
                }
            } else {
                RollbackStatus::UnchangedProven {
                    manifest_identity: identity,
                }
            }
        }
        _ => RollbackStatus::Failed,
    }
}

fn restore_one(roots: &Roots, moved: &AppliedMove<'_>) -> Result<(), ActionFailureKind> {
    let (source_parent, source_name) =
        resolve_parent(&roots.stage, &moved.action.target.logical_path)
            .map_err(|_| ActionFailureKind::MutationFailed)?;
    ensure_absent(&source_parent, source_name.as_c_str())?;
    let (destination, destination_name) = destination(roots, moved.action)?;
    let identity = inspect_named_file(destination, destination_name.as_c_str())?;
    if !same_content(&identity, &moved.action.target.expected_identity) {
        return Err(ActionFailureKind::PreconditionMismatch);
    }
    fs::renameat_with(
        destination,
        destination_name.as_c_str(),
        &source_parent,
        source_name.as_c_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| ActionFailureKind::MutationFailed)?;
    sync_dir(destination)?;
    sync_dir(&source_parent)?;
    if moved.metadata_created {
        remove_quarantine_metadata(&roots.quarantine, moved.action)?;
    }
    remove_quarantine_temporary_metadata(&roots.quarantine, moved.action)?;
    Ok(())
}

/// Finish private trash cleanup only after a durable successful transaction
/// commit. The operation is idempotent and retryable after a cleanup failure.
pub fn cleanup_committed_actions(
    request: CommittedCleanupRequest<'_>,
) -> Result<CommittedCleanup, CommittedCleanupFailure> {
    let roots = open_roots(
        request.stage_root,
        request.trash_root,
        request.artifact_quarantine_root,
    )
    .map_err(|_| cleanup_failure(CleanupFailureKind::InvalidPrivateRoot, None))?;
    let parsed = read_journal(request.journal_path)
        .map_err(|_| cleanup_failure(CleanupFailureKind::JournalFailed, None))?;
    if parsed.incomplete_tail
        || !parsed
            .records
            .iter()
            .any(|record| matches!(record.event, JournalEvent::TransactionCommitted { .. }))
    {
        return Err(cleanup_failure(
            CleanupFailureKind::TransactionNotCommitted,
            None,
        ));
    }
    if !matches!(
        parsed.records.first().map(|record| &record.event),
        Some(JournalEvent::PlanPrepared { plan }) if plan == request.plan
    ) {
        return Err(cleanup_failure(CleanupFailureKind::JournalFailed, None));
    }
    let already_cleaned = parsed
        .records
        .iter()
        .filter_map(|record| match &record.event {
            JournalEvent::CleanupCompleted { action_id, .. } => Some(action_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut writer = ActionJournalWriter::open_append(request.journal_path)
        .map_err(|_| cleanup_failure(CleanupFailureKind::JournalFailed, None))?;
    let mut cleaned = already_cleaned.iter().cloned().collect::<Vec<_>>();
    for action in &request.plan.actions {
        if already_cleaned.contains(&action.id) {
            continue;
        }
        if request
            .faults
            .fail(ActionFaultPoint::BeforeCleanup, Some(&action.id))
        {
            record_cleanup_failure(&mut writer, action);
            return Err(cleanup_failure(
                CleanupFailureKind::FaultInjected,
                Some(action.id.clone()),
            ));
        }
        let result = if action.kind == ActionKind::Delete {
            cleanup_delete(&roots.trash, action)
        } else {
            verify_quarantine(&roots.quarantine, action)
        };
        if let Err(kind) = result {
            record_cleanup_failure(&mut writer, action);
            return Err(cleanup_failure(kind, Some(action.id.clone())));
        }
        if request
            .faults
            .fail(ActionFaultPoint::AfterCleanupMutation, Some(&action.id))
        {
            record_cleanup_failure(&mut writer, action);
            return Err(cleanup_failure(
                CleanupFailureKind::FaultInjected,
                Some(action.id.clone()),
            ));
        }
        let kind = if action.kind == ActionKind::Delete {
            CleanupKind::DeleteTrashRemoved
        } else {
            CleanupKind::ArtifactQuarantineDurable
        };
        writer
            .append_and_sync(&JournalEvent::CleanupCompleted {
                action_id: action.id.clone(),
                kind,
            })
            .map_err(|_| {
                cleanup_failure(CleanupFailureKind::JournalFailed, Some(action.id.clone()))
            })?;
        cleaned.push(action.id.clone());
    }
    cleaned.sort();
    Ok(CommittedCleanup {
        cleaned_action_ids: cleaned,
    })
}

fn cleanup_delete(trash: &OwnedFd, action: &PlannedAction) -> Result<(), CleanupFailureKind> {
    let name = safe_name(action.id.as_str()).map_err(|_| CleanupFailureKind::InvalidPrivateRoot)?;
    match fs::statat(trash, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            let identity = inspect_named_file(trash, name.as_c_str())
                .map_err(|_| CleanupFailureKind::ArtifactMissingOrChanged)?;
            if !same_content(&identity, &action.target.expected_identity) {
                return Err(CleanupFailureKind::ArtifactMissingOrChanged);
            }
            fs::unlinkat(trash, name.as_c_str(), AtFlags::empty())
                .map_err(|_| CleanupFailureKind::DurabilityFailed)?;
            sync_dir(trash).map_err(|_| CleanupFailureKind::DurabilityFailed)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(_) => Err(CleanupFailureKind::ArtifactMissingOrChanged),
    }
}

fn verify_quarantine(
    quarantine: &OwnedFd,
    action: &PlannedAction,
) -> Result<(), CleanupFailureKind> {
    let quarantine_id = action
        .artifact_quarantine_id
        .as_ref()
        .ok_or(CleanupFailureKind::ArtifactMissingOrChanged)?;
    let name = safe_name(quarantine_id.as_str())
        .map_err(|_| CleanupFailureKind::ArtifactMissingOrChanged)?;
    let identity = inspect_named_file(quarantine, name.as_c_str())
        .map_err(|_| CleanupFailureKind::ArtifactMissingOrChanged)?;
    if !same_content(&identity, &action.target.expected_identity) {
        return Err(CleanupFailureKind::ArtifactMissingOrChanged);
    }
    let metadata = read_quarantine_metadata(quarantine, action)
        .map_err(|_| CleanupFailureKind::ArtifactMissingOrChanged)?;
    if !metadata.validate(action) {
        return Err(CleanupFailureKind::ArtifactMissingOrChanged);
    }
    sync_dir(quarantine).map_err(|_| CleanupFailureKind::DurabilityFailed)
}

fn record_cleanup_failure(writer: &mut ActionJournalWriter, action: &PlannedAction) {
    let _ = writer.append_and_sync(&JournalEvent::FailureRecorded {
        action_id: Some(action.id.clone()),
        code: JournalFailureCode::CleanupFailed,
    });
}

fn cleanup_failure(
    kind: CleanupFailureKind,
    action_id: Option<ActionId>,
) -> CommittedCleanupFailure {
    CommittedCleanupFailure { kind, action_id }
}

fn setup_failure(
    kind: ActionFailureKind,
    request: &ActionExecutionRequest<'_>,
) -> ActionExecutionFailure {
    let rollback = match request.manifest_prover.capture_manifest(request.stage_root) {
        Ok(identity) if identity == request.plan.initial_manifest_identity => {
            RollbackStatus::UnchangedProven {
                manifest_identity: identity,
            }
        }
        _ => RollbackStatus::Failed,
    };
    ActionExecutionFailure {
        kind,
        applied_action_ids: Vec::new(),
        rollback,
    }
}

fn recovery_setup_failure(
    kind: ActionFailureKind,
    request: &ActionRecoveryRequest<'_>,
) -> ActionExecutionFailure {
    let rollback = match request.manifest_prover.capture_manifest(request.stage_root) {
        Ok(identity) if identity == request.plan.initial_manifest_identity => {
            RollbackStatus::UnchangedProven {
                manifest_identity: identity,
            }
        }
        _ => RollbackStatus::Failed,
    };
    ActionExecutionFailure {
        kind,
        applied_action_ids: Vec::new(),
        rollback,
    }
}

fn open_roots(stage: &Path, trash: &Path, quarantine: &Path) -> Result<Roots, ActionFailureKind> {
    let stage_canonical =
        std::fs::canonicalize(stage).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    let trash_canonical =
        std::fs::canonicalize(trash).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    let quarantine_canonical =
        std::fs::canonicalize(quarantine).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    let overlaps = |left: &Path, right: &Path| left.starts_with(right) || right.starts_with(left);
    if overlaps(&stage_canonical, &trash_canonical)
        || overlaps(&stage_canonical, &quarantine_canonical)
        || overlaps(&trash_canonical, &quarantine_canonical)
    {
        return Err(ActionFailureKind::RootOverlap);
    }
    let stage = open_private_dir(stage)?;
    let trash = open_private_dir(trash)?;
    let quarantine = open_private_dir(quarantine)?;
    let stage_stat = fs::fstat(&stage).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    let trash_stat = fs::fstat(&trash).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    let quarantine_stat =
        fs::fstat(&quarantine).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    if stage_stat.st_dev != trash_stat.st_dev || stage_stat.st_dev != quarantine_stat.st_dev {
        return Err(ActionFailureKind::CrossFilesystem);
    }
    Ok(Roots {
        stage,
        trash,
        quarantine,
    })
}

fn open_private_dir(path: &Path) -> Result<OwnedFd, ActionFailureKind> {
    let fd = fs::open(path, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    let stat = fs::fstat(&fd).map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(ActionFailureKind::InvalidPrivateRoot);
    }
    Ok(fd)
}

fn preflight_destinations(roots: &Roots, plan: &ActionPlan) -> Result<(), ActionFailureKind> {
    for action in &plan.actions {
        let (destination, name) = destination(roots, action)?;
        ensure_absent(destination, name.as_c_str())?;
        if action.kind == ActionKind::Quarantine {
            let metadata = metadata_name(action)?;
            ensure_absent(&roots.quarantine, metadata.as_c_str())?;
        }
    }
    Ok(())
}

fn destination<'a>(
    roots: &'a Roots,
    action: &PlannedAction,
) -> Result<(&'a OwnedFd, CString), ActionFailureKind> {
    match action.kind {
        ActionKind::Delete => Ok((&roots.trash, safe_name(action.id.as_str())?)),
        ActionKind::Quarantine => {
            let id = action
                .artifact_quarantine_id
                .as_ref()
                .ok_or(ActionFailureKind::QuarantineMetadataFailed)?;
            Ok((&roots.quarantine, safe_name(id.as_str())?))
        }
    }
}

fn ensure_absent(parent: &OwnedFd, name: &std::ffi::CStr) -> Result<(), ActionFailureKind> {
    match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Ok(_) => Err(ActionFailureKind::DestinationExists),
        Err(_) => Err(ActionFailureKind::InvalidPrivateRoot),
    }
}

fn inspect_stage_target(
    stage: &OwnedFd,
    action: &PlannedAction,
) -> Result<SourceIdentity, ActionFailureKind> {
    let (parent, name) = resolve_parent(stage, &action.target.logical_path)?;
    inspect_named_file(&parent, name.as_c_str())
}

fn inspect_stage_target_optional(
    stage: &OwnedFd,
    action: &PlannedAction,
) -> Result<Option<SourceIdentity>, ActionFailureKind> {
    let (parent, name) = resolve_parent(stage, &action.target.logical_path)?;
    inspect_named_file_optional(&parent, name.as_c_str())
}

fn inspect_destination(
    roots: &Roots,
    action: &PlannedAction,
) -> Result<SourceIdentity, ActionFailureKind> {
    let (directory, name) = destination(roots, action)?;
    inspect_named_file(directory, name.as_c_str())
}

fn inspect_named_file(
    parent: &OwnedFd,
    name: &std::ffi::CStr,
) -> Result<SourceIdentity, ActionFailureKind> {
    let fd = fs::openat(parent, name, FILE_FLAGS, Mode::empty())
        .map_err(|_| ActionFailureKind::PreconditionMismatch)?;
    let before = fs::fstat(&fd).map_err(|_| ActionFailureKind::PreconditionMismatch)?;
    let before_key = StatKey::from_stat(&before)?;
    if !before_key.file_type.is_file() || before_key.link_count != 1 {
        return Err(ActionFailureKind::PreconditionMismatch);
    }
    let mut file = File::from(fd);
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ActionFailureKind::PreconditionMismatch)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or(ActionFailureKind::PreconditionMismatch)?;
        hasher.update(&buffer[..read]);
    }
    let after = fs::fstat(&file).map_err(|_| ActionFailureKind::PreconditionMismatch)?;
    if before_key != StatKey::from_stat(&after)? || observed != before_key.byte_len {
        return Err(ActionFailureKind::PreconditionMismatch);
    }
    before_key.source_identity(Digest::from_array(hasher.finalize().into()))
}

fn inspect_named_file_optional(
    parent: &OwnedFd,
    name: &std::ffi::CStr,
) -> Result<Option<SourceIdentity>, ActionFailureKind> {
    match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Ok(_) => inspect_named_file(parent, name).map(Some),
        Err(_) => Err(ActionFailureKind::PreconditionMismatch),
    }
}

fn resolve_parent(
    root: &OwnedFd,
    logical_path: &LogicalPath,
) -> Result<(OwnedFd, CString), ActionFailureKind> {
    let segments = logical_path.segments();
    let (last, ancestors) = segments
        .split_last()
        .ok_or(ActionFailureKind::PreconditionMismatch)?;
    let mut current = root
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| ActionFailureKind::InvalidPrivateRoot)?;
    for segment in ancestors {
        let name = safe_bytes(segment.as_slice())?;
        current = fs::openat(&current, name.as_c_str(), DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| ActionFailureKind::PreconditionMismatch)?;
    }
    Ok((current, safe_bytes(last.as_slice())?))
}

fn safe_name(value: &str) -> Result<CString, ActionFailureKind> {
    safe_bytes(value.as_bytes())
}

fn safe_bytes(value: &[u8]) -> Result<CString, ActionFailureKind> {
    if value.is_empty() || value == b"." || value == b".." || value.contains(&b'/') {
        return Err(ActionFailureKind::PreconditionMismatch);
    }
    CString::new(value).map_err(|_| ActionFailureKind::PreconditionMismatch)
}

fn write_quarantine_metadata(
    directory: &OwnedFd,
    action: &PlannedAction,
) -> Result<(), ActionFailureKind> {
    let metadata = ArtifactQuarantineMetadata::new(action)?;
    let bytes =
        serde_json::to_vec(&metadata).map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
    let final_name = metadata_name(action)?;
    let temporary_name = safe_name(&format!(".{}.metadata.tmp", action.id.as_str()))?;
    let fd = fs::openat(
        directory,
        temporary_name.as_c_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
    let mut file = File::from(fd);
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
        file.sync_all()
            .map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
        fs::renameat_with(
            directory,
            temporary_name.as_c_str(),
            directory,
            final_name.as_c_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
        sync_dir(directory)
    })();
    if result.is_err() {
        let _ = fs::unlinkat(directory, temporary_name.as_c_str(), AtFlags::empty());
    }
    result
}

fn read_quarantine_metadata(
    directory: &OwnedFd,
    action: &PlannedAction,
) -> Result<ArtifactQuarantineMetadata, ActionFailureKind> {
    let name = metadata_name(action)?;
    let fd = fs::openat(directory, name.as_c_str(), FILE_FLAGS, Mode::empty())
        .map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
    let file = File::from(fd);
    let mut bytes = Vec::new();
    file.take(1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| ActionFailureKind::QuarantineMetadataFailed)?;
    serde_json::from_slice(&bytes).map_err(|_| ActionFailureKind::QuarantineMetadataFailed)
}

fn remove_quarantine_metadata(
    directory: &OwnedFd,
    action: &PlannedAction,
) -> Result<(), ActionFailureKind> {
    let name = metadata_name(action)?;
    match fs::unlinkat(directory, name.as_c_str(), AtFlags::empty()) {
        Ok(()) => sync_dir(directory),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(_) => Err(ActionFailureKind::QuarantineMetadataFailed),
    }
}

fn remove_quarantine_temporary_metadata(
    directory: &OwnedFd,
    action: &PlannedAction,
) -> Result<(), ActionFailureKind> {
    if action.kind != ActionKind::Quarantine {
        return Ok(());
    }
    let name = safe_name(&format!(".{}.metadata.tmp", action.id.as_str()))?;
    match fs::unlinkat(directory, name.as_c_str(), AtFlags::empty()) {
        Ok(()) => sync_dir(directory),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(_) => Err(ActionFailureKind::QuarantineMetadataFailed),
    }
}

fn quarantine_metadata_exists(directory: &OwnedFd, action: &PlannedAction) -> bool {
    action.kind == ActionKind::Quarantine
        && metadata_name(action)
            .is_ok_and(|name| fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).is_ok())
}

fn metadata_name(action: &PlannedAction) -> Result<CString, ActionFailureKind> {
    let id = action
        .artifact_quarantine_id
        .as_ref()
        .ok_or(ActionFailureKind::QuarantineMetadataFailed)?;
    safe_name(&format!("{}.json", id.as_str()))
}

fn sync_dir(directory: &OwnedFd) -> Result<(), ActionFailureKind> {
    fs::fsync(directory).map_err(|_| ActionFailureKind::DurabilityFailed)
}

fn same_content(left: &SourceIdentity, right: &SourceIdentity) -> bool {
    left.file_type == SourceFileType::RegularFile
        && right.file_type == SourceFileType::RegularFile
        && left.link_count == 1
        && right.link_count == 1
        && left.byte_len == right.byte_len
        && left.content_digest == right.content_digest
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StatKey {
    device: u64,
    inode: u64,
    mode: u64,
    byte_len: u64,
    link_count: u64,
    modified_seconds: i64,
    modified_nanoseconds: u32,
    changed_seconds: i64,
    changed_nanoseconds: u32,
    file_type: FileType,
}

impl StatKey {
    fn from_stat(stat: &Stat) -> Result<Self, ActionFailureKind> {
        Ok(Self {
            device: checked_u64(stat.st_dev)?,
            inode: checked_u64(stat.st_ino)?,
            mode: checked_u64(stat.st_mode)?,
            byte_len: checked_u64(stat.st_size)?,
            link_count: checked_u64(stat.st_nlink)?,
            modified_seconds: checked_i64(stat.st_mtime)?,
            modified_nanoseconds: checked_u32(stat.st_mtime_nsec)?,
            changed_seconds: checked_i64(stat.st_ctime)?,
            changed_nanoseconds: checked_u32(stat.st_ctime_nsec)?,
            file_type: FileType::from_raw_mode(stat.st_mode),
        })
    }

    fn source_identity(self, content_digest: Digest) -> Result<SourceIdentity, ActionFailureKind> {
        Ok(SourceIdentity {
            device: self.device,
            inode: self.inode,
            file_type: SourceFileType::RegularFile,
            byte_len: self.byte_len,
            link_count: self.link_count,
            modified: FileTimestamp::new(self.modified_seconds, self.modified_nanoseconds),
            changed: FileTimestamp::new(self.changed_seconds, self.changed_nanoseconds),
            content_digest,
        })
    }
}

#[allow(clippy::useless_conversion)]
fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, ActionFailureKind> {
    value
        .try_into()
        .map_err(|_| ActionFailureKind::PreconditionMismatch)
}

#[allow(clippy::useless_conversion)]
fn checked_i64<T: TryInto<i64>>(value: T) -> Result<i64, ActionFailureKind> {
    value
        .try_into()
        .map_err(|_| ActionFailureKind::PreconditionMismatch)
}

#[allow(clippy::useless_conversion)]
fn checked_u32<T: TryInto<u32>>(value: T) -> Result<u32, ActionFailureKind> {
    value
        .try_into()
        .map_err(|_| ActionFailureKind::PreconditionMismatch)
}
