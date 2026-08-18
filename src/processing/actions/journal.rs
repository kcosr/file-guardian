use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use rustix::fs::{self, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::domain::{Digest, SourceIdentity};
use crate::processing::domain::{ActionId, ActionKind, ArtifactQuarantineId, Outcome};

use super::plan::ActionPlan;

const FILE_MAGIC: &[u8; 8] = b"FGAJNL1\n";
const FRAME_MAGIC: &[u8; 4] = b"FGJ1";
const FRAME_END: &[u8; 4] = b"JEND";
const FRAME_VERSION: u16 = 1;
const FRAME_FLAGS: u16 = 0;
const HEADER_FIELDS_LEN: usize = 4 + 2 + 2 + 8 + 4;
const HEADER_LEN: usize = HEADER_FIELDS_LEN + 32;
const TRAILER_LEN: usize = 32 + 4;
const MAX_EVENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupKind {
    DeleteTrashRemoved,
    ArtifactQuarantineDurable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    Allow,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalFailureCode {
    PreconditionMismatch,
    MutationFailed,
    SyncFailed,
    RollbackFailed,
    VerificationFailed,
    DecisionFailed,
    CleanupFailed,
    InternalFailure,
}

/// Safe, durable action transaction events.  No variant can contain source
/// bytes, native analyzer output, or an operating-system path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEvent {
    PlanPrepared {
        plan: ActionPlan,
    },
    PreconditionValidated {
        action_id: ActionId,
        observed_identity: SourceIdentity,
    },
    ActionStarted {
        action_id: ActionId,
    },
    ActionApplied {
        action_id: ActionId,
        result_identity: SourceIdentity,
        artifact_quarantine_id: Option<ArtifactQuarantineId>,
    },
    ActionFsynced {
        action_id: ActionId,
    },
    RollbackStarted,
    ActionRolledBack {
        action_id: ActionId,
        restored_identity: SourceIdentity,
    },
    VerificationStarted {
        manifest_identity: Digest,
    },
    VerificationCompleted {
        manifest_identity: Digest,
        decision: VerificationDecision,
    },
    CleanupCompleted {
        action_id: ActionId,
        kind: CleanupKind,
    },
    DecisionPrepared {
        outcome: Outcome,
        current_manifest_identity: Option<Digest>,
    },
    TransactionCommitted {
        final_manifest_identity: Digest,
    },
    FailureRecorded {
        action_id: Option<ActionId>,
        code: JournalFailureCode,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    pub sequence: u64,
    pub event: JournalEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRead {
    pub records: Vec<JournalRecord>,
    /// True only when the bytes end in a structurally valid prefix of the next
    /// file header or frame.  Complete corrupt frames are always errors.
    pub incomplete_tail: bool,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("action journal I/O failed")]
    Io(#[from] io::Error),
    #[error("action journal exceeds its size limit")]
    TooLarge,
    #[error("action journal header is invalid")]
    InvalidFileHeader,
    #[error("action journal frame header is invalid")]
    InvalidFrameHeader,
    #[error("action journal frame sequence is invalid")]
    InvalidSequence,
    #[error("action journal frame payload exceeds its size limit")]
    EventTooLarge,
    #[error("action journal frame checksum is invalid")]
    InvalidChecksum,
    #[error("action journal frame terminator is invalid")]
    InvalidTerminator,
    #[error("action journal event is invalid")]
    InvalidEvent,
    #[error("action journal event transition is invalid")]
    InvalidTransition,
    #[error("action journal writer is poisoned after an uncertain write")]
    WriterPoisoned,
    #[error("action journal has an incomplete tail and cannot be appended")]
    IncompleteTail,
}

/// Create-only append writer.  Every append is one framed event followed by a
/// data sync; an uncertain write poisons the writer so a sequence is never
/// reused after partial I/O.
pub struct ActionJournalWriter {
    file: File,
    next_sequence: u64,
    records: Vec<JournalRecord>,
    poisoned: bool,
}

impl ActionJournalWriter {
    pub fn create(path: &Path) -> Result<Self, JournalError> {
        let fd = fs::open(
            path,
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error())))?;
        let mut file = File::from(fd);
        file.write_all(FILE_MAGIC)?;
        file.sync_all()?;
        sync_parent_directory(path)?;
        Ok(Self {
            file,
            next_sequence: 0,
            records: Vec::new(),
            poisoned: false,
        })
    }

    pub fn open_append(path: &Path) -> Result<Self, JournalError> {
        let parsed = read_journal(path)?;
        if parsed.incomplete_tail {
            return Err(JournalError::IncompleteTail);
        }
        Self::open_with_records(path, parsed.records)
    }

    /// Reopen a journal after a process crash. A structurally valid partial
    /// final frame is truncated back to the last complete, checksummed frame
    /// and synced before new recovery records may be appended. Interior
    /// corruption and a partial file header remain unrecoverable.
    pub fn open_repair_tail(path: &Path) -> Result<Self, JournalError> {
        let parsed = read_journal(path)?;
        if parsed.incomplete_tail {
            let current_len = std::fs::metadata(path)?.len();
            let complete_len = parsed.records.iter().try_fold(
                u64::try_from(FILE_MAGIC.len()).map_err(|_| JournalError::TooLarge)?,
                |length, record| {
                    let frame_len = encode_frame(record.sequence, &record.event)?.len();
                    length
                        .checked_add(u64::try_from(frame_len).map_err(|_| JournalError::TooLarge)?)
                        .ok_or(JournalError::TooLarge)
                },
            )?;
            if current_len < u64::try_from(FILE_MAGIC.len()).map_err(|_| JournalError::TooLarge)?
                || current_len < complete_len
            {
                return Err(JournalError::IncompleteTail);
            }
            let fd = fs::open(
                path,
                OFlags::WRONLY | OFlags::APPEND | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| {
                JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
            })?;
            let file = File::from(fd);
            file.set_len(complete_len)?;
            file.sync_all()?;
        }
        Self::open_with_records(path, parsed.records)
    }

    fn open_with_records(path: &Path, records: Vec<JournalRecord>) -> Result<Self, JournalError> {
        let next_sequence =
            u64::try_from(records.len()).map_err(|_| JournalError::InvalidSequence)?;
        let fd = fs::open(
            path,
            OFlags::WRONLY | OFlags::APPEND | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error())))?;
        Ok(Self {
            file: File::from(fd),
            next_sequence,
            records,
            poisoned: false,
        })
    }

    pub fn append_and_sync(&mut self, event: &JournalEvent) -> Result<u64, JournalError> {
        if self.poisoned {
            return Err(JournalError::WriterPoisoned);
        }
        let sequence = self.next_sequence;
        self.records.push(JournalRecord {
            sequence,
            event: event.clone(),
        });
        if let Err(error) = validate_event_transitions(&self.records) {
            self.records.pop();
            return Err(error);
        }
        let frame = match encode_frame(sequence, event) {
            Ok(frame) => frame,
            Err(error) => {
                self.records.pop();
                return Err(error);
            }
        };
        if let Err(error) = self.file.write_all(&frame) {
            self.poisoned = true;
            return Err(JournalError::Io(error));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::InvalidSequence)?;
        if let Err(error) = self.file.sync_data() {
            self.poisoned = true;
            return Err(JournalError::Io(error));
        }
        Ok(sequence)
    }

    pub fn sync(&mut self) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::WriterPoisoned);
        }
        if let Err(error) = self.file.sync_data() {
            self.poisoned = true;
            return Err(JournalError::Io(error));
        }
        Ok(())
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().ok_or_else(|| {
        JournalError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "action journal requires a parent directory",
        ))
    })?;
    let fd = fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error())))?;
    fs::fsync(fd)
        .map_err(|error| JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error())))
}

pub fn read_journal(path: &Path) -> Result<JournalRead, JournalError> {
    let fd = fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error())))?;
    let mut file = File::from(fd);
    let length = file.metadata()?.len();
    if length > MAX_JOURNAL_BYTES {
        return Err(JournalError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)?;
    parse_journal(&bytes)
}

pub fn parse_journal(bytes: &[u8]) -> Result<JournalRead, JournalError> {
    if bytes.len() < FILE_MAGIC.len() {
        return if FILE_MAGIC.starts_with(bytes) {
            Ok(JournalRead {
                records: Vec::new(),
                incomplete_tail: true,
            })
        } else {
            Err(JournalError::InvalidFileHeader)
        };
    }
    if &bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(JournalError::InvalidFileHeader);
    }

    let mut cursor = FILE_MAGIC.len();
    let mut records = Vec::new();
    let mut expected_sequence = 0_u64;
    while cursor < bytes.len() {
        let remaining = &bytes[cursor..];
        if remaining.len() < FRAME_MAGIC.len() {
            if FRAME_MAGIC.starts_with(remaining) {
                return finish_incomplete(records);
            }
            return Err(JournalError::InvalidFrameHeader);
        }
        if &remaining[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err(JournalError::InvalidFrameHeader);
        }
        if remaining.len() < HEADER_LEN {
            return if valid_partial_header(remaining, expected_sequence) {
                finish_incomplete(records)
            } else {
                Err(JournalError::InvalidFrameHeader)
            };
        }
        let header_fields = &remaining[..HEADER_FIELDS_LEN];
        let version = u16::from_be_bytes(header_fields[4..6].try_into().expect("fixed header"));
        let flags = u16::from_be_bytes(header_fields[6..8].try_into().expect("fixed header"));
        let sequence = u64::from_be_bytes(header_fields[8..16].try_into().expect("fixed header"));
        let payload_len =
            u32::from_be_bytes(header_fields[16..20].try_into().expect("fixed header")) as usize;
        if version != FRAME_VERSION || flags != FRAME_FLAGS {
            return Err(JournalError::InvalidFrameHeader);
        }
        if sequence != expected_sequence {
            return Err(JournalError::InvalidSequence);
        }
        if payload_len > MAX_EVENT_BYTES {
            return Err(JournalError::EventTooLarge);
        }
        let expected_header_checksum = Sha256::digest(header_fields);
        if remaining[HEADER_FIELDS_LEN..HEADER_LEN] != expected_header_checksum[..] {
            return Err(JournalError::InvalidChecksum);
        }
        let frame_len = HEADER_LEN
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(TRAILER_LEN))
            .ok_or(JournalError::EventTooLarge)?;
        if remaining.len() < frame_len {
            return finish_incomplete(records);
        }
        let payload = &remaining[HEADER_LEN..HEADER_LEN + payload_len];
        let checksum_start = HEADER_LEN + payload_len;
        let checksum_end = checksum_start + 32;
        if remaining[checksum_start..checksum_end] != Sha256::digest(payload)[..] {
            return Err(JournalError::InvalidChecksum);
        }
        if &remaining[checksum_end..checksum_end + FRAME_END.len()] != FRAME_END {
            return Err(JournalError::InvalidTerminator);
        }
        let event = serde_json::from_slice(payload).map_err(|_| JournalError::InvalidEvent)?;
        records.push(JournalRecord { sequence, event });
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::InvalidSequence)?;
        cursor += frame_len;
    }
    validate_event_transitions(&records)?;
    Ok(JournalRead {
        records,
        incomplete_tail: false,
    })
}

fn valid_partial_header(bytes: &[u8], expected_sequence: u64) -> bool {
    let mut fixed = Vec::with_capacity(16);
    fixed.extend_from_slice(FRAME_MAGIC);
    fixed.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    fixed.extend_from_slice(&FRAME_FLAGS.to_be_bytes());
    fixed.extend_from_slice(&expected_sequence.to_be_bytes());
    let fixed_len = bytes.len().min(fixed.len());
    if bytes[..fixed_len] != fixed[..fixed_len] {
        return false;
    }
    if bytes.len() < HEADER_FIELDS_LEN {
        return true;
    }
    let payload_len =
        u32::from_be_bytes(bytes[16..20].try_into().expect("complete length field")) as usize;
    if payload_len > MAX_EVENT_BYTES {
        return false;
    }
    let checksum = Sha256::digest(&bytes[..HEADER_FIELDS_LEN]);
    let available_checksum = &bytes[HEADER_FIELDS_LEN..];
    available_checksum == &checksum[..available_checksum.len()]
}

fn finish_incomplete(records: Vec<JournalRecord>) -> Result<JournalRead, JournalError> {
    validate_event_transitions(&records)?;
    Ok(JournalRead {
        records,
        incomplete_tail: true,
    })
}

fn encode_frame(sequence: u64, event: &JournalEvent) -> Result<Vec<u8>, JournalError> {
    let payload = serde_json::to_vec(event).map_err(|_| JournalError::InvalidEvent)?;
    if payload.len() > MAX_EVENT_BYTES {
        return Err(JournalError::EventTooLarge);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| JournalError::EventTooLarge)?;
    let mut header = Vec::with_capacity(HEADER_FIELDS_LEN);
    header.extend_from_slice(FRAME_MAGIC);
    header.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    header.extend_from_slice(&FRAME_FLAGS.to_be_bytes());
    header.extend_from_slice(&sequence.to_be_bytes());
    header.extend_from_slice(&payload_len.to_be_bytes());
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + TRAILER_LEN);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&Sha256::digest(&header));
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&Sha256::digest(&payload));
    frame.extend_from_slice(FRAME_END);
    Ok(frame)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActionProgress {
    Planned,
    Preconditioned,
    Started,
    Applied,
    Fsynced,
    Cleaned,
    RolledBack,
}

fn validate_event_transitions(records: &[JournalRecord]) -> Result<(), JournalError> {
    let Some(JournalRecord {
        event: JournalEvent::PlanPrepared { plan },
        ..
    }) = records.first()
    else {
        return if records.is_empty() {
            Ok(())
        } else {
            Err(JournalError::InvalidTransition)
        };
    };
    let mut progress = plan
        .actions
        .iter()
        .map(|action| (action.id.clone(), ActionProgress::Planned))
        .collect::<BTreeMap<_, _>>();
    let action_by_id = plan
        .actions
        .iter()
        .map(|action| (action.id.clone(), action))
        .collect::<BTreeMap<_, _>>();
    let mut rollback = false;
    let mut verification_started = None;
    let mut verification_completed = None;
    let mut decision = None;
    let mut committed = false;

    for record in records.iter().skip(1) {
        if committed
            && !matches!(
                &record.event,
                JournalEvent::CleanupCompleted { .. } | JournalEvent::FailureRecorded { .. }
            )
        {
            return Err(JournalError::InvalidTransition);
        }
        if committed
            && progress
                .values()
                .all(|value| *value == ActionProgress::Cleaned)
        {
            return Err(JournalError::InvalidTransition);
        }
        if !committed
            && decision.is_some()
            && !matches!(
                &record.event,
                JournalEvent::TransactionCommitted { .. } | JournalEvent::FailureRecorded { .. }
            )
        {
            return Err(JournalError::InvalidTransition);
        }
        match &record.event {
            JournalEvent::PlanPrepared { .. } => return Err(JournalError::InvalidTransition),
            JournalEvent::PreconditionValidated {
                action_id,
                observed_identity,
            } => {
                let action = action_by_id
                    .get(action_id)
                    .ok_or(JournalError::InvalidTransition)?;
                if progress.get(action_id) != Some(&ActionProgress::Planned)
                    || observed_identity != &action.target.expected_identity
                    || rollback
                    || verification_started.is_some()
                {
                    return Err(JournalError::InvalidTransition);
                }
                progress.insert(action_id.clone(), ActionProgress::Preconditioned);
            }
            JournalEvent::ActionStarted { action_id } => {
                if progress.get(action_id) != Some(&ActionProgress::Preconditioned)
                    || rollback
                    || verification_started.is_some()
                {
                    return Err(JournalError::InvalidTransition);
                }
                progress.insert(action_id.clone(), ActionProgress::Started);
            }
            JournalEvent::ActionApplied {
                action_id,
                result_identity,
                artifact_quarantine_id,
            } => {
                let action = action_by_id
                    .get(action_id)
                    .ok_or(JournalError::InvalidTransition)?;
                let expected_quarantine = action.artifact_quarantine_id.as_ref();
                if progress.get(action_id) != Some(&ActionProgress::Started)
                    || !same_file_content(&action.target.expected_identity, result_identity)
                    || artifact_quarantine_id.as_ref() != expected_quarantine
                    || rollback
                    || verification_started.is_some()
                {
                    return Err(JournalError::InvalidTransition);
                }
                progress.insert(action_id.clone(), ActionProgress::Applied);
            }
            JournalEvent::ActionFsynced { action_id } => {
                if progress.get(action_id) != Some(&ActionProgress::Applied) || rollback {
                    return Err(JournalError::InvalidTransition);
                }
                progress.insert(action_id.clone(), ActionProgress::Fsynced);
            }
            JournalEvent::RollbackStarted => {
                if rollback
                    || committed
                    || !progress.values().any(|value| {
                        matches!(
                            value,
                            ActionProgress::Started
                                | ActionProgress::Applied
                                | ActionProgress::Fsynced
                        )
                    })
                {
                    return Err(JournalError::InvalidTransition);
                }
                rollback = true;
            }
            JournalEvent::ActionRolledBack {
                action_id,
                restored_identity,
            } => {
                let action = action_by_id
                    .get(action_id)
                    .ok_or(JournalError::InvalidTransition)?;
                if !rollback
                    || !matches!(
                        progress.get(action_id),
                        Some(ActionProgress::Applied | ActionProgress::Fsynced)
                    )
                    || !same_file_content(&action.target.expected_identity, restored_identity)
                {
                    return Err(JournalError::InvalidTransition);
                }
                progress.insert(action_id.clone(), ActionProgress::RolledBack);
            }
            JournalEvent::VerificationStarted { manifest_identity } => {
                if rollback
                    || verification_started.is_some()
                    || progress
                        .values()
                        .any(|value| *value != ActionProgress::Fsynced)
                {
                    return Err(JournalError::InvalidTransition);
                }
                verification_started = Some(*manifest_identity);
            }
            JournalEvent::VerificationCompleted {
                manifest_identity,
                decision: verification_decision,
            } => {
                if verification_started != Some(*manifest_identity)
                    || verification_completed.is_some()
                    || rollback
                {
                    return Err(JournalError::InvalidTransition);
                }
                verification_completed = Some((*manifest_identity, *verification_decision));
            }
            JournalEvent::CleanupCompleted { action_id, kind } => {
                let action = action_by_id
                    .get(action_id)
                    .ok_or(JournalError::InvalidTransition)?;
                let kind_matches = matches!(
                    (action.kind, kind),
                    (ActionKind::Delete, CleanupKind::DeleteTrashRemoved)
                        | (
                            ActionKind::Quarantine,
                            CleanupKind::ArtifactQuarantineDurable
                        )
                );
                if !committed
                    || progress.get(action_id) != Some(&ActionProgress::Fsynced)
                    || !kind_matches
                    || rollback
                {
                    return Err(JournalError::InvalidTransition);
                }
                progress.insert(action_id.clone(), ActionProgress::Cleaned);
            }
            JournalEvent::DecisionPrepared {
                outcome,
                current_manifest_identity,
            } => {
                if decision.is_some() {
                    return Err(JournalError::InvalidTransition);
                }
                if *outcome == Outcome::AllowModified {
                    let Some((manifest, VerificationDecision::Allow)) = verification_completed
                    else {
                        return Err(JournalError::InvalidTransition);
                    };
                    if current_manifest_identity != &Some(manifest)
                        || progress
                            .values()
                            .any(|value| *value != ActionProgress::Fsynced)
                    {
                        return Err(JournalError::InvalidTransition);
                    }
                } else if !matches!(outcome, Outcome::Error | Outcome::Cancelled) {
                    return Err(JournalError::InvalidTransition);
                }
                decision = Some((*outcome, *current_manifest_identity));
            }
            JournalEvent::TransactionCommitted {
                final_manifest_identity,
            } => {
                if decision != Some((Outcome::AllowModified, Some(*final_manifest_identity))) {
                    return Err(JournalError::InvalidTransition);
                }
                if committed {
                    return Err(JournalError::InvalidTransition);
                }
                committed = true;
            }
            JournalEvent::FailureRecorded { action_id, code } => {
                if action_id
                    .as_ref()
                    .is_some_and(|id| !action_by_id.contains_key(id))
                {
                    return Err(JournalError::InvalidTransition);
                }
                if committed
                    && (*code != JournalFailureCode::CleanupFailed
                        || action_id
                            .as_ref()
                            .is_none_or(|id| progress.get(id) == Some(&ActionProgress::Cleaned)))
                {
                    return Err(JournalError::InvalidTransition);
                }
            }
        }
    }
    Ok(())
}

fn same_file_content(expected: &SourceIdentity, observed: &SourceIdentity) -> bool {
    observed.file_type == expected.file_type
        && observed.link_count == 1
        && observed.byte_len == expected.byte_len
        && observed.content_digest == expected.content_digest
}
