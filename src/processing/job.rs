//! Durable, owner-only storage for processing jobs.
//!
//! The store keeps an advisory lock for the lifetime of [`JobLease`].  All
//! mutable metadata is replaced descriptor-relatively and made durable with a
//! file sync, rename, and parent-directory sync.

use crate::domain::{Digest, RunId};
use crate::processing::domain::{
    Disposition, HandoffStatus, JobExecutionState, Outcome, TerminalJobState,
};
use crate::processing::report::ProcessingReport;
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use rustix::process::geteuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const JOB_STATE_SCHEMA_VERSION: &str = "1";
const DECISION_SCHEMA_VERSION: &str = "1";
const HEARTBEAT_SCHEMA_VERSION: &str = "1";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const READ_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const WRITE_FILE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const PRIVATE_DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
const PRIVATE_FILE_MODE: Mode = Mode::from_raw_mode(0o600);
const MAX_PRIVATE_JSON_BYTES: u64 = 64 * 1024 * 1024;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Administrator-selected roots used by the durable job store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStorePaths {
    pub jobs_root: PathBuf,
    pub reports_root: PathBuf,
    pub quarantine_root: PathBuf,
}

/// Closed protected root containing a job. Callers cannot supply a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobLocation {
    Active,
    Quarantined,
}

/// Validated process and boot identity recorded in the lease heartbeat.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseIdentity {
    pub process_nonce: String,
    pub boot_nonce: String,
}

impl<'de> Deserialize<'de> for LeaseIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            process_nonce: String,
            boot_nonce: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.process_nonce, wire.boot_nonce).map_err(serde::de::Error::custom)
    }
}

impl LeaseIdentity {
    pub fn new(
        process_nonce: impl Into<String>,
        boot_nonce: impl Into<String>,
    ) -> Result<Self, JobStoreError> {
        let value = Self {
            process_nonce: process_nonce.into(),
            boot_nonce: boot_nonce.into(),
        };
        validate_nonce(&value.process_nonce)?;
        validate_nonce(&value.boot_nonce)?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), JobStoreError> {
        validate_nonce(&self.process_nonce)?;
        validate_nonce(&self.boot_nonce)
    }
}

/// Durable execution state. Outcome, disposition, and handoff remain grouped
/// only in the terminal value and are not inferred from execution state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobStateRecord {
    schema_version: String,
    pub run_id: RunId,
    pub execution: JobExecutionState,
    pub terminal: Option<TerminalJobState>,
    pub revision: u64,
    pub updated_unix_millis: i64,
    pub lease: LeaseIdentity,
}

impl JobStateRecord {
    fn created(run_id: RunId, lease: LeaseIdentity, now_unix_millis: i64) -> Self {
        Self {
            schema_version: JOB_STATE_SCHEMA_VERSION.to_owned(),
            run_id,
            execution: JobExecutionState::Created,
            terminal: None,
            revision: 0,
            updated_unix_millis: now_unix_millis,
            lease,
        }
    }

    fn validate(&self) -> Result<(), JobStoreError> {
        if self.schema_version != JOB_STATE_SCHEMA_VERSION {
            return Err(JobStoreError::SchemaVersion("state.json"));
        }
        self.lease.validate()?;
        if (self.execution == JobExecutionState::Terminal) != self.terminal.is_some() {
            return Err(JobStoreError::InvalidTerminalShape);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for JobStateRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            run_id: RunId,
            execution: JobExecutionState,
            terminal: Option<TerminalJobState>,
            revision: u64,
            updated_unix_millis: i64,
            lease: LeaseIdentity,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            execution: wire.execution,
            terminal: wire.terminal,
            revision: wire.revision,
            updated_unix_millis: wire.updated_unix_millis,
            lease: wire.lease,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRecord {
    schema_version: String,
    pub run_id: RunId,
    pub lease: LeaseIdentity,
    pub sequence: u64,
    pub unix_millis: i64,
}

impl HeartbeatRecord {
    fn new(run_id: RunId, lease: LeaseIdentity, sequence: u64, unix_millis: i64) -> Self {
        Self {
            schema_version: HEARTBEAT_SCHEMA_VERSION.to_owned(),
            run_id,
            lease,
            sequence,
            unix_millis,
        }
    }

    fn validate(&self) -> Result<(), JobStoreError> {
        if self.schema_version != HEARTBEAT_SCHEMA_VERSION {
            return Err(JobStoreError::SchemaVersion("heartbeat"));
        }
        self.lease.validate()
    }
}

impl<'de> Deserialize<'de> for HeartbeatRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            run_id: RunId,
            lease: LeaseIdentity,
            sequence: u64,
            unix_millis: i64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let schema_version = wire.schema_version;
        let value = Self::new(wire.run_id, wire.lease, wire.sequence, wire.unix_millis);
        if value.schema_version != schema_version {
            return Err(serde::de::Error::custom(JobStoreError::SchemaVersion(
                "heartbeat",
            )));
        }
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Configured terminal action captured before disposition begins.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionDisposition {
    Retain,
    Discard,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDispositions {
    configured: DecisionDisposition,
    effective: DecisionDisposition,
}

impl DecisionDispositions {
    pub fn new(
        outcome: Outcome,
        configured: DecisionDisposition,
        effective: DecisionDisposition,
    ) -> Result<Self, JobStoreError> {
        if configured != effective
            && !(matches!(outcome, Outcome::Error | Outcome::Cancelled)
                && effective == DecisionDisposition::Quarantine)
        {
            return Err(JobStoreError::InvalidDispositionOverride);
        }
        Ok(Self {
            configured,
            effective,
        })
    }

    pub const fn configured(self) -> DecisionDisposition {
        self.configured
    }

    pub const fn effective(self) -> DecisionDisposition {
        self.effective
    }
}

impl<'de> Deserialize<'de> for DecisionDispositions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            configured: DecisionDisposition,
            effective: DecisionDisposition,
        }
        let wire = Wire::deserialize(deserializer)?;
        // Outcome-dependent validation is performed by the containing private
        // decision after deserialization.
        Ok(Self {
            configured: wire.configured,
            effective: wire.effective,
        })
    }
}

/// Private, durable proposal used to resume disposition and report publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateDecisionRecord {
    schema_version: String,
    pub run_id: RunId,
    pub proposed_outcome: Outcome,
    pub final_manifest_identity: Option<Digest>,
    pub policy_evidence_identity: Option<Digest>,
    pub dispositions: DecisionDispositions,
    pub public_report_identity: Digest,
    pub draft_report_body: Value,
}

impl PrivateDecisionRecord {
    pub fn new(
        run_id: RunId,
        proposed_outcome: Outcome,
        final_manifest_identity: Option<Digest>,
        policy_evidence_identity: Option<Digest>,
        dispositions: DecisionDispositions,
        public_report_identity: Digest,
        draft_report_body: Value,
    ) -> Result<Self, JobStoreError> {
        let value = Self {
            schema_version: DECISION_SCHEMA_VERSION.to_owned(),
            run_id,
            proposed_outcome,
            final_manifest_identity,
            policy_evidence_identity,
            dispositions,
            public_report_identity,
            draft_report_body,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), JobStoreError> {
        if self.schema_version != DECISION_SCHEMA_VERSION {
            return Err(JobStoreError::SchemaVersion("decision.json"));
        }
        if self.proposed_outcome.is_allowed() && self.policy_evidence_identity.is_none() {
            return Err(JobStoreError::AllowedDecisionMissingEvidence);
        }
        DecisionDispositions::new(
            self.proposed_outcome,
            self.dispositions.configured,
            self.dispositions.effective,
        )?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PrivateDecisionRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            run_id: RunId,
            proposed_outcome: Outcome,
            final_manifest_identity: Option<Digest>,
            policy_evidence_identity: Option<Digest>,
            dispositions: DecisionDispositions,
            public_report_identity: Digest,
            draft_report_body: Value,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            proposed_outcome: wire.proposed_outcome,
            final_manifest_identity: wire.final_manifest_identity,
            policy_evidence_identity: wire.policy_evidence_identity,
            dispositions: wire.dispositions,
            public_report_identity: wire.public_report_identity,
            draft_report_body: wire.draft_report_body,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Fixed paths beneath a validated job directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobPaths {
    root: PathBuf,
}

impl JobPaths {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn stage(&self) -> PathBuf {
        self.root.join("stage")
    }
    pub fn private_root(&self) -> PathBuf {
        self.root.join("private")
    }
    pub fn initial_root(&self) -> PathBuf {
        self.private_root().join("initial")
    }
    pub fn initial_manifest(&self) -> PathBuf {
        self.initial_root().join("manifest")
    }
    pub fn initial_objects(&self) -> PathBuf {
        self.initial_root().join("objects")
    }
    pub fn verification_root(&self) -> PathBuf {
        self.private_root().join("verification")
    }
    pub fn verification_manifest(&self) -> PathBuf {
        self.verification_root().join("manifest")
    }
    pub fn verification_objects(&self) -> PathBuf {
        self.verification_root().join("objects")
    }
    pub fn analyzer_views(&self) -> PathBuf {
        self.private_root().join("analyzer-views")
    }
    pub fn scanner_output(&self) -> PathBuf {
        self.private_root().join("scanner-output")
    }
    pub fn action_journal(&self) -> PathBuf {
        self.private_root().join("action-journal")
    }
    pub fn artifact_quarantine(&self) -> PathBuf {
        self.private_root().join("artifact-quarantine")
    }
    pub fn temporary(&self) -> PathBuf {
        self.private_root().join("tmp")
    }
}

/// A validated durable store. Roots must already exist and be owned by the
/// effective user with no group/world permissions.
pub struct JobStore {
    paths: JobStorePaths,
    jobs_root: OwnedFd,
    reports_root: OwnedFd,
    quarantine_root: OwnedFd,
}

impl JobStore {
    pub fn open(paths: JobStorePaths) -> Result<Self, JobStoreError> {
        if !paths.jobs_root.is_absolute()
            || !paths.reports_root.is_absolute()
            || !paths.quarantine_root.is_absolute()
        {
            return Err(JobStoreError::RootNotAbsolute);
        }
        let (jobs_root, jobs_identity) = open_secure_root(&paths.jobs_root, "jobs root")?;
        let (reports_root, reports_identity) =
            open_secure_root(&paths.reports_root, "reports root")?;
        let (quarantine_root, quarantine_identity) =
            open_secure_root(&paths.quarantine_root, "quarantine root")?;
        let canonical_paths = JobStorePaths {
            jobs_root: canonical_root(&paths.jobs_root, jobs_identity)?,
            reports_root: canonical_root(&paths.reports_root, reports_identity)?,
            quarantine_root: canonical_root(&paths.quarantine_root, quarantine_identity)?,
        };
        if jobs_identity == reports_identity
            || jobs_identity == quarantine_identity
            || reports_identity == quarantine_identity
            || roots_overlap(&canonical_paths.jobs_root, &canonical_paths.reports_root)
            || roots_overlap(&canonical_paths.jobs_root, &canonical_paths.quarantine_root)
            || roots_overlap(
                &canonical_paths.reports_root,
                &canonical_paths.quarantine_root,
            )
        {
            return Err(JobStoreError::AliasedRoots);
        }
        if jobs_identity.0 != quarantine_identity.0 {
            return Err(JobStoreError::QuarantineFilesystemMismatch);
        }
        Ok(Self {
            paths: canonical_paths,
            jobs_root,
            reports_root,
            quarantine_root,
        })
    }

    pub fn paths(&self) -> &JobStorePaths {
        &self.paths
    }

    /// Creates a complete private layout and atomically publishes it as
    /// `jobs/<run-id>` while retaining the exclusive advisory lock.
    pub fn create(
        &self,
        run_id: &RunId,
        lease: LeaseIdentity,
        now_unix_millis: i64,
    ) -> Result<JobLease, JobStoreError> {
        lease.validate()?;
        let temporary_name = next_temporary_name("creating");
        mkdir_private(&self.jobs_root, &temporary_name, "create temporary job")?;
        let temporary =
            open_private_directory(&self.jobs_root, &temporary_name, "open temporary job")?;
        let setup = (|| {
            create_layout(&temporary)?;
            let lock = create_and_lock(&temporary)?;
            let state = JobStateRecord::created(run_id.clone(), lease.clone(), now_unix_millis);
            atomic_replace_json(&temporary, "state.json", &state)?;
            let heartbeat = HeartbeatRecord::new(run_id.clone(), lease, 0, now_unix_millis);
            atomic_replace_json(&temporary, "heartbeat", &heartbeat)?;
            sync_directory(&temporary, "sync new job")?;
            fs::renameat_with(
                &self.jobs_root,
                temporary_name.as_str(),
                &self.jobs_root,
                run_id.as_str(),
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| io_error("publish job", error))?;
            sync_directory(&self.jobs_root, "sync jobs root")?;
            Ok(JobLease {
                run_id: run_id.clone(),
                paths: JobPaths {
                    root: self.paths.jobs_root.join(run_id.as_str()),
                },
                run_dir: temporary,
                _lock: lock,
                state,
                heartbeat,
                location: JobLocation::Active,
            })
        })();
        if setup.is_err() {
            // The temporary name is host-generated and a direct child of the
            // already validated root. It may already have been renamed, in
            // which case this is a harmless NotFound.
            let _ = remove_direct_child_tree(&self.paths.jobs_root, &temporary_name);
        }
        setup
    }

    pub fn try_acquire(&self, run_id: &RunId) -> Result<JobLease, JobStoreError> {
        self.try_acquire_at(run_id, JobLocation::Active)
    }

    pub fn try_acquire_quarantined(&self, run_id: &RunId) -> Result<JobLease, JobStoreError> {
        self.try_acquire_at(run_id, JobLocation::Quarantined)
    }

    pub fn try_acquire_at(
        &self,
        run_id: &RunId,
        location: JobLocation,
    ) -> Result<JobLease, JobStoreError> {
        let (root, root_path) = match location {
            JobLocation::Active => (&self.jobs_root, &self.paths.jobs_root),
            JobLocation::Quarantined => (&self.quarantine_root, &self.paths.quarantine_root),
        };
        let run_dir = open_private_directory(root, run_id.as_str(), "open job")?;
        let lock = open_and_lock(&run_dir)?;
        let state: JobStateRecord = read_json(&run_dir, "state.json")?;
        let heartbeat: HeartbeatRecord = read_json(&run_dir, "heartbeat")?;
        if &state.run_id != run_id || &heartbeat.run_id != run_id {
            return Err(JobStoreError::RunIdentityMismatch);
        }
        Ok(JobLease {
            run_id: run_id.clone(),
            paths: JobPaths {
                root: root_path.join(run_id.as_str()),
            },
            run_dir,
            _lock: lock,
            state,
            heartbeat,
            location,
        })
    }

    /// Attempts to obtain an unlocked job whose durable heartbeat is stale.
    /// Active locks and fresh unlocked jobs are both intentionally skipped.
    pub fn try_acquire_stale(
        &self,
        run_id: &RunId,
        now_unix_millis: i64,
        stale_after_millis: u64,
    ) -> Result<Option<JobLease>, JobStoreError> {
        let lease = match self.try_acquire(run_id) {
            Ok(lease) => lease,
            Err(JobStoreError::Locked) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(lease
            .is_stale(now_unix_millis, stale_after_millis)
            .then_some(lease))
    }

    pub fn try_acquire_quarantined_stale(
        &self,
        run_id: &RunId,
        now_unix_millis: i64,
        stale_after_millis: u64,
    ) -> Result<Option<JobLease>, JobStoreError> {
        let lease = match self.try_acquire_quarantined(run_id) {
            Ok(lease) => lease,
            Err(JobStoreError::Locked) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(lease
            .is_stale(now_unix_millis, stale_after_millis)
            .then_some(lease))
    }

    pub fn list_run_ids(&self) -> Result<Vec<RunId>, JobStoreError> {
        list_run_ids_in(&self.paths.jobs_root, "list jobs")
    }

    pub fn list_recoverable_run_ids(&self) -> Result<Vec<RunId>, JobStoreError> {
        let mut ids = list_run_ids_in(&self.paths.jobs_root, "list jobs")?;
        ids.extend(list_run_ids_in(
            &self.paths.quarantine_root,
            "list quarantined jobs",
        )?);
        ids.sort();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(JobStoreError::DuplicateRunLocation);
        }
        Ok(ids)
    }

    /// Publishes the final report once. Existing paths are never overwritten.
    pub fn publish_report_once(
        &self,
        run_id: &RunId,
        report: &ProcessingReport,
    ) -> Result<PathBuf, JobStoreError> {
        if report.run_id.as_str() != run_id.as_str() {
            return Err(JobStoreError::RunIdentityMismatch);
        }
        let bytes = report
            .to_json_line()
            .map_err(|source| JobStoreError::SerializeReport(Box::new(source)))?;
        let name = format!("{}.json", run_id.as_str());
        atomic_create_bytes(&self.reports_root, &name, &bytes)?;
        Ok(self.paths.reports_root.join(name))
    }
}

fn list_run_ids_in(root: &Path, operation: &'static str) -> Result<Vec<RunId>, JobStoreError> {
    let mut ids = Vec::new();
    for entry in
        std::fs::read_dir(root).map_err(|source| JobStoreError::Io { operation, source })?
    {
        let entry = entry.map_err(|source| JobStoreError::Io { operation, source })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(JobStoreError::UnexpectedRootEntry);
        };
        if name.starts_with('.') {
            continue;
        }
        let run_id = RunId::new(name).map_err(|_| JobStoreError::UnexpectedRootEntry)?;
        let file_type = entry
            .file_type()
            .map_err(|source| JobStoreError::Io { operation, source })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(JobStoreError::UnexpectedRootEntry);
        }
        ids.push(run_id);
    }
    ids.sort();
    Ok(ids)
}

/// Exclusive mutation lease for one job.
pub struct JobLease {
    run_id: RunId,
    paths: JobPaths,
    run_dir: OwnedFd,
    _lock: File,
    state: JobStateRecord,
    heartbeat: HeartbeatRecord,
    location: JobLocation,
}

impl JobLease {
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }
    pub fn paths(&self) -> &JobPaths {
        &self.paths
    }
    pub fn state(&self) -> &JobStateRecord {
        &self.state
    }
    pub fn heartbeat_record(&self) -> &HeartbeatRecord {
        &self.heartbeat
    }
    pub fn location(&self) -> JobLocation {
        self.location
    }

    pub fn heartbeat(&mut self, now_unix_millis: i64) -> Result<(), JobStoreError> {
        self.heartbeat.sequence = self
            .heartbeat
            .sequence
            .checked_add(1)
            .ok_or(JobStoreError::RevisionOverflow)?;
        self.heartbeat.unix_millis = now_unix_millis;
        atomic_replace_json(&self.run_dir, "heartbeat", &self.heartbeat)
    }

    /// Claims the heartbeat for a new process/boot identity after the caller
    /// acquires the lock and classifies the prior heartbeat as stale.
    pub fn claim_lease(
        &mut self,
        lease: LeaseIdentity,
        now_unix_millis: i64,
    ) -> Result<(), JobStoreError> {
        lease.validate()?;
        self.heartbeat.sequence = self
            .heartbeat
            .sequence
            .checked_add(1)
            .ok_or(JobStoreError::RevisionOverflow)?;
        self.heartbeat.lease = lease;
        self.heartbeat.unix_millis = now_unix_millis;
        atomic_replace_json(&self.run_dir, "heartbeat", &self.heartbeat)
    }

    pub fn is_stale(&self, now_unix_millis: i64, stale_after_millis: u64) -> bool {
        let Ok(stale_after) = i64::try_from(stale_after_millis) else {
            return false;
        };
        now_unix_millis.saturating_sub(self.heartbeat.unix_millis) > stale_after
    }

    pub fn transition(
        &mut self,
        next: JobExecutionState,
        now_unix_millis: i64,
    ) -> Result<(), JobStoreError> {
        if !normal_transition(self.state.execution, next) {
            return Err(JobStoreError::InvalidTransition {
                from: self.state.execution,
                to: next,
            });
        }
        if next == JobExecutionState::PreparingDecision {
            let decision = self.read_decision()?;
            if decision.run_id != self.run_id {
                return Err(JobStoreError::RunIdentityMismatch);
            }
        }
        self.persist_state(next, None, now_unix_millis)
    }

    /// Enters decision preparation from any pre-decision phase, but only after
    /// an exact private decision has been durably recorded.
    pub fn enter_preparing_decision(&mut self, now_unix_millis: i64) -> Result<(), JobStoreError> {
        if matches!(
            self.state.execution,
            JobExecutionState::PreparingDecision
                | JobExecutionState::Disposing
                | JobExecutionState::PublishingReport
                | JobExecutionState::Terminal
        ) {
            return Err(JobStoreError::InvalidTransition {
                from: self.state.execution,
                to: JobExecutionState::PreparingDecision,
            });
        }
        let decision = self.read_decision()?;
        if decision.run_id != self.run_id {
            return Err(JobStoreError::RunIdentityMismatch);
        }
        self.persist_state(JobExecutionState::PreparingDecision, None, now_unix_millis)
    }

    pub fn finish_terminal(
        &mut self,
        terminal: TerminalJobState,
        now_unix_millis: i64,
    ) -> Result<(), JobStoreError> {
        if self.state.execution != JobExecutionState::PublishingReport {
            return Err(JobStoreError::InvalidTransition {
                from: self.state.execution,
                to: JobExecutionState::Terminal,
            });
        }
        self.persist_state(JobExecutionState::Terminal, Some(terminal), now_unix_millis)
    }

    /// Durably advances the lifecycle of a terminal retained stage.
    ///
    /// Processing outcome is immutable after report publication. The only
    /// permitted post-terminal changes consume an available/retained stage by
    /// handing it off or discard any retained stage. This keeps the canonical
    /// job state aligned with the mutable auxiliary completion status without
    /// permitting a second processing outcome or disposition.
    pub fn advance_terminal_stage(
        &mut self,
        disposition: Disposition,
        handoff: HandoffStatus,
        now_unix_millis: i64,
    ) -> Result<(), JobStoreError> {
        let current = self
            .state
            .terminal
            .ok_or(JobStoreError::TerminalStageTransition)?;
        let permitted = current.disposition == Disposition::Retained
            && matches!(
                (current.handoff, disposition, handoff),
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
        if !permitted {
            return Err(JobStoreError::TerminalStageTransition);
        }
        let terminal = TerminalJobState::new(current.outcome, disposition, handoff)
            .map_err(|_| JobStoreError::TerminalStageTransition)?;
        self.persist_state(JobExecutionState::Terminal, Some(terminal), now_unix_millis)
    }

    pub fn write_decision(&self, decision: &PrivateDecisionRecord) -> Result<(), JobStoreError> {
        if decision.run_id != self.run_id {
            return Err(JobStoreError::RunIdentityMismatch);
        }
        decision.validate()?;
        atomic_create_json(&self.run_dir, "decision.json", decision)
    }

    pub fn read_decision(&self) -> Result<PrivateDecisionRecord, JobStoreError> {
        let decision: PrivateDecisionRecord = read_json(&self.run_dir, "decision.json")?;
        if decision.run_id != self.run_id {
            return Err(JobStoreError::RunIdentityMismatch);
        }
        Ok(decision)
    }

    pub fn recovery_directive(&self) -> RecoveryDirective {
        RecoveryDirective::for_state(&self.state)
    }

    fn persist_state(
        &mut self,
        execution: JobExecutionState,
        terminal: Option<TerminalJobState>,
        now_unix_millis: i64,
    ) -> Result<(), JobStoreError> {
        let mut candidate = self.state.clone();
        candidate.execution = execution;
        candidate.terminal = terminal;
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or(JobStoreError::RevisionOverflow)?;
        candidate.updated_unix_millis = now_unix_millis;
        candidate.validate()?;
        atomic_replace_json(&self.run_dir, "state.json", &candidate)?;
        self.state = candidate;
        Ok(())
    }
}

/// Fail-closed recovery classification for every durable execution state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDirective {
    FailAcquisition,
    FailAnalysis,
    RecoverActionsAndQuarantine,
    ValidateResolutionAndRecapture,
    ResumeRecordedDisposition,
    ResumeDisposition,
    ResumeReportPublication,
    PreserveRetained,
    GarbageCollectTombstone,
    PreserveQuarantined,
    PreserveRetainedError,
}

impl RecoveryDirective {
    pub fn for_state(state: &JobStateRecord) -> Self {
        use JobExecutionState as S;
        match state.execution {
            S::Created | S::Acquiring => Self::FailAcquisition,
            S::Acquired | S::BaselineCaptured | S::AnalyzingInitial | S::ResolvingInitial => {
                Self::FailAnalysis
            }
            S::PlanningActions
            | S::ApplyingActions
            | S::CapturingVerification
            | S::AnalyzingVerification
            | S::ResolvingVerification => Self::RecoverActionsAndQuarantine,
            S::RevalidatingFinal | S::Sealing => Self::ValidateResolutionAndRecapture,
            S::PreparingDecision => Self::ResumeRecordedDisposition,
            S::Disposing => Self::ResumeDisposition,
            S::PublishingReport => Self::ResumeReportPublication,
            S::Terminal => match state
                .terminal
                .as_ref()
                .expect("validated terminal state always has terminal fields")
            {
                TerminalJobState {
                    disposition: Disposition::Retained,
                    handoff: HandoffStatus::Available | HandoffStatus::Unavailable,
                    ..
                } => Self::PreserveRetained,
                TerminalJobState {
                    disposition: Disposition::Retained,
                    handoff: HandoffStatus::HandedOff,
                    ..
                }
                | TerminalJobState {
                    disposition: Disposition::Discarded,
                    ..
                } => Self::GarbageCollectTombstone,
                TerminalJobState {
                    disposition: Disposition::Quarantined,
                    ..
                } => Self::PreserveQuarantined,
                TerminalJobState {
                    disposition: Disposition::RetainedError,
                    ..
                } => Self::PreserveRetainedError,
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum JobStoreError {
    #[error("job store roots must be absolute")]
    RootNotAbsolute,
    #[error("job store root is not owned by the effective user or has group/world access")]
    InsecureRoot,
    #[error("job directory or file is not owner-only")]
    InsecureJobEntry,
    #[error("job store roots alias one another")]
    AliasedRoots,
    #[error("jobs and quarantine roots must be on the same filesystem")]
    QuarantineFilesystemMismatch,
    #[error("unexpected entry in protected jobs root")]
    UnexpectedRootEntry,
    #[error("a run identity exists in both active and quarantine roots")]
    DuplicateRunLocation,
    #[error("job is already locked by another process")]
    Locked,
    #[error("run identity does not match its containing job")]
    RunIdentityMismatch,
    #[error("invalid lease nonce")]
    InvalidNonce,
    #[error("invalid schema version in {0}")]
    SchemaVersion(&'static str),
    #[error("terminal fields must exist if and only if execution is terminal")]
    InvalidTerminalShape,
    #[error("invalid post-terminal retained-stage transition")]
    TerminalStageTransition,
    #[error("an allowed private decision must bind policy evidence")]
    AllowedDecisionMissingEvidence,
    #[error("only error or cancelled decisions may override disposition to quarantine")]
    InvalidDispositionOverride,
    #[error("invalid job transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: JobExecutionState,
        to: JobExecutionState,
    },
    #[error("job revision or heartbeat sequence overflow")]
    RevisionOverflow,
    #[error("private JSON exceeds the configured safety bound")]
    JsonTooLarge,
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("processing report serialization failed: {0}")]
    SerializeReport(Box<crate::processing::report::ReportError>),
    #[error("{operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

fn validate_nonce(value: &str) -> Result<(), JobStoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(JobStoreError::InvalidNonce);
    }
    Ok(())
}

fn normal_transition(from: JobExecutionState, to: JobExecutionState) -> bool {
    use JobExecutionState as S;
    matches!(
        (from, to),
        (S::Created, S::Acquiring)
            | (S::Acquiring, S::Acquired)
            | (S::Acquired, S::BaselineCaptured)
            | (S::BaselineCaptured, S::AnalyzingInitial)
            | (S::AnalyzingInitial, S::ResolvingInitial)
            | (
                S::ResolvingInitial,
                S::PlanningActions | S::RevalidatingFinal
            )
            | (S::PlanningActions, S::ApplyingActions)
            | (S::ApplyingActions, S::CapturingVerification)
            | (S::CapturingVerification, S::AnalyzingVerification)
            | (S::AnalyzingVerification, S::ResolvingVerification)
            | (S::ResolvingVerification, S::RevalidatingFinal)
            | (S::RevalidatingFinal, S::Sealing)
            | (S::Sealing, S::PreparingDecision)
            | (S::PreparingDecision, S::Disposing)
            | (S::Disposing, S::PublishingReport)
    )
}

fn create_layout(run_dir: &OwnedFd) -> Result<(), JobStoreError> {
    for name in ["stage", "private"] {
        mkdir_private(run_dir, name, "create job layout")?;
    }
    let private = open_private_directory(run_dir, "private", "open private job layout")?;
    for name in [
        "initial",
        "verification",
        "analyzer-views",
        "scanner-output",
        "action-journal",
        "artifact-quarantine",
        "tmp",
    ] {
        mkdir_private(&private, name, "create private job layout")?;
    }
    for phase_name in ["initial", "verification"] {
        let phase = open_private_directory(&private, phase_name, "open phase job layout")?;
        for name in ["manifest", "objects"] {
            mkdir_private(&phase, name, "create phase job layout")?;
        }
    }
    Ok(())
}

fn open_secure_root(
    path: &Path,
    operation: &'static str,
) -> Result<(OwnedFd, (u64, u64)), JobStoreError> {
    let fd = fs::open(path, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error(operation, error))?;
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect store root", error))?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err(JobStoreError::InsecureRoot);
    }
    #[cfg(target_os = "macos")]
    let device = u64::try_from(stat.st_dev).map_err(|_| JobStoreError::InsecureRoot)?;
    #[cfg(not(target_os = "macos"))]
    let device = stat.st_dev;
    Ok((fd, (device, stat.st_ino)))
}

fn canonical_root(path: &Path, expected: (u64, u64)) -> Result<PathBuf, JobStoreError> {
    let canonical = std::fs::canonicalize(path).map_err(|source| JobStoreError::Io {
        operation: "canonicalize store root",
        source,
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|source| JobStoreError::Io {
        operation: "inspect canonical store root",
        source,
    })?;
    if (metadata.dev(), metadata.ino()) != expected {
        return Err(JobStoreError::InsecureRoot);
    }
    Ok(canonical)
}

fn roots_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn mkdir_private<Fd: std::os::fd::AsFd>(
    parent: &Fd,
    name: &str,
    operation: &'static str,
) -> Result<(), JobStoreError> {
    fs::mkdirat(parent, name, PRIVATE_DIRECTORY_MODE)
        .map_err(|error| io_error(operation, error))?;
    let fd = open_private_directory(parent, name, operation)?;
    fs::fchmod(&fd, PRIVATE_DIRECTORY_MODE)
        .map_err(|error| io_error("set private directory mode", error))?;
    sync_directory(parent, "sync directory creation")
}

fn open_private_directory<Fd: std::os::fd::AsFd>(
    parent: &Fd,
    name: &str,
    operation: &'static str,
) -> Result<OwnedFd, JobStoreError> {
    let fd = fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error(operation, error))?;
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect private directory", error))?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err(JobStoreError::InsecureJobEntry);
    }
    Ok(fd)
}

fn create_and_lock(run_dir: &OwnedFd) -> Result<File, JobStoreError> {
    let fd = fs::openat(run_dir, "lock", WRITE_FILE_FLAGS, PRIVATE_FILE_MODE)
        .map_err(|error| io_error("create job lock", error))?;
    fs::fchmod(&fd, PRIVATE_FILE_MODE).map_err(|error| io_error("set lock mode", error))?;
    let file = File::from(fd);
    lock_file(&file)?;
    file.sync_all().map_err(|source| JobStoreError::Io {
        operation: "sync job lock",
        source,
    })?;
    sync_directory(run_dir, "sync job lock creation")?;
    Ok(file)
}

fn open_and_lock(run_dir: &OwnedFd) -> Result<File, JobStoreError> {
    let fd = fs::openat(
        run_dir,
        "lock",
        OFlags::RDWR.union(OFlags::CLOEXEC).union(OFlags::NOFOLLOW),
        Mode::empty(),
    )
    .map_err(|error| io_error("open job lock", error))?;
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect job lock", error))?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != 0o600 || stat.st_nlink != 1 {
        return Err(JobStoreError::InsecureJobEntry);
    }
    let file = File::from(fd);
    lock_file(&file)?;
    Ok(file)
}

fn lock_file(file: &File) -> Result<(), JobStoreError> {
    match fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Err(JobStoreError::Locked),
        Err(error) => Err(io_error("lock job", error)),
    }
}

fn atomic_replace_json<T: Serialize>(
    directory: &OwnedFd,
    name: &str,
    value: &T,
) -> Result<(), JobStoreError> {
    let bytes = serde_json::to_vec(value)?;
    let temporary = write_temporary(directory, name, &bytes)?;
    let result = fs::renameat(directory, temporary.as_str(), directory, name)
        .map_err(|error| io_error("replace durable metadata", error));
    if result.is_err() {
        let _ = fs::unlinkat(directory, temporary.as_str(), AtFlags::empty());
    }
    result?;
    sync_directory(directory, "sync metadata replacement")
}

fn atomic_create_json<T: Serialize>(
    directory: &OwnedFd,
    name: &str,
    value: &T,
) -> Result<(), JobStoreError> {
    let bytes = serde_json::to_vec(value)?;
    atomic_create_bytes(directory, name, &bytes)
}

fn atomic_create_bytes(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), JobStoreError> {
    let temporary = write_temporary(directory, name, bytes)?;
    let result = fs::renameat_with(
        directory,
        temporary.as_str(),
        directory,
        name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| io_error("publish immutable file", error));
    if result.is_err() {
        let _ = fs::unlinkat(directory, temporary.as_str(), AtFlags::empty());
    }
    result?;
    sync_directory(directory, "sync immutable publication")
}

fn write_temporary(
    directory: &OwnedFd,
    target_name: &str,
    bytes: &[u8],
) -> Result<String, JobStoreError> {
    if bytes.len() as u64 > MAX_PRIVATE_JSON_BYTES {
        return Err(JobStoreError::JsonTooLarge);
    }
    let temporary = format!(".{}.{}", target_name, next_temporary_name("tmp"));
    let fd = fs::openat(
        directory,
        temporary.as_str(),
        WRITE_FILE_FLAGS,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| io_error("create metadata temporary", error))?;
    fs::fchmod(&fd, PRIVATE_FILE_MODE).map_err(|error| io_error("set metadata mode", error))?;
    let mut file = File::from(fd);
    let result = (|| {
        file.write_all(bytes).map_err(|source| JobStoreError::Io {
            operation: "write durable metadata",
            source,
        })?;
        file.sync_all().map_err(|source| JobStoreError::Io {
            operation: "sync durable metadata",
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::unlinkat(directory, temporary.as_str(), AtFlags::empty());
    }
    result?;
    Ok(temporary)
}

fn read_json<T: DeserializeOwned>(directory: &OwnedFd, name: &str) -> Result<T, JobStoreError> {
    let fd = fs::openat(directory, name, READ_FILE_FLAGS, Mode::empty())
        .map_err(|error| io_error("open durable metadata", error))?;
    let stat = fs::fstat(&fd).map_err(|error| io_error("inspect durable metadata", error))?;
    if stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || u64::try_from(stat.st_size).map_or(true, |size| size > MAX_PRIVATE_JSON_BYTES)
    {
        return Err(JobStoreError::InsecureJobEntry);
    }
    serde_json::from_reader(File::from(fd)).map_err(JobStoreError::from)
}

fn sync_directory<Fd: std::os::fd::AsFd>(
    directory: &Fd,
    operation: &'static str,
) -> Result<(), JobStoreError> {
    fs::fsync(directory).map_err(|error| io_error(operation, error))
}

fn next_temporary_name(kind: &str) -> String {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{kind}-{}-{counter}", std::process::id())
}

fn remove_direct_child_tree(root: &Path, name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || !name.starts_with('.')
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe child"));
    }
    std::fs::remove_dir_all(root.join(name))
}

fn io_error(operation: &'static str, error: rustix::io::Errno) -> JobStoreError {
    JobStoreError::Io {
        operation,
        source: io::Error::from_raw_os_error(error.raw_os_error()),
    }
}

pub fn system_time_unix_millis() -> Result<i64, JobStoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| JobStoreError::Io {
            operation: "read system clock",
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })?;
    i64::try_from(duration.as_millis()).map_err(|_| JobStoreError::RevisionOverflow)
}
