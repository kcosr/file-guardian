//! Aggregate capacity admission and explicit terminal retention maintenance.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::DateTime;
use rustix::fs::{self as rfs, FlockOperation};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::RunId;
use crate::processing::artifact::ArtifactQuarantineStore;
use crate::processing::completion::{
    discard_retained_stage, inspect_job, purge_terminal_job, CompletionError,
};
use crate::processing::config::CompletionDisposition as ConfigDisposition;
use crate::processing::domain::{Disposition, HandoffStatus};
use crate::processing::job::{JobStore, JobStoreError};
use crate::processing::policy::CompiledPolicyDirective;
use crate::processing::report::ProcessingReport;
use crate::processing::runtime::{
    CompiledProcessingRuntime, EffectiveActionMode, FrozenRetentionLimits,
};

const RESERVATION_SCHEMA: &str = "file-guardian-retention-reservation/1";
const RESERVATION_DIRECTORY: &str = ".retention-reservations";
const RETENTION_LOCK: &str = ".lock";
const MAX_MAINTENANCE_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSweep {
    pub expired_jobs: u64,
    pub expired_artifacts: u64,
    pub released_reservations: u64,
}

#[derive(Debug, Error)]
pub enum RetentionError {
    #[error("retention state is unavailable")]
    StateUnavailable,
    #[error("retention capacity is unavailable")]
    CapacityUnavailable,
    #[error("retention state is inconsistent")]
    InconsistentState,
    #[error("retention arithmetic overflowed")]
    Overflow,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationRecord {
    schema_version: String,
    run_id: RunId,
    created_unix_millis: i64,
    available_bytes: u64,
    quarantine_bytes: u64,
    artifact_bytes: u64,
}

impl ReservationRecord {
    fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version != RESERVATION_SCHEMA {
            return Err(RetentionError::InconsistentState);
        }
        Ok(())
    }
}

pub struct RetentionController {
    jobs_root: PathBuf,
    reports_root: PathBuf,
    quarantine_root: PathBuf,
    artifact_root: PathBuf,
    reservation_root: PathBuf,
    limits: FrozenRetentionLimits,
}

pub struct RetentionReservation {
    reservation_root: PathBuf,
    run_id: RunId,
}

impl RetentionController {
    pub fn open(
        store: &JobStore,
        artifact_root: &Path,
        limits: FrozenRetentionLimits,
    ) -> Result<Self, RetentionError> {
        require_private_directory(&store.paths().jobs_root)?;
        require_private_directory(&store.paths().reports_root)?;
        require_private_directory(&store.paths().quarantine_root)?;
        require_private_directory(artifact_root)?;
        let reservation_root = store.paths().jobs_root.join(RESERVATION_DIRECTORY);
        match fs::create_dir(&reservation_root) {
            Ok(()) => fs::set_permissions(&reservation_root, fs::Permissions::from_mode(0o700))
                .map_err(|_| RetentionError::StateUnavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RetentionError::StateUnavailable),
        }
        require_private_directory(&reservation_root)?;
        sync_directory(&store.paths().jobs_root)?;
        Ok(Self {
            jobs_root: store.paths().jobs_root.clone(),
            reports_root: store.paths().reports_root.clone(),
            quarantine_root: store.paths().quarantine_root.clone(),
            artifact_root: artifact_root.to_owned(),
            reservation_root,
            limits,
        })
    }

    pub fn reserve(
        &self,
        store: &JobStore,
        runtime: &CompiledProcessingRuntime,
        now_unix_millis: i64,
    ) -> Result<RetentionReservation, RetentionError> {
        if runtime.jobs.jobs_root != self.jobs_root
            || runtime.jobs.reports_root != self.reports_root
            || runtime.jobs.quarantine_root != self.quarantine_root
            || runtime.jobs.artifact_quarantine_root != self.artifact_root
            || runtime.jobs.retention != self.limits
        {
            return Err(RetentionError::InconsistentState);
        }
        let _lock = self.lock()?;
        let reservations = self.reservations()?;
        if reservations
            .iter()
            .any(|record| record.run_id == runtime.run_id)
        {
            return Err(RetentionError::InconsistentState);
        }

        let reserve_available =
            completion_dispositions(runtime).contains(&ConfigDisposition::Retain);
        let actions_can_mutate = runtime.action_mode == EffectiveActionMode::Apply
            && runtime.policy.bindings.iter().any(|binding| {
                matches!(
                    binding.directive,
                    CompiledPolicyDirective::Delete | CompiledPolicyDirective::Quarantine
                )
            });
        let reserve_quarantine = completion_dispositions(runtime)
            .contains(&ConfigDisposition::Quarantine)
            || actions_can_mutate;
        let reserve_artifact = runtime.action_mode == EffectiveActionMode::Apply
            && runtime
                .policy
                .bindings
                .iter()
                .any(|binding| binding.directive == CompiledPolicyDirective::Quarantine);
        let requested = runtime.jobs.capture.max_total_bytes;
        let record = ReservationRecord {
            schema_version: RESERVATION_SCHEMA.to_owned(),
            run_id: runtime.run_id.clone(),
            created_unix_millis: now_unix_millis,
            available_bytes: if reserve_available { requested } else { 0 },
            quarantine_bytes: if reserve_quarantine { requested } else { 0 },
            artifact_bytes: if reserve_artifact { requested } else { 0 },
        };
        record.validate()?;

        let reserved_available = sum_reservations(&reservations, |value| value.available_bytes)?;
        let reserved_quarantine = sum_reservations(&reservations, |value| value.quarantine_bytes)?;
        let reserved_artifact = sum_reservations(&reservations, |value| value.artifact_bytes)?;
        let reserved_runs = reservations
            .iter()
            .map(|value| value.run_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let available_used = active_stage_bytes(store, &reserved_runs)?;
        let quarantine_used = root_payload_bytes(&self.quarantine_root, &reserved_runs)?;
        let artifact_used = root_file_bytes(&self.artifact_root)?;
        require_capacity(
            available_used,
            reserved_available,
            record.available_bytes,
            self.limits.available_max_bytes,
        )?;
        require_capacity(
            quarantine_used,
            reserved_quarantine,
            record.quarantine_bytes,
            self.limits.quarantine_max_bytes,
        )?;
        require_capacity(
            artifact_used,
            reserved_artifact,
            record.artifact_bytes,
            self.limits.artifact_quarantine_max_bytes,
        )?;
        write_reservation(&self.reservation_root, &record)?;
        Ok(RetentionReservation {
            reservation_root: self.reservation_root.clone(),
            run_id: runtime.run_id.clone(),
        })
    }

    pub fn sweep_expired(
        &self,
        store: &JobStore,
        now_unix_millis: i64,
        stale_after_millis: u64,
    ) -> Result<RetentionSweep, RetentionError> {
        let mut sweep = RetentionSweep::default();
        for run_id in store
            .list_recoverable_run_ids()
            .map_err(|_| RetentionError::StateUnavailable)?
        {
            let status = match inspect_job(store, &run_id) {
                Ok(status) if status.report_published => status,
                _ => continue,
            };
            let report = match read_report(&self.reports_root, &run_id) {
                Ok(report) => report,
                Err(_) => continue,
            };
            let expires = terminal_expiration(&report, status.disposition, self.limits)?;
            if now_unix_millis < expires {
                continue;
            }
            if status.disposition == Disposition::Retained
                && status.handoff != HandoffStatus::HandedOff
            {
                match discard_retained_stage(store, &run_id) {
                    Ok(()) => {}
                    Err(CompletionError::JobStore(JobStoreError::Locked)) => continue,
                    Err(_) => return Err(RetentionError::StateUnavailable),
                }
            }
            match purge_terminal_job(store, &run_id) {
                Ok(()) => {}
                Err(CompletionError::JobStore(JobStoreError::Locked)) => continue,
                Err(_) => return Err(RetentionError::StateUnavailable),
            }
            sweep.expired_jobs = sweep
                .expired_jobs
                .checked_add(1)
                .ok_or(RetentionError::Overflow)?;
        }
        sweep.expired_artifacts = self.sweep_artifacts(now_unix_millis)?;
        sweep.released_reservations =
            self.sweep_reservations(now_unix_millis, stale_after_millis)?;
        Ok(sweep)
    }

    fn sweep_artifacts(&self, now_unix_millis: i64) -> Result<u64, RetentionError> {
        let bindings = artifact_report_bindings(&self.reports_root)?;
        let store = ArtifactQuarantineStore::open(&self.artifact_root, &self.reports_root)
            .map_err(|_| RetentionError::StateUnavailable)?;
        let ttl_millis = ttl_millis(self.limits.artifact_quarantine_ttl_secs)?;
        let mut expired = 0_u64;
        for entry in
            fs::read_dir(&self.artifact_root).map_err(|_| RetentionError::StateUnavailable)?
        {
            let entry = entry.map_err(|_| RetentionError::StateUnavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(RetentionError::InconsistentState);
            };
            let Some(identifier) = name.strip_suffix(".json") else {
                continue;
            };
            let Some((run_id, quarantine_id)) = bindings.get(identifier) else {
                continue;
            };
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| RetentionError::StateUnavailable)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(RetentionError::InconsistentState);
            }
            let modified = metadata
                .modified()
                .map_err(|_| RetentionError::StateUnavailable)?
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| RetentionError::InconsistentState)?
                .as_millis();
            let modified = i64::try_from(modified).map_err(|_| RetentionError::Overflow)?;
            if now_unix_millis < modified.saturating_add(ttl_millis) {
                continue;
            }
            store
                .discard(run_id, quarantine_id)
                .map_err(|_| RetentionError::StateUnavailable)?;
            expired = expired.checked_add(1).ok_or(RetentionError::Overflow)?;
        }
        Ok(expired)
    }

    fn sweep_reservations(
        &self,
        now_unix_millis: i64,
        stale_after_millis: u64,
    ) -> Result<u64, RetentionError> {
        let _lock = self.lock()?;
        let stale_after = i64::try_from(stale_after_millis).unwrap_or(i64::MAX);
        let mut released = 0_u64;
        for record in self.reservations()? {
            let active = self.jobs_root.join(record.run_id.as_str()).exists()
                || self.quarantine_root.join(record.run_id.as_str()).exists();
            let terminal = self
                .reports_root
                .join(format!("{}.json", record.run_id.as_str()))
                .is_file();
            let orphan_stale = !active
                && now_unix_millis >= record.created_unix_millis.saturating_add(stale_after);
            if terminal || orphan_stale {
                remove_reservation(&self.reservation_root, &record.run_id)?;
                released = released.checked_add(1).ok_or(RetentionError::Overflow)?;
            }
        }
        Ok(released)
    }

    fn lock(&self) -> Result<File, RetentionError> {
        let path = self.reservation_root.join(RETENTION_LOCK);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|_| RetentionError::StateUnavailable)?;
        rfs::flock(file.as_fd(), FlockOperation::LockExclusive)
            .map_err(|_| RetentionError::StateUnavailable)?;
        Ok(file)
    }

    fn reservations(&self) -> Result<Vec<ReservationRecord>, RetentionError> {
        let mut records = Vec::new();
        for entry in
            fs::read_dir(&self.reservation_root).map_err(|_| RetentionError::StateUnavailable)?
        {
            let entry = entry.map_err(|_| RetentionError::StateUnavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(RetentionError::InconsistentState);
            };
            if name == RETENTION_LOCK {
                continue;
            }
            if !name.ends_with(".json") || !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                return Err(RetentionError::InconsistentState);
            }
            let bytes = fs::read(entry.path()).map_err(|_| RetentionError::StateUnavailable)?;
            let record: ReservationRecord =
                serde_json::from_slice(&bytes).map_err(|_| RetentionError::InconsistentState)?;
            record.validate()?;
            if name != format!("{}.json", record.run_id.as_str()) {
                return Err(RetentionError::InconsistentState);
            }
            records.push(record);
        }
        records.sort_by(|left, right| left.run_id.cmp(&right.run_id));
        if records
            .windows(2)
            .any(|pair| pair[0].run_id == pair[1].run_id)
        {
            return Err(RetentionError::InconsistentState);
        }
        Ok(records)
    }
}

impl RetentionReservation {
    pub fn release(self) -> Result<(), RetentionError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.reservation_root.join(RETENTION_LOCK))
            .map_err(|_| RetentionError::StateUnavailable)?;
        rfs::flock(file.as_fd(), FlockOperation::LockExclusive)
            .map_err(|_| RetentionError::StateUnavailable)?;
        remove_reservation(&self.reservation_root, &self.run_id)
    }
}

fn completion_dispositions(runtime: &CompiledProcessingRuntime) -> [ConfigDisposition; 5] {
    [
        runtime.completion.allow,
        runtime.completion.allow_modified,
        runtime.completion.deny,
        runtime.completion.error,
        runtime.completion.cancelled,
    ]
}

fn require_capacity(
    used: u64,
    reserved: u64,
    requested: u64,
    limit: u64,
) -> Result<(), RetentionError> {
    let total = used
        .checked_add(reserved)
        .and_then(|value| value.checked_add(requested))
        .ok_or(RetentionError::Overflow)?;
    if total > limit {
        return Err(RetentionError::CapacityUnavailable);
    }
    Ok(())
}

fn sum_reservations(
    values: &[ReservationRecord],
    field: impl Fn(&ReservationRecord) -> u64,
) -> Result<u64, RetentionError> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(field(value))
            .ok_or(RetentionError::Overflow)
    })
}

fn active_stage_bytes(
    store: &JobStore,
    reserved_runs: &BTreeSet<String>,
) -> Result<u64, RetentionError> {
    store
        .list_run_ids()
        .map_err(|_| RetentionError::StateUnavailable)?
        .into_iter()
        .filter(|run_id| !reserved_runs.contains(run_id.as_str()))
        .try_fold(0_u64, |sum, run_id| {
            let stage = store.paths().jobs_root.join(run_id.as_str()).join("stage");
            match fs::symlink_metadata(&stage) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(sum),
                _ => return Err(RetentionError::InconsistentState),
            }
            sum.checked_add(path_bytes(&stage, 0)?)
                .ok_or(RetentionError::Overflow)
        })
}

fn root_payload_bytes(
    root: &Path,
    reserved_runs: &BTreeSet<String>,
) -> Result<u64, RetentionError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root).map_err(|_| RetentionError::StateUnavailable)? {
        let entry = entry.map_err(|_| RetentionError::StateUnavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(RetentionError::InconsistentState);
        };
        if name.starts_with('.') || reserved_runs.contains(name) {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|_| RetentionError::StateUnavailable)?;
        if !kind.is_dir() || kind.is_symlink() {
            return Err(RetentionError::InconsistentState);
        }
        total = total
            .checked_add(path_bytes(&entry.path(), 0)?)
            .ok_or(RetentionError::Overflow)?;
    }
    Ok(total)
}

fn root_file_bytes(root: &Path) -> Result<u64, RetentionError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root).map_err(|_| RetentionError::StateUnavailable)? {
        let entry = entry.map_err(|_| RetentionError::StateUnavailable)?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| RetentionError::StateUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RetentionError::InconsistentState);
        }
        if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or(RetentionError::Overflow)?;
        } else if metadata.is_dir() {
            total = total
                .checked_add(path_bytes(&entry.path(), 0)?)
                .ok_or(RetentionError::Overflow)?;
        }
    }
    Ok(total)
}

fn path_bytes(path: &Path, depth: usize) -> Result<u64, RetentionError> {
    if depth > MAX_MAINTENANCE_DEPTH {
        return Err(RetentionError::InconsistentState);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RetentionError::StateUnavailable)?;
    if metadata.file_type().is_symlink() {
        return Ok(metadata.len());
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Err(RetentionError::InconsistentState);
    }
    fs::read_dir(path)
        .map_err(|_| RetentionError::StateUnavailable)?
        .try_fold(0_u64, |sum, entry| {
            let entry = entry.map_err(|_| RetentionError::StateUnavailable)?;
            sum.checked_add(path_bytes(&entry.path(), depth + 1)?)
                .ok_or(RetentionError::Overflow)
        })
}

fn terminal_expiration(
    report: &ProcessingReport,
    disposition: Disposition,
    limits: FrozenRetentionLimits,
) -> Result<i64, RetentionError> {
    if disposition == Disposition::Retained {
        if let Some(expires_at) = report
            .stage
            .as_ref()
            .and_then(|stage| stage.expires_at.as_ref())
        {
            return parse_timestamp_millis(expires_at.as_str());
        }
    }
    let finished = parse_timestamp_millis(report.finished_at.as_str())?;
    let ttl = match disposition {
        Disposition::Retained | Disposition::Discarded => limits.available_ttl_secs,
        Disposition::Quarantined | Disposition::RetainedError => limits.quarantine_ttl_secs,
    };
    Ok(finished.saturating_add(ttl_millis(ttl)?))
}

fn parse_timestamp_millis(value: &str) -> Result<i64, RetentionError> {
    DateTime::parse_from_rfc3339(value)
        .map_err(|_| RetentionError::InconsistentState)
        .map(|value| value.timestamp_millis())
}

fn ttl_millis(seconds: u64) -> Result<i64, RetentionError> {
    let millis = seconds.checked_mul(1_000).ok_or(RetentionError::Overflow)?;
    i64::try_from(millis).map_err(|_| RetentionError::Overflow)
}

fn read_report(root: &Path, run_id: &RunId) -> Result<ProcessingReport, RetentionError> {
    let bytes = fs::read(root.join(format!("{}.json", run_id.as_str())))
        .map_err(|_| RetentionError::StateUnavailable)?;
    serde_json::from_slice(&bytes).map_err(|_| RetentionError::InconsistentState)
}

fn artifact_report_bindings(
    reports_root: &Path,
) -> Result<BTreeMap<String, (RunId, crate::processing::ArtifactQuarantineId)>, RetentionError> {
    let mut bindings = BTreeMap::new();
    for entry in fs::read_dir(reports_root).map_err(|_| RetentionError::StateUnavailable)? {
        let entry = entry.map_err(|_| RetentionError::StateUnavailable)?;
        if !entry.file_type().is_ok_and(|kind| kind.is_file())
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|_| RetentionError::StateUnavailable)?;
        let report: ProcessingReport = match serde_json::from_slice(&bytes) {
            Ok(report) => report,
            Err(_) => continue,
        };
        let run_id = RunId::new(report.run_id.as_str().to_owned())
            .map_err(|_| RetentionError::InconsistentState)?;
        for action in &report.actions {
            let Some(identifier) = action.artifact_quarantine_id.as_ref() else {
                continue;
            };
            let quarantine_id =
                crate::processing::ArtifactQuarantineId::new(identifier.as_str().to_owned())
                    .map_err(|_| RetentionError::InconsistentState)?;
            if bindings
                .insert(
                    identifier.as_str().to_owned(),
                    (run_id.clone(), quarantine_id),
                )
                .is_some()
            {
                return Err(RetentionError::InconsistentState);
            }
        }
    }
    Ok(bindings)
}

fn write_reservation(root: &Path, record: &ReservationRecord) -> Result<(), RetentionError> {
    let path = root.join(format!("{}.json", record.run_id.as_str()));
    let bytes = serde_json::to_vec(record).map_err(|_| RetentionError::InconsistentState)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| RetentionError::StateUnavailable)?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RetentionError::StateUnavailable)?;
    sync_directory(root)
}

fn remove_reservation(root: &Path, run_id: &RunId) -> Result<(), RetentionError> {
    match fs::remove_file(root.join(format!("{}.json", run_id.as_str()))) {
        Ok(()) => sync_directory(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RetentionError::StateUnavailable),
    }
}

fn require_private_directory(path: &Path) -> Result<(), RetentionError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RetentionError::StateUnavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(RetentionError::StateUnavailable);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), RetentionError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| RetentionError::StateUnavailable)
}
