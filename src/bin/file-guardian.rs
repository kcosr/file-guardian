use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;
use cron::Schedule;
use file_guardian::cli::{
    ActionMode, Args, ArtifactCommand, Command, DaemonArgs, JobCommand, ProcessArgs, ProcessSource,
    StageCommand,
};
use file_guardian::domain::RunId;
use file_guardian::processing::acquisition::local::AcquisitionCancellation;
use file_guardian::processing::artifact::{ArtifactQuarantineError, ArtifactQuarantineStore};
use file_guardian::processing::completion::{
    discard_retained_stage, handoff_stage, inspect_job, recover_job,
    HandoffMode as CompletionHandoffMode,
};
use file_guardian::processing::config::{
    DaemonJob, DaemonOverlap, DaemonSource, ProcessingConfigFile,
};
use file_guardian::processing::engine::{ProcessingEngine, ProcessingEngineRequest};
use file_guardian::processing::job::{
    system_time_unix_millis, JobStore, JobStorePaths, LeaseIdentity,
};
use file_guardian::processing::report::{
    IssueSummary, OmissionSummary, PersistenceStatus, PhasesSummary, ProcessingOutcome,
    ProcessingReport, ProcessingReportData, ProcessingStatistics, Rfc3339Timestamp, SafeId,
};
use file_guardian::processing::runtime::{
    compile_processing_runtime, ProcessingCompileRequest, ProcessingSourceRequest,
    RequestedActionMode,
};
use file_guardian::processing::ArtifactQuarantineId;
use file_guardian::runtime::secure_run_id;
use serde::Serialize;
use std::str::FromStr;
use tokio::sync::mpsc;

const DEFAULT_CONFIG_PATH: &str = "/etc/file-guardian/config.toml";

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    run(args).await
}

async fn run(args: Args) -> ExitCode {
    // A syntactically valid command always receives an in-memory host identity
    // before configuration is opened. Auxiliary commands may replace it with a
    // caller-supplied, report-safe durable run ID, but unsafe operands are never
    // reflected into machine output.
    let generated_run_id = match secure_run_id() {
        Ok(run_id) => run_id,
        Err(_) => match RunId::from_suffix("startup-error") {
            Ok(run_id) => run_id,
            Err(_) => return report_construction_failure(),
        },
    };
    let generated_safe_id = match SafeId::new(generated_run_id.as_str().to_owned()) {
        Ok(run_id) => run_id,
        Err(_) => return report_construction_failure(),
    };
    let run_id = command_run_id(&args.command)
        .and_then(|value| RunId::new(value.to_owned()).ok())
        .and_then(|value| SafeId::new(value.as_str().to_owned()).ok())
        .unwrap_or(generated_safe_id);
    let request_id = command_request_id(&args.command);

    let config = match load_config(args.config.as_deref()) {
        Ok(config) => config,
        Err(()) => {
            return match &args.command {
                Command::Process(_) | Command::Daemon(_) => {
                    emit_error_report(run_id, request_id, "configuration_failure")
                }
                _ => emit_auxiliary_error(&args.command, run_id, "configuration_failure"),
            }
        }
    };

    match args.command {
        Command::Process(process) => {
            run_process(&config, generated_run_id, run_id, request_id, process).await
        }
        Command::Stage(stage) => match stage.command {
            StageCommand::Discard(arguments) => {
                run_stage_discard(&config, run_id, &arguments.run_id)
            }
            StageCommand::Handoff(arguments) => run_stage_handoff(&config, run_id, arguments),
        },
        Command::Job(job) => match job.command {
            JobCommand::Inspect(arguments) => run_job_inspect(&config, run_id, &arguments.run_id),
            JobCommand::Recover => run_job_recover(&config, run_id),
        },
        Command::Artifact(artifact) => match artifact.command {
            ArtifactCommand::Inspect(arguments) => {
                run_artifact_inspect(&config, run_id, &arguments.run_id, &arguments.quarantine_id)
            }
            ArtifactCommand::Recover(arguments) => run_artifact_recover(
                &config,
                run_id,
                &arguments.run_id,
                &arguments.quarantine_id,
                &arguments.destination,
            ),
            ArtifactCommand::Discard(arguments) => {
                run_artifact_discard(&config, run_id, &arguments.run_id, &arguments.quarantine_id)
            }
        },
        Command::Daemon(arguments) => run_daemon(config, run_id, arguments).await,
    }
}

fn run_artifact_inspect(
    config: &ProcessingConfigFile,
    report_run_id: SafeId,
    run_id: &str,
    quarantine_id: &str,
) -> ExitCode {
    let Some((store, run_id, quarantine_id)) = artifact_operands(config, run_id, quarantine_id)
    else {
        return emit_auxiliary_error_name(
            "artifact_inspect",
            report_run_id,
            "invalid_artifact_identity",
        );
    };
    match store.inspect(&run_id, &quarantine_id) {
        Ok(record) => write_auxiliary(
            &AuxiliaryResult::completed("artifact_inspect", report_run_id, Some(record)),
            0,
        ),
        Err(ArtifactQuarantineError::Unavailable | ArtifactQuarantineError::ReportBinding) => {
            write_auxiliary(
                &AuxiliaryResult::<serde_json::Value>::inapplicable(
                    "artifact_inspect",
                    report_run_id,
                    "artifact_unavailable",
                ),
                20,
            )
        }
        Err(_) => emit_auxiliary_error_name("artifact_inspect", report_run_id, "operation_failure"),
    }
}

fn run_artifact_recover(
    config: &ProcessingConfigFile,
    report_run_id: SafeId,
    run_id: &str,
    quarantine_id: &str,
    destination: &Path,
) -> ExitCode {
    let Some((store, run_id, quarantine_id)) = artifact_operands(config, run_id, quarantine_id)
    else {
        return emit_auxiliary_error_name(
            "artifact_recover",
            report_run_id,
            "invalid_artifact_identity",
        );
    };
    match store.recover(&run_id, &quarantine_id, destination) {
        Ok(receipt) => write_auxiliary(
            &AuxiliaryResult::completed("artifact_recover", report_run_id, Some(receipt)),
            0,
        ),
        Err(
            ArtifactQuarantineError::Unavailable
            | ArtifactQuarantineError::ReportBinding
            | ArtifactQuarantineError::DestinationExists,
        ) => write_auxiliary(
            &AuxiliaryResult::<serde_json::Value>::inapplicable(
                "artifact_recover",
                report_run_id,
                "artifact_or_destination_unavailable",
            ),
            20,
        ),
        Err(_) => emit_auxiliary_error_name("artifact_recover", report_run_id, "operation_failure"),
    }
}

fn run_artifact_discard(
    config: &ProcessingConfigFile,
    report_run_id: SafeId,
    run_id: &str,
    quarantine_id: &str,
) -> ExitCode {
    let Some((store, run_id, quarantine_id)) = artifact_operands(config, run_id, quarantine_id)
    else {
        return emit_auxiliary_error_name(
            "artifact_discard",
            report_run_id,
            "invalid_artifact_identity",
        );
    };
    match store.discard(&run_id, &quarantine_id) {
        Ok(receipt) => write_auxiliary(
            &AuxiliaryResult::completed("artifact_discard", report_run_id, Some(receipt)),
            0,
        ),
        Err(ArtifactQuarantineError::ReportBinding) => write_auxiliary(
            &AuxiliaryResult::<serde_json::Value>::inapplicable(
                "artifact_discard",
                report_run_id,
                "artifact_unavailable",
            ),
            20,
        ),
        Err(_) => emit_auxiliary_error_name("artifact_discard", report_run_id, "operation_failure"),
    }
}

fn artifact_operands(
    config: &ProcessingConfigFile,
    run_id: &str,
    quarantine_id: &str,
) -> Option<(ArtifactQuarantineStore, RunId, ArtifactQuarantineId)> {
    let run_id = RunId::new(run_id.to_owned()).ok()?;
    let quarantine_id = ArtifactQuarantineId::new(quarantine_id.to_owned()).ok()?;
    let store = ArtifactQuarantineStore::open(
        &config.processing.jobs.artifact_quarantine_root,
        &config.processing.jobs.reports_root,
    )
    .ok()?;
    Some((store, run_id, quarantine_id))
}

fn run_stage_handoff(
    config: &ProcessingConfigFile,
    report_run_id: SafeId,
    arguments: file_guardian::cli::StageHandoffArgs,
) -> ExitCode {
    let Some(run_id) = parse_run_id(&arguments.run_id) else {
        return emit_auxiliary_error_name("stage_handoff", report_run_id, "invalid_run_id");
    };
    let store = match open_job_store(config) {
        Ok(store) => store,
        Err(()) => {
            return emit_auxiliary_error_name(
                "stage_handoff",
                report_run_id,
                "job_store_unavailable",
            )
        }
    };
    let mode = match arguments.mode {
        file_guardian::cli::HandoffMode::Move => CompletionHandoffMode::Move,
        file_guardian::cli::HandoffMode::Copy => CompletionHandoffMode::Copy,
    };
    match handoff_stage(
        &store,
        &run_id,
        &arguments.destination,
        mode,
        &AcquisitionCancellation::default(),
    ) {
        Ok(receipt) => write_auxiliary(
            &AuxiliaryResult::completed("stage_handoff", report_run_id, Some(receipt)),
            0,
        ),
        Err(
            file_guardian::processing::completion::CompletionError::HandoffUnavailable
            | file_guardian::processing::completion::CompletionError::DestinationExists
            | file_guardian::processing::completion::CompletionError::HandoffIntentMismatch
            | file_guardian::processing::completion::CompletionError::CrossFilesystemMove,
        ) => write_auxiliary(
            &AuxiliaryResult::<serde_json::Value>::inapplicable(
                "stage_handoff",
                report_run_id,
                "handoff_unavailable",
            ),
            20,
        ),
        Err(_) => emit_auxiliary_error_name("stage_handoff", report_run_id, "operation_failure"),
    }
}

async fn run_process(
    config: &ProcessingConfigFile,
    domain_run_id: RunId,
    report_run_id: SafeId,
    request_id: Option<SafeId>,
    arguments: ProcessArgs,
) -> ExitCode {
    let engine_request_id = arguments.request_id.clone();
    let source = match arguments.source {
        ProcessSource::Path(arguments) => ProcessingSourceRequest::Path {
            path: arguments.path,
        },
        ProcessSource::Git(arguments) => ProcessingSourceRequest::Git {
            remote: arguments.remote,
            reference: arguments.checkout_ref,
        },
    };
    let action_mode = arguments.action_mode.map(|mode| match mode {
        ActionMode::Evaluate => RequestedActionMode::Evaluate,
        ActionMode::Apply => RequestedActionMode::Apply,
    });
    let request = ProcessingCompileRequest {
        run_id: domain_run_id,
        profile_id: arguments.profile,
        action_mode,
        source,
    };
    match execute_processing(
        config,
        request,
        engine_request_id,
        AcquisitionCancellation::default(),
    )
    .await
    {
        Ok(report) => write_report(&mut io::stdout().lock(), &report),
        Err(issue_code) => emit_error_report(report_run_id, request_id, issue_code),
    }
}

async fn execute_processing(
    config: &ProcessingConfigFile,
    request: ProcessingCompileRequest,
    request_id: Option<String>,
    cancellation: AcquisitionCancellation,
) -> Result<ProcessingReport, &'static str> {
    let runtime = Arc::new(
        compile_processing_runtime(config, request).map_err(|_| "runtime_compilation_failure")?,
    );
    let store = Arc::new(
        JobStore::open(JobStorePaths {
            jobs_root: runtime.jobs.jobs_root.clone(),
            reports_root: runtime.jobs.reports_root.clone(),
            quarantine_root: runtime.jobs.quarantine_root.clone(),
        })
        .map_err(|_| "job_store_unavailable")?,
    );
    let lease_identity = recovery_lease_identity().map_err(|_| "processing_identity_failure")?;
    let engine = ProcessingEngine::new(runtime, store, lease_identity, cancellation)
        .map_err(|_| "engine_setup_failure")?;
    engine
        .process(ProcessingEngineRequest { request_id })
        .await
        .map_err(|_| "processing_execution_failure")
}

async fn run_daemon(
    config: ProcessingConfigFile,
    startup_run_id: SafeId,
    arguments: DaemonArgs,
) -> ExitCode {
    let selected = match select_daemon_jobs(&config, &arguments.jobs) {
        Ok(selected) => selected,
        Err(issue) => return emit_error_report(startup_run_id, None, issue),
    };
    for job in &selected {
        let run_id = match secure_run_id() {
            Ok(run_id) => run_id,
            Err(_) => {
                return emit_error_report(startup_run_id, None, "processing_identity_failure")
            }
        };
        if compile_processing_runtime(&config, daemon_compile_request(run_id, job)).is_err() {
            return emit_error_report(startup_run_id, None, "daemon_preflight_failure");
        }
    }

    let now = Utc::now();
    let mut jobs = match selected
        .into_iter()
        .map(|job| ScheduledDaemonJob::new(job, now))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(jobs) => jobs,
        Err(issue) => return emit_error_report(startup_run_id, None, issue),
    };
    let config = Arc::new(config);
    let (completed_tx, mut completed_rx) = mpsc::channel::<DaemonCompletion>(jobs.len().max(1));
    for job in &mut jobs {
        if job.definition.run_on_start && job.request_trigger() == DaemonTrigger::Start {
            spawn_daemon_job(Arc::clone(&config), job, completed_tx.clone());
        }
    }

    let shutdown = daemon_shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let delay = next_daemon_delay(&jobs, Utc::now());
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(delay) => {
                let now = Utc::now();
                for job in &mut jobs {
                    let due = job.take_due(now);
                    for _ in 0..due {
                        match job.request_trigger() {
                            DaemonTrigger::Start => {
                                spawn_daemon_job(Arc::clone(&config), job, completed_tx.clone());
                            }
                            DaemonTrigger::Queued => {
                                eprintln!("daemon job '{}' queued one overlapping tick", job.definition.id);
                            }
                            DaemonTrigger::Rejected => {
                                eprintln!("daemon job '{}' rejected an overlapping tick", job.definition.id);
                            }
                        }
                    }
                }
            }
            completion = completed_rx.recv() => {
                let Some(completion) = completion else {
                    return ExitCode::from(30);
                };
                if write_daemon_report(&completion.report).is_err() {
                    cancel_daemon_jobs(&mut jobs);
                    return ExitCode::from(30);
                }
                let Some(job) = jobs.iter_mut().find(|job| job.definition.id == completion.job_id) else {
                    cancel_daemon_jobs(&mut jobs);
                    return ExitCode::from(30);
                };
                if job.complete() {
                    spawn_daemon_job(Arc::clone(&config), job, completed_tx.clone());
                }
            }
        }
    }

    cancel_daemon_jobs(&mut jobs);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while jobs.iter().any(|job| job.running) {
        let completion = match tokio::time::timeout_at(deadline, completed_rx.recv()).await {
            Ok(Some(completion)) => completion,
            _ => return ExitCode::from(30),
        };
        if write_daemon_report(&completion.report).is_err() {
            return ExitCode::from(30);
        }
        let Some(job) = jobs
            .iter_mut()
            .find(|job| job.definition.id == completion.job_id)
        else {
            return ExitCode::from(30);
        };
        job.queued = false;
        job.complete();
    }
    ExitCode::SUCCESS
}

fn select_daemon_jobs(
    config: &ProcessingConfigFile,
    requested: &[String],
) -> Result<Vec<DaemonJob>, &'static str> {
    let mut seen = BTreeSet::new();
    if requested.iter().any(|id| !seen.insert(id.as_str())) {
        return Err("duplicate_daemon_job");
    }
    let mut selected = if requested.is_empty() {
        config
            .daemon
            .jobs
            .iter()
            .filter(|job| job.enabled)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        let by_id = config
            .daemon
            .jobs
            .iter()
            .map(|job| (job.id.as_str(), job))
            .collect::<BTreeMap<_, _>>();
        requested
            .iter()
            .map(|id| {
                by_id
                    .get(id.as_str())
                    .filter(|job| job.enabled)
                    .map(|job| (*job).clone())
                    .ok_or("unknown_or_disabled_daemon_job")
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if selected.is_empty() {
        return Err("no_enabled_daemon_jobs");
    }
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(selected)
}

fn daemon_compile_request(run_id: RunId, job: &DaemonJob) -> ProcessingCompileRequest {
    ProcessingCompileRequest {
        run_id,
        profile_id: Some(job.profile.clone()),
        action_mode: None,
        source: match &job.source {
            DaemonSource::Path { path } => ProcessingSourceRequest::Path { path: path.clone() },
            DaemonSource::Git { remote, reference } => ProcessingSourceRequest::Git {
                remote: remote.clone(),
                reference: reference.clone(),
            },
        },
    }
}

fn spawn_daemon_job(
    config: Arc<ProcessingConfigFile>,
    job: &mut ScheduledDaemonJob,
    completed: mpsc::Sender<DaemonCompletion>,
) {
    let definition = job.definition.clone();
    let cancellation = AcquisitionCancellation::default();
    job.cancellation = Some(cancellation.clone());
    let job_id = definition.id.clone();
    tokio::spawn(async move {
        let (domain_run_id, report_run_id) = match secure_run_id() {
            Ok(run_id) => {
                let report_id =
                    SafeId::new(run_id.as_str().to_owned()).expect("secure run ID is report-safe");
                (Some(run_id), report_id)
            }
            Err(_) => (
                None,
                SafeId::new("run_daemon-identity-error").expect("static daemon error ID is safe"),
            ),
        };
        let report = if let Some(run_id) = domain_run_id {
            let request_id = Some(format!("daemon:{}", definition.id));
            match execute_processing(
                &config,
                daemon_compile_request(run_id, &definition),
                request_id.clone(),
                cancellation,
            )
            .await
            {
                Ok(report) => report,
                Err(issue) => build_error_report(
                    report_run_id,
                    request_id.and_then(|id| SafeId::new(id).ok()),
                    issue,
                ),
            }
        } else {
            build_error_report(report_run_id, None, "processing_identity_failure")
        };
        let _ = completed.send(DaemonCompletion { job_id, report }).await;
    });
}

fn cancel_daemon_jobs(jobs: &mut [ScheduledDaemonJob]) {
    for job in jobs {
        job.queued = false;
        if let Some(cancellation) = &job.cancellation {
            cancellation.cancel();
        }
    }
}

fn write_daemon_report(report: &ProcessingReport) -> io::Result<()> {
    let bytes = report
        .to_json_line()
        .map_err(|_| io::Error::other("invalid daemon report"))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.flush()
}

fn next_daemon_delay(jobs: &[ScheduledDaemonJob], now: chrono::DateTime<Utc>) -> Duration {
    jobs.iter()
        .filter_map(|job| job.next)
        .min()
        .and_then(|next| next.signed_duration_since(now).to_std().ok())
        .unwrap_or(Duration::from_secs(24 * 60 * 60))
}

async fn daemon_shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

struct DaemonCompletion {
    job_id: String,
    report: ProcessingReport,
}

struct ScheduledDaemonJob {
    definition: DaemonJob,
    schedule: Schedule,
    next: Option<chrono::DateTime<Utc>>,
    running: bool,
    queued: bool,
    cancellation: Option<AcquisitionCancellation>,
}

impl ScheduledDaemonJob {
    fn new(definition: DaemonJob, now: chrono::DateTime<Utc>) -> Result<Self, &'static str> {
        let schedule =
            Schedule::from_str(&definition.schedule).map_err(|_| "invalid_daemon_schedule")?;
        let next = schedule.after(&now).next();
        Ok(Self {
            definition,
            schedule,
            next,
            running: false,
            queued: false,
            cancellation: None,
        })
    }

    fn request_trigger(&mut self) -> DaemonTrigger {
        if !self.running {
            self.running = true;
            DaemonTrigger::Start
        } else if self.definition.overlap == DaemonOverlap::QueueOne && !self.queued {
            self.queued = true;
            DaemonTrigger::Queued
        } else {
            DaemonTrigger::Rejected
        }
    }

    fn take_due(&mut self, now: chrono::DateTime<Utc>) -> usize {
        let mut due = 0_usize;
        while self.next.is_some_and(|next| next <= now) && due < 1024 {
            let previous = self.next.expect("checked");
            self.next = self.schedule.after(&previous).next();
            due += 1;
        }
        due
    }

    fn complete(&mut self) -> bool {
        self.running = false;
        self.cancellation = None;
        if self.queued {
            self.queued = false;
            self.running = true;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonTrigger {
    Start,
    Queued,
    Rejected,
}

fn run_job_inspect(
    config: &ProcessingConfigFile,
    report_run_id: SafeId,
    operand: &str,
) -> ExitCode {
    let Some(run_id) = parse_run_id(operand) else {
        return emit_auxiliary_error_name("job_inspect", report_run_id, "invalid_run_id");
    };
    let store = match open_job_store(config) {
        Ok(store) => store,
        Err(()) => {
            return emit_auxiliary_error_name("job_inspect", report_run_id, "job_store_unavailable")
        }
    };
    match inspect_job(&store, &run_id) {
        Ok(completion) => write_auxiliary(
            &AuxiliaryResult::completed("job_inspect", report_run_id, Some(completion)),
            0,
        ),
        Err(_) => emit_auxiliary_error_name("job_inspect", report_run_id, "status_unavailable"),
    }
}

fn run_job_recover(config: &ProcessingConfigFile, report_run_id: SafeId) -> ExitCode {
    let store = match open_job_store(config) {
        Ok(store) => store,
        Err(()) => {
            return emit_auxiliary_error_name("job_recover", report_run_id, "job_store_unavailable")
        }
    };
    let run_ids = match store.list_recoverable_run_ids() {
        Ok(run_ids) => run_ids,
        Err(_) => {
            return emit_auxiliary_error_name("job_recover", report_run_id, "job_listing_failure")
        }
    };
    let now = match system_time_unix_millis() {
        Ok(now) => now,
        Err(_) => return emit_auxiliary_error_name("job_recover", report_run_id, "clock_failure"),
    };
    let stale_after_millis = match config.processing.jobs.stale_after_secs.checked_mul(1_000) {
        Some(value) => value,
        None => {
            return emit_auxiliary_error_name("job_recover", report_run_id, "configuration_failure")
        }
    };
    let recovery_lease = match recovery_lease_identity() {
        Ok(identity) => identity,
        Err(()) => {
            return emit_auxiliary_error_name(
                "job_recover",
                report_run_id,
                "recovery_identity_failure",
            )
        }
    };
    let mut recovered = Vec::new();
    let mut untouched = Vec::new();
    let mut failed = Vec::new();
    for run_id in run_ids {
        match recover_job(
            &store,
            &run_id,
            now,
            stale_after_millis,
            recovery_lease.clone(),
        ) {
            Ok(status) => recovered.push(status),
            Err(file_guardian::processing::completion::CompletionError::JobNotStale) => {
                if let Ok(id) = SafeId::new(run_id.as_str().to_owned()) {
                    untouched.push(id);
                }
            }
            Err(_) => {
                if let Ok(id) = SafeId::new(run_id.as_str().to_owned()) {
                    failed.push(JobRecoveryFailure {
                        run_id: id,
                        issue_code: "recovery_failed",
                    });
                }
            }
        }
    }
    let batch = JobRecoveryBatch {
        recovered,
        untouched,
        failed,
    };
    if batch.failed.is_empty() {
        write_auxiliary(
            &AuxiliaryResult::completed("job_recover", report_run_id, Some(batch)),
            0,
        )
    } else {
        write_auxiliary(
            &AuxiliaryResult::error_with_result(
                "job_recover",
                report_run_id,
                "partial_recovery_failure",
                batch,
            ),
            30,
        )
    }
}

fn recovery_lease_identity() -> Result<LeaseIdentity, ()> {
    let random = secure_run_id().map_err(|_| ())?;
    let suffix = random.as_str().strip_prefix("run_").ok_or(())?;
    let process_nonce = format!("recovery-{}-{suffix}", std::process::id());
    let boot_nonce = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("boot-{suffix}"));
    LeaseIdentity::new(process_nonce, boot_nonce).map_err(|_| ())
}

fn run_stage_discard(
    config: &ProcessingConfigFile,
    report_run_id: SafeId,
    operand: &str,
) -> ExitCode {
    let Some(run_id) = parse_run_id(operand) else {
        return emit_auxiliary_error_name("stage_discard", report_run_id, "invalid_run_id");
    };
    let store = match open_job_store(config) {
        Ok(store) => store,
        Err(()) => {
            return emit_auxiliary_error_name(
                "stage_discard",
                report_run_id,
                "job_store_unavailable",
            )
        }
    };
    match inspect_job(&store, &run_id) {
        Ok(status)
            if status.disposition == file_guardian::processing::domain::Disposition::Discarded =>
        {
            return write_auxiliary(
                &AuxiliaryResult::completed("stage_discard", report_run_id, Some(status)),
                0,
            );
        }
        Ok(status) if !status.stage_available() => {
            return write_auxiliary(
                &AuxiliaryResult::inapplicable_with_result(
                    "stage_discard",
                    report_run_id,
                    "stage_unavailable",
                    status,
                ),
                20,
            );
        }
        Ok(_) => {}
        Err(_) => {
            return emit_auxiliary_error_name("stage_discard", report_run_id, "status_unavailable");
        }
    }
    match discard_retained_stage(&store, &run_id) {
        Ok(()) => match inspect_job(&store, &run_id) {
            Ok(status) => write_auxiliary(
                &AuxiliaryResult::completed("stage_discard", report_run_id, Some(status)),
                0,
            ),
            Err(_) => {
                emit_auxiliary_error_name("stage_discard", report_run_id, "status_unavailable")
            }
        },
        Err(file_guardian::processing::completion::CompletionError::HandoffUnavailable) => {
            match inspect_job(&store, &run_id) {
                Ok(status)
                    if status.disposition
                        == file_guardian::processing::domain::Disposition::Discarded =>
                {
                    write_auxiliary(
                        &AuxiliaryResult::completed("stage_discard", report_run_id, Some(status)),
                        0,
                    )
                }
                _ => write_auxiliary(
                    &AuxiliaryResult::<serde_json::Value>::inapplicable(
                        "stage_discard",
                        report_run_id,
                        "stage_unavailable",
                    ),
                    20,
                ),
            }
        }
        Err(_) => emit_auxiliary_error_name("stage_discard", report_run_id, "operation_failure"),
    }
}

fn parse_run_id(value: &str) -> Option<RunId> {
    RunId::new(value.to_owned()).ok()
}

fn open_job_store(config: &ProcessingConfigFile) -> Result<JobStore, ()> {
    JobStore::open(JobStorePaths {
        jobs_root: config.processing.jobs.root.clone(),
        reports_root: config.processing.jobs.reports_root.clone(),
        quarantine_root: config.processing.jobs.quarantine_root.clone(),
    })
    .map_err(|_| ())
}

fn load_config(explicit: Option<&Path>) -> Result<ProcessingConfigFile, ()> {
    let path = explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        env::var_os("FILE_GUARDIAN_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    });
    let raw = fs::read_to_string(path).map_err(|_| ())?;
    ProcessingConfigFile::parse(&raw).map_err(|_| ())
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AuxiliaryStatus {
    Completed,
    Inapplicable,
    Error,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AuxiliaryResult<T: Serialize> {
    schema_version: &'static str,
    operation: &'static str,
    run_id: SafeId,
    status: AuxiliaryStatus,
    result: Option<T>,
    issue_code: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct JobRecoveryBatch {
    recovered: Vec<file_guardian::processing::completion::CompletionStatus>,
    untouched: Vec<SafeId>,
    failed: Vec<JobRecoveryFailure>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct JobRecoveryFailure {
    run_id: SafeId,
    issue_code: &'static str,
}

impl<T: Serialize> AuxiliaryResult<T> {
    fn completed(operation: &'static str, run_id: SafeId, result: Option<T>) -> Self {
        Self {
            schema_version: "file-guardian-auxiliary-result/1",
            operation,
            run_id,
            status: AuxiliaryStatus::Completed,
            result,
            issue_code: None,
        }
    }

    fn inapplicable(operation: &'static str, run_id: SafeId, issue_code: &'static str) -> Self {
        Self {
            schema_version: "file-guardian-auxiliary-result/1",
            operation,
            run_id,
            status: AuxiliaryStatus::Inapplicable,
            result: None,
            issue_code: Some(issue_code),
        }
    }

    fn inapplicable_with_result(
        operation: &'static str,
        run_id: SafeId,
        issue_code: &'static str,
        result: T,
    ) -> Self {
        Self {
            schema_version: "file-guardian-auxiliary-result/1",
            operation,
            run_id,
            status: AuxiliaryStatus::Inapplicable,
            result: Some(result),
            issue_code: Some(issue_code),
        }
    }

    fn error_with_result(
        operation: &'static str,
        run_id: SafeId,
        issue_code: &'static str,
        result: T,
    ) -> Self {
        Self {
            schema_version: "file-guardian-auxiliary-result/1",
            operation,
            run_id,
            status: AuxiliaryStatus::Error,
            result: Some(result),
            issue_code: Some(issue_code),
        }
    }
}

fn emit_auxiliary_error(command: &Command, run_id: SafeId, issue_code: &'static str) -> ExitCode {
    let operation = match command {
        Command::Stage(stage) => match stage.command {
            StageCommand::Handoff(_) => "stage_handoff",
            StageCommand::Discard(_) => "stage_discard",
        },
        Command::Artifact(artifact) => match artifact.command {
            ArtifactCommand::Inspect(_) => "artifact_inspect",
            ArtifactCommand::Recover(_) => "artifact_recover",
            ArtifactCommand::Discard(_) => "artifact_discard",
        },
        Command::Job(job) => match job.command {
            JobCommand::Inspect(_) => "job_inspect",
            JobCommand::Recover => "job_recover",
        },
        Command::Process(_) => "process",
        Command::Daemon(_) => "daemon",
    };
    emit_auxiliary_error_name(operation, run_id, issue_code)
}

fn emit_auxiliary_error_name(
    operation: &'static str,
    run_id: SafeId,
    issue_code: &'static str,
) -> ExitCode {
    let result = AuxiliaryResult::<serde_json::Value> {
        schema_version: "file-guardian-auxiliary-result/1",
        operation,
        run_id,
        status: AuxiliaryStatus::Error,
        result: None,
        issue_code: Some(issue_code),
    };
    write_auxiliary(&result, 30)
}

fn write_auxiliary<T: Serialize>(result: &AuxiliaryResult<T>, exit_code: u8) -> ExitCode {
    let mut bytes = match serde_json::to_vec(result) {
        Ok(bytes) => bytes,
        Err(_) => return report_construction_failure(),
    };
    bytes.push(b'\n');
    let mut stdout = io::stdout().lock();
    if stdout
        .write_all(&bytes)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        eprintln!("auxiliary result could not be written");
        return ExitCode::from(30);
    }
    ExitCode::from(exit_code)
}

fn command_run_id(command: &Command) -> Option<&str> {
    match command {
        Command::Stage(stage) => match &stage.command {
            StageCommand::Handoff(args) => Some(&args.run_id),
            StageCommand::Discard(args) => Some(&args.run_id),
        },
        Command::Artifact(artifact) => match &artifact.command {
            ArtifactCommand::Inspect(args) => Some(&args.run_id),
            ArtifactCommand::Recover(args) => Some(&args.run_id),
            ArtifactCommand::Discard(args) => Some(&args.run_id),
        },
        Command::Job(job) => match &job.command {
            JobCommand::Inspect(args) => Some(&args.run_id),
            JobCommand::Recover => None,
        },
        Command::Process(_) | Command::Daemon(_) => None,
    }
}

fn command_request_id(command: &Command) -> Option<SafeId> {
    let Command::Process(ProcessArgs { request_id, .. }) = command else {
        return None;
    };
    request_id
        .as_ref()
        .and_then(|value| SafeId::new(value.clone()).ok())
}

fn emit_error_report(
    run_id: SafeId,
    request_id: Option<SafeId>,
    issue_code: &'static str,
) -> ExitCode {
    let report = build_error_report(run_id, request_id, issue_code);
    write_report(&mut io::stdout().lock(), &report)
}

fn build_error_report(
    run_id: SafeId,
    request_id: Option<SafeId>,
    issue_code: &'static str,
) -> ProcessingReport {
    let timestamp = Utc::now().to_rfc3339();
    ProcessingReport::new(ProcessingReportData {
        run_id,
        request_id,
        outcome: ProcessingOutcome::Error,
        modified: false,
        started_at: Rfc3339Timestamp::new(timestamp.clone())
            .expect("chrono produces canonical RFC 3339 timestamps"),
        finished_at: Rfc3339Timestamp::new(timestamp)
            .expect("chrono produces canonical RFC 3339 timestamps"),
        persistence_status: PersistenceStatus::Unavailable,
        source: None,
        acquisition: None,
        stage: None,
        policy: None,
        phases: PhasesSummary {
            initial: None,
            verification: None,
        },
        pi_invocations: Vec::new(),
        adjudications: Vec::new(),
        actions: Vec::new(),
        issues: vec![IssueSummary {
            code: SafeId::new(issue_code).expect("static issue code is report-safe"),
            phase: None,
            component_id: None,
        }],
        degradations: Vec::new(),
        statistics: ProcessingStatistics {
            initial_artifacts: 0,
            verification_artifacts: 0,
            total_findings: 0,
            total_actions: 0,
            duration_ms: 0,
        },
        omissions: OmissionSummary {
            details_omitted: false,
            reason: None,
        },
    })
    .expect("static unavailable error report is valid")
}

fn write_report(writer: &mut impl Write, report: &ProcessingReport) -> ExitCode {
    let bytes = match report.to_json_line() {
        Ok(bytes) => bytes,
        Err(_) => return report_construction_failure(),
    };
    if writer
        .write_all(&bytes)
        .and_then(|()| writer.flush())
        .is_err()
    {
        eprintln!("processing report could not be written");
        return ExitCode::from(ProcessingOutcome::Error.exit_code() as u8);
    }
    ExitCode::from(report.exit_code as u8)
}

fn report_construction_failure() -> ExitCode {
    eprintln!("processing report could not be constructed");
    ExitCode::from(ProcessingOutcome::Error.exit_code() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn unsafe_auxiliary_run_id_is_not_reflected() {
        let args =
            Args::try_parse_from(["file-guardian", "stage", "discard", "../../private/source"])
                .unwrap();
        let generated = SafeId::new("run_generated").unwrap();
        let selected = command_run_id(&args.command)
            .and_then(|value| SafeId::new(value.to_owned()).ok())
            .unwrap_or_else(|| generated.clone());
        assert_eq!(selected, generated);
    }

    #[test]
    fn valid_auxiliary_run_id_is_reused_for_the_error_report() {
        let args = Args::try_parse_from([
            "file-guardian",
            "artifact",
            "inspect",
            "run_abc",
            "quarantine_7",
        ])
        .unwrap();
        assert_eq!(command_run_id(&args.command), Some("run_abc"));
    }

    #[test]
    fn failing_stdout_writer_returns_error_exit() {
        let timestamp = Rfc3339Timestamp::new("2026-08-17T12:00:00+00:00").unwrap();
        let report = ProcessingReport::new(ProcessingReportData {
            run_id: SafeId::new("run_test").unwrap(),
            request_id: None,
            outcome: ProcessingOutcome::Error,
            modified: false,
            started_at: timestamp.clone(),
            finished_at: timestamp,
            persistence_status: PersistenceStatus::Unavailable,
            source: None,
            acquisition: None,
            stage: None,
            policy: None,
            phases: PhasesSummary {
                initial: None,
                verification: None,
            },
            pi_invocations: Vec::new(),
            adjudications: Vec::new(),
            actions: Vec::new(),
            issues: vec![IssueSummary {
                code: SafeId::new("test_failure").unwrap(),
                phase: None,
                component_id: None,
            }],
            degradations: Vec::new(),
            statistics: ProcessingStatistics {
                initial_artifacts: 0,
                verification_artifacts: 0,
                total_findings: 0,
                total_actions: 0,
                duration_ms: 0,
            },
            omissions: OmissionSummary {
                details_omitted: false,
                reason: None,
            },
        })
        .unwrap();
        assert_eq!(
            write_report(&mut FailingWriter, &report),
            ExitCode::from(30)
        );
    }

    #[test]
    fn daemon_overlap_modes_are_bounded_and_schedules_advance() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-18T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let definition = |overlap| DaemonJob {
            id: "upload".to_owned(),
            enabled: true,
            profile: "review".to_owned(),
            schedule: "* * * * * *".to_owned(),
            run_on_start: true,
            overlap,
            source: DaemonSource::Path {
                path: PathBuf::from("/srv/incoming"),
            },
        };

        let mut rejected = ScheduledDaemonJob::new(definition(DaemonOverlap::Reject), now).unwrap();
        assert_eq!(rejected.request_trigger(), DaemonTrigger::Start);
        assert_eq!(rejected.request_trigger(), DaemonTrigger::Rejected);
        assert!(!rejected.complete());

        let mut queued = ScheduledDaemonJob::new(definition(DaemonOverlap::QueueOne), now).unwrap();
        assert_eq!(queued.request_trigger(), DaemonTrigger::Start);
        assert_eq!(queued.request_trigger(), DaemonTrigger::Queued);
        assert_eq!(queued.request_trigger(), DaemonTrigger::Rejected);
        assert!(queued.complete());
        assert!(!queued.complete());
        assert_eq!(queued.take_due(now + chrono::Duration::seconds(3)), 3);
    }
}
