use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use file_guardian::cli::{ActionMode, Args, AuthorizeArgs, Command, DaemonArgs};
use file_guardian::config::{
    ActionMode as ConfigActionMode, Config, DaemonJobConfig, DaemonJobKind, DaemonTarget,
};
use file_guardian::domain::{IssueCode, RunId};
use file_guardian::logging::LoggingSettings;
use file_guardian::report::{AuthorizationOutcome, AuthorizationReport, ReportIdentifier};
use file_guardian::runtime::{
    compile_invocation, report_from_result, secure_run_id, startup_error_report, ReportContext,
};
use file_guardian::service::AuthorizationService;
use tokio::signal;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match args.command {
        Command::Authorize(authorize) => run_authorize_command(args.config.as_deref(), authorize),
        Command::Daemon(daemon) => run_daemon_command(args.config.as_deref(), daemon).await,
    }
}

fn run_authorize_command(config_path: Option<&Path>, args: AuthorizeArgs) -> ExitCode {
    let run_id = match secure_run_id() {
        Ok(run_id) => run_id,
        Err(error) => {
            eprintln!("failed to obtain secure randomness: {error}");
            return emit_report(&startup_error_report(
                fallback_report_id(),
                request_id(&args),
                IssueCode::InternalFailure,
                "secure run identity could not be generated",
            ));
        }
    };
    let config = match Config::load_from_sources(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load authorization configuration: {error}");
            return emit_report(&startup_error_report(
                run_id,
                request_id(&args),
                IssueCode::ConfigurationFailure,
                "authorization configuration could not be loaded",
            ));
        }
    };
    let _logging = match init_logging(&config) {
        Ok(guards) => guards,
        Err(error) => {
            eprintln!("failed to initialize logging: {error}");
            return emit_report(&startup_error_report(
                run_id,
                request_id(&args),
                IssueCode::ConfigurationFailure,
                "authorization logging could not be initialized",
            ));
        }
    };
    match authorize_with_config(&config, &args, run_id) {
        Ok(report) => emit_report(&report),
        Err((run_id, message)) => {
            eprintln!("authorization could not start: {message}");
            emit_report(&startup_error_report(
                run_id,
                request_id(&args),
                IssueCode::ConfigurationFailure,
                "authorization request could not be compiled",
            ))
        }
    }
}

fn authorize_with_config(
    config: &Config,
    args: &AuthorizeArgs,
    run_id: RunId,
) -> Result<AuthorizationReport, (RunId, String)> {
    let started = Instant::now();
    let compiled = compile_invocation(
        config,
        args.profile.as_deref(),
        args.action_mode.map(|mode| match mode {
            ActionMode::Evaluate => ConfigActionMode::Evaluate,
            ActionMode::Apply => ConfigActionMode::Apply,
        }),
        run_id.clone(),
        args.path.clone(),
    )
    .map_err(|error| (run_id.clone(), error.to_string()))?;
    let result = AuthorizationService::authorize(compiled.request);
    report_from_result(
        ReportContext {
            run_id: run_id.clone(),
            request_id: request_id(args),
            policy: Some(compiled.policy),
            duration_ms: elapsed_millis(started),
        },
        result,
    )
    .map_err(|error| (run_id, error.to_string()))
}

fn emit_report(report: &AuthorizationReport) -> ExitCode {
    let mut stdout = io::stdout().lock();
    match write_report(&mut stdout, report) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("failed to write authorization report: {error}");
            ExitCode::from(30)
        }
    }
}

fn write_report(
    writer: &mut impl Write,
    report: &AuthorizationReport,
) -> Result<u8, file_guardian::report::ReportWriteError> {
    report.write_json_line(writer)?;
    writer.flush()?;
    Ok(report.exit_code as u8)
}

async fn run_daemon_command(config_path: Option<&Path>, args: DaemonArgs) -> ExitCode {
    let config = match Config::load_from_sources(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load daemon configuration: {error}");
            return ExitCode::from(30);
        }
    };
    let _logging = match init_logging(&config) {
        Ok(guards) => guards,
        Err(error) => {
            eprintln!("failed to initialize logging: {error}");
            return ExitCode::from(30);
        }
    };
    let jobs = match config.validate_for_daemon(&args.jobs) {
        Ok(jobs) => jobs.into_iter().cloned().collect::<Vec<_>>(),
        Err(error) => {
            tracing::error!("daemon configuration is invalid: {error}");
            return ExitCode::from(30);
        }
    };
    let config = Arc::new(config);
    let (failed_tx, mut failed_rx) = mpsc::channel::<String>(jobs.len());
    let mut handles = Vec::with_capacity(jobs.len());
    for job in jobs {
        let config = Arc::clone(&config);
        let failed_tx = failed_tx.clone();
        handles.push(tokio::spawn(async move {
            run_daemon_loop(config, job, failed_tx).await;
        }));
    }
    drop(failed_tx);

    let status = tokio::select! {
        result = signal::ctrl_c() => {
            match result {
                Ok(()) => {
                    tracing::info!("received shutdown signal");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    tracing::error!("failed to listen for shutdown signal: {error}");
                    ExitCode::from(30)
                }
            }
        }
        failed = failed_rx.recv() => {
            if let Some(job_id) = failed {
                tracing::error!(job_id, "daemon policy scan became unhealthy");
            } else {
                tracing::error!("all daemon jobs stopped unexpectedly");
            }
            ExitCode::from(30)
        }
    };
    for handle in handles {
        handle.abort();
    }
    status
}

async fn run_daemon_loop(config: Arc<Config>, job: DaemonJobConfig, failed: mpsc::Sender<String>) {
    let DaemonJobKind::PolicyScan {
        profile,
        target,
        every_secs,
        run_on_start,
    } = &job.kind;
    if *run_on_start
        && !run_daemon_scan_blocking(
            Arc::clone(&config),
            job.id.clone(),
            profile.clone(),
            target.clone(),
        )
        .await
    {
        let _ = failed.send(job.id).await;
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(*every_secs));
    interval.tick().await;
    loop {
        interval.tick().await;
        if !run_daemon_scan_blocking(
            Arc::clone(&config),
            job.id.clone(),
            profile.clone(),
            target.clone(),
        )
        .await
        {
            let _ = failed.send(job.id).await;
            return;
        }
    }
}

async fn run_daemon_scan_blocking(
    config: Arc<Config>,
    job_id: String,
    profile: String,
    target: DaemonTarget,
) -> bool {
    match tokio::task::spawn_blocking(move || run_daemon_scan(&config, &job_id, &profile, &target))
        .await
    {
        Ok(healthy) => healthy,
        Err(error) => {
            tracing::error!("daemon policy scan task failed: {error}");
            false
        }
    }
}

fn run_daemon_scan(config: &Config, job_id: &str, profile: &str, target: &DaemonTarget) -> bool {
    let targets = match resolve_targets(target) {
        Ok(targets) if !targets.is_empty() => targets,
        Ok(_) => {
            tracing::error!(job_id, "daemon target matched no inputs");
            return false;
        }
        Err(error) => {
            tracing::error!(job_id, "daemon targets could not be resolved: {error}");
            return false;
        }
    };
    for path in targets {
        let run_id = match secure_run_id() {
            Ok(run_id) => run_id,
            Err(error) => {
                tracing::error!(
                    job_id,
                    "secure run identity could not be generated: {error}"
                );
                return false;
            }
        };
        let args = AuthorizeArgs {
            profile: Some(profile.to_string()),
            request_id: None,
            action_mode: Some(ActionMode::Evaluate),
            path,
        };
        let report = match authorize_with_config(config, &args, run_id) {
            Ok(report) => report,
            Err((_, error)) => {
                tracing::error!(job_id, "daemon authorization could not start: {error}");
                return false;
            }
        };
        match report.to_json_line() {
            Ok(line) => {
                if let Err(error) = io::stderr().lock().write_all(&line) {
                    tracing::error!(job_id, "daemon report could not be written: {error}");
                    return false;
                }
            }
            Err(error) => {
                tracing::error!(job_id, "daemon report could not be serialized: {error}");
                return false;
            }
        }
        if report.outcome == AuthorizationOutcome::Error {
            return false;
        }
    }
    true
}

fn resolve_targets(target: &DaemonTarget) -> Result<Vec<PathBuf>, String> {
    match target {
        DaemonTarget::Literal { path } => Ok(vec![path.clone()]),
        DaemonTarget::Patterns { patterns } => {
            let mut paths = BTreeSet::new();
            for pattern in patterns {
                for entry in glob::glob(pattern).map_err(|error| error.to_string())? {
                    let path = entry.map_err(|error| error.to_string())?;
                    paths.insert(path);
                }
            }
            Ok(paths.into_iter().collect())
        }
    }
}

fn request_id(args: &AuthorizeArgs) -> Option<ReportIdentifier> {
    args.request_id
        .as_ref()
        .map(|value| ReportIdentifier::new(value.clone()).expect("Clap validated request ID"))
}

fn init_logging(config: &Config) -> Result<file_guardian::logging::LoggingGuards, String> {
    LoggingSettings::from_config(&config.logging)
        .map_err(|error| error.to_string())?
        .init_tracing()
        .map_err(|error| error.to_string())
}

fn fallback_report_id() -> RunId {
    RunId::from_suffix("startup-error").expect("static fallback report ID is valid")
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use file_guardian::report::ReportIdentifier;

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
    fn target_resolution_is_sorted_and_deduplicated() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("b.txt"), b"b").unwrap();
        std::fs::write(temp.path().join("a.txt"), b"a").unwrap();
        let target = DaemonTarget::Patterns {
            patterns: vec![
                format!("{}/*.txt", temp.path().display()),
                format!("{}/a.*", temp.path().display()),
            ],
        };
        assert_eq!(
            resolve_targets(&target).unwrap(),
            vec![temp.path().join("a.txt"), temp.path().join("b.txt")]
        );
    }

    #[test]
    fn report_writer_failure_is_detectable_before_success_exit() {
        let report = startup_error_report(
            RunId::from_suffix("write-error").unwrap(),
            Some(ReportIdentifier::new("request").unwrap()),
            IssueCode::InternalFailure,
            "test report",
        );
        assert!(write_report(&mut FailingWriter, &report).is_err());
    }
}
