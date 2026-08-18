use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use file_guardian::domain::{Digest, RunId};
use file_guardian::processing::acquisition::local::{
    acquire_local, AcquisitionCancellation, LocalAcquisitionRequest,
};
use file_guardian::processing::completion::{revalidate_and_seal, CompletionStatus};
use file_guardian::processing::config::{CaptureLimits, ProcessingConfigFile, SymlinkPolicy};
use file_guardian::processing::domain::{
    Disposition, HandoffStatus, JobExecutionState, Outcome, TerminalJobState,
};
use file_guardian::processing::job::{
    system_time_unix_millis, DecisionDisposition, DecisionDispositions, JobStore, JobStorePaths,
    LeaseIdentity, PrivateDecisionRecord,
};
use tempfile::TempDir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_file-guardian"))
}

fn private_dir(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

struct Fixture {
    _temporary: TempDir,
    config: PathBuf,
    paths: JobStorePaths,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let paths = JobStorePaths {
            jobs_root: private_dir(temporary.path(), "jobs"),
            reports_root: private_dir(temporary.path(), "reports"),
            quarantine_root: private_dir(temporary.path(), "quarantine"),
        };
        let artifact_quarantine = private_dir(temporary.path(), "artifact-quarantine");
        let example = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/examples/processing-v3.toml"),
        )
        .unwrap();
        let configured = example
            .replace(
                "/var/lib/file-guardian/jobs",
                paths.jobs_root.to_str().unwrap(),
            )
            .replace(
                "/var/lib/file-guardian/reports",
                paths.reports_root.to_str().unwrap(),
            )
            .replace(
                "/var/lib/file-guardian/quarantine",
                paths.quarantine_root.to_str().unwrap(),
            )
            .replace(
                "/var/lib/file-guardian/artifact-quarantine",
                artifact_quarantine.to_str().unwrap(),
            );
        ProcessingConfigFile::parse(&configured).unwrap();
        let config = temporary.path().join("config.toml");
        fs::write(&config, configured).unwrap();
        Self {
            _temporary: temporary,
            config,
            paths,
        }
    }

    fn retained_job(&self, run_id: &RunId) {
        let store = JobStore::open(self.paths.clone()).unwrap();
        let mut lease = store
            .create(
                run_id,
                LeaseIdentity::new("binary-process", "binary-boot").unwrap(),
                system_time_unix_millis().unwrap(),
            )
            .unwrap();
        let source = self._temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload.txt"), b"payload\n").unwrap();
        let cancellation = AcquisitionCancellation::default();
        lease.transition(JobExecutionState::Acquiring, 1).unwrap();
        let acquired = acquire_local(LocalAcquisitionRequest {
            source: &source,
            stage: &lease.paths().stage(),
            jobs_root: &self.paths.jobs_root,
            limits: &CaptureLimits {
                max_entries: 16,
                max_files: 16,
                max_file_bytes: 1024 * 1024,
                max_total_bytes: 2 * 1024 * 1024,
                max_depth: 8,
            },
            symlinks: SymlinkPolicy::Reject,
            cancellation: &cancellation,
        })
        .unwrap();
        for (state, now) in [
            (JobExecutionState::Acquired, 2),
            (JobExecutionState::BaselineCaptured, 3),
            (JobExecutionState::AnalyzingInitial, 4),
            (JobExecutionState::ResolvingInitial, 5),
            (JobExecutionState::RevalidatingFinal, 6),
            (JobExecutionState::Sealing, 7),
        ] {
            lease.transition(state, now).unwrap();
        }
        let sealed = revalidate_and_seal(
            &lease.paths().stage(),
            &acquired.entries,
            acquired.manifest_identity,
            &cancellation,
        )
        .unwrap();
        let manifest = sealed.manifest_identity();
        let decision = PrivateDecisionRecord::new(
            run_id.clone(),
            Outcome::Allow,
            Some(manifest),
            Some(Digest::sha256(b"policy-evidence")),
            DecisionDispositions::new(
                Outcome::Allow,
                DecisionDisposition::Retain,
                DecisionDisposition::Retain,
            )
            .unwrap(),
            Digest::sha256(b"report"),
            serde_json::json!({"fixture": "binary-admin"}),
        )
        .unwrap();
        lease.write_decision(&decision).unwrap();
        lease.enter_preparing_decision(8).unwrap();
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
        let status = CompletionStatus {
            run_id: run_id.clone(),
            outcome: Outcome::Allow,
            disposition: Disposition::Retained,
            handoff: HandoffStatus::Available,
            sealed: true,
            final_manifest_identity: Some(manifest),
            report_published: true,
        };
        let status_path = lease.paths().root().join("completion-status.json");
        fs::write(&status_path, serde_json::to_vec(&status).unwrap()).unwrap();
        fs::set_permissions(status_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = binary();
        command.arg("--config").arg(&self.config);
        command
    }
}

fn json(output: &Output) -> serde_json::Value {
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn job_inspect_returns_mutable_completion_status() {
    let fixture = Fixture::new();
    let run_id = RunId::from_suffix("binary-inspect").unwrap();
    fixture.retained_job(&run_id);

    let output = fixture
        .command()
        .args(["job", "inspect", run_id.as_str()])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result = json(&output);
    assert_eq!(result["schema_version"], "file-guardian-auxiliary-result/1");
    assert_eq!(result["operation"], "job_inspect");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["run_id"], run_id.as_str());
    assert_eq!(result["result"]["outcome"], "allow");
    assert_eq!(result["result"]["disposition"], "retained");
    assert_eq!(result["result"]["handoff"], "available");
    assert_eq!(result["issue_code"], serde_json::Value::Null);
}

#[test]
fn stage_discard_removes_available_stage_and_updates_inspection() {
    let fixture = Fixture::new();
    let run_id = RunId::from_suffix("binary-discard").unwrap();
    fixture.retained_job(&run_id);

    let output = fixture
        .command()
        .args(["stage", "discard", run_id.as_str()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result = json(&output);
    assert_eq!(result["operation"], "stage_discard");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["result"]["disposition"], "discarded");
    assert!(!fixture
        .paths
        .jobs_root
        .join(run_id.as_str())
        .join("stage")
        .exists());

    let inspected = fixture
        .command()
        .args(["job", "inspect", run_id.as_str()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(0));
    assert_eq!(json(&inspected)["result"]["disposition"], "discarded");

    let repeated = fixture
        .command()
        .args(["stage", "discard", run_id.as_str()])
        .output()
        .unwrap();
    assert_eq!(repeated.status.code(), Some(0));
    assert_eq!(json(&repeated), result);
}

#[test]
fn stage_copy_handoff_is_verified_and_exact_retry_is_idempotent() {
    let fixture = Fixture::new();
    let run_id = RunId::from_suffix("binary-handoff").unwrap();
    fixture.retained_job(&run_id);
    let approved = private_dir(fixture._temporary.path(), "approved");
    let destination = approved.join("published");

    let invoke = || {
        fixture
            .command()
            .args(["stage", "handoff", run_id.as_str(), "--destination"])
            .arg(&destination)
            .args(["--mode", "copy"])
            .output()
            .unwrap()
    };
    let output = invoke();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let receipt = json(&output);
    assert_eq!(receipt["operation"], "stage_handoff");
    assert_eq!(receipt["status"], "completed");
    assert_eq!(receipt["result"]["mode"], "copy");
    assert_eq!(
        fs::read(destination.join("payload.txt")).unwrap(),
        b"payload\n"
    );

    let repeated = invoke();
    assert_eq!(
        repeated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&repeated.stdout)
    );
    assert_eq!(json(&repeated), receipt);

    let inspected = fixture
        .command()
        .args(["job", "inspect", run_id.as_str()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(0));
    assert_eq!(json(&inspected)["result"]["handoff"], "handed_off");
}

#[test]
fn unavailable_stage_discard_is_inapplicable_not_success() {
    let fixture = Fixture::new();
    let run_id = RunId::from_suffix("binary-missing").unwrap();
    let output = fixture
        .command()
        .args(["stage", "discard", run_id.as_str()])
        .output()
        .unwrap();

    // No durable job exists, so the state is operationally ambiguous rather
    // than an idempotent, recorded discard.
    assert_eq!(output.status.code(), Some(30));
    let result = json(&output);
    assert_eq!(result["status"], "error");
    assert_eq!(result["issue_code"], "status_unavailable");
}

#[test]
fn job_recover_reports_fresh_jobs_as_untouched() {
    let fixture = Fixture::new();
    let run_id = RunId::from_suffix("binary-fresh").unwrap();
    fixture.retained_job(&run_id);

    let output = fixture.command().args(["job", "recover"]).output().unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result = json(&output);
    assert_eq!(result["operation"], "job_recover");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["result"]["recovered"], serde_json::json!([]));
    assert_eq!(
        result["result"]["untouched"],
        serde_json::json!([run_id.as_str()])
    );
    assert_eq!(result["result"]["failed"], serde_json::json!([]));
}
