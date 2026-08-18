//! Command-line contract for processing jobs and retained job administration.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};

/// File Guardian command-line arguments.
#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(
    author,
    version,
    about = "Processes file trees and repositories through configured policy pipelines"
)]
pub struct Args {
    /// Path to the File Guardian configuration file.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// Explicit File Guardian operating mode.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Acquire and process one filesystem tree or Git repository.
    Process(ProcessArgs),

    /// Manage a retained publication stage.
    Stage(StageArgs),

    /// Inspect or manage a quarantined artifact.
    Artifact(ArtifactArgs),

    /// Inspect or recover durable processing jobs.
    Job(JobArgs),

    /// Run configured background jobs until shutdown.
    Daemon(DaemonArgs),
}

/// Common arguments for one processing job.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ProcessArgs {
    /// Processing profile ID. The configured default is used when omitted.
    #[arg(long, value_name = "PROFILE_ID")]
    pub profile: Option<String>,

    /// Bounded, caller-provided correlation ID echoed in the report.
    #[arg(long, value_name = "ID", value_parser = validate_request_id)]
    pub request_id: Option<String>,

    /// Requested action authority. Policy may reduce, but never expand, it.
    #[arg(long, value_enum, value_name = "MODE")]
    pub action_mode: Option<ActionMode>,

    #[command(subcommand)]
    pub source: ProcessSource,
}

/// Source acquired by a processing job.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ProcessSource {
    /// Copy one literal regular file or directory into an owned stage.
    Path(ProcessPathArgs),

    /// Acquire one local Git repository without modifying it.
    Repo(ProcessRepoArgs),

    /// Clone one supported HTTPS or SSH Git remote.
    Git(ProcessGitArgs),
}

/// Filesystem source arguments.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ProcessPathArgs {
    /// Literal regular file or directory to copy and process.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

/// Local Git repository source arguments.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ProcessRepoArgs {
    /// Optional branch or tag selected as the materialized HEAD.
    #[arg(long = "ref", value_name = "REF", value_parser = validate_git_ref)]
    pub checkout_ref: Option<String>,

    /// Literal path to a local Git repository.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

/// Remote Git repository source arguments.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ProcessGitArgs {
    /// Optional advertised branch or tag selected as the materialized HEAD.
    #[arg(long = "ref", value_name = "REF", value_parser = validate_git_ref)]
    pub checkout_ref: Option<String>,

    /// HTTPS, SSH, or SCP-like Git remote accepted by source validation.
    #[arg(value_name = "REMOTE")]
    pub remote: String,
}

/// Retained-stage command group.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct StageArgs {
    #[command(subcommand)]
    pub command: StageCommand,
}

/// Operations on a retained publication stage.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum StageCommand {
    /// Move or copy a sealed allowed stage to a caller-owned destination.
    Handoff(StageHandoffArgs),

    /// Discard a retained stage.
    Discard(StageDiscardArgs),
}

/// Arguments for a verified stage handoff.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct StageHandoffArgs {
    /// Durable processing run ID.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,

    /// Absolute, absent destination for the verified stage.
    #[arg(long, value_name = "PATH")]
    pub destination: PathBuf,

    /// Exact handoff mechanism; move never falls back to copy.
    #[arg(long, value_enum, value_name = "MODE")]
    pub mode: HandoffMode,
}

/// Arguments for discarding a retained stage.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct StageDiscardArgs {
    /// Durable processing run ID.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,
}

/// Handoff mechanism for a retained stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum HandoffMode {
    /// Atomically rename a stage on the same filesystem.
    Move,

    /// Copy, verify, and atomically publish a stage.
    Copy,
}

/// Artifact-quarantine command group.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ArtifactArgs {
    #[command(subcommand)]
    pub command: ArtifactCommand,
}

/// Operations on durable quarantined artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ArtifactCommand {
    /// Inspect safe metadata for one quarantined artifact.
    Inspect(ArtifactInspectArgs),

    /// Recover one quarantined artifact to a new caller-owned destination.
    Recover(ArtifactRecoverArgs),

    /// Permanently discard one quarantined artifact.
    Discard(ArtifactDiscardArgs),
}

/// Identity of one quarantined artifact.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ArtifactInspectArgs {
    /// Durable processing run ID.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,

    /// Opaque quarantine ID from the processing report.
    #[arg(value_name = "QUARANTINE_ID")]
    pub quarantine_id: String,
}

/// Arguments for recovering one quarantined artifact.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ArtifactRecoverArgs {
    /// Durable processing run ID.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,

    /// Opaque quarantine ID from the processing report.
    #[arg(value_name = "QUARANTINE_ID")]
    pub quarantine_id: String,

    /// Absolute, absent destination for the recovered artifact.
    #[arg(long, value_name = "PATH")]
    pub destination: PathBuf,
}

/// Identity of one quarantined artifact to discard.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct ArtifactDiscardArgs {
    /// Durable processing run ID.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,

    /// Opaque quarantine ID from the processing report.
    #[arg(value_name = "QUARANTINE_ID")]
    pub quarantine_id: String,
}

/// Durable-job command group.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct JobArgs {
    #[command(subcommand)]
    pub command: JobCommand,
}

/// Operations on durable processing jobs.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum JobCommand {
    /// Inspect current mutable status for one durable job.
    Inspect(JobInspectArgs),

    /// Recover all stale jobs found in the configured job store.
    Recover,
}

/// Arguments for inspecting one durable job.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct JobInspectArgs {
    /// Durable processing run ID.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,
}

/// Arguments for the daemon process.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct DaemonArgs {
    /// Run only the named configured job. Repeat to select multiple jobs.
    #[arg(long = "job", value_name = "JOB_ID")]
    pub jobs: Vec<String>,
}

/// Action authority requested for a processing job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum ActionMode {
    /// Evaluate policy without modifying the owned stage.
    Evaluate,

    /// Permit actions up to the authority granted by the selected profile.
    Apply,
}

/// Validates and returns a caller-provided report correlation ID.
///
/// Request IDs are intentionally more limited than arbitrary JSON strings so
/// they can be copied safely into structured logs and operator tooling. They
/// are not filesystem paths, secrets, authorization tokens, or operation IDs.
pub fn validate_request_id(value: &str) -> Result<String, String> {
    const MAX_BYTES: usize = 128;

    if value.is_empty() || value.len() > MAX_BYTES {
        return Err(format!(
            "request ID must contain 1 to {MAX_BYTES} ASCII characters"
        ));
    }

    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Err("request ID must start with an ASCII letter or digit".to_string());
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(
            "request ID may contain only ASCII letters, digits, '.', '_', ':', or '-'".to_string(),
        );
    }

    Ok(value.to_string())
}

fn validate_git_ref(value: &str) -> Result<String, String> {
    const MAX_BYTES: usize = 1024;

    if value.is_empty() || value.len() > MAX_BYTES {
        return Err(format!("Git ref must contain 1 to {MAX_BYTES} bytes"));
    }
    if value.starts_with('-') {
        return Err("Git ref must not begin with '-'".to_string());
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("Git ref must not contain ASCII control characters".to_string());
    }
    if value == "@"
        || value.starts_with('/')
        || value.ends_with('/')
        || value.ends_with('.')
        || value.contains("..")
        || value.contains("@{")
        || value.contains("//")
        || value
            .bytes()
            .any(|byte| matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\'))
        || value
            .split('/')
            .any(|component| component.starts_with('.') || component.ends_with(".lock"))
    {
        return Err("Git ref is not a valid branch or tag name".to_string());
    }
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Git ref must be a branch or tag name, not a raw object ID".to_string());
    }

    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_bounded_and_log_safe() {
        for valid in ["build-4821", "A", "tenant_7:upload.12"] {
            assert_eq!(validate_request_id(valid).unwrap(), valid);
        }

        for invalid in [
            "",
            "-leading",
            "has space",
            "line\nbreak",
            "../escape",
            "ümlaut",
        ] {
            assert!(
                validate_request_id(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(validate_request_id(&"a".repeat(128)).is_ok());
        assert!(validate_request_id(&"a".repeat(129)).is_err());
    }

    #[test]
    fn git_ref_rejects_empty_option_like_control_and_oversized_values() {
        for valid in ["main", "release/v1", "refs/tags/v1.2.3"] {
            assert_eq!(validate_git_ref(valid).unwrap(), valid);
        }
        for invalid in [
            "",
            "--upload-pack=evil",
            "line\nbreak",
            "feature..old",
            "refs/heads/.hidden",
            "refs/tags/release.lock",
            "0123456789abcdef0123456789abcdef01234567",
        ] {
            assert!(validate_git_ref(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(validate_git_ref(&"a".repeat(1024)).is_ok());
        assert!(validate_git_ref(&"a".repeat(1025)).is_err());
    }
}
