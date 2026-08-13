//! Command-line contract for the explicit authorization and daemon modes.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};

/// File Guardian command-line arguments.
#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(
    author,
    version,
    about = "Evaluates file trees against configured authorization policy"
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
    /// Evaluate one file or directory as a single authorization transaction.
    Authorize(AuthorizeArgs),

    /// Run configured background jobs until shutdown.
    Daemon(DaemonArgs),
}

/// Arguments for one authorization transaction.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct AuthorizeArgs {
    /// Authorization profile ID. The configured default is used when omitted.
    #[arg(long, value_name = "PROFILE_ID")]
    pub profile: Option<String>,

    /// Bounded, caller-provided correlation ID echoed in the report.
    #[arg(long, value_name = "ID", value_parser = validate_request_id)]
    pub request_id: Option<String>,

    /// Requested action authority. Policy may reduce, but never expand, it.
    #[arg(long, value_enum, value_name = "MODE")]
    pub action_mode: Option<ActionMode>,

    /// Literal regular file or directory to authorize.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

/// Arguments for the daemon process.
#[derive(Clone, Debug, Eq, PartialEq, ClapArgs)]
pub struct DaemonArgs {
    /// Run only the named configured job. Repeat to select multiple jobs.
    #[arg(long = "job", value_name = "JOB_ID")]
    pub jobs: Vec<String>,
}

/// Action authority requested for an authorization transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum ActionMode {
    /// Evaluate policy without modifying the staged transaction.
    Evaluate,

    /// Permit actions up to the authority granted by the selected profile.
    Apply,
}

/// Validates and returns a caller-provided report correlation ID.
///
/// Request IDs are intentionally more limited than arbitrary JSON strings so
/// they can be copied safely into structured logs and operator tooling. They
/// are not filesystem paths, secrets, or authorization tokens.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authorize_with_every_option() {
        let args = Args::try_parse_from([
            "file-guardian",
            "--config",
            "/etc/file-guardian-v2.toml",
            "authorize",
            "--profile",
            "publication",
            "--request-id",
            "build:4821-attempt_2",
            "--action-mode",
            "evaluate",
            "/private/staging/upload",
        ])
        .unwrap();

        assert_eq!(
            args.config,
            Some(PathBuf::from("/etc/file-guardian-v2.toml"))
        );
        assert_eq!(
            args.command,
            Command::Authorize(AuthorizeArgs {
                profile: Some("publication".to_string()),
                request_id: Some("build:4821-attempt_2".to_string()),
                action_mode: Some(ActionMode::Evaluate),
                path: PathBuf::from("/private/staging/upload"),
            })
        );
    }

    #[test]
    fn parses_apply_and_repeated_daemon_jobs() {
        let authorize = Args::try_parse_from([
            "file-guardian",
            "authorize",
            "--action-mode",
            "apply",
            "/tmp/input",
        ])
        .unwrap();
        assert!(matches!(
            authorize.command,
            Command::Authorize(AuthorizeArgs {
                action_mode: Some(ActionMode::Apply),
                ..
            })
        ));

        let daemon = Args::try_parse_from([
            "file-guardian",
            "daemon",
            "--job",
            "uploads",
            "--job",
            "fingerprint-sync",
        ])
        .unwrap();
        assert_eq!(
            daemon.command,
            Command::Daemon(DaemonArgs {
                jobs: vec!["uploads".to_string(), "fingerprint-sync".to_string()]
            })
        );
    }

    #[test]
    fn authorize_requires_exactly_one_path() {
        assert!(Args::try_parse_from(["file-guardian", "authorize"]).is_err());
        assert!(
            Args::try_parse_from(["file-guardian", "authorize", "/tmp/one", "/tmp/two"]).is_err()
        );
    }

    #[test]
    fn rejects_obsolete_implicit_mode_flags_and_bare_invocation() {
        assert!(Args::try_parse_from(["file-guardian"]).is_err());
        assert!(Args::try_parse_from(["file-guardian", "--once"]).is_err());
        assert!(Args::try_parse_from(["file-guardian", "--dry-run"]).is_err());
        assert!(Args::try_parse_from(["file-guardian", "/tmp/input"]).is_err());
    }

    #[test]
    fn rejects_unknown_action_modes() {
        assert!(Args::try_parse_from([
            "file-guardian",
            "authorize",
            "--action-mode",
            "delete",
            "/tmp/input"
        ])
        .is_err());
    }

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
}
