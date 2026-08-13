use std::path::PathBuf;

use clap::Parser;
use file_guardian::cli::{ActionMode, Args, AuthorizeArgs, Command, DaemonArgs};

#[test]
fn public_parser_exposes_explicit_authorize_contract() {
    let args = Args::try_parse_from([
        "file-guardian",
        "authorize",
        "--profile",
        "publication",
        "--request-id",
        "upload-42",
        "--action-mode",
        "evaluate",
        "/staging/upload-42",
    ])
    .unwrap();

    assert_eq!(
        args.command,
        Command::Authorize(AuthorizeArgs {
            profile: Some("publication".to_string()),
            request_id: Some("upload-42".to_string()),
            action_mode: Some(ActionMode::Evaluate),
            path: PathBuf::from("/staging/upload-42"),
        })
    );
}

#[test]
fn public_parser_exposes_explicit_daemon_contract() {
    let args = Args::try_parse_from([
        "file-guardian",
        "--config",
        "/etc/file-guardian/config.toml",
        "daemon",
        "--job",
        "uploads",
        "--job",
        "scheduled-policy-scan",
    ])
    .unwrap();

    assert_eq!(
        args.command,
        Command::Daemon(DaemonArgs {
            jobs: vec!["uploads".to_string(), "scheduled-policy-scan".to_string()],
        })
    );
}

#[test]
fn obsolete_implicit_modes_are_not_accepted() {
    for invocation in [
        vec!["file-guardian", "--once"],
        vec!["file-guardian", "--dry-run"],
        vec!["file-guardian", "/tmp/input"],
    ] {
        assert!(Args::try_parse_from(invocation).is_err());
    }
}

#[test]
fn authorize_operand_cardinality_is_enforced_by_clap() {
    assert!(Args::try_parse_from(["file-guardian", "authorize"]).is_err());
    assert!(
        Args::try_parse_from(["file-guardian", "authorize", "/tmp/input-a", "/tmp/input-b"])
            .is_err()
    );
}
