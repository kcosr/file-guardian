use std::path::PathBuf;

use clap::Parser;
use file_guardian::cli::{
    ActionMode, Args, ArtifactArgs, ArtifactCommand, ArtifactDiscardArgs, ArtifactInspectArgs,
    ArtifactRecoverArgs, Command, DaemonArgs, HandoffMode, JobArgs, JobCommand, JobInspectArgs,
    ProcessArgs, ProcessGitArgs, ProcessPathArgs, ProcessSource, StageArgs, StageCommand,
    StageDiscardArgs, StageHandoffArgs,
};

#[test]
fn parses_each_processing_source_with_the_common_options() {
    let path = Args::try_parse_from([
        "file-guardian",
        "--config",
        "/etc/file-guardian.toml",
        "process",
        "--profile",
        "upload",
        "--request-id",
        "tenant_7:upload.12",
        "--action-mode",
        "apply",
        "path",
        "/incoming/upload",
    ])
    .unwrap();
    assert_eq!(path.config, Some(PathBuf::from("/etc/file-guardian.toml")));
    assert_eq!(
        path.command,
        Command::Process(ProcessArgs {
            profile: Some("upload".to_string()),
            request_id: Some("tenant_7:upload.12".to_string()),
            action_mode: Some(ActionMode::Apply),
            source: ProcessSource::Path(ProcessPathArgs {
                path: PathBuf::from("/incoming/upload"),
            }),
        })
    );

    let git = Args::try_parse_from([
        "file-guardian",
        "process",
        "--profile",
        "repository-review",
        "git",
        "--ref",
        "v2.1.0",
        "git@example.test:team/project.git",
    ])
    .unwrap();
    assert_eq!(
        git.command,
        Command::Process(ProcessArgs {
            profile: Some("repository-review".to_string()),
            request_id: None,
            action_mode: None,
            source: ProcessSource::Git(ProcessGitArgs {
                checkout_ref: Some("v2.1.0".to_string()),
                remote: "git@example.test:team/project.git".to_string(),
            }),
        })
    );
}

#[test]
fn parses_stage_handoff_and_discard() {
    let handoff = Args::try_parse_from([
        "file-guardian",
        "stage",
        "handoff",
        "run_abc",
        "--destination",
        "/approved/upload",
        "--mode",
        "copy",
    ])
    .unwrap();
    assert_eq!(
        handoff.command,
        Command::Stage(StageArgs {
            command: StageCommand::Handoff(StageHandoffArgs {
                run_id: "run_abc".to_string(),
                destination: PathBuf::from("/approved/upload"),
                mode: HandoffMode::Copy,
            }),
        })
    );

    let discard = Args::try_parse_from(["file-guardian", "stage", "discard", "run_abc"]).unwrap();
    assert_eq!(
        discard.command,
        Command::Stage(StageArgs {
            command: StageCommand::Discard(StageDiscardArgs {
                run_id: "run_abc".to_string(),
            }),
        })
    );
}

#[test]
fn parses_all_artifact_operations() {
    let inspect = Args::try_parse_from([
        "file-guardian",
        "artifact",
        "inspect",
        "run_abc",
        "quarantine_7",
    ])
    .unwrap();
    assert_eq!(
        inspect.command,
        Command::Artifact(ArtifactArgs {
            command: ArtifactCommand::Inspect(ArtifactInspectArgs {
                run_id: "run_abc".to_string(),
                quarantine_id: "quarantine_7".to_string(),
            }),
        })
    );

    let recover = Args::try_parse_from([
        "file-guardian",
        "artifact",
        "recover",
        "run_abc",
        "quarantine_7",
        "--destination",
        "/recovered/item",
    ])
    .unwrap();
    assert_eq!(
        recover.command,
        Command::Artifact(ArtifactArgs {
            command: ArtifactCommand::Recover(ArtifactRecoverArgs {
                run_id: "run_abc".to_string(),
                quarantine_id: "quarantine_7".to_string(),
                destination: PathBuf::from("/recovered/item"),
            }),
        })
    );

    let discard = Args::try_parse_from([
        "file-guardian",
        "artifact",
        "discard",
        "run_abc",
        "quarantine_7",
    ])
    .unwrap();
    assert_eq!(
        discard.command,
        Command::Artifact(ArtifactArgs {
            command: ArtifactCommand::Discard(ArtifactDiscardArgs {
                run_id: "run_abc".to_string(),
                quarantine_id: "quarantine_7".to_string(),
            }),
        })
    );
}

#[test]
fn parses_job_inspection_global_recovery_and_retained_daemon_selection() {
    let inspect = Args::try_parse_from(["file-guardian", "job", "inspect", "run_abc"]).unwrap();
    assert_eq!(
        inspect.command,
        Command::Job(JobArgs {
            command: JobCommand::Inspect(JobInspectArgs {
                run_id: "run_abc".to_string(),
            }),
        })
    );

    let recover = Args::try_parse_from(["file-guardian", "job", "recover"]).unwrap();
    assert_eq!(
        recover.command,
        Command::Job(JobArgs {
            command: JobCommand::Recover,
        })
    );

    let daemon = Args::try_parse_from([
        "file-guardian",
        "daemon",
        "--job",
        "uploads",
        "--job",
        "repository-review",
    ])
    .unwrap();
    assert_eq!(
        daemon.command,
        Command::Daemon(DaemonArgs {
            jobs: vec!["uploads".to_string(), "repository-review".to_string()],
        })
    );
}

#[test]
fn rejects_obsolete_authorize_and_implicit_modes() {
    for invocation in [
        vec!["file-guardian"],
        vec!["file-guardian", "authorize", "/tmp/input"],
        vec!["file-guardian", "--once"],
        vec!["file-guardian", "--dry-run"],
        vec!["file-guardian", "/tmp/input"],
    ] {
        assert!(Args::try_parse_from(invocation).is_err());
    }
}

#[test]
fn rejects_missing_extra_and_misplaced_processing_arguments() {
    for invocation in [
        vec!["file-guardian", "process"],
        vec!["file-guardian", "process", "path"],
        vec!["file-guardian", "process", "path", "/one", "/two"],
        vec!["file-guardian", "process", "repo"],
        vec!["file-guardian", "process", "git"],
        vec!["file-guardian", "process", "path", "--ref", "main", "/one"],
        vec![
            "file-guardian",
            "process",
            "path",
            "/one",
            "--profile",
            "late",
        ],
        vec![
            "file-guardian",
            "process",
            "--action-mode",
            "delete",
            "path",
            "/one",
        ],
        vec![
            "file-guardian",
            "process",
            "repo",
            "--ref",
            "--evil",
            "/repo",
        ],
    ] {
        assert!(
            Args::try_parse_from(invocation.clone()).is_err(),
            "accepted {invocation:?}"
        );
    }
}

#[test]
fn rejects_incomplete_auxiliary_commands_and_unknown_modes() {
    for invocation in [
        vec!["file-guardian", "stage"],
        vec!["file-guardian", "stage", "handoff", "run_abc"],
        vec![
            "file-guardian",
            "stage",
            "handoff",
            "run_abc",
            "--destination",
            "/target",
            "--mode",
            "rename",
        ],
        vec!["file-guardian", "stage", "discard"],
        vec!["file-guardian", "stage", "discard", "run_abc", "extra"],
        vec!["file-guardian", "artifact", "inspect", "run_abc"],
        vec![
            "file-guardian",
            "artifact",
            "inspect",
            "run_abc",
            "q_1",
            "extra",
        ],
        vec!["file-guardian", "artifact", "recover", "run_abc", "q_1"],
        vec!["file-guardian", "artifact", "discard", "run_abc"],
        vec!["file-guardian", "job", "inspect"],
        vec!["file-guardian", "job", "recover", "run_abc"],
    ] {
        assert!(
            Args::try_parse_from(invocation.clone()).is_err(),
            "accepted {invocation:?}"
        );
    }
}

#[test]
fn operation_id_is_not_a_caller_visible_flag() {
    for invocation in [
        vec![
            "file-guardian",
            "stage",
            "discard",
            "run_abc",
            "--operation-id",
            "retry-1",
        ],
        vec![
            "file-guardian",
            "artifact",
            "recover",
            "run_abc",
            "q_1",
            "--destination",
            "/target",
            "--operation-id",
            "retry-1",
        ],
        vec![
            "file-guardian",
            "artifact",
            "discard",
            "run_abc",
            "q_1",
            "--operation-id",
            "retry-1",
        ],
        vec![
            "file-guardian",
            "job",
            "recover",
            "--operation-id",
            "retry-1",
        ],
        vec![
            "file-guardian",
            "stage",
            "handoff",
            "run_abc",
            "--destination",
            "/target",
            "--mode",
            "move",
            "--operation-id",
            "retry-1",
        ],
    ] {
        assert!(Args::try_parse_from(invocation).is_err());
    }
}

#[test]
fn request_id_validation_is_preserved_on_process() {
    for valid in ["build-4821", "A", "tenant_7:upload.12"] {
        assert!(Args::try_parse_from([
            "file-guardian",
            "process",
            "--request-id",
            valid,
            "path",
            "/input",
        ])
        .is_ok());
    }

    for invalid in [
        "",
        "-leading",
        "has space",
        "line\nbreak",
        "../escape",
        "ümlaut",
    ] {
        assert!(Args::try_parse_from([
            "file-guardian",
            "process",
            "--request-id",
            invalid,
            "path",
            "/input",
        ])
        .is_err());
    }
    assert!(Args::try_parse_from([
        "file-guardian",
        "process",
        "--request-id",
        &"a".repeat(128),
        "path",
        "/input",
    ])
    .is_ok());
    assert!(Args::try_parse_from([
        "file-guardian",
        "process",
        "--request-id",
        &"a".repeat(129),
        "path",
        "/input",
    ])
    .is_err());
}
