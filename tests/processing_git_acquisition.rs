#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use file_guardian::processing::acquisition::git::{
    acquire_remote_repository_source, enumerate_local_repository, freeze_remote_advertisement,
    materialize_frozen_head, GitAcquisitionError, GitCommandLimits, GitCommandRunner,
    GitEnumerationLimits, GitEnumerationRequest, RemoteLocator, SanitizedGitEnvironment,
};
use file_guardian::processing::acquisition::local::{
    acquire_local, AcquisitionCancellation, LocalAcquisitionRequest,
};
use file_guardian::processing::config::{CaptureLimits, SymlinkPolicy};
use file_guardian::processing::domain::{GitBlobMode, GitHistoryScope, GitTransport};
use tempfile::TempDir;

fn git_binary() -> PathBuf {
    PathBuf::from("/usr/bin/git")
}

fn runner() -> GitCommandRunner {
    GitCommandRunner::new(
        git_binary(),
        GitCommandLimits {
            wall_timeout: Duration::from_secs(10),
            max_stdout_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
        },
        SanitizedGitEnvironment::empty(),
    )
    .unwrap()
}

fn enumeration(history: GitHistoryScope, patterns: Vec<&str>) -> GitEnumerationRequest {
    GitEnumerationRequest {
        history,
        history_ref_patterns: patterns.into_iter().map(str::to_owned).collect(),
        checkout_ref: None,
        allowed_checkout_ref_patterns: vec!["refs/heads/*".to_owned()],
        limits: GitEnumerationLimits {
            max_refs: 100,
            max_commits: 100,
            max_unique_blobs: 100,
            max_provenance_occurrences: 1000,
            max_git_bytes: 8 * 1024 * 1024,
        },
    }
}

fn git(repo: &Path, arguments: &[&OsStr]) -> Vec<u8> {
    let output = Command::new(git_binary())
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn git_s(repo: &Path, arguments: &[&str]) -> Vec<u8> {
    let arguments = arguments.iter().map(OsStr::new).collect::<Vec<_>>();
    git(repo, &arguments)
}

fn write(repo: &Path, name: impl AsRef<Path>, bytes: &[u8]) {
    let path = repo.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

fn commit(repo: &Path, message: &str) {
    git_s(repo, &["add", "-A"]);
    git_s(repo, &["commit", "-q", "-m", message]);
}

fn repository_fixture() -> TempDir {
    let fixture = TempDir::new().unwrap();
    git_s(fixture.path(), &["init", "-q", "-b", "main"]);
    git_s(fixture.path(), &["config", "user.name", "Fixture"]);
    git_s(
        fixture.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    write(fixture.path(), "tracked.txt", b"old bytes\n");
    commit(fixture.path(), "base");

    git_s(fixture.path(), &["switch", "-q", "-c", "side"]);
    write(fixture.path(), "side-only.txt", b"only on side\n");
    commit(fixture.path(), "side");

    git_s(fixture.path(), &["switch", "-q", "main"]);
    write(fixture.path(), "tracked.txt", b"head bytes\n");
    let raw_name = OsString::from_vec(vec![b'n', b'o', b'n', 0xff, b'u']);
    write(fixture.path(), PathBuf::from(raw_name), b"raw path\n");
    write(fixture.path(), "bin/run", b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(
        fixture.path().join("bin/run"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    commit(fixture.path(), "main");
    fixture
}

fn capture_limits() -> CaptureLimits {
    CaptureLimits {
        max_entries: 1_000,
        max_files: 1_000,
        max_file_bytes: 1024 * 1024,
        max_total_bytes: 16 * 1024 * 1024,
        max_depth: 32,
    }
}

fn private_stage() -> (TempDir, PathBuf, PathBuf) {
    let jobs = TempDir::new().unwrap();
    fs::set_permissions(jobs.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let run = jobs.path().join("run");
    let stage = run.join("stage");
    fs::create_dir(&run).unwrap();
    fs::create_dir(&stage).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    let root = jobs.path().to_path_buf();
    (jobs, root, stage)
}

fn remote_job_paths() -> (TempDir, PathBuf) {
    let job = TempDir::new().unwrap();
    fs::set_permissions(job.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let stage = job.path().join("stage");
    fs::create_dir(&stage).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    (job, stage)
}

fn remote_fixture_runner(
    directory: &Path,
    repository: &Path,
    locator: &str,
    fail_fetch: bool,
) -> GitCommandRunner {
    fn quoted(value: &str) -> String {
        format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
    }

    let script = directory.join(if fail_fetch {
        "fake-remote-git-failure"
    } else {
        "fake-remote-git"
    });
    let log = directory.join("fake-remote-git.log");
    let body = format!(
        r#"#!/usr/bin/python3
import os
import sys
locator = {}
fixture = {}
args = sys.argv[1:]
while args and (args[0] == '--no-replace-objects' or args[0] == '-c'):
    args = args[1:] if args[0] == '--no-replace-objects' else args[2:]
if {} and len(args) >= 3 and args[0] == '-C' and args[2] == 'fetch':
    with open(os.path.join(args[1], 'credential-bearing-metadata'), 'w') as output:
        output.write(locator)
    sys.stderr.write(locator)
    sys.exit(17)
args = [fixture if value == locator else value for value in args]
with open({}, 'a') as output:
    output.write(repr(args) + '\n')
os.execve('/usr/bin/git', ['/usr/bin/git', '-c', 'protocol.file.allow=always', *args], os.environ)
"#,
        quoted(locator),
        quoted(repository.to_str().unwrap()),
        if fail_fetch { "True" } else { "False" },
        quoted(log.to_str().unwrap()),
    );
    fs::write(&script, body).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    GitCommandRunner::new(
        script,
        GitCommandLimits {
            wall_timeout: Duration::from_secs(10),
            max_stdout_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
        },
        SanitizedGitEnvironment::empty(),
    )
    .unwrap()
}

#[test]
fn remote_locator_accepts_only_bounded_https_and_ssh_forms() {
    for (value, transport) in [
        ("https://example.invalid/org/repo.git", GitTransport::Https),
        ("ssh://git@example.invalid/org/repo.git", GitTransport::Ssh),
        ("git@example.invalid:org/repo.git", GitTransport::Ssh),
    ] {
        let parsed = RemoteLocator::parse(value).unwrap();
        assert_eq!(parsed.transport(), transport);
        assert!(!format!("{parsed:?}").contains("example.invalid"));
    }
    for value in [
        "http://example.invalid/x",
        "file:///tmp/x",
        "/tmp/local",
        "../local",
        "-uploader:repo",
        "https://user:password@example.invalid/x",
        "https://example.invalid/x?token=secret",
        "ext::helper",
    ] {
        assert_eq!(
            RemoteLocator::parse(value).unwrap_err(),
            GitAcquisitionError::InvalidRemote,
            "accepted {value}"
        );
    }
}

#[test]
fn sanitized_authentication_environment_debug_never_exposes_values() {
    let environment = SanitizedGitEnvironment::from_current(&["HOME"]).unwrap();
    let rendered = format!("{environment:?}");
    if let Some(home) = std::env::var_os("HOME") {
        assert!(!rendered.contains(home.to_string_lossy().as_ref()));
    }
    assert!(rendered.contains("configured_entries"));
}

#[tokio::test]
async fn runner_uses_direct_argv_bounds_output_and_withholds_diagnostics() {
    let fixture = TempDir::new().unwrap();
    let runner = GitCommandRunner::new(
        git_binary(),
        GitCommandLimits {
            wall_timeout: Duration::from_secs(2),
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
        SanitizedGitEnvironment::empty(),
    )
    .unwrap();
    let marker = fixture.path().join("must-not-exist");
    let injection = OsString::from(format!("$(touch {})", marker.display()));
    let error = runner.run(None, &[injection]).await.unwrap_err();
    assert!(!marker.exists());
    let rendered = error.to_string();
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("example.invalid"));
    assert!(
        matches!(&error, GitAcquisitionError::CommandFailed { .. }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn runner_times_out_and_reaps_a_process_group() {
    let runner = GitCommandRunner::new(
        git_binary(),
        GitCommandLimits {
            wall_timeout: Duration::from_millis(100),
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
        SanitizedGitEnvironment::empty(),
    )
    .unwrap();
    assert_eq!(
        runner
            .run(
                None,
                &[
                    OsString::from("-c"),
                    OsString::from("alias.slow=!/bin/sleep 30"),
                    OsString::from("slow"),
                ],
            )
            .await
            .unwrap_err(),
        GitAcquisitionError::Timeout
    );
}

#[tokio::test]
async fn runner_rejects_a_descendant_that_holds_output_after_git_exits() {
    let runner = GitCommandRunner::new(
        git_binary(),
        GitCommandLimits {
            wall_timeout: Duration::from_secs(3),
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
        SanitizedGitEnvironment::empty(),
    )
    .unwrap();
    assert_eq!(
        runner
            .run(
                None,
                &[
                    OsString::from("-c"),
                    OsString::from("alias.leaky=!/bin/sleep 30 & exit 0"),
                    OsString::from("leaky"),
                ],
            )
            .await
            .unwrap_err(),
        GitAcquisitionError::OutputRead
    );
}

#[tokio::test]
async fn fake_git_advertisement_is_parsed_without_exposing_locator() {
    let fixture = TempDir::new().unwrap();
    let script = fixture.path().join("fake-git");
    let oid = "1111111111111111111111111111111111111111";
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf 'ref: refs/heads/main\\tHEAD\\n{oid}\\tHEAD\\n{oid}\\trefs/heads/main\\n'\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let runner = GitCommandRunner::new(
        &script,
        GitCommandLimits {
            wall_timeout: Duration::from_secs(2),
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
        SanitizedGitEnvironment::empty(),
    )
    .unwrap();
    let locator = RemoteLocator::parse("ssh://git@example.invalid/org/private").unwrap();
    let advertisement = freeze_remote_advertisement(&runner, &locator, 10)
        .await
        .unwrap();
    assert_eq!(advertisement.transport, GitTransport::Ssh);
    assert_eq!(advertisement.object_format, "sha1");
    assert_eq!(advertisement.refs.len(), 1);
}

#[tokio::test]
async fn remote_acquisition_freezes_all_refs_publishes_head_and_scrubs_repository_metadata() {
    let fixture = repository_fixture();
    let runner_dir = TempDir::new().unwrap();
    let locator_text = "https://git@example.invalid/private/repository.git";
    let runner = remote_fixture_runner(runner_dir.path(), fixture.path(), locator_text, false);
    let locator = RemoteLocator::parse(locator_text).unwrap();
    let (_job, stage) = remote_job_paths();
    let cancellation = AcquisitionCancellation::default();

    let acquired = acquire_remote_repository_source(
        &runner,
        &locator,
        &enumeration(GitHistoryScope::AllRefs, vec![]),
        &stage,
        &capture_limits(),
        SymlinkPolicy::Reject,
        &cancellation,
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "remote acquisition failed: {error:?}; commands: {}",
            fs::read_to_string(runner_dir.path().join("fake-remote-git.log")).unwrap_or_default()
        )
    });

    assert!(stage.join(".git").is_dir());
    assert!(!git_s(&stage, &["log", "-1", "--format=%H"]).is_empty());
    assert_eq!(
        fs::read(stage.join("tracked.txt")).unwrap(),
        b"head bytes\n"
    );
    assert_eq!(acquired.repository.commits.len(), 3);
    assert!(acquired.repository.frozen_refs.len() >= 2);
    assert_eq!(acquired.summary.transport, Some(GitTransport::Https));
    assert_eq!(acquired.summary.commit_count, 3);
    assert_eq!(
        acquired.summary.working_tree_manifest_identity,
        Some(acquired.working_tree.manifest_identity)
    );
    assert!(!format!("{:?}", acquired.summary).contains("example.invalid"));
    assert!(acquired
        .working_tree
        .entries
        .iter()
        .any(|entry| entry.logical_path.to_string() == "tracked.txt"));
    assert!(acquired.working_tree.statistics.files > 3);
}

#[tokio::test]
async fn remote_acquisition_honors_head_and_reachable_ref_scopes() {
    let fixture = repository_fixture();
    let runner_dir = TempDir::new().unwrap();
    let locator_text = "ssh://git@example.invalid/private/scoped.git";
    let runner = remote_fixture_runner(runner_dir.path(), fixture.path(), locator_text, false);
    let locator = RemoteLocator::parse(locator_text).unwrap();

    let (_head_job, head_stage) = remote_job_paths();
    let cancellation = AcquisitionCancellation::default();
    let head = acquire_remote_repository_source(
        &runner,
        &locator,
        &enumeration(GitHistoryScope::Head, vec![]),
        &head_stage,
        &capture_limits(),
        SymlinkPolicy::Reject,
        &cancellation,
    )
    .await
    .unwrap();
    assert_eq!(head.repository.commits.len(), 1);
    assert_eq!(head.repository.frozen_refs.len(), 1);
    assert!(head_stage.join(".git").is_dir());

    let (_reachable_job, reachable_stage) = remote_job_paths();
    let reachable = acquire_remote_repository_source(
        &runner,
        &locator,
        &enumeration(GitHistoryScope::Reachable, vec!["refs/heads/side"]),
        &reachable_stage,
        &capture_limits(),
        SymlinkPolicy::Reject,
        &cancellation,
    )
    .await
    .unwrap();
    assert_eq!(reachable.repository.commits.len(), 3);
    assert_eq!(reachable.repository.frozen_refs.len(), 2);
    assert!(reachable_stage.join(".git").is_dir());
}

#[tokio::test]
async fn remote_acquisition_removes_credential_bearing_metadata_on_fetch_failure() {
    let fixture = repository_fixture();
    let runner_dir = TempDir::new().unwrap();
    let locator_text = "https://git@example.invalid/private/failure.git";
    let runner = remote_fixture_runner(runner_dir.path(), fixture.path(), locator_text, true);
    let locator = RemoteLocator::parse(locator_text).unwrap();
    let (_job, stage) = remote_job_paths();
    let cancellation = AcquisitionCancellation::default();

    let error = acquire_remote_repository_source(
        &runner,
        &locator,
        &enumeration(GitHistoryScope::Head, vec![]),
        &stage,
        &capture_limits(),
        SymlinkPolicy::Reject,
        &cancellation,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, GitAcquisitionError::CommandFailed { .. }));
    assert!(!error.to_string().contains(locator_text));
    let staged_config = fs::read_to_string(stage.join(".git/config")).unwrap_or_default();
    assert!(!staged_config.contains(locator_text));
}

#[tokio::test]
async fn real_repository_head_and_all_ref_scopes_are_distinct_and_paths_are_lossless() {
    let fixture = repository_fixture();
    let head = enumerate_local_repository(
        &runner(),
        fixture.path(),
        &enumeration(GitHistoryScope::Head, vec![]),
    )
    .await
    .unwrap();
    assert_eq!(head.commits.len(), 1);
    assert!(head.blobs.iter().any(|blob| {
        blob.provenance.occurrences.iter().any(|occurrence| {
            occurrence
                .path
                .segments()
                .iter()
                .any(|segment| segment.as_slice().contains(&0xff))
        })
    }));

    let all = enumerate_local_repository(
        &runner(),
        fixture.path(),
        &enumeration(GitHistoryScope::AllRefs, vec![]),
    )
    .await
    .unwrap();
    assert_eq!(all.commits.len(), 3);
    assert!(all.commits.len() > head.commits.len());
    assert!(all.frozen_refs.len() >= 2);

    let stage = TempDir::new().unwrap();
    materialize_frozen_head(&head, stage.path(), false).unwrap();
    assert_eq!(
        fs::read(stage.path().join("tracked.txt")).unwrap(),
        b"head bytes\n"
    );
    assert!(!stage.path().join(".git").exists());
    assert!(head
        .blobs
        .iter()
        .any(|blob| blob.provenance.mode == GitBlobMode::Executable));
    assert_eq!(
        fs::metadata(stage.path().join("bin/run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[tokio::test]
async fn local_directory_copy_preserves_the_exact_repository_and_detects_git_afterward() {
    let fixture = repository_fixture();
    write(fixture.path(), ".gitignore", b"ignored.txt\n");
    commit(fixture.path(), "ignore policy");
    write(fixture.path(), "tracked.txt", b"dirty working tree bytes\n");
    write(fixture.path(), "untracked.txt", b"untracked bytes\n");
    write(
        fixture.path(),
        "ignored.txt",
        b"ignored but published bytes\n",
    );

    let (_jobs, jobs_root, stage) = private_stage();
    let cancellation = AcquisitionCancellation::default();
    let acquired = acquire_local(LocalAcquisitionRequest {
        source: fixture.path(),
        stage: &stage,
        jobs_root: &jobs_root,
        limits: &capture_limits(),
        symlinks: SymlinkPolicy::Reject,
        cancellation: &cancellation,
    })
    .unwrap();
    let repository = enumerate_local_repository(
        &runner(),
        &stage,
        &enumeration(GitHistoryScope::Head, vec![]),
    )
    .await
    .unwrap();

    assert!(acquired
        .entries
        .iter()
        .any(|entry| { entry.logical_path.to_string() == ".git/HEAD" }));
    assert_eq!(
        fs::read(stage.join("tracked.txt")).unwrap(),
        b"dirty working tree bytes\n"
    );
    assert_eq!(
        fs::read(stage.join("untracked.txt")).unwrap(),
        b"untracked bytes\n"
    );
    assert_eq!(
        fs::read(stage.join("ignored.txt")).unwrap(),
        b"ignored but published bytes\n"
    );
    assert!(stage.join(".git").is_dir());
    assert!(repository
        .head_tree
        .iter()
        .any(|entry| entry.bytes == b"head bytes\n"));
}

#[tokio::test]
async fn local_directory_copy_preserves_absolute_and_escaping_symlinks_exactly() {
    for (name, target) in [
        ("absolute-link", "/etc/passwd"),
        ("escape-link", "../outside"),
    ] {
        let fixture = repository_fixture();
        std::os::unix::fs::symlink(target, fixture.path().join(name)).unwrap();
        let (_jobs, jobs_root, stage) = private_stage();
        let cancellation = AcquisitionCancellation::default();
        acquire_local(LocalAcquisitionRequest {
            source: fixture.path(),
            stage: &stage,
            jobs_root: &jobs_root,
            limits: &capture_limits(),
            symlinks: SymlinkPolicy::Preserve,
            cancellation: &cancellation,
        })
        .unwrap();
        assert_eq!(
            fs::read_link(stage.join(name)).unwrap(),
            PathBuf::from(target)
        );
    }
}

#[tokio::test]
async fn frozen_head_materialization_preserves_an_escaping_symlink_without_following_it() {
    let fixture = repository_fixture();
    fs::create_dir_all(fixture.path().join("nested")).unwrap();
    std::os::unix::fs::symlink("../../outside", fixture.path().join("nested/bad-link")).unwrap();
    commit(fixture.path(), "escaping symlink");
    let frozen = enumerate_local_repository(
        &runner(),
        fixture.path(),
        &enumeration(GitHistoryScope::Head, vec![]),
    )
    .await
    .unwrap();
    let stage = TempDir::new().unwrap();
    materialize_frozen_head(&frozen, stage.path(), true).unwrap();
    assert_eq!(
        fs::read_link(stage.path().join("nested/bad-link")).unwrap(),
        PathBuf::from("../../outside")
    );
}

#[tokio::test]
async fn frozen_head_materialization_preserves_a_relative_symlink_within_the_tree() {
    let fixture = repository_fixture();
    fs::create_dir_all(fixture.path().join("nested")).unwrap();
    std::os::unix::fs::symlink("../tracked.txt", fixture.path().join("nested/good-link")).unwrap();
    commit(fixture.path(), "safe symlink");
    let frozen = enumerate_local_repository(
        &runner(),
        fixture.path(),
        &enumeration(GitHistoryScope::Head, vec![]),
    )
    .await
    .unwrap();
    let stage = TempDir::new().unwrap();
    materialize_frozen_head(&frozen, stage.path(), true).unwrap();
    assert_eq!(
        fs::read_link(stage.path().join("nested/good-link")).unwrap(),
        Path::new("../tracked.txt")
    );
}

#[tokio::test]
async fn reachable_requires_every_pattern_and_checkout_policy_is_enforced() {
    let fixture = repository_fixture();
    let reachable = enumerate_local_repository(
        &runner(),
        fixture.path(),
        &enumeration(GitHistoryScope::Reachable, vec!["refs/heads/side"]),
    )
    .await
    .unwrap();
    assert_eq!(reachable.commits.len(), 3);

    let error = enumerate_local_repository(
        &runner(),
        fixture.path(),
        &enumeration(GitHistoryScope::Reachable, vec!["refs/heads/missing"]),
    )
    .await
    .unwrap_err();
    assert_eq!(error, GitAcquisitionError::RefPatternUnmatched);

    let mut request = enumeration(GitHistoryScope::Head, vec![]);
    request.allowed_checkout_ref_patterns = vec!["refs/tags/*".to_owned()];
    assert_eq!(
        enumerate_local_repository(&runner(), fixture.path(), &request)
            .await
            .unwrap_err(),
        GitAcquisitionError::CheckoutRefForbidden
    );
}

#[tokio::test]
async fn lfs_pointers_and_gitlinks_fail_closed() {
    let fixture = repository_fixture();
    write(
        fixture.path(),
        "pointer.bin",
        b"version https://git-lfs.github.com/spec/v1\noid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsize 7\n",
    );
    commit(fixture.path(), "lfs pointer");
    assert_eq!(
        enumerate_local_repository(
            &runner(),
            fixture.path(),
            &enumeration(GitHistoryScope::Head, vec![]),
        )
        .await
        .unwrap_err(),
        GitAcquisitionError::LfsPointer
    );

    fs::remove_file(fixture.path().join("pointer.bin")).unwrap();
    git_s(fixture.path(), &["add", "-A"]);
    let head = String::from_utf8(git_s(fixture.path(), &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    git_s(
        fixture.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            &head,
            "vendor/sub",
        ],
    );
    git_s(fixture.path(), &["commit", "-q", "-m", "gitlink"]);
    assert_eq!(
        enumerate_local_repository(
            &runner(),
            fixture.path(),
            &enumeration(GitHistoryScope::Head, vec![]),
        )
        .await
        .unwrap_err(),
        GitAcquisitionError::Submodule
    );
}
