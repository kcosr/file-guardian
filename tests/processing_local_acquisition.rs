#![cfg(unix)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Barrier,
};

use file_guardian::processing::acquisition::local::{
    acquire_local, capture_owned_stage, AcquiredEntryKind, AcquisitionCancellation,
    LocalAcquisitionError, LocalAcquisitionIssueCode, LocalAcquisitionRequest,
};
use file_guardian::processing::config::{CaptureLimits, SymlinkPolicy};
use tempfile::TempDir;

fn limits() -> CaptureLimits {
    CaptureLimits {
        max_entries: 1_000,
        max_files: 1_000,
        max_file_bytes: 128 * 1024 * 1024,
        max_total_bytes: 256 * 1024 * 1024,
        max_depth: 32,
    }
}

struct Fixture {
    root: TempDir,
    jobs: std::path::PathBuf,
    stage: std::path::PathBuf,
    cancellation: AcquisitionCancellation,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let jobs = root.path().join("jobs");
        let run = jobs.join("run_test");
        let stage = run.join("stage");
        fs::create_dir(&jobs).unwrap();
        fs::create_dir(&run).unwrap();
        fs::create_dir(&stage).unwrap();
        for directory in [&jobs, &run, &stage] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            root,
            jobs,
            stage,
            cancellation: AcquisitionCancellation::default(),
        }
    }

    fn source(&self) -> std::path::PathBuf {
        self.root.path().join("source")
    }

    fn acquire(
        &self,
        source: &std::path::Path,
        capture_limits: &CaptureLimits,
        symlinks: SymlinkPolicy,
    ) -> Result<
        file_guardian::processing::acquisition::local::LocalAcquisitionResult,
        LocalAcquisitionError,
    > {
        acquire_local(LocalAcquisitionRequest {
            source,
            stage: &self.stage,
            jobs_root: &self.jobs,
            limits: capture_limits,
            symlinks,
            cancellation: &self.cancellation,
        })
    }
}

#[test]
fn copies_a_literal_tree_with_normalized_publication_modes() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("ordinary"), b"ordinary bytes").unwrap();
    fs::write(source.join("nested/executable"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(
        source.join("nested/executable"),
        fs::Permissions::from_mode(0o751),
    )
    .unwrap();

    let result = fixture
        .acquire(&source, &limits(), SymlinkPolicy::Reject)
        .unwrap();

    assert_eq!(result.statistics.entries, 3);
    assert_eq!(result.statistics.files, 2);
    assert_eq!(
        fs::read(fixture.stage.join("ordinary")).unwrap(),
        b"ordinary bytes"
    );
    assert_eq!(
        fs::read(fixture.stage.join("nested/executable")).unwrap(),
        b"#!/bin/sh\n"
    );
    assert_eq!(
        fs::metadata(fixture.stage.join("ordinary")).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(fixture.stage.join("nested/executable"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert!(result.entries.iter().any(|entry| {
        entry.kind == AcquiredEntryKind::RegularFile && entry.publication_mode == 0o755
    }));
    assert_eq!(
        fs::read(source.join("ordinary")).unwrap(),
        b"ordinary bytes"
    );
}

#[test]
fn rejects_a_single_file_source() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::write(&source, [0_u8, 1, 2, 255]).unwrap();

    assert!(matches!(
        fixture.acquire(&source, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::SpecialFileRejected)
    ));
}

#[test]
fn captures_an_empty_tree_with_a_stable_empty_manifest() {
    let first = Fixture::new();
    let first_source = first.source();
    fs::create_dir(&first_source).unwrap();
    let first_result = first
        .acquire(&first_source, &limits(), SymlinkPolicy::Reject)
        .unwrap();

    let second = Fixture::new();
    let second_source = second.source();
    fs::create_dir(&second_source).unwrap();
    let second_result = second
        .acquire(&second_source, &limits(), SymlinkPolicy::Reject)
        .unwrap();

    assert!(first_result.entries.is_empty());
    assert_eq!(first_result.statistics.entries, 0);
    assert_eq!(
        first_result.manifest_identity,
        second_result.manifest_identity
    );
}

#[test]
fn copies_source_hardlinks_as_independent_stage_files() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("first"), b"shared bytes").unwrap();
    fs::hard_link(source.join("first"), source.join("second")).unwrap();
    assert_eq!(
        fs::metadata(source.join("first")).unwrap().ino(),
        fs::metadata(source.join("second")).unwrap().ino()
    );

    fixture
        .acquire(&source, &limits(), SymlinkPolicy::Reject)
        .unwrap();

    let first = fs::metadata(fixture.stage.join("first")).unwrap();
    let second = fs::metadata(fixture.stage.join("second")).unwrap();
    assert_ne!(first.ino(), second.ino());
    assert_eq!(first.nlink(), 1);
    assert_eq!(second.nlink(), 1);
}

#[test]
fn rejects_links_by_default_and_preserves_them_without_following() {
    let rejected = Fixture::new();
    let source = rejected.source();
    fs::create_dir(&source).unwrap();
    fs::write(rejected.root.path().join("outside"), b"must not be copied").unwrap();
    symlink("../outside", source.join("escape")).unwrap();
    assert!(matches!(
        rejected.acquire(&source, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::SymlinkRejected)
    ));

    let preserved = Fixture::new();
    let source = preserved.source();
    fs::create_dir(&source).unwrap();
    fs::write(preserved.root.path().join("outside"), b"must not be copied").unwrap();
    symlink("../outside", source.join("escape")).unwrap();
    let result = preserved
        .acquire(&source, &limits(), SymlinkPolicy::Preserve)
        .unwrap();
    assert_eq!(result.statistics.symbolic_links, 1);
    assert_eq!(
        fs::read_link(preserved.stage.join("escape")).unwrap(),
        std::path::Path::new("../outside")
    );
    assert_eq!(result.entries[0].kind, AcquiredEntryKind::SymbolicLink);
}

#[test]
fn rejects_root_symlinks_and_special_entries() {
    let linked = Fixture::new();
    fs::write(linked.root.path().join("target"), b"target").unwrap();
    let source = linked.source();
    symlink(linked.root.path().join("target"), &source).unwrap();
    assert!(matches!(
        linked.acquire(&source, &limits(), SymlinkPolicy::Preserve),
        Err(LocalAcquisitionError::SymlinkRejected)
    ));

    let special = Fixture::new();
    let source = special.source();
    fs::create_dir(&source).unwrap();
    let _socket = UnixListener::bind(source.join("socket")).unwrap();
    assert!(matches!(
        special.acquire(&source, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::SpecialFileRejected)
    ));
}

#[test]
fn preserves_non_utf8_names_as_logical_segments() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::create_dir(&source).unwrap();
    let name = OsString::from_vec(vec![b'n', 0xff]);
    fs::write(source.join(&name), b"bytes").unwrap();

    let result = fixture
        .acquire(&source, &limits(), SymlinkPolicy::Reject)
        .unwrap();
    assert_eq!(
        result.entries[0].logical_path.segments()[0].as_slice(),
        &[b'n', 0xff]
    );
    assert_eq!(fs::read(fixture.stage.join(name)).unwrap(), b"bytes");
}

#[test]
fn rejects_source_and_jobs_overlap_before_copying() {
    let fixture = Fixture::new();
    let source = fixture.root.path();
    assert!(matches!(
        fixture.acquire(source, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::SourceJobsOverlap)
    ));
    assert!(fs::read_dir(&fixture.stage).unwrap().next().is_none());

    let nested = fixture.jobs.join("caller-source");
    fs::create_dir(&nested).unwrap();
    assert!(matches!(
        fixture.acquire(&nested, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::SourceJobsOverlap)
    ));
}

#[test]
fn requires_a_fresh_owner_only_stage() {
    let nonempty = Fixture::new();
    let source = nonempty.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("source"), b"source").unwrap();
    fs::write(nonempty.stage.join("old"), b"old").unwrap();
    assert!(matches!(
        nonempty.acquire(&source, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::StageNotEmpty)
    ));

    let exposed = Fixture::new();
    let source = exposed.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("source"), b"source").unwrap();
    fs::set_permissions(&exposed.stage, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        exposed.acquire(&source, &limits(), SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::StageNotPrivate)
    ));
}

#[test]
fn enforces_entry_file_byte_and_depth_limits() {
    let entry = Fixture::new();
    let source = entry.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a"), b"a").unwrap();
    fs::write(source.join("b"), b"b").unwrap();
    let mut bounded = limits();
    bounded.max_entries = 1;
    assert!(matches!(
        entry.acquire(&source, &bounded, SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::EntryLimitExceeded)
    ));

    let count = Fixture::new();
    let source = count.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a"), b"a").unwrap();
    fs::write(source.join("b"), b"b").unwrap();
    let mut bounded = limits();
    bounded.max_files = 1;
    assert!(matches!(
        count.acquire(&source, &bounded, SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::FileLimitExceeded)
    ));

    let file = Fixture::new();
    let source = file.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("large"), b"12345").unwrap();
    let mut bounded = limits();
    bounded.max_file_bytes = 4;
    assert!(matches!(
        file.acquire(&source, &bounded, SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::FileSizeLimitExceeded)
    ));

    let total = Fixture::new();
    let source = total.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a"), b"123").unwrap();
    fs::write(source.join("b"), b"456").unwrap();
    let mut bounded = limits();
    bounded.max_total_bytes = 5;
    assert!(matches!(
        total.acquire(&source, &bounded, SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::TotalSizeLimitExceeded)
    ));

    let depth = Fixture::new();
    let source = depth.source();
    fs::create_dir_all(source.join("one/two")).unwrap();
    let mut bounded = limits();
    bounded.max_depth = 1;
    assert!(matches!(
        depth.acquire(&source, &bounded, SymlinkPolicy::Reject),
        Err(LocalAcquisitionError::DepthLimitExceeded)
    ));
}

#[test]
fn cancellation_is_cooperative_and_fail_closed() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::write(&source, b"source").unwrap();
    fixture.cancellation.cancel();
    let error = fixture
        .acquire(&source, &limits(), SymlinkPolicy::Reject)
        .unwrap_err();
    assert!(matches!(error, LocalAcquisitionError::Cancelled));
    assert_eq!(error.issue().code, LocalAcquisitionIssueCode::Cancelled);
    assert!(fs::read_dir(&fixture.stage).unwrap().next().is_none());
}

#[test]
fn detects_a_file_mutated_while_it_is_copied() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::create_dir(&source).unwrap();
    let mutable = source.join("mutable");
    fs::write(&mutable, vec![0_u8; 32 * 1024 * 1024]).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let writer_source = mutable;
    let writer_barrier = Arc::clone(&barrier);
    let writer_stop = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let mut file = OpenOptions::new().write(true).open(writer_source).unwrap();
        writer_barrier.wait();
        let mut byte = 0_u8;
        while !writer_stop.load(Ordering::Acquire) {
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&[byte]).unwrap();
            file.flush().unwrap();
            byte = byte.wrapping_add(1);
        }
    });
    barrier.wait();
    let result = fixture.acquire(&source, &limits(), SymlinkPolicy::Reject);
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    assert!(matches!(result, Err(LocalAcquisitionError::InputUnstable)));
}

#[test]
fn owned_stage_capture_enforces_symlink_policy_and_preserves_targets_exactly() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.stage.join("nested")).unwrap();
    fs::write(fixture.stage.join("file.txt"), b"bytes").unwrap();
    symlink("../file.txt", fixture.stage.join("nested/safe-link")).unwrap();
    assert!(matches!(
        capture_owned_stage(
            &fixture.stage,
            &fixture.jobs,
            &limits(),
            SymlinkPolicy::Reject,
            &fixture.cancellation,
        ),
        Err(LocalAcquisitionError::SymlinkRejected)
    ));
    let captured = capture_owned_stage(
        &fixture.stage,
        &fixture.jobs,
        &limits(),
        SymlinkPolicy::Preserve,
        &fixture.cancellation,
    )
    .unwrap();
    assert_eq!(captured.statistics.symbolic_links, 1);

    fs::remove_file(fixture.stage.join("nested/safe-link")).unwrap();
    symlink("../../outside", fixture.stage.join("nested/escape-link")).unwrap();
    let captured = capture_owned_stage(
        &fixture.stage,
        &fixture.jobs,
        &limits(),
        SymlinkPolicy::Preserve,
        &fixture.cancellation,
    )
    .unwrap();
    assert_eq!(captured.statistics.symbolic_links, 1);
    assert_eq!(
        fs::read_link(fixture.stage.join("nested/escape-link")).unwrap(),
        PathBuf::from("../../outside")
    );
}

#[test]
fn owned_stage_capture_enforces_limits() {
    let fixture = Fixture::new();
    fs::write(fixture.stage.join("large"), b"12345").unwrap();
    let mut bounded = limits();
    bounded.max_file_bytes = 4;
    assert!(matches!(
        capture_owned_stage(
            &fixture.stage,
            &fixture.jobs,
            &bounded,
            SymlinkPolicy::Reject,
            &fixture.cancellation,
        ),
        Err(LocalAcquisitionError::FileSizeLimitExceeded)
    ));
    bounded.max_file_bytes = 5;
    bounded.max_total_bytes = 4;
    assert!(matches!(
        capture_owned_stage(
            &fixture.stage,
            &fixture.jobs,
            &bounded,
            SymlinkPolicy::Reject,
            &fixture.cancellation,
        ),
        Err(LocalAcquisitionError::TotalSizeLimitExceeded)
    ));
}

#[test]
fn owned_stage_capture_detects_concurrent_file_mutation() {
    let fixture = Fixture::new();
    let path = fixture.stage.join("mutable");
    fs::write(&path, vec![0_u8; 32 * 1024 * 1024]).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let writer_barrier = Arc::clone(&barrier);
    let writer_stop = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        writer_barrier.wait();
        let mut byte = 0_u8;
        while !writer_stop.load(Ordering::Acquire) {
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&[byte]).unwrap();
            file.flush().unwrap();
            byte = byte.wrapping_add(1);
        }
    });
    barrier.wait();
    let result = capture_owned_stage(
        &fixture.stage,
        &fixture.jobs,
        &limits(),
        SymlinkPolicy::Reject,
        &fixture.cancellation,
    );
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    assert!(matches!(result, Err(LocalAcquisitionError::InputUnstable)));
}

#[test]
fn exact_private_modes_are_independent_of_the_process_umask() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "restrictive_umask_helper"])
        .env("FILE_GUARDIAN_UMASK_HELPER", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "umask helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "executed in an isolated child by exact_private_modes_are_independent_of_the_process_umask"]
fn restrictive_umask_helper() {
    if std::env::var_os("FILE_GUARDIAN_UMASK_HELPER").is_none() {
        return;
    }
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("directory")).unwrap();
    fs::write(source.join("directory/file"), b"bytes").unwrap();
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));

    fixture
        .acquire(&source, &limits(), SymlinkPolicy::Reject)
        .unwrap();
    assert_eq!(
        fs::metadata(fixture.stage.join("directory"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(fixture.stage.join("directory/file"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn errors_and_debug_views_do_not_expose_source_paths() {
    let fixture = Fixture::new();
    let secret_component = "private-source-canary-7cd9";
    let source = fixture.root.path().join(secret_component);
    fs::write(&source, b"source").unwrap();
    let capture_limits = limits();
    let request = LocalAcquisitionRequest {
        source: &source,
        stage: &fixture.stage,
        jobs_root: &fixture.jobs,
        limits: &capture_limits,
        symlinks: SymlinkPolicy::Reject,
        cancellation: &fixture.cancellation,
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains(secret_component));
    assert!(!debug.contains(fixture.root.path().to_string_lossy().as_ref()));

    let error = LocalAcquisitionError::InputUnavailable;
    let rendered = format!("{error:?} {} {:?}", error, error.issue());
    assert!(!rendered.contains(secret_component));
    assert!(!rendered.contains(fixture.root.path().to_string_lossy().as_ref()));
}
