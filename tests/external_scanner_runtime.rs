#![cfg(target_os = "linux")]

use file_guardian::analyzers::external::{
    AssignmentDisposition, ExternalScannerRunner, FirstPartyScannerInvocation,
    NormalizedScannerOccurrence, PreparedScannerExecutable, PreparedScannerSandbox,
    ScannerAssignment, ScannerAssignmentSurface, ScannerCancellation, ScannerCompletion,
    ScannerKind, ScannerProtocolError, ScannerRunError, ScannerRunLimits, ScannerSandboxError,
    ScannerSandboxSpec, ScannerVersion, ScannerVersionRequirement,
};
use file_guardian::domain::{
    AnalyzerId, ArtifactId, CandidateId, FindingCategory, InspectionPhase, ObservationId, RuleId,
    Severity, ValidatedLocation,
};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

fn assignment(suffix: &str, path: &str, disposition: AssignmentDisposition) -> ScannerAssignment {
    ScannerAssignment {
        candidate_id: CandidateId::from_suffix(suffix).unwrap(),
        artifact_id: ArtifactId::from_suffix(suffix).unwrap(),
        view_path: path.to_owned(),
        byte_len: 12,
        disposition,
        surface: ScannerAssignmentSurface::WorkingTree,
    }
}

fn occurrence(suffix: &str, artifact_suffix: &str) -> NormalizedScannerOccurrence {
    NormalizedScannerOccurrence {
        occurrence_id: ObservationId::from_suffix(suffix).unwrap(),
        candidate_id: CandidateId::from_suffix(artifact_suffix).unwrap(),
        artifact_id: ArtifactId::from_suffix(artifact_suffix).unwrap(),
        rule_id: RuleId::new("synthetic.credential").unwrap(),
        category: FindingCategory::Credential,
        severity: Severity::High,
        location: Some(ValidatedLocation::line_column(1, 1).unwrap()),
    }
}

#[test]
fn whole_view_completion_is_derived_from_the_host_assignment() {
    let assignments = vec![
        assignment("01", "src/main.rs", AssignmentDisposition::Scan),
        assignment("02", "asset.bin", AssignmentDisposition::NotApplicable),
    ];
    let completion = ScannerCompletion::whole_view(
        ScannerKind::Gitleaks,
        AnalyzerId::new("gitleaks").unwrap(),
        InspectionPhase::Initial,
        &assignments,
        vec![occurrence("01", "01")],
        1024,
        4,
    )
    .unwrap();
    assert!(completion.coverage.is_complete());
    assert_eq!(completion.coverage.assigned, 2);
    assert_eq!(completion.coverage.completed, 1);
    assert_eq!(completion.coverage.not_applicable, 1);
    assert_eq!(completion.surfaces.len(), 1);
    assert_eq!(completion.occurrences.len(), 1);
}

#[test]
fn repeated_artifact_bytes_remain_distinct_candidate_assignments() {
    let first = assignment("01", "first.txt", AssignmentDisposition::Scan);
    let mut second = assignment("02", "second.txt", AssignmentDisposition::Scan);
    second.artifact_id = first.artifact_id.clone();
    let completion = ScannerCompletion::whole_view(
        ScannerKind::Gitleaks,
        AnalyzerId::new("gitleaks").unwrap(),
        InspectionPhase::Initial,
        &[first, second],
        Vec::new(),
        1024,
        4,
    )
    .unwrap();
    assert_eq!(completion.coverage.completed, 2);
}

#[test]
fn completion_rejects_foreign_duplicate_and_not_applicable_occurrences() {
    let assignments = vec![
        assignment("01", "one.txt", AssignmentDisposition::Scan),
        assignment("02", "two.bin", AssignmentDisposition::NotApplicable),
    ];
    let analyzer = || AnalyzerId::new("scanner").unwrap();
    assert_eq!(
        ScannerCompletion::whole_view(
            ScannerKind::Trufflehog,
            analyzer(),
            InspectionPhase::Initial,
            &assignments,
            vec![occurrence("01", "99")],
            1024,
            10,
        ),
        Err(ScannerProtocolError::UnassignedArtifact)
    );
    assert_eq!(
        ScannerCompletion::whole_view(
            ScannerKind::Trufflehog,
            analyzer(),
            InspectionPhase::Initial,
            &assignments,
            vec![occurrence("01", "02")],
            1024,
            10,
        ),
        Err(ScannerProtocolError::NotApplicableFinding)
    );
    assert_eq!(
        ScannerCompletion::whole_view(
            ScannerKind::Trufflehog,
            analyzer(),
            InspectionPhase::Initial,
            &assignments,
            vec![occurrence("01", "01"), occurrence("01", "01")],
            1024,
            10,
        ),
        Err(ScannerProtocolError::DuplicateOccurrence)
    );
}

#[test]
fn completion_rejects_noncanonical_paths_and_finding_overflow() {
    let invalid = [assignment("01", "../outside", AssignmentDisposition::Scan)];
    assert_eq!(
        ScannerCompletion::whole_view(
            ScannerKind::Gitleaks,
            AnalyzerId::new("gitleaks").unwrap(),
            InspectionPhase::Verification,
            &invalid,
            Vec::new(),
            1024,
            1,
        ),
        Err(ScannerProtocolError::InvalidAssignmentPath)
    );
    let valid = [assignment("01", "inside", AssignmentDisposition::Scan)];
    assert_eq!(
        ScannerCompletion::whole_view(
            ScannerKind::Gitleaks,
            AnalyzerId::new("gitleaks").unwrap(),
            InspectionPhase::Verification,
            &valid,
            vec![occurrence("01", "01")],
            1024,
            0,
        ),
        Err(ScannerProtocolError::FindingLimit)
    );
    assert_eq!(
        ScannerCompletion::whole_view(
            ScannerKind::Gitleaks,
            AnalyzerId::new("gitleaks").unwrap(),
            InspectionPhase::Verification,
            &valid,
            Vec::new(),
            11,
            1,
        ),
        Err(ScannerProtocolError::OversizedAssignment)
    );
}

#[test]
fn path_discovery_rejects_empty_and_relative_components() {
    assert_eq!(
        PreparedScannerExecutable::discover(
            ScannerKind::Gitleaks,
            OsStr::new("gitleaks"),
            Some(OsStr::new("/usr/bin::/bin")),
        )
        .unwrap_err(),
        ScannerSandboxError::PathEnvironmentInvalid
    );
    assert_eq!(
        PreparedScannerExecutable::discover(
            ScannerKind::Gitleaks,
            OsStr::new("gitleaks"),
            Some(OsStr::new("relative:/bin")),
        )
        .unwrap_err(),
        ScannerSandboxError::PathEnvironmentInvalid
    );
}

#[test]
fn executable_identity_is_digest_mode_and_inode_bound_and_revalidated() {
    let root = TempDir::new().unwrap();
    let executable = root.path().join("gitleaks");
    write_static_elf(&executable, 0);
    let prepared =
        PreparedScannerExecutable::discover(ScannerKind::Gitleaks, executable.as_os_str(), None)
            .unwrap();
    let identity = prepared.identity().clone();
    assert_ne!(identity.mode & 0o111, 0);
    assert!(identity.byte_len >= 120);
    assert!(prepared.revalidate().is_ok());

    fs::rename(&executable, root.path().join("old-scanner")).unwrap();
    write_static_elf(&executable, 7);
    assert_eq!(
        prepared.revalidate(),
        Err(ScannerSandboxError::ExecutableChanged)
    );
}

#[tokio::test]
async fn pre_cancelled_invocation_never_starts_the_sandbox() {
    let root = TempDir::new().unwrap();
    let scanner_path = root.path().join("trufflehog");
    let bubblewrap_path = root.path().join("bwrap");
    write_static_elf(&scanner_path, 0);
    write_static_elf(&bubblewrap_path, 0);
    let scanner = PreparedScannerExecutable::discover(
        ScannerKind::Trufflehog,
        scanner_path.as_os_str(),
        None,
    )
    .unwrap();
    let sandbox = PreparedScannerSandbox::prepare(ScannerSandboxSpec {
        bubblewrap_executable: bubblewrap_path,
        expected_bubblewrap_version: "test".to_owned(),
    })
    .unwrap();
    let input = root.path().join("input");
    let output = root.path().join("output");
    fs::create_dir(&input).unwrap();
    fs::create_dir(&output).unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    let cancellation = ScannerCancellation::default();
    cancellation.cancel();
    let result = ExternalScannerRunner::new(sandbox)
        .run(
            &scanner,
            ScannerVersionRequirement::new(
                ScannerVersion::new(3, 90, 0),
                ScannerVersion::new(4, 0, 0),
            ),
            FirstPartyScannerInvocation::Trufflehog {
                input_view: &input,
                output_directory: &output,
            },
            ScannerRunLimits {
                wall_timeout: Duration::from_secs(1),
                termination_grace: Duration::from_millis(10),
                max_output_bytes: 1024,
                memory_bytes: 64 * 1024 * 1024,
                cpu_seconds: 1,
                open_files: 32,
            },
            cancellation,
        )
        .await;
    assert_eq!(result.unwrap_err(), ScannerRunError::Cancelled);
}

#[tokio::test]
#[ignore = "live Bubblewrap acceptance; requires a static C toolchain"]
async fn live_bubblewrap_confines_a_malicious_static_scanner_and_scrubs_output() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("scanner.c");
    let scanner_path = root.path().join("trufflehog");
    fs::write(
        &source,
        br#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    puts("trufflehog 3.90.0");
    return 0;
  }
  if (open("/etc/passwd", O_RDONLY) >= 0) return 91;
  int input = open("/input/sample.txt", O_RDONLY);
  if (input < 0) return 92;
  char bytes[8];
  if (read(input, bytes, sizeof(bytes)) <= 0) return 93;
  close(input);
  if (open("/input/sample.txt", O_WRONLY) >= 0) return 94;
  if (access("/input/setsid", F_OK) == 0) {
    pid_t child = fork();
    if (child < 0) return 96;
    if (child == 0) { setsid(); sleep(30); _exit(0); }
    return 0;
  }
  if (access("/input/malicious", F_OK) == 0) {
    mkdir("/output/nested", 0700);
    int output = open("/output/nested/exfil", O_WRONLY | O_CREAT, 0600);
    if (output >= 0) {
      if (write(output, bytes, sizeof(bytes)) < 0) return 95;
      close(output);
    }
  }
  return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .args(["-static", "-Os", "-o"])
        .arg(&scanner_path)
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success());
    let scanner = PreparedScannerExecutable::discover(
        ScannerKind::Trufflehog,
        scanner_path.as_os_str(),
        None,
    )
    .unwrap();
    let sandbox = PreparedScannerSandbox::prepare(ScannerSandboxSpec {
        bubblewrap_executable: "/usr/bin/bwrap".into(),
        expected_bubblewrap_version: "0.11.1".to_owned(),
    })
    .unwrap();
    let limits = ScannerRunLimits {
        wall_timeout: Duration::from_secs(5),
        termination_grace: Duration::from_millis(100),
        max_output_bytes: 4096,
        memory_bytes: 64 * 1024 * 1024,
        cpu_seconds: 2,
        open_files: 32,
    };
    let requirement =
        ScannerVersionRequirement::new(ScannerVersion::new(3, 90, 0), ScannerVersion::new(4, 0, 0));

    let input = root.path().join("input-ok");
    let output = root.path().join("output-ok");
    fs::create_dir(&input).unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(input.join("sample.txt"), b"fixture\n").unwrap();
    fs::set_permissions(input.join("sample.txt"), fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    let result = ExternalScannerRunner::new(sandbox.clone())
        .run(
            &scanner,
            requirement,
            FirstPartyScannerInvocation::Trufflehog {
                input_view: &input,
                output_directory: &output,
            },
            limits.clone(),
            ScannerCancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.version, ScannerVersion::new(3, 90, 0));
    assert_eq!(result.exit.code, Some(0));

    let setsid_input = root.path().join("input-setsid");
    let setsid_output = root.path().join("output-setsid");
    fs::create_dir(&setsid_input).unwrap();
    fs::create_dir(&setsid_output).unwrap();
    fs::write(setsid_input.join("sample.txt"), b"fixture\n").unwrap();
    fs::write(setsid_input.join("setsid"), b"trigger\n").unwrap();
    for path in [setsid_input.join("sample.txt"), setsid_input.join("setsid")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    fs::set_permissions(&setsid_input, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&setsid_output, fs::Permissions::from_mode(0o700)).unwrap();
    let result = ExternalScannerRunner::new(sandbox.clone())
        .run(
            &scanner,
            requirement,
            FirstPartyScannerInvocation::Trufflehog {
                input_view: &setsid_input,
                output_directory: &setsid_output,
            },
            limits.clone(),
            ScannerCancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit.code, Some(0));
    assert_eq!(fs::read_dir(setsid_output).unwrap().count(), 0);

    let malicious_input = root.path().join("input-malicious");
    let malicious_output = root.path().join("output-malicious");
    fs::create_dir(&malicious_input).unwrap();
    fs::create_dir(&malicious_output).unwrap();
    fs::write(malicious_input.join("sample.txt"), b"fixture\n").unwrap();
    fs::write(malicious_input.join("malicious"), b"trigger\n").unwrap();
    for path in [
        malicious_input.join("sample.txt"),
        malicious_input.join("malicious"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    fs::set_permissions(&malicious_input, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&malicious_output, fs::Permissions::from_mode(0o700)).unwrap();
    let result = ExternalScannerRunner::new(sandbox)
        .run(
            &scanner,
            requirement,
            FirstPartyScannerInvocation::Trufflehog {
                input_view: &malicious_input,
                output_directory: &malicious_output,
            },
            limits,
            ScannerCancellation::default(),
        )
        .await;
    assert!(matches!(result, Err(ScannerRunError::PrivateOutput)));
    assert_eq!(fs::read_dir(malicious_output).unwrap().count(), 0);
}

/// Produces a structurally valid little-endian static ELF64 with one PT_LOAD.
/// It is sufficient for immutable preflight tests and is never executed.
fn write_static_elf(path: &std::path::Path, marker: u8) {
    let mut bytes = vec![0_u8; 120];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400078_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    let byte_len = bytes.len() as u64;
    bytes[88..96].copy_from_slice(&byte_len.to_le_bytes());
    bytes[96..104].copy_from_slice(&byte_len.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[119] = marker;
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
