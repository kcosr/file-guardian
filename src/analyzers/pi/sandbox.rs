use super::proxy::NATIVE_SEARCH_MAX_RESULTS;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

pub(crate) const PI_TOOLS: &str =
    "bash,read,grep,find,ls,manifest_list,triage_request,submit_triage";
pub(crate) const PI_CLI_OUTPUT_MODE: &str = "text";
pub(crate) const PI_RUNTIME_CONTEXT_MODE: &str = "print";

/// Administrator-installed runtime paths. File Guardian validates the normal
/// executable and expected versions; it does not construct or attest a private
/// runtime closure.
#[derive(Clone, Debug)]
pub(crate) struct PiRuntimeSpec {
    pub bubblewrap_executable: PathBuf,
    pub expected_bubblewrap_version: String,
    pub pi_executable: PathBuf,
    pub expected_pi_version: String,
    pub instruction_file: PathBuf,
    pub trusted_extension: PathBuf,
    pub tool_sidecar_runner: PathBuf,
    pub isolated_agent_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedPiRuntime {
    pub(crate) spec: PiRuntimeSpec,
    identity: [u8; 32],
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum PiSandboxError {
    #[cfg(not(target_os = "linux"))]
    #[error("Pi triage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("Pi runtime configuration failed preflight")]
    InvalidRuntime,
    #[error("Bubblewrap version verification failed")]
    BubblewrapVersion,
}

impl PreparedPiRuntime {
    pub(crate) fn prepare(spec: PiRuntimeSpec) -> Result<Self, PiSandboxError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = spec;
            return Err(PiSandboxError::UnsupportedPlatform);
        }
        #[cfg(target_os = "linux")]
        {
            validate_runtime_spec(&spec)?;
            let scratch = spec.isolated_agent_dir.join("scratch");
            if !scratch.exists() {
                fs::create_dir(&scratch).map_err(|_| PiSandboxError::InvalidRuntime)?;
                fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700))
                    .map_err(|_| PiSandboxError::InvalidRuntime)?;
            }
            validate_private_directory(&scratch)?;
            let identity = runtime_identity(&spec);
            Ok(Self { spec, identity })
        }
    }

    pub(crate) fn revalidate(&self) -> Result<(), PiSandboxError> {
        validate_runtime_spec(&self.spec)?;
        validate_private_directory(&self.spec.isolated_agent_dir.join("scratch"))
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub(crate) async fn verify_bubblewrap_version(&self) -> Result<(), PiSandboxError> {
        self.revalidate()?;
        let mut child = Command::new(&self.spec.bubblewrap_executable)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| PiSandboxError::BubblewrapVersion)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(PiSandboxError::BubblewrapVersion)?;
        let read = async {
            let mut bytes = Vec::with_capacity(64);
            stdout
                .take(128)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| PiSandboxError::BubblewrapVersion)?;
            let status = child
                .wait()
                .await
                .map_err(|_| PiSandboxError::BubblewrapVersion)?;
            Ok::<_, PiSandboxError>((status, bytes))
        };
        let (status, bytes) = match timeout(Duration::from_secs(2), read).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(1), child.wait()).await;
                return Err(PiSandboxError::BubblewrapVersion);
            }
        };
        let expected = format!("bubblewrap {}\n", self.spec.expected_bubblewrap_version);
        if !status.success() || bytes != expected.as_bytes() {
            return Err(PiSandboxError::BubblewrapVersion);
        }
        self.revalidate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PiProcessCommand {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub current_directory: PathBuf,
    pub inherited_proxy_fd: RawFd,
}

impl std::fmt::Debug for PiProcessCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PiProcessCommand")
            .field("program", &self.program)
            .field("arguments", &self.arguments)
            .field(
                "environment_names",
                &self
                    .environment
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("current_directory", &self.current_directory)
            .field("inherited_proxy_fd", &self.inherited_proxy_fd)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct PiProcessInvocation<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub thinking: &'a str,
    pub proxy_socket_path: &'a Path,
    pub proxy_directory_fd: RawFd,
    pub analyzer_input_view: &'a Path,
    pub max_search_results: u64,
    pub proxy_token: &'a str,
    pub analyzer_id: &'a str,
    pub run_id: &'a str,
    pub manifest_identity: &'a str,
    pub credential_environment: &'a [(OsString, OsString)],
}

pub(crate) fn compile_pi_process_command(
    runtime: &PreparedPiRuntime,
    invocation: &PiProcessInvocation<'_>,
) -> Result<PiProcessCommand, PiSandboxError> {
    debug_assert_eq!(PI_RUNTIME_CONTEXT_MODE, "print");
    runtime.revalidate()?;
    validate_proxy_socket_path(invocation.proxy_socket_path)?;
    validate_input_view(invocation.analyzer_input_view)?;
    if invocation.max_search_results == 0
        || invocation.max_search_results > NATIVE_SEARCH_MAX_RESULTS
    {
        return Err(PiSandboxError::InvalidRuntime);
    }

    let scratch = runtime.spec.isolated_agent_dir.join("scratch");
    let tool_path = OsString::from("/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin");
    let mut environment = vec![
        (OsString::from("HOME"), OsString::from("/agent")),
        (OsString::from("PATH"), tool_path.clone()),
        (OsString::from("TMPDIR"), OsString::from("/scratch")),
        (
            OsString::from("PI_CODING_AGENT_DIR"),
            OsString::from("/agent"),
        ),
        (OsString::from("PI_TELEMETRY"), OsString::from("0")),
        (
            OsString::from("FILE_GUARDIAN_PI_PROXY_SOCKET"),
            OsString::from("/proxy/proxy.sock"),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_RUN_TOKEN"),
            OsString::from(invocation.proxy_token),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_ANALYZER_ID"),
            OsString::from(invocation.analyzer_id),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_RUN_ID"),
            OsString::from(invocation.run_id),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_MANIFEST_IDENTITY"),
            OsString::from(invocation.manifest_identity),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS"),
            OsString::from(invocation.max_search_results.to_string()),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_BUBBLEWRAP"),
            runtime.spec.bubblewrap_executable.as_os_str().to_owned(),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_INPUT_VIEW"),
            OsString::from("/input"),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_SCRATCH_ROOT"),
            OsString::from("/scratch"),
        ),
        (OsString::from("FILE_GUARDIAN_PI_TOOL_PATH"), tool_path),
        (
            OsString::from("FILE_GUARDIAN_PI_TOOL_SIDECAR_RUNNER"),
            OsString::from("/policy/tool-sidecar-runner.js"),
        ),
    ];
    let mut names = environment
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    for (name, value) in invocation.credential_environment {
        validate_environment(name, value, &names)?;
        names.insert(name.clone());
        environment.push((name.clone(), value.clone()));
    }
    environment.sort_by(|left, right| left.0.cmp(&right.0));

    let spec = &runtime.spec;
    let runtime_roots = runtime_install_roots(spec)?;
    let mut pi_arguments = os_args(&[
        "--print",
        "--mode",
        PI_CLI_OUTPUT_MODE,
        "--no-session",
        "--no-builtin-tools",
        "--tools",
        PI_TOOLS,
        "--no-extensions",
        "--extension",
    ]);
    pi_arguments.push(OsString::from("/policy/file-guardian-extension.js"));
    pi_arguments.extend(os_args(&[
        "--no-skills",
        "--no-prompt-templates",
        "--no-themes",
        "--no-context-files",
        "--no-approve",
        "--provider",
        invocation.provider,
        "--model",
        invocation.model,
        "--thinking",
        invocation.thinking,
    ]));

    // The stage and ordinary installed runtime are read-only. Bubblewrap does
    // not expose the complete host root and does not synthesize or inspect a
    // private runtime closure.
    let mut arguments = os_args(&[
        "--unshare-pid",
        "--die-with-parent",
        "--tmpfs",
        "/",
        "--tmpfs",
        "/tmp",
    ]);
    let standard_roots = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt"];
    for path in standard_roots {
        if Path::new(path).exists() {
            arguments.extend(os_args(&["--ro-bind", path, path]));
        }
    }
    let mut created_parents = BTreeSet::new();
    // `/etc/resolv.conf` is commonly a symlink into a runtime-specific
    // directory (for example `/run/systemd/resolve` or `/mnt/wsl`). Mount the
    // exact resolved file when that target is outside the ordinary read-only
    // runtime roots; otherwise Pi has provider networking but no DNS.
    append_runtime_config_target(
        &mut arguments,
        Path::new("/etc/resolv.conf"),
        &standard_roots,
        &mut created_parents,
    )?;
    for root in runtime_roots {
        if standard_roots
            .iter()
            .any(|standard| root.starts_with(standard))
        {
            continue;
        }
        append_mount_parents(&mut arguments, &root, &mut created_parents)?;
        arguments.extend(os_args(&["--ro-bind"]));
        arguments.push(root.as_os_str().to_owned());
        arguments.push(root.into_os_string());
    }
    arguments.extend(os_args(&["--dir", "/policy"]));
    arguments.extend(os_args(&["--ro-bind"]));
    arguments.push(invocation.analyzer_input_view.as_os_str().to_owned());
    arguments.push(OsString::from("/input"));
    arguments.extend(os_args(&["--ro-bind"]));
    arguments.push(
        invocation
            .proxy_socket_path
            .parent()
            .ok_or(PiSandboxError::InvalidRuntime)?
            .as_os_str()
            .to_owned(),
    );
    arguments.push(OsString::from("/proxy"));
    arguments.extend(os_args(&["--ro-bind"]));
    arguments.push(spec.trusted_extension.as_os_str().to_owned());
    arguments.push(OsString::from("/policy/file-guardian-extension.js"));
    arguments.extend(os_args(&["--ro-bind"]));
    arguments.push(spec.tool_sidecar_runner.as_os_str().to_owned());
    arguments.push(OsString::from("/policy/tool-sidecar-runner.js"));
    arguments.push(OsString::from("--bind"));
    arguments.push(spec.isolated_agent_dir.as_os_str().to_owned());
    arguments.push(OsString::from("/agent"));
    arguments.extend(os_args(&["--bind"]));
    arguments.push(scratch.as_os_str().to_owned());
    arguments.push(OsString::from("/scratch"));
    arguments.extend(os_args(&[
        "--proc", "/proc", "--dev", "/dev", "--chdir", "/input",
    ]));
    arguments.push(OsString::from("--"));
    arguments.push(spec.pi_executable.as_os_str().to_owned());
    arguments.extend(pi_arguments);

    Ok(PiProcessCommand {
        program: spec.bubblewrap_executable.clone(),
        arguments,
        environment,
        current_directory: spec.isolated_agent_dir.clone(),
        inherited_proxy_fd: invocation.proxy_directory_fd,
    })
}

fn runtime_install_roots(spec: &PiRuntimeSpec) -> Result<Vec<PathBuf>, PiSandboxError> {
    let mut roots = Vec::new();
    for executable in [&spec.pi_executable, &spec.bubblewrap_executable] {
        for path in [
            executable.clone(),
            fs::canonicalize(executable).map_err(|_| PiSandboxError::InvalidRuntime)?,
        ] {
            let parent = path.parent().ok_or(PiSandboxError::InvalidRuntime)?;
            let root = if parent.file_name() == Some(OsStr::new("bin")) {
                parent.parent().ok_or(PiSandboxError::InvalidRuntime)?
            } else {
                parent
            };
            if root == Path::new("/") {
                return Err(PiSandboxError::InvalidRuntime);
            }
            roots.push(root.to_path_buf());
        }
    }
    roots.sort();
    roots.dedup();
    let all = roots.clone();
    roots.retain(|candidate| {
        !all.iter()
            .any(|other| other != candidate && candidate.starts_with(other))
    });
    Ok(roots)
}

fn append_mount_parents(
    arguments: &mut Vec<OsString>,
    root: &Path,
    created: &mut BTreeSet<PathBuf>,
) -> Result<(), PiSandboxError> {
    let parent = root.parent().ok_or(PiSandboxError::InvalidRuntime)?;
    let mut parents = parent
        .ancestors()
        .take_while(|value| *value != Path::new("/"))
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    parents.reverse();
    for path in parents {
        if created.insert(path.clone()) {
            arguments.push(OsString::from("--dir"));
            arguments.push(path.into_os_string());
        }
    }
    Ok(())
}

fn append_runtime_config_target(
    arguments: &mut Vec<OsString>,
    configured_path: &Path,
    ordinary_roots: &[&str],
    created: &mut BTreeSet<PathBuf>,
) -> Result<(), PiSandboxError> {
    let target = fs::canonicalize(configured_path).map_err(|_| PiSandboxError::InvalidRuntime)?;
    let metadata = fs::metadata(&target).map_err(|_| PiSandboxError::InvalidRuntime)?;
    if !metadata.is_file() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    if ordinary_roots
        .iter()
        .any(|root| target.starts_with(Path::new(root)))
    {
        return Ok(());
    }
    append_mount_parents(arguments, &target, created)?;
    arguments.extend(os_args(&["--ro-bind"]));
    arguments.push(target.as_os_str().to_owned());
    arguments.push(target.into_os_string());
    Ok(())
}

fn validate_runtime_spec(spec: &PiRuntimeSpec) -> Result<(), PiSandboxError> {
    for path in [
        &spec.bubblewrap_executable,
        &spec.pi_executable,
        &spec.instruction_file,
        &spec.trusted_extension,
        &spec.tool_sidecar_runner,
        &spec.isolated_agent_dir,
    ] {
        if !path.is_absolute() {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    for executable in [&spec.bubblewrap_executable, &spec.pi_executable] {
        let metadata = fs::metadata(executable).map_err(|_| PiSandboxError::InvalidRuntime)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    for file in [
        &spec.instruction_file,
        &spec.trusted_extension,
        &spec.tool_sidecar_runner,
    ] {
        let metadata = fs::symlink_metadata(file).map_err(|_| PiSandboxError::InvalidRuntime)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    if spec.expected_bubblewrap_version.trim().is_empty()
        || spec.expected_pi_version.trim().is_empty()
    {
        return Err(PiSandboxError::InvalidRuntime);
    }
    validate_private_directory(&spec.isolated_agent_dir)
}

fn validate_private_directory(path: &Path) -> Result<(), PiSandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PiSandboxError::InvalidRuntime)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(())
}

fn validate_proxy_socket_path(path: &Path) -> Result<(), PiSandboxError> {
    if !path.is_absolute() || path.file_name() != Some(OsStr::new("proxy.sock")) {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(())
}

fn validate_input_view(path: &Path) -> Result<(), PiSandboxError> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(())
}

fn validate_environment(
    name: &OsStr,
    value: &OsStr,
    existing: &BTreeSet<OsString>,
) -> Result<(), PiSandboxError> {
    let name = name.to_str().ok_or(PiSandboxError::InvalidRuntime)?;
    let value = value.to_str().ok_or(PiSandboxError::InvalidRuntime)?;
    const FORBIDDEN: &[&str] = &[
        "PATH",
        "HOME",
        "TMPDIR",
        "NODE_PATH",
        "NODE_OPTIONS",
        "PI_CODING_AGENT_DIR",
        "PI_TELEMETRY",
        "FILE_GUARDIAN_PI_PROXY_SOCKET",
        "FILE_GUARDIAN_PI_RUN_TOKEN",
        "FILE_GUARDIAN_PI_ANALYZER_ID",
        "FILE_GUARDIAN_PI_RUN_ID",
        "FILE_GUARDIAN_PI_MANIFEST_IDENTITY",
        "FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS",
        "FILE_GUARDIAN_PI_BUBBLEWRAP",
        "FILE_GUARDIAN_PI_INPUT_VIEW",
        "FILE_GUARDIAN_PI_SCRATCH_ROOT",
        "FILE_GUARDIAN_PI_TOOL_PATH",
        "FILE_GUARDIAN_PI_TOOL_SIDECAR_RUNNER",
    ];
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || name.as_bytes().contains(&0)
        || value.as_bytes().contains(&0)
        || FORBIDDEN.contains(&name)
        || existing.contains(OsStr::new(name))
    {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(())
}

fn runtime_identity(spec: &PiRuntimeSpec) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for value in [
        spec.pi_executable.as_os_str(),
        OsStr::new(&spec.expected_pi_version),
        spec.bubblewrap_executable.as_os_str(),
        OsStr::new(&spec.expected_bubblewrap_version),
        spec.trusted_extension.as_os_str(),
        spec.tool_sidecar_runner.as_os_str(),
    ] {
        let bytes = value.as_encoded_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

fn os_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        spec: PiRuntimeSpec,
        input: PathBuf,
        socket: PathBuf,
    }

    fn executable(path: &Path) {
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let bwrap = root.path().join("bwrap");
        let pi = root.path().join("pi");
        let instruction = root.path().join("instruction.md");
        let extension = root.path().join("extension.js");
        let runner = root.path().join("runner.js");
        let agent = root.path().join("agent");
        let input = root.path().join("input");
        let proxy = root.path().join("proxy");
        executable(&bwrap);
        executable(&pi);
        fs::write(&instruction, "review").unwrap();
        fs::write(&extension, "export default {};").unwrap();
        fs::write(&runner, "").unwrap();
        fs::create_dir(&agent).unwrap();
        fs::create_dir(&input).unwrap();
        fs::create_dir(&proxy).unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o700)).unwrap();
        Fixture {
            spec: PiRuntimeSpec {
                bubblewrap_executable: bwrap,
                expected_bubblewrap_version: "0.11.1".into(),
                pi_executable: pi,
                expected_pi_version: "0.83.0".into(),
                instruction_file: instruction,
                trusted_extension: extension,
                tool_sidecar_runner: runner,
                isolated_agent_dir: agent,
            },
            input,
            socket: proxy.join("proxy.sock"),
            _root: root,
        }
    }

    #[test]
    fn uses_sparse_normal_runtime_with_exact_read_only_stage_and_writable_scratch() {
        let fixture = fixture();
        let prepared = PreparedPiRuntime::prepare(fixture.spec.clone()).unwrap();
        let command = compile_pi_process_command(
            &prepared,
            &PiProcessInvocation {
                provider: "provider",
                model: "model",
                thinking: "high",
                proxy_socket_path: &fixture.socket,
                proxy_directory_fd: 7,
                analyzer_input_view: &fixture.input,
                max_search_results: 100,
                proxy_token: "token",
                analyzer_id: "pi",
                run_id: "run",
                manifest_identity: "sha256:manifest",
                credential_environment: &[],
            },
        )
        .unwrap();
        assert!(!command.arguments.windows(3).any(|values| {
            values == [OsStr::new("--ro-bind"), OsStr::new("/"), OsStr::new("/")]
        }));
        assert!(command.arguments.windows(3).any(|values| {
            values
                == [
                    OsStr::new("--ro-bind"),
                    fixture.input.as_os_str(),
                    OsStr::new("/input"),
                ]
        }));
        assert!(command.arguments.windows(3).any(|values| {
            values
                == [
                    OsStr::new("--ro-bind"),
                    OsStr::new("/usr"),
                    OsStr::new("/usr"),
                ]
        }));
        assert!(command.arguments.windows(3).any(|values| values
            == [
                OsStr::new("--ro-bind"),
                fixture._root.path().as_os_str(),
                fixture._root.path().as_os_str(),
            ]));
        assert!(command
            .arguments
            .iter()
            .any(|value| value == fixture.spec.pi_executable.as_os_str()));
        assert!(!command.arguments.iter().any(|value| value == "/policy/pi"));
        assert!(!command.arguments.iter().any(|value| value == "/runtime"));
        assert!(command
            .environment
            .iter()
            .any(|(name, value)| { name == "FILE_GUARDIAN_PI_INPUT_VIEW" && value == "/input" }));
    }

    #[test]
    fn rejects_relative_or_nonexecutable_runtime() {
        let mut fixture = fixture();
        fixture.spec.pi_executable = PathBuf::from("pi");
        assert!(matches!(
            PreparedPiRuntime::prepare(fixture.spec),
            Err(PiSandboxError::InvalidRuntime)
        ));
    }

    #[test]
    fn credential_mapping_cannot_replace_runtime_environment() {
        let fixture = fixture();
        let prepared = PreparedPiRuntime::prepare(fixture.spec).unwrap();
        assert!(compile_pi_process_command(
            &prepared,
            &PiProcessInvocation {
                provider: "provider",
                model: "model",
                thinking: "high",
                proxy_socket_path: &fixture.socket,
                proxy_directory_fd: 7,
                analyzer_input_view: &fixture.input,
                max_search_results: 100,
                proxy_token: "token",
                analyzer_id: "pi",
                run_id: "run",
                manifest_identity: "sha256:manifest",
                credential_environment: &[(OsString::from("PATH"), OsString::from("/tmp"))],
            },
        )
        .is_err());
    }

    #[test]
    fn mounts_resolved_runtime_config_targets_outside_ordinary_roots() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime");
        let configured = root.path().join("configured");
        fs::create_dir(&runtime).unwrap();
        fs::write(runtime.join("resolv.conf"), "nameserver 127.0.0.1\n").unwrap();
        std::os::unix::fs::symlink(runtime.join("resolv.conf"), &configured).unwrap();
        let mut arguments = Vec::new();
        let mut created = BTreeSet::new();

        append_runtime_config_target(&mut arguments, &configured, &["/usr", "/etc"], &mut created)
            .unwrap();

        let resolved = fs::canonicalize(configured).unwrap();
        assert!(arguments.windows(3).any(|values| {
            values
                == [
                    OsStr::new("--ro-bind"),
                    resolved.as_os_str(),
                    resolved.as_os_str(),
                ]
        }));
    }
}
