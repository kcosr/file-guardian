use super::proxy::NATIVE_SEARCH_MAX_RESULTS;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::fd::RawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

pub(crate) const PI_TOOLS: &str =
    "bash,read,grep,find,ls,manifest_list,triage_request,submit_triage";
/// Pi's `--mode` controls serialized stdout, independently of the extension
/// context mode selected by `--print`.
pub(crate) const PI_CLI_OUTPUT_MODE: &str = "text";
/// Pi 0.83 maps `--print --mode text` to `ctx.mode == "print"`. The proxy
/// runtime-ready handshake must validate this value, not the CLI output mode.
pub(crate) const PI_RUNTIME_CONTEXT_MODE: &str = "print";

#[derive(Clone, Debug)]
pub(crate) struct PiRuntimeSpec {
    pub bubblewrap_executable: PathBuf,
    pub expected_bubblewrap_version: String,
    pub runtime_root: PathBuf,
    pub runtime_manifest: PathBuf,
    pub launcher: PathBuf,
    pub pi_entrypoint: PathBuf,
    pub expected_pi_version: String,
    pub instruction_file: PathBuf,
    pub trusted_extension: PathBuf,
    pub tool_sidecar_runner: PathBuf,
    pub isolated_agent_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedPiRuntime {
    pub(crate) spec: PiRuntimeSpec,
    stamps: Vec<AssetStamp>,
    identity: [u8; 32],
}

#[derive(Clone, Debug)]
struct AssetStamp {
    path: PathBuf,
    kind: AssetKind,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssetKind {
    File,
    Tree,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    schema_version: String,
    pi_version: String,
    files: Vec<RuntimeManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifestEntry {
    path: PathBuf,
    sha256: String,
    executable: bool,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum PiSandboxError {
    #[cfg(not(target_os = "linux"))]
    #[error("Pi triage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("Pi runtime bundle failed immutable preflight")]
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
            let stamps = vec![
                stamp_file(&spec.bubblewrap_executable)?,
                stamp_tree(&spec.runtime_root)?,
                stamp_file(&spec.instruction_file)?,
                stamp_file(&spec.trusted_extension)?,
                stamp_file(&spec.tool_sidecar_runner)?,
            ];
            let identity = runtime_identity(&spec, &stamps);
            Ok(Self {
                spec,
                stamps,
                identity,
            })
        }
    }

    pub(crate) fn revalidate(&self) -> Result<(), PiSandboxError> {
        validate_runtime_spec(&self.spec)?;
        for expected in &self.stamps {
            let actual = match expected.kind {
                AssetKind::File => stamp_file(&expected.path)?,
                AssetKind::Tree => stamp_tree(&expected.path)?,
            };
            if actual.digest != expected.digest {
                return Err(PiSandboxError::InvalidRuntime);
            }
        }
        Ok(())
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
    validate_max_search_results(invocation.max_search_results)?;
    let mut environment = vec![
        (
            OsString::from("HOME"),
            runtime.spec.isolated_agent_dir.as_os_str().to_owned(),
        ),
        (
            OsString::from("PATH"),
            runtime.spec.runtime_root.join("bin").into_os_string(),
        ),
        (
            OsString::from("TMPDIR"),
            runtime.spec.isolated_agent_dir.as_os_str().to_owned(),
        ),
        (
            OsString::from("PI_CODING_AGENT_DIR"),
            runtime.spec.isolated_agent_dir.as_os_str().to_owned(),
        ),
        (OsString::from("PI_OFFLINE"), OsString::from("1")),
        (OsString::from("PI_TELEMETRY"), OsString::from("0")),
        (
            OsString::from("FILE_GUARDIAN_PI_PROXY_SOCKET"),
            invocation.proxy_socket_path.as_os_str().to_owned(),
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
            OsString::from("FILE_GUARDIAN_PI_RUNTIME_ROOT"),
            runtime.spec.runtime_root.as_os_str().to_owned(),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_RUNTIME_LAUNCHER"),
            runtime.spec.launcher.as_os_str().to_owned(),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_INPUT_VIEW"),
            invocation.analyzer_input_view.as_os_str().to_owned(),
        ),
        (
            OsString::from("FILE_GUARDIAN_PI_TOOL_SIDECAR_RUNNER"),
            runtime.spec.tool_sidecar_runner.as_os_str().to_owned(),
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
    let launcher = spec.runtime_root.join(&spec.launcher);
    let mut pi_arguments = vec![spec.runtime_root.join(&spec.pi_entrypoint).into_os_string()];
    pi_arguments.extend(os_args(&[
        "--print",
        "--mode",
        PI_CLI_OUTPUT_MODE,
        "--no-session",
        "--no-builtin-tools",
        "--tools",
        PI_TOOLS,
        "--no-extensions",
        "--extension",
    ]));
    pi_arguments.push(spec.trusted_extension.as_os_str().to_owned());
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
    // Pi itself retains the host network and filesystem namespaces: provider
    // requests and the ordinary runtime must behave exactly as they do for a
    // regular process. The dedicated PID namespace is only a lifetime
    // boundary. Bubblewrap remains PID 1/reaper in that namespace, so when the
    // Pi command exits (or bwrap is killed), the kernel also destroys every
    // descendant even if it called setsid(2) and escaped Pi's process group.
    // Re-bind /dev after the root bind because bwrap's mount namespace is
    // created with nodev; Pi must retain the same device access as its parent.
    let mut arguments = os_args(&[
        "--unshare-pid",
        "--die-with-parent",
        "--bind",
        "/",
        "/",
        "--dev-bind",
        "/dev",
        "/dev",
        "--chdir",
    ]);
    arguments.push(spec.isolated_agent_dir.as_os_str().to_owned());
    arguments.push(OsString::from("--"));
    arguments.push(launcher.into_os_string());
    arguments.extend(pi_arguments);
    Ok(PiProcessCommand {
        program: spec.bubblewrap_executable.clone(),
        arguments,
        environment,
        current_directory: spec.isolated_agent_dir.clone(),
        inherited_proxy_fd: invocation.proxy_directory_fd,
    })
}

fn validate_runtime_spec(spec: &PiRuntimeSpec) -> Result<(), PiSandboxError> {
    for path in [
        &spec.bubblewrap_executable,
        &spec.runtime_root,
        &spec.runtime_manifest,
        &spec.instruction_file,
        &spec.trusted_extension,
        &spec.tool_sidecar_runner,
        &spec.isolated_agent_dir,
    ] {
        if !path.is_absolute() {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    let launcher = normalize_relative(&spec.launcher)?;
    let entrypoint = normalize_relative(&spec.pi_entrypoint)?;
    let manifest_relative = spec
        .runtime_manifest
        .strip_prefix(&spec.runtime_root)
        .map_err(|_| PiSandboxError::InvalidRuntime)?;
    if manifest_relative.as_os_str().is_empty() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    verify_secure_file(&spec.bubblewrap_executable, true)?;
    verify_secure_file(&spec.instruction_file, false)?;
    verify_secure_file(&spec.trusted_extension, false)?;
    verify_private_agent_tree(&spec.isolated_agent_dir)?;
    verify_runtime_manifest(spec, &launcher, &entrypoint, manifest_relative)
}

fn verify_runtime_manifest(
    spec: &PiRuntimeSpec,
    launcher: &Path,
    entrypoint: &Path,
    manifest_relative: &Path,
) -> Result<(), PiSandboxError> {
    verify_secure_tree(&spec.runtime_root)?;
    verify_secure_file(&spec.runtime_manifest, false)?;
    let bytes = read_bounded(&spec.runtime_manifest, 1024 * 1024)?;
    let manifest: RuntimeManifest =
        serde_json::from_slice(&bytes).map_err(|_| PiSandboxError::InvalidRuntime)?;
    if manifest.schema_version != "file-guardian-pi-runtime/1"
        || manifest.pi_version != spec.expected_pi_version
        || manifest.files.is_empty()
    {
        return Err(PiSandboxError::InvalidRuntime);
    }
    let mut declared = BTreeMap::new();
    for entry in manifest.files {
        let relative = normalize_relative(&entry.path)?;
        if relative == manifest_relative || declared.insert(relative, entry).is_some() {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    let mut actual = BTreeSet::new();
    collect_files(&spec.runtime_root, &spec.runtime_root, &mut actual)?;
    actual.remove(manifest_relative);
    if actual != declared.keys().cloned().collect() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    for (relative, entry) in &declared {
        let path = spec.runtime_root.join(relative);
        verify_secure_file(&path, entry.executable)?;
        let digest = hex_digest(&hash_file(&path)?);
        if digest != entry.sha256 || entry.sha256.len() != 64 {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    if !declared.get(launcher).is_some_and(|entry| entry.executable)
        || !declared.contains_key(entrypoint)
        || !declared.contains_key(Path::new("share/misc/magic.mgc"))
        || [
            "bin/bash",
            "bin/cat",
            "bin/head",
            "bin/tail",
            "bin/wc",
            "bin/sort",
            "bin/cut",
            "bin/tr",
            "bin/xargs",
            "bin/cp",
            "bin/mkdir",
            "bin/mv",
            "bin/rm",
            "bin/touch",
            "bin/rg",
            "bin/fd",
            "bin/grep",
            "bin/find",
            "bin/ls",
            "bin/sed",
            "bin/awk",
            "bin/file",
            "bin/jq",
            "bin/tar",
            "bin/unzip",
        ]
        .iter()
        .any(|path| {
            !declared
                .get(Path::new(path))
                .is_some_and(|entry| entry.executable)
        })
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
    if !path.is_absolute() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    let current_uid = rustix::process::geteuid().as_raw();
    let mut pending = vec![path.to_owned()];
    while let Some(entry_path) = pending.pop() {
        let metadata = fs::symlink_metadata(&entry_path).map_err(invalid_io)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != current_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PiSandboxError::InvalidRuntime);
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&entry_path).map_err(invalid_io)? {
                pending.push(entry.map_err(invalid_io)?.path());
            }
        } else if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    Ok(())
}

fn validate_max_search_results(value: u64) -> Result<(), PiSandboxError> {
    if value == 0 || value > NATIVE_SEARCH_MAX_RESULTS {
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
        "PI_OFFLINE",
        "PI_TELEMETRY",
        "FILE_GUARDIAN_PI_PROXY_SOCKET",
        "FILE_GUARDIAN_PI_RUN_TOKEN",
        "FILE_GUARDIAN_PI_ANALYZER_ID",
        "FILE_GUARDIAN_PI_RUN_ID",
        "FILE_GUARDIAN_PI_MANIFEST_IDENTITY",
        "FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS",
        "FILE_GUARDIAN_PI_BUBBLEWRAP",
        "FILE_GUARDIAN_PI_RUNTIME_ROOT",
        "FILE_GUARDIAN_PI_RUNTIME_LAUNCHER",
        "FILE_GUARDIAN_PI_INPUT_VIEW",
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

fn verify_secure_tree(root: &Path) -> Result<(), PiSandboxError> {
    verify_secure_metadata(root, &fs::symlink_metadata(root).map_err(invalid_io)?, true)?;
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(invalid_io)? {
            let path = entry.map_err(invalid_io)?.path();
            let metadata = fs::symlink_metadata(&path).map_err(invalid_io)?;
            if metadata.is_dir() {
                verify_secure_metadata(&path, &metadata, true)?;
                pending.push(path);
            } else if metadata.is_file() {
                verify_secure_metadata(&path, &metadata, false)?;
            } else {
                return Err(PiSandboxError::InvalidRuntime);
            }
        }
    }
    Ok(())
}

fn verify_private_agent_tree(root: &Path) -> Result<(), PiSandboxError> {
    let current_uid = rustix::process::geteuid().as_raw();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(invalid_io)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != current_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PiSandboxError::InvalidRuntime);
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(invalid_io)? {
                pending.push(entry.map_err(invalid_io)?.path());
            }
        } else if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    Ok(())
}

fn verify_secure_file(path: &Path, executable: bool) -> Result<(), PiSandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(invalid_io)?;
    verify_secure_metadata(path, &metadata, false)?;
    if executable != (metadata.permissions().mode() & 0o111 != 0) || metadata.nlink() != 1 {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(())
}

fn verify_secure_metadata(
    path: &Path,
    metadata: &Metadata,
    directory: bool,
) -> Result<(), PiSandboxError> {
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(PiSandboxError::InvalidRuntime);
    }
    let current_uid = rustix::process::getuid().as_raw();
    if metadata.uid() != 0 && metadata.uid() != current_uid {
        return Err(PiSandboxError::InvalidRuntime);
    }
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor).map_err(invalid_io)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o022 != 0
            || (metadata.uid() != 0 && metadata.uid() != current_uid)
        {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), PiSandboxError> {
    for entry in fs::read_dir(directory).map_err(invalid_io)? {
        let path = entry.map_err(invalid_io)?.path();
        let metadata = fs::symlink_metadata(&path).map_err(invalid_io)?;
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.insert(
                path.strip_prefix(root)
                    .map_err(|_| PiSandboxError::InvalidRuntime)?
                    .to_owned(),
            );
        } else {
            return Err(PiSandboxError::InvalidRuntime);
        }
    }
    Ok(())
}

fn stamp_file(path: &Path) -> Result<AssetStamp, PiSandboxError> {
    Ok(AssetStamp {
        path: path.to_owned(),
        kind: AssetKind::File,
        digest: hash_file(path)?,
    })
}

fn stamp_tree(path: &Path) -> Result<AssetStamp, PiSandboxError> {
    let mut hasher = Sha256::new();
    let mut files = BTreeSet::new();
    collect_files(path, path, &mut files)?;
    for relative in files {
        hasher.update(relative.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(hash_file(&path.join(relative))?);
    }
    Ok(AssetStamp {
        path: path.to_owned(),
        kind: AssetKind::Tree,
        digest: hasher.finalize().into(),
    })
}

#[cfg(target_os = "linux")]
fn runtime_identity(spec: &PiRuntimeSpec, stamps: &[AssetStamp]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"schema", b"file-guardian-pi-preflight/1");
    hash_field(
        &mut hasher,
        b"bubblewrap-version",
        spec.expected_bubblewrap_version.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"pi-version",
        spec.expected_pi_version.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"launcher",
        spec.launcher.as_os_str().as_encoded_bytes(),
    );
    hash_field(
        &mut hasher,
        b"entrypoint",
        spec.pi_entrypoint.as_os_str().as_encoded_bytes(),
    );
    for (index, stamp) in stamps.iter().enumerate() {
        hash_field(
            &mut hasher,
            format!("asset-{index}").as_bytes(),
            &stamp.digest,
        );
    }
    hasher.finalize().into()
}

#[cfg(target_os = "linux")]
fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hash_file(path: &Path) -> Result<[u8; 32], PiSandboxError> {
    let mut file = File::open(path).map_err(invalid_io)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(invalid_io)?;
    Ok(hasher.finalize().into())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, PiSandboxError> {
    let file = File::open(path).map_err(invalid_io)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid_io)?;
    if bytes.len() as u64 > limit {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(bytes)
}

fn normalize_relative(path: &Path) -> Result<PathBuf, PiSandboxError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            _ => return Err(PiSandboxError::InvalidRuntime),
        }
    }
    Ok(normalized)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn invalid_io(_: io::Error) -> PiSandboxError {
    PiSandboxError::InvalidRuntime
}
fn os_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        spec: PiRuntimeSpec,
        proxy: PathBuf,
        input: PathBuf,
        _socket: UnixListener,
    }

    impl Fixture {
        fn new() -> Self {
            let secure_parent = secure_test_parent();
            let root = tempfile::Builder::new()
                .prefix(".pi-sandbox-test-")
                .tempdir_in(secure_parent)
                .unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let runtime = root.path().join("runtime");
            for directory in [
                runtime.clone(),
                runtime.join("bin"),
                runtime.join("lib"),
                runtime.join("lib/pi"),
                runtime.join("lib/pi/dist"),
                runtime.join("share"),
                runtime.join("share/misc"),
                root.path().join("config"),
                root.path().join("proxy"),
                root.path().join("input"),
            ] {
                fs::create_dir_all(&directory).unwrap();
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let files = [
                ("bin/node", b"static-node".as_slice(), true),
                ("bin/bash", b"static-bash", true),
                ("bin/cat", b"static-cat", true),
                ("bin/head", b"static-head", true),
                ("bin/tail", b"static-tail", true),
                ("bin/wc", b"static-wc", true),
                ("bin/sort", b"static-sort", true),
                ("bin/cut", b"static-cut", true),
                ("bin/tr", b"static-tr", true),
                ("bin/xargs", b"static-xargs", true),
                ("bin/cp", b"static-cp", true),
                ("bin/mkdir", b"static-mkdir", true),
                ("bin/mv", b"static-mv", true),
                ("bin/rm", b"static-rm", true),
                ("bin/touch", b"static-touch", true),
                ("bin/rg", b"static-ripgrep", true),
                ("bin/fd", b"static-fd", true),
                ("bin/grep", b"static-grep", true),
                ("bin/find", b"static-find", true),
                ("bin/ls", b"static-ls", true),
                ("bin/sed", b"static-sed", true),
                ("bin/awk", b"static-awk", true),
                ("bin/file", b"static-file", true),
                ("bin/jq", b"static-jq", true),
                ("bin/tar", b"static-tar", true),
                ("bin/unzip", b"static-unzip", true),
                ("lib/pi/dist/cli.js", b"pi-entrypoint", false),
                ("share/misc/magic.mgc", b"file-magic-database", false),
            ];
            let mut entries = Vec::new();
            for (relative, bytes, executable) in files {
                let path = runtime.join(relative);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
                )
                .unwrap();
                entries.push(json!({
                    "path": relative,
                    "sha256": hex_digest(&hash_file(&path).unwrap()),
                    "executable": executable,
                }));
            }
            let manifest = runtime.join("manifest.json");
            fs::write(
                &manifest,
                serde_json::to_vec(&json!({
                    "schema_version": "file-guardian-pi-runtime/1",
                    "pi_version": "0.83.0",
                    "files": entries,
                }))
                .unwrap(),
            )
            .unwrap();
            fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
            let bwrap = root.path().join("bwrap");
            let instruction = root.path().join("instruction.md");
            let extension = root.path().join("extension.js");
            let sidecar_runner = root.path().join("tool-sidecar-runner.js");
            for (path, bytes, mode) in [
                (&bwrap, b"fake-bwrap".as_slice(), 0o700),
                (&instruction, b"trusted instruction", 0o600),
                (&extension, b"trusted extension", 0o600),
                (&sidecar_runner, b"trusted sidecar runner", 0o600),
            ] {
                fs::write(path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            }
            let proxy = root.path().join("proxy");
            fs::set_permissions(&proxy, fs::Permissions::from_mode(0o700)).unwrap();
            let socket = UnixListener::bind(proxy.join("proxy.sock")).unwrap();
            let input = root.path().join("input");
            let input_file = input.join("artifact.txt");
            fs::write(&input_file, b"immutable artifact").unwrap();
            fs::set_permissions(&input_file, fs::Permissions::from_mode(0o600)).unwrap();
            Self {
                spec: PiRuntimeSpec {
                    bubblewrap_executable: bwrap,
                    expected_bubblewrap_version: "0.11.1".into(),
                    runtime_root: runtime,
                    runtime_manifest: manifest,
                    launcher: "bin/node".into(),
                    pi_entrypoint: "lib/pi/dist/cli.js".into(),
                    expected_pi_version: "0.83.0".into(),
                    instruction_file: instruction,
                    trusted_extension: extension,
                    tool_sidecar_runner: sidecar_runner,
                    isolated_agent_dir: root.path().join("config"),
                },
                proxy,
                input,
                _socket: socket,
                _root: root,
            }
        }

        fn prepare(&self) -> PreparedPiRuntime {
            PreparedPiRuntime::prepare(self.spec.clone()).unwrap()
        }
    }

    fn secure_test_parent() -> PathBuf {
        let current = std::env::current_dir().unwrap();
        current
            .ancestors()
            .find(|path| {
                path.ancestors().all(|ancestor| {
                    fs::metadata(ancestor).is_ok_and(|metadata| {
                        metadata.is_dir() && metadata.permissions().mode() & 0o022 == 0
                    })
                })
            })
            .expect("test host must expose a secure ancestor directory")
            .to_path_buf()
    }

    #[test]
    fn command_debug_and_argv_never_contain_secret_environment_values() {
        let secret = "sentinel-provider-secret";
        let token = "sentinel-run-token";
        let command = PiProcessCommand {
            program: PathBuf::from("/usr/bin/bwrap"),
            arguments: os_args(&["--unshare-all", "--", "/runtime/bin/node"]),
            environment: vec![
                (OsString::from("PROVIDER_KEY"), OsString::from(secret)),
                (
                    OsString::from("FILE_GUARDIAN_PI_RUN_TOKEN"),
                    OsString::from(token),
                ),
            ],
            current_directory: PathBuf::from("/private/pi"),
            inherited_proxy_fd: 7,
        };
        let debug = format!("{command:?}");
        let argv = command
            .arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!debug.contains(secret));
        assert!(!debug.contains(token));
        assert!(!argv.contains(secret));
        assert!(!argv.contains(token));
        assert!(debug.contains("PROVIDER_KEY"));
    }

    #[test]
    fn credential_environment_rejects_process_control_names() {
        let existing = BTreeSet::new();
        for name in ["PATH", "HOME", "NODE_OPTIONS", "NODE_PATH", "PI_OFFLINE"] {
            assert_eq!(
                validate_environment(OsStr::new(name), OsStr::new("value"), &existing),
                Err(PiSandboxError::InvalidRuntime)
            );
        }
    }

    #[test]
    fn runtime_paths_must_be_normalized_relative_paths() {
        for invalid in ["", "/bin/node", "../node", "bin/../node", "./node"] {
            assert_eq!(
                normalize_relative(Path::new(invalid)),
                Err(PiSandboxError::InvalidRuntime)
            );
        }
        assert_eq!(
            normalize_relative(Path::new("bin/node")).unwrap(),
            Path::new("bin/node")
        );
    }

    #[test]
    fn analyzer_input_view_must_be_private_real_and_unlinked() {
        let relative = Path::new("relative-input");
        assert_eq!(
            validate_input_view(relative),
            Err(PiSandboxError::InvalidRuntime)
        );

        let fixture = Fixture::new();
        assert_eq!(validate_input_view(&fixture.input), Ok(()));

        fs::set_permissions(&fixture.input, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            validate_input_view(&fixture.input),
            Err(PiSandboxError::InvalidRuntime)
        );
        fs::set_permissions(&fixture.input, fs::Permissions::from_mode(0o700)).unwrap();

        let original = fixture.input.join("artifact.txt");
        let hardlink = fixture.input.join("hardlink.txt");
        fs::hard_link(&original, &hardlink).unwrap();
        assert_eq!(
            validate_input_view(&fixture.input),
            Err(PiSandboxError::InvalidRuntime)
        );
        fs::remove_file(hardlink).unwrap();

        let symlink_path = fixture.input.join("symlink.txt");
        symlink(&original, &symlink_path).unwrap();
        assert_eq!(
            validate_input_view(&fixture.input),
            Err(PiSandboxError::InvalidRuntime)
        );
    }

    #[test]
    fn search_result_limit_must_fit_extension_schema() {
        assert_eq!(validate_max_search_results(1), Ok(()));
        assert_eq!(
            validate_max_search_results(NATIVE_SEARCH_MAX_RESULTS),
            Ok(())
        );
        assert_eq!(
            validate_max_search_results(0),
            Err(PiSandboxError::InvalidRuntime)
        );
        assert_eq!(
            validate_max_search_results(NATIVE_SEARCH_MAX_RESULTS + 1),
            Err(PiSandboxError::InvalidRuntime)
        );
    }

    #[test]
    fn manifest_pinned_bundle_compiles_normal_pi_with_sidecar_settings() {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        prepared.revalidate().unwrap();
        let credentials = [(OsString::from("INTERNAL_API_KEY"), OsString::from("secret"))];
        let command = compile_pi_process_command(
            &prepared,
            &PiProcessInvocation {
                provider: "internal",
                model: "classified-model",
                thinking: "high",
                proxy_socket_path: &fixture.proxy.join("proxy.sock"),
                proxy_directory_fd: 7,
                analyzer_input_view: &fixture.input,
                max_search_results: 37,
                proxy_token: "token",
                analyzer_id: "semantic",
                run_id: "run-1",
                manifest_identity: "sha256:manifest",
                credential_environment: &credentials,
            },
        )
        .unwrap();
        let args = command
            .arguments
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let entrypoint = fixture
            .spec
            .runtime_root
            .join("lib/pi/dist/cli.js")
            .to_string_lossy()
            .into_owned();
        let extension = fixture
            .spec
            .trusted_extension
            .to_string_lossy()
            .into_owned();
        let agent_dir = fixture
            .spec
            .isolated_agent_dir
            .to_string_lossy()
            .into_owned();
        let launcher = fixture
            .spec
            .runtime_root
            .join("bin/node")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            &args[..12],
            &[
                "--unshare-pid",
                "--die-with-parent",
                "--bind",
                "/",
                "/",
                "--dev-bind",
                "/dev",
                "/dev",
                "--chdir",
                agent_dir.as_str(),
                "--",
                launcher.as_str(),
            ]
        );
        for required in [
            entrypoint.as_str(),
            "--print",
            "--mode",
            PI_CLI_OUTPUT_MODE,
            "--no-session",
            "--no-builtin-tools",
            PI_TOOLS,
            "--no-extensions",
            extension.as_str(),
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
            "--no-context-files",
            "--no-approve",
        ] {
            assert!(
                args.iter().any(|value| value == required),
                "missing {required}"
            );
        }
        assert!(!args.iter().any(|value| value == "--system-prompt"));
        assert!(args.iter().any(|value| value == "--unshare-pid"));
        assert!(args.iter().any(|value| value == "--die-with-parent"));
        assert!(!args.iter().any(|value| value == "--unshare-net"));
        assert!(!args.iter().any(|value| value == "--unshare-all"));
        assert!(!args.iter().any(|value| value == "--ro-bind"));
        assert!(args.windows(3).any(|values| values == ["--bind", "/", "/"]));
        assert!(args
            .windows(3)
            .any(|values| values == ["--dev-bind", "/dev", "/dev"]));
        assert!(args
            .windows(2)
            .any(|values| values == ["--mode", PI_CLI_OUTPUT_MODE]));
        assert_eq!(PI_RUNTIME_CONTEXT_MODE, "print");
        assert_eq!(command.program, fixture.spec.bubblewrap_executable);
        assert_eq!(command.current_directory, fixture.spec.isolated_agent_dir);
        assert_eq!(command.inherited_proxy_fd, 7);
        let debug = format!("{command:?}");
        assert!(!args
            .iter()
            .any(|value| value.contains("secret") || value.contains("token")));
        assert!(!debug.contains("secret") && !debug.contains("token"));
        let names = command
            .environment
            .iter()
            .map(|(name, _)| name.to_string_lossy())
            .collect::<BTreeSet<_>>();
        for name in [
            "HOME",
            "PATH",
            "TMPDIR",
            "PI_CODING_AGENT_DIR",
            "PI_OFFLINE",
            "PI_TELEMETRY",
            "FILE_GUARDIAN_PI_PROXY_SOCKET",
            "FILE_GUARDIAN_PI_RUN_TOKEN",
            "FILE_GUARDIAN_PI_ANALYZER_ID",
            "FILE_GUARDIAN_PI_RUN_ID",
            "FILE_GUARDIAN_PI_MANIFEST_IDENTITY",
            "FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS",
            "FILE_GUARDIAN_PI_BUBBLEWRAP",
            "FILE_GUARDIAN_PI_RUNTIME_ROOT",
            "FILE_GUARDIAN_PI_RUNTIME_LAUNCHER",
            "FILE_GUARDIAN_PI_INPUT_VIEW",
            "FILE_GUARDIAN_PI_TOOL_SIDECAR_RUNNER",
            "INTERNAL_API_KEY",
        ] {
            assert!(names.contains(name));
        }
        for forbidden in ["NODE_PATH", "NODE_OPTIONS"] {
            assert!(!names.contains(forbidden));
        }
        assert_eq!(
            command
                .environment
                .iter()
                .find(|(name, _)| name == "PATH")
                .map(|(_, value)| value),
            Some(&fixture.spec.runtime_root.join("bin").into_os_string())
        );
        assert_eq!(
            command
                .environment
                .iter()
                .find(|(name, _)| name == "FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS")
                .map(|(_, value)| value),
            Some(&OsString::from("37"))
        );
    }

    #[test]
    fn prepared_assets_are_revalidated_and_change_identity() {
        for choose in 0..3 {
            let fixture = Fixture::new();
            let prepared = fixture.prepare();
            let old_identity = prepared.identity();
            let path = match choose {
                0 => &fixture.spec.instruction_file,
                1 => &fixture.spec.trusted_extension,
                2 => &fixture.spec.tool_sidecar_runner,
                _ => unreachable!(),
            };
            fs::write(path, b"mutated asset bytes").unwrap();
            assert_eq!(prepared.revalidate(), Err(PiSandboxError::InvalidRuntime));
            let new = PreparedPiRuntime::prepare(fixture.spec.clone()).unwrap();
            assert_ne!(new.identity(), old_identity);
        }
    }

    #[test]
    fn private_agent_state_may_change_without_changing_runtime_identity() {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        let old_identity = prepared.identity();
        let settings = fixture.spec.isolated_agent_dir.join("settings.json");
        fs::write(&settings, b"{}").unwrap();
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();

        prepared.revalidate().unwrap();
        let refreshed = PreparedPiRuntime::prepare(fixture.spec.clone()).unwrap();
        assert_eq!(refreshed.identity(), old_identity);
    }

    #[test]
    fn rejects_manifest_and_filesystem_substitution_attacks() {
        let extra = Fixture::new();
        fs::write(extra.spec.runtime_root.join("extra"), b"extra").unwrap();
        assert!(PreparedPiRuntime::prepare(extra.spec).is_err());

        let missing = Fixture::new();
        fs::remove_file(missing.spec.runtime_root.join("bin/bash")).unwrap();
        assert!(PreparedPiRuntime::prepare(missing.spec).is_err());

        let writable = Fixture::new();
        fs::set_permissions(
            &writable.spec.trusted_extension,
            fs::Permissions::from_mode(0o622),
        )
        .unwrap();
        assert!(PreparedPiRuntime::prepare(writable.spec).is_err());

        let symlinked = Fixture::new();
        fs::remove_file(&symlinked.spec.trusted_extension).unwrap();
        symlink(
            &symlinked.spec.instruction_file,
            &symlinked.spec.trusted_extension,
        )
        .unwrap();
        assert!(PreparedPiRuntime::prepare(symlinked.spec).is_err());

        let hardlinked = Fixture::new();
        fs::remove_file(&hardlinked.spec.trusted_extension).unwrap();
        fs::hard_link(
            &hardlinked.spec.instruction_file,
            &hardlinked.spec.trusted_extension,
        )
        .unwrap();
        assert!(PreparedPiRuntime::prepare(hardlinked.spec).is_err());

        let special = Fixture::new();
        let _listener =
            UnixListener::bind(special.spec.runtime_root.join("unexpected.sock")).unwrap();
        assert!(PreparedPiRuntime::prepare(special.spec).is_err());

        let wrong_version = Fixture::new();
        let mut spec = wrong_version.spec;
        spec.expected_pi_version = "0.84.0".into();
        assert!(PreparedPiRuntime::prepare(spec).is_err());

        let wrong_mode = Fixture::new();
        fs::set_permissions(
            wrong_mode.spec.runtime_root.join("bin/node"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(PreparedPiRuntime::prepare(wrong_mode.spec).is_err());

        let missing_helper = Fixture::new();
        fs::remove_file(missing_helper.spec.runtime_root.join("bin/rg")).unwrap();
        assert!(PreparedPiRuntime::prepare(missing_helper.spec).is_err());

        let non_executable_helper = Fixture::new();
        fs::set_permissions(
            non_executable_helper.spec.runtime_root.join("bin/fd"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(PreparedPiRuntime::prepare(non_executable_helper.spec).is_err());

        let public_agent_dir = Fixture::new();
        fs::set_permissions(
            &public_agent_dir.spec.isolated_agent_dir,
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(PreparedPiRuntime::prepare(public_agent_dir.spec).is_err());

        let public_agent_file = Fixture::new();
        let auth = public_agent_file.spec.isolated_agent_dir.join("auth.json");
        fs::write(&auth, b"{}").unwrap();
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PreparedPiRuntime::prepare(public_agent_file.spec).is_err());
    }

    #[tokio::test]
    async fn hanging_bubblewrap_version_probe_is_killed_and_reaped() {
        let fixture = Fixture::new();
        fs::write(
            &fixture.spec.bubblewrap_executable,
            b"#!/bin/sh\ntrap '' TERM\nsleep 60\n",
        )
        .unwrap();
        fs::set_permissions(
            &fixture.spec.bubblewrap_executable,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let prepared = fixture.prepare();
        let result = timeout(Duration::from_secs(4), prepared.verify_bubblewrap_version()).await;
        assert_eq!(result.unwrap(), Err(PiSandboxError::BubblewrapVersion));
    }
}
