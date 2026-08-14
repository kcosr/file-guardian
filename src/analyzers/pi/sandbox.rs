use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

pub(crate) const SANDBOX_PROXY_SOCKET: &str = "/run/file-guardian/proxy.sock";
pub(crate) const PI_TOOLS: &str = "manifest_list,artifact_metadata,artifact_read,artifact_read_range,artifact_search,prior_observations,submit_classification";
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
    #[error("Pi classification is unsupported on this platform")]
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
                stamp_tree(&spec.isolated_agent_dir)?,
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
pub(crate) struct SandboxCommand {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
}

impl std::fmt::Debug for SandboxCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxCommand")
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
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct SandboxInvocation<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub thinking: &'a str,
    pub proxy_endpoint_dir: &'a Path,
    pub proxy_token: &'a str,
    pub analyzer_id: &'a str,
    pub run_id: &'a str,
    pub manifest_identity: &'a str,
    pub credential_environment: &'a [(OsString, OsString)],
}

pub(crate) fn compile_sandbox_command(
    runtime: &PreparedPiRuntime,
    invocation: &SandboxInvocation<'_>,
) -> Result<SandboxCommand, PiSandboxError> {
    debug_assert_eq!(PI_RUNTIME_CONTEXT_MODE, "print");
    runtime.revalidate()?;
    validate_proxy_dir(invocation.proxy_endpoint_dir)?;
    let mut environment = vec![
        (OsString::from("HOME"), OsString::from("/home/pi")),
        (OsString::from("TMPDIR"), OsString::from("/tmp")),
        (
            OsString::from("PI_CODING_AGENT_DIR"),
            OsString::from("/config"),
        ),
        (OsString::from("PI_OFFLINE"), OsString::from("1")),
        (OsString::from("PI_TELEMETRY"), OsString::from("0")),
        (
            OsString::from("FILE_GUARDIAN_PI_PROXY_SOCKET"),
            OsString::from(SANDBOX_PROXY_SOCKET),
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
    let extension_target = Path::new("/policy/file-guardian-extension.js");
    let mut arguments = os_args(&[
        "--unshare-all",
        "--unshare-user",
        "--share-net",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--hostname",
        "file-guardian-pi",
        "--cap-drop",
        "ALL",
        "--tmpfs",
        "/",
        "--dir",
        "/runtime",
        "--dir",
        "/policy",
        "--dir",
        "/config",
        "--dir",
        "/etc",
        "--dir",
        "/etc/ssl",
        "--dir",
        "/etc/ssl/certs",
        "--dir",
        "/run",
        "--dir",
        "/run/file-guardian",
        "--dir",
        "/home",
        "--dir",
        "/home/pi",
        "--dir",
        "/work",
        "--dir",
        "/tmp",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
    ]);
    push_pair(&mut arguments, &spec.runtime_root, Path::new("/runtime"));
    arguments.push(OsString::from("--ro-bind"));
    push_pair(&mut arguments, &spec.trusted_extension, extension_target);
    arguments.push(OsString::from("--ro-bind"));
    push_pair(
        &mut arguments,
        &spec.isolated_agent_dir,
        Path::new("/config"),
    );
    for (source, target) in [
        ("etc/resolv.conf", "/etc/resolv.conf"),
        ("etc/hosts", "/etc/hosts"),
        ("etc/nsswitch.conf", "/etc/nsswitch.conf"),
        (
            "etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/certs/ca-certificates.crt",
        ),
    ] {
        arguments.push(OsString::from("--ro-bind"));
        push_pair(
            &mut arguments,
            &spec.runtime_root.join(source),
            Path::new(target),
        );
    }
    arguments.push(OsString::from("--ro-bind"));
    push_pair(
        &mut arguments,
        invocation.proxy_endpoint_dir,
        Path::new("/run/file-guardian"),
    );
    arguments.extend(os_args(&["--chdir", "/work", "--"]));
    arguments.push(sandbox_runtime_path(&spec.launcher)?);
    arguments.push(sandbox_runtime_path(&spec.pi_entrypoint)?);
    arguments.extend(os_args(&[
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
    arguments.push(extension_target.as_os_str().to_owned());
    arguments.extend(os_args(&[
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
    Ok(SandboxCommand {
        program: spec.bubblewrap_executable.clone(),
        arguments,
        environment,
    })
}

fn validate_runtime_spec(spec: &PiRuntimeSpec) -> Result<(), PiSandboxError> {
    for path in [
        &spec.bubblewrap_executable,
        &spec.runtime_root,
        &spec.runtime_manifest,
        &spec.instruction_file,
        &spec.trusted_extension,
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
    verify_secure_tree(&spec.isolated_agent_dir)?;
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
        || [
            "etc/resolv.conf",
            "etc/hosts",
            "etc/nsswitch.conf",
            "etc/ssl/certs/ca-certificates.crt",
        ]
        .iter()
        .any(|path| !declared.contains_key(Path::new(path)))
    {
        return Err(PiSandboxError::InvalidRuntime);
    }
    Ok(())
}

fn validate_proxy_dir(path: &Path) -> Result<(), PiSandboxError> {
    if !path.is_absolute() {
        return Err(PiSandboxError::InvalidRuntime);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| PiSandboxError::InvalidRuntime)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
        return Err(PiSandboxError::InvalidRuntime);
    }
    let entries = fs::read_dir(path).map_err(|_| PiSandboxError::InvalidRuntime)?;
    let names = entries
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|_| PiSandboxError::InvalidRuntime)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names != [OsString::from("proxy.sock")] {
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

fn sandbox_runtime_path(relative: &Path) -> Result<OsString, PiSandboxError> {
    Ok(Path::new("/runtime")
        .join(normalize_relative(relative)?)
        .into_os_string())
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
fn push_pair(arguments: &mut Vec<OsString>, source: &Path, target: &Path) {
    arguments.push(source.as_os_str().to_owned());
    arguments.push(target.as_os_str().to_owned());
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
                runtime.join("etc"),
                runtime.join("etc/ssl"),
                runtime.join("etc/ssl/certs"),
                root.path().join("config"),
                root.path().join("proxy"),
            ] {
                fs::create_dir_all(&directory).unwrap();
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let files = [
                ("bin/node", b"static-node".as_slice(), true),
                ("lib/pi/dist/cli.js", b"pi-entrypoint", false),
                ("etc/resolv.conf", b"nameserver 127.0.0.1\n", false),
                ("etc/hosts", b"127.0.0.1 localhost\n", false),
                ("etc/nsswitch.conf", b"hosts: files dns\n", false),
                ("etc/ssl/certs/ca-certificates.crt", b"test-ca\n", false),
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
            for (path, bytes, mode) in [
                (&bwrap, b"fake-bwrap".as_slice(), 0o700),
                (&instruction, b"trusted instruction", 0o600),
                (&extension, b"trusted extension", 0o600),
            ] {
                fs::write(path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            }
            let proxy = root.path().join("proxy");
            fs::set_permissions(&proxy, fs::Permissions::from_mode(0o700)).unwrap();
            let socket = UnixListener::bind(proxy.join("proxy.sock")).unwrap();
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
                    isolated_agent_dir: root.path().join("config"),
                },
                proxy,
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
        let command = SandboxCommand {
            program: PathBuf::from("/usr/bin/bwrap"),
            arguments: os_args(&["--unshare-all", "--", "/runtime/bin/node"]),
            environment: vec![
                (OsString::from("PROVIDER_KEY"), OsString::from(secret)),
                (
                    OsString::from("FILE_GUARDIAN_PI_RUN_TOKEN"),
                    OsString::from(token),
                ),
            ],
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
    fn manifest_pinned_bundle_compiles_exact_confinement_command() {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        prepared.revalidate().unwrap();
        let credentials = [(OsString::from("INTERNAL_API_KEY"), OsString::from("secret"))];
        let command = compile_sandbox_command(
            &prepared,
            &SandboxInvocation {
                provider: "internal",
                model: "classified-model",
                thinking: "high",
                proxy_endpoint_dir: &fixture.proxy,
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
        for required in [
            "--unshare-all",
            "--unshare-user",
            "--share-net",
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "--tmpfs",
            "--proc",
            "--dev",
            "/runtime/bin/node",
            "/runtime/lib/pi/dist/cli.js",
            "--print",
            "--mode",
            PI_CLI_OUTPUT_MODE,
            "--no-session",
            "--no-builtin-tools",
            PI_TOOLS,
            "--no-extensions",
            "/policy/file-guardian-extension.js",
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
        assert!(args
            .windows(2)
            .any(|values| values == ["--mode", PI_CLI_OUTPUT_MODE]));
        assert_eq!(PI_RUNTIME_CONTEXT_MODE, "print");
        assert!(!args
            .windows(3)
            .any(|values| values[0] == "--ro-bind" && values[1] == "/"));
        assert!(!args
            .iter()
            .any(|value| value.contains("staging") || value.contains("objects")));
        for target in [
            "/runtime",
            "/policy/file-guardian-extension.js",
            "/config",
            "/run/file-guardian",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/ssl/certs/ca-certificates.crt",
        ] {
            assert!(
                args.iter().any(|value| value == target),
                "missing mount {target}"
            );
        }
        let actual_mounts = args
            .windows(3)
            .filter(|values| values[0] == "--ro-bind")
            .map(|values| (values[1].clone(), values[2].clone()))
            .collect::<BTreeSet<_>>();
        let expected_mounts = [
            (fixture.spec.runtime_root.clone(), PathBuf::from("/runtime")),
            (
                fixture.spec.trusted_extension.clone(),
                PathBuf::from("/policy/file-guardian-extension.js"),
            ),
            (
                fixture.spec.isolated_agent_dir.clone(),
                PathBuf::from("/config"),
            ),
            (
                fixture.spec.runtime_root.join("etc/resolv.conf"),
                PathBuf::from("/etc/resolv.conf"),
            ),
            (
                fixture.spec.runtime_root.join("etc/hosts"),
                PathBuf::from("/etc/hosts"),
            ),
            (
                fixture.spec.runtime_root.join("etc/nsswitch.conf"),
                PathBuf::from("/etc/nsswitch.conf"),
            ),
            (
                fixture
                    .spec
                    .runtime_root
                    .join("etc/ssl/certs/ca-certificates.crt"),
                PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
            ),
            (fixture.proxy.clone(), PathBuf::from("/run/file-guardian")),
        ]
        .into_iter()
        .map(|(source, target)| {
            (
                source.to_string_lossy().into_owned(),
                target.to_string_lossy().into_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
        assert_eq!(actual_mounts, expected_mounts);
        let names = command
            .environment
            .iter()
            .map(|(name, _)| name.to_string_lossy())
            .collect::<BTreeSet<_>>();
        for name in [
            "HOME",
            "TMPDIR",
            "PI_CODING_AGENT_DIR",
            "PI_OFFLINE",
            "PI_TELEMETRY",
            "FILE_GUARDIAN_PI_PROXY_SOCKET",
            "FILE_GUARDIAN_PI_RUN_TOKEN",
            "FILE_GUARDIAN_PI_ANALYZER_ID",
            "FILE_GUARDIAN_PI_RUN_ID",
            "FILE_GUARDIAN_PI_MANIFEST_IDENTITY",
            "INTERNAL_API_KEY",
        ] {
            assert!(names.contains(name));
        }
        for forbidden in ["PATH", "NODE_PATH", "NODE_OPTIONS"] {
            assert!(!names.contains(forbidden));
        }
    }

    #[test]
    fn prepared_assets_are_revalidated_and_change_identity() {
        for choose in 0..4 {
            let fixture = Fixture::new();
            let prepared = fixture.prepare();
            let old_identity = prepared.identity();
            let path = match choose {
                0 => &fixture.spec.instruction_file,
                1 => &fixture.spec.trusted_extension,
                2 => &fixture.spec.runtime_root.join("lib/pi/dist/cli.js"),
                _ => {
                    let config = fixture.spec.isolated_agent_dir.join("settings.json");
                    fs::write(&config, b"old").unwrap();
                    // This entry was added after preparation, so failure itself proves tree mutation.
                    assert_eq!(prepared.revalidate(), Err(PiSandboxError::InvalidRuntime));
                    continue;
                }
            };
            fs::write(path, b"mutated asset bytes").unwrap();
            assert_eq!(prepared.revalidate(), Err(PiSandboxError::InvalidRuntime));
            if choose != 2 {
                let new = PreparedPiRuntime::prepare(fixture.spec.clone()).unwrap();
                assert_ne!(new.identity(), old_identity);
            }
        }
    }

    #[test]
    fn rejects_manifest_and_filesystem_substitution_attacks() {
        let extra = Fixture::new();
        fs::write(extra.spec.runtime_root.join("extra"), b"extra").unwrap();
        assert!(PreparedPiRuntime::prepare(extra.spec).is_err());

        let missing = Fixture::new();
        fs::remove_file(missing.spec.runtime_root.join("etc/hosts")).unwrap();
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
