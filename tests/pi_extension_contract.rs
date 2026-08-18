use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::process::Command;

const EXTENSION: &str = include_str!("../src/analyzers/pi/assets/file_guardian_extension.js");
const SIDECAR: &str = include_str!("../src/analyzers/pi/assets/tool_sidecar_runner.js");
const RUST_CONFIG: &str = include_str!("../src/config/mod.rs");
const RUST_PI_MOD: &str = include_str!("../src/analyzers/pi/mod.rs");
const RUST_PROTOCOL: &str = include_str!("../src/analyzers/pi/protocol.rs");
const RUST_PROXY: &str = include_str!("../src/analyzers/pi/proxy.rs");
const RUST_RUNNER: &str = include_str!("../src/analyzers/pi/runner.rs");
const RUST_SANDBOX: &str = include_str!("../src/analyzers/pi/sandbox.rs");
const NODE_HARNESS: &str = include_str!("pi_extension_harness.mjs");
const SIDECAR_HARNESS: &str = include_str!("pi_tool_sidecar_harness.mjs");
const BWRAP_SIDECAR_HARNESS: &str = include_str!("pi_tool_sidecar_bwrap_harness.mjs");

const EXPECTED_TOOLS: [&str; 8] = [
    "bash",
    "find",
    "grep",
    "ls",
    "manifest_list",
    "triage_request",
    "read",
    "submit_triage",
];

#[test]
fn trusted_extension_registers_only_the_closed_tool_grant() {
    let registered: BTreeSet<_> = EXTENSION
        .split("name: \"")
        .skip(1)
        .filter_map(|tail| tail.split_once('"').map(|(name, _)| name))
        .collect();
    let expected: BTreeSet<_> = EXPECTED_TOOLS.into_iter().collect();

    assert_eq!(registered, expected);
    assert_eq!(
        EXTENSION.matches("executionMode: \"sequential\"").count(),
        8
    );
    assert!(EXTENSION.contains("terminate: true"));
    assert!(EXTENSION.contains("await proxyRequest(\"submit_triage\""));
    assert!(EXTENSION.contains("terminalState = \"accepted\""));

    for forbidden in [
        "write",
        "edit",
        "artifact_metadata",
        "artifact_read",
        "artifact_read_range",
        "artifact_search",
    ] {
        assert!(
            !registered.contains(forbidden),
            "registered obsolete or unsafe tool {forbidden}"
        );
    }
}

#[test]
fn extension_and_host_use_distinct_matching_wire_and_terminal_versions() {
    assert!(EXTENSION.contains("const PROTOCOL = \"file-guardian-pi-proxy/3\""));
    assert!(
        RUST_PROTOCOL.contains("pub const PROTOCOL_VERSION: &str = \"file-guardian-pi-proxy/3\"")
    );
    assert!(EXTENSION.contains("Type.Literal(\"file-guardian-pi-triage/1\")"));
    assert!(RUST_PROTOCOL.contains("file-guardian-pi-triage/1"));

    for field in [
        "run_token",
        "request_id",
        "run_id",
        "analyzer_id",
        "manifest_identity",
    ] {
        assert!(EXTENSION.contains(field), "extension omits {field}");
        assert!(RUST_PROTOCOL.contains(field), "host protocol omits {field}");
    }

    assert!(EXTENSION.contains("proxyRequest(\"instruction\")"));
    assert!(RUST_PROTOCOL.contains("Instruction {}"));
}

#[test]
fn terminal_tool_is_candidate_free_and_identity_bound() {
    for required in [
        "const TerminalTriage = strictObject({",
        "invocation_id: InvocationId",
        "request_identity: Digest",
        "prior_observations_identity: Digest",
        "finding_id: FindingId",
        "Type.Literal(\"false_positive\")",
        "stage_attestation:",
        "assigned_finding_count:",
        "assessed_finding_count:",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing triage field: {required}"
        );
    }
    for forbidden in ["candidates:", "rationale:", "matched_value:", "snippet:"] {
        assert!(
            !EXTENSION.contains(forbidden),
            "terminal schema exposes forbidden field: {forbidden}"
        );
    }
}

#[test]
fn extension_and_host_share_the_same_response_ceiling() {
    assert!(EXTENSION.contains("const MAX_PROXY_RESPONSE_BYTES = 2 * 1024 * 1024;"));
    assert!(RUST_PROXY.contains("EXTENSION_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;"));
    assert!(RUST_PROXY.contains("self.max_response_bytes > EXTENSION_MAX_RESPONSE_BYTES"));
}

#[test]
fn extension_and_host_share_the_native_tool_output_ceiling() {
    assert!(EXTENSION.contains("const MAX_NATIVE_TOOL_OUTPUT_BYTES = 64 * 1024;"));
    assert!(RUST_PROXY.contains("NATIVE_TOOL_MAX_OUTPUT_BYTES: usize = 64 * 1024;"));
    assert!(RUST_PROXY.contains("output_bytes > NATIVE_TOOL_MAX_OUTPUT_BYTES as u64"));
}

#[test]
fn extension_host_and_config_share_the_native_read_ceiling() {
    assert!(SIDECAR.contains("const MAX_READ_FILE_BYTES = 1024 * 1024;"));
    assert!(RUST_PROXY.contains("NATIVE_READ_MAX_BYTES: u64 = 1024 * 1024;"));
    assert!(RUST_CONFIG.contains("self.max_read_bytes_per_call.expect(\"checked above\")"));
    assert!(RUST_CONFIG.contains("> NATIVE_READ_MAX_BYTES"));
}

#[test]
fn trusted_extension_has_only_the_reviewed_runtime_capabilities() {
    for required in [
        "from \"node:child_process\"",
        "from \"node:net\"",
        "from \"node:path\"",
        "from \"node:readline\"",
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--ro-bind",
        "--tmpfs",
        "\"/agent\"",
        "\"/proxy\"",
        "toolSidecarRunner",
        "FILE_GUARDIAN_INPUT_ROOT: inputView",
        "FILE_GUARDIAN_WORK_ROOT: scratchRoot",
        "FILE_GUARDIAN_TOOL_PATH: toolPath",
        "stdio: [\"pipe\", \"pipe\", \"pipe\"]",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing reviewed capability {required}"
        );
    }

    assert!(!EXTENSION.contains("from \"node:fs"));
    assert!(!EXTENSION.contains("--share-net"));
    assert!(EXTENSION.contains("already-sparse outer Pi namespace"));
    for required in [
        "from \"node:fs/promises\"",
        "const INPUT_ROOT = testRoots?.[0] ?? process.env.FILE_GUARDIAN_INPUT_ROOT",
        "const WORK_ROOT = testRoots?.[1] ?? process.env.FILE_GUARDIAN_WORK_ROOT",
        "runtimeExecutable(\"bash\")",
        "runtimeExecutable(\"rg\")",
        "runtimeExecutable(\"fd\")",
        "detached: true",
        "process.kill(-child.pid, \"SIGKILL\")",
    ] {
        assert!(
            SIDECAR.contains(required),
            "missing sidecar capability {required}"
        );
    }

    for forbidden in [
        "node:http",
        "node:https",
        "fetch(",
        "exec(",
        "execFile(",
        "shell:",
        "process.env,",
        "pi.exec(",
        "registerCommand(",
        "registerShortcut(",
        "registerFlag(",
        "appendEntry(",
        "sendMessage(",
        "sendUserMessage(",
    ] {
        assert!(
            !EXTENSION.contains(forbidden),
            "trusted extension contains forbidden capability {forbidden}"
        );
    }
}

#[test]
fn native_paths_are_confined_to_the_read_only_input_tree() {
    for required in [
        "const INPUT_ROOT = testRoots?.[0] ?? process.env.FILE_GUARDIAN_INPUT_ROOT",
        "isAbsolute(rawPath)",
        "!value.includes(\"\\0\")",
        "rawPath.startsWith(\"~\")",
        "rawPath.startsWith(\"@\")",
        "rawPath.split(\"/\").includes(\"..\")",
        "const root = await realpath(INPUT_ROOT)",
        "const canonical = await realpath(lexical)",
        "metadata.isSymbolicLink()",
        "!metadata.isFile()",
        "!metadata.isDirectory()",
        "Path is outside the immutable input.",
    ] {
        assert!(
            SIDECAR.contains(required),
            "missing confinement contract: {required}"
        );
    }

    assert!(!EXTENSION.contains("resolveToCwd"));
    assert!(!EXTENSION.contains("process.cwd"));
}

#[test]
fn native_helpers_and_bash_run_only_in_the_networkless_sidecar() {
    assert_eq!(SIDECAR.matches("\"--no-ignore\"").count(), 2);
    assert_eq!(SIDECAR.matches("\"--hidden\"").count(), 2);
    assert!(SIDECAR.contains("const MAX_OUTPUT_BYTES = 64 * 1024"));
    assert!(SIDECAR.contains("const COMMAND_TIMEOUT_MILLIS = 10_000"));
    assert!(SIDECAR.contains("\"--noprofile\", \"--norc\", \"-c\""));
    assert!(SIDECAR.contains("cwd: INPUT_ROOT"));
    assert!(SIDECAR.contains("cwd = WORK_ROOT"));
    assert!(EXTENSION.contains("await startToolSidecar()"));
    assert!(EXTENSION.contains("await stopToolSidecar()"));
    assert!(EXTENSION.contains("sidecarRequest(tool, params, signal)"));
}

#[test]
fn native_outcomes_are_audited_and_only_fatal_failures_latch() {
    for required in [
        "\"native_tool_begin\"",
        "\"native_tool_end\"",
        "tool_call_id: toolCallId",
        "path,",
        "output_bytes: outputBytes",
        "result_count: resultCount",
        "outcome,",
        "error_code: errorCode",
        "\"completed\"",
        "\"recoverable_error\"",
        "\"fatal_error\"",
        "\"invalid_arguments\"",
        "\"execution_failed\"",
        "latchIntegrityFailure()",
        "if (integrityFailure) throw integrityFailure",
        "if (error === integrityFailure) throw error",
        "Pi sandboxed tool integrity check failed",
        "requireAccepted(result)",
        "result.accepted !== true",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing native audit contract: {required}"
        );
    }

    assert!(EXTENSION.contains("import { createHash } from \"node:crypto\""));
    assert!(EXTENSION.contains("Buffer.byteLength(value, \"utf8\") > MAX_PATH_CHARACTERS"));
    assert!(EXTENSION.contains("/[\\u0000-\\u001f\\u007f-\\u009f]/.test(value)"));
    assert!(EXTENSION
        .contains("`tc_${createHash(\"sha256\").update(value, \"utf8\").digest(\"hex\")}`"));
    assert!(EXTENSION.contains("error instanceof RecoverableNativeToolError"));
    assert!(SIDECAR.contains("Command arguments were rejected. Revise them and retry."));
    assert!(SIDECAR.contains("Read offset is beyond end of file."));
}

#[test]
fn manifest_pages_are_cursor_bound_and_walkable() {
    for required in [
        "file-guardian-pi-manifest-page/1",
        "let nextManifestCursor = 0",
        "parameters: strictObject({})",
        "async execute(_toolCallId, _params, signal)",
        "const cursor = nextManifestCursor",
        "proxyRequest(\"manifest_list\", { cursor }, signal)",
        "nextManifestCursor = page.next_cursor ?? page.total_count",
        "result.next_cursor === null",
        "result.next_cursor !== pageEnd",
        "Call repeatedly until next_cursor is null.",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing manifest pagination contract: {required}"
        );
    }
    assert!(RUST_PROTOCOL.contains("ManifestList {\n        cursor: u64,\n    }"));
    assert!(RUST_PROXY.contains("manifest_page_value("));
    assert!(RUST_PROXY.contains("next_cursor: Option<u64>"));
    assert!(NODE_HARNESS.contains("discontinuous manifest page"));
    assert!(NODE_HARNESS.contains("getNextManifestCursor(), 3"));
}

#[test]
fn executable_node_harness_passes_when_node_is_available() {
    for (script, label) in [
        ("tests/pi_extension_harness.mjs", "Pi extension"),
        ("tests/pi_tool_sidecar_harness.mjs", "Pi tool sidecar"),
        (
            "tests/pi_tool_sidecar_bwrap_harness.mjs",
            "Pi Bubblewrap sidecar confinement",
        ),
    ] {
        let output = match Command::new("node")
            .arg(script)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == ErrorKind::NotFound => return,
            Err(error) => panic!("could not execute {label} harness: {error}"),
        };
        assert!(
            output.status.success(),
            "{label} harness failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(SIDECAR_HARNESS.contains("persistent"));
    assert!(BWRAP_SIDECAR_HARNESS.contains("hostConnectionObserved"));
    assert!(BWRAP_SIDECAR_HARNESS.contains("git -C /input rev-parse --verify HEAD"));
    assert!(BWRAP_SIDECAR_HARNESS.contains("printf changed > /input/artifact.txt"));
    assert!(BWRAP_SIDECAR_HARNESS.contains("printf scratch > /work/state.txt"));
}

#[test]
fn trusted_extension_authenticates_runtime_and_replaces_the_prompt() {
    for required in [
        "FILE_GUARDIAN_PI_PROXY_SOCKET",
        "FILE_GUARDIAN_PI_RUN_TOKEN",
        "FILE_GUARDIAN_PI_RUN_ID",
        "FILE_GUARDIAN_PI_MANIFEST_IDENTITY",
        "FILE_GUARDIAN_PI_ANALYZER_ID",
        "runtime_ready",
        "pi_version: VERSION",
        "model_in_catalog:",
        "active_tools: activeTools",
        "assertExactToolGrant()",
        "pi.on(\"model_select\"",
        "pi.on(\"thinking_level_select\"",
        "pi.on(\"before_agent_start\"",
        "return { systemPrompt: runtimeInstruction }",
    ] {
        assert!(EXTENSION.contains(required), "missing contract: {required}");
    }
}

#[test]
fn caller_fields_cannot_override_authenticated_proxy_envelope() {
    let fields = EXTENSION
        .find("\t\t...fields,\n\t\tprotocol: PROTOCOL,")
        .expect("caller fields must precede authenticated envelope fields");
    let request_end = EXTENSION[fields..]
        .find("\n\t};")
        .expect("proxy request object must close");
    assert!(
        !EXTENSION[fields + "\t\t...fields,".len()..fields + request_end].contains("...fields")
    );
    assert!(EXTENSION.contains(
        "async execute(_toolCallId, _params, signal) {\n\t\t\treturn proxyToolResult(await proxyRequest(\"triage_request\", {}, signal));"
    ));
}

#[test]
fn every_tool_parameter_object_is_closed_and_bounded() {
    assert!(EXTENSION.contains("additionalProperties: false"));
    assert!(!EXTENSION.contains("Type.Any("));
    assert!(!EXTENSION.contains("Type.Unknown("));
    assert!(EXTENSION.contains("Type.Integer({ minimum: 1, maximum: MAX_READ_LINES })"));
    assert!(EXTENSION.contains("Type.Integer({ minimum: 0, maximum: 20 })"));
    assert_eq!(
        EXTENSION
            .matches("Type.Integer({ minimum: 1, maximum: maxSearchResults })")
            .count(),
        3
    );
    assert!(EXTENSION.contains("maxItems:"));
    assert!(EXTENSION.contains("maxLength:"));
    assert!(EXTENSION.contains("uniqueItems: true"));
    assert!(EXTENSION.contains("^fnd_[A-Za-z0-9_-]{1,96}$"));
    assert!(EXTENSION.contains("^pii_[A-Za-z0-9_-]{1,96}$"));
    assert!(EXTENSION.contains("hasExactKeys(response"));
}

#[test]
fn configured_search_result_cap_is_strict_and_clamps_every_default() {
    for required in [
        "const MAX_CONFIGURED_SEARCH_RESULTS = 10000;",
        "FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS",
        "requiredBoundedIntegerEnvironment(",
        "/^[1-9][0-9]*$/",
        "parsed > maximum",
        "Math.min(DEFAULT_GREP_MATCHES, maxSearchResults)",
        "Math.min(DEFAULT_FIND_RESULTS, maxSearchResults)",
        "Math.min(DEFAULT_LS_ENTRIES, maxSearchResults)",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing search cap contract: {required}"
        );
    }

    assert!(!EXTENSION.contains("MAX_GREP_MATCHES"));
    assert!(!EXTENSION.contains("MAX_FIND_RESULTS"));
    assert!(!EXTENSION.contains("MAX_LS_ENTRIES"));
    assert!(RUST_PROXY.contains("pub(crate) const NATIVE_SEARCH_MAX_RESULTS: u64 = 10_000;"));
    assert!(RUST_CONFIG
        .contains("self.max_search_results.expect(\"checked above\") > NATIVE_SEARCH_MAX_RESULTS"));
    assert!(RUST_CONFIG.contains("must not exceed the native schema limit"));
    assert!(RUST_SANDBOX.contains("use super::proxy::NATIVE_SEARCH_MAX_RESULTS;"));
    assert!(RUST_SANDBOX.contains("invocation.max_search_results == 0"));
    assert!(RUST_SANDBOX.contains("invocation.max_search_results > NATIVE_SEARCH_MAX_RESULTS"));
    assert!(RUST_SANDBOX.contains("OsString::from(\"FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS\")"));
    assert!(RUST_SANDBOX.contains("OsString::from(invocation.max_search_results.to_string())"));
    assert!(RUST_RUNNER.contains("max_search_results: invocation.max_search_results"));
    assert!(RUST_PI_MOD.contains("PiProxyLimits, NATIVE_SEARCH_MAX_RESULTS"));
    assert!(RUST_PI_MOD.contains("spec.max_search_results > NATIVE_SEARCH_MAX_RESULTS"));
}
