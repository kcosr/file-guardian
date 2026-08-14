use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::process::Command;

const EXTENSION: &str = include_str!("../src/analyzers/pi/assets/file_guardian_extension.js");
const RUST_CONFIG: &str = include_str!("../src/config/mod.rs");
const RUST_PI_MOD: &str = include_str!("../src/analyzers/pi/mod.rs");
const RUST_PROTOCOL: &str = include_str!("../src/analyzers/pi/protocol.rs");
const RUST_PROXY: &str = include_str!("../src/analyzers/pi/proxy.rs");
const RUST_RUNNER: &str = include_str!("../src/analyzers/pi/runner.rs");
const RUST_SANDBOX: &str = include_str!("../src/analyzers/pi/sandbox.rs");
const NODE_HARNESS: &str = include_str!("pi_extension_harness.mjs");

const EXPECTED_TOOLS: [&str; 7] = [
    "find",
    "grep",
    "ls",
    "manifest_list",
    "prior_observations",
    "read",
    "submit_classification",
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
        7
    );
    assert!(EXTENSION.contains("terminate: true"));
    assert!(EXTENSION.contains("await proxyRequest(\"submit_classification\""));
    assert!(EXTENSION.contains("terminalState = \"accepted\""));

    for forbidden in [
        "bash",
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
    assert!(EXTENSION.contains("const PROTOCOL = \"file-guardian-pi-proxy/2\""));
    assert!(
        RUST_PROTOCOL.contains("pub const PROTOCOL_VERSION: &str = \"file-guardian-pi-proxy/2\"")
    );
    assert!(EXTENSION.contains("Type.Literal(\"file-guardian-pi-classifier/1\")"));
    assert!(RUST_PROTOCOL.contains("file-guardian-pi-classifier/1"));

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
    assert!(EXTENSION.contains("const MAX_NATIVE_READ_FILE_BYTES = 1024 * 1024;"));
    assert!(RUST_PROXY.contains("NATIVE_READ_MAX_BYTES: u64 = 1024 * 1024;"));
    assert!(RUST_CONFIG.contains("self.max_read_bytes_per_call.expect(\"checked above\")"));
    assert!(RUST_CONFIG.contains("> NATIVE_READ_MAX_BYTES"));
}

#[test]
fn trusted_extension_has_only_the_reviewed_runtime_capabilities() {
    for required in [
        "from \"node:child_process\"",
        "from \"node:fs/promises\"",
        "from \"node:net\"",
        "from \"node:path\"",
        "const RG = \"/runtime/bin/rg\"",
        "const FD = \"/runtime/bin/fd\"",
        "env: {}",
        "stdio: [\"ignore\", \"pipe\", \"pipe\"]",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing reviewed capability {required}"
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
        "const INPUT_ROOT = \"/input\"",
        "isAbsolute(rawPath)",
        "rawPath.includes(\"\\0\")",
        "rawPath.startsWith(\"~\")",
        "rawPath.startsWith(\"@\")",
        "rawPath.split(\"/\").includes(\"..\")",
        "const root = await realpath(INPUT_ROOT)",
        "const canonical = await realpath(lexical)",
        "metadata.isSymbolicLink()",
        "!metadata.isFile()",
        "!metadata.isDirectory()",
        "path is outside the analyzer input",
    ] {
        assert!(
            EXTENSION.contains(required),
            "missing confinement contract: {required}"
        );
    }

    assert!(!EXTENSION.contains("resolveToCwd"));
    assert!(!EXTENSION.contains("process.cwd"));
}

#[test]
fn native_helpers_are_no_ignore_bounded_and_shell_free() {
    assert_eq!(EXTENSION.matches("\"--no-ignore\"").count(), 2);
    assert_eq!(EXTENSION.matches("\"--hidden\"").count(), 2);
    assert_eq!(EXTENSION.matches("args.push(\"--\"").count(), 1);
    assert!(EXTENSION.contains("\"--\",\n\t\t\t\t\tpattern,"));
    assert!(EXTENSION.contains("const MAX_NATIVE_TOOL_OUTPUT_BYTES = 64 * 1024"));
    assert!(EXTENSION.contains("const MAX_NATIVE_NOTICE_BYTES = 256"));
    assert!(EXTENSION.contains("const HELPER_TIMEOUT_MILLIS = 10000"));
    assert!(EXTENSION.contains("child.kill(\"SIGKILL\")"));
    assert!(EXTENSION.contains("stderrBytes > MAX_HELPER_STDERR_BYTES"));
    assert!(EXTENSION.contains(
        "const resultLimitReached = killedForResultLimit || lines.length >= resultLimit"
    ));
    assert!(EXTENSION.contains("[Truncated: ${resultLimit} ${limitKind} limit]"));
    assert!(EXTENSION.contains("[Truncated: ${MAX_NATIVE_TOOL_OUTPUT_BYTES} output byte limit]"));
    assert!(EXTENSION.contains("[`${limitKind}LimitReached`]"));
    assert!(EXTENSION.contains("const entryLimitReached = entries.length > limit"));
    assert!(EXTENSION.contains("\"--max-columns\""));
    assert!(EXTENSION.contains("\"--max-columns-preview\""));
    assert!(EXTENSION.contains("const lastCompleteLine = rawText.lastIndexOf(\"\\n\")"));
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
        "Pi read-only tool integrity check failed",
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
    assert!(EXTENSION.contains("Invalid search arguments. Revise them and retry."));
    assert!(EXTENSION.contains("Read offset is beyond end of file. Revise it and retry."));
    assert!(NODE_HARNESS.contains("RecoverableNativeToolError"));
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
    assert!(NODE_HARNESS.contains("sensitive-partial-line"));
    assert!(NODE_HARNESS.contains("getNextManifestCursor(), 3"));
}

#[test]
fn executable_node_harness_passes_when_node_is_available() {
    let output = match Command::new("node")
        .arg("tests/pi_extension_harness.mjs")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == ErrorKind::NotFound => return,
        Err(error) => panic!("could not execute Pi extension harness: {error}"),
    };
    assert!(
        output.status.success(),
        "Pi extension harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
    assert!(EXTENSION.contains("^a_[A-Za-z0-9_.:-]{1,126}$"));
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
    assert!(RUST_SANDBOX.contains("validate_max_search_results(invocation.max_search_results)?"));
    assert!(RUST_SANDBOX.contains("value > NATIVE_SEARCH_MAX_RESULTS"));
    assert!(RUST_SANDBOX.contains("OsString::from(\"FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS\")"));
    assert!(RUST_SANDBOX.contains("OsString::from(invocation.max_search_results.to_string())"));
    assert!(RUST_RUNNER.contains("max_search_results: invocation.max_search_results"));
    assert!(RUST_PI_MOD.contains("PiProxyLimits, NATIVE_SEARCH_MAX_RESULTS"));
    assert!(RUST_PI_MOD.contains("spec.max_search_results > NATIVE_SEARCH_MAX_RESULTS"));
}
