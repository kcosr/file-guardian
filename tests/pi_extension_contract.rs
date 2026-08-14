use std::collections::BTreeSet;

const EXTENSION: &str = include_str!("../src/analyzers/pi/assets/file_guardian_extension.js");
const RUST_PROTOCOL: &str = include_str!("../src/analyzers/pi/protocol.rs");
const RUST_PROXY: &str = include_str!("../src/analyzers/pi/proxy.rs");

const EXPECTED_TOOLS: [&str; 7] = [
    "artifact_metadata",
    "artifact_read",
    "artifact_read_range",
    "artifact_search",
    "manifest_list",
    "prior_observations",
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
    assert!(EXTENSION.contains("terminate: true"));
    assert!(EXTENSION.contains("await proxyRequest(\"submit_classification\""));
    assert!(EXTENSION.contains("terminalState = \"accepted\""));
    assert_eq!(EXTENSION.matches("registerProxyTool(pi, {").count(), 6);
    assert!(EXTENSION.contains("...definition,\n\t\texecutionMode: \"sequential\","));
    assert!(EXTENSION
        .contains("parameters: TerminalClassification,\n\t\texecutionMode: \"sequential\","));
}

#[test]
fn extension_and_host_use_distinct_matching_wire_and_terminal_versions() {
    assert!(EXTENSION.contains("const PROTOCOL = \"file-guardian-pi-proxy/1\""));
    assert!(
        RUST_PROTOCOL.contains("pub const PROTOCOL_VERSION: &str = \"file-guardian-pi-proxy/1\"")
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

    // Instruction bytes are authenticated bootstrap data, never an LLM tool.
    assert!(EXTENSION.contains("proxyRequest(\"instruction\")"));
    assert!(RUST_PROTOCOL.contains("Instruction {}"));
}

#[test]
fn extension_and_host_share_the_same_response_ceiling() {
    assert!(EXTENSION.contains("const MAX_PROXY_RESPONSE_BYTES = 2 * 1024 * 1024;"));
    assert!(RUST_PROXY.contains("const EXTENSION_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;"));
    assert!(RUST_PROXY.contains("self.max_response_bytes > EXTENSION_MAX_RESPONSE_BYTES"));
}

#[test]
fn trusted_extension_has_no_ambient_host_capabilities() {
    for forbidden in [
        "node:fs",
        "node:child_process",
        "node:http",
        "node:https",
        "fetch(",
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

    assert_eq!(EXTENSION.matches("from \"node:").count(), 1);
    assert!(EXTENSION.contains("from \"node:net\""));
}

#[test]
fn trusted_extension_authenticates_runtime_and_replaces_the_prompt() {
    for required in [
        "FILE_GUARDIAN_PI_PROXY_SOCKET",
        "FILE_GUARDIAN_PI_RUN_TOKEN",
        "FILE_GUARDIAN_PI_RUN_ID",
        "FILE_GUARDIAN_PI_MANIFEST_IDENTITY",
        "FILE_GUARDIAN_PI_ANALYZER_ID",
        "file-guardian-pi-proxy/1",
        "runtime_ready",
        "proxyRequest(\"instruction\")",
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
    assert!(EXTENSION.contains("maximum: Number.MAX_SAFE_INTEGER"));
    assert!(EXTENSION.contains("maxItems:"));
    assert!(EXTENSION.contains("maxLength:"));
    assert!(EXTENSION.contains("uniqueItems: true"));
    assert!(EXTENSION.contains("^a_[A-Za-z0-9_.:-]{1,126}$"));
    assert!(EXTENSION.contains("hasExactKeys(response"));
}
