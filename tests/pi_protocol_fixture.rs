use file_guardian::analyzers::pi::protocol::{
    ProxyOperation, ProxyRequest, OUTPUT_SCHEMA_VERSION, PROTOCOL_VERSION, REQUIRED_TOOLS,
};
use file_guardian::analyzers::pi::triage::PiTriageTerminalSubmission;
use file_guardian::analyzers::pi::triage::TRIAGE_TERMINAL_SCHEMA;
use file_guardian::domain::Digest;
use serde_json::json;

fn envelope(operation: serde_json::Value) -> serde_json::Value {
    let mut value = json!({
        "protocol": PROTOCOL_VERSION,
        "run_token": "opaque-token",
        "request_id": 1,
        "run_id": "run_fixture",
        "analyzer_id": "pi-triage",
        "manifest_identity": Digest::sha256(b"manifest"),
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(operation.as_object().unwrap().clone());
    value
}

#[test]
fn proxy_and_terminal_versions_are_exact_end_state_contracts() {
    assert_eq!(PROTOCOL_VERSION, "file-guardian-pi-proxy/3");
    assert_eq!(OUTPUT_SCHEMA_VERSION, TRIAGE_TERMINAL_SCHEMA);
    assert_eq!(
        REQUIRED_TOOLS,
        [
            "bash",
            "read",
            "grep",
            "find",
            "ls",
            "manifest_list",
            "triage_request",
            "submit_triage",
        ]
    );
}

#[test]
fn request_parser_accepts_only_strict_triage_operations() {
    let request: ProxyRequest = serde_json::from_value(envelope(json!({
        "type": "triage_request"
    })))
    .unwrap();
    assert!(matches!(
        request.operation,
        ProxyOperation::TriageRequest {}
    ));

    for obsolete in ["prior_observations", "submit_classification"] {
        assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
            "type": obsolete
        })))
        .is_err());
    }

    assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
        "type": "triage_request",
        "unknown": true
    })))
    .is_err());
}

#[test]
fn checked_in_terminal_fixture_uses_the_strict_candidate_free_schema() {
    let source = include_str!("../docs/examples/pi-triage/restricted.json");
    let submission: PiTriageTerminalSubmission = serde_json::from_str(source).unwrap();
    assert_eq!(submission.schema_version, TRIAGE_TERMINAL_SCHEMA);
    assert_eq!(submission.assessments.len(), 1);
    let value: serde_json::Value = serde_json::from_str(source).unwrap();
    for forbidden in ["candidates", "rationale", "snippet", "matched_value"] {
        assert!(value.get(forbidden).is_none());
        assert!(value["assessments"][0].get(forbidden).is_none());
    }
}
