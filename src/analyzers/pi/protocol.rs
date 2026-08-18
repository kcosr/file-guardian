//! Authenticated host/extension wire protocol for Pi triage.

use crate::analyzers::pi::triage::PiTriageTerminalSubmission;
use crate::domain::{
    AnalyzerId, ClassificationCode, ConfiguredConfidence, Digest, ReasonCode, RunId,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "file-guardian-pi-proxy/3";
pub const OUTPUT_SCHEMA_VERSION: &str = "file-guardian-pi-triage/1";

pub const REQUIRED_TOOLS: &[&str] = &[
    "bash",
    "read",
    "grep",
    "find",
    "ls",
    "manifest_list",
    "triage_request",
    "submit_triage",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyRequest {
    pub protocol: String,
    pub run_token: String,
    pub request_id: u64,
    pub run_id: RunId,
    pub analyzer_id: AnalyzerId,
    pub manifest_identity: Digest,
    #[serde(flatten)]
    pub operation: ProxyOperation,
}

impl<'de> Deserialize<'de> for ProxyRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("proxy request must be an object"))?;
        let operation_name = object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("proxy request requires a string type"))?;
        let operation_fields: &[&str] = match operation_name {
            "runtime_ready" => &[
                "pi_version",
                "provider",
                "model",
                "thinking",
                "mode",
                "model_in_catalog",
                "active_tools",
            ],
            "instruction" | "triage_request" => &[],
            "manifest_list" => &["cursor"],
            "native_tool_begin" => &["tool_call_id", "tool", "path"],
            "native_tool_end" => &[
                "tool_call_id",
                "tool",
                "path",
                "outcome",
                "error_code",
                "output_bytes",
                "result_count",
            ],
            "submit_triage" => &["payload"],
            _ => return Err(serde::de::Error::custom("unknown proxy request type")),
        };
        const COMMON_FIELDS: &[&str] = &[
            "protocol",
            "run_token",
            "request_id",
            "run_id",
            "analyzer_id",
            "manifest_identity",
            "type",
        ];
        if object.keys().any(|field| {
            !COMMON_FIELDS.contains(&field.as_str()) && !operation_fields.contains(&field.as_str())
        }) {
            return Err(serde::de::Error::custom(
                "proxy request contains an unknown field",
            ));
        }

        #[derive(Deserialize)]
        struct Common {
            protocol: String,
            run_token: String,
            request_id: u64,
            run_id: RunId,
            analyzer_id: AnalyzerId,
            manifest_identity: Digest,
        }
        let common: Common = serde_json::from_value(value.clone())
            .map_err(|_| serde::de::Error::custom("invalid proxy request envelope"))?;
        let mut operation_object = serde_json::Map::new();
        operation_object.insert(
            "type".into(),
            object.get("type").expect("validated type field").clone(),
        );
        for field in operation_fields {
            if let Some(value) = object.get(*field) {
                operation_object.insert((*field).into(), value.clone());
            }
        }
        let operation = serde_json::from_value(serde_json::Value::Object(operation_object))
            .map_err(|_| serde::de::Error::custom("invalid proxy request operation"))?;
        Ok(Self {
            protocol: common.protocol,
            run_token: common.run_token,
            request_id: common.request_id,
            run_id: common.run_id,
            analyzer_id: common.analyzer_id,
            manifest_identity: common.manifest_identity,
            operation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyOperation {
    RuntimeReady {
        pi_version: String,
        provider: String,
        model: String,
        thinking: String,
        mode: String,
        model_in_catalog: bool,
        active_tools: Vec<String>,
    },
    Instruction {},
    ManifestList {
        cursor: u64,
    },
    NativeToolBegin {
        tool_call_id: String,
        tool: NativeTool,
        path: String,
    },
    NativeToolEnd {
        tool_call_id: String,
        tool: NativeTool,
        path: String,
        outcome: NativeToolOutcome,
        error_code: Option<NativeToolErrorCode>,
        output_bytes: u64,
        result_count: u64,
    },
    TriageRequest {},
    SubmitTriage {
        payload: PiTriageTerminalSubmission,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTool {
    Bash,
    Read,
    Grep,
    Find,
    Ls,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeToolOutcome {
    Completed,
    RecoverableError,
    FatalError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeToolErrorCode {
    InvalidArguments,
    ExecutionFailed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyResponse {
    Ok {
        protocol: String,
        request_id: u64,
        result: serde_json::Value,
    },
    Error {
        protocol: String,
        request_id: u64,
        error: ProxyError,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyError {
    pub code: ProxyErrorCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyErrorCode {
    ProtocolViolation,
    Unauthorized,
    InvalidRequest,
    BudgetExceeded,
    TerminalAlreadySubmitted,
    InternalError,
}

/// Compile-time closed vocabulary retained by the analyzer configuration.
/// Triage uses only its reason-code set; classifications are protocol-fixed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationVocabulary {
    classifications: BTreeSet<ClassificationCode>,
    confidences: BTreeSet<ConfiguredConfidence>,
    reason_codes: BTreeSet<ReasonCode>,
}

impl ClassificationVocabulary {
    pub fn new(
        classifications: impl IntoIterator<Item = ClassificationCode>,
        confidences: impl IntoIterator<Item = ConfiguredConfidence>,
        reason_codes: impl IntoIterator<Item = ReasonCode>,
    ) -> Result<Self, VocabularyError> {
        let vocabulary = Self {
            classifications: classifications.into_iter().collect(),
            confidences: confidences.into_iter().collect(),
            reason_codes: reason_codes.into_iter().collect(),
        };
        if vocabulary.classifications.is_empty()
            || vocabulary.confidences.is_empty()
            || vocabulary.reason_codes.is_empty()
        {
            return Err(VocabularyError::Empty);
        }
        Ok(vocabulary)
    }

    pub fn reason_codes(&self) -> impl Iterator<Item = ReasonCode> + '_ {
        self.reason_codes.iter().cloned()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VocabularyError {
    #[error("classification vocabularies must not be empty")]
    Empty,
}

/// Host-side list ceilings used to derive the triage terminal limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalValidationLimits {
    pub max_subject_artifact_ids: usize,
    pub max_artifact_classifications: usize,
    pub max_reason_codes_per_classification: usize,
}

impl TerminalValidationLimits {
    pub fn new(
        max_subject_artifact_ids: usize,
        max_artifact_classifications: usize,
        max_reason_codes_per_classification: usize,
    ) -> Result<Self, TerminalLimitError> {
        if max_subject_artifact_ids == 0
            || max_artifact_classifications == 0
            || max_reason_codes_per_classification == 0
        {
            return Err(TerminalLimitError);
        }
        Ok(Self {
            max_subject_artifact_ids,
            max_artifact_classifications,
            max_reason_codes_per_classification,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("terminal validation limits must be greater than zero")]
pub struct TerminalLimitError;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope(operation: serde_json::Value) -> serde_json::Value {
        let mut value = json!({
            "protocol": PROTOCOL_VERSION,
            "run_token": "token",
            "request_id": 1,
            "run_id": "run_one",
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
    fn only_end_state_triage_operations_parse() {
        assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
            "type": "triage_request"
        })))
        .is_ok());
        assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
            "type": "prior_observations"
        })))
        .is_err());
        assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
            "type": "submit_classification",
            "payload": {}
        })))
        .is_err());
    }

    #[test]
    fn envelope_and_operations_deny_unknown_fields() {
        assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
            "type": "triage_request",
            "extra": true
        })))
        .is_err());
        assert!(serde_json::from_value::<ProxyRequest>(envelope(json!({
            "type": "manifest_list"
        })))
        .is_err());
    }
}
