use super::{AnalyzerId, ArtifactId, InspectionPhase, SubjectId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueCode {
    InputUnavailable,
    WorkspaceFailure,
    EnumerationFailure,
    UnsupportedFileType,
    SymlinkRejected,
    HardlinkRejected,
    FilesystemCrossingRejected,
    FileUnreadable,
    FileUnstable,
    FileDisappeared,
    FileInserted,
    SizeLimitExceeded,
    RequiredAnalyzerTimeout,
    RequiredAnalyzerBudgetExceeded,
    RequiredAnalyzerProcessFailure,
    RequiredAnalyzerProtocolFailure,
    AnalyzerFailure,
    InvalidAnalyzerOutput,
    IncompleteCoverage,
    InternalFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InspectionIssue {
    pub phase: InspectionPhase,
    pub code: IssueCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_id: Option<AnalyzerId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<SubjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<ArtifactId>,
    #[serde(rename = "safe_message")]
    pub message: SanitizedMessage,
}

/// Bounded diagnostic text. Callers must not include paths, content, or secrets.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SanitizedMessage(String);

impl SanitizedMessage {
    pub const MAX_BYTES: usize = 512;

    pub fn new(value: impl Into<String>) -> Result<Self, SanitizedMessageError> {
        let value = value.into();
        if value.is_empty() || value.len() > Self::MAX_BYTES {
            return Err(SanitizedMessageError::Length);
        }
        if value.chars().any(char::is_control) {
            return Err(SanitizedMessageError::ControlCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SanitizedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for SanitizedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SanitizedMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SanitizedMessageError {
    #[error("sanitized message must contain 1 to 512 bytes")]
    Length,
    #[error("sanitized message must not contain control characters")]
    ControlCharacter,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_text_is_bounded_and_single_line() {
        assert!(SanitizedMessage::new("capture failed").is_ok());
        assert!(SanitizedMessage::new("line one\nline two").is_err());
        assert!(SanitizedMessage::new("x".repeat(513)).is_err());
    }

    #[test]
    fn issue_uses_safe_message_wire_name() {
        let issue = InspectionIssue {
            phase: InspectionPhase::Initial,
            code: IssueCode::RequiredAnalyzerTimeout,
            analyzer_id: Some(AnalyzerId::new("semantic-review").unwrap()),
            subject_id: None,
            artifact_id: None,
            message: SanitizedMessage::new("Analyzer exceeded its wall-time budget").unwrap(),
        };

        let value = serde_json::to_value(issue).unwrap();
        assert_eq!(value["code"], "required_analyzer_timeout");
        assert_eq!(value["analyzer_id"], "semantic-review");
        assert_eq!(
            value["safe_message"],
            "Analyzer exceeded its wall-time budget"
        );
        assert!(value.get("message").is_none());
    }
}
