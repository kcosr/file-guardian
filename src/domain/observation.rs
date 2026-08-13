use super::{ArtifactId, ObservationId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

macro_rules! semantic_identifier {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

semantic_identifier!(AnalyzerId, "analyzer id");
semantic_identifier!(RuleId, "rule id");
semantic_identifier!(ClassificationCode, "classification code");
semantic_identifier!(ReasonCode, "reason code");

fn validate_identifier(value: &str, label: &'static str) -> Result<(), IdentifierError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
    {
        return Err(IdentifierError { label });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{label} must contain 1 to 128 safe identifier characters")]
pub struct IdentifierError {
    label: &'static str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Secret,
    Credential,
    SensitiveContent,
    KnownSensitiveFile,
    Filename,
    ContentPattern,
    PolicyViolation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidatedLocation {
    ByteRange { start: u64, end_exclusive: u64 },
    Line { line: u64 },
    LineColumn { line: u64, column: u64 },
}

impl ValidatedLocation {
    pub fn byte_range(start: u64, end_exclusive: u64) -> Result<Self, ValidatedLocationError> {
        if start >= end_exclusive {
            return Err(ValidatedLocationError::EmptyByteRange);
        }
        Ok(Self::ByteRange {
            start,
            end_exclusive,
        })
    }

    pub fn line(line: u64) -> Result<Self, ValidatedLocationError> {
        if line == 0 {
            return Err(ValidatedLocationError::OneBased);
        }
        Ok(Self::Line { line })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidatedLocationError {
    #[error("byte range must be non-empty")]
    EmptyByteRange,
    #[error("line and column locations are one-based")]
    OneBased,
}

/// Evidence safe for reports: reason codes only, never matched bytes or snippets.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SafeEvidence {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<ReasonCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Finding {
    pub id: ObservationId,
    pub analyzer_id: AnalyzerId,
    pub rule_id: RuleId,
    pub artifact_id: ArtifactId,
    pub category: FindingCategory,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ValidatedLocation>,
    #[serde(default)]
    pub evidence: SafeEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationScope {
    Tree,
    Artifact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Classification {
    pub id: ObservationId,
    pub analyzer_id: AnalyzerId,
    pub code: ClassificationCode,
    pub scope: ClassificationScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_artifacts: Vec<ArtifactId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfiguredConfidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<ReasonCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedObservation {
    Finding(Finding),
    Classification(Classification),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_json_has_no_content_or_action_field() {
        let finding = Finding {
            id: ObservationId::from_suffix("1").unwrap(),
            analyzer_id: AnalyzerId::new("builtin").unwrap(),
            rule_id: RuleId::new("secret.password").unwrap(),
            artifact_id: ArtifactId::from_suffix("1").unwrap(),
            category: FindingCategory::Credential,
            severity: Severity::High,
            location: Some(ValidatedLocation::byte_range(2, 8).unwrap()),
            evidence: SafeEvidence {
                reason_codes: vec![ReasonCode::new("password_pattern").unwrap()],
            },
        };
        let json = serde_json::to_value(finding).unwrap();
        assert!(json.get("content").is_none());
        assert!(json.get("action").is_none());
        assert_eq!(json["evidence"]["reason_codes"][0], "password_pattern");
    }

    #[test]
    fn semantic_identifiers_reject_prose_and_controls() {
        assert!(RuleId::new("publication/restricted").is_ok());
        assert!(RuleId::new("contains secret\nvalue").is_err());
    }
}
