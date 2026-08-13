use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpaqueIdError {
    #[error("{kind} must start with {prefix}")]
    Prefix {
        kind: &'static str,
        prefix: &'static str,
    },
    #[error("opaque identifier suffix must contain 1 to 96 ASCII letters, digits, '_' or '-'")]
    InvalidSuffix,
}

macro_rules! opaque_id {
    ($name:ident, $prefix:literal, $kind:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, OpaqueIdError> {
                let value = value.into();
                validate(&value, $prefix, $kind)?;
                Ok(Self(value))
            }

            pub fn from_suffix(suffix: impl AsRef<str>) -> Result<Self, OpaqueIdError> {
                Self::new(format!("{}{}", $prefix, suffix.as_ref()))
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

        impl FromStr for $name {
            type Err = OpaqueIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
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
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn validate(value: &str, prefix: &'static str, kind: &'static str) -> Result<(), OpaqueIdError> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or(OpaqueIdError::Prefix { kind, prefix })?;
    if suffix.is_empty()
        || suffix.len() > 96
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(OpaqueIdError::InvalidSuffix);
    }
    Ok(())
}

opaque_id!(RunId, "run_", "run identifier");
opaque_id!(SubjectId, "subject_", "subject identifier");
opaque_id!(ArtifactId, "a_", "artifact identifier");
opaque_id!(ObjectId, "obj_", "object identifier");
opaque_id!(CandidateId, "c_", "candidate identifier");
opaque_id!(ObservationId, "obs_", "observation identifier");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_ids_are_typed_and_strict() {
        let id = ArtifactId::from_suffix("0001-a").unwrap();
        assert_eq!(id.as_str(), "a_0001-a");
        assert!(ArtifactId::new("../object").is_err());
        assert!(ArtifactId::new("a_with/slash").is_err());
        assert!(ArtifactId::new("subject_0001").is_err());
    }

    #[test]
    fn deserialization_applies_validation() {
        assert!(serde_json::from_str::<RunId>("\"run_ok\"").is_ok());
        assert!(serde_json::from_str::<RunId>("\"run_../bad\"").is_err());
    }
}
