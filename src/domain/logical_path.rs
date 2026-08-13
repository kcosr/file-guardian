use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, ffi::OsStr, fmt};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PathSegment {
    bytes: Vec<u8>,
}

impl PathSegment {
    pub fn utf8(value: impl Into<String>) -> Result<Self, LogicalPathError> {
        let value = value.into();
        validate_segment_bytes(value.as_bytes())?;
        Ok(Self {
            bytes: value.into_bytes(),
        })
    }

    pub fn from_bytes(value: impl AsRef<[u8]>) -> Result<Self, LogicalPathError> {
        let value = value.as_ref();
        validate_segment_bytes(value)?;
        Ok(Self {
            bytes: value.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, LogicalPathError> {
        Ok(self.bytes.clone())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Serialize for PathSegment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct WireSegment<'a> {
            encoding: &'static str,
            value: &'a str,
        }

        if let Ok(value) = std::str::from_utf8(&self.bytes) {
            WireSegment {
                encoding: "utf8",
                value,
            }
            .serialize(serializer)
        } else {
            #[derive(Serialize)]
            struct OwnedWireSegment {
                encoding: &'static str,
                value: String,
            }
            OwnedWireSegment {
                encoding: "base64url",
                value: URL_SAFE_NO_PAD.encode(&self.bytes),
            }
            .serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PathSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireSegment {
            encoding: String,
            value: String,
        }

        let wire = WireSegment::deserialize(deserializer)?;
        match wire.encoding.as_str() {
            "utf8" => Self::utf8(wire.value).map_err(serde::de::Error::custom),
            "base64url" => {
                let decoded = URL_SAFE_NO_PAD
                    .decode(&wire.value)
                    .map_err(|_| serde::de::Error::custom(LogicalPathError::InvalidBase64url))?;
                if std::str::from_utf8(&decoded).is_ok()
                    || URL_SAFE_NO_PAD.encode(&decoded) != wire.value
                {
                    return Err(serde::de::Error::custom(
                        LogicalPathError::NonCanonicalEncoding,
                    ));
                }
                Self::from_bytes(decoded).map_err(serde::de::Error::custom)
            }
            _ => Err(serde::de::Error::unknown_variant(
                &wire.encoding,
                &["utf8", "base64url"],
            )),
        }
    }
}

impl Ord for PathSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        // Constructors and LogicalPath deserialization guarantee validity.
        self.bytes.cmp(&other.bytes)
    }
}

impl PartialOrd for PathSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LogicalPath {
    segments: Vec<PathSegment>,
}

impl LogicalPath {
    pub fn new(segments: Vec<PathSegment>) -> Result<Self, LogicalPathError> {
        if segments.is_empty() {
            return Err(LogicalPathError::EmptyPath);
        }
        for segment in &segments {
            segment.as_bytes()?;
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    pub fn byte_segments(&self) -> Result<Vec<Vec<u8>>, LogicalPathError> {
        self.segments.iter().map(PathSegment::as_bytes).collect()
    }
}

impl<'de> Deserialize<'de> for LogicalPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WirePath {
            segments: Vec<PathSegment>,
        }

        let wire = WirePath::deserialize(deserializer)?;
        Self::new(wire.segments).map_err(serde::de::Error::custom)
    }
}

#[cfg(unix)]
impl TryFrom<&OsStr> for PathSegment {
    type Error = LogicalPathError;

    fn try_from(value: &OsStr) -> Result<Self, Self::Error> {
        use std::os::unix::ffi::OsStrExt;
        Self::from_bytes(value.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LogicalPathError {
    #[error("logical path must contain at least one segment")]
    EmptyPath,
    #[error("logical path segment must not be empty")]
    EmptySegment,
    #[error("logical path segment must not be '.' or '..'")]
    TraversalSegment,
    #[error("logical path segment must not contain '/' or NUL")]
    InvalidByte,
    #[error("base64url path segment is invalid")]
    InvalidBase64url,
    #[error("path segment does not use its canonical encoding")]
    NonCanonicalEncoding,
}

fn validate_segment_bytes(value: &[u8]) -> Result<(), LogicalPathError> {
    if value.is_empty() {
        return Err(LogicalPathError::EmptySegment);
    }
    if value == b"." || value == b".." {
        return Err(LogicalPathError::TraversalSegment);
    }
    if value.contains(&b'/') || value.contains(&0) {
        return Err(LogicalPathError::InvalidByte);
    }
    Ok(())
}

impl fmt::Display for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, segment) in self.segments.iter().enumerate() {
            if index != 0 {
                formatter.write_str("/")?;
            }
            match std::str::from_utf8(segment.as_slice()) {
                Ok(value) => formatter.write_str(value)?,
                Err(_) => write!(
                    formatter,
                    "<base64url:{}>",
                    URL_SAFE_NO_PAD.encode(segment.as_slice())
                )?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_is_structured_and_round_trips_non_utf8() {
        let path = LogicalPath::new(vec![
            PathSegment::utf8("packages").unwrap(),
            PathSegment::from_bytes([0xff, b'a']).unwrap(),
        ])
        .unwrap();
        let json = serde_json::to_value(&path).unwrap();
        assert_eq!(json["segments"][0]["encoding"], "utf8");
        assert_eq!(json["segments"][1]["encoding"], "base64url");
        assert_eq!(serde_json::from_value::<LogicalPath>(json).unwrap(), path);
    }

    #[test]
    fn rejects_unsafe_and_noncanonical_segments() {
        assert!(PathSegment::utf8("..").is_err());
        assert!(PathSegment::utf8("a/b").is_err());
        let utf8_as_base64 = serde_json::json!({
            "segments": [{"encoding": "base64url", "value": "YWJj"}]
        });
        assert!(serde_json::from_value::<LogicalPath>(utf8_as_base64).is_err());
    }

    #[test]
    fn ordering_uses_original_path_bytes() {
        let a = LogicalPath::new(vec![PathSegment::utf8("a").unwrap()]).unwrap();
        let non_utf8 = LogicalPath::new(vec![PathSegment::from_bytes([0xff]).unwrap()]).unwrap();
        assert!(a < non_utf8);
    }
}
