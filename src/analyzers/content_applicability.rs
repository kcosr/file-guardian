use std::fmt;
use std::io::Read;

use globset::{Candidate, GlobBuilder, GlobSet, GlobSetBuilder};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::domain::{Artifact, Digest, LogicalPath, ObjectId, Provenance};

/// Opens captured immutable objects by identifier. Implementations must never
/// resolve paths in the live input tree.
pub trait ArtifactReader {
    fn open_object(&self, object_id: &ObjectId) -> Result<Box<dyn Read + '_>, ArtifactReadError>;
}

impl ArtifactReader for crate::authorization::ObjectStore {
    fn open_object(&self, object_id: &ObjectId) -> Result<Box<dyn Read + '_>, ArtifactReadError> {
        self.open(object_id)
            .map(|file| Box::new(file) as Box<dyn Read>)
            .map_err(|_| ArtifactReadError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ArtifactReadError {
    #[error("immutable object is unavailable")]
    Unavailable,
    #[error("immutable object could not be read")]
    ReadFailed,
}

/// A compiled byte-preserving path policy for artifacts that must be text.
///
/// Globs have literal separators and match the same canonical raw logical path
/// bytes used by analyzer eligibility. An empty matcher means no path is
/// required to contain UTF-8 text.
#[derive(Clone, Debug)]
pub struct RequiredTextMatcher {
    patterns: GlobSet,
}

impl RequiredTextMatcher {
    pub fn compile(patterns: &[String]) -> Result<Self, RequiredTextMatcherError> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let glob = GlobBuilder::new(pattern)
                .literal_separator(true)
                .backslash_escape(true)
                .build()
                .map_err(|source| RequiredTextMatcherError::InvalidGlob {
                    pattern: pattern.clone(),
                    source,
                })?;
            builder.add(glob);
        }
        let patterns = builder.build().map_err(RequiredTextMatcherError::Build)?;
        Ok(Self { patterns })
    }

    pub fn is_required(&self, artifact: &Artifact) -> bool {
        self.is_required_path(logical_path(artifact))
    }

    pub(crate) fn is_required_path(&self, logical_path: &LogicalPath) -> bool {
        self.patterns
            .is_match_candidate(&Candidate::from_bytes(&logical_path_bytes(logical_path)))
    }
}

impl Default for RequiredTextMatcher {
    fn default() -> Self {
        Self::compile(&[]).expect("an empty required-text matcher is valid")
    }
}

#[derive(Debug, Error)]
pub enum RequiredTextMatcherError {
    #[error("invalid required-text glob '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("required-text matcher could not be built: {0}")]
    Build(#[source] globset::Error),
}

/// Verified UTF-8 content. Debug output intentionally omits the content.
#[derive(Clone, Eq, PartialEq)]
pub struct TextContent(String);

impl TextContent {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for TextContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TextContent")
            .field("byte_len", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TextArtifactDisposition {
    Text(TextContent),
    NotApplicableBinary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum TextApplicabilityError {
    #[error("immutable object is unavailable")]
    ObjectUnavailable,
    #[error("immutable object could not be read")]
    ObjectReadFailed,
    #[error("immutable object does not match its manifest identity")]
    ObjectIdentityMismatch,
    #[error("an artifact required to be text was classified as binary content")]
    RequiredTextBinaryContent,
    #[error("valid UTF-8 text exceeds the content inspection limit")]
    TextLimitExceeded,
}

/// Verifies and classifies one frozen assignment after eligibility selection.
///
/// Every byte is streamed through SHA-256 and conservative UTF-8 text
/// classification before a result is returned. Invalid UTF-8, NUL, and control
/// characters other than tab, line feed, form feed, and carriage return are
/// ordinary binary unless the artifact's path is covered by `required_text`.
/// Valid oversized text is an inspection error; a large binary remains
/// explicitly not applicable.
pub fn assess_text_artifact(
    artifact: &Artifact,
    reader: &impl ArtifactReader,
    max_text_bytes: u64,
    required_text: &RequiredTextMatcher,
) -> Result<TextArtifactDisposition, TextApplicabilityError> {
    let input = reader
        .open_object(&artifact.object_id)
        .map_err(|error| match error {
            ArtifactReadError::Unavailable => TextApplicabilityError::ObjectUnavailable,
            ArtifactReadError::ReadFailed => TextApplicabilityError::ObjectReadFailed,
        })?;
    assess_text_reader(
        logical_path(artifact),
        artifact.byte_len,
        artifact.content_digest,
        input,
        max_text_bytes,
        required_text,
    )
}

pub(crate) fn assess_text_reader(
    logical_path: &LogicalPath,
    expected_byte_len: u64,
    expected_digest: Digest,
    mut input: Box<dyn Read + '_>,
    max_text_bytes: u64,
    required_text: &RequiredTextMatcher,
) -> Result<TextArtifactDisposition, TextApplicabilityError> {
    let mut retained = (expected_byte_len <= max_text_bytes).then(Vec::new);
    let mut hasher = Sha256::new();
    let mut byte_len = 0_u64;
    let mut utf8 = StreamingUtf8::default();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| TextApplicabilityError::ObjectReadFailed)?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        let read_u64 =
            u64::try_from(read).map_err(|_| TextApplicabilityError::ObjectIdentityMismatch)?;
        byte_len = byte_len
            .checked_add(read_u64)
            .ok_or(TextApplicabilityError::ObjectIdentityMismatch)?;
        hasher.update(bytes);
        utf8.feed(bytes);
        if retained.as_ref().is_some_and(|retained| {
            u64::try_from(retained.len())
                .ok()
                .and_then(|length| length.checked_add(read_u64))
                .is_some_and(|length| length <= max_text_bytes)
        }) {
            retained
                .as_mut()
                .expect("retention was just confirmed")
                .extend_from_slice(bytes);
        } else {
            retained = None;
        }
    }

    let digest = Digest::from_array(hasher.finalize().into());
    if byte_len != expected_byte_len || digest != expected_digest {
        return Err(TextApplicabilityError::ObjectIdentityMismatch);
    }

    if !utf8.is_text() {
        return if required_text.is_required_path(logical_path) {
            Err(TextApplicabilityError::RequiredTextBinaryContent)
        } else {
            Ok(TextArtifactDisposition::NotApplicableBinary)
        };
    }
    let retained = retained.ok_or(TextApplicabilityError::TextLimitExceeded)?;
    let text = String::from_utf8(retained)
        .expect("the streaming validator accepted exactly the retained immutable bytes");
    Ok(TextArtifactDisposition::Text(TextContent(text)))
}

#[derive(Default)]
struct StreamingUtf8 {
    incomplete: Vec<u8>,
    invalid: bool,
    contains_binary_control: bool,
}

impl StreamingUtf8 {
    fn feed(&mut self, bytes: &[u8]) {
        if self.invalid {
            return;
        }
        let mut candidate = std::mem::take(&mut self.incomplete);
        candidate.extend_from_slice(bytes);
        match std::str::from_utf8(&candidate) {
            Ok(text) => self.inspect_controls(text),
            Err(error) if error.error_len().is_some() => self.invalid = true,
            Err(error) => {
                let valid = std::str::from_utf8(&candidate[..error.valid_up_to()])
                    .expect("the UTF-8 validator identifies a valid prefix");
                self.inspect_controls(valid);
                self.incomplete
                    .extend_from_slice(&candidate[error.valid_up_to()..]);
            }
        }
    }

    fn inspect_controls(&mut self, text: &str) {
        self.contains_binary_control |= text
            .chars()
            .any(|character| character.is_control() && !is_permitted_text_control(character));
    }

    fn is_text(&self) -> bool {
        !self.invalid && !self.contains_binary_control && self.incomplete.is_empty()
    }
}

fn is_permitted_text_control(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\u{000c}' | '\r')
}

fn logical_path(artifact: &Artifact) -> &LogicalPath {
    match &artifact.provenance {
        Provenance::Physical { logical_path } => logical_path,
        Provenance::Derived { member_path, .. } => member_path,
    }
}

fn logical_path_bytes(path: &LogicalPath) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, segment) in path.segments().iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(segment.as_slice());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::domain::{ArtifactId, ArtifactKind, LogicalPath, ObjectId, PathSegment, SubjectId};

    struct MemoryReader(Vec<u8>);

    impl ArtifactReader for MemoryReader {
        fn open_object(
            &self,
            _object_id: &ObjectId,
        ) -> Result<Box<dyn Read + '_>, ArtifactReadError> {
            Ok(Box::new(Cursor::new(self.0.as_slice())))
        }
    }

    fn artifact(path: &str, bytes: &[u8]) -> Artifact {
        Artifact {
            id: ArtifactId::from_suffix("0001").unwrap(),
            subject_id: SubjectId::from_suffix("0001").unwrap(),
            object_id: ObjectId::from_suffix("0001").unwrap(),
            kind: ArtifactKind::PhysicalFile,
            byte_len: bytes.len() as u64,
            content_digest: Digest::sha256(bytes),
            provenance: Provenance::Physical {
                logical_path: LogicalPath::new(
                    path.split('/')
                        .map(|segment| PathSegment::utf8(segment).unwrap())
                        .collect(),
                )
                .unwrap(),
            },
        }
    }

    #[test]
    fn valid_utf8_is_text_and_debug_omits_content() {
        let bytes = "sensitive café".as_bytes();
        let result = assess_text_artifact(
            &artifact("upload.txt", bytes),
            &MemoryReader(bytes.to_vec()),
            1024,
            &RequiredTextMatcher::default(),
        )
        .unwrap();
        let TextArtifactDisposition::Text(content) = result else {
            panic!("expected text")
        };
        assert_eq!(content.as_str(), "sensitive café");
        assert!(!format!("{content:?}").contains("sensitive"));
    }

    #[test]
    fn streaming_utf8_accepts_a_scalar_split_across_reads() {
        let bytes = "€".as_bytes();
        let mut validator = StreamingUtf8::default();
        validator.feed(&bytes[..1]);
        validator.feed(&bytes[1..2]);
        validator.feed(&bytes[2..]);
        assert!(validator.is_text());
    }

    #[test]
    fn nul_invalid_utf8_and_binary_controls_are_ordinary_binary() {
        for bytes in [
            b"text\0tail".as_slice(),
            &[0xff, 0xfe][..],
            &[0x01, 0x01][..],
            "\u{0085}".as_bytes(),
        ] {
            assert_eq!(
                assess_text_artifact(
                    &artifact("upload.bin", bytes),
                    &MemoryReader(bytes.to_vec()),
                    1,
                    &RequiredTextMatcher::default(),
                )
                .unwrap(),
                TextArtifactDisposition::NotApplicableBinary
            );
        }
    }

    #[test]
    fn required_text_path_turns_binary_into_an_error() {
        let matcher = RequiredTextMatcher::compile(&["**/*.rs".to_string()]).unwrap();
        for bytes in [vec![0xff], vec![0x01; 1024]] {
            assert_eq!(
                assess_text_artifact(
                    &artifact("src/main.rs", &bytes),
                    &MemoryReader(bytes.clone()),
                    3,
                    &matcher,
                ),
                Err(TextApplicabilityError::RequiredTextBinaryContent)
            );
        }
    }

    #[test]
    fn permitted_control_whitespace_and_unicode_remain_text() {
        let bytes = "first\tcolumn\nsecond\r\npage\u{000c}café €".as_bytes();
        let result = assess_text_artifact(
            &artifact("upload.txt", bytes),
            &MemoryReader(bytes.to_vec()),
            bytes.len() as u64,
            &RequiredTextMatcher::default(),
        )
        .unwrap();

        let TextArtifactDisposition::Text(content) = result else {
            panic!("expected ordinary text controls and Unicode to remain text")
        };
        assert_eq!(content.as_bytes(), bytes);
    }

    #[test]
    fn required_text_globs_match_raw_non_utf8_path_bytes() {
        let bytes = [0xff];
        let mut candidate = artifact("placeholder.rs", &bytes);
        candidate.provenance = Provenance::Physical {
            logical_path: LogicalPath::new(vec![
                PathSegment::utf8("src").unwrap(),
                PathSegment::from_bytes(vec![0xff, b'.', b'r', b's']).unwrap(),
            ])
            .unwrap(),
        };
        let matcher = RequiredTextMatcher::compile(&["**/*.rs".to_string()]).unwrap();
        assert!(matcher.is_required(&candidate));
    }

    #[test]
    fn oversized_text_errors_but_oversized_binary_is_not_applicable() {
        let text = b"four";
        assert_eq!(
            assess_text_artifact(
                &artifact("upload", text),
                &MemoryReader(text.to_vec()),
                3,
                &RequiredTextMatcher::default(),
            ),
            Err(TextApplicabilityError::TextLimitExceeded)
        );
        let binary = b"four\0";
        assert_eq!(
            assess_text_artifact(
                &artifact("upload", binary),
                &MemoryReader(binary.to_vec()),
                3,
                &RequiredTextMatcher::default(),
            )
            .unwrap(),
            TextArtifactDisposition::NotApplicableBinary
        );

        let control_heavy = vec![0x01; 1024];
        assert_eq!(
            assess_text_artifact(
                &artifact("upload.bin", &control_heavy),
                &MemoryReader(control_heavy.clone()),
                3,
                &RequiredTextMatcher::default(),
            )
            .unwrap(),
            TextArtifactDisposition::NotApplicableBinary
        );
    }

    #[test]
    fn identity_disagreement_is_never_not_applicable() {
        let expected = [0xff];
        let actual = [0xfe];
        assert_eq!(
            assess_text_artifact(
                &artifact("upload.bin", &expected),
                &MemoryReader(actual.to_vec()),
                1024,
                &RequiredTextMatcher::default(),
            ),
            Err(TextApplicabilityError::ObjectIdentityMismatch)
        );
    }
}
