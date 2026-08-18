use super::protocol::{
    NormalizedScannerOccurrence, ScannerAssignment, ScannerCompletion, ScannerKind,
    ScannerProtocolError,
};
use super::runner::{NativeExit, ScannerRunOutput};
use crate::domain::{
    AnalyzerId, ArtifactId, CandidateId, FindingCategory, InspectionPhase, ObservationId, RuleId,
    Severity, ValidatedLocation,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScannerVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl fmt::Display for ScannerVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Serialize for ScannerVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl ScannerVersion {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScannerVersionRequirement {
    pub minimum_inclusive: ScannerVersion,
    pub maximum_exclusive: ScannerVersion,
}

impl ScannerVersionRequirement {
    pub const fn new(minimum_inclusive: ScannerVersion, maximum_exclusive: ScannerVersion) -> Self {
        Self {
            minimum_inclusive,
            maximum_exclusive,
        }
    }

    pub fn accepts(self, version: ScannerVersion) -> bool {
        self.minimum_inclusive <= version && version < self.maximum_exclusive
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScannerCapability {
    WorkingTree,
    MaterializedGitHistory,
}

#[derive(Clone, Copy, Debug)]
pub struct ScannerAdapterContext<'a> {
    pub analyzer_id: &'a AnalyzerId,
    pub phase: InspectionPhase,
    pub assignments: &'a [ScannerAssignment],
    pub max_file_bytes: u64,
    pub max_findings: u64,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScannerAdapterError {
    #[error("native scanner kind does not match the selected first-party adapter")]
    ScannerKind,
    #[error("native scanner version output is invalid")]
    VersionOutput,
    #[error("native scanner version requirement exceeds the reviewed adapter range")]
    VersionRequirement,
    #[error("native scanner version is unsupported")]
    UnsupportedVersion,
    #[error("native scanner process did not exit normally")]
    AbnormalExit,
    #[error("native scanner output is malformed")]
    MalformedOutput,
    #[error("native scanner output disagrees with its exit status")]
    ExitOutputMismatch,
    #[error("native scanner finding uses an invalid or unknown input path")]
    FindingPath,
    #[error("native scanner emitted Git metadata for a working-tree invocation")]
    UnexpectedGitMetadata,
    #[error("native scanner finding uses an invalid rule identifier")]
    RuleIdentifier,
    #[error("native scanner finding location is invalid")]
    Location,
    #[error("native scanner emitted too many findings")]
    FindingLimit,
    #[error("host-owned scanner completion is invalid")]
    Completion,
}

impl From<ScannerProtocolError> for ScannerAdapterError {
    fn from(_: ScannerProtocolError) -> Self {
        Self::Completion
    }
}

pub trait FirstPartyScannerAdapter {
    fn kind(&self) -> ScannerKind;

    fn capabilities(&self) -> &'static [ScannerCapability] {
        &[
            ScannerCapability::WorkingTree,
            ScannerCapability::MaterializedGitHistory,
        ]
    }

    fn parse_version(&self, output: &[u8]) -> Result<ScannerVersion, ScannerAdapterError>;

    fn normalize(
        &self,
        context: ScannerAdapterContext<'_>,
        output: &ScannerRunOutput,
    ) -> Result<ScannerCompletion, ScannerAdapterError>;
}

pub(super) fn require_kind(
    expected: ScannerKind,
    output: &ScannerRunOutput,
) -> Result<(), ScannerAdapterError> {
    if output.kind != expected {
        return Err(ScannerAdapterError::ScannerKind);
    }
    Ok(())
}

pub(super) fn normal_exit(exit: NativeExit) -> Result<i32, ScannerAdapterError> {
    match exit {
        NativeExit {
            code: Some(code),
            signal: None,
        } => Ok(code),
        _ => Err(ScannerAdapterError::AbnormalExit),
    }
}

pub(super) fn parse_semver_line(
    output: &[u8],
    optional_product: &str,
) -> Result<ScannerVersion, ScannerAdapterError> {
    if output.is_empty() || output.len() > 128 || !output.is_ascii() {
        return Err(ScannerAdapterError::VersionOutput);
    }
    let output = std::str::from_utf8(output).map_err(|_| ScannerAdapterError::VersionOutput)?;
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    if line.is_empty() || line.chars().any(char::is_control) {
        return Err(ScannerAdapterError::VersionOutput);
    }
    let value = if let Some(product_version) = line.strip_prefix(optional_product) {
        product_version
            .strip_prefix(' ')
            .ok_or(ScannerAdapterError::VersionOutput)?
    } else {
        line
    };
    let value = value.strip_prefix('v').unwrap_or(value);
    let (core, suffix) = value.find(['-', '+']).map_or((value, None), |index| {
        (&value[..index], Some(&value[index..]))
    });
    if suffix.is_some_and(|suffix| {
        suffix.len() < 2
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    }) {
        return Err(ScannerAdapterError::VersionOutput);
    }
    let mut parts = core.split('.');
    let major = parse_version_number(parts.next())?;
    let minor = parse_version_number(parts.next())?;
    let patch = parse_version_number(parts.next())?;
    if parts.next().is_some() {
        return Err(ScannerAdapterError::VersionOutput);
    }
    Ok(ScannerVersion::new(major, minor, patch))
}

fn parse_version_number(value: Option<&str>) -> Result<u64, ScannerAdapterError> {
    let value = value.ok_or(ScannerAdapterError::VersionOutput)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ScannerAdapterError::VersionOutput);
    }
    value
        .parse()
        .map_err(|_| ScannerAdapterError::VersionOutput)
}

pub(super) struct AssignmentIndex<'a> {
    by_path: BTreeMap<&'a str, &'a ScannerAssignment>,
}

impl<'a> AssignmentIndex<'a> {
    pub fn new(assignments: &'a [ScannerAssignment]) -> Result<Self, ScannerAdapterError> {
        let mut by_path = BTreeMap::new();
        for assignment in assignments {
            let path = canonical_assignment_path(&assignment.view_path)?;
            if by_path.insert(path, assignment).is_some() {
                return Err(ScannerAdapterError::FindingPath);
            }
        }
        Ok(Self { by_path })
    }

    pub fn assignment_for_native_path(
        &self,
        native_path: &str,
    ) -> Result<MappedAssignment, ScannerAdapterError> {
        if native_path.is_empty() || native_path.chars().any(char::is_control) {
            return Err(ScannerAdapterError::FindingPath);
        }
        let path = if let Some(path) = native_path.strip_prefix("/input/") {
            path
        } else if native_path == "/input" || native_path.starts_with('/') {
            return Err(ScannerAdapterError::FindingPath);
        } else {
            native_path.strip_prefix("./").unwrap_or(native_path)
        };
        let path = canonical_assignment_path(path)?;
        self.by_path
            .get(path)
            .map(|assignment| MappedAssignment {
                candidate_id: assignment.candidate_id.clone(),
                artifact_id: assignment.artifact_id.clone(),
            })
            .ok_or(ScannerAdapterError::FindingPath)
    }
}

pub(super) struct MappedAssignment {
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
}

fn canonical_assignment_path(path: &str) -> Result<&str, ScannerAdapterError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ScannerAdapterError::FindingPath);
    }
    Ok(path)
}

pub(super) struct ParsedOccurrence {
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
    pub rule_id: RuleId,
    pub category: FindingCategory,
    pub severity: Severity,
    pub location: Option<ValidatedLocation>,
}

pub(super) fn rule_id(scanner: ScannerKind, native: &str) -> Result<RuleId, ScannerAdapterError> {
    if native.is_empty() || native.len() > 96 || !native.is_ascii() {
        return Err(ScannerAdapterError::RuleIdentifier);
    }
    let mut component = String::with_capacity(native.len());
    let mut separator = false;
    for byte in native.bytes() {
        let normalized = match byte {
            b'A'..=b'Z' => byte.to_ascii_lowercase() as char,
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => byte as char,
            b' ' => {
                if separator || component.is_empty() {
                    continue;
                }
                '-'
            }
            _ => return Err(ScannerAdapterError::RuleIdentifier),
        };
        component.push(normalized);
        separator = normalized == '-';
    }
    while component.ends_with('-') {
        component.pop();
    }
    if component.is_empty() {
        return Err(ScannerAdapterError::RuleIdentifier);
    }
    let digest = Sha256::digest(native.as_bytes());
    let native_key = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    RuleId::new(format!(
        "{}/{}-{native_key}",
        scanner.executable_name(),
        component
    ))
    .map_err(|_| ScannerAdapterError::RuleIdentifier)
}

pub(super) fn line_location(
    line: u64,
    column: u64,
) -> Result<Option<ValidatedLocation>, ScannerAdapterError> {
    match (line, column) {
        (0, 0) => Ok(None),
        (0, _) => Err(ScannerAdapterError::Location),
        (line, 0) => ValidatedLocation::line(line)
            .map(Some)
            .map_err(|_| ScannerAdapterError::Location),
        (line, column) => ValidatedLocation::line_column(line, column)
            .map(Some)
            .map_err(|_| ScannerAdapterError::Location),
    }
}

pub(super) fn complete(
    kind: ScannerKind,
    context: ScannerAdapterContext<'_>,
    mut parsed: Vec<ParsedOccurrence>,
) -> Result<ScannerCompletion, ScannerAdapterError> {
    let max_findings = usize::try_from(context.max_findings).unwrap_or(usize::MAX);
    if parsed.len() > max_findings {
        return Err(ScannerAdapterError::FindingLimit);
    }
    parsed.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.candidate_id.cmp(&right.candidate_id))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.location.cmp(&right.location))
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.severity.cmp(&right.severity))
    });
    parsed.dedup_by(|left, right| {
        left.artifact_id == right.artifact_id
            && left.candidate_id == right.candidate_id
            && left.rule_id == right.rule_id
            && left.location == right.location
            && left.category == right.category
            && left.severity == right.severity
    });
    let phase = match context.phase {
        InspectionPhase::Initial => "initial",
        InspectionPhase::Verification => "verification",
    };
    let occurrences = parsed
        .into_iter()
        .map(|occurrence| {
            let occurrence_key = occurrence_key(kind, context, &occurrence);
            let occurrence_id = ObservationId::from_suffix(format!(
                "ext-{}-{phase}-{occurrence_key}",
                kind.executable_name(),
            ))
            .map_err(|_| ScannerAdapterError::Completion)?;
            Ok(NormalizedScannerOccurrence {
                occurrence_id,
                candidate_id: occurrence.candidate_id,
                artifact_id: occurrence.artifact_id,
                rule_id: occurrence.rule_id,
                category: occurrence.category,
                severity: occurrence.severity,
                location: occurrence.location,
            })
        })
        .collect::<Result<Vec<_>, ScannerAdapterError>>()?;
    ScannerCompletion::whole_view(
        kind,
        context.analyzer_id.clone(),
        context.phase,
        context.assignments,
        occurrences,
        context.max_file_bytes,
        context.max_findings,
    )
    .map_err(Into::into)
}

fn occurrence_key(
    kind: ScannerKind,
    context: ScannerAdapterContext<'_>,
    occurrence: &ParsedOccurrence,
) -> String {
    let mut digest = Sha256::new();
    hash_component(&mut digest, kind.executable_name().as_bytes());
    hash_component(&mut digest, context.analyzer_id.as_str().as_bytes());
    hash_component(&mut digest, &[context.phase as u8]);
    hash_component(&mut digest, occurrence.candidate_id.as_str().as_bytes());
    hash_component(&mut digest, occurrence.artifact_id.as_str().as_bytes());
    hash_component(&mut digest, occurrence.rule_id.as_str().as_bytes());
    hash_component(&mut digest, &[occurrence.category as u8]);
    hash_component(&mut digest, &[occurrence.severity as u8]);
    match &occurrence.location {
        None => hash_component(&mut digest, &[0]),
        Some(ValidatedLocation::ByteRange {
            start,
            end_exclusive,
        }) => {
            hash_component(&mut digest, &[1]);
            hash_component(&mut digest, &start.to_be_bytes());
            hash_component(&mut digest, &end_exclusive.to_be_bytes());
        }
        Some(ValidatedLocation::Line { line }) => {
            hash_component(&mut digest, &[2]);
            hash_component(&mut digest, &line.to_be_bytes());
        }
        Some(ValidatedLocation::LineColumn { line, column }) => {
            hash_component(&mut digest, &[3]);
            hash_component(&mut digest, &line.to_be_bytes());
            hash_component(&mut digest, &column.to_be_bytes());
        }
    }
    digest.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_component(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
