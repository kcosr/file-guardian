use super::adapter::{
    complete, line_location, normal_exit, parse_semver_line, require_kind, rule_id,
    AssignmentIndex, FirstPartyScannerAdapter, ParsedOccurrence, ScannerAdapterContext,
    ScannerAdapterError, ScannerCapability, ScannerVersion, ScannerVersionRequirement,
};
use super::protocol::{ScannerCompletion, ScannerKind};
use super::runner::{NativeExit, ScannerRunOutput};
use crate::domain::{FindingCategory, Severity};
use serde::Deserialize;

pub const TRUFFLEHOG_FINDINGS_EXIT: i32 = 183;
pub const TRUFFLEHOG_VERSION_REQUIREMENT: ScannerVersionRequirement =
    ScannerVersionRequirement::new(ScannerVersion::new(3, 90, 0), ScannerVersion::new(4, 0, 0));

#[derive(Clone, Copy, Debug)]
pub struct TrufflehogAdapter {
    version_requirement: ScannerVersionRequirement,
}

impl Default for TrufflehogAdapter {
    fn default() -> Self {
        Self {
            version_requirement: TRUFFLEHOG_VERSION_REQUIREMENT,
        }
    }
}

impl TrufflehogAdapter {
    pub fn with_version_requirement(
        version_requirement: ScannerVersionRequirement,
    ) -> Result<Self, ScannerAdapterError> {
        if version_requirement.minimum_inclusive < TRUFFLEHOG_VERSION_REQUIREMENT.minimum_inclusive
            || version_requirement.maximum_exclusive
                > TRUFFLEHOG_VERSION_REQUIREMENT.maximum_exclusive
            || version_requirement.minimum_inclusive >= version_requirement.maximum_exclusive
        {
            return Err(ScannerAdapterError::VersionRequirement);
        }
        Ok(Self {
            version_requirement,
        })
    }

    pub fn validate_version_output(
        &self,
        output: &[u8],
    ) -> Result<ScannerVersion, ScannerAdapterError> {
        let version = parse_semver_line(output, "trufflehog")?;
        if !self.version_requirement.accepts(version) {
            return Err(ScannerAdapterError::UnsupportedVersion);
        }
        Ok(version)
    }

    pub fn normalize_bytes(
        &self,
        context: ScannerAdapterContext<'_>,
        exit: NativeExit,
        stdout: &[u8],
    ) -> Result<ScannerCompletion, ScannerAdapterError> {
        let code = normal_exit(exit)?;
        if !matches!(code, 0 | TRUFFLEHOG_FINDINGS_EXIT) {
            return Err(ScannerAdapterError::AbnormalExit);
        }
        let max_findings = usize::try_from(context.max_findings).unwrap_or(usize::MAX);
        let assignments = AssignmentIndex::new(context.assignments)?;
        let mut parsed = Vec::new();
        if !stdout.is_empty() {
            for line in stdout.split(|byte| *byte == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                if parsed.len() == max_findings {
                    return Err(ScannerAdapterError::FindingLimit);
                }
                let finding: NativeFinding = serde_json::from_slice(line)
                    .map_err(|_| ScannerAdapterError::MalformedOutput)?;
                if !finding.verification_error.is_empty() {
                    return Err(ScannerAdapterError::MalformedOutput);
                }
                let source = finding
                    .source_metadata
                    .data
                    .filesystem
                    .ok_or(ScannerAdapterError::UnexpectedGitMetadata)?;
                if finding.source_metadata.data.git.is_some() {
                    return Err(ScannerAdapterError::UnexpectedGitMetadata);
                }
                let line = u64::try_from(source.line).map_err(|_| ScannerAdapterError::Location)?;
                let assignment = assignments.assignment_for_native_path(&source.file)?;
                let normalized_rule = rule_id(ScannerKind::Trufflehog, &finding.detector_name)?;
                parsed.push(ParsedOccurrence {
                    candidate_id: assignment.candidate_id,
                    artifact_id: assignment.artifact_id,
                    rule_id: normalized_rule,
                    category: FindingCategory::Credential,
                    severity: if finding.verified {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    location: line_location(line, 0)?,
                });
            }
        }
        let has_findings = !parsed.is_empty();
        if (code == TRUFFLEHOG_FINDINGS_EXIT) != has_findings {
            return Err(ScannerAdapterError::ExitOutputMismatch);
        }
        complete(ScannerKind::Trufflehog, context, parsed)
    }
}

impl FirstPartyScannerAdapter for TrufflehogAdapter {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Trufflehog
    }

    fn capabilities(&self) -> &'static [ScannerCapability] {
        &[
            ScannerCapability::WorkingTree,
            ScannerCapability::MaterializedGitHistory,
        ]
    }

    fn parse_version(&self, output: &[u8]) -> Result<ScannerVersion, ScannerAdapterError> {
        self.validate_version_output(output)
    }

    fn normalize(
        &self,
        context: ScannerAdapterContext<'_>,
        output: &ScannerRunOutput,
    ) -> Result<ScannerCompletion, ScannerAdapterError> {
        require_kind(ScannerKind::Trufflehog, output)?;
        if !self.version_requirement.accepts(output.version) {
            return Err(ScannerAdapterError::UnsupportedVersion);
        }
        self.normalize_bytes(context, output.exit, output.stdout())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NativeFinding {
    source_metadata: NativeSourceMetadata,
    detector_name: String,
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    verification_error: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NativeSourceMetadata {
    data: NativeSourceData,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NativeSourceData {
    #[serde(default)]
    filesystem: Option<NativeFilesystem>,
    #[serde(default)]
    git: Option<NativeGit>,
}

#[derive(Deserialize)]
struct NativeFilesystem {
    file: String,
    #[serde(default)]
    line: i64,
}

#[derive(Deserialize)]
struct NativeGit {}
