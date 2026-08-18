use super::adapter::{
    complete, line_location, normal_exit, parse_semver_line, require_kind, rule_id,
    AssignmentIndex, FirstPartyScannerAdapter, ParsedOccurrence, ScannerAdapterContext,
    ScannerAdapterError, ScannerCapability, ScannerVersion, ScannerVersionRequirement,
};
use super::protocol::{ScannerCompletion, ScannerKind};
use super::runner::{NativeExit, ScannerRunOutput};
use crate::domain::{FindingCategory, Severity};
use serde::Deserialize;

pub const GITLEAKS_FINDINGS_EXIT: i32 = 42;
pub const GITLEAKS_VERSION_REQUIREMENT: ScannerVersionRequirement =
    ScannerVersionRequirement::new(ScannerVersion::new(8, 19, 0), ScannerVersion::new(9, 0, 0));

#[derive(Clone, Copy, Debug)]
pub struct GitleaksAdapter {
    version_requirement: ScannerVersionRequirement,
}

impl Default for GitleaksAdapter {
    fn default() -> Self {
        Self {
            version_requirement: GITLEAKS_VERSION_REQUIREMENT,
        }
    }
}

impl GitleaksAdapter {
    pub fn with_version_requirement(
        version_requirement: ScannerVersionRequirement,
    ) -> Result<Self, ScannerAdapterError> {
        if version_requirement.minimum_inclusive < GITLEAKS_VERSION_REQUIREMENT.minimum_inclusive
            || version_requirement.maximum_exclusive
                > GITLEAKS_VERSION_REQUIREMENT.maximum_exclusive
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
        let version = parse_semver_line(output, "gitleaks version")?;
        if !self.version_requirement.accepts(version) {
            return Err(ScannerAdapterError::UnsupportedVersion);
        }
        Ok(version)
    }

    pub fn normalize_bytes(
        &self,
        context: ScannerAdapterContext<'_>,
        exit: NativeExit,
        report: &[u8],
    ) -> Result<ScannerCompletion, ScannerAdapterError> {
        let code = normal_exit(exit)?;
        if !matches!(code, 0 | GITLEAKS_FINDINGS_EXIT) {
            return Err(ScannerAdapterError::AbnormalExit);
        }
        let findings: Vec<NativeFinding> =
            serde_json::from_slice(report).map_err(|_| ScannerAdapterError::MalformedOutput)?;
        let has_findings = !findings.is_empty();
        if (code == GITLEAKS_FINDINGS_EXIT) != has_findings {
            return Err(ScannerAdapterError::ExitOutputMismatch);
        }
        let max_findings = usize::try_from(context.max_findings).unwrap_or(usize::MAX);
        if findings.len() > max_findings {
            return Err(ScannerAdapterError::FindingLimit);
        }
        let assignments = AssignmentIndex::new(context.assignments)?;
        let mut parsed = Vec::with_capacity(findings.len());
        for finding in findings {
            if !finding.commit.is_empty() || !finding.symlink_file.is_empty() {
                return Err(ScannerAdapterError::UnexpectedGitMetadata);
            }
            if !finding.secret.is_empty() && finding.secret != "REDACTED" {
                return Err(ScannerAdapterError::MalformedOutput);
            }
            validate_extent(&finding)?;
            let assignment = assignments.assignment_for_native_path(&finding.file)?;
            let normalized_rule = rule_id(ScannerKind::Gitleaks, &finding.rule_id)?;
            let (category, severity) = classify(&finding.rule_id, &finding.tags);
            let location = line_location(finding.start_line, finding.start_column)?;
            parsed.push(ParsedOccurrence {
                candidate_id: assignment.candidate_id,
                artifact_id: assignment.artifact_id,
                rule_id: normalized_rule,
                category,
                severity,
                location,
            });
        }
        complete(ScannerKind::Gitleaks, context, parsed)
    }
}

impl FirstPartyScannerAdapter for GitleaksAdapter {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Gitleaks
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
        require_kind(ScannerKind::Gitleaks, output)?;
        if !self.version_requirement.accepts(output.version) {
            return Err(ScannerAdapterError::UnsupportedVersion);
        }
        self.normalize_bytes(context, output.exit, output.report())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NativeFinding {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(default)]
    start_line: u64,
    #[serde(default)]
    end_line: u64,
    #[serde(default)]
    start_column: u64,
    #[serde(default)]
    end_column: u64,
    file: String,
    #[serde(default)]
    symlink_file: String,
    #[serde(default)]
    commit: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    secret: String,
}

fn validate_extent(finding: &NativeFinding) -> Result<(), ScannerAdapterError> {
    if finding.end_line != 0 && (finding.start_line == 0 || finding.end_line < finding.start_line) {
        return Err(ScannerAdapterError::Location);
    }
    if finding.end_column != 0 && finding.start_column == 0 {
        return Err(ScannerAdapterError::Location);
    }
    if finding.end_line == finding.start_line
        && finding.end_column != 0
        && finding.end_column < finding.start_column
    {
        return Err(ScannerAdapterError::Location);
    }
    Ok(())
}

fn classify(rule: &str, tags: &[String]) -> (FindingCategory, Severity) {
    let credential = ["credential", "password", "private-key", "token", "api-key"]
        .iter()
        .any(|needle| rule.to_ascii_lowercase().contains(needle))
        || tags.iter().any(|tag| {
            matches!(
                tag.to_ascii_lowercase().as_str(),
                "credential" | "password" | "private-key" | "token" | "key"
            )
        });
    if credential {
        (FindingCategory::Credential, Severity::High)
    } else {
        (FindingCategory::Secret, Severity::Medium)
    }
}
