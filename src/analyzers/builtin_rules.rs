use std::collections::BTreeSet;

use super::content_applicability::{
    assess_text_artifact, assess_text_reader, ArtifactReadError, ArtifactReader,
    RequiredTextMatcher, TextApplicabilityError, TextArtifactDisposition,
};

use crate::domain::{
    AnalyzerCoverage, AnalyzerId, Artifact, ArtifactId, ArtifactManifest, CoverageStatus, Finding,
    FindingCategory, InspectionIssue, InspectionPhase, IssueCode, LogicalPath,
    NormalizedObservation, ObservationId, Provenance, ReasonCode, RuleId, SafeEvidence,
    SanitizedMessage, Severity, ValidatedLocation,
};
use crate::rules::CompiledRule;

#[derive(Clone, Debug)]
pub struct BuiltinAnalyzerLimits {
    pub max_content_bytes: u64,
    pub max_findings: usize,
    pub content_applicability: BuiltinContentApplicability,
}

impl Default for BuiltinAnalyzerLimits {
    fn default() -> Self {
        Self {
            max_content_bytes: 16 * 1024 * 1024,
            max_findings: 10_000,
            content_applicability: BuiltinContentApplicability::default(),
        }
    }
}

/// Compiled path policy that distinguishes ordinary binary uploads from paths
/// whose policy requires valid UTF-8 text. Applicability is evaluated only
/// after the pipeline freezes the analyzer assignment.
#[derive(Clone, Debug, Default)]
pub struct BuiltinContentApplicability {
    pub required_text: RequiredTextMatcher,
}

#[derive(Debug, thiserror::Error)]
pub enum BuiltinAnalyzerError {
    #[error("built-in analyzer id is invalid: {0}")]
    AnalyzerId(#[source] crate::domain::IdentifierError),
    #[error("built-in rule id is invalid: {name}: {source}")]
    RuleId {
        name: String,
        #[source]
        source: crate::domain::IdentifierError,
    },
    #[error("duplicate built-in rule id {0}")]
    DuplicateRule(RuleId),
    #[error("max_content_bytes and max_findings must both be nonzero")]
    InvalidLimits,
    #[error("built-in analyzer artifact assignment is not in canonical order")]
    AssignmentNotCanonical,
    #[error("built-in analyzer assignment references unknown artifact {0}")]
    UnknownAssignedArtifact(ArtifactId),
}

#[derive(Clone, Debug)]
struct AnalyzerRule {
    id: RuleId,
    filename_glob: Option<glob::Pattern>,
    content_regex: Option<regex::Regex>,
}

#[derive(Clone, Debug)]
pub struct BuiltinRulesAnalyzer {
    id: AnalyzerId,
    rules: Vec<AnalyzerRule>,
    limits: BuiltinAnalyzerLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinRulesResult {
    pub observations: Vec<NormalizedObservation>,
    pub issues: Vec<InspectionIssue>,
    pub coverage: AnalyzerCoverage,
    /// Canonical outcomes for assignments which completed successfully. An
    /// incomplete result deliberately omits failed and unvisited artifacts so
    /// callers cannot mistake aggregate coverage for per-artifact success.
    pub assignment_outcomes: Vec<BuiltinAssignmentOutcome>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinAssignmentOutcome {
    pub artifact_id: ArtifactId,
    pub disposition: BuiltinAssignmentDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinAssignmentDisposition {
    Completed,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BuiltinProcessingAssignment {
    pub artifact_id: ArtifactId,
    pub logical_path: LogicalPath,
    pub byte_len: u64,
    pub content_digest: crate::domain::Digest,
}

pub(crate) trait BuiltinProcessingReader {
    fn open_artifact(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Box<dyn std::io::Read + '_>, ArtifactReadError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BuiltinProcessingResult {
    pub observations: Vec<NormalizedObservation>,
    pub assignment_outcomes: Vec<BuiltinAssignmentOutcome>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum BuiltinProcessingError {
    #[error("built-in processing assignment is not canonical")]
    Assignment,
    #[error("immutable processing content is unavailable")]
    Unavailable,
    #[error("immutable processing content is invalid")]
    InvalidContent,
    #[error("built-in processing budget was exceeded")]
    BudgetExceeded,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingFinding {
    logical_path: LogicalPath,
    artifact_id: ArtifactId,
    rule_id: RuleId,
    category: FindingCategory,
    location: Option<ValidatedLocation>,
    reason_code: ReasonCode,
}

impl BuiltinRulesAnalyzer {
    pub fn new(
        id: impl Into<String>,
        rules: Vec<CompiledRule>,
        limits: BuiltinAnalyzerLimits,
    ) -> Result<Self, BuiltinAnalyzerError> {
        if limits.max_content_bytes == 0 || limits.max_findings == 0 {
            return Err(BuiltinAnalyzerError::InvalidLimits);
        }

        let id = AnalyzerId::new(id).map_err(BuiltinAnalyzerError::AnalyzerId)?;
        let mut seen = BTreeSet::new();
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let rule_id =
                RuleId::new(rule.name.clone()).map_err(|source| BuiltinAnalyzerError::RuleId {
                    name: rule.name.clone(),
                    source,
                })?;
            if !seen.insert(rule_id.clone()) {
                return Err(BuiltinAnalyzerError::DuplicateRule(rule_id));
            }
            compiled.push(AnalyzerRule {
                id: rule_id,
                filename_glob: rule.filename_glob,
                content_regex: rule.content_regex,
            });
        }
        compiled.sort_by(|left, right| left.id.cmp(&right.id));

        Ok(Self {
            id,
            rules: compiled,
            limits,
        })
    }

    pub fn id(&self) -> &AnalyzerId {
        &self.id
    }

    pub(crate) fn analyze_processing(
        &self,
        phase: InspectionPhase,
        assignments: &[BuiltinProcessingAssignment],
        reader: &impl BuiltinProcessingReader,
    ) -> Result<BuiltinProcessingResult, BuiltinProcessingError> {
        if assignments
            .windows(2)
            .any(|pair| pair[0].artifact_id >= pair[1].artifact_id)
        {
            return Err(BuiltinProcessingError::Assignment);
        }
        let content_required = self.rules.iter().any(|rule| rule.content_regex.is_some());
        let filename_required = self.rules.iter().any(|rule| rule.filename_glob.is_some());
        let mut findings = Vec::new();
        let mut assignment_outcomes = Vec::with_capacity(assignments.len());
        for assignment in assignments {
            let mut not_applicable = false;
            if filename_required {
                let filename = assignment
                    .logical_path
                    .segments()
                    .last()
                    .and_then(|segment| std::str::from_utf8(segment.as_slice()).ok())
                    .ok_or(BuiltinProcessingError::InvalidContent)?;
                for rule in &self.rules {
                    if rule
                        .filename_glob
                        .as_ref()
                        .is_some_and(|pattern| pattern.matches(filename))
                    {
                        push_processing_finding(
                            &mut findings,
                            self.limits.max_findings,
                            PendingFinding {
                                logical_path: assignment.logical_path.clone(),
                                artifact_id: assignment.artifact_id.clone(),
                                rule_id: rule.id.clone(),
                                category: FindingCategory::Filename,
                                location: None,
                                reason_code: reason("filename_glob_match"),
                            },
                        )?;
                    }
                }
            }
            if content_required {
                let input = reader
                    .open_artifact(&assignment.artifact_id)
                    .map_err(|_| BuiltinProcessingError::Unavailable)?;
                match assess_text_reader(
                    &assignment.logical_path,
                    assignment.byte_len,
                    assignment.content_digest,
                    input,
                    self.limits.max_content_bytes,
                    &self.limits.content_applicability.required_text,
                ) {
                    Ok(TextArtifactDisposition::NotApplicableBinary) => not_applicable = true,
                    Ok(TextArtifactDisposition::Text(content)) => {
                        for rule in &self.rules {
                            let Some(pattern) = &rule.content_regex else {
                                continue;
                            };
                            for matched in pattern.find_iter(content.as_str()) {
                                push_processing_finding(
                                    &mut findings,
                                    self.limits.max_findings,
                                    PendingFinding {
                                        logical_path: assignment.logical_path.clone(),
                                        artifact_id: assignment.artifact_id.clone(),
                                        rule_id: rule.id.clone(),
                                        category: FindingCategory::ContentPattern,
                                        location: match_location(&matched),
                                        reason_code: reason("content_regex_match"),
                                    },
                                )?;
                            }
                        }
                    }
                    Err(TextApplicabilityError::TextLimitExceeded) => {
                        return Err(BuiltinProcessingError::BudgetExceeded)
                    }
                    Err(_) => return Err(BuiltinProcessingError::InvalidContent),
                }
            }
            assignment_outcomes.push(BuiltinAssignmentOutcome {
                artifact_id: assignment.artifact_id.clone(),
                disposition: if not_applicable {
                    BuiltinAssignmentDisposition::NotApplicable
                } else {
                    BuiltinAssignmentDisposition::Completed
                },
            });
        }
        Ok(BuiltinProcessingResult {
            observations: finalize_findings(&self.id, phase, findings),
            assignment_outcomes,
        })
    }

    /// Inspects exactly the assigned artifacts.
    ///
    /// Assignments are an executor-owned contract and must contain known
    /// artifact identifiers in strictly increasing canonical order. Empty
    /// assignments are valid and produce complete zero coverage.
    pub fn analyze(
        &self,
        phase: InspectionPhase,
        manifest: &ArtifactManifest,
        assignment: &[ArtifactId],
        reader: &impl ArtifactReader,
    ) -> Result<BuiltinRulesResult, BuiltinAnalyzerError> {
        if assignment.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BuiltinAnalyzerError::AssignmentNotCanonical);
        }
        let artifacts = assignment
            .iter()
            .map(|artifact_id| {
                manifest.artifact(artifact_id).ok_or_else(|| {
                    BuiltinAnalyzerError::UnknownAssignedArtifact(artifact_id.clone())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let assigned = assignment.len() as u64;
        let content_required = self.rules.iter().any(|rule| rule.content_regex.is_some());
        let filename_required = self.rules.iter().any(|rule| rule.filename_glob.is_some());
        let mut findings = Vec::new();
        let mut issues = Vec::new();
        let mut completed = 0_u64;
        let mut not_applicable = 0_u64;
        let mut assignment_outcomes = Vec::with_capacity(artifacts.len());
        let mut limit_reached = false;

        for artifact in artifacts {
            if limit_reached {
                break;
            }

            let mut artifact_complete = true;
            let mut artifact_not_applicable = false;
            if filename_required {
                match filename(artifact) {
                    Some(filename) => {
                        for rule in &self.rules {
                            if rule
                                .filename_glob
                                .as_ref()
                                .is_some_and(|pattern| pattern.matches(filename))
                                && !push_finding(
                                    &mut findings,
                                    self.limits.max_findings,
                                    PendingFinding {
                                        logical_path: logical_path(artifact).clone(),
                                        artifact_id: artifact.id.clone(),
                                        rule_id: rule.id.clone(),
                                        category: FindingCategory::Filename,
                                        location: None,
                                        reason_code: reason("filename_glob_match"),
                                    },
                                )
                            {
                                issues.push(issue(
                                    &self.id,
                                    phase,
                                    artifact,
                                    IssueCode::SizeLimitExceeded,
                                    "built-in analyzer finding limit exceeded",
                                ));
                                artifact_complete = false;
                                limit_reached = true;
                                break;
                            }
                        }
                    }
                    None => {
                        issues.push(issue(
                            &self.id,
                            phase,
                            artifact,
                            IssueCode::InvalidAnalyzerOutput,
                            "built-in filename rules require a UTF-8 filename",
                        ));
                        artifact_complete = false;
                    }
                }
            }

            if content_required && !limit_reached {
                match assess_text_artifact(
                    artifact,
                    reader,
                    self.limits.max_content_bytes,
                    &self.limits.content_applicability.required_text,
                ) {
                    Ok(TextArtifactDisposition::NotApplicableBinary) => {
                        artifact_not_applicable = true;
                    }
                    Ok(TextArtifactDisposition::Text(content)) => {
                        for rule in &self.rules {
                            let Some(pattern) = &rule.content_regex else {
                                continue;
                            };
                            for matched in pattern.find_iter(content.as_str()) {
                                let location = match_location(&matched);
                                if !push_finding(
                                    &mut findings,
                                    self.limits.max_findings,
                                    PendingFinding {
                                        logical_path: logical_path(artifact).clone(),
                                        artifact_id: artifact.id.clone(),
                                        rule_id: rule.id.clone(),
                                        category: FindingCategory::ContentPattern,
                                        location,
                                        reason_code: reason("content_regex_match"),
                                    },
                                ) {
                                    issues.push(issue(
                                        &self.id,
                                        phase,
                                        artifact,
                                        IssueCode::SizeLimitExceeded,
                                        "built-in analyzer finding limit exceeded",
                                    ));
                                    artifact_complete = false;
                                    limit_reached = true;
                                    break;
                                }
                            }
                            if limit_reached {
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        let (code, message) = applicability_issue(error);
                        issues.push(issue(&self.id, phase, artifact, code, message));
                        artifact_complete = false;
                    }
                }
            }

            if artifact_complete {
                if artifact_not_applicable {
                    not_applicable += 1;
                    assignment_outcomes.push(BuiltinAssignmentOutcome {
                        artifact_id: artifact.id.clone(),
                        disposition: BuiltinAssignmentDisposition::NotApplicable,
                    });
                } else {
                    completed += 1;
                    assignment_outcomes.push(BuiltinAssignmentOutcome {
                        artifact_id: artifact.id.clone(),
                        disposition: BuiltinAssignmentDisposition::Completed,
                    });
                }
            }
        }

        let observations = finalize_findings(&self.id, phase, findings);
        let status = if completed + not_applicable == assigned {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Incomplete
        };
        let coverage = AnalyzerCoverage::new(
            self.id.clone(),
            phase,
            assigned,
            assigned,
            completed,
            not_applicable,
            status,
        )
        .expect("analyzer coverage counters are internally consistent");

        Ok(BuiltinRulesResult {
            observations,
            issues,
            coverage,
            assignment_outcomes,
        })
    }
}

fn push_processing_finding(
    findings: &mut Vec<PendingFinding>,
    limit: usize,
    finding: PendingFinding,
) -> Result<(), BuiltinProcessingError> {
    if push_finding(findings, limit, finding) {
        Ok(())
    } else {
        Err(BuiltinProcessingError::BudgetExceeded)
    }
}

fn finalize_findings(
    analyzer_id: &AnalyzerId,
    phase: InspectionPhase,
    mut findings: Vec<PendingFinding>,
) -> Vec<NormalizedObservation> {
    findings.sort();
    let analyzer_digest = crate::domain::Digest::sha256(analyzer_id.as_str()).to_string();
    let analyzer_key = &analyzer_digest["sha256:".len().."sha256:".len() + 16];
    let phase_key = match phase {
        InspectionPhase::Initial => "initial",
        InspectionPhase::Verification => "verification",
    };
    findings
        .into_iter()
        .enumerate()
        .map(|(index, pending)| {
            NormalizedObservation::Finding(Finding {
                id: ObservationId::from_suffix(format!(
                    "builtin-{analyzer_key}-{phase_key}-{:08}",
                    index + 1
                ))
                .expect("bounded canonical observation id"),
                analyzer_id: analyzer_id.clone(),
                rule_id: pending.rule_id,
                artifact_id: pending.artifact_id,
                category: pending.category,
                severity: Severity::High,
                location: pending.location,
                evidence: SafeEvidence {
                    reason_codes: vec![pending.reason_code],
                },
            })
        })
        .collect()
}

fn logical_path(artifact: &Artifact) -> &LogicalPath {
    match &artifact.provenance {
        Provenance::Physical { logical_path } => logical_path,
        Provenance::Derived { member_path, .. } => member_path,
    }
}

fn filename(artifact: &Artifact) -> Option<&str> {
    logical_path(artifact)
        .segments()
        .last()
        .and_then(|segment| std::str::from_utf8(segment.as_slice()).ok())
}

fn push_finding(findings: &mut Vec<PendingFinding>, limit: usize, finding: PendingFinding) -> bool {
    if findings.len() == limit {
        return false;
    }
    findings.push(finding);
    true
}

fn match_location(matched: &regex::Match<'_>) -> Option<ValidatedLocation> {
    if matched.is_empty() {
        None
    } else {
        Some(
            ValidatedLocation::byte_range(matched.start() as u64, matched.end() as u64)
                .expect("non-empty regex match has a valid byte range"),
        )
    }
}

fn reason(value: &str) -> ReasonCode {
    ReasonCode::new(value).expect("static reason code is valid")
}

fn applicability_issue(error: TextApplicabilityError) -> (IssueCode, &'static str) {
    match error {
        TextApplicabilityError::ObjectUnavailable | TextApplicabilityError::ObjectReadFailed => (
            IssueCode::AnalyzerFailure,
            "built-in analyzer could not read the immutable object",
        ),
        TextApplicabilityError::ObjectIdentityMismatch => (
            IssueCode::AnalyzerFailure,
            "immutable object does not match its manifest identity",
        ),
        TextApplicabilityError::RequiredTextBinaryContent => (
            IssueCode::InvalidAnalyzerOutput,
            "required text artifact was classified as binary content",
        ),
        TextApplicabilityError::TextLimitExceeded => (
            IssueCode::SizeLimitExceeded,
            "text artifact exceeds the built-in content inspection limit",
        ),
    }
}

fn issue(
    analyzer_id: &AnalyzerId,
    phase: InspectionPhase,
    artifact: &Artifact,
    code: IssueCode,
    message: &str,
) -> InspectionIssue {
    InspectionIssue {
        phase,
        code,
        analyzer_id: Some(analyzer_id.clone()),
        subject_id: Some(artifact.subject_id.clone()),
        artifact_id: Some(artifact.id.clone()),
        message: SanitizedMessage::new(message).expect("static diagnostic is valid"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use glob::Pattern;
    use regex::Regex;

    use super::*;
    use crate::analyzers::ArtifactReadError;
    use crate::domain::{
        ArtifactKind, Digest, LogicalPath, ObjectId, PathSegment, PhysicalSubject, SourceFileType,
        SourceIdentity, SubjectId,
    };
    use crate::rules::RuleSource;

    #[derive(Default)]
    struct MemoryReader {
        objects: BTreeMap<ObjectId, Vec<u8>>,
    }

    impl ArtifactReader for MemoryReader {
        fn open_object(
            &self,
            object_id: &ObjectId,
        ) -> Result<Box<dyn std::io::Read + '_>, ArtifactReadError> {
            let bytes = self
                .objects
                .get(object_id)
                .ok_or(ArtifactReadError::Unavailable)?;
            Ok(Box::new(Cursor::new(bytes.as_slice())))
        }
    }

    fn rule(name: &str, glob: Option<&str>, regex: Option<&str>) -> CompiledRule {
        CompiledRule {
            name: name.to_owned(),
            filename_glob: glob.map(|value| Pattern::new(value).unwrap()),
            content_regex: regex.map(|value| Regex::new(value).unwrap()),
            source: RuleSource::new("<test>"),
        }
    }

    fn manifest(entries: &[(&str, &[u8])]) -> (ArtifactManifest, MemoryReader) {
        let mut subjects = Vec::new();
        let mut artifacts = Vec::new();
        let mut reader = MemoryReader::default();
        for (index, (path, bytes)) in entries.iter().enumerate() {
            let suffix = format!("{:04}", index + 1);
            let subject_id = SubjectId::from_suffix(&suffix).unwrap();
            let artifact_id = ArtifactId::from_suffix(&suffix).unwrap();
            let object_id = ObjectId::from_suffix(&suffix).unwrap();
            let logical_path = LogicalPath::new(
                path.split('/')
                    .map(|part| PathSegment::utf8(part).unwrap())
                    .collect(),
            )
            .unwrap();
            let digest = Digest::sha256(bytes);
            subjects.push(PhysicalSubject {
                id: subject_id.clone(),
                relative_path: logical_path.clone(),
                source_identity: SourceIdentity {
                    device: 1,
                    inode: (index + 1) as u64,
                    file_type: SourceFileType::RegularFile,
                    byte_len: bytes.len() as u64,
                    link_count: 1,
                    modified: None,
                    changed: None,
                    content_digest: digest,
                },
                object_id: object_id.clone(),
                byte_len: bytes.len() as u64,
            });
            artifacts.push(Artifact {
                id: artifact_id,
                subject_id,
                object_id: object_id.clone(),
                kind: ArtifactKind::PhysicalFile,
                byte_len: bytes.len() as u64,
                content_digest: digest,
                provenance: Provenance::Physical { logical_path },
            });
            reader.objects.insert(object_id, bytes.to_vec());
        }
        (ArtifactManifest::new(subjects, artifacts).unwrap(), reader)
    }

    fn analyzer(rules: Vec<CompiledRule>) -> BuiltinRulesAnalyzer {
        BuiltinRulesAnalyzer::new("builtin", rules, BuiltinAnalyzerLimits::default()).unwrap()
    }

    fn analyze_all(
        analyzer: &BuiltinRulesAnalyzer,
        phase: InspectionPhase,
        manifest: &ArtifactManifest,
        reader: &impl ArtifactReader,
    ) -> BuiltinRulesResult {
        let assignment = manifest
            .artifacts()
            .iter()
            .map(|artifact| artifact.id.clone())
            .collect::<Vec<_>>();
        analyzer
            .analyze(phase, manifest, &assignment, reader)
            .unwrap()
    }

    #[test]
    fn returns_every_filename_and_content_occurrence_in_canonical_order() {
        let (manifest, reader) = manifest(&[("credentials.secret", b"token=one token=two")]);
        let analyzer = analyzer(vec![
            rule("z-token", None, Some("token=[a-z]+")),
            rule("a-secret-name", Some("*.secret"), None),
        ]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);

        assert!(result.coverage.is_complete());
        assert!(result.issues.is_empty());
        assert_eq!(result.observations.len(), 3);
        let rules: Vec<_> = result
            .observations
            .iter()
            .map(|observation| match observation {
                NormalizedObservation::Finding(finding) => finding.rule_id.as_str(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(rules, ["a-secret-name", "z-token", "z-token"]);
    }

    #[test]
    fn multiple_regex_rules_and_occurrences_are_all_reported() {
        let (manifest, reader) = manifest(&[("input.txt", b"alpha beta alpha")]);
        let analyzer = analyzer(vec![
            rule("alpha", None, Some("alpha")),
            rule("beta", None, Some("beta")),
        ]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);
        assert_eq!(result.observations.len(), 3);
    }

    #[test]
    fn inspects_only_the_explicit_artifact_assignment() {
        let (manifest, reader) = manifest(&[
            ("unassigned.secret", b"token=unassigned"),
            ("assigned.txt", b"clean"),
        ]);
        let analyzer = analyzer(vec![
            rule("secret-name", Some("*.secret"), None),
            rule("token", None, Some("token=")),
        ]);
        let assignment = vec![manifest.artifacts()[1].id.clone()];

        let result = analyzer
            .analyze(InspectionPhase::Initial, &manifest, &assignment, &reader)
            .unwrap();

        assert!(result.observations.is_empty());
        assert!(result.issues.is_empty());
        assert!(result.coverage.is_complete());
        assert_eq!(result.coverage.eligible, 1);
        assert_eq!(result.coverage.assigned, 1);
        assert_eq!(result.coverage.completed, 1);
    }

    #[test]
    fn empty_assignment_has_complete_zero_coverage() {
        let (manifest, reader) = manifest(&[("unassigned.secret", b"token=unassigned")]);
        let analyzer = analyzer(vec![
            rule("secret-name", Some("*.secret"), None),
            rule("token", None, Some("token=")),
        ]);

        let result = analyzer
            .analyze(InspectionPhase::Initial, &manifest, &[], &reader)
            .unwrap();

        assert!(result.observations.is_empty());
        assert!(result.issues.is_empty());
        assert!(result.coverage.is_complete());
        assert_eq!(result.coverage.eligible, 0);
        assert_eq!(result.coverage.assigned, 0);
        assert_eq!(result.coverage.completed, 0);
        assert_eq!(result.coverage.not_applicable, 0);
    }

    #[test]
    fn rejects_unknown_duplicate_and_noncanonical_assignments() {
        let (manifest, reader) = manifest(&[("first", b"one"), ("second", b"two")]);
        let analyzer = analyzer(vec![rule("content", None, Some("."))]);
        let first = manifest.artifacts()[0].id.clone();
        let second = manifest.artifacts()[1].id.clone();

        assert!(matches!(
            analyzer.analyze(
                InspectionPhase::Initial,
                &manifest,
                &[first.clone(), first],
                &reader,
            ),
            Err(BuiltinAnalyzerError::AssignmentNotCanonical)
        ));
        assert!(matches!(
            analyzer.analyze(
                InspectionPhase::Initial,
                &manifest,
                &[second, manifest.artifacts()[0].id.clone()],
                &reader,
            ),
            Err(BuiltinAnalyzerError::AssignmentNotCanonical)
        ));

        let unknown = ArtifactId::from_suffix("9999").unwrap();
        assert!(matches!(
            analyzer.analyze(
                InspectionPhase::Initial,
                &manifest,
                std::slice::from_ref(&unknown),
                &reader,
            ),
            Err(BuiltinAnalyzerError::UnknownAssignedArtifact(id)) if id == unknown
        ));
    }

    #[test]
    fn ordering_uses_logical_paths_and_phase_ids_do_not_collide() {
        let (manifest, reader) = manifest(&[("z.txt", b"hit"), ("a.txt", b"hit")]);
        let analyzer = analyzer(vec![rule("match", None, Some("hit"))]);

        let initial = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);
        let verification =
            analyze_all(&analyzer, InspectionPhase::Verification, &manifest, &reader);

        let initial_ids: Vec<_> = initial
            .observations
            .iter()
            .map(|observation| match observation {
                NormalizedObservation::Finding(finding) => {
                    (finding.artifact_id.as_str(), finding.id.as_str())
                }
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(initial_ids[0].0, "a_0002");
        assert!(initial_ids[0].1.contains("initial"));
        let NormalizedObservation::Finding(verification_finding) = &verification.observations[0]
        else {
            unreachable!();
        };
        assert!(verification_finding.id.as_str().contains("verification"));
        assert_ne!(initial_ids[0].1, verification_finding.id.as_str());
    }

    #[test]
    fn zero_width_regex_match_is_reported_without_an_invalid_location() {
        let (manifest, reader) = manifest(&[("input.txt", b"content")]);
        let analyzer = analyzer(vec![rule("start", None, Some("^"))]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);
        let NormalizedObservation::Finding(finding) = &result.observations[0] else {
            unreachable!();
        };
        assert!(finding.location.is_none());
        assert!(result.coverage.is_complete());
    }

    #[test]
    fn observations_never_contain_raw_matched_values() {
        let secret = "token=do-not-report-this";
        let (manifest, reader) = manifest(&[("input.txt", secret.as_bytes())]);
        let analyzer = analyzer(vec![rule("token", None, Some("token=[a-z-]+"))]);

        let json = serde_json::to_string(
            &analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader).observations,
        )
        .unwrap();
        assert!(!json.contains("do-not-report-this"));
        assert!(json.contains("content_regex_match"));
    }

    #[test]
    fn reads_captured_object_not_a_replaced_live_source() {
        let (manifest, reader) = manifest(&[("input.txt", b"captured-secret")]);
        let replaced_live_source = b"clean replacement";
        let analyzer = analyzer(vec![rule("captured", None, Some("captured-secret"))]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(replaced_live_source, b"clean replacement");
    }

    #[test]
    fn binary_is_not_applicable_but_text_limits_and_object_failures_fail_closed() {
        let analyzer = BuiltinRulesAnalyzer::new(
            "builtin",
            vec![rule("anything", None, Some("."))],
            BuiltinAnalyzerLimits {
                max_content_bytes: 3,
                max_findings: 1,
                content_applicability: BuiltinContentApplicability::default(),
            },
        )
        .unwrap();

        let (invalid_manifest, invalid_reader) = manifest(&[("invalid", &[0xff])]);
        let invalid = analyze_all(
            &analyzer,
            InspectionPhase::Initial,
            &invalid_manifest,
            &invalid_reader,
        );
        assert!(invalid.coverage.is_complete());
        assert_eq!(invalid.coverage.not_applicable, 1);
        assert!(invalid.issues.is_empty());

        let (large_manifest, large_reader) = manifest(&[("large", b"four")]);
        let large = analyze_all(
            &analyzer,
            InspectionPhase::Initial,
            &large_manifest,
            &large_reader,
        );
        assert!(!large.coverage.is_complete());
        assert_eq!(large.issues[0].code, IssueCode::SizeLimitExceeded);

        let (missing_manifest, _) = manifest(&[("missing", b"one")]);
        let missing = analyze_all(
            &analyzer,
            InspectionPhase::Initial,
            &missing_manifest,
            &MemoryReader::default(),
        );
        assert!(!missing.coverage.is_complete());
        assert_eq!(missing.issues[0].code, IssueCode::AnalyzerFailure);

        let (limited_manifest, limited_reader) = manifest(&[("limited", b"aaa")]);
        let limited = analyze_all(
            &analyzer,
            InspectionPhase::Initial,
            &limited_manifest,
            &limited_reader,
        );
        assert_eq!(limited.observations.len(), 1);
        assert!(!limited.coverage.is_complete());
        assert_eq!(limited.issues[0].code, IssueCode::SizeLimitExceeded);
    }

    #[test]
    fn reports_exact_canonical_dispositions_for_mixed_text_and_binary_assignments() {
        let analyzer = analyzer(vec![rule("content", None, Some("needle"))]);
        let (manifest, reader) = manifest(&[
            ("binary.bin", &[0xff]),
            ("clean.txt", b"clean text"),
            ("match.txt", b"needle"),
        ]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);

        assert!(result.coverage.is_complete());
        assert_eq!(result.coverage.completed, 2);
        assert_eq!(result.coverage.not_applicable, 1);
        assert_eq!(result.assignment_outcomes.len(), 3);
        assert!(result
            .assignment_outcomes
            .windows(2)
            .all(|pair| pair[0].artifact_id < pair[1].artifact_id));
        assert_eq!(
            result
                .assignment_outcomes
                .iter()
                .map(|outcome| outcome.disposition)
                .collect::<Vec<_>>(),
            vec![
                BuiltinAssignmentDisposition::NotApplicable,
                BuiltinAssignmentDisposition::Completed,
                BuiltinAssignmentDisposition::Completed,
            ]
        );
    }

    #[test]
    fn filename_rules_still_run_when_binary_content_is_not_applicable() {
        let analyzer = BuiltinRulesAnalyzer::new(
            "builtin",
            vec![
                rule("blocked-name", Some("*.secret"), None),
                rule("content", None, Some(".")),
            ],
            BuiltinAnalyzerLimits {
                max_content_bytes: 3,
                max_findings: 10,
                content_applicability: BuiltinContentApplicability::default(),
            },
        )
        .unwrap();
        let (manifest, reader) = manifest(&[("invalid.secret", &[0xff])]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);

        assert!(result.coverage.is_complete());
        assert_eq!(result.coverage.completed, 0);
        assert_eq!(result.coverage.not_applicable, 1);
        assert!(result.issues.is_empty());
        assert_eq!(result.observations.len(), 1);
        assert!(result.observations.iter().all(|observation| matches!(
            observation,
            NormalizedObservation::Finding(finding)
                if finding.category == FindingCategory::Filename
        )));
    }

    #[test]
    fn required_text_binary_is_incomplete() {
        let analyzer = BuiltinRulesAnalyzer::new(
            "builtin",
            vec![rule("content", None, Some("."))],
            BuiltinAnalyzerLimits {
                max_content_bytes: 3,
                max_findings: 10,
                content_applicability: BuiltinContentApplicability {
                    required_text: RequiredTextMatcher::compile(&["**/*.rs".to_string()]).unwrap(),
                },
            },
        )
        .unwrap();
        let (manifest, reader) = manifest(&[("src/main.rs", &[0xff])]);

        let result = analyze_all(&analyzer, InspectionPhase::Initial, &manifest, &reader);

        assert!(!result.coverage.is_complete());
        assert_eq!(result.coverage.not_applicable, 0);
        assert_eq!(result.issues[0].code, IssueCode::InvalidAnalyzerOutput);
    }

    #[test]
    fn binary_applicability_does_not_hide_object_or_digest_failures() {
        let analyzer = BuiltinRulesAnalyzer::new(
            "builtin",
            vec![rule("content", None, Some("."))],
            BuiltinAnalyzerLimits {
                max_content_bytes: 3,
                max_findings: 10,
                content_applicability: BuiltinContentApplicability::default(),
            },
        )
        .unwrap();
        let (missing_manifest, _) = manifest(&[("missing", b"one")]);

        let result = analyze_all(
            &analyzer,
            InspectionPhase::Initial,
            &missing_manifest,
            &MemoryReader::default(),
        );

        assert!(!result.coverage.is_complete());
        assert_eq!(result.coverage.not_applicable, 0);
        assert_eq!(result.issues[0].code, IssueCode::AnalyzerFailure);

        let (corrupt_manifest, mut corrupt_reader) = manifest(&[("corrupt", b"one")]);
        let object_id = corrupt_manifest.artifacts()[0].object_id.clone();
        corrupt_reader.objects.insert(object_id, b"two".to_vec());
        let corrupt = analyze_all(
            &analyzer,
            InspectionPhase::Initial,
            &corrupt_manifest,
            &corrupt_reader,
        );
        assert!(!corrupt.coverage.is_complete());
        assert_eq!(corrupt.coverage.not_applicable, 0);
        assert_eq!(corrupt.issues[0].code, IssueCode::AnalyzerFailure);
    }
}
