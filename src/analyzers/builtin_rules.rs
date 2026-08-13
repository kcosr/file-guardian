use std::collections::BTreeSet;
use std::io::Read;

use crate::domain::{
    AnalyzerCoverage, AnalyzerId, Artifact, ArtifactId, ArtifactManifest, CoverageStatus, Finding,
    FindingCategory, InspectionIssue, InspectionPhase, IssueCode, LogicalPath,
    NormalizedObservation, ObjectId, ObservationId, Provenance, ReasonCode, RuleId, SafeEvidence,
    SanitizedMessage, Severity, ValidatedLocation,
};
use crate::rules::CompiledRule;

/// Reads a captured immutable object. Implementations must resolve only object
/// identifiers from the run workspace, never paths in the live source tree.
pub trait ArtifactReader {
    fn read_object(
        &self,
        object_id: &ObjectId,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ArtifactReadError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactReadError {
    #[error("immutable object is unavailable")]
    Unavailable,
    #[error("immutable object exceeds the requested read limit")]
    LimitExceeded,
}

impl ArtifactReader for crate::authorization::ObjectStore {
    fn read_object(
        &self,
        object_id: &ObjectId,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ArtifactReadError> {
        let object = self
            .open(object_id)
            .map_err(|_| ArtifactReadError::Unavailable)?;
        let mut bytes = Vec::new();
        object
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ArtifactReadError::Unavailable)?;
        if bytes.len() as u64 > max_bytes {
            return Err(ArtifactReadError::LimitExceeded);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// Compiled policy for content that the built-in regex engine cannot inspect.
///
/// Exclusion explicitly declares that content rules do not apply to an
/// artifact. It is counted in coverage; it is not a successful content scan.
/// Filename rules still run for an excluded artifact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuiltinContentApplicability {
    pub invalid_utf8: UnsupportedContentPolicy,
    pub over_max_bytes: UnsupportedContentPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UnsupportedContentPolicy {
    /// Fail closed with an issue and incomplete coverage.
    #[default]
    Fail,
    /// Declare content rules inapplicable and record an explicit exclusion.
    Exclude,
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
    #[error("built-in rule {0} embeds an action; authorization actions belong to policy")]
    EmbeddedAction(RuleId),
    #[error("max_content_bytes and max_findings must both be nonzero")]
    InvalidLimits,
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
            if rule.action.is_some() {
                return Err(BuiltinAnalyzerError::EmbeddedAction(rule_id));
            }
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

    pub fn analyze(
        &self,
        phase: InspectionPhase,
        manifest: &ArtifactManifest,
        reader: &impl ArtifactReader,
    ) -> BuiltinRulesResult {
        let assigned = manifest.artifacts().len() as u64;
        let content_required = self.rules.iter().any(|rule| rule.content_regex.is_some());
        let filename_required = self.rules.iter().any(|rule| rule.filename_glob.is_some());
        let mut findings = Vec::new();
        let mut issues = Vec::new();
        let mut completed = 0_u64;
        let mut excluded = 0_u64;
        let mut limit_reached = false;

        let mut artifacts: Vec<_> = manifest.artifacts().iter().collect();
        artifacts.sort_by(|left, right| {
            logical_path(left)
                .cmp(logical_path(right))
                .then_with(|| left.id.cmp(&right.id))
        });

        for artifact in artifacts {
            if limit_reached {
                break;
            }

            let mut artifact_complete = true;
            let mut artifact_excluded = false;
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
                if artifact.byte_len > self.limits.max_content_bytes {
                    match self.limits.content_applicability.over_max_bytes {
                        UnsupportedContentPolicy::Fail => {
                            issues.push(issue(
                                &self.id,
                                phase,
                                artifact,
                                IssueCode::SizeLimitExceeded,
                                "artifact exceeds the built-in content inspection limit",
                            ));
                            artifact_complete = false;
                        }
                        UnsupportedContentPolicy::Exclude => artifact_excluded = true,
                    }
                } else {
                    match reader.read_object(&artifact.object_id, self.limits.max_content_bytes) {
                        Err(ArtifactReadError::Unavailable) => {
                            issues.push(issue(
                                &self.id,
                                phase,
                                artifact,
                                IssueCode::AnalyzerFailure,
                                "built-in analyzer could not read the immutable object",
                            ));
                            artifact_complete = false;
                        }
                        Err(ArtifactReadError::LimitExceeded) => {
                            issues.push(issue(
                                &self.id,
                                phase,
                                artifact,
                                IssueCode::SizeLimitExceeded,
                                "immutable object exceeds the built-in content inspection limit",
                            ));
                            artifact_complete = false;
                        }
                        Ok(bytes)
                            if bytes.len() as u64 != artifact.byte_len
                                || crate::domain::Digest::sha256(&bytes)
                                    != artifact.content_digest =>
                        {
                            issues.push(issue(
                                &self.id,
                                phase,
                                artifact,
                                IssueCode::AnalyzerFailure,
                                "immutable object does not match its manifest identity",
                            ));
                            artifact_complete = false;
                        }
                        Ok(bytes) => match std::str::from_utf8(&bytes) {
                            Err(_) => match self.limits.content_applicability.invalid_utf8 {
                                UnsupportedContentPolicy::Fail => {
                                    issues.push(issue(
                                        &self.id,
                                        phase,
                                        artifact,
                                        IssueCode::InvalidAnalyzerOutput,
                                        "built-in content rules require UTF-8 content",
                                    ));
                                    artifact_complete = false;
                                }
                                UnsupportedContentPolicy::Exclude => artifact_excluded = true,
                            },
                            Ok(content) => {
                                for rule in &self.rules {
                                    let Some(pattern) = &rule.content_regex else {
                                        continue;
                                    };
                                    for matched in pattern.find_iter(content) {
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
                        },
                    }
                }
            }

            if artifact_complete {
                if artifact_excluded {
                    excluded += 1;
                } else {
                    completed += 1;
                }
            }
        }

        findings.sort();
        let analyzer_digest = crate::domain::Digest::sha256(self.id.as_str()).to_string();
        let analyzer_key = &analyzer_digest["sha256:".len().."sha256:".len() + 16];
        let phase_key = match phase {
            InspectionPhase::Initial => "initial",
            InspectionPhase::Verification => "verification",
        };
        let observations = findings
            .into_iter()
            .enumerate()
            .map(|(index, pending)| {
                NormalizedObservation::Finding(Finding {
                    id: ObservationId::from_suffix(format!(
                        "builtin-{analyzer_key}-{phase_key}-{:08}",
                        index + 1
                    ))
                    .expect("bounded canonical observation id"),
                    analyzer_id: self.id.clone(),
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
            .collect();
        let status = if completed + excluded == assigned {
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
            excluded,
            status,
        )
        .expect("analyzer coverage counters are internally consistent");

        BuiltinRulesResult {
            observations,
            issues,
            coverage,
        }
    }
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

    use glob::Pattern;
    use regex::Regex;

    use super::*;
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
        fn read_object(
            &self,
            object_id: &ObjectId,
            max_bytes: u64,
        ) -> Result<Vec<u8>, ArtifactReadError> {
            let bytes = self
                .objects
                .get(object_id)
                .ok_or(ArtifactReadError::Unavailable)?;
            if bytes.len() as u64 > max_bytes {
                return Err(ArtifactReadError::LimitExceeded);
            }
            Ok(bytes.clone())
        }
    }

    fn rule(name: &str, glob: Option<&str>, regex: Option<&str>) -> CompiledRule {
        CompiledRule {
            name: name.to_owned(),
            filename_glob: glob.map(|value| Pattern::new(value).unwrap()),
            content_regex: regex.map(|value| Regex::new(value).unwrap()),
            action: None,
            source: RuleSource::Inline,
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

    #[test]
    fn returns_every_filename_and_content_occurrence_in_canonical_order() {
        let (manifest, reader) = manifest(&[("credentials.secret", b"token=one token=two")]);
        let analyzer = analyzer(vec![
            rule("z-token", None, Some("token=[a-z]+")),
            rule("a-secret-name", Some("*.secret"), None),
        ]);

        let result = analyzer.analyze(InspectionPhase::Initial, &manifest, &reader);

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

        let result = analyzer.analyze(InspectionPhase::Initial, &manifest, &reader);
        assert_eq!(result.observations.len(), 3);
    }

    #[test]
    fn ordering_uses_logical_paths_and_phase_ids_do_not_collide() {
        let (manifest, reader) = manifest(&[("z.txt", b"hit"), ("a.txt", b"hit")]);
        let analyzer = analyzer(vec![rule("match", None, Some("hit"))]);

        let initial = analyzer.analyze(InspectionPhase::Initial, &manifest, &reader);
        let verification = analyzer.analyze(InspectionPhase::Verification, &manifest, &reader);

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

        let result = analyzer.analyze(InspectionPhase::Initial, &manifest, &reader);
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
            &analyzer
                .analyze(InspectionPhase::Initial, &manifest, &reader)
                .observations,
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

        let result = analyzer.analyze(InspectionPhase::Initial, &manifest, &reader);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(replaced_live_source, b"clean replacement");
    }

    #[test]
    fn unsupported_content_fails_closed_by_default() {
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
        let invalid =
            analyzer.analyze(InspectionPhase::Initial, &invalid_manifest, &invalid_reader);
        assert!(!invalid.coverage.is_complete());
        assert_eq!(invalid.issues[0].code, IssueCode::InvalidAnalyzerOutput);
        assert_eq!(invalid.issues[0].analyzer_id.as_ref(), Some(analyzer.id()));

        let (large_manifest, large_reader) = manifest(&[("large", b"four")]);
        let large = analyzer.analyze(InspectionPhase::Initial, &large_manifest, &large_reader);
        assert!(!large.coverage.is_complete());
        assert_eq!(large.issues[0].code, IssueCode::SizeLimitExceeded);

        let (missing_manifest, _) = manifest(&[("missing", b"one")]);
        let missing = analyzer.analyze(
            InspectionPhase::Initial,
            &missing_manifest,
            &MemoryReader::default(),
        );
        assert!(!missing.coverage.is_complete());
        assert_eq!(missing.issues[0].code, IssueCode::AnalyzerFailure);

        let (limited_manifest, limited_reader) = manifest(&[("limited", b"aaa")]);
        let limited =
            analyzer.analyze(InspectionPhase::Initial, &limited_manifest, &limited_reader);
        assert_eq!(limited.observations.len(), 1);
        assert!(!limited.coverage.is_complete());
        assert_eq!(limited.issues[0].code, IssueCode::SizeLimitExceeded);
    }

    #[test]
    fn explicit_content_exclusions_are_complete_and_filename_rules_still_run() {
        let analyzer = BuiltinRulesAnalyzer::new(
            "builtin",
            vec![
                rule("blocked-name", Some("*.secret"), None),
                rule("content", None, Some(".")),
            ],
            BuiltinAnalyzerLimits {
                max_content_bytes: 3,
                max_findings: 10,
                content_applicability: BuiltinContentApplicability {
                    invalid_utf8: UnsupportedContentPolicy::Exclude,
                    over_max_bytes: UnsupportedContentPolicy::Exclude,
                },
            },
        )
        .unwrap();
        let (manifest, reader) =
            manifest(&[("invalid.secret", &[0xff]), ("large.secret", b"four")]);

        let result = analyzer.analyze(InspectionPhase::Initial, &manifest, &reader);

        assert!(result.coverage.is_complete());
        assert_eq!(result.coverage.completed, 0);
        assert_eq!(result.coverage.excluded, 2);
        assert!(result.issues.is_empty());
        assert_eq!(result.observations.len(), 2);
        assert!(result.observations.iter().all(|observation| matches!(
            observation,
            NormalizedObservation::Finding(finding)
                if finding.category == FindingCategory::Filename
        )));
    }

    #[test]
    fn explicit_applicability_exclusions_do_not_hide_object_or_digest_failures() {
        let analyzer = BuiltinRulesAnalyzer::new(
            "builtin",
            vec![rule("content", None, Some("."))],
            BuiltinAnalyzerLimits {
                max_content_bytes: 3,
                max_findings: 10,
                content_applicability: BuiltinContentApplicability {
                    invalid_utf8: UnsupportedContentPolicy::Exclude,
                    over_max_bytes: UnsupportedContentPolicy::Exclude,
                },
            },
        )
        .unwrap();
        let (missing_manifest, _) = manifest(&[("missing", b"one")]);

        let result = analyzer.analyze(
            InspectionPhase::Initial,
            &missing_manifest,
            &MemoryReader::default(),
        );

        assert!(!result.coverage.is_complete());
        assert_eq!(result.coverage.excluded, 0);
        assert_eq!(result.issues[0].code, IssueCode::AnalyzerFailure);

        let (corrupt_manifest, mut corrupt_reader) = manifest(&[("corrupt", b"one")]);
        let object_id = corrupt_manifest.artifacts()[0].object_id.clone();
        corrupt_reader.objects.insert(object_id, b"two".to_vec());
        let corrupt =
            analyzer.analyze(InspectionPhase::Initial, &corrupt_manifest, &corrupt_reader);
        assert!(!corrupt.coverage.is_complete());
        assert_eq!(corrupt.coverage.excluded, 0);
        assert_eq!(corrupt.issues[0].code, IssueCode::AnalyzerFailure);
    }

    #[test]
    fn legacy_action_rules_are_rejected() {
        let mut legacy = rule("legacy", Some("*"), None);
        legacy.action = Some(crate::config::PolicyAction::Remove);
        assert!(matches!(
            BuiltinRulesAnalyzer::new("builtin", vec![legacy], BuiltinAnalyzerLimits::default()),
            Err(BuiltinAnalyzerError::EmbeddedAction(_))
        ));
    }
}
